"""Getting the records somewhere else: analytics, and an anchor out of reach.

Two different jobs that are easy to confuse, so they are separate functions.

**A replica is for reading.** Dashboards, counts, trend lines -- the things a
lender wants in Fabric or a warehouse. It is a copy, and it is not evidence: it
lives in a system whose operators are the subject of the records, and whatever
governs that system governs the copy. Verify the ledger, chart the replica.

**An anchor is for proving.** One short line, kept where the ledger's operator
cannot edit it, which is what makes a truncation of the newest records
detectable at all. Anchoring into the same warehouse you replicate to protects
nothing.

Neither function takes a dependency on a cloud SDK. Custody ships one dependency
on purpose, and a sink is a callable, so a lender who wants Event Hubs writes
this once against their own SDK:

    from azure.eventhub import EventHubProducerClient, EventData

    producer = EventHubProducerClient.from_connection_string(dsn, eventhub_name="custody")

    def event_hub_sink(record):
        producer.send_batch([EventData(json.dumps(record, default=str))])

    ledger = Ledger(..., on_record=event_hub_sink, on_append=anchor_sink("anchors.log"))

From there it is Eventstream into a Lakehouse table and Power BI on top, and
none of that plumbing belongs in this package.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Callable


def jsonl_sink(path: str | Path) -> Callable[[dict[str, Any]], None]:
    """Append each record to a JSON Lines file.

    Opened per write rather than held. A long-lived handle on the hot path of a
    regulated workflow is a buffer that can be lost in a crash, and the record
    is already durable in the ledger by the time this runs -- so the slow,
    boring version is the correct one.
    """
    target = Path(path)

    def sink(record: dict[str, Any]) -> None:
        with target.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(record, default=str, sort_keys=True) + "\n")

    return sink


def anchor_sink(path: str | Path) -> Callable[[str], None]:
    """Append each anchor to a file, newest last.

    A file on the same host is the weakest possible destination and is here to
    make the wiring obvious, not to be the answer. Put the real one somewhere
    this system's operator has no write access to.
    """
    target = Path(path)

    def sink(anchor: str) -> None:
        with target.open("a", encoding="utf-8") as fh:
            fh.write(anchor + "\n")

    return sink


class CheckpointError(Exception):
    """The checkpoint names a record this ledger does not contain."""


def replicate(ledger, sink: Callable[[dict[str, Any]], None], *,
              since: str | None = None) -> dict[str, Any]:
    """Copy records added after a checkpoint. Returns the next checkpoint.

    Pull rather than push, for the case where the push sink was not configured,
    was configured late, or failed while the ledger kept working -- all of which
    happen, and none of which should cost a lender their dashboard.

    `since` is the **record_id** of the last record already copied, not its
    timestamp. Timestamps were the obvious choice and are wrong: two records
    written inside the same millisecond share one, and a `>` filter then drops
    the second from the replica for good, silently, under exactly the load that
    makes it likely. A record_id is unique and the ledger's order is total and
    immutable, so resuming from one is exact.

    A checkpoint from a different ledger raises rather than copying everything.
    Re-copying a whole ledger into a warehouse that already holds it is a
    duplicate-key incident at best, and a silently doubled dashboard at worst.
    """
    records = _after(ledger, since)
    for record in records:
        sink(record)
    return {
        "copied": len(records),
        "checkpoint": records[-1]["record_id"] if records else since,
        "checkpoint_written_at": records[-1].get("timestamp") if records else None,
        "anchor": ledger.anchor,
    }


def _after(ledger, since: str | None) -> list[dict[str, Any]]:
    records = ledger.records()
    if since is None:
        return records
    for index, record in enumerate(records):
        if record.get("record_id") == since:
            return records[index + 1:]
    raise CheckpointError(
        f"no record {since!r} in this ledger. The checkpoint belongs to a "
        "different ledger, or the record it names has been removed -- either way, "
        "copying from the start would duplicate everything already replicated."
    )
