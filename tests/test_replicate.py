"""Replication tests.

The distinction under test is the one that matters in the architecture: a
replica is a copy for reading, and an anchor is the thing that proves nothing
was removed. Sending both to the same place is the mistake this file exists to
make visible.
"""
from __future__ import annotations

import json
import pathlib
import sys
import tempfile

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent / "src"))

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402

from custody.chain import verify_chain  # noqa: E402
from custody.ledger import Ledger  # noqa: E402
from custody.replicate import (  # noqa: E402
    CheckpointError, anchor_sink, jsonl_sink, replicate,
)

PAYSTUB = "ACME LOGISTICS  Gross pay 4,206.00  YTD 50,472.00"


def _decide(led: Ledger, loan: str = "1000254") -> None:
    with led.decision(loan=loan, principal="j@l", purpose="income") as d:
        out = d.call(model="claude-sonnet-5", prompt="p", sources=[PAYSTUB],
                     response={"gross_pay": 4206.00})
        d.gate(out, citations={"gross_pay": "paystub"}, confidence=0.94)
        d.commit(outcome=out)


def test_the_push_hook_sees_the_sealed_record() -> None:
    seen: list = []
    led = Ledger(policy="v1", signing_key=Ed25519PrivateKey.generate(),
                 on_record=seen.append)
    _decide(led)
    assert len(seen) == 1
    assert seen[0]["hash"] and seen[0]["signature"], "the hook got an unsealed record"


def test_a_replica_verifies_the_same_as_the_ledger() -> None:
    """A copy that cannot be verified is a log, and this one is meant to be more."""
    with tempfile.TemporaryDirectory() as tmp:
        out = pathlib.Path(tmp) / "records.jsonl"
        led = Ledger(policy="v1", signing_key=Ed25519PrivateKey.generate(),
                     on_record=jsonl_sink(out))
        _decide(led)
        _decide(led, "1000255")

        copied = [json.loads(line) for line in out.read_text().splitlines()]
        assert len(copied) == 2
        verify_chain(copied, led.public_key)


def test_a_checkpoint_copies_only_what_is_new() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        out = pathlib.Path(tmp) / "records.jsonl"
        led = Ledger(policy="v1", signing_key=Ed25519PrivateKey.generate())
        _decide(led)

        first = replicate(led, jsonl_sink(out))
        assert first["copied"] == 1

        again = replicate(led, jsonl_sink(out), since=first["checkpoint"])
        assert again["copied"] == 0, "re-running the checkpoint duplicated records"

        _decide(led, "1000256")
        third = replicate(led, jsonl_sink(out), since=first["checkpoint"])
        assert third["copied"] == 1, "a new record was not picked up"


def test_records_sharing_a_millisecond_are_not_dropped() -> None:
    """The reason a checkpoint is a record_id and not a timestamp.

    Several decisions inside one millisecond share a timestamp, and a `>` filter
    on that would drop every one after the checkpoint -- silently, and under
    exactly the load that makes it likely.
    """
    with tempfile.TemporaryDirectory() as tmp:
        out = pathlib.Path(tmp) / "records.jsonl"
        led = Ledger(policy="v1", signing_key=Ed25519PrivateKey.generate())
        for _ in range(12):
            _decide(led)

        first = replicate(led, jsonl_sink(out), since=None)
        assert first["copied"] == 12

        for _ in range(8):
            _decide(led)
        second = replicate(led, jsonl_sink(out), since=first["checkpoint"])
        assert second["copied"] == 8, (
            f"copied {second['copied']} of 8 records added after the checkpoint"
        )

        copied = [json.loads(line) for line in out.read_text().splitlines()]
        assert len(copied) == 20
        assert len({r["record_id"] for r in copied}) == 20, "the replica has duplicates"


def test_a_checkpoint_from_another_ledger_raises() -> None:
    """Copying from the start would duplicate everything already replicated."""
    with tempfile.TemporaryDirectory() as tmp:
        led = Ledger(policy="v1", signing_key=Ed25519PrivateKey.generate())
        _decide(led)
        try:
            replicate(led, jsonl_sink(pathlib.Path(tmp) / "r.jsonl"),
                      since="dec_not_from_this_ledger")
            raise AssertionError("a foreign checkpoint silently copied everything")
        except CheckpointError:
            pass


def test_the_anchor_sink_writes_one_line_per_append() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        anchors = pathlib.Path(tmp) / "anchors.log"
        led = Ledger(policy="v1", signing_key=Ed25519PrivateKey.generate(),
                     on_append=anchor_sink(anchors))
        _decide(led)
        _decide(led)

        lines = anchors.read_text().splitlines()
        assert len(lines) == 2
        assert lines[-1].startswith("custody-anchor:v1:2:")


def test_replication_does_not_disturb_the_ledger() -> None:
    led = Ledger(policy="v1", signing_key=Ed25519PrivateKey.generate())
    _decide(led)
    before = json.dumps(led.records())
    with tempfile.TemporaryDirectory() as tmp:
        replicate(led, jsonl_sink(pathlib.Path(tmp) / "r.jsonl"))
    assert json.dumps(led.records()) == before


if __name__ == "__main__":
    failures = 0
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            try:
                fn()
                print(f"PASS {name}")
            except AssertionError as exc:
                failures += 1
                print(f"FAIL {name}: {exc}")
    print(f"\n{failures} failure(s)")
    raise SystemExit(1 if failures else 0)
