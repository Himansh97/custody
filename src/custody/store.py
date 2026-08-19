"""Append-only storage.

"Append-only" enforced by a code review is a promise. Enforced by the database
is a property. This store installs SQLite triggers that abort any UPDATE or
DELETE against the ledger table, so the guarantee survives someone opening the
file with a SQL client at two in the morning — which is exactly the scenario an
examiner is asking about.

That does not make the file immutable; anyone with write access can drop the
table or replace the file wholesale. It does not have to. The hash chain in
`chain.py` makes *that* detectable, and the two together are the actual
guarantee: you cannot change a record quietly, and you cannot remove one without
leaving a gap that verification names.

The four indexed columns are not arbitrary. LL-2026-04 requires a seller/servicer
to disclose, promptly and on request, what AI it runs and for what purpose — and
the questions that actually arrive are about a loan, a date range, a model, or a
person. Those four are what this table answers quickly; everything else is a
scan. (The letter names no columns and specifies no schema. This is our reading
of what "promptly" demands, not a transcription of a requirement.)
"""
from __future__ import annotations

import json
import sqlite3
import threading
from pathlib import Path
from typing import Any, Callable

from .chain import GENESIS

_SCHEMA = """
CREATE TABLE IF NOT EXISTS records (
    seq        INTEGER PRIMARY KEY AUTOINCREMENT,
    record_id  TEXT NOT NULL UNIQUE,
    loan       TEXT NOT NULL,
    ts         TEXT NOT NULL,
    model      TEXT,
    principal  TEXT NOT NULL,
    body       TEXT NOT NULL,
    prev_hash  TEXT NOT NULL,
    hash       TEXT NOT NULL UNIQUE,
    signature  TEXT NOT NULL
);

-- The four dimensions the mandate names.
CREATE INDEX IF NOT EXISTS ix_records_loan      ON records(loan);
CREATE INDEX IF NOT EXISTS ix_records_ts        ON records(ts);
CREATE INDEX IF NOT EXISTS ix_records_model     ON records(model);
CREATE INDEX IF NOT EXISTS ix_records_principal ON records(principal);
"""

# Written as one statement per trigger because SQLite will not create both from
# a single execute, and silently creating only the first would leave the weaker
# half of the guarantee in place with nothing to show for it.
_GUARDS = (
    """CREATE TRIGGER IF NOT EXISTS records_are_immutable
       BEFORE UPDATE ON records
       BEGIN SELECT RAISE(ABORT, 'custody: the ledger is append-only'); END""",
    """CREATE TRIGGER IF NOT EXISTS records_cannot_be_removed
       BEFORE DELETE ON records
       BEGIN SELECT RAISE(ABORT, 'custody: the ledger is append-only'); END""",
)


class Store:
    """Thread-safe by construction, because the chain requires it.

    Appending is a read-modify-write: read the head hash, seal against it,
    insert. Two writers interleaving there both chain onto the same head and
    produce a *fork* -- two records claiming the same predecessor -- which
    verification correctly rejects, on a ledger where nobody did anything wrong.

    So the lock is not really about SQLite's threading rules, though it satisfies
    those too. It is what makes the chain well-defined under concurrency.
    Serialising writes to an audit ledger costs nothing anybody will notice.
    """

    def __init__(self, path: str | Path = ":memory:"):
        self.path = str(path)
        # check_same_thread=False is safe only because every access below is
        # taken under _lock. Removing the lock without removing this would
        # reintroduce races SQLite would otherwise have refused outright.
        self._db = sqlite3.connect(self.path, check_same_thread=False)
        self._lock = threading.RLock()
        self._db.row_factory = sqlite3.Row
        self._db.executescript(_SCHEMA)
        for guard in _GUARDS:
            self._db.execute(guard)
        self._db.commit()

    # ------------------------------------------------------------------ write

    def append_chained(self, record: dict[str, Any],
                       seal: Callable[[dict[str, Any], str], dict[str, Any]]) -> dict[str, Any]:
        """Seal against the current head and insert, atomically.

        The only correct way to add to a chain. `seal` receives the record and
        the head hash it must chain onto, and the whole read-seal-write happens
        under one lock so no other writer can slip between the read and the
        insert.
        """
        with self._lock:
            sealed = seal(record, self._head_hash_locked())
            self._insert_locked(sealed)
            return sealed

    def append(self, record: dict[str, Any]) -> None:
        """Insert an already-sealed record. Prefer `append_chained`."""
        with self._lock:
            self._insert_locked(record)

    def _insert_locked(self, record: dict[str, Any]) -> None:
        self._db.execute(
            "INSERT INTO records (record_id, loan, ts, model, principal, body, "
            "prev_hash, hash, signature) VALUES (?,?,?,?,?,?,?,?,?)",
            (
                record["record_id"],
                record["loan"],
                record["timestamp"],
                record.get("model"),
                record["principal"],
                json.dumps(record, sort_keys=True, default=str),
                record["prev_hash"],
                record["hash"],
                record["signature"],
            ),
        )
        self._db.commit()

    def head_hash(self) -> str:
        """The hash the next record must chain onto."""
        with self._lock:
            return self._head_hash_locked()

    def _head_hash_locked(self) -> str:
        row = self._db.execute("SELECT hash FROM records ORDER BY seq DESC LIMIT 1").fetchone()
        return row["hash"] if row else GENESIS

    # ------------------------------------------------------------------- read

    def all(self) -> list[dict[str, Any]]:
        return list(self._rows("SELECT body FROM records ORDER BY seq"))

    def by_loan(self, loan: str) -> list[dict[str, Any]]:
        return list(self._rows("SELECT body FROM records WHERE loan = ? ORDER BY seq", (loan,)))

    def query(
        self,
        *,
        loan: str | None = None,
        model: str | None = None,
        principal: str | None = None,
        since: str | None = None,
        until: str | None = None,
    ) -> list[dict[str, Any]]:
        """The mandate's four dimensions, combinable."""
        clauses, args = [], []
        for column, value in (("loan", loan), ("model", model), ("principal", principal)):
            if value is not None:
                clauses.append(f"{column} = ?")
                args.append(value)
        if since is not None:
            clauses.append("ts >= ?")
            args.append(since)
        if until is not None:
            clauses.append("ts <= ?")
            args.append(until)
        where = f" WHERE {' AND '.join(clauses)}" if clauses else ""
        return list(self._rows(f"SELECT body FROM records{where} ORDER BY seq", tuple(args)))

    def loans(self) -> list[str]:
        with self._lock:
            return [r["loan"] for r in self._db.execute(
                "SELECT DISTINCT loan FROM records ORDER BY loan")]

    def _rows(self, sql: str, args: tuple = ()) -> list[dict[str, Any]]:
        # Materialised inside the lock rather than yielded: a generator would
        # hand the live cursor to the caller and read from it after the lock is
        # gone.
        with self._lock:
            return [json.loads(row["body"]) for row in self._db.execute(sql, args)]

    def close(self) -> None:
        with self._lock:
            self._db.close()
