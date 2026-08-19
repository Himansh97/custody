"""Append-only storage, on SQLite or Postgres.

"Append-only" enforced by a code review is a promise. Enforced by the database
is a property. Both backends install triggers that abort any UPDATE or DELETE
against the ledger, so the guarantee survives someone opening the database with a
SQL client at two in the morning -- which is exactly the scenario an examiner is
asking about.

That does not make the data immutable; anyone with sufficient privilege can drop
the table or replace the file. It does not have to. The hash chain makes *that*
detectable, and the two together are the actual guarantee: you cannot change a
record quietly, and you cannot remove one without leaving a gap that verification
names.

## Why the chain cannot fork

Appending is a read-modify-write: read the head hash, seal against it, insert. If
two writers interleave there, both seal against the same predecessor and the
ledger gains two records claiming the same `prev_hash`. That is a fork, and
verification correctly rejects it -- on a ledger where nobody did anything wrong.

A process-level lock fixes that for one process, which is exactly as far as it
goes. The moment there are two application instances -- which is the whole reason
to want Postgres -- the lock protects nothing.

So the real guarantee is a **unique constraint on `prev_hash`**. A fork is not
unlikely, it is not permitted: the second writer's insert violates uniqueness and
fails. Locking is then only an optimisation to keep well-behaved writers from
colliding, and correctness no longer depends on it.

The four indexed columns follow LL-2026-04's disclosure obligation: the questions
that actually arrive are about a loan, a date range, a model, or a person.
"""
from __future__ import annotations

import json
import threading
from pathlib import Path
from typing import Any, Callable

from .chain import GENESIS

# Namespaced so an application using Postgres advisory locks for its own purposes
# cannot collide with ours by accident.
_ADVISORY_LOCK_KEY = 0x00C0570D


class ChainForked(Exception):
    """Another writer sealed against the same predecessor.

    Not corruption. The insert was refused precisely so the ledger stays
    verifiable, and the caller should re-read the head and try again.
    """


class _BaseStore:
    """Shared record/row mapping. Backends supply connection and dialect."""

    placeholder = "?"

    def _row(self, record: dict[str, Any]) -> tuple:
        return (
            record["record_id"],
            record["loan"],
            record["timestamp"],
            record.get("model"),
            record["principal"],
            json.dumps(record, sort_keys=True, default=str),
            record["prev_hash"],
            record["hash"],
            record["signature"],
        )

    @property
    def _insert_sql(self) -> str:
        marks = ",".join([self.placeholder] * 9)
        return (
            "INSERT INTO records (record_id, loan, ts, model, principal, body, "
            f"prev_hash, hash, signature) VALUES ({marks})"
        )

    def _where(self, loan, model, principal, since, until) -> tuple[str, list]:
        clauses, args = [], []
        for column, value in (("loan", loan), ("model", model), ("principal", principal)):
            if value is not None:
                clauses.append(f"{column} = {self.placeholder}")
                args.append(value)
        if since is not None:
            clauses.append(f"ts >= {self.placeholder}")
            args.append(since)
        if until is not None:
            clauses.append(f"ts <= {self.placeholder}")
            args.append(until)
        return (f" WHERE {' AND '.join(clauses)}" if clauses else ""), args


# -------------------------------------------------------------------- sqlite

_SQLITE_SCHEMA = """
CREATE TABLE IF NOT EXISTS records (
    seq        INTEGER PRIMARY KEY AUTOINCREMENT,
    record_id  TEXT NOT NULL UNIQUE,
    loan       TEXT NOT NULL,
    ts         TEXT NOT NULL,
    model      TEXT,
    principal  TEXT NOT NULL,
    body       TEXT NOT NULL,
    -- UNIQUE is the guarantee, not the lock: two writers cannot both chain onto
    -- the same predecessor, so the chain cannot fork even under a race.
    prev_hash  TEXT NOT NULL UNIQUE,
    hash       TEXT NOT NULL UNIQUE,
    signature  TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS ix_records_loan      ON records(loan);
CREATE INDEX IF NOT EXISTS ix_records_ts        ON records(ts);
CREATE INDEX IF NOT EXISTS ix_records_model     ON records(model);
CREATE INDEX IF NOT EXISTS ix_records_principal ON records(principal);
"""

_SQLITE_GUARDS = (
    """CREATE TRIGGER IF NOT EXISTS records_are_immutable
       BEFORE UPDATE ON records
       BEGIN SELECT RAISE(ABORT, 'custody: the ledger is append-only'); END""",
    """CREATE TRIGGER IF NOT EXISTS records_cannot_be_removed
       BEFORE DELETE ON records
       BEGIN SELECT RAISE(ABORT, 'custody: the ledger is append-only'); END""",
)


class Store(_BaseStore):
    """SQLite. One process, one file -- good for a pilot, not for two instances."""

    def __init__(self, path: str | Path = ":memory:"):
        import sqlite3

        self._sqlite3 = sqlite3
        self.path = str(path)
        # check_same_thread=False is safe only because every access is taken
        # under _lock. Removing the lock without removing this reintroduces
        # races SQLite would otherwise have refused outright.
        self._db = sqlite3.connect(self.path, check_same_thread=False)
        self._lock = threading.RLock()
        self._db.row_factory = sqlite3.Row
        self._db.executescript(_SQLITE_SCHEMA)
        for guard in _SQLITE_GUARDS:
            self._db.execute(guard)
        self._db.commit()

    def append_chained(self, record: dict[str, Any],
                       seal: Callable[[dict[str, Any], str], dict[str, Any]]) -> dict[str, Any]:
        with self._lock:
            sealed = seal(record, self._head_locked())
            try:
                self._db.execute(self._insert_sql, self._row(sealed))
            except self._sqlite3.IntegrityError as exc:
                if "prev_hash" in str(exc):
                    raise ChainForked(str(exc)) from None
                raise
            self._db.commit()
            return sealed

    def append(self, record: dict[str, Any]) -> None:
        with self._lock:
            self._db.execute(self._insert_sql, self._row(record))
            self._db.commit()

    def head_hash(self) -> str:
        with self._lock:
            return self._head_locked()

    def _head_locked(self) -> str:
        row = self._db.execute(
            "SELECT hash FROM records ORDER BY seq DESC LIMIT 1").fetchone()
        return row["hash"] if row else GENESIS

    def all(self) -> list[dict[str, Any]]:
        return self._rows("SELECT body FROM records ORDER BY seq")

    def by_loan(self, loan: str) -> list[dict[str, Any]]:
        return self._rows("SELECT body FROM records WHERE loan = ? ORDER BY seq", (loan,))

    def query(self, *, loan=None, model=None, principal=None, since=None, until=None):
        where, args = self._where(loan, model, principal, since, until)
        return self._rows(f"SELECT body FROM records{where} ORDER BY seq", tuple(args))

    def loans(self) -> list[str]:
        with self._lock:
            return [r["loan"] for r in self._db.execute(
                "SELECT DISTINCT loan FROM records ORDER BY loan")]

    def _rows(self, sql: str, args: tuple = ()) -> list[dict[str, Any]]:
        # Materialised inside the lock rather than yielded: a generator would
        # hand the live cursor to the caller and read from it after the lock is
        # gone.
        with self._lock:
            return [json.loads(r["body"]) for r in self._db.execute(sql, args)]

    def close(self) -> None:
        with self._lock:
            self._db.close()


# ------------------------------------------------------------------ postgres

_PG_SCHEMA = """
CREATE TABLE IF NOT EXISTS records (
    seq        BIGSERIAL PRIMARY KEY,
    record_id  TEXT NOT NULL UNIQUE,
    loan       TEXT NOT NULL,
    ts         TEXT NOT NULL,
    model      TEXT,
    principal  TEXT NOT NULL,
    body       TEXT NOT NULL,
    prev_hash  TEXT NOT NULL UNIQUE,
    hash       TEXT NOT NULL UNIQUE,
    signature  TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS ix_records_loan      ON records(loan);
CREATE INDEX IF NOT EXISTS ix_records_ts        ON records(ts);
CREATE INDEX IF NOT EXISTS ix_records_model     ON records(model);
CREATE INDEX IF NOT EXISTS ix_records_principal ON records(principal);

CREATE OR REPLACE FUNCTION custody_append_only() RETURNS trigger AS $fn$
BEGIN
    RAISE EXCEPTION 'custody: the ledger is append-only';
END;
$fn$ LANGUAGE plpgsql;
"""

# DROP first: CREATE TRIGGER has no IF NOT EXISTS before PG 14, and this has to
# be idempotent across versions.
_PG_GUARDS = (
    "DROP TRIGGER IF EXISTS records_are_immutable ON records",
    """CREATE TRIGGER records_are_immutable BEFORE UPDATE ON records
       FOR EACH ROW EXECUTE FUNCTION custody_append_only()""",
    "DROP TRIGGER IF EXISTS records_cannot_be_removed ON records",
    """CREATE TRIGGER records_cannot_be_removed BEFORE DELETE ON records
       FOR EACH ROW EXECUTE FUNCTION custody_append_only()""",
)


class PostgresStore(_BaseStore):
    """Postgres, for when one application instance is not enough.

    The trigger is the same guarantee as SQLite's. The stronger control is one
    this cannot install for you -- revoke the privileges outright, so the trigger
    is a backstop rather than the only defence:

        REVOKE UPDATE, DELETE ON records FROM custody_app;

    Serialisation is a transaction-scoped advisory lock, which works across
    instances where a process lock does not. It is an optimisation: the unique
    constraint on `prev_hash` is what makes a fork impossible, and a caller who
    loses a race gets `ChainForked` and retries rather than writing a ledger that
    will not verify.

    **A pool, not a connection.** One connection cannot carry two transactions,
    so sharing it across threads makes the advisory lock meaningless -- the
    threads serialise on the connection instead of on the lock, and psycopg
    raises OutOfOrderTransactionNesting when their transactions interleave. CI
    found this by losing 19 of 20 concurrent writes. Each writer now takes its
    own connection, which is also what `custody serve` needs: it is a threading
    HTTP server, and a request handler must not wait on another request's
    transaction.
    """

    placeholder = "%s"

    def __init__(self, dsn: str, *, min_size: int = 1, max_size: int = 16):
        try:
            import psycopg
            from psycopg_pool import ConnectionPool
        except ImportError:  # pragma: no cover - depends on the install extra
            raise RuntimeError(
                "Postgres support needs psycopg -- pip install custody-ledger[postgres]"
            ) from None

        self._psycopg = psycopg
        self.dsn = dsn
        self._pool = ConnectionPool(dsn, min_size=min_size, max_size=max_size,
                                    open=True, timeout=30)
        self._pool.wait(timeout=30)
        with self._pool.connection() as conn, conn.cursor() as cur:
            cur.execute(_PG_SCHEMA)
            for guard in _PG_GUARDS:
                cur.execute(guard)

    def append_chained(self, record: dict[str, Any],
                       seal: Callable[[dict[str, Any], str], dict[str, Any]]) -> dict[str, Any]:
        # One connection, one transaction: take the advisory lock, read the
        # head, insert. Other writers block on the lock rather than on this
        # connection, and the lock is released when the transaction ends --
        # including when it ends badly.
        with self._pool.connection() as conn, conn.cursor() as cur:
            cur.execute("SELECT pg_advisory_xact_lock(%s)", (_ADVISORY_LOCK_KEY,))
            cur.execute("SELECT hash FROM records ORDER BY seq DESC LIMIT 1")
            row = cur.fetchone()
            sealed = seal(record, row[0] if row else GENESIS)
            try:
                cur.execute(self._insert_sql, self._row(sealed))
            except self._psycopg.errors.UniqueViolation as exc:
                if "prev_hash" in str(exc):
                    raise ChainForked(str(exc)) from None
                raise
            return sealed

    def append(self, record: dict[str, Any]) -> None:
        with self._pool.connection() as conn, conn.cursor() as cur:
            cur.execute(self._insert_sql, self._row(record))

    def head_hash(self) -> str:
        with self._pool.connection() as conn, conn.cursor() as cur:
            cur.execute("SELECT hash FROM records ORDER BY seq DESC LIMIT 1")
            row = cur.fetchone()
            return row[0] if row else GENESIS

    def all(self) -> list[dict[str, Any]]:
        return self._rows("SELECT body FROM records ORDER BY seq")

    def by_loan(self, loan: str) -> list[dict[str, Any]]:
        return self._rows("SELECT body FROM records WHERE loan = %s ORDER BY seq", (loan,))

    def query(self, *, loan=None, model=None, principal=None, since=None, until=None):
        where, args = self._where(loan, model, principal, since, until)
        return self._rows(f"SELECT body FROM records{where} ORDER BY seq", tuple(args))

    def loans(self) -> list[str]:
        with self._pool.connection() as conn, conn.cursor() as cur:
            cur.execute("SELECT DISTINCT loan FROM records ORDER BY loan")
            return [r[0] for r in cur.fetchall()]

    def _rows(self, sql: str, args: tuple = ()) -> list[dict[str, Any]]:
        with self._pool.connection() as conn, conn.cursor() as cur:
            cur.execute(sql, args)
            return [json.loads(r[0]) for r in cur.fetchall()]

    def close(self) -> None:
        self._pool.close()


# ------------------------------------------------------------------- factory


def open_store(url: str | Path = ":memory:"):
    """`postgresql://...` gives Postgres; anything else is a SQLite path."""
    text = str(url)
    if text.startswith(("postgres://", "postgresql://")):
        return PostgresStore(text)
    return Store(text)
