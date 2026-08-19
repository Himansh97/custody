"""One conformance suite, run against every backend.

Two storage backends are two chances for them to disagree, and a disagreement
here is not a bug in a feature -- it is a ledger that verifies on one deployment
and not on another. So the assertions live in one place and both backends face
exactly the same ones.

SQLite always runs. Postgres runs when CUSTODY_TEST_DSN points at a database,
and is skipped loudly otherwise, because a silently-skipped database test reads
identically to a passing one.

    CUSTODY_TEST_DSN=postgresql://custody:custody@localhost/custody python3 tests/test_store_backends.py
"""
from __future__ import annotations

import os
import pathlib
import sys
import tempfile
import threading

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent / "src"))

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402

from custody.chain import GENESIS, verify_chain  # noqa: E402
from custody.ledger import Ledger  # noqa: E402
from custody.signing import load_public_key  # noqa: E402
from custody.store import ChainForked, PostgresStore, Store, open_store  # noqa: E402

DSN = os.environ.get("CUSTODY_TEST_DSN")
PAYSTUB = "Gross pay 4,206.00  YTD 50,472.00"


# ------------------------------------------------------------------ fixtures


def _sqlite():
    return Store(":memory:")


def _postgres():
    store = PostgresStore(DSN)
    # Each test starts from an empty ledger. TRUNCATE rather than DELETE
    # precisely because the append-only trigger is row-level and would abort a
    # DELETE -- which is the point of the trigger, and is asserted below.
    with store._db.cursor() as cur:
        cur.execute("TRUNCATE records RESTART IDENTITY")
    return store


def _ledger(store):
    return Ledger(policy="income-calc-v3", signing_key=Ed25519PrivateKey.generate(),
                  store=store)


def _public(ledger):
    return load_public_key(ledger.signer.public_key_bytes(), ledger.algorithm)


def _write(ledger, n):
    with ledger.decision(loan=f"loan-{n % 3}", principal="t@x.example",
                         purpose="income") as d:
        out = d.call(model="m", prompt="p", sources=[PAYSTUB], response={"gross": 4206.00})
        d.gate(out, citations={"gross": "paystub"}, confidence=0.95)
        d.commit(outcome=out)


# --------------------------------------------------------------- conformance


def check_empty_ledger_heads_at_genesis(store):
    assert store.head_hash() == GENESIS


def check_records_come_back_in_order(store):
    ledger = _ledger(store)
    for i in range(5):
        _write(ledger, i)
    records = store.all()
    assert len(records) == 5
    verify_chain(records, _public(ledger))
    prev = GENESIS
    for record in records:
        assert record["prev_hash"] == prev
        prev = record["hash"]


def check_query_filters(store):
    ledger = _ledger(store)
    for i in range(6):
        _write(ledger, i)
    assert sorted(store.loans()) == ["loan-0", "loan-1", "loan-2"]
    assert len(store.by_loan("loan-0")) == 2
    assert len(store.query(loan="loan-1")) == 2
    assert len(store.query(principal="t@x.example")) == 6
    assert store.query(loan="loan-1", principal="nobody@x.example") == []


def check_update_is_refused(store):
    """The trigger, not a code review, is what makes this append-only."""
    _write(_ledger(store), 0)
    try:
        with _cursor(store) as (cur, mark):
            cur.execute(f"UPDATE records SET body = {mark}", ("tampered",))
    except Exception as exc:
        assert "append-only" in str(exc), f"refused, but not by our trigger: {exc}"
    else:
        raise AssertionError("an UPDATE against the ledger succeeded")


def check_delete_is_refused(store):
    _write(_ledger(store), 0)
    try:
        with _cursor(store) as (cur, mark):
            cur.execute("DELETE FROM records")
    except Exception as exc:
        assert "append-only" in str(exc), f"refused, but not by our trigger: {exc}"
    else:
        raise AssertionError("a DELETE against the ledger succeeded")


def check_the_chain_cannot_fork(store):
    """The unique constraint, not the lock, is the guarantee.

    Sealing twice against the same predecessor is exactly what two application
    instances do when they race. The second insert must be refused -- a lock
    cannot promise this across processes, and a UNIQUE constraint can.
    """
    ledger = _ledger(store)
    _write(ledger, 0)
    head = store.head_hash()

    from custody.chain import seal
    first = seal({"record_id": "a", "loan": "L", "timestamp": "t",
                  "principal": "p", "model": "m"}, head, ledger.signer)
    second = seal({"record_id": "b", "loan": "L", "timestamp": "t",
                   "principal": "p", "model": "m"}, head, ledger.signer)
    store.append(first)
    try:
        store.append(second)
    except Exception as exc:
        assert "prev_hash" in str(exc) or isinstance(exc, ChainForked), \
            f"refused for the wrong reason: {exc}"
    else:
        raise AssertionError("two records chained onto the same predecessor")


def check_concurrent_writers_do_not_fork(store):
    ledger = _ledger(store)
    threads = [threading.Thread(target=_write, args=(ledger, i)) for i in range(20)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    records = store.all()
    assert len(records) == 20, f"lost writes: {len(records)} of 20"
    verify_chain(records, _public(ledger))


CHECKS = [v for k, v in sorted(globals().items()) if k.startswith("check_")]


def _cursor(store):
    """Raw cursor plus the backend's placeholder, for the tamper attempts."""
    import contextlib

    @contextlib.contextmanager
    def sqlite_cursor():
        yield store._db, "?"

    @contextlib.contextmanager
    def pg_cursor():
        with store._db.cursor() as cur:
            yield cur, "%s"

    return (pg_cursor if isinstance(store, PostgresStore) else sqlite_cursor)()


# ------------------------------------------------------------------- drivers


def _run(label, make_store):
    failures = 0
    for check in CHECKS:
        store = make_store()
        try:
            check(store)
            print(f"PASS [{label}] {check.__name__}")
        except Exception as exc:
            failures += 1
            print(f"FAIL [{label}] {check.__name__}: {exc}")
        finally:
            store.close()
    return failures


def test_sqlite_backend():
    assert _run("sqlite", _sqlite) == 0


def test_postgres_backend():
    if not DSN:
        print("SKIP [postgres] CUSTODY_TEST_DSN is not set -- Postgres was NOT tested")
        return
    assert _run("postgres", _postgres) == 0


def test_open_store_routes_on_the_url():
    with tempfile.TemporaryDirectory() as tmp:
        store = open_store(pathlib.Path(tmp) / "l.db")
        assert isinstance(store, Store)
        store.close()
    assert isinstance(open_store(":memory:"), Store)
    # A postgresql:// url must not fall through to SQLite and quietly create a
    # file called "postgresql:" -- which is what a startswith() typo would do.
    try:
        open_store("postgresql://nobody@127.0.0.1:1/none")
    except Exception as exc:
        assert not isinstance(exc, TypeError), exc
    else:
        raise AssertionError("a dsn pointing nowhere connected successfully")
    assert not pathlib.Path("postgresql:").exists()


if __name__ == "__main__":
    failures = 0
    failures += _run("sqlite", _sqlite)
    if DSN:
        failures += _run("postgres", _postgres)
    else:
        print("\nSKIP [postgres] CUSTODY_TEST_DSN is not set -- Postgres was NOT tested")
    try:
        test_open_store_routes_on_the_url()
        print("PASS [both]   open_store routes on the url")
    except AssertionError as exc:
        failures += 1
        print(f"FAIL [both]   open_store routes on the url: {exc}")
    print(f"\n{failures} failure(s)")
    raise SystemExit(1 if failures else 0)
