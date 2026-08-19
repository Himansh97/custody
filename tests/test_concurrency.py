"""Concurrent writers must not fork the chain.

Appending is a read-modify-write: read the head hash, seal against it, insert.
If two threads interleave there, both seal against the same predecessor and the
ledger ends up with two records claiming the same `prev_hash` -- a fork, which
verification correctly rejects, on a ledger where nobody did anything wrong.

Found by running `custody serve` from a built wheel: ThreadingHTTPServer handed
a request to a second thread and SQLite refused the cross-thread access. The
threading complaint was the symptom; the fork was the bug underneath it.
"""
from __future__ import annotations

import pathlib
import sys
import threading

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent / "src"))

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402

from custody.chain import verify_chain  # noqa: E402
from custody.ledger import Ledger  # noqa: E402

PAYSTUB = "Gross pay 4,206.00  YTD 50,472.00"


def _write(ledger: Ledger, n: int) -> None:
    with ledger.decision(loan=f"loan-{n % 3}", principal="t@x.example",
                         purpose="income") as d:
        out = d.call(model="m", prompt="p", sources=[PAYSTUB], response={"gross": 4206.00})
        d.gate(out, citations={"gross": "paystub"}, confidence=0.95)
        d.commit(outcome=out)


def test_the_chain_survives_concurrent_writers() -> None:
    ledger = Ledger(policy="p", signing_key=Ed25519PrivateKey.generate())

    threads = [threading.Thread(target=_write, args=(ledger, i)) for i in range(40)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    records = ledger.records()
    assert len(records) == 40, f"lost writes: {len(records)} of 40"

    # The real assertion: no two records share a predecessor.
    prevs = [r["prev_hash"] for r in records]
    assert len(set(prevs)) == len(prevs), "the chain forked -- two records share a prev_hash"

    verify_chain(records, ledger.public_key)


def test_reads_and_writes_can_interleave() -> None:
    """`custody serve` reads on request threads while a pipeline may be writing."""
    ledger = Ledger(policy="p", signing_key=Ed25519PrivateKey.generate())
    errors: list[BaseException] = []

    def reader() -> None:
        try:
            for _ in range(30):
                ledger.records()
                ledger.for_loan("loan-1")
        except BaseException as exc:      # noqa: BLE001 - the point is to catch anything
            errors.append(exc)

    def writer() -> None:
        try:
            for i in range(30):
                _write(ledger, i)
        except BaseException as exc:      # noqa: BLE001
            errors.append(exc)

    threads = [threading.Thread(target=reader), threading.Thread(target=writer),
               threading.Thread(target=reader)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert not errors, f"concurrent access raised: {errors[0]!r}"
    verify_chain(ledger.records(), ledger.public_key)


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
