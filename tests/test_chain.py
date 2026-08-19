"""Tamper-evidence tests.

A chain that passes on clean data proves nothing on its own — the interesting
question is whether it *fails* on every way a record can be interfered with, and
whether it points at the right one when it does. An examiner asking "has this
been edited?" is owed a specific answer, not a red light.
"""
from __future__ import annotations

import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent / "src"))

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402

from custody.chain import (  # noqa: E402
    GENESIS,
    ChainError,
    canonical,
    compute_hash,
    seal,
    verify_chain,
)

KEY = Ed25519PrivateKey.generate()
PUB = KEY.public_key()


def _chain(n: int = 4) -> list[dict]:
    out: list[dict] = []
    prev = GENESIS
    for i in range(n):
        record = {"record_id": f"r{i}", "seq": i, "loan": "1000254", "payload": f"step {i}"}
        sealed = seal(record, prev, KEY)
        out.append(sealed)
        prev = sealed["hash"]
    return out


def test_a_clean_chain_verifies() -> None:
    verify_chain(_chain(), PUB)


def test_a_chain_verifies_without_the_key() -> None:
    """The browser has the records and no private key. It must still be able to
    answer "was anything changed?" — that is the whole basis of the demo being
    honest rather than a green tick someone drew."""
    verify_chain(_chain())


def test_editing_a_record_is_caught_and_located() -> None:
    records = _chain()
    records[2]["payload"] = "step 2 (quietly changed)"
    try:
        verify_chain(records, PUB)
    except ChainError as exc:
        assert exc.index == 2, f"blamed record {exc.index}, should be 2"
        assert exc.record_id == "r2"
    else:
        raise AssertionError("an edited record verified")


def test_deleting_a_record_is_caught_at_the_gap() -> None:
    records = _chain()
    del records[1]
    try:
        verify_chain(records, PUB)
    except ChainError as exc:
        # Index 1 is now the old record 2, whose prev_hash points at the record
        # that is no longer there.
        assert exc.index == 1, f"blamed record {exc.index}, should be 1"
    else:
        raise AssertionError("a deleted record went unnoticed")


def test_reordering_records_is_caught() -> None:
    records = _chain()
    records[1], records[2] = records[2], records[1]
    try:
        verify_chain(records, PUB)
    except ChainError:
        pass
    else:
        raise AssertionError("a reordered chain verified")


def test_appending_a_forged_record_fails_without_the_key() -> None:
    """Someone holding the file can recompute hashes — that is why the signature
    exists. The chain alone accepts a well-formed forgery; the signature does not."""
    records = _chain()
    forged = {"record_id": "forged", "seq": 99, "loan": "1000254", "payload": "approved"}
    forged["prev_hash"] = records[-1]["hash"]
    forged["hash"] = compute_hash(forged, forged["prev_hash"])
    forged["signature"] = "00" * 64
    records.append(forged)

    verify_chain(records)          # chain continuity alone cannot tell

    try:
        verify_chain(records, PUB)
    except ChainError as exc:
        assert exc.index == len(records) - 1
        assert "signature" in exc.reason
    else:
        raise AssertionError("a forged record passed signature verification")


def test_a_record_signed_by_the_wrong_key_is_rejected() -> None:
    other = Ed25519PrivateKey.generate()
    records = _chain(2)
    records[1]["signature"] = other.sign(bytes.fromhex(records[1]["hash"])).hex()
    try:
        verify_chain(records, PUB)
    except ChainError as exc:
        assert exc.index == 1
    else:
        raise AssertionError("a foreign signature verified")


def test_the_chain_fields_are_not_part_of_their_own_hash() -> None:
    """Otherwise sealing could never terminate."""
    record = {"record_id": "r", "seq": 0, "loan": "1"}
    sealed = seal(record, GENESIS, KEY)
    assert canonical(sealed) == canonical(record)


def test_canonical_form_is_stable_under_key_order() -> None:
    """Two systems that disagree on byte order report tampering that never
    happened — the worst possible false positive for this product."""
    a = {"loan": "1", "seq": 2, "record_id": "r"}
    b = {"record_id": "r", "loan": "1", "seq": 2}
    assert canonical(a) == canonical(b)
    assert compute_hash(a, GENESIS) == compute_hash(b, GENESIS)


def test_genesis_must_be_the_first_prev_hash() -> None:
    record = {"record_id": "r0", "seq": 0}
    sealed = seal(record, "ab" * 32, KEY)   # sealed against something that isn't genesis
    try:
        verify_chain([sealed], PUB)
    except ChainError as exc:
        assert exc.index == 0
    else:
        raise AssertionError("a chain starting mid-air verified")


def test_numbers_are_serialised_in_a_form_javascript_also_produces() -> None:
    """Python writes the float 4206.0 as `4206.0`; JavaScript writes `4206`.

    If the two disagree, the browser verifier reports a broken chain on a
    perfectly good ledger — which would discredit the one signal this product
    sells. Integral floats are emitted as integers so both agree.
    """
    out = canonical({"a": 4206.0, "b": 8200.83, "c": 0.0, "d": True, "e": [1.0, 2.5]})
    assert b'"a":4206' in out and b'"a":4206.0' not in out
    assert b'"b":8200.83' in out
    assert b'"c":0' in out
    assert b'"d":true' in out, "a bool was flattened into an int"
    assert b'"e":[1,2.5]' in out


def test_non_ascii_is_escaped_rather_than_emitted_raw() -> None:
    """Byte-level agreement across languages depends on it."""
    out = canonical({"note": "resum\u00e9"})
    assert b"\\u00e9" in out
    assert "é".encode("utf-8") not in out


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
