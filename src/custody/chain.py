"""The tamper-evidence layer: hash chaining and signatures.

Everything else in Custody is bookkeeping. This module is the part that makes a
record mean something to an examiner, so it is deliberately small and has no
dependency on the rest of the package.

Two independent guarantees, and they answer different questions:

* **The chain** answers "was anything changed or removed after the fact?" Each
  record's hash covers the previous record's hash, so altering record 4 breaks
  5, 6 and 7 as well. Deleting a record breaks the link across the gap. This is
  verifiable by anyone with the records and a SHA-256 implementation — including
  a browser, which is why the demo can re-verify honestly with no server.

* **The signature** answers "did this come from the system that claims to have
  written it?" A chain alone can be recomputed wholesale by whoever holds the
  file; an Ed25519 signature over each record's hash cannot, without the private
  key.

The hash deliberately covers only the *content* fields. `prev_hash`, `hash` and
`signature` are excluded because they cannot be inputs to their own computation.
"""
from __future__ import annotations

import hashlib
import json
from typing import Any, Iterable

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

# The prev_hash of the first record in a chain. Sixty-four zeroes is a value no
# SHA-256 digest can collide with in practice, so "is this genesis?" needs no
# separate flag that someone could forge.
GENESIS = "0" * 64

# Fields that are *about* the chain rather than part of the record's meaning.
# They are excluded from the hash input; the rest of the record is covered.
_CHAIN_FIELDS = frozenset({"prev_hash", "hash", "signature"})


def _portable(value: Any) -> Any:
    """Normalise numbers so another language produces the same bytes.

    Python renders the float 4206.0 as `4206.0`; JavaScript renders the same
    value as `4206`. Nothing has been tampered with, but the hashes differ, and
    a verifier written in the other language reports a broken chain on a
    perfectly good ledger — the worst failure this product could have, because
    it destroys trust in the one signal it sells.

    Integral floats are therefore emitted as integers, which is the form both
    languages agree on. Fractional values already round-trip identically under
    both shortest-representation rules. Exponent-range floats do not, and money
    never lives there; if a caller needs that range they should be carrying a
    string or a Decimal, and `default=str` below keeps a Decimal working.
    """
    if isinstance(value, bool):
        return value                      # bool is an int subclass — check first
    if isinstance(value, float) and value.is_integer():
        return int(value)
    if isinstance(value, dict):
        return {k: _portable(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_portable(v) for v in value]
    return value


def canonical(record: dict[str, Any]) -> bytes:
    """The exact bytes that get hashed.

    Canonicalisation matters more than it looks. Two systems must agree on these
    bytes or verification fails for reasons that have nothing to do with
    tampering — so key order is sorted, separators are fixed, numbers are put in
    a portable form, and non-ASCII is escaped rather than emitted raw.
    `default=str` keeps a stray datetime or Decimal from raising here, where the
    failure would surface as a corrupted chain rather than the serialisation bug
    it actually is.
    """
    body = {k: _portable(v) for k, v in record.items() if k not in _CHAIN_FIELDS}
    return json.dumps(
        body, sort_keys=True, separators=(",", ":"), ensure_ascii=True, default=str
    ).encode("utf-8")


def compute_hash(record: dict[str, Any], prev_hash: str) -> str:
    """SHA-256 over the previous hash followed by this record's canonical bytes.

    The previous hash is mixed in as raw text rather than being stored inside the
    body, so a record's own content stays readable without chain plumbing in the
    middle of it.
    """
    digest = hashlib.sha256()
    digest.update(prev_hash.encode("ascii"))
    digest.update(canonical(record))
    return digest.hexdigest()


def seal(record: dict[str, Any], prev_hash: str, key: Ed25519PrivateKey) -> dict[str, Any]:
    """Attach prev_hash, hash and signature. Returns a new dict."""
    sealed = dict(record)
    sealed["prev_hash"] = prev_hash
    sealed["hash"] = compute_hash(record, prev_hash)
    sealed["signature"] = key.sign(bytes.fromhex(sealed["hash"])).hex()
    return sealed


class ChainError(Exception):
    """Raised by `verify_chain` when a chain does not hold."""

    def __init__(self, index: int, record_id: str | None, reason: str):
        self.index = index
        self.record_id = record_id
        self.reason = reason
        where = f"record {index}" + (f" ({record_id})" if record_id else "")
        super().__init__(f"{where}: {reason}")


def verify_chain(
    records: Iterable[dict[str, Any]], public_key: Ed25519PublicKey | None = None
) -> None:
    """Recompute the whole chain from genesis. Raises `ChainError` on the first break.

    Naming *which* record broke is the point. "Verification failed" tells an
    examiner nothing and tells an engineer less; the first broken link is where
    the investigation starts, and everything after it is unreliable rather than
    independently suspect.

    `public_key` is optional so a verifier holding only the records can still
    check continuity — which is exactly the browser's position in the demo.
    """
    prev = GENESIS
    for index, record in enumerate(records):
        rid = record.get("record_id")

        stored_prev = record.get("prev_hash")
        if stored_prev != prev:
            raise ChainError(
                index, rid,
                f"prev_hash is {stored_prev!r}, expected {prev!r} — a record was "
                "altered, removed, or inserted before this point",
            )

        expected = compute_hash(record, prev)
        if record.get("hash") != expected:
            raise ChainError(
                index, rid, "content does not match its hash — this record was altered"
            )

        if public_key is not None:
            signature = record.get("signature")
            if not signature:
                raise ChainError(index, rid, "no signature")
            try:
                public_key.verify(bytes.fromhex(signature), bytes.fromhex(expected))
            except (InvalidSignature, ValueError):
                raise ChainError(
                    index, rid, "signature does not verify against this key"
                ) from None

        prev = record["hash"]
