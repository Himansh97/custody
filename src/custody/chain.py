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

from .signing import ED25519, LocalSigner, verify_signature

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


def seal(record: dict[str, Any], prev_hash: str, signer) -> dict[str, Any]:
    """Attach the algorithm, prev_hash, hash and signature. Returns a new dict.

    `sig_alg` goes into the record *body*, so it is covered by the hash. An
    attacker who could rewrite it freely could claim a record was signed with
    something weaker than it was; here that claim breaks the chain before anyone
    gets as far as checking a signature.

    A raw private key is still accepted for callers written against the earlier
    signature, and is wrapped in a LocalSigner.
    """
    if not hasattr(signer, "sign") or not hasattr(signer, "algorithm"):
        signer = LocalSigner(signer, ED25519)

    body = dict(record)
    body["sig_alg"] = signer.algorithm

    sealed = dict(body)
    sealed["prev_hash"] = prev_hash
    sealed["hash"] = compute_hash(body, prev_hash)
    sealed["signature"] = signer.sign(bytes.fromhex(sealed["hash"])).hex()
    return sealed


class ChainError(Exception):
    """Raised by `verify_chain` when a chain does not hold."""

    def __init__(self, index: int, record_id: str | None, reason: str):
        self.index = index
        self.record_id = record_id
        self.reason = reason
        where = f"record {index}" + (f" ({record_id})" if record_id else "")
        super().__init__(f"{where}: {reason}")


def verify_chain(records: Iterable[dict[str, Any]], public_key=None) -> None:
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
            algorithm = record.get("sig_alg", ED25519)
            if not verify_signature(
                public_key, bytes.fromhex(signature), bytes.fromhex(expected), algorithm
            ):
                raise ChainError(
                    index, rid,
                    f"signature ({algorithm}) does not verify against this key",
                ) from None

        prev = record["hash"]


# --------------------------------------------------------------------- anchors
#
# A hash chain proves each record follows the one before it. That catches an
# edit, a removal from the middle, a reordering -- but not a truncation. Delete
# the newest three records and what is left is a shorter chain that verifies
# perfectly: there is no gap, because a gap is a link pointing at something that
# is not there, and the end of a chain points at nothing by definition.
#
# No amount of cleverness inside the ledger closes that. The missing information
# is *how long the chain should be*, and a file cannot testify to its own
# completeness -- whoever can delete the records can delete the count.
#
# So the fix is to put that one fact somewhere the ledger's owner does not
# control. An anchor is that fact, small enough to email, paste into a ticket,
# commit to a separate repo, or push to an append-only bucket:
#
#     custody-anchor:v1:6:0cf2c799d2d5a25dc29857eac3724cb3f11e36d3b50764038b33f34dda870cd9
#
# Hold one from last month and a truncation performed since is arithmetic: the
# ledger is shorter than the anchor says, or its head is not the hash you kept.

ANCHOR_PREFIX = "custody-anchor:v1"


class AnchorError(Exception):
    """The ledger does not match an anchor recorded outside it."""


def make_anchor(count: int, head: str) -> str:
    """The smallest fact that makes truncation detectable: how many, and last hash."""
    return f"{ANCHOR_PREFIX}:{int(count)}:{head}"


def parse_anchor(token: str) -> tuple[int, str]:
    parts = (token or "").strip().split(":")
    if len(parts) != 4 or f"{parts[0]}:{parts[1]}" != ANCHOR_PREFIX:
        raise ValueError(f"not a custody anchor: {token!r}")
    try:
        count = int(parts[2])
    except ValueError:
        raise ValueError(f"anchor has a non-numeric count: {token!r}") from None
    return count, parts[3]


def anchor_for(records) -> str:
    """The anchor a ledger currently attests to. Record it somewhere else."""
    records = list(records)
    head = records[-1]["hash"] if records else GENESIS
    return make_anchor(len(records), head)


def check_anchor(records, expected: str) -> None:
    """Compare a ledger against an anchor kept outside it.

    Deliberately separate from `verify_chain`: that function answers "was this
    altered", which needs nothing but the records, and this one answers "is this
    all of it", which cannot be answered from the records alone. Collapsing them
    would suggest the second question is free, and it is not -- it costs you an
    anchor, recorded somewhere else, in advance.
    """
    want_count, want_head = parse_anchor(expected)
    records = list(records)
    head = records[-1]["hash"] if records else GENESIS

    if len(records) < want_count:
        raise AnchorError(
            f"the ledger has {len(records)} records but the anchor attests to "
            f"{want_count} — {want_count - len(records)} of the newest records are "
            "missing. This is a truncation; the remaining chain verifies because a "
            "truncated chain always does."
        )
    if len(records) == want_count and head != want_head:
        raise AnchorError(
            f"the ledger has the expected {want_count} records but its head hash is "
            f"{head[:16]}… where the anchor says {want_head[:16]}… — the ledger was "
            "rewritten, not merely appended to."
        )
    if len(records) > want_count:
        # Growth is normal. What must still hold is that the anchored record is
        # exactly where it was: a rewrite of history followed by fresh appends
        # would leave the count larger and the anchored position wrong.
        at = records[want_count - 1]["hash"] if want_count else GENESIS
        if at != want_head:
            raise AnchorError(
                f"record {want_count} of this ledger hashes to {at[:16]}… but the "
                f"anchor recorded {want_head[:16]}… at that position — history before "
                "the anchor was rewritten."
            )
