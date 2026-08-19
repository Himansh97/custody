#!/usr/bin/env python3
"""Verify a Custody packet. One file, no installation, nothing to trust but this.

    python3 verify_packet.py packet.json [anchor]

The rest of Custody is a library you would have to take on faith. This file is
deliberately not that: it is short enough to read end to end in a few minutes,
it imports nothing that is not in Python's standard library, and it never
touches the Custody package. If it disagrees with the lender's own tooling,
believe this one.

WHAT IT PROVES

  Hash chain      Every record's hash is recomputed from its contents and the
                  hash of the record before it. Editing a record, deleting one,
                  or reordering two breaks the chain at a point this names.
                  Needs nothing but hashlib.

  Signature       That the records came from the holder of a particular private
                  key, rather than from anyone who happened to have the file and
                  could recompute hashes. Needs the `cryptography` package; if it
                  is absent this says so and checks the chain alone rather than
                  pretending.

WHAT IT DOES NOT PROVE

  That the records are true. Nothing can. A ledger proves that what was written
  has not been altered since -- not that the right thing was written. Anyone who
  tells you otherwise is selling something.

  That records were never *withheld*. A chain that verifies is internally
  consistent; a decision that was never recorded at all leaves no gap to find.
  This is why the capture is structural in the library rather than a call
  somebody remembers to make, but no verifier can see what was never there.

  That the chain is *complete at the end*. Removing a record from the middle
  breaks the link and is reported below. Removing the most recent records
  breaks nothing -- what remains is a shorter chain that verifies perfectly.
  Detecting that requires knowing what the head should have been, which is
  information this file does not have and cannot derive. If completeness
  matters to you, compare the final hash printed below against a head hash
  recorded somewhere the ledger's owner does not control.
"""
import hashlib
import json
import sys

GENESIS = "0" * 64
CHAIN_FIELDS = ("prev_hash", "hash", "signature")


def portable(value):
    """Numbers in the one form every language agrees on.

    Python renders the float 4206.0 as `4206.0` and JavaScript renders it as
    `4206`. Both are correct and they hash differently, so integral floats are
    written as integers. Without this a verifier in one language reports
    tampering on a ledger written by another.
    """
    if isinstance(value, bool):
        return value                        # bool is a subclass of int
    if isinstance(value, float) and value.is_integer():
        return int(value)
    if isinstance(value, dict):
        return {k: portable(v) for k, v in value.items()}
    if isinstance(value, list):
        return [portable(v) for v in value]
    return value


def canonical(record):
    """The exact bytes that were hashed: sorted keys, no spaces, ASCII-escaped."""
    body = {k: portable(v) for k, v in record.items() if k not in CHAIN_FIELDS}
    return json.dumps(
        body, sort_keys=True, separators=(",", ":"), ensure_ascii=True, default=str
    ).encode("utf-8")


def record_hash(record, prev_hash):
    digest = hashlib.sha256()
    digest.update(prev_hash.encode("ascii"))
    digest.update(canonical(record))
    return digest.hexdigest()


def check_signature(public_hex, algorithm, signature_hex, digest_hex):
    """None if signatures cannot be checked here; True/False otherwise."""
    try:
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import ec, ed25519, utils
    except ImportError:
        return None

    raw = bytes.fromhex(public_hex)
    signature = bytes.fromhex(signature_hex)
    digest = bytes.fromhex(digest_hex)
    try:
        if algorithm == "ed25519":
            ed25519.Ed25519PublicKey.from_public_bytes(raw).verify(signature, digest)
        elif algorithm == "ecdsa-p256-sha256":
            if len(signature) != 64:
                return False
            der = utils.encode_dss_signature(
                int.from_bytes(signature[:32], "big"),
                int.from_bytes(signature[32:], "big"),
            )
            ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), raw).verify(
                der, digest, ec.ECDSA(utils.Prehashed(hashes.SHA256()))
            )
        else:
            return False
    except Exception:
        return False
    return True


ANCHOR_PREFIX = "custody-anchor:v1"


def check_anchor(records, token):
    """Compare the packet against an anchor recorded outside the lender.

    This is the only check here that needs something the packet cannot supply.
    A truncated chain verifies -- every remaining link is genuine -- so proving
    nothing was removed from the end means knowing how long it should have been,
    and that fact has to come from somewhere the lender does not control.
    """
    parts = token.strip().split(":")
    if len(parts) != 4 or f"{parts[0]}:{parts[1]}" != ANCHOR_PREFIX:
        print(f"  not a custody anchor: {token!r}")
        return 2
    want_count, want_head = int(parts[2]), parts[3]
    head = records[-1]["hash"] if records else "0" * 64

    if len(records) < want_count:
        print(f"  ANCHOR MISMATCH: this packet has {len(records)} records, the anchor")
        print(f"    attests to {want_count}. {want_count - len(records)} of the newest are")
        print("    missing -- a truncation, which the chain above cannot see.")
        return 1
    at = records[want_count - 1]["hash"] if want_count else "0" * 64
    if at != want_head:
        print(f"  ANCHOR MISMATCH: record {want_count} hashes to {at[:16]}... but the")
        print(f"    anchor recorded {want_head[:16]}... — history was rewritten.")
        return 1
    print(f"  OK  matches the anchor supplied ({want_count} records)")
    return 0


def main(path, anchor=None):
    with open(path, encoding="utf-8") as fh:
        packet = json.load(fh)

    records = packet.get("records") or []
    public_hex = packet.get("public_key")
    if not records:
        print("no records in this packet")
        return 2

    print(f"{path}")
    print(f"  loan            {packet.get('loan', '(whole ledger)')}")
    print(f"  records         {len(records)}")
    print(f"  policy          {packet.get('policy_version', '?')}")
    print(f"  public key      {(public_hex or '(none supplied)')[:32]}...")
    print()

    prev = GENESIS
    signatures_checked = 0
    signatures_skipped = False

    for index, record in enumerate(records):
        rid = record.get("record_id", "?")

        if record.get("prev_hash") != prev:
            print(f"  BROKEN at record {index} ({rid})")
            print("    its prev_hash does not match the record before it -- something was")
            print("    altered, removed, or inserted at or before this point.")
            return 1

        expected = record_hash(record, prev)
        if record.get("hash") != expected:
            print(f"  BROKEN at record {index} ({rid})")
            print("    its contents no longer hash to the value stored with it -- this")
            print("    record was edited after it was written.")
            return 1

        if public_hex and record.get("signature"):
            algorithm = record.get("sig_alg", "ed25519")
            result = check_signature(
                public_hex, algorithm, record["signature"], expected
            )
            if result is None:
                signatures_skipped = True
            elif result is False:
                print(f"  BROKEN at record {index} ({rid})")
                print(f"    its {algorithm} signature does not verify against the public")
                print("    key in this packet.")
                return 1
            else:
                signatures_checked += 1

        prev = record["hash"]

    print(f"  OK  hash chain verified across {len(records)} records")
    if signatures_checked:
        algorithms = sorted({r.get("sig_alg", "ed25519") for r in records})
        print(f"  OK  {signatures_checked} signatures verified ({', '.join(algorithms)})")
    elif signatures_skipped:
        print("  --  signatures NOT checked: the `cryptography` package is not installed.")
        print("      The chain above still proves nothing was altered or removed.")
    elif not public_hex:
        print("  --  signatures NOT checked: no public key in this packet.")

    anchor_status = 0
    if anchor:
        anchor_status = check_anchor(records, anchor)
    else:
        print(f"  --  completeness NOT checked. Anchor for this packet:")
        print(f"      {ANCHOR_PREFIX}:{len(records)}:{prev}")
        print("      A verifying chain does not prove records were not removed from")
        print("      the END; a truncated chain verifies too. Pass an anchor recorded")
        print("      earlier, elsewhere, as the second argument to check that.")

    print()
    print("  This proves the records have not been altered since they were written.")
    print("  It does not prove they are true, and it cannot show a decision that was")
    print("  never recorded in the first place.")
    return anchor_status


if __name__ == "__main__":
    if len(sys.argv) not in (2, 3):
        print(__doc__.strip().split("\n\n")[0])
        print("\nusage: python3 verify_packet.py <packet.json> [anchor]")
        raise SystemExit(2)
    raise SystemExit(main(sys.argv[1], sys.argv[2] if len(sys.argv) == 3 else None))
