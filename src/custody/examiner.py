"""The artifact an examiner actually asks for.

Everything else exists so that this function can answer one question honestly:
*what did your AI do to loan 1000254, and who checked it?*

The packet is deliberately self-contained. It carries the records, the public
key, and the verification result, so the recipient does not need access to the
lender's systems — or to trust the lender's word — to check it. That property is
the entire value: an audit artifact you have to take on faith is a letter, not
evidence.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .chain import ChainError, verify_chain
from .ledger import MANDATE_FIELDS


def chain_status(records: list[dict[str, Any]], public_key: Ed25519PublicKey | None) -> dict:
    """Verify, and report the break rather than just the failure."""
    try:
        verify_chain(records, public_key)
    except ChainError as exc:
        return {
            "verified": False,
            "broken_at": exc.index,
            "record_id": exc.record_id,
            "reason": exc.reason,
        }
    return {"verified": True, "records": len(records)}


def coverage(records: list[dict[str, Any]]) -> dict[str, Any]:
    """Which mandate fields are missing, on which records.

    Reported rather than assumed. A packet that quietly omits `policy_version`
    on three records is the kind of thing that surfaces during an audit instead
    of before one, so it is surfaced here first — as a number the lender can act
    on, not a pass/fail nobody can debug.
    """
    gaps: dict[str, list[str]] = {}
    for record in records:
        if record.get("event") != "ai_decision":
            continue
        for field in MANDATE_FIELDS:
            # decision_outcome is legitimately null when a decision was rejected
            # or routed rather than committed — nothing was written downstream,
            # and inventing a value to fill the field would be the lie.
            if field == "decision_outcome" and record.get("disposition") != "committed":
                continue
            if record.get(field) in (None, ""):
                gaps.setdefault(field, []).append(record["record_id"])
    return {"complete": not gaps, "missing": gaps}


def packet(
    ledger, loan: str, *, requested_by: str = "examiner"
) -> dict[str, Any]:
    """The full chain of evidence for one loan."""
    records = ledger.for_loan(loan)
    full = ledger.records()

    # Verified against the *whole* ledger, not just this loan's slice. A per-loan
    # slice has gaps in it by construction — the records between belong to other
    # loans — and verifying the slice alone would report every honest ledger as
    # broken.
    status = chain_status(full, ledger.public_key)

    ai = [r for r in records if r.get("event") == "ai_decision"]
    reviews = [r for r in records if r.get("event") == "human_review"]

    return {
        "loan": loan,
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "requested_by": requested_by,
        "policy_version": ledger.policy,
        "summary": {
            "ai_decisions": len(ai),
            "human_reviews": len(reviews),
            "committed": sum(1 for r in ai if r.get("disposition") == "committed"),
            "rejected": sum(1 for r in ai if r.get("response_treatment") == "reject"),
            "routed_to_human": sum(1 for r in ai if r.get("disposition") == "routed_to_human"),
            "models_used": sorted({r["model"] for r in ai if r.get("model")}),
        },
        "chain": status,
        "mandate_coverage": coverage(records),
        "records": records,
        "public_key": ledger.public_key_hex,
        "sig_alg": ledger.algorithm,
    }


def export(ledger, path: str, *, loans: list[str] | None = None) -> dict[str, Any]:
    """Write the whole ledger plus per-loan packets to one JSON file.

    This is what the browser demo loads. Shipping the real records and the real
    public key means the page can recompute the hashes itself — the verification
    a visitor watches is genuine, not a green tick drawn next to a picture.
    """
    records = ledger.records()
    loans = loans or sorted({r["loan"] for r in records})
    bundle = {
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "policy_version": ledger.policy,
        "public_key": ledger.public_key_hex,
        "sig_alg": ledger.algorithm,
        "chain": chain_status(records, ledger.public_key),
        "records": records,
        "packets": {loan: packet(ledger, loan) for loan in loans},
    }
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(bundle, fh, indent=1, sort_keys=False, default=str)
    return bundle
