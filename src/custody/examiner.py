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
from .ledger import DENIAL_FIELDS, MANDATE_FIELDS


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
        event = record.get("event")
        if event == "ai_denied":
            # A refused call has no model output, no endpoint and no outcome, so
            # holding it to the full set would report gaps that are the correct
            # state of affairs. What it must still carry is who asked, under
            # which policy, and when.
            for field in DENIAL_FIELDS:
                if record.get(field) in (None, ""):
                    gaps.setdefault(field, []).append(record["record_id"])
            continue
        if event != "ai_decision":
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


def disclosure(ledger, *, requested_by: str = "Fannie Mae") -> dict[str, Any]:
    """The whole-book answer to the clause this library was built for.

    LL-2026-04's disclosure obligation is not per loan. It asks, of the
    seller/servicer, what types of AI/ML are in use, for what purpose and in
    what manner, and what safeguards are implemented. A packet answers that for
    one file; this answers it for everything that ran.

    Assembled from the records rather than from a register somebody maintains,
    because a register is a claim and the records are what happened. The
    consequence is stated in `limits` and not buried: this can only describe AI
    that was routed through Custody, and an inventory built solely from what was
    instrumented is worse than no inventory if it is read as complete.
    """
    records = ledger.records()
    ai = [r for r in records if r.get("event") == "ai_decision"]
    denied = [r for r in records if r.get("event") == "ai_denied"]
    reviews = [r for r in records if r.get("event") == "human_review"]
    attempted = ai + denied

    # "Types of AI/ML used", by the endpoint that answered rather than the name
    # a caller asked for -- the two differ exactly when it matters most.
    models: dict[str, dict[str, Any]] = {}
    for record in attempted:
        name = record.get("model")
        if not name:
            continue
        entry = models.setdefault(
            name, {"model": name, "endpoints": set(), "purposes": set(), "decisions": 0}
        )
        entry["decisions"] += 1
        if record.get("endpoint"):
            entry["endpoints"].add(record["endpoint"])
        entry["purposes"].add(record.get("purpose"))

    # "Purpose and manner of use", with the treatment mix that shows what the
    # safeguards did rather than only that they exist.
    purposes: dict[str, dict[str, Any]] = {}
    for record in attempted:
        name = record.get("purpose") or "(unstated)"
        entry = purposes.setdefault(
            name,
            {"purpose": name, "decisions": 0, "pass": 0, "review": 0, "reject": 0,
             "denied": 0, "committed": 0, "routed_to_human": 0, "overrides": 0,
             "models": set(), "policies": set()},
        )
        entry["decisions"] += 1
        treatment = record.get("response_treatment")
        if treatment in entry:
            entry[treatment] += 1
        disposition = str(record.get("disposition") or "")
        if disposition.startswith("committed"):
            entry["committed"] += 1
        if disposition in ("committed_over_rejection", "committed_without_authority"):
            entry["overrides"] += 1
        if disposition == "routed_to_human":
            entry["routed_to_human"] += 1
        if record.get("model"):
            entry["models"].add(record["model"])
        if record.get("policy_version"):
            entry["policies"].add(record["policy_version"])

    # "Safeguards implemented", evidenced by the checks that actually fired.
    checks: dict[str, int] = {}
    for record in ai:
        for finding in record.get("findings") or []:
            checks[finding.get("check", "?")] = checks.get(finding.get("check", "?"), 0) + 1

    policies = sorted({r.get("policy_version") for r in attempted if r.get("policy_version")})
    ungoverned = sum(1 for r in attempted if r.get("policy_decision") == "unevaluated")
    timestamps = sorted(r["timestamp"] for r in attempted if r.get("timestamp"))

    return {
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "requested_by": requested_by,
        "period": {"first": timestamps[0] if timestamps else None,
                   "last": timestamps[-1] if timestamps else None},
        "totals": {
            "decisions_attempted": len(attempted),
            "decisions_made": len(ai),
            "denied_by_policy": len(denied),
            "human_reviews": len(reviews),
            "loans": len({r.get("loan") for r in attempted}),
        },
        "models": [
            {**entry, "endpoints": sorted(entry["endpoints"]),
             "purposes": sorted(p for p in entry["purposes"] if p)}
            for entry in sorted(models.values(), key=lambda e: e["model"])
        ],
        "purposes": [
            {**entry, "models": sorted(entry["models"]),
             "policies": sorted(entry["policies"])}
            for entry in sorted(purposes.values(), key=lambda e: -e["decisions"])
        ],
        "safeguards": {
            "gate": "deterministic; no model is used to judge another model",
            "checks_that_fired": dict(sorted(checks.items())),
            "policies_in_force": policies,
            "decisions_under_no_evaluated_policy": ungoverned,
            "policy_review": review_status(ledger),
        },
        "integrity": {
            "chain": chain_status(records, ledger.public_key),
            "anchor": ledger.anchor,
            "mandate_coverage": coverage(records),
        },
        "limits": [
            "Covers only AI routed through this ledger. It cannot inventory models "
            "it never saw, and must not be read as a complete list for the "
            "organisation.",
            "Proves the records were not altered. Does not prove they are true, and "
            "cannot show a decision that was never recorded.",
            "No bias or fair-lending testing is performed or claimed.",
        ],
    }


def review_status(ledger) -> dict[str, Any] | None:
    """The ledger's policy review state, or None when no policy document is used."""
    getter = getattr(ledger, "review_status", None)
    return getter() if callable(getter) else None


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
    denied = [r for r in records if r.get("event") == "ai_denied"]

    return {
        "loan": loan,
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "requested_by": requested_by,
        "policy_version": ledger.policy,
        "summary": {
            "ai_decisions": len(ai),
            "human_reviews": len(reviews),
            # Every disposition that wrote something downstream, including the
            # two that did it over an objection. Counting only the clean
            # `committed` would drop an override out of the total and make the
            # numbers disagree with the records under them.
            "committed": sum(
                1 for r in ai if str(r.get("disposition") or "").startswith("committed")
            ),
            "overrides": sum(
                1 for r in ai
                if r.get("disposition") in
                ("committed_over_rejection", "committed_without_authority")
            ),
            "rejected": sum(1 for r in ai if r.get("response_treatment") == "reject"),
            "routed_to_human": sum(1 for r in ai if r.get("disposition") == "routed_to_human"),
            "models_used": sorted({r["model"] for r in ai if r.get("model")}),
            # Calls the policy refused. Reported because a governance record
            # showing only the AI that was permitted is not a record of the
            # controls -- it is a record of the successes.
            "denied_by_policy": len(denied),
        },
        "chain": status,
        # Whether the policy governing this ledger is inside the review interval
        # its owner set. LL-2026-04 requires that review; a packet that says
        # nothing about it lets an overdue policy pass unremarked.
        "policy_review": review_status(ledger),
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
        # The whole-book answer travels with the page. A reviewer who opens this
        # in a browser should see the same thing the CLI prints, or the two
        # drift and one of them starts being the wrong one to quote.
        "disclosure": disclosure(ledger),
    }
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(bundle, fh, indent=1, sort_keys=False, default=str)
    return bundle
