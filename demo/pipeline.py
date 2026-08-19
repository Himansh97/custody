"""A synthetic loan file moving through an AI pipeline, recorded end to end.

Everything here is fabricated — the borrower, the employer, the documents, the
loan number. There is no real PII in this repository and never will be.

The model outputs are fixed rather than live. That is deliberate, not a
shortcut: the point of the demo is the *record*, and a record anyone can
reproduce byte-for-byte by running this file is worth more than one that depends
on a model happening to return the same thing twice. The gate does not know or
care where the output came from.

The middle step is the one to watch. The model returns a monthly income figure
that appears in none of the documents it was given — a plausible-looking number,
arrived at by a plausible-looking route, and simply wrong. The gate rejects it,
a named underwriter corrects it, and all three events land in the chain. That
sequence is what a lender has to be able to show a GSE: not that the AI was
right, but that when it was wrong, somebody caught it and the record proves it.
"""
from __future__ import annotations

import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402

from custody.examiner import export  # noqa: E402
from custody.ledger import Ledger  # noqa: E402

FIXTURES = pathlib.Path(__file__).resolve().parent / "fixtures"
LOAN = "1000254"
BORROWER = "Dana Whitfield"          # fabricated
UNDERWRITER = "sam.okafor@northgate-lending.example"
PROCESSOR = "jane.mireles@northgate-lending.example"

# A fixed key so the committed ledger.json verifies for anyone who clones this
# repo. A real deployment keeps its private key in a KMS and never in source —
# said here rather than left for a reader to assume we did not know.
DEMO_SEED = bytes.fromhex(
    "9f2c41d7a86b35e0c4197fd2b8e5a30716c9d4f83b2e6a05d19c7382fe4b60a1"
)


def read(name: str) -> str:
    return (FIXTURES / name).read_text(encoding="utf-8")


def run(path: str = str(ROOT / "demo" / "ledger.json")) -> dict:
    paystub = read("paystub-2026-07-15.txt")
    w2 = read("w2-2025.txt")
    bank = read("bank-statement-2026-06.txt")

    ledger = Ledger(
        policy="northgate-uw-policy-v3.2",
        signing_key=Ed25519PrivateKey.from_private_bytes(DEMO_SEED),
    )
    ids = [BORROWER]

    # --- 1. Document classification ------------------------------------------
    # Routine, correct, and committed. Most of the log looks like this, which is
    # the point: the interesting records are only legible against a normal one.
    with ledger.decision(loan=LOAN, principal=PROCESSOR, purpose="document_classification",
                         identifiers=ids) as d:
        out = d.call(
            model="claude-haiku-4-5",
            prompt=f"Classify each document in this bundle.\n\n{paystub[:200]}...",
            sources=[paystub, w2, bank],
            response={"doc_type": "paystub"},
        )
        v = d.gate(
            out,
            citations={"doc_type": "paystub-2026-07-15"},
            allowed={"doc_type": ["paystub", "w2", "bank_statement", "1003", "unknown"]},
            confidence=0.97,
        )
        if v.ok:
            d.commit(outcome=out)

    # --- 2. Income extraction — the model invents a figure --------------------
    # 6,842.00 is not in the paystub, the W-2 or the bank statement. It is the
    # shape of an answer rather than an answer, and nothing downstream of the
    # gate could tell the difference.
    with ledger.decision(loan=LOAN, principal=PROCESSOR, purpose="income_calculation",
                         identifiers=ids) as d:
        out = d.call(
            model="claude-sonnet-5",
            prompt=(
                f"Borrower {BORROWER}, loan {LOAN}. Compute qualifying monthly income "
                f"from the attached paystub and W-2.\n\n{paystub}\n\n{w2}"
            ),
            sources=[paystub, w2],
            response={"monthly_income": 6842.00, "basis": "averaged base plus overtime"},
        )
        v = d.gate(out, citations={"monthly_income": "paystub-2026-07-15",
                                   "basis": "paystub-2026-07-15"}, confidence=0.91)
        assert v.treatment == "reject", "the demo's central failure did not fire"
        d.route_to_human(queue="uw-review",
                         note="figure binding rejected the extracted income")
        rejected_id = d.record_id

    # --- 3. A human corrects it ----------------------------------------------
    # The W-2 says 98,410.00 for the year. That figure is in a document, so it is
    # checkable — which is the whole difference between this record and the one
    # above it.
    correction_id = ledger.human_review(
        loan=LOAN, reviewer=UNDERWRITER, decision_id=rejected_id, action="corrected",
        outcome={"monthly_income": 8200.83, "basis": "W-2 box 1 98,410.00 / 12"},
        note="Model figure appears in no document. Recomputed from the W-2 and verified "
             "against the paystub YTD.",
        identifiers=ids,
    )
    # The underwriter's finding is now itself citable evidence. 8,200.83 is a
    # derived figure and appears in no document, so without this it would be
    # indistinguishable from the invention the gate just caught — which is
    # correct, and is why a human establishing a basis has to enter the record
    # as a source rather than as a conversation nobody can find later.
    correction_basis = (
        f"custody record {correction_id} — human review by {UNDERWRITER}: "
        "qualifying monthly income 8,200.83, basis W-2 box 1 98,410.00 / 12"
    )

    # --- 4. Condition clearing — right, but not sure --------------------------
    # Low confidence is not evidence of being wrong. It routes to a person
    # instead of being rejected, which is what the mandate's human-in-the-loop
    # expectation actually asks for.
    with ledger.decision(loan=LOAN, principal=PROCESSOR, purpose="condition_clearing",
                         identifiers=ids) as d:
        out = d.call(
            model="claude-sonnet-5",
            prompt=f"Does the bank statement evidence the payroll deposits?\n\n{bank}",
            sources=[bank, paystub],
            response={"condition_status": "satisfied", "deposits_matched": 3190.24},
        )
        v = d.gate(
            out,
            citations={"condition_status": "bank-statement-2026-06",
                       "deposits_matched": "bank-statement-2026-06"},
            allowed={"condition_status": ["satisfied", "not_satisfied", "needs_review"]},
            confidence=0.62,
        )
        d.route_to_human(queue="processor-review",
                         note="confidence below the policy floor")
        low_confidence_id = d.record_id

    ledger.human_review(
        loan=LOAN, reviewer=PROCESSOR, decision_id=low_confidence_id, action="approved",
        outcome={"condition_status": "satisfied"},
        note="Two payroll deposits of 3,190.24 visible on the June statement.",
        identifiers=ids,
    )

    # --- 5. Final write to the LOS -------------------------------------------
    with ledger.decision(loan=LOAN, principal=PROCESSOR, purpose="los_write",
                         identifiers=ids) as d:
        out = d.call(
            model="claude-sonnet-5",
            prompt="Assemble the verified income figures for the LOS write.",
            sources=[w2, paystub, correction_basis],
            response={"qualifying_monthly_income": 8200.83, "annual_income": 98410.00},
        )
        v = d.gate(
            out,
            citations={
                "qualifying_monthly_income": correction_id,   # cites the human, by record id
                "annual_income": "w2-2025",
            },
            confidence=0.99,
        )
        assert v.ok, f"the final write should pass on human-established evidence: {v.findings}"
        d.commit(outcome=out)

    bundle = export(ledger, path)
    return bundle


if __name__ == "__main__":
    out = run()
    print(f"records:        {len(out['records'])}")
    print(f"chain verified: {out['chain']['verified']}")
    print(f"policy:         {out['policy_version']}")
    for loan, pkt in out["packets"].items():
        s = pkt["summary"]
        print(
            f"loan {loan}: {s['ai_decisions']} AI decisions, {s['human_reviews']} human "
            f"reviews, {s['rejected']} rejected, {s['routed_to_human']} routed"
        )
        print(f"  mandate coverage complete: {pkt['mandate_coverage']['complete']}")
