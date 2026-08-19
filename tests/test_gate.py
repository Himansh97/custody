"""Gate and redaction tests.

The gate's job is to be right about two opposite mistakes. Letting a fabricated
figure through puts a defect on a loan file. Rejecting a correct extraction
because a paystub writes 8,412.00 and the model writes 8412 trains everyone to
switch the gate off, which is worse — a gate nobody trusts is a gate nobody
runs.
"""
from __future__ import annotations

import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent / "src"))

from custody.redact import redact, redact_value  # noqa: E402
from custody.verify import PASS, REJECT, REVIEW, gate  # noqa: E402

PAYSTUB = "ACME LOGISTICS  Pay period 07/01-07/15  Gross pay 4,206.00  YTD 50,472.00"
W2 = "Wages, tips, other compensation 100,944.00  Federal income tax withheld 18,170.00"
SOURCES = [PAYSTUB, W2]
CITED = {"monthly_income": "paystub-2026-07-15", "annual_income": "w2-2025"}


# --------------------------------------------------------------- figure binding


def test_a_fabricated_figure_is_rejected() -> None:
    """The live failure this check exists for: in CareerOS the model wrote a 35%
    that appeared in no source, and the gate discarded the generation."""
    v = gate(
        {"monthly_income": 9150.00},
        sources=SOURCES,
        citations={"monthly_income": "paystub-2026-07-15"},
        confidence=0.95,
    )
    assert v.treatment == REJECT
    assert any("9150" in f.detail for f in v.findings), v.findings


def test_a_figure_present_in_a_source_passes() -> None:
    v = gate(
        {"annual_income": 100944.00},
        sources=SOURCES,
        citations={"annual_income": "w2-2025"},
        confidence=0.95,
    )
    assert v.treatment == PASS, v.findings


def test_formatting_differences_are_not_fabrication() -> None:
    """8412 vs 8,412.00 is the same figure. A gate that cannot see that gets
    turned off within a week."""
    for claimed in (4206, 4206.0, 4206.00, "4,206.00", "$4,206"):
        v = gate(
            {"gross_pay": claimed},
            sources=SOURCES,
            citations={"gross_pay": "paystub-2026-07-15"},
            confidence=0.95,
        )
        assert v.treatment == PASS, f"{claimed!r} was rejected: {v.findings}"


def test_small_integers_do_not_trip_the_check() -> None:
    """Counts and indices appear in every document. Treating them as claims is
    how a check earns a reputation for crying wolf."""
    v = gate(
        {"documents_reviewed": 3, "annual_income": 100944.00},
        sources=SOURCES,
        citations={"documents_reviewed": "bundle", "annual_income": "w2-2025"},
        confidence=0.95,
    )
    assert v.treatment == PASS, v.findings


# ------------------------------------------------------------------- grounding


def test_an_uncited_field_is_rejected() -> None:
    v = gate({"annual_income": 100944.00}, sources=SOURCES, citations={}, confidence=0.95)
    assert v.treatment == REJECT
    assert any(f.check == "field_grounding" for f in v.findings)


# ------------------------------------------------------------------ vocabulary


def test_a_value_outside_the_allowed_set_is_rejected() -> None:
    v = gate(
        {"doc_type": "Paystub (probably)"},
        sources=SOURCES,
        citations={"doc_type": "bundle"},
        allowed={"doc_type": ["paystub", "w2", "bank_statement"]},
        confidence=0.99,
    )
    assert v.treatment == REJECT
    assert any(f.check == "closed_vocabulary" for f in v.findings)


def test_a_value_inside_the_allowed_set_passes() -> None:
    v = gate(
        {"doc_type": "paystub"},
        sources=SOURCES,
        citations={"doc_type": "bundle"},
        allowed={"doc_type": ["paystub", "w2", "bank_statement"]},
        confidence=0.99,
    )
    assert v.treatment == PASS, v.findings


# ------------------------------------------------------------------ confidence


def test_low_confidence_routes_to_a_human_rather_than_rejecting() -> None:
    """Not being sure is not the same as being wrong."""
    v = gate(
        {"annual_income": 100944.00},
        sources=SOURCES,
        citations=CITED,
        confidence=0.61,
    )
    assert v.treatment == REVIEW, v.findings
    assert v.needs_human and not v.ok


def test_a_missing_confidence_is_treated_as_unsure() -> None:
    v = gate({"annual_income": 100944.00}, sources=SOURCES, citations=CITED)
    assert v.treatment == REVIEW


def test_the_worst_finding_wins() -> None:
    """A reject and a review together is a reject."""
    v = gate({"annual_income": 9150.00}, sources=SOURCES, citations=CITED, confidence=0.10)
    assert v.treatment == REJECT


def test_every_verdict_carries_its_reason() -> None:
    """A verdict with no explanation is the black box the mandate exists to ban."""
    v = gate({"annual_income": 9150.00}, sources=SOURCES, citations=CITED, confidence=0.99)
    assert v.as_dict()["findings"], "rejected with no stated reason"


# -------------------------------------------------------------------- redaction


def test_the_loan_number_survives_redaction() -> None:
    """It is the required query key. A record without it cannot be produced for
    an examiner asking about a loan."""
    text = "Loan 1000254 for Dana Whitfield, SSN 123-45-6789"
    out = redact(text, loan="1000254", identifiers=["Dana Whitfield"])
    assert "1000254" in out
    assert "123-45-6789" not in out
    assert "Dana Whitfield" not in out


def test_a_nine_digit_loan_number_is_not_mistaken_for_an_account() -> None:
    """The account pattern matches any run of nine or more digits, so the loan
    number has to be protected before the patterns run."""
    out = redact("Loan 100025412 balance 4,206.00", loan="100025412")
    assert "100025412" in out, out


def test_patterned_pii_is_replaced_with_a_visible_label() -> None:
    """A blank looks like missing data and invites somebody to go and fill it in."""
    out = redact(
        "call 315-450-7742 or dana@example.com, dob 04/11/1994", loan="1000254"
    )
    for gone in ("315-450-7742", "dana@example.com", "04/11/1994"):
        assert gone not in out
    assert "[PHONE]" in out and "[EMAIL]" in out and "[DOB]" in out


def test_a_short_identifier_does_not_carve_up_ordinary_words() -> None:
    out = redact("gross pay was steady", loan="1", identifiers=["Ro"])
    assert out == "gross pay was steady"


def test_an_identifier_only_matches_whole_words() -> None:
    out = redact("Rose reported gross pay", loan="1", identifiers=["Rose"])
    assert "gross" in out and "Rose" not in out


def test_redaction_reaches_into_nested_values() -> None:
    """Outcomes are dicts, prompts are strings; both land in the record."""
    out = redact_value(
        {"borrower": "Dana Whitfield", "amounts": ["ssn 123-45-6789", 4206.0]},
        loan="1000254",
        identifiers=["Dana Whitfield"],
    )
    assert out["borrower"] == "[BORROWER]"
    assert "123-45-6789" not in out["amounts"][0]
    assert out["amounts"][1] == 4206.0, "a number was mangled by string redaction"


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
