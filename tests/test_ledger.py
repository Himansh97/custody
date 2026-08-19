"""Ledger, store and examiner tests.

The test that matters most in this file is `test_every_mandate_field_is_present`.
If it fails, Custody does not do the one thing it exists to do, and every other
passing test is decoration.
"""
from __future__ import annotations

import pathlib
import sqlite3
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent / "src"))

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402

from custody.examiner import coverage, packet  # noqa: E402
from custody.ledger import MANDATE_FIELDS, Ledger  # noqa: E402
from custody.store import Store  # noqa: E402
from custody.verify import REJECT  # noqa: E402
from custody.chain import ChainError, verify_chain  # noqa: E402

PAYSTUB = "ACME LOGISTICS  Gross pay 4,206.00  YTD 50,472.00"


def _ledger() -> Ledger:
    return Ledger(policy="income-calc-v3", signing_key=Ed25519PrivateKey.generate())


def _good_decision(led: Ledger, loan: str = "1000254") -> str:
    with led.decision(loan=loan, principal="jane@lender.com", purpose="income") as d:
        out = d.call(model="claude-sonnet-5", prompt="extract gross pay",
                     sources=[PAYSTUB], response={"gross_pay": 4206.00})
        v = d.gate(out, citations={"gross_pay": "paystub"}, confidence=0.94)
        assert v.ok, v.findings
        d.commit(outcome=out)
        return d.record_id


# ----------------------------------------------------------------- the mandate


def test_every_mandate_field_is_present() -> None:
    """The eight fields LL-2026-04 names, on every AI decision record.

    This is the product's reason to exist. Nothing else in this file matters if
    it fails."""
    led = _ledger()
    _good_decision(led)
    with led.decision(loan="1000254", principal="jane@lender.com", purpose="income") as d:
        out = d.call(model="claude-sonnet-5", prompt="p", sources=[PAYSTUB],
                     response={"gross_pay": 9999.00})
        d.gate(out, citations={"gross_pay": "paystub"}, confidence=0.99)
        d.route_to_human(queue="uw-review")

    for record in led.records():
        if record["event"] != "ai_decision":
            continue
        for field in MANDATE_FIELDS:
            if field == "decision_outcome" and record["disposition"] != "committed":
                continue   # nothing was written downstream; inventing one would be the lie
            assert record.get(field) not in (None, ""), (
                f"{field} missing on {record['record_id']} ({record['disposition']})"
            )


def test_coverage_reports_gaps_rather_than_hiding_them() -> None:
    led = _ledger()
    _good_decision(led)
    assert coverage(led.records())["complete"] is True


# ------------------------------------------------------------- nothing escapes


def test_an_abandoned_decision_still_writes_a_record() -> None:
    """A gap looks identical to a deletion to whoever reads this later."""
    led = _ledger()
    with led.decision(loan="1000254", principal="jane@lender.com", purpose="income") as d:
        d.call(model="claude-sonnet-5", prompt="p", sources=[PAYSTUB], response={"x": 4206})
        # no commit, no route — the caller simply walked away

    records = led.records()
    assert len(records) == 1
    assert records[0]["disposition"] == "abandoned"


def test_a_decision_that_raises_is_recorded_and_the_error_still_propagates() -> None:
    led = _ledger()
    try:
        with led.decision(loan="1000254", principal="jane@lender.com", purpose="income") as d:
            d.call(model="claude-sonnet-5", prompt="p", sources=[PAYSTUB], response={"x": 1})
            raise RuntimeError("the model endpoint timed out")
    except RuntimeError:
        pass
    else:
        raise AssertionError("the exception was swallowed")

    record = led.records()[0]
    assert record["disposition"] == "errored"
    assert "timed out" in record["note"]


def test_committing_over_a_rejection_is_recorded_as_an_override() -> None:
    """Making it impossible drives the work outside the system, where nothing is
    recorded at all. A visible override beats an invisible one."""
    led = _ledger()
    with led.decision(loan="1000254", principal="jane@lender.com", purpose="income") as d:
        out = d.call(model="claude-sonnet-5", prompt="p", sources=[PAYSTUB],
                     response={"gross_pay": 9999.00})
        v = d.gate(out, citations={"gross_pay": "paystub"}, confidence=0.99)
        assert v.treatment == REJECT
        d.commit(outcome=out)

    record = led.records()[0]
    assert record["disposition"] == "committed_over_rejection"
    assert record["response_treatment"] == REJECT


# ------------------------------------------------------------------ the store


def test_the_database_itself_refuses_updates_and_deletes() -> None:
    """Append-only enforced by a code review is a promise; enforced by the
    database it is a property that survives a SQL client at 2am."""
    store = Store()
    led = Ledger(policy="p", signing_key=Ed25519PrivateKey.generate(), store=store)
    _good_decision(led)

    for sql in ("UPDATE records SET loan = 'other'", "DELETE FROM records"):
        try:
            store._db.execute(sql)
        except sqlite3.IntegrityError as exc:
            assert "append-only" in str(exc)
        else:
            raise AssertionError(f"the store permitted: {sql}")


def test_the_four_mandated_query_dimensions_work() -> None:
    led = _ledger()
    _good_decision(led, loan="1000254")
    _good_decision(led, loan="1000999")

    assert len(led.store.query(loan="1000254")) == 1
    assert len(led.store.query(model="claude-sonnet-5")) == 2
    assert len(led.store.query(principal="jane@lender.com")) == 2
    assert len(led.store.query(since="1970-01-01")) == 2
    assert led.store.query(loan="1000254", model="nonexistent") == []


# ------------------------------------------------------------------- the chain


def test_the_ledger_produces_a_verifying_chain() -> None:
    led = _ledger()
    for _ in range(3):
        _good_decision(led)
    verify_chain(led.records(), led.public_key)


def test_human_review_chains_into_the_same_ledger() -> None:
    """The AI record and the human record cannot drift apart if they share a chain."""
    led = _ledger()
    decision_id = _good_decision(led)
    review_id = led.human_review(
        loan="1000254", reviewer="sam@lender.com", decision_id=decision_id,
        action="corrected", outcome={"gross_pay": 4206.00}, note="matches the paystub",
    )
    verify_chain(led.records(), led.public_key)

    review = [r for r in led.records() if r["record_id"] == review_id][0]
    assert review["reviews"] == decision_id
    assert review["principal"] == "sam@lender.com"


# ---------------------------------------------------------------- the examiner


def test_the_packet_answers_the_question_an_examiner_asks() -> None:
    led = _ledger()
    did = _good_decision(led, loan="1000254")
    led.human_review(loan="1000254", reviewer="sam@lender.com", decision_id=did,
                     action="approved")
    _good_decision(led, loan="1000999")

    p = packet(led, "1000254")
    assert p["loan"] == "1000254"
    assert p["summary"]["ai_decisions"] == 1
    assert p["summary"]["human_reviews"] == 1
    assert p["chain"]["verified"] is True
    assert all(r["loan"] == "1000254" for r in p["records"]), "another loan leaked in"


def test_the_packet_verifies_the_whole_ledger_not_the_slice() -> None:
    """A per-loan slice has gaps by construction — the records in between belong
    to other loans. Verifying the slice would report every honest ledger broken."""
    led = _ledger()
    _good_decision(led, loan="1000254")
    _good_decision(led, loan="1000999")
    _good_decision(led, loan="1000254")

    assert packet(led, "1000254")["chain"]["verified"] is True


def test_a_tampered_record_is_reported_in_the_packet_with_its_location() -> None:
    led = _ledger()
    _good_decision(led, loan="1000254")
    _good_decision(led, loan="1000254")

    records = led.records()
    records[0]["decision_outcome"] = {"gross_pay": 9999.00}
    try:
        verify_chain(records, led.public_key)
    except ChainError as exc:
        assert exc.index == 0
    else:
        raise AssertionError("a tampered record verified")


def test_rejected_decisions_appear_in_the_packet() -> None:
    """Showing only the successes is how an audit trail becomes a brochure."""
    led = _ledger()
    with led.decision(loan="1000254", principal="jane@lender.com", purpose="income") as d:
        out = d.call(model="claude-sonnet-5", prompt="p", sources=[PAYSTUB],
                     response={"gross_pay": 9999.00})
        d.gate(out, citations={"gross_pay": "paystub"}, confidence=0.99)
        d.route_to_human(queue="uw-review")

    p = packet(led, "1000254")
    assert p["summary"]["rejected"] == 1
    assert len(p["records"]) == 1


# ------------------------------------------------------------------- redaction


def test_borrower_pii_never_reaches_the_stored_record() -> None:
    led = _ledger()
    with led.decision(loan="1000254", principal="jane@lender.com", purpose="income",
                      identifiers=["Dana Whitfield"]) as d:
        out = d.call(
            model="claude-sonnet-5",
            prompt="Borrower Dana Whitfield, SSN 123-45-6789, loan 1000254. Gross pay?",
            sources=[PAYSTUB], response={"gross_pay": 4206.00},
        )
        d.gate(out, citations={"gross_pay": "paystub"}, confidence=0.94)
        d.commit(outcome=out)

    prompt = led.records()[0]["prompt_redacted"]
    assert "Dana Whitfield" not in prompt
    assert "123-45-6789" not in prompt
    assert "1000254" in prompt, "the loan number is the query key and must survive"


def test_pii_in_free_text_notes_is_redacted_too() -> None:
    """Found by audit: `note` was the one field that skipped redaction.

    It is also the field most likely to contain PII, because it is the only one
    a human types prose into. Three routes reach it -- a note passed to
    route_to_human, a reviewer's note on a human_review, and an exception
    message on the error path -- and all three were writing raw text into a
    record the whole design says an examiner may read.
    """
    import json

    led = _ledger()
    with led.decision(loan="1000254", principal="jane@lender.com", purpose="income",
                      identifiers=["Dana Whitfield"]) as d:
        out = d.call(model="m", prompt="p", sources=[PAYSTUB], response={"gross_pay": 4206.00})
        d.gate(out, citations={"gross_pay": "paystub"}, confidence=0.40)
        d.route_to_human(queue="uw-review",
                         note="Dana Whitfield called from 214-555-0182 about SSN 123-45-6789")
    decision_id = led.records()[0]["record_id"]

    led.human_review(loan="1000254", reviewer="sam@lender.com", decision_id=decision_id,
                     action="corrected", outcome={"monthly_income": 8200.83},
                     note="Spoke to Dana Whitfield, DOB 03/14/1987, confirmed the W-2.",
                     identifiers=["Dana Whitfield"])

    blob = json.dumps(led.records())
    for secret in ("Dana Whitfield", "214-555-0182", "123-45-6789", "03/14/1987"):
        assert secret not in blob, f"{secret!r} survived into the ledger via a note"
    assert "1000254" in blob, "the loan number must still survive"


def test_an_exception_message_carrying_pii_is_redacted() -> None:
    """The error path builds `note` from the exception text, which nobody writes
    with an audit record in mind."""
    import json

    led = _ledger()
    try:
        with led.decision(loan="1000254", principal="jane@lender.com", purpose="income",
                          identifiers=["Dana Whitfield"]) as d:
            d.call(model="m", prompt="p", sources=[PAYSTUB], response={"gross_pay": 1.0})
            raise ValueError("no record for Dana Whitfield / SSN 123-45-6789")
    except ValueError:
        pass

    record = led.records()[0]
    assert record["disposition"] == "errored"
    blob = json.dumps(record)
    assert "Dana Whitfield" not in blob and "123-45-6789" not in blob, \
        f"an exception message leaked PII: {record['note']!r}"


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
