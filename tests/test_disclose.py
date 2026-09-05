"""Disclosure tests.

`custody packet` answers a question about one loan. This answers the one
LL-2026-04 actually asks, which is about the business: what AI is in use, for
what purpose, and what safeguards ran. The tests that matter are the ones
checking it does not flatter the lender -- refusals, overrides and ungoverned
decisions all have to survive into the report.
"""
from __future__ import annotations

import pathlib
import sys
import tempfile

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent / "src"))

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402

from custody.examiner import disclosure  # noqa: E402
from custody.ledger import Ledger  # noqa: E402
from custody.policy import Policy, PolicyDenied, PolicyError, write_starter  # noqa: E402

PAYSTUB = "ACME LOGISTICS  Gross pay 4,206.00  YTD 50,472.00"

POLICY = Policy({
    "policy_id": "AI-UW-001", "version": "2.0",
    "owner": "compliance@lender.example", "last_reviewed": "2026-07-01",
    "use_cases": {
        "income_calculation": {
            "approved": True, "models": ["claude-sonnet-5"],
            "confidence_floor": 0.85, "ai_can_decide": False,
        },
        "adverse_action": {"approved": False, "models": []},
    },
})


def _ledger(policy=POLICY) -> Ledger:
    return Ledger(policy=policy, signing_key=Ed25519PrivateKey.generate())


def _decide(led, *, loan="1000254", confidence=0.94, commit=True, fields=None):
    with led.decision(loan=loan, principal="j@l", purpose="income_calculation") as d:
        out = d.call(model="claude-sonnet-5", prompt="p", sources=[PAYSTUB],
                     response=fields or {"gross_pay": 4206.00})
        d.gate(out, citations={"gross_pay": "paystub"}, confidence=confidence)
        if commit:
            d.commit(outcome=out)
        else:
            d.route_to_human(queue="uw")


def _deny(led, loan="1000254"):
    try:
        with led.decision(loan=loan, principal="j@l", purpose="adverse_action") as d:
            d.call(model="claude-sonnet-5", prompt="p", response={})
    except PolicyDenied:
        pass


def test_it_names_the_endpoint_not_only_the_model() -> None:
    """"Types of AI/ML used" has to survive a repointed deployment."""
    led = _ledger()
    with led.decision(loan="1", principal="j@l", purpose="income_calculation") as d:
        out = d.call(model="claude-sonnet-5", prompt="p", sources=[PAYSTUB],
                     response={"gross_pay": 4206.00})
        d.resolved("anthropic:messages:claude-sonnet-5")
        d.gate(out, citations={"gross_pay": "paystub"}, confidence=0.99)
        d.commit(outcome=out)

    models = disclosure(led)["models"]
    assert models[0]["model"] == "claude-sonnet-5"
    assert "anthropic:messages:claude-sonnet-5" in models[0]["endpoints"]


def test_refusals_appear_in_the_disclosure() -> None:
    """A report of only the AI you permitted is a record of successes."""
    led = _ledger()
    _decide(led)
    _deny(led)

    report = disclosure(led)
    assert report["totals"]["denied_by_policy"] == 1
    denied = [p for p in report["purposes"] if p["purpose"] == "adverse_action"][0]
    assert denied["denied"] == 1 and denied["committed"] == 0


def test_overrides_are_counted_not_absorbed() -> None:
    """`ai_can_decide: false` and a commit anyway must be visible."""
    led = _ledger()
    _decide(led)
    income = [p for p in disclosure(led)["purposes"] if p["purpose"] == "income_calculation"][0]
    assert income["committed"] == 1
    assert income["overrides"] == 1, "an override was absorbed into the committed count"


def test_decisions_under_no_policy_are_flagged() -> None:
    """The bare version string still works, and the report says nothing checked."""
    led = Ledger(policy="uw-v3", signing_key=Ed25519PrivateKey.generate())
    _decide(led)
    safeguards = disclosure(led)["safeguards"]
    assert safeguards["decisions_under_no_evaluated_policy"] == 1


def test_the_checks_that_fired_are_evidence_that_a_safeguard_ran() -> None:
    led = _ledger()
    _decide(led, fields={"gross_pay": 9999.99}, commit=False)
    fired = disclosure(led)["safeguards"]["checks_that_fired"]
    assert fired.get("figure_binding") == 1, fired


def test_it_reports_the_chain_and_an_anchor() -> None:
    led = _ledger()
    _decide(led)
    integrity = disclosure(led)["integrity"]
    assert integrity["chain"]["verified"] is True
    assert integrity["anchor"].startswith("custody-anchor:v1:1:")


def test_it_states_what_it_cannot_cover() -> None:
    """A model inventory read as complete when it is not is worse than none."""
    led = _ledger()
    _decide(led)
    limits = " ".join(disclosure(led)["limits"]).lower()
    assert "cannot inventory models it never saw" in limits
    assert "fair-lending" in limits


def test_an_empty_ledger_discloses_nothing_rather_than_raising() -> None:
    report = disclosure(_ledger())
    assert report["totals"]["decisions_attempted"] == 0
    assert report["models"] == []


def test_it_counts_distinct_loans() -> None:
    led = _ledger()
    _decide(led, loan="1000254")
    _decide(led, loan="1000255")
    _decide(led, loan="1000255")
    assert disclosure(led)["totals"]["loans"] == 2


# ------------------------------------------------------------------- scaffold


def test_the_starter_policy_loads_and_permits_something() -> None:
    """The first thing after `pip install` must not be a schema hunt."""
    with tempfile.TemporaryDirectory() as tmp:
        path = pathlib.Path(tmp) / "starter.json"
        write_starter(path)
        policy = Policy.load(path)
        assert policy.for_purpose("income_calculation").allowed
        assert not policy.for_purpose("adverse_action_reasoning").allowed
        assert policy.owner, "the starter policy names no owner"
        assert not policy.review_status()["overdue"], "a fresh scaffold reads as overdue"


def test_the_scaffold_refuses_to_overwrite_a_policy() -> None:
    """Overwriting orphans every record citing that version."""
    with tempfile.TemporaryDirectory() as tmp:
        path = pathlib.Path(tmp) / "starter.json"
        write_starter(path)
        try:
            write_starter(path)
            raise AssertionError("an existing policy was overwritten")
        except PolicyError:
            pass
        write_starter(path, force=True)


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
