"""Policy engine tests.

The two that matter here are `test_a_denied_call_never_reaches_the_model` and
`test_a_denial_is_a_record_that_chains`. The first is the control; the second is
the evidence that the control ran. A policy engine with only the first is
unfalsifiable, and one with only the second is advice.
"""
from __future__ import annotations

import json
import pathlib
import sys
import tempfile
from datetime import date

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent / "src"))

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402

from custody.chain import verify_chain  # noqa: E402
from custody.examiner import coverage, packet  # noqa: E402
from custody.ledger import DENIAL_FIELDS, Ledger  # noqa: E402
from custody.policy import Policy, PolicyDenied, PolicyError, resolved_versions  # noqa: E402
from custody.verify import DENIED, REVIEW  # noqa: E402

PAYSTUB = "ACME LOGISTICS  Gross pay 4,206.00  YTD 50,472.00"

DOCUMENT = {
    "policy_id": "AI-INCOME-001",
    "version": "3.0",
    "owner": "compliance@lender.example",
    "last_reviewed": "2026-07-01",
    "use_cases": {
        "income_calculation": {
            "approved": True,
            "models": ["claude-sonnet-5"],
            "confidence_floor": 0.85,
            "human_review": "on_review",
            "ai_can_decide": True,
        },
        "adverse_action": {
            "approved": False,
            "models": ["claude-sonnet-5"],
        },
    },
}


def _policy(**overrides) -> Policy:
    doc = json.loads(json.dumps(DOCUMENT))
    doc.update(overrides)
    return Policy(doc)


def _ledger(policy=None) -> Ledger:
    return Ledger(
        policy=policy or _policy(), signing_key=Ed25519PrivateKey.generate()
    )


# ------------------------------------------------------------------ the control


def test_a_denied_call_never_reaches_the_model() -> None:
    """The model function must not run. Everything else here is downstream of this."""
    led = _ledger()
    invoked = []

    try:
        with led.decision(loan="1000254", principal="jane@lender.com",
                          purpose="adverse_action") as d:
            d.call(model="claude-sonnet-5", prompt="why was this denied",
                   invoke=lambda: invoked.append(1))
        raise AssertionError("PolicyDenied was not raised")
    except PolicyDenied:
        pass

    assert not invoked, "the policy denied the call and the model was called anyway"


def test_an_unapproved_model_is_refused_for_an_approved_purpose() -> None:
    led = _ledger()
    try:
        with led.decision(loan="1", principal="j@l", purpose="income_calculation") as d:
            d.call(model="gpt-4o", prompt="p", response={})
        raise AssertionError("an unapproved model was allowed")
    except PolicyDenied as exc:
        assert "not approved" in str(exc), str(exc)


def test_an_unlisted_purpose_is_denied_rather_than_defaulted() -> None:
    """A policy that permits whatever nobody wrote down is not a policy."""
    verdict = _policy().for_purpose("pricing_recommendation")
    assert not verdict.allowed
    assert "not a use case" in (verdict.reason or "")


def test_the_model_behind_a_deployment_can_be_approved_instead_of_the_deployment() -> None:
    """Azure routes on a deployment name and the model behind it can change."""
    policy = _policy(use_cases={
        "income_calculation": {"approved": True, "models": ["gpt-4o-2024-11-20"]}
    })
    endpoint = "azure-openai:acme-uw:gpt-4o-prod:gpt-4o-2024-11-20"
    assert policy.for_model("income_calculation", "gpt-4o-prod", endpoint).allowed

    stale = "azure-openai:acme-uw:gpt-4o-prod:gpt-4o-2024-05-13"
    assert not policy.for_model("income_calculation", "gpt-4o-prod", stale).allowed, \
        "the deployment was repointed at an unapproved model and the call was allowed"


def test_resolved_versions_offers_every_segment() -> None:
    assert "claude-sonnet-5" in resolved_versions("anthropic:messages:claude-sonnet-5")
    assert resolved_versions(None) == ()


def test_a_deployment_repointed_after_the_call_is_rejected_not_denied() -> None:
    """The model that answered can only be checked once it has answered.

    A pre-call denial would be a lie about what happened, so this lands as a
    rejection with a reason instead: the output exists and must not be used.
    """
    policy = _policy(use_cases={
        "income_calculation": {"approved": True, "models": ["gpt-4o-2024-11-20"]}
    })
    led = _ledger(policy)
    with led.decision(loan="1", principal="j@l", purpose="income_calculation") as d:
        out = d.call(model="gpt-4o-2024-11-20", prompt="p", sources=[PAYSTUB],
                     response={"gross_pay": 4206.00})
        d.resolved("azure-openai:acme:gpt-4o-prod:gpt-4o-2024-05-13")
        verdict = d.gate(out, citations={"gross_pay": "paystub"}, confidence=0.99)
        d.route_to_human(queue="uw")

    assert verdict.treatment == "reject", verdict.findings
    assert any(f.check == "policy_model" for f in verdict.findings), verdict.findings
    record = led.records()[0]
    assert record["event"] == "ai_decision", "a call that happened was recorded as denied"
    assert record["model"] == "gpt-4o-2024-05-13", record["model"]


def test_resolving_an_approved_endpoint_leaves_the_verdict_alone() -> None:
    led = _ledger()
    with led.decision(loan="1", principal="j@l", purpose="income_calculation") as d:
        out = d.call(model="claude-sonnet-5", prompt="p", sources=[PAYSTUB],
                     response={"gross_pay": 4206.00})
        d.resolved("anthropic:messages:claude-sonnet-5")
        verdict = d.gate(out, citations={"gross_pay": "paystub"}, confidence=0.99)
        d.commit(outcome=out)
    assert verdict.ok, verdict.findings


# ------------------------------------------------------------------- data rules
#
# These exist because the shipped starter policy said `prohibited_data:
# ["ssn", ...]` for a release while nothing checked it. A control document
# stating a rule the engine does not apply is the worst defect this project can
# have, so the rule is tested from both directions: what the caller declares,
# and what is actually in the documents.


def _data_policy(**case) -> Policy:
    body = {"approved": True, "models": ["claude-sonnet-5"],
            "allowed_data": ["income", "employment", "paystub", "w2"],
            "prohibited_data": ["ssn", "bank_account_number"]}
    body.update(case)
    return _policy(use_cases={"income_calculation": body})


def _attempt(led, **kwargs):
    """Try one decision. Returns (reached_the_model, denial reason or None)."""
    reached = []
    try:
        with led.decision(loan="1", principal="j@l", purpose="income_calculation",
                          data=kwargs.get("data", ())) as d:
            d.call(model="claude-sonnet-5", prompt=kwargs.get("prompt", "Compute income."),
                   sources=kwargs.get("sources", [PAYSTUB]),
                   invoke=lambda: reached.append(1) or {"gross_pay": 4206.00})
    except PolicyDenied as exc:
        return False, str(exc)
    return bool(reached), None


def test_a_prohibited_data_class_is_refused() -> None:
    reached, reason = _attempt(_ledger(_data_policy()), data=["income", "ssn"])
    assert not reached, "a decision declaring prohibited data reached the model"
    assert "prohibited" in reason, reason


def test_a_class_outside_the_allowed_set_is_refused() -> None:
    reached, reason = _attempt(_ledger(_data_policy()), data=["credit_score"])
    assert not reached
    assert "not in the allowed set" in reason, reason


def test_declared_classes_inside_the_policy_are_allowed() -> None:
    reached, reason = _attempt(_ledger(_data_policy()), data=["income", "paystub"])
    assert reached, reason


def test_data_rules_cannot_be_left_unchecked_by_declaring_nothing() -> None:
    """The bug this section exists for: a rule that silently does not apply."""
    reached, reason = _attempt(_ledger(_data_policy()), data=())
    assert not reached, "a policy with data rules was satisfied by declaring nothing"
    assert "declared no data classes" in reason, reason


def test_a_prohibited_class_is_found_in_the_documents_not_just_the_declaration() -> None:
    """Declaring the right thing must not launder a document full of the wrong thing."""
    reached, reason = _attempt(
        _ledger(_data_policy()), data=["income"],
        sources=[PAYSTUB + "  SSN 123-45-6789"],
    )
    assert not reached, "an SSN in a source document reached the model"
    assert "ssn" in reason and "appears in a document" in reason, reason


def test_a_prohibited_class_is_found_in_the_prompt_too() -> None:
    reached, reason = _attempt(
        _ledger(_data_policy()), data=["income"],
        prompt="Borrower SSN 123-45-6789, compute income.",
    )
    assert not reached, "an SSN in the prompt reached the model"


def test_a_class_that_cannot_be_detected_is_honestly_declaration_only() -> None:
    """"Income" has no shape. The policy still applies; nothing pretends to find it."""
    from custody.redact import detector_for
    assert detector_for("income") is None
    assert detector_for("ssn") is not None
    assert detector_for("bank_account_number") is not None, "an alias lost its detector"


def test_a_policy_with_no_data_rules_needs_no_declaration() -> None:
    """Existing callers keep working; the rule only bites where one was written."""
    policy = _policy(use_cases={
        "income_calculation": {"approved": True, "models": ["claude-sonnet-5"]}})
    reached, reason = _attempt(_ledger(policy), data=())
    assert reached, reason


def test_the_declared_classes_land_on_the_record() -> None:
    led = _ledger(_data_policy())
    _attempt(led, data=["income", "paystub"])
    assert led.records()[0]["data_classes"] == ["income", "paystub"]


# ----------------------------------------------------------------- the evidence


def test_a_denial_is_a_record_that_chains() -> None:
    """Refusals are evidence. A ledger of only the permitted calls is a brochure."""
    led = _ledger()
    try:
        with led.decision(loan="1000254", principal="jane@lender.com",
                          purpose="adverse_action") as d:
            d.call(model="claude-sonnet-5", prompt="p", response={})
    except PolicyDenied:
        pass

    records = led.records()
    assert len(records) == 1, "the denial was not recorded"
    record = records[0]
    assert record["event"] == "ai_denied"
    assert record["response_treatment"] == DENIED
    assert record["disposition"] == "denied_by_policy"
    assert record["policy_decision"] == "deny"
    assert "not approved" in (record["policy_reason"] or "")
    verify_chain(records, led.public_key)


def test_a_denial_carries_the_fields_a_refusal_can_carry() -> None:
    led = _ledger()
    try:
        with led.decision(loan="1", principal="jane@lender.com",
                          purpose="adverse_action") as d:
            d.call(model="claude-sonnet-5", prompt="p", response={})
    except PolicyDenied:
        pass

    record = led.records()[0]
    for field in DENIAL_FIELDS:
        assert record.get(field) not in (None, ""), f"denial record has no {field}"
    assert coverage(led.records())["complete"], coverage(led.records())["missing"]


def test_an_unevaluated_policy_says_so_on_the_record() -> None:
    """The bare version string still works, and the record does not imply a check."""
    led = Ledger(policy="income-calc-v3", signing_key=Ed25519PrivateKey.generate())
    with led.decision(loan="1", principal="j@l", purpose="income") as d:
        out = d.call(model="claude-sonnet-5", prompt="p", sources=[PAYSTUB],
                     response={"gross_pay": 4206.00})
        d.gate(out, citations={"gross_pay": "paystub"}, confidence=0.94)
        d.commit(outcome=out)

    record = led.records()[0]
    assert record["policy_decision"] == "unevaluated"
    assert record["policy_id"] is None


def test_the_policy_identifier_lands_in_policy_version() -> None:
    led = _ledger()
    assert led.policy == "AI-INCOME-001@3.0"


# ---------------------------------------------------------- policy drives the gate


def test_the_policys_confidence_floor_is_the_one_that_runs() -> None:
    """The risk tolerance a lender approved, not the one at the call site."""
    led = _ledger()
    with led.decision(loan="1", principal="j@l", purpose="income_calculation") as d:
        out = d.call(model="claude-sonnet-5", prompt="p", sources=[PAYSTUB],
                     response={"gross_pay": 4206.00})
        verdict = d.gate(out, citations={"gross_pay": "paystub"}, confidence=0.83)
        d.route_to_human(queue="uw")

    assert verdict.treatment == REVIEW, \
        "0.83 cleared a policy floor of 0.85"
    assert any("0.85" in f.detail for f in verdict.findings), verdict.findings


def test_human_review_always_downgrades_a_passing_verdict() -> None:
    policy = _policy(use_cases={
        "income_calculation": {
            "approved": True, "models": ["claude-sonnet-5"], "human_review": "always",
        }
    })
    led = _ledger(policy)
    with led.decision(loan="1", principal="j@l", purpose="income_calculation") as d:
        out = d.call(model="claude-sonnet-5", prompt="p", sources=[PAYSTUB],
                     response={"gross_pay": 4206.00})
        verdict = d.gate(out, citations={"gross_pay": "paystub"}, confidence=0.99)
        d.route_to_human(queue="uw")

    assert verdict.treatment == REVIEW, "a policy requiring human review returned pass"
    assert any(f.check == "policy_human_review" for f in verdict.findings)


def test_committing_without_authority_is_recorded_rather_than_blocked() -> None:
    """Same reasoning as an override of a rejection: invisible is worse than logged."""
    policy = _policy(use_cases={
        "income_calculation": {
            "approved": True, "models": ["claude-sonnet-5"], "ai_can_decide": False,
        }
    })
    led = _ledger(policy)
    with led.decision(loan="1", principal="j@l", purpose="income_calculation") as d:
        out = d.call(model="claude-sonnet-5", prompt="p", sources=[PAYSTUB],
                     response={"gross_pay": 4206.00})
        d.gate(out, citations={"gross_pay": "paystub"}, confidence=0.99)
        d.commit(outcome=out)

    assert led.records()[0]["disposition"] == "committed_without_authority"


# ------------------------------------------------------------------- the loading


def test_an_unknown_key_is_an_error_not_a_default() -> None:
    """A misspelled control that silently keeps its default is the worst case."""
    try:
        Policy({"policy_id": "P", "version": "1", "use_cases": {
            "x": {"approved": True, "confidence_flor": 0.99}}})
        raise AssertionError("a misspelled key was accepted")
    except PolicyError as exc:
        assert "confidence_flor" in str(exc), str(exc)


def test_a_policy_without_an_id_or_version_will_not_load() -> None:
    for missing in ("policy_id", "version"):
        doc = {"policy_id": "P", "version": "1"}
        doc.pop(missing)
        try:
            Policy(doc)
            raise AssertionError(f"a policy without {missing} loaded")
        except PolicyError:
            pass


def test_a_policy_loads_from_a_file_and_from_a_path_string() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        path = pathlib.Path(tmp) / "uw.json"
        path.write_text(json.dumps(DOCUMENT), encoding="utf-8")
        led = Ledger(policy=str(path), signing_key=Ed25519PrivateKey.generate())
        assert led.policy == "AI-INCOME-001@3.0"
        assert led.policy_doc is not None


def test_an_out_of_range_confidence_floor_is_refused() -> None:
    try:
        Policy({"policy_id": "P", "version": "1",
                "use_cases": {"x": {"approved": True, "confidence_floor": 1.4}}})
        raise AssertionError("a floor of 1.4 loaded")
    except PolicyError:
        pass


# ------------------------------------------------------------------ annual review


def test_an_overdue_review_is_visible_rather_than_silent() -> None:
    """LL-2026-04 requires an owner reviewing at least annually."""
    policy = _policy(last_reviewed="2024-01-01")
    status = policy.review_status(as_of=date(2026, 9, 4))
    assert status["overdue"] and status["overdue_days"] > 0, status
    assert status["owner"] == "compliance@lender.example"


def test_a_policy_never_reviewed_is_overdue_not_unknown() -> None:
    policy = _policy(last_reviewed=None)
    assert policy.review_status()["overdue"] is True


def test_the_packet_reports_the_review_state() -> None:
    led = _ledger(_policy(last_reviewed="2024-01-01"))
    with led.decision(loan="1000254", principal="j@l", purpose="income_calculation") as d:
        out = d.call(model="claude-sonnet-5", prompt="p", sources=[PAYSTUB],
                     response={"gross_pay": 4206.00})
        d.gate(out, citations={"gross_pay": "paystub"}, confidence=0.99)
        d.commit(outcome=out)

    report = packet(led, "1000254")
    assert report["policy_review"]["overdue"] is True, report["policy_review"]


def test_the_packet_counts_denials() -> None:
    led = _ledger()
    try:
        with led.decision(loan="1000254", principal="j@l", purpose="adverse_action") as d:
            d.call(model="claude-sonnet-5", prompt="p", response={})
    except PolicyDenied:
        pass
    assert packet(led, "1000254")["summary"]["denied_by_policy"] == 1


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
