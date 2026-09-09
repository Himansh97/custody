"""Per-principal authorization tests.

`principal` was recorded on every decision and checked by nothing. A field the
ledger carries but the policy never reads is provenance, not authorization: it
says who claimed to be asking, and permits them whatever the use case permits
anybody.
"""
from __future__ import annotations

import json
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent / "src"))

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402

from custody.ledger import Ledger  # noqa: E402
from custody.policy import Policy, PolicyDenied  # noqa: E402

DOCUMENT = {
    "policy_id": "AI-INCOME-001",
    "version": "3.0",
    "owner": "compliance@lender.example",
    "last_reviewed": "2026-07-01",
    "use_cases": {
        "income_calculation": {
            "approved": True,
            "models": ["claude-sonnet-5"],
            "principals": ["jane@lender.com"],
        },
    },
}


def _policy(**overrides) -> Policy:
    doc = json.loads(json.dumps(DOCUMENT))
    doc.update(overrides)
    return Policy(doc)


def _ledger(policy=None) -> Ledger:
    return Ledger(policy=policy or _policy(), signing_key=Ed25519PrivateKey.generate())


def test_a_principal_outside_the_use_case_never_reaches_the_model() -> None:
    """The control. Everything else about principals is downstream of this."""
    led = _ledger()
    invoked = []

    try:
        with led.decision(loan="1000254", principal="mallory@lender.com",
                          purpose="income_calculation") as d:
            d.call(model="claude-sonnet-5", prompt="extract income",
                   invoke=lambda: invoked.append(1))
        raise AssertionError("PolicyDenied was not raised")
    except PolicyDenied as denied:
        assert "mallory@lender.com" in str(denied)

    assert invoked == [], "the model was called for an unauthorised principal"


def test_a_listed_principal_is_allowed() -> None:
    led = _ledger()
    with led.decision(loan="1000254", principal="jane@lender.com",
                      purpose="income_calculation") as d:
        out = d.call(model="claude-sonnet-5", prompt="extract income",
                     invoke=lambda: "4,206.00 a month")
    assert out == "4,206.00 a month"


def test_a_use_case_naming_no_principals_is_unrestricted() -> None:
    """Absence is not a silent deny -- it would break every policy written
    before this feature existed. It is reported instead, not enforced."""
    doc = json.loads(json.dumps(DOCUMENT))
    del doc["use_cases"]["income_calculation"]["principals"]
    led = _ledger(Policy(doc))

    with led.decision(loan="1000254", principal="anyone@lender.com",
                      purpose="income_calculation") as d:
        out = d.call(model="claude-sonnet-5", prompt="extract income",
                     invoke=lambda: "ok")
    assert out == "ok"


def test_an_empty_principal_list_permits_nobody() -> None:
    """Consistent with `models: []`, which approves no model rather than all."""
    doc = json.loads(json.dumps(DOCUMENT))
    doc["use_cases"]["income_calculation"]["principals"] = []
    led = _ledger(Policy(doc))

    try:
        with led.decision(loan="1000254", principal="jane@lender.com",
                          purpose="income_calculation") as d:
            d.call(model="claude-sonnet-5", prompt="x", invoke=lambda: "y")
        raise AssertionError("PolicyDenied was not raised")
    except PolicyDenied:
        pass


def test_a_principal_denial_is_a_record_that_chains() -> None:
    """The control is only half of it. A refusal nobody can see is not evidence."""
    from custody.chain import verify_chain

    led = _ledger()
    try:
        with led.decision(loan="1000254", principal="mallory@lender.com",
                          purpose="income_calculation") as d:
            d.call(model="claude-sonnet-5", prompt="x", invoke=lambda: "y")
    except PolicyDenied:
        pass

    records = led.records()
    denials = [r for r in records if r.get("event") == "ai_denied"]
    assert len(denials) == 1, f"expected one denial record, got {len(denials)}"
    assert denials[0]["principal"] == "mallory@lender.com"
    verify_chain(records, led.public_key)   # raises if the denial broke the chain


def test_the_disclosure_names_use_cases_that_restrict_no_principal() -> None:
    """`for_principal` promises the omission is reported rather than enforced.

    If it is not reported, that docstring is a claim this library cannot back,
    which is the one thing it is not allowed to be.
    """
    from custody.examiner import disclosure

    doc = json.loads(json.dumps(DOCUMENT))
    del doc["use_cases"]["income_calculation"]["principals"]
    doc["use_cases"]["fraud_check"] = {
        "approved": True, "models": ["claude-sonnet-5"],
        "principals": ["jane@lender.com"],
    }
    led = _ledger(Policy(doc))

    report = disclosure(led)
    unrestricted = report["safeguards"]["use_cases_restricting_no_principal"]
    assert "income_calculation" in unrestricted
    assert "fraud_check" not in unrestricted


def test_the_starter_policy_authorises_the_principal_the_readme_uses() -> None:
    """The quickstart must survive the starter policy shipping a principal rule.

    Two files have to agree: README's `custody run` example and STARTER_POLICY.
    Nobody edits both. So this reads the README rather than restating it, and
    fails when they drift -- the same reason test_crosslang diffs the two
    canonicalisers instead of trusting they match.
    """
    import re

    from custody.policy import STARTER_POLICY

    readme = (pathlib.Path(__file__).resolve().parent.parent / "README.md").read_text()
    block = re.search(r"custody run .*?(?=\n```)", readme, re.S)
    assert block, "no `custody run` example found in README"
    quickstart = block.group(0)

    principal = re.search(r"--principal (\S+)", quickstart)
    purpose = re.search(r"--purpose (\S+)", quickstart)
    assert principal and purpose, "the README example names no principal or purpose"

    case = STARTER_POLICY["use_cases"][purpose.group(1)]
    approved = case.get("principals")
    assert approved is not None, "the starter policy states no principal rule"
    assert principal.group(1) in approved, (
        f"README runs as {principal.group(1)!r}; starter approves {approved}"
    )


def test_ci_runs_the_starter_policy_as_a_principal_it_approves() -> None:
    """The release workflow installs the wheel and drives the CLI for real.

    It is a third file that has to agree with STARTER_POLICY, and it is the one
    that finds out by failing a release rather than a test. The happy-path run
    must use an approved principal, or the smoke test measures the principal
    rule instead of the thing it was written to measure.
    """
    import re

    from custody.policy import STARTER_POLICY

    workflow = (
        pathlib.Path(__file__).resolve().parent.parent
        / ".github" / "workflows" / "publish.yml"
    ).read_text()

    run = re.search(
        r"custody run[^\n]*--principal (\S+)(?:[^\n]|\n\s+)*?--purpose income_calculation",
        workflow,
    )
    assert run, "no income_calculation run found in publish.yml"

    approved = STARTER_POLICY["use_cases"]["income_calculation"].get("principals")
    assert approved is not None
    assert run.group(1) in approved, (
        f"CI runs as {run.group(1)!r}; the starter approves {approved}"
    )
