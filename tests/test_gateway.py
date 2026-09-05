"""Gateway tests.

The property under test is the one the two-call API shape gives up: there is no
request to this service that returns a model's output without also having
written a record, and no request that reaches the model past a policy that
refused it.
"""
from __future__ import annotations

import json
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent / "src"))

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402

from custody.chain import verify_chain  # noqa: E402
from custody.gateway import GatewayError, handle_decision  # noqa: E402
from custody.ledger import Ledger  # noqa: E402
from custody.policy import Policy  # noqa: E402

PAYSTUB = "ACME LOGISTICS  Gross pay 4,206.00  YTD 50,472.00"

POLICY = Policy({
    "policy_id": "AI-INCOME-001",
    "version": "3.0",
    "owner": "compliance@lender.example",
    "last_reviewed": "2026-07-01",
    "use_cases": {
        "income_calculation": {
            "approved": True, "models": ["claude-sonnet-5"], "confidence_floor": 0.85,
        },
        "adverse_action": {"approved": False, "models": []},
    },
})


def _ledger() -> Ledger:
    return Ledger(policy=POLICY, signing_key=Ed25519PrivateKey.generate())


def _extract(calls: list | None = None, fields=None, confidence=0.94):
    def call(instruction, documents):
        if calls is not None:
            calls.append(instruction)
        return (
            dict(fields if fields is not None else {"gross_pay": 4206.00}),
            confidence,
            "anthropic:messages:claude-sonnet-5",
            {"gross_pay": "paystub"},
        )
    return call


def _request(**overrides) -> dict:
    body = {
        "loan": "1000254",
        "principal": "jane@lender.com",
        "purpose": "income_calculation",
        "model": "claude-sonnet-5",
        "instruction": "Extract qualifying monthly income.",
        "documents": [{"id": "paystub", "text": PAYSTUB}],
    }
    body.update(overrides)
    return body


def test_an_allowed_decision_returns_output_and_leaves_a_record() -> None:
    led = _ledger()
    status, body = handle_decision(led, _extract(), _request())
    assert status == 200, body
    assert body["treatment"] == "pass", body
    assert body["fields"]["gross_pay"] == 4206.00
    assert len(led.records()) == 1
    assert led.records()[0]["record_id"] == body["record_id"]
    verify_chain(led.records(), led.public_key)


def test_a_refused_purpose_never_reaches_the_model() -> None:
    """The whole reason this is a proxy and not two advisory endpoints."""
    led = _ledger()
    calls: list = []
    status, body = handle_decision(
        led, _extract(calls), _request(purpose="adverse_action")
    )
    assert status == 403, body
    assert not calls, "the policy refused and the model was called anyway"
    assert "fields" not in body, "a refused call returned model output"
    assert led.records()[0]["event"] == "ai_denied"


def test_every_answered_request_has_a_record_behind_it() -> None:
    led = _ledger()
    for purpose in ("income_calculation", "adverse_action", "income_calculation"):
        handle_decision(led, _extract(), _request(purpose=purpose))
    assert len(led.records()) == 3
    verify_chain(led.records(), led.public_key)


def test_a_failing_gate_routes_and_does_not_commit() -> None:
    led = _ledger()
    invented = _extract(fields={"gross_pay": 9999.99}, confidence=0.99)
    status, body = handle_decision(led, invented, _request())
    assert status == 200
    assert body["treatment"] == "reject", body
    assert body["disposition"] == "routed_to_human"
    assert led.records()[0]["decision_outcome"] is None


def test_the_policys_floor_applies_over_the_wire_too() -> None:
    led = _ledger()
    status, body = handle_decision(led, _extract(confidence=0.83), _request())
    assert body["treatment"] == "review", body


def test_a_request_without_a_principal_is_refused() -> None:
    led = _ledger()
    body = _request()
    del body["principal"]
    try:
        handle_decision(led, _extract(), body)
        raise AssertionError("a decision was recorded with no principal")
    except GatewayError as exc:
        assert exc.status == 400


def test_documents_may_be_bare_strings() -> None:
    led = _ledger()
    status, body = handle_decision(led, _extract(), _request(documents=[PAYSTUB]))
    assert status == 200, body


def test_the_response_carries_an_anchor_to_store_elsewhere() -> None:
    led = _ledger()
    _, body = handle_decision(led, _extract(), _request())
    assert body["anchor"].startswith("custody-anchor:v1:1:")


def test_a_model_that_raises_still_leaves_a_record() -> None:
    led = _ledger()

    def explodes(instruction, documents):
        raise RuntimeError("upstream 503")

    try:
        handle_decision(led, explodes, _request())
    except RuntimeError:
        pass
    assert len(led.records()) == 1, "a failed model call left no record"
    assert led.records()[0]["disposition"] == "errored"


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
