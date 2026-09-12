"""The gateway's `principal` must come from the credential, not the body.

Over the wire `principal` was whatever the caller typed. A bearer token carries
no identity, so any holder of it could write a record naming anybody: the field
the policy now authorizes on was, on this transport, self-asserted.
"""
from __future__ import annotations

import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent / "src"))

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402

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
            "approved": True, "models": ["claude-sonnet-5"],
            "confidence_floor": 0.85,
            "principals": ["jane@lender.com"],
        },
    },
})


def _ledger() -> Ledger:
    return Ledger(policy=POLICY, signing_key=Ed25519PrivateKey.generate())


def _extract(calls: list | None = None):
    def call(instruction, documents):
        if calls is not None:
            calls.append(instruction)
        return ({"gross_pay": 4206.00}, 0.94,
                "anthropic:messages:claude-sonnet-5", {"gross_pay": "paystub"})
    return call


def _request(**overrides) -> dict:
    body = {
        "loan": "1000254",
        "purpose": "income_calculation",
        "model": "claude-sonnet-5",
        "instruction": "Extract qualifying monthly income.",
        "documents": [{"id": "paystub", "text": PAYSTUB}],
    }
    body.update(overrides)
    return body


def test_the_authenticated_identity_is_the_principal_on_the_record() -> None:
    """A body that names nobody is fine when the credential names someone."""
    led = _ledger()
    status, _ = handle_decision(led, _extract(), _request(),
                                authenticated_principal="jane@lender.com")
    assert status == 200
    ai = [r for r in led.records() if r.get("event") == "ai_decision"]
    assert ai and ai[0]["principal"] == "jane@lender.com"


def test_a_body_claiming_another_principal_is_refused() -> None:
    """The control. Silently rewriting the claim would be worse than refusing:
    a caller that believes it acts for someone else should be told it does not."""
    led = _ledger()
    calls: list = []
    try:
        handle_decision(led, _extract(calls),
                        _request(principal="jane@lender.com"),
                        authenticated_principal="mallory@lender.com")
        raise AssertionError("GatewayError was not raised")
    except GatewayError as exc:
        assert exc.status == 403
        assert "jane@lender.com" in str(exc)
    assert calls == [], "the model was called on a contested identity"


def test_a_matching_claim_is_allowed() -> None:
    """Naming yourself is redundant, not an error."""
    led = _ledger()
    status, _ = handle_decision(led, _extract(),
                                _request(principal="jane@lender.com"),
                                authenticated_principal="jane@lender.com")
    assert status == 200


def test_without_a_bound_identity_the_body_still_names_the_principal() -> None:
    """Backwards compatible: a plain shared token behaves as it always did."""
    led = _ledger()
    status, _ = handle_decision(led, _extract(),
                                _request(principal="jane@lender.com"))
    assert status == 200
    ai = [r for r in led.records() if r.get("event") == "ai_decision"]
    assert ai and ai[0]["principal"] == "jane@lender.com"


# ------------------------------------------------------------------ transport

def _running(identities=None, token=None):
    """A gateway on a real socket, so the binding is tested where it is read."""
    import threading
    from http.server import ThreadingHTTPServer

    from custody.gateway import _handler

    led = _ledger()
    handler = _handler(led, _extract(), token, identities=identities)
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    return httpd, led, f"http://127.0.0.1:{httpd.server_port}/decision"


def _post(url, body, bearer=None):
    import json as _json
    import urllib.error
    import urllib.request

    req = urllib.request.Request(
        url, data=_json.dumps(body).encode(),
        headers={"Content-Type": "application/json"}, method="POST")
    if bearer:
        req.add_header("Authorization", f"Bearer {bearer}")
    try:
        with urllib.request.urlopen(req, timeout=5) as r:
            return r.status, _json.loads(r.read())
    except urllib.error.HTTPError as e:
        return e.code, _json.loads(e.read() or b"{}")


def test_a_token_bound_to_an_identity_names_the_principal_itself() -> None:
    httpd, led, url = _running(identities={"tok-jane": "jane@lender.com"})
    try:
        status, _ = _post(url, _request(), bearer="tok-jane")
        assert status == 200, status
        ai = [r for r in led.records() if r.get("event") == "ai_decision"]
        assert ai and ai[0]["principal"] == "jane@lender.com"
    finally:
        httpd.shutdown()


def test_a_bound_token_cannot_be_used_to_write_someone_elses_name() -> None:
    """The hole this closes: a valid credential asserting an identity it does
    not hold."""
    httpd, led, url = _running(identities={"tok-mallory": "mallory@lender.com"})
    try:
        status, body = _post(url, _request(principal="jane@lender.com"),
                             bearer="tok-mallory")
        assert status == 403, status
        assert "mallory@lender.com" in body["error"]
        assert led.store.count() == 0, "a contested identity reached the ledger"
    finally:
        httpd.shutdown()


def test_an_unknown_token_is_still_unauthorised() -> None:
    httpd, _led, url = _running(identities={"tok-jane": "jane@lender.com"})
    try:
        status, _ = _post(url, _request(), bearer="tok-nobody")
        assert status == 401, status
    finally:
        httpd.shutdown()


def test_identities_load_from_a_file() -> None:
    """`--identities` reads a path, and nothing else here exercised that path.

    The dict-taking tests above all passed while `load_identities` raised
    NameError on its first line, which is the difference between testing a
    function and testing the way it is actually reached.
    """
    import json as _json
    import tempfile

    from custody.gateway import load_identities

    with tempfile.TemporaryDirectory() as tmp:
        path = pathlib.Path(tmp) / "callers.json"
        path.write_text(_json.dumps({"tok-jane": "jane@lender.com"}))
        path.chmod(0o600)
        assert load_identities(path) == {"tok-jane": "jane@lender.com"}


def test_an_identities_file_that_is_not_token_to_principal_is_refused() -> None:
    import json as _json
    import tempfile

    from custody.gateway import load_identities

    with tempfile.TemporaryDirectory() as tmp:
        path = pathlib.Path(tmp) / "bad.json"
        path.write_text(_json.dumps({"tok-jane": ["jane@lender.com"]}))
        try:
            load_identities(path)
            raise AssertionError("a list principal was accepted")
        except SystemExit:
            pass


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
