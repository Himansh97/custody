"""`custody serve` exposes an audit trail. It must not do so unauthenticated.

Fannie Mae's Information Security and Business Resiliency Supplement section 3.1
requires access to Confidential Information be limited to authorised users on a
need-to-know basis. The ledger contains loan numbers and derived financial data,
so a port anyone on the network can read is not that.

The token is a floor, not a control -- one shared secret, no identity behind it.
These tests pin the floor.
"""
from __future__ import annotations

import pathlib
import sys
import threading
import urllib.error
import urllib.request

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent / "src"))

from http.server import ThreadingHTTPServer  # noqa: E402

from custody.ledger import Ledger  # noqa: E402
from custody.server import _handler, serve  # noqa: E402
from custody.signing import LocalSigner  # noqa: E402


def _ledger() -> Ledger:
    led = Ledger(policy="p", signer=LocalSigner())
    with led.decision(loan="1", principal="a@b.example", purpose="x") as d:
        out = d.call(model="m", prompt="p", sources=["Gross pay 4,206.00"],
                     response={"g": 4206.00})
        d.gate(out, citations={"g": "paystub"}, confidence=0.95)
        d.commit(outcome=out)
    return led


def _running(token):
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), _handler(_ledger(), token))
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    return httpd, f"http://127.0.0.1:{httpd.server_port}"


def _get(url, header_token=None):
    request = urllib.request.Request(url)
    if header_token:
        request.add_header("Authorization", f"Bearer {header_token}")
    try:
        with urllib.request.urlopen(request, timeout=5) as response:
            return response.status
    except urllib.error.HTTPError as exc:
        return exc.code


def test_without_a_token_the_ledger_is_not_readable() -> None:
    httpd, base = _running("s3cret")
    try:
        for path in ("/", "/api/records", "/api/verify", "/api/loan/1"):
            assert _get(base + path) == 401, f"{path} served without a token"
    finally:
        httpd.shutdown()


def test_a_wrong_token_is_rejected() -> None:
    httpd, base = _running("s3cret")
    try:
        assert _get(base + "/api/records", "wrong") == 401
        assert _get(base + "/api/records?token=wrong") == 401
    finally:
        httpd.shutdown()


def test_the_right_token_works_in_a_header_or_a_query() -> None:
    httpd, base = _running("s3cret")
    try:
        assert _get(base + "/api/records", "s3cret") == 200
        assert _get(base + "/api/records?token=s3cret") == 200
        assert _get(base + "/?token=s3cret") == 200
    finally:
        httpd.shutdown()


def test_binding_beyond_loopback_without_a_token_is_refused() -> None:
    """Warning and starting anyway is how an unauthenticated audit trail ends up
    on a network. The person who did it remembers a decision, not a warning they
    scrolled past."""
    try:
        serve(db=":memory:", key_path=None, host="0.0.0.0", port=0)
    except SystemExit as exc:
        assert "refusing to bind" in str(exc)
        assert "CUSTODY_TOKEN" in str(exc)
    except Exception as exc:      # noqa: BLE001 - anything else means it got past the guard
        raise AssertionError(f"expected a refusal, got {exc!r}") from None
    else:
        raise AssertionError("it bound 0.0.0.0 with no token")


def test_no_token_mode_still_exists_for_people_who_mean_it() -> None:
    httpd, base = _running(None)
    try:
        assert _get(base + "/api/verify") == 200
    finally:
        httpd.shutdown()


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
