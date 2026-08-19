"""`custody serve` — the same review page, backed by a live ledger.

Stdlib only. What this serves is an audit trail containing loan numbers and
derived financial data, so it is bound to localhost by default and refuses
outright to bind anywhere else without a token. Fannie Mae's Information
Security and Business Resiliency Supplement §3.1 requires access to Confidential
Information be limited to authorised users on a need-to-know basis; a port
anybody on the network can read is not that.

The token is a floor, not a control. It is one shared secret with no identity
behind it, which satisfies nothing the Supplement says about unique user IDs,
MFA or least privilege. A real deployment puts this behind the same SSO the rest
of the estate uses and does not expose it directly at all. The banner says so
every time it starts, because a tool that lets you do the wrong thing quietly is
how the wrong thing ends up in production.

The page it renders is the same file the public demo is baked from, so what a
lender clicks on the website and what they get after installing are the same
product.
"""
from __future__ import annotations

import hmac
import json
import os
import secrets
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, unquote, urlparse

from .examiner import chain_status, packet
from .ledger import Ledger
from .render import build_html


def _bundle(ledger: Ledger) -> dict:
    records = ledger.records()
    loans = sorted({r["loan"] for r in records})
    return {
        "generated_at": "live",
        "policy_version": ledger.policy,
        "public_key": ledger.public_key_hex,
        "sig_alg": ledger.algorithm,
        "chain": chain_status(records, ledger.public_key),
        "records": records,
        "packets": {loan: packet(ledger, loan) for loan in loans},
    }


def _handler(ledger: Ledger, token: str | None):
    class Handler(BaseHTTPRequestHandler):
        server_version = "custody"

        def _send(self, code: int, body: bytes, content_type: str) -> None:
            self.send_response(code)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            # This page is the audit record. Nothing about it should be cached
            # by anything, including the browser that just showed a stale
            # verification result.
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)

        def _json(self, code: int, payload) -> None:
            self._send(code, json.dumps(payload, indent=1, default=str).encode(),
                       "application/json; charset=utf-8")

        def _authorised(self, query: dict) -> bool:
            if token is None:
                return True
            supplied = ""
            header = self.headers.get("Authorization", "")
            if header.startswith("Bearer "):
                supplied = header[7:]
            elif "token" in query:
                # Accepted so a link can be shared with a colleague, at the cost
                # of the token landing in browser history and any proxy log. It
                # is the weaker path and is documented as such.
                supplied = query["token"][0]
            # Constant-time: a plain == leaks the token one character at a time
            # to anyone willing to measure.
            return hmac.compare_digest(supplied, token)

        def do_GET(self) -> None:  # noqa: N802 - stdlib naming
            parsed = urlparse(self.path)
            path = parsed.path
            query = parse_qs(parsed.query)

            if not self._authorised(query):
                self.send_response(401)
                self.send_header("WWW-Authenticate", 'Bearer realm="custody"')
                self.send_header("Content-Length", "0")
                self.end_headers()
                return

            if path in ("/", "/index.html"):
                # Rendered per request rather than cached: a ledger that gained
                # records since the page was built should show them, and a page
                # showing yesterday's chain while claiming to be live would be
                # the same class of lie the project exists to prevent.
                self._send(200, build_html(_bundle(ledger)).encode("utf-8"),
                           "text/html; charset=utf-8")
                return

            if path == "/api/records":
                self._json(200, ledger.records())
                return

            if path == "/api/verify":
                self._json(200, chain_status(ledger.records(), ledger.public_key))
                return

            if path.startswith("/api/loan/"):
                loan = unquote(path[len("/api/loan/"):]).strip("/")
                result = packet(ledger, loan)
                if not result["records"]:
                    self._json(404, {"error": f"no records for loan {loan}"})
                    return
                self._json(200, result)
                return

            self._json(404, {"error": "not found",
                             "routes": ["/", "/api/records", "/api/verify", "/api/loan/{loan}"]})

        def log_message(self, fmt, *args):
            print(f"  {self.address_string()} {fmt % args}")

    return Handler


LOCAL = ("127.0.0.1", "localhost", "::1")


def serve(*, db: str, key_path: str | None, host: str = "127.0.0.1", port: int = 8787,
          token: str | None = None, no_token: bool = False) -> None:
    from .cli import load_signer

    token = token or os.environ.get("CUSTODY_TOKEN")

    if host not in LOCAL and not token and not no_token:
        # Refusing is the whole point. Warning and starting anyway is how an
        # unauthenticated audit trail ends up on a network, and the person who
        # did it will remember a warning they scrolled past, not a decision.
        raise SystemExit(
            f"refusing to bind {host} with no token.\n"
            "  This serves an audit trail containing loan numbers and financial data.\n"
            "  Set CUSTODY_TOKEN, pass --token, or bind 127.0.0.1.\n"
            "  --no-token overrides this, and you should have a reason."
        )
    if host in LOCAL and token is None and not no_token:
        # A token even on loopback, because anything else running on this host
        # can reach it -- including a browser tab on a page you did not write.
        token = secrets.token_urlsafe(24)

    signer = load_signer(key_path)
    ledger = Ledger(policy="-", signer=signer, path=db)
    records = ledger.records()
    status = chain_status(records, ledger.public_key)

    print(f"custody  {db}  {len(records)} records  signed with {signer.algorithm}")
    print(f"         chain: {'verified' if status['verified'] else status}")
    if token:
        print(f"         http://{host}:{port}/?token={token}")
    else:
        print(f"         http://{host}:{port}/   (NO TOKEN -- anyone who can reach this port)")
    if host not in LOCAL:
        print()
        print("         This is bound beyond loopback. A shared token is a floor, not a")
        print("         control: no identity, no MFA, no least privilege. Put it behind")
        print("         your SSO before anyone but you uses it.")
    print("         ctrl-c to stop")

    httpd = ThreadingHTTPServer((host, port), _handler(ledger, token))
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nstopped.")
    finally:
        httpd.server_close()
