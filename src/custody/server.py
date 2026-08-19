"""`custody serve` — the same review page, backed by a live ledger.

Stdlib only, and bound to localhost by default. This is a tool for looking at
your own ledger on your own machine, not a service: it has no authentication,
and a component holding an audit trail should not be quietly reachable by
anything that can route to it. Binding elsewhere requires saying so explicitly,
and says so back.

The page it renders is the same file the public demo is baked from, so what a
lender clicks on the website and what they get after installing are the same
product.
"""
from __future__ import annotations

import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import unquote, urlparse

from .examiner import chain_status, packet
from .ledger import Ledger
from .render import build_html


def _bundle(ledger: Ledger) -> dict:
    records = ledger.records()
    loans = sorted({r["loan"] for r in records})
    return {
        "generated_at": "live",
        "policy_version": ledger.policy,
        "public_key": ledger.public_key.public_bytes_raw().hex(),
        "chain": chain_status(records, ledger.public_key),
        "records": records,
        "packets": {loan: packet(ledger, loan) for loan in loans},
    }


def _handler(ledger: Ledger):
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

        def do_GET(self) -> None:  # noqa: N802 - stdlib naming
            path = urlparse(self.path).path

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


def serve(*, db: str, key_path: str | None, host: str = "127.0.0.1", port: int = 8787) -> None:
    from .cli import load_key

    ledger = Ledger(policy="-", signing_key=load_key(key_path), path=db)
    records = ledger.records()
    status = chain_status(records, ledger.public_key)

    print(f"custody  {db}  {len(records)} records")
    print(f"         chain: {'verified' if status['verified'] else status}")
    if host not in ("127.0.0.1", "localhost", "::1"):
        print(f"         WARNING: bound to {host} with no authentication — this exposes")
        print( "         an audit trail to anything that can reach this port.")
    print(f"         http://{host}:{port}/   (ctrl-c to stop)")

    httpd = ThreadingHTTPServer((host, port), _handler(ledger))
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nstopped.")
    finally:
        httpd.server_close()
