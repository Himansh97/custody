"""`custody gateway` -- governance for callers that are not Python.

The library form of Custody works because there is no way to reach the model
that does not go through a `Decision`. A .NET service in the LOS cannot use it,
and the obvious answer -- publish an authorize endpoint and a validate endpoint
and ask the caller to use both -- quietly gives up the property that made the
library worth having. A caller can authorize, ignore the answer, call the model
itself and never validate. Nothing about that shape prevents it, and the failure
is silent: you find out when someone asks for records of a use case whose
records were never written.

So the gateway does not advise. The model call is made **here**, on the far side
of the policy check, and the caller gets the output only after it has been
gated and recorded. There is no request that returns a model's answer and no
record, because there is no code path that produces one.

    POST /decision
    {
      "loan": "1000254",
      "principal": "jane@lender.com",
      "purpose": "income_calculation",
      "model": "claude-sonnet-5",
      "instruction": "Extract qualifying monthly income.",
      "documents": [{"id": "paystub-2026-07-15", "text": "..."}],
      "identifiers": ["Dana Whitfield"],
      "data": ["income", "paystub"]
    }

Same auth posture as `custody serve`, and the same warning: a shared bearer
token is a floor, not a control. It carries no identity, which is exactly what
`principal` in the record is claiming to be -- so in front of anything real this
belongs behind the same SSO as the rest of the estate, with `principal` taken
from the authenticated session rather than from the request body. The banner
says so on every start.
"""
from __future__ import annotations

import hmac
import json
import os
import secrets
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from .ledger import Ledger
from .policy import PolicyDenied

# A body larger than this is refused before it is read. The documents a decision
# needs are paystubs and W-2s; anything at this scale is a mistake or an attempt
# to exhaust the process, and both should fail fast.
MAX_BODY = 4 * 1024 * 1024


class GatewayError(Exception):
    def __init__(self, status: int, message: str):
        self.status = status
        super().__init__(message)


def _documents(payload: dict) -> list[tuple[str, str]]:
    docs = payload.get("documents") or []
    if not isinstance(docs, list):
        raise GatewayError(400, "documents must be a list")
    out: list[tuple[str, str]] = []
    for index, doc in enumerate(docs):
        if isinstance(doc, str):
            out.append((f"doc-{index}", doc))
        elif isinstance(doc, dict) and "text" in doc:
            out.append((str(doc.get("id") or f"doc-{index}"), str(doc["text"])))
        else:
            raise GatewayError(400, f"document {index} needs a text field")
    return out


def handle_decision(ledger: Ledger, extract, payload: dict) -> tuple[int, dict]:
    """One decision, start to finish. Returns the HTTP status and the body.

    Split out from the HTTP plumbing so it can be tested without a socket, and
    so the only difference between the gateway and the library is transport.
    """
    for required in ("loan", "principal", "purpose"):
        if not payload.get(required):
            raise GatewayError(400, f"{required} is required")

    documents = _documents(payload)
    instruction = payload.get("instruction") or ""
    model = payload.get("model") or "claude-sonnet-5"
    queue = payload.get("queue") or "review"

    # The model call goes inside `invoke`, so the policy check in `Decision.call`
    # runs before it rather than beside it. Calling the adapter first and passing
    # the result in would put the model on the far side of nothing at all.
    got: dict = {}

    def invoke():
        fields, confidence, endpoint, citations = extract(instruction, documents)
        got.update(fields=fields, confidence=confidence, endpoint=endpoint,
                   citations=citations)
        return fields

    denied: dict | None = None
    allowed: dict | None = None

    with ledger.decision(
        loan=str(payload["loan"]),
        principal=str(payload["principal"]),
        purpose=str(payload["purpose"]),
        identifiers=payload.get("identifiers") or (),
        data=payload.get("data") or (),
    ) as d:
        try:
            d.call(model=model, prompt=instruction,
                   sources=[text for _, text in documents], invoke=invoke)
        except PolicyDenied as exc:
            # 403 and no output. The caller learns it was refused and why; it
            # does not learn what the model would have said, because the model
            # was never asked.
            denied = {
                "decision": "denied",
                "record_id": d.record_id,
                "reason": str(exc),
                "policy": ledger.policy,
            }
        else:
            # What answered, not what was asked for.
            d.resolved(got.get("endpoint") or "")
            verdict = d.gate(got["fields"], citations=got.get("citations"),
                             confidence=got.get("confidence"))
            if verdict.ok:
                d.commit(outcome=got["fields"])
            else:
                d.route_to_human(queue=queue)
            allowed = {
                "decision": "allowed",
                "record_id": d.record_id,
                "treatment": verdict.treatment,
                "findings": verdict.as_dict()["findings"],
                "fields": got["fields"] if verdict.ok else None,
                "confidence": got.get("confidence"),
                "endpoint": d.endpoint,
                "policy": ledger.policy,
            }

    # Outside the block on purpose: the record is written on the way out, so the
    # disposition and the anchor are only true here. Reading them inside would
    # hand the caller an anchor for a ledger that did not yet contain this
    # decision -- an anchor that is wrong the instant it is stored.
    if denied is not None:
        denied["anchor"] = ledger.anchor
        return 403, denied

    allowed["disposition"] = d.disposition
    # Handed back so the caller can ship it somewhere out of this system's reach
    # without a second round trip.
    allowed["anchor"] = ledger.anchor
    return 200, allowed


def _handler(ledger: Ledger, extract, token: str | None):
    class Handler(BaseHTTPRequestHandler):
        server_version = "custody-gateway"

        def _json(self, code: int, payload) -> None:
            body = json.dumps(payload, indent=1, default=str).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)

        def _authorised(self) -> bool:
            if token is None:
                return True
            header = self.headers.get("Authorization", "")
            supplied = header[7:] if header.startswith("Bearer ") else ""
            return hmac.compare_digest(supplied, token)

        def do_POST(self) -> None:  # noqa: N802 - stdlib naming
            if not self._authorised():
                self._json(401, {"error": "unauthorised"})
                return
            if self.path.rstrip("/") not in ("/decision", ""):
                self._json(404, {"error": "not found", "routes": ["POST /decision"]})
                return

            length = int(self.headers.get("Content-Length") or 0)
            if length > MAX_BODY:
                self._json(413, {"error": f"body larger than {MAX_BODY} bytes"})
                return
            try:
                payload = json.loads(self.rfile.read(length) or b"{}")
            except json.JSONDecodeError as exc:
                self._json(400, {"error": f"body is not JSON: {exc}"})
                return
            if not isinstance(payload, dict):
                self._json(400, {"error": "body must be a JSON object"})
                return

            try:
                status, body = handle_decision(ledger, extract, payload)
            except GatewayError as exc:
                self._json(exc.status, {"error": str(exc)})
                return
            except Exception as exc:                       # noqa: BLE001
                # The decision recorded itself as errored on the way out of the
                # context manager, so the ledger already has this. What the
                # caller gets back is the type, not the message: an exception
                # string from a model client is a place borrower details turn up
                # unplanned, and this one crosses a network.
                self._json(502, {"error": type(exc).__name__})
                return
            self._json(status, body)

        def do_GET(self) -> None:  # noqa: N802 - stdlib naming
            if self.path.rstrip("/") in ("/health", ""):
                self._json(200, {"ok": True, "policy": ledger.policy,
                                 "records": ledger.store.count()})
                return
            self._json(404, {"error": "the gateway only answers POST /decision"})

        def log_message(self, fmt, *args):
            print(f"  {self.address_string()} {fmt % args}")

    return Handler


LOCAL = ("127.0.0.1", "localhost", "::1")


def serve_gateway(*, ledger: Ledger, extract, host: str = "127.0.0.1",
                  port: int = 8788, token: str | None = None,
                  no_token: bool = False) -> None:
    token = token or os.environ.get("CUSTODY_TOKEN")

    if host not in LOCAL and not token and not no_token:
        raise SystemExit(
            f"refusing to bind {host} with no token.\n"
            "  This endpoint calls a model with documents you post to it and writes\n"
            "  loan records. Set CUSTODY_TOKEN, pass --token, or bind 127.0.0.1.\n"
            "  --no-token overrides this, and you should have a reason."
        )
    if host in LOCAL and token is None and not no_token:
        token = secrets.token_urlsafe(24)

    print(f"custody gateway  policy {ledger.policy}  signed with {ledger.algorithm}")
    if ledger.policy_doc is None:
        print("  WARNING: no policy document. Nothing is being enforced -- every")
        print("           purpose and model will be allowed. Pass --policy a .json.")
    else:
        review = ledger.review_status()
        if review and review["overdue"]:
            print(f"  WARNING: {review['detail']}")
    print(f"  POST http://{host}:{port}/decision")
    if token:
        print(f"  Authorization: Bearer {token}")
    else:
        print("  NO TOKEN -- anyone who can reach this port can spend your model budget")
    print()
    print("  A bearer token is a floor, not a control. It carries no identity, and")
    print("  `principal` on every record is a claim the caller makes about itself.")
    print("  Put this behind your SSO and set principal from the session.")
    print("  ctrl-c to stop")

    httpd = ThreadingHTTPServer((host, port), _handler(ledger, extract, token))
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nstopped.")
    finally:
        httpd.server_close()
