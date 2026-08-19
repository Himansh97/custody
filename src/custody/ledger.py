"""The API surface: a decision you cannot make without recording it.

The design premise is that compliance logging fails when it is a separate step.
Someone adds a model call in a hurry, the `log.write(...)` after it never gets
written, and nobody notices until an examiner asks. So here the call *is* the
record — you open a decision, and the only way to reach the model is through it:

    with ledger.decision(loan="1000254", principal="jane@lender.com",
                         purpose="income_calculation") as d:
        out     = d.call(model="claude-sonnet-5", prompt=p, sources=[paystub, w2])
        verdict = d.gate(out, citations=cites, confidence=0.93)
        if verdict.ok:
            d.commit(outcome={"monthly_income": 4206.00})
        else:
            d.route_to_human(queue="uw-review")

Every field LL-2026-04 names is filled as a side effect of using it normally,
which is the only kind of instrumentation that survives contact with a deadline.

A decision that is opened and never resolved still writes a record. So does one
that raises. An audit trail with holes in it where the awkward cases were is
worse than no audit trail, because it looks complete.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Iterable, Sequence

from .chain import seal
from .signing import ED25519, LocalSigner, public_bytes
from .redact import redact_value
from .store import Store, open_store
from .verify import REJECT, REVIEW, Verdict, gate as run_gate

# The eight fields LL-2026-04 requires on every AI decision record. Named here
# rather than left implicit across the module so the mandate-coverage test has
# one thing to assert against and a reader has one place to check.
MANDATE_FIELDS = (
    "principal",
    "model",
    "endpoint",
    "prompt_redacted",
    "response_treatment",
    "policy_version",
    "decision_outcome",
    "timestamp",
)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


class Decision:
    """One AI decision, from prompt to outcome. Created by `Ledger.decision`."""

    def __init__(
        self,
        ledger: "Ledger",
        *,
        loan: str,
        principal: str,
        purpose: str,
        identifiers: Iterable[str],
    ):
        self.ledger = ledger
        self.loan = loan
        self.principal = principal
        self.purpose = purpose
        self.identifiers = tuple(identifiers)
        self.record_id = f"dec_{uuid.uuid4().hex[:16]}"
        self.opened_at = _now()

        self.model: str | None = None
        self.endpoint: str | None = None
        self.prompt: str | None = None
        self.sources: tuple[str, ...] = ()
        self.response: Any = None
        self.verdict: Verdict | None = None
        self.outcome: dict[str, Any] | None = None
        self.disposition: str | None = None
        self.note: str | None = None
        self._written = False

    # ---------------------------------------------------------------- the call

    def call(
        self,
        *,
        model: str,
        prompt: str,
        sources: Sequence[str] = (),
        endpoint: str | None = None,
        invoke: Callable[[], Any] | None = None,
        response: Any = None,
    ) -> Any:
        """Record the call and return the model's output.

        `invoke` is called here so the metadata is captured whether or not the
        model raises. Passing `response` instead suits replaying a call made
        elsewhere — and the demo, which ships fixed outputs so the same run is
        reproducible by anyone reading the repo.
        """
        if invoke is None and response is None:
            raise ValueError("call() needs either invoke= or response=")

        self.model = model
        self.endpoint = endpoint or f"anthropic:messages:{model}"
        self.prompt = prompt
        self.sources = tuple(sources)
        self.response = invoke() if invoke is not None else response
        return self.response

    # ---------------------------------------------------------------- the gate

    def gate(self, output: dict[str, Any], **kwargs: Any) -> Verdict:
        """Run the deterministic checks. `sources` defaults to what `call` saw."""
        kwargs.setdefault("sources", self.sources)
        self.verdict = run_gate(output, **kwargs)
        return self.verdict

    # -------------------------------------------------------------- the ending

    def commit(self, outcome: dict[str, Any]) -> None:
        """What was actually written downstream — the mandate's decision_outcome.

        Committing behind a failed gate is allowed but recorded as an override,
        because a system that makes it impossible gets bypassed entirely and
        then nothing is recorded at all. An override that is visible in the log
        is far better than one that happened outside it.
        """
        self.outcome = outcome
        if self.verdict is not None and self.verdict.treatment == REJECT:
            self.disposition = "committed_over_rejection"
            self.note = "committed despite a rejecting verdict"
        else:
            self.disposition = "committed"

    def route_to_human(self, *, queue: str, note: str | None = None) -> None:
        self.disposition = "routed_to_human"
        self.note = note or f"routed to {queue}"

    # ------------------------------------------------------------ the recording

    def __enter__(self) -> "Decision":
        return self

    def __exit__(self, exc_type, exc, tb) -> bool:
        if exc is not None:
            self.disposition = "errored"
            self.note = f"{exc_type.__name__}: {exc}"
        elif self.disposition is None:
            # Opened, used, and abandoned. Recorded rather than dropped: a gap is
            # indistinguishable from a deletion to whoever reads this later.
            self.disposition = "abandoned"
            self.note = "the decision was opened and never resolved"
        self._write()
        return False   # never swallow the caller's exception

    def _write(self) -> None:
        if self._written:
            return
        self._written = True

        treatment = self.verdict.treatment if self.verdict else REVIEW
        record = {
            "record_id": self.record_id,
            "event": "ai_decision",
            "loan": self.loan,
            "purpose": self.purpose,
            # --- the eight mandate fields ---
            "principal": self.principal,
            "model": self.model,
            "endpoint": self.endpoint,
            "prompt_redacted": redact_value(
                self.prompt, loan=self.loan, identifiers=self.identifiers
            ),
            "response_treatment": treatment,
            "policy_version": self.ledger.policy,
            "decision_outcome": redact_value(
                self.outcome, loan=self.loan, identifiers=self.identifiers
            ),
            "timestamp": self.opened_at,
            # --- why, and what happened next ---
            "findings": self.verdict.as_dict()["findings"] if self.verdict else [],
            "disposition": self.disposition,
            "note": self.note,
            "sources_seen": len(self.sources),
            "completed_at": _now(),
        }
        self.ledger._append(record)


class Ledger:
    def __init__(
        self,
        *,
        policy: str,
        signing_key=None,
        signer=None,
        store: Store | None = None,
        path: str | Path = ":memory:",   # or a postgresql:// DSN
    ):
        """`signer` is the way in: a LocalSigner, a KeyVaultSigner, or anything
        with `.algorithm`, `.sign(digest)` and `.public_key_bytes()`.

        `signing_key` still accepts a raw private key and wraps it, so callers
        written before signers existed keep working.
        """
        if signer is None:
            if signing_key is None:
                raise ValueError("a Ledger needs either signer= or signing_key=")
            signer = (
                signing_key
                if hasattr(signing_key, "algorithm")
                else LocalSigner(signing_key, ED25519)
            )
        self.policy = policy
        self.signer = signer
        self.store = store or open_store(path)

    @property
    def algorithm(self) -> str:
        return self.signer.algorithm

    @property
    def public_key_hex(self) -> str:
        return self.signer.public_key_bytes().hex()

    @property
    def public_key(self):
        """The public key object, for `verify_chain`."""
        from .signing import load_public_key
        return load_public_key(self.signer.public_key_bytes(), self.signer.algorithm)

    def decision(
        self,
        *,
        loan: str,
        principal: str,
        purpose: str,
        identifiers: Iterable[str] = (),
    ) -> Decision:
        return Decision(
            self, loan=loan, principal=principal, purpose=purpose, identifiers=identifiers
        )

    def human_review(
        self,
        *,
        loan: str,
        reviewer: str,
        decision_id: str,
        action: str,
        outcome: dict[str, Any] | None = None,
        note: str | None = None,
        identifiers: Iterable[str] = (),
    ) -> str:
        """Record a person's decision about an AI output.

        This is the half of the trail that actually answers the GSE's question.
        "The model proposed X" is not oversight; "a named person saw the model
        propose X, at this time, and did Y about it" is. It chains into the same
        ledger as the AI record it refers to, so the two cannot drift apart.
        """
        record_id = f"hum_{uuid.uuid4().hex[:16]}"
        self._append(
            {
                "record_id": record_id,
                "event": "human_review",
                "loan": loan,
                "purpose": "human_review",
                "principal": reviewer,
                "model": None,
                "endpoint": None,
                "prompt_redacted": None,
                "response_treatment": "human_decision",
                "policy_version": self.policy,
                "decision_outcome": redact_value(
                    outcome, loan=loan, identifiers=identifiers
                ),
                "timestamp": _now(),
                "reviews": decision_id,
                "action": action,
                "note": note,
                "findings": [],
                "disposition": f"human_{action}",
            }
        )
        return record_id

    def _append(self, record: dict[str, Any]) -> None:
        # Atomic read-seal-write. Sealing against a head read in a separate call
        # lets two concurrent writers chain onto the same predecessor and fork
        # the chain.
        self.store.append_chained(record, lambda r, head: seal(r, head, self.signer))

    # --------------------------------------------------------------- read side

    def records(self) -> list[dict[str, Any]]:
        return self.store.all()

    def for_loan(self, loan: str) -> list[dict[str, Any]]:
        return self.store.by_loan(loan)
