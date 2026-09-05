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

from .chain import make_anchor, seal
from .signing import ED25519, LocalSigner, public_bytes
from .policy import HUMAN_ALWAYS, Allowance, Policy, PolicyDenied, as_policy
from .redact import redact_value
from .store import Store, open_store
from .verify import DENIED, REJECT, REVIEW, Verdict, gate as run_gate

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


# What a refused call must still carry. A denial has no model output to
# describe, so the full set would report gaps that are simply the truth about a
# call that never happened.
DENIAL_FIELDS = (
    "principal",
    "response_treatment",
    "policy_version",
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
        data: Iterable[str] = (),
        allowance: Allowance | None = None,
    ):
        self.ledger = ledger
        # None means no policy engine is in use -- the original interface, where
        # `policy` was a version string nothing evaluated. Recorded as such
        # rather than as an allow, because "nothing checked" and "checked and
        # permitted" are different facts about a decision.
        self.allowance = allowance
        self.loan = loan
        self.principal = principal
        self.purpose = purpose
        self.identifiers = tuple(identifiers)
        # What the caller says this decision touches. Declared rather than
        # inferred: "income" has no shape, and a policy rule that silently fails
        # to apply is a control document making a false statement.
        self.data = tuple(str(d) for d in data)
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
        self.denial: Allowance | None = None
        self.model_drift: Allowance | None = None
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

        # Before `invoke`, never after. A policy check that runs alongside the
        # call is advice; one the call cannot get past is a control.
        self._enforce_policy()

        self.response = invoke() if invoke is not None else response
        return self.response

    def _enforce_policy(self) -> None:
        """Raise `PolicyDenied` unless the policy permits this purpose and model.

        Raising rather than returning is deliberate. A caller who ignores a
        returned verdict still reaches the model; a caller who ignores an
        exception does not exist.
        """
        if self.allowance is None:
            return
        if not self.allowance.allowed:
            self._deny(self.allowance)

        policy = self.ledger.policy_doc
        if policy is not None:
            # The documents as well as the declaration, so a prohibited class
            # with a recognisable shape cannot be evaded by naming another one.
            verdict = policy.for_data(
                self.purpose, self.data, (self.prompt or "",) + self.sources
            )
            if not verdict.allowed:
                self._deny(verdict)

            verdict = policy.for_model(self.purpose, self.model, self.endpoint)
            if not verdict.allowed:
                self._deny(verdict)
            # The model check can tighten nothing else, but it resolves the
            # allowance against the endpoint that actually answered.
            self.allowance = verdict

    def _deny(self, allowance: Allowance) -> None:
        self.denial = allowance
        raise PolicyDenied(allowance)

    def resolved(self, endpoint: str) -> None:
        """Record the endpoint that actually answered, and re-check the policy.

        The pre-call check can only test the model that was *asked for*. A
        deployment name resolves to a real model version in the response, and
        that version can change without a code change -- so the second check has
        to happen here, after the call, and cannot prevent it. What it can do is
        stop the output being used and say why in the record.
        """
        if not endpoint:
            return
        self.endpoint = endpoint
        if ":" in endpoint:
            self.model = endpoint.rsplit(":", 1)[-1]

        policy = self.ledger.policy_doc
        if policy is None:
            return
        verdict = policy.for_model(self.purpose, self.model, endpoint)
        if verdict.allowed:
            self.allowance = verdict
        else:
            self.model_drift = verdict

    # ---------------------------------------------------------------- the gate

    def gate(self, output: dict[str, Any], **kwargs: Any) -> Verdict:
        """Run the deterministic checks.

        `sources` defaults to what `call` saw. The confidence floor, the closed
        vocabularies and whether a human is required regardless of the verdict
        come from the policy when there is one, so that the risk tolerance a
        lender approved is the one that runs -- rather than whatever an
        engineer typed at the call site. An explicit keyword still wins, and is
        visible in the diff of the code that overrode it.
        """
        kwargs.setdefault("sources", self.sources)
        if self.allowance is not None and self.allowance.allowed:
            kwargs.setdefault("confidence_floor", self.allowance.confidence_floor)
            kwargs.setdefault(
                "human_review_required", self.allowance.human_review == HUMAN_ALWAYS
            )
            if self.allowance.vocabulary:
                kwargs.setdefault("allowed", dict(self.allowance.vocabulary))
        if self.model_drift is not None:
            kwargs.setdefault("model_denied", self.model_drift.reason)
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
        no_authority = (
            self.allowance is not None
            and self.allowance.allowed
            and not self.allowance.ai_can_decide
        )
        if self.verdict is not None and self.verdict.treatment == REJECT:
            self.disposition = "committed_over_rejection"
            self.note = "committed despite a rejecting verdict"
        elif no_authority:
            # Same reasoning as committing over a rejection: refusing outright
            # sends the work around the ledger, and an override nobody can see
            # is worse than one recorded in the evidence.
            self.disposition = "committed_without_authority"
            self.note = (
                f"the policy for {self.purpose!r} permits AI to recommend but not "
                "to decide; this outcome was committed anyway"
            )
        else:
            self.disposition = "committed"

    def route_to_human(self, *, queue: str, note: str | None = None) -> None:
        self.disposition = "routed_to_human"
        self.note = note or f"routed to {queue}"

    # ------------------------------------------------------------ the recording

    def __enter__(self) -> "Decision":
        return self

    def __exit__(self, exc_type, exc, tb) -> bool:
        if isinstance(exc, PolicyDenied):
            # Not an error. The system worked: a call the policy did not permit
            # did not happen, and the refusal is evidence in its own right.
            self.disposition = "denied_by_policy"
            self.note = str(exc)
        elif exc is not None:
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

        denied = self.denial is not None
        treatment = DENIED if denied else (
            self.verdict.treatment if self.verdict else REVIEW
        )
        record = {
            "record_id": self.record_id,
            # A refused call is a different kind of event from a decision that
            # was made, and collapsing them would let a ledger of nothing but
            # denials read as a ledger of decisions.
            "event": "ai_denied" if denied else "ai_decision",
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
            # Which rules were in force and what they concluded. `unevaluated`
            # is the honest value when a caller passed a bare version string
            # instead of a policy: nothing checked, and a record should not
            # imply otherwise.
            **(
                (self.denial or self.allowance).as_record_fields()
                if (self.denial or self.allowance) is not None
                else {"policy_id": None, "policy_decision": "unevaluated",
                      "policy_reason": None}
            ),
            # Redacted like everything else. `note` carries free text a caller
            # passed to route_to_human(), and on the error path it is an
            # exception message -- which is exactly where a borrower's details
            # turn up unplanned, in the one field nobody thought to sanitise.
            "note": redact_value(
                self.note, loan=self.loan, identifiers=self.identifiers
            ),
            "sources_seen": len(self.sources),
            "data_classes": list(self.data),
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
        on_append: Callable[[str], None] | None = None,
        on_record: Callable[[dict[str, Any]], None] | None = None,
    ):
        """`signer` is the way in: a LocalSigner, a KeyVaultSigner, or anything
        with `.algorithm`, `.sign(digest)` and `.public_key_bytes()`.

        `signing_key` still accepts a raw private key and wraps it, so callers
        written before signers existed keep working.

        `policy` takes a `Policy`, a path to a policy JSON file, or -- as
        before -- a bare version string that nothing evaluates. The string form
        is kept because a ledger recording *something* about which rules were in
        force beats a migration that stops people adopting it, but only the
        first two forms enforce anything, and the records say which was used.
        """
        if signer is None and signing_key is not None:
            signer = (
                signing_key
                if hasattr(signing_key, "algorithm")
                else LocalSigner(signing_key, ED25519)
            )
        # signer=None opens the ledger read-only. Reading a ledger does not need
        # the private key -- verifying a signature needs the public one, and
        # producing a disclosure report needs neither. Requiring the signing key
        # to run a report would mean the person compiling evidence for an
        # examiner must also be able to write records, which is exactly the
        # separation of duties this library argues for everywhere else.
        self.policy_doc, self.policy = as_policy(policy)
        self.signer = signer
        self.store = store or open_store(path)
        # Called with the anchor token after every append, so an operator can
        # push it somewhere this process cannot later edit -- which is the only
        # way a truncation of the newest records becomes detectable. Deliberately
        # a callback rather than a built-in destination: the place that is out of
        # reach differs per lender, and guessing wrong would be worse than asking.
        self.on_append = on_append
        # The sealed record, for a replica somewhere else. Separate from
        # `on_append` because they are different jobs: a replica is for reading
        # and an anchor is for proving, and a lender who sends both to the same
        # place has one of them and thinks they have two.
        self.on_record = on_record
        self._public_key_hex: str | None = None

    @property
    def anchor(self) -> str:
        """What this ledger currently attests to. Record it somewhere else."""
        return make_anchor(self.store.count(), self.store.head_hash())

    @property
    def read_only(self) -> bool:
        return self.signer is None

    @property
    def algorithm(self) -> str | None:
        if self.signer is not None:
            return self.signer.algorithm
        records = self.store.all()
        # Self-describing: a ledger says how it was signed, so a reader does not
        # have to be told.
        return records[0].get("sig_alg", ED25519) if records else None

    @property
    def public_key_hex(self) -> str | None:
        if self.signer is not None:
            return self.signer.public_key_bytes().hex()
        return self._public_key_hex

    @property
    def public_key(self):
        """The public key object, for `verify_chain`. None if we do not have one.

        `verify_chain` accepts None and checks continuity alone, which is the
        honest result rather than a silent pass -- the same position the browser
        is in on the demo page.
        """
        from .signing import load_public_key
        if self.signer is not None:
            return load_public_key(self.signer.public_key_bytes(), self.signer.algorithm)
        if self._public_key_hex:
            return load_public_key(self._public_key_hex, self.algorithm or ED25519)
        return None

    def with_public_key(self, public_key_hex: str | None) -> "Ledger":
        """Supply a public key to a read-only ledger, so signatures get checked."""
        self._public_key_hex = public_key_hex
        return self

    def decision(
        self,
        *,
        loan: str,
        principal: str,
        purpose: str,
        identifiers: Iterable[str] = (),
        data: Iterable[str] = (),
    ) -> Decision:
        """Open a decision. The policy is evaluated here, enforced at `call`.

        Evaluating early means an unapproved purpose is known before a prompt is
        built; enforcing at `call` means the refusal lands on the line that would
        have reached the model, which is where a reader looks for it.
        """
        allowance = (
            self.policy_doc.for_purpose(purpose) if self.policy_doc is not None else None
        )
        return Decision(
            self, loan=loan, principal=principal, purpose=purpose,
            identifiers=identifiers, data=data, allowance=allowance,
        )

    def review_status(self, as_of=None) -> dict[str, Any] | None:
        """Whether this ledger's policy is inside its review interval.

        None when no policy document is in use -- there is nothing to be overdue.
        """
        if self.policy_doc is None:
            return None
        return self.policy_doc.review_status(as_of)

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
                # A reviewer types prose here -- "spoke to the borrower, see
                # the number on file". Free text from a human is the most
                # likely place for PII in the whole record.
                "note": redact_value(note, loan=loan, identifiers=identifiers),
                "findings": [],
                "disposition": f"human_{action}",
                "policy_id": self.policy_doc.policy_id if self.policy_doc else None,
                "policy_decision": "not_applicable",
                "data_classes": [],
                "policy_reason": None,
            }
        )
        return record_id

    def _append(self, record: dict[str, Any]) -> None:
        if self.signer is None:
            raise ValueError(
                "this ledger was opened read-only (no signer). An unsigned record "
                "would break the chain for every reader, so it is refused rather "
                "than written."
            )
        # Atomic read-seal-write. Sealing against a head read in a separate call
        # lets two concurrent writers chain onto the same predecessor and fork
        # the chain.
        sealed = self.store.append_chained(
            record, lambda r, head: seal(r, head, self.signer)
        )
        if self.on_record is not None:
            self.on_record(sealed)
        if self.on_append is not None:
            # The record is already durable by the time this runs, so a failing
            # sink cannot cost you the record. It is not swallowed either: a
            # silently dead anchor is worse than no anchor, because it looks
            # like protection right up until the day it is needed.
            self.on_append(make_anchor(self.store.count(), sealed["hash"]))

    # --------------------------------------------------------------- read side

    def records(self) -> list[dict[str, Any]]:
        return self.store.all()

    def for_loan(self, loan: str) -> list[dict[str, Any]]:
        return self.store.by_loan(loan)
