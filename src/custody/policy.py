"""The layer above the gate: what the AI was allowed to attempt at all.

The gate in `verify.py` answers "is this output safe to use". This module
answers the earlier question -- "was this model allowed to be asked this, for
this purpose, by this system" -- and it is deliberately not code.

    if use_case == "income_calculation":
        allow()

is not a governance policy. It is a governance policy that only an engineer can
read, that changes without review, and that leaves nothing behind saying which
version was in force when a particular loan was decided. So a policy here is a
versioned JSON document, owned by whoever signs off on it, and the engine's only
job is to evaluate it and put its identity on every record it governs.

**JSON rather than YAML on purpose.** This package takes exactly one dependency
(see the note in `pyproject.toml`) because it sits in the call path of a
regulated workflow. `requires-python = ">=3.10"` rules out `tomllib` as well.
JSON is what is left, and a policy file is read far more often than it is
written.

**Unknown keys are an error, not a shrug.** A misspelled `confidence_flor` that
silently keeps the default floor is the worst possible failure for a control
document: compliance approved a number that never took effect, and nothing
anywhere says so. Loading is strict, and the error names the key.

A policy file:

    {
      "policy_id": "AI-INCOME-001",
      "version": "3.0",
      "owner": "compliance@lender.example",
      "last_reviewed": "2026-07-01",
      "use_cases": {
        "income_calculation": {
          "approved": true,
          "models": ["claude-sonnet-5", "gpt-4o-2024-11-20"],
          "confidence_floor": 0.85,
          "human_review": "on_review",
          "ai_can_decide": false,
          "prohibited_data": ["ssn", "bank_account_number"]
        }
      }
    }
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

from .redact import detector_for

# How a use case treats human involvement.
#   always     -- a person sees every output, whatever the gate said
#   on_review  -- a person sees it when the gate says review or reject (default)
#   never      -- the gate's verdict stands alone
HUMAN_ALWAYS, HUMAN_ON_REVIEW, HUMAN_NEVER = "always", "on_review", "never"
_HUMAN_REVIEW_VALUES = (HUMAN_ALWAYS, HUMAN_ON_REVIEW, HUMAN_NEVER)

_POLICY_KEYS = frozenset({
    "policy_id", "version", "owner", "last_reviewed", "review_interval_days",
    "use_cases",
})
_USE_CASE_KEYS = frozenset({
    "approved", "models", "confidence_floor", "human_review", "ai_can_decide",
    "allowed_data", "prohibited_data", "vocabulary", "note",
})

# LL-2026-04 requires an owner who reviews the policies at least annually. That
# is the interval unless a lender's own risk tolerance sets a shorter one.
DEFAULT_REVIEW_INTERVAL_DAYS = 365


class PolicyError(Exception):
    """The policy document is malformed. Raised at load time, never at call time."""


class PolicyDenied(Exception):
    """The policy did not permit this call.

    Raised by `Decision.call` rather than returned, so that a caller who ignores
    return values still cannot reach the model. The decision that raised it is
    recorded as a denial before the exception leaves the block.
    """

    def __init__(self, allowance: "Allowance"):
        self.allowance = allowance
        super().__init__(allowance.reason or "denied by policy")


@dataclass(frozen=True)
class Allowance:
    """What the policy permits for one purpose, and why not when it does not."""

    allowed: bool
    reason: str | None = None
    purpose: str | None = None
    policy_id: str | None = None
    policy_version: str | None = None
    confidence_floor: float = 0.80
    human_review: str = HUMAN_ON_REVIEW
    ai_can_decide: bool = True
    models: tuple[str, ...] = ()
    allowed_data: tuple[str, ...] = ()
    prohibited_data: tuple[str, ...] = ()
    vocabulary: Mapping[str, tuple[str, ...]] = field(default_factory=dict)

    def __bool__(self) -> bool:
        return self.allowed

    def as_record_fields(self) -> dict[str, Any]:
        """The part of an allowance that belongs in the ledger.

        Not the whole policy. A record should carry enough to say which rules
        were in force and what they concluded; reproducing the document on every
        row would bloat the ledger and still not be the authoritative copy.
        """
        return {
            "policy_id": self.policy_id,
            "policy_decision": "allow" if self.allowed else "deny",
            "policy_reason": self.reason,
        }


def _deny(reason: str, policy: "Policy | None" = None, purpose: str | None = None) -> Allowance:
    return Allowance(
        allowed=False,
        reason=reason,
        purpose=purpose,
        policy_id=policy.policy_id if policy else None,
        policy_version=policy.version if policy else None,
    )


@dataclass(frozen=True)
class UseCase:
    name: str
    approved: bool
    models: tuple[str, ...]
    confidence_floor: float
    human_review: str
    ai_can_decide: bool
    allowed_data: tuple[str, ...]
    prohibited_data: tuple[str, ...]
    vocabulary: Mapping[str, tuple[str, ...]]


class Policy:
    """A loaded, versioned policy document.

    Immutable once loaded. A policy that could be mutated at runtime would make
    `policy_version` on a record a claim rather than a fact.
    """

    def __init__(self, document: Mapping[str, Any], *, source: str | None = None):
        self.source = source
        doc = dict(document)

        unknown = set(doc) - _POLICY_KEYS
        if unknown:
            raise PolicyError(
                f"unknown key(s) in policy{self._where()}: {', '.join(sorted(unknown))}. "
                "Loading is strict because a misspelled control that silently keeps its "
                "default is indistinguishable from a control nobody wrote."
            )

        for required in ("policy_id", "version"):
            if not doc.get(required):
                raise PolicyError(f"policy{self._where()} has no {required}")

        self.policy_id = str(doc["policy_id"])
        self.version = str(doc["version"])
        self.owner = doc.get("owner")
        self.last_reviewed = self._parse_date(doc.get("last_reviewed"))
        self.review_interval_days = int(
            doc.get("review_interval_days") or DEFAULT_REVIEW_INTERVAL_DAYS
        )

        use_cases = doc.get("use_cases") or {}
        if not isinstance(use_cases, Mapping):
            raise PolicyError(f"use_cases{self._where()} must be an object")
        self.use_cases = {
            name: self._parse_use_case(name, body) for name, body in use_cases.items()
        }

    # ------------------------------------------------------------------ loading

    @classmethod
    def load(cls, path: str | Path) -> "Policy":
        path = Path(path)
        try:
            document = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            raise PolicyError(f"{path} is not valid JSON: {exc}") from None
        if not isinstance(document, Mapping):
            raise PolicyError(f"{path} does not contain a policy object")
        return cls(document, source=str(path))

    def _where(self) -> str:
        return f" ({self.source})" if getattr(self, "source", None) else ""

    @staticmethod
    def _parse_date(value: Any) -> date | None:
        if value in (None, ""):
            return None
        try:
            return date.fromisoformat(str(value)[:10])
        except ValueError:
            raise PolicyError(
                f"last_reviewed must be an ISO date (YYYY-MM-DD), got {value!r}"
            ) from None

    def _parse_use_case(self, name: str, body: Any) -> UseCase:
        if not isinstance(body, Mapping):
            raise PolicyError(f"use case {name!r} must be an object")

        unknown = set(body) - _USE_CASE_KEYS
        if unknown:
            raise PolicyError(
                f"unknown key(s) in use case {name!r}: {', '.join(sorted(unknown))}"
            )

        human_review = str(body.get("human_review", HUMAN_ON_REVIEW))
        if human_review not in _HUMAN_REVIEW_VALUES:
            raise PolicyError(
                f"use case {name!r} has human_review={human_review!r}; "
                f"expected one of {', '.join(_HUMAN_REVIEW_VALUES)}"
            )

        floor = body.get("confidence_floor", 0.80)
        try:
            floor = float(floor)
        except (TypeError, ValueError):
            raise PolicyError(
                f"use case {name!r} has a non-numeric confidence_floor: {floor!r}"
            ) from None
        if not 0.0 <= floor <= 1.0:
            raise PolicyError(
                f"use case {name!r} has confidence_floor {floor}, outside 0.0-1.0"
            )

        vocabulary = body.get("vocabulary") or {}
        if not isinstance(vocabulary, Mapping):
            raise PolicyError(f"use case {name!r}: vocabulary must be an object")

        return UseCase(
            name=name,
            approved=bool(body.get("approved", False)),
            models=tuple(body.get("models") or ()),
            confidence_floor=floor,
            human_review=human_review,
            ai_can_decide=bool(body.get("ai_can_decide", True)),
            allowed_data=tuple(body.get("allowed_data") or ()),
            prohibited_data=tuple(body.get("prohibited_data") or ()),
            vocabulary={k: tuple(v) for k, v in vocabulary.items()},
        )

    # --------------------------------------------------------------- evaluation

    @property
    def identifier(self) -> str:
        """What lands in `policy_version` on a record: id and version together.

        Either alone is ambiguous. `3.0` says nothing about which document, and
        `AI-INCOME-001` says nothing about which revision of it.
        """
        return f"{self.policy_id}@{self.version}"

    def for_purpose(self, purpose: str) -> Allowance:
        """Is this purpose an approved use of AI at all?

        An unlisted purpose is denied rather than defaulted. A policy that
        permits whatever nobody thought to write down is not a policy.
        """
        case = self.use_cases.get(purpose)
        if case is None:
            return _deny(
                f"{purpose!r} is not a use case in {self.identifier}; "
                "unlisted purposes are denied",
                self, purpose,
            )
        if not case.approved:
            return _deny(
                f"use case {purpose!r} is present in {self.identifier} but not approved",
                self, purpose,
            )
        return Allowance(
            allowed=True,
            purpose=purpose,
            policy_id=self.policy_id,
            policy_version=self.version,
            confidence_floor=case.confidence_floor,
            human_review=case.human_review,
            ai_can_decide=case.ai_can_decide,
            models=case.models,
            allowed_data=case.allowed_data,
            prohibited_data=case.prohibited_data,
            vocabulary=case.vocabulary,
        )

    def for_data(self, purpose: str, declared: Iterable[str],
                 texts: Sequence[str] = ()) -> Allowance:
        """Is this decision allowed to touch the data it is touching?

        Two mechanisms, because one is not enough, and the difference between
        them is the difference between a control and a promise.

        **Declared** classes are what the caller says this decision involves.
        "Income" has no shape; nothing can find it in a document, so the caller
        names it and the policy is checked against that. If a use case sets any
        data rule at all and the caller declares nothing, the call is refused
        rather than passed: a rule that quietly does not apply is exactly the
        control document making a statement that is not true.

        **Detected** classes are the ones with a shape -- an SSN, an account
        number, an email. Those are found in the documents themselves, so a
        prohibited class cannot be evaded by declaring the wrong thing.
        """
        allowance = self.for_purpose(purpose)
        if not allowance.allowed:
            return allowance

        case = self.use_cases[purpose]
        if not case.allowed_data and not case.prohibited_data:
            return allowance          # the policy sets no data rules

        declared = tuple(str(d).strip().lower() for d in declared if str(d).strip())
        if not declared:
            return _deny(
                f"use case {purpose!r} in {self.identifier} sets data rules, and this "
                "decision declared no data classes. Pass data=[...] naming what it "
                "touches -- an unchecked rule is worse than no rule.",
                self, purpose,
            )

        # Prohibited first. A class that is explicitly forbidden should be
        # reported as forbidden, not as "missing from the allowed list" -- the
        # second is true but tells the reader the wrong thing about their policy.
        prohibited = {p.lower() for p in case.prohibited_data}
        overlap = sorted(set(declared) & prohibited)
        if overlap:
            return _deny(
                f"data class(es) {', '.join(overlap)} are prohibited for {purpose!r} "
                f"in {self.identifier}",
                self, purpose,
            )

        if case.allowed_data:
            allowed = {a.lower() for a in case.allowed_data}
            outside = sorted(set(declared) - allowed)
            if outside:
                return _deny(
                    f"data class(es) {', '.join(outside)} are not in the allowed set for "
                    f"{purpose!r} in {self.identifier} ({', '.join(sorted(allowed))})",
                    self, purpose,
                )

        # The half a caller cannot get wrong by declaring the wrong thing.
        for name in sorted(prohibited):
            pattern = detector_for(name)
            if pattern is None:
                continue
            for text in texts:
                if text and pattern.search(text):
                    return _deny(
                        f"a value matching the prohibited class {name!r} appears in a "
                        f"document supplied to this decision, which {self.identifier} "
                        f"does not permit for {purpose!r}",
                        self, purpose,
                    )

        return allowance

    def for_model(self, purpose: str, model: str, endpoint: str | None = None) -> Allowance:
        """Is this model approved for this purpose?

        Checked against the model asked for *and* the version that answered, if
        an endpoint carries one. Azure routes on a deployment name and the model
        behind it can be repointed without a code change, so approving
        `gpt-4o-prod` approves whatever is behind it today. Approving
        `gpt-4o-2024-11-20` approves a model.
        """
        allowance = self.for_purpose(purpose)
        if not allowance.allowed:
            return allowance

        approved = set(allowance.models)
        if not approved:
            return _deny(
                f"use case {purpose!r} in {self.identifier} approves no models, "
                "so no model may be called for it",
                self, purpose,
            )

        candidates = {model} | set(resolved_versions(endpoint))
        if approved & candidates:
            return allowance

        seen = model if not endpoint else f"{model} (endpoint {endpoint})"
        return _deny(
            f"model {seen} is not approved for {purpose!r} in {self.identifier}; "
            f"approved: {', '.join(sorted(approved))}",
            self, purpose,
        )

    # ------------------------------------------------------------ annual review

    def review_due(self, as_of: date | None = None) -> date | None:
        """When this policy must next be reviewed, or None if it has never been."""
        if self.last_reviewed is None:
            return None
        from datetime import timedelta
        return self.last_reviewed + timedelta(days=self.review_interval_days)

    def review_status(self, as_of: date | None = None) -> dict[str, Any]:
        """Whether the annual review LL-2026-04 requires has actually happened.

        Custody cannot perform the review or name the owner for you. It can stop
        the omission from being invisible, which is the part that otherwise
        surfaces during an audit rather than before one.
        """
        as_of = as_of or datetime.now(timezone.utc).date()
        due = self.review_due()
        if due is None:
            return {
                "policy": self.identifier,
                "owner": self.owner,
                "reviewed": False,
                "overdue": True,
                "detail": "no last_reviewed date recorded",
            }
        overdue_days = (as_of - due).days
        return {
            "policy": self.identifier,
            "owner": self.owner,
            "reviewed": True,
            "last_reviewed": self.last_reviewed.isoformat(),
            "due": due.isoformat(),
            "overdue": overdue_days > 0,
            "overdue_days": max(overdue_days, 0),
            "detail": (
                f"review was due {due.isoformat()}, {overdue_days} days ago"
                if overdue_days > 0
                else f"next review due {due.isoformat()}"
            ),
        }


# A policy that loads, permits one obvious thing, and refuses one obvious thing.
# Shipped in the package rather than left in the repository, because the first
# question anyone has after `pip install` is what a policy looks like, and
# reverse-engineering the schema from error messages is not an onboarding path.
#
# The two placeholders the letter cares about -- an owner, and a review date --
# are filled with values that are plainly yours to replace rather than left null,
# so a first run is clean and the thing to change is obvious.
STARTER_POLICY: dict[str, Any] = {
    "policy_id": "AI-UW-001",
    "version": "0.1",
    "owner": "you@your-lender.example",
    "last_reviewed": "2026-09-01",
    "review_interval_days": 365,
    "use_cases": {
        "income_calculation": {
            "approved": True,
            "models": ["claude-sonnet-5"],
            "confidence_floor": 0.85,
            "human_review": "on_review",
            "ai_can_decide": True,
            "allowed_data": ["income", "employment", "paystub", "w2"],
            "prohibited_data": ["ssn", "bank_account_number"],
            "note": "Replace owner and last_reviewed before this governs anything real.",
        },
        "adverse_action_reasoning": {
            "approved": False,
            "models": [],
            "note": "Not approved for AI. Adverse action reasons carry ECOA exposure.",
        },
    },
}


def write_starter(path: str | Path, *, force: bool = False) -> Path:
    """Write a starter policy. Refuses to overwrite one that already exists.

    Overwriting a policy in place would destroy the approved version some
    records already cite, and those records would then name a document that no
    longer says what it said.
    """
    target = Path(path)
    if target.exists() and not force:
        raise PolicyError(
            f"{target} already exists. Overwriting a policy would orphan every "
            "record citing that version -- pass --force if you are certain."
        )
    target.write_text(json.dumps(STARTER_POLICY, indent=2) + "\n", encoding="utf-8")
    return target


def resolved_versions(endpoint: str | None) -> tuple[str, ...]:
    """Model identifiers carried by an endpoint string.

    Endpoints are colon-delimited and provider-shaped:

        anthropic:messages:claude-sonnet-5
        azure-openai:acme-uw:gpt-4o-prod:gpt-4o-2024-11-20

    Rather than parse per provider -- which would need updating every time one
    is added, and would fail closed on an adapter someone wrote themselves --
    every segment is offered as a candidate. A policy approves exact strings, so
    an extra candidate can only match something an approver actually wrote down.
    """
    if not endpoint:
        return ()
    return tuple(part for part in str(endpoint).split(":") if part)


def as_policy(value: Any) -> tuple["Policy | None", str]:
    """Accept a Policy, a path to one, or a bare version string.

    The bare string is the original interface and still works: it lands in
    `policy_version` and nothing evaluates it. Callers who want enforcement pass
    a Policy.
    """
    if value is None:
        raise PolicyError("a Ledger needs a policy")
    if isinstance(value, Policy):
        return value, value.identifier
    if isinstance(value, Path):
        policy = Policy.load(value)
        return policy, policy.identifier
    if isinstance(value, Mapping):
        policy = Policy(value)
        return policy, policy.identifier
    text = str(value)
    if text.endswith(".json"):
        policy = Policy.load(text)
        return policy, policy.identifier
    return None, text
