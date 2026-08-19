"""The gate: deterministic checks that decide what happens to a model's output.

LL-2026-04 requires a `response_treatment` on every record — what was actually
done with what the model returned. That field is only worth anything if
something real produced it, which is what this module is.

Two rules govern the design.

**No model judges another model.** Every check here is deterministic and
reproducible: given the same output and the same sources, it returns the same
verdict forever. An examiner can re-run it. A second model scoring the first
one is not evidence, it is a second thing to audit.

**Three outcomes, not two.** `pass` and `reject` are easy; `review` is the one
that matters. The mandate expects human-in-the-loop below confidence
thresholds, and a system with only pass/fail either auto-commits things it
should not or blocks things a person would have waved through in seconds.

The figure check is the one that has already earned its place in production. In
CareerOS the model wrote a "35%" that appeared in no source document, and the
figure check discarded the whole generation before it reached a stranger. Same
failure mode here, considerably more expensive: a fabricated income figure that
reaches the LOS is a defect on a loan file.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Iterable, Sequence

PASS, REVIEW, REJECT = "pass", "review", "reject"

# Ordered worst-first so a verdict is the max of its findings.
_RANK = {PASS: 0, REVIEW: 1, REJECT: 2}

# A number as it appears in a document: 8,412.00 / $1,250 / 6.875% / 30
_NUMBER = re.compile(r"\d[\d,]*(?:\.\d+)?")

# Figures that carry no factual weight on their own. Small integers appear in
# every document as counts, page numbers and list indices; treating them as
# claims makes the check cry wolf until somebody switches it off. The threshold
# is deliberate: a fabricated dollar amount or rate is always larger.
_TRIVIAL = frozenset({"0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "10", "12"})


@dataclass(frozen=True)
class Finding:
    check: str
    treatment: str
    detail: str


@dataclass
class Verdict:
    """What the gate decided, and why.

    `findings` is the reason and goes into the record. A verdict with no
    explanation is a black box, which is the exact thing the mandate exists to
    prohibit.
    """

    treatment: str = PASS
    findings: list[Finding] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return self.treatment == PASS

    @property
    def needs_human(self) -> bool:
        return self.treatment in (REVIEW, REJECT)

    def add(self, finding: Finding) -> None:
        self.findings.append(finding)
        if _RANK[finding.treatment] > _RANK[self.treatment]:
            self.treatment = finding.treatment

    def as_dict(self) -> dict[str, Any]:
        return {
            "treatment": self.treatment,
            "findings": [
                {"check": f.check, "treatment": f.treatment, "detail": f.detail}
                for f in self.findings
            ],
        }


def _figures(text: str) -> set[str]:
    """Numeric tokens, normalised so 8,412.00 and 8412 are the same figure.

    Without normalisation the check fails on formatting rather than on truth —
    the model writes `8412.0`, the paystub says `8,412.00`, and a correct
    extraction gets rejected. Trailing zeros go too, for the same reason.
    """
    out: set[str] = set()
    for raw in _NUMBER.findall(text or ""):
        plain = raw.replace(",", "")
        if "." in plain:
            plain = plain.rstrip("0").rstrip(".")
        if plain and plain not in _TRIVIAL:
            out.add(plain)
    return out


def check_figures(output: dict[str, Any], sources: Sequence[str]) -> list[Finding]:
    """Every figure the model asserts must appear in a document it was given."""
    supported: set[str] = set()
    for src in sources:
        supported |= _figures(src)

    claimed = _figures(" ".join(str(v) for v in _leaf_values(output)))
    return [
        Finding(
            "figure_binding",
            REJECT,
            f"{fig!r} appears in no source document supplied to the model",
        )
        for fig in sorted(claimed - supported)
    ]


def check_grounding(output: dict[str, Any], citations: dict[str, Any] | None) -> list[Finding]:
    """Every extracted field must say which document it came from.

    An uncited field is indistinguishable from an invented one after the fact,
    and "after the fact" is the only time anybody looks.
    """
    citations = citations or {}
    return [
        Finding("field_grounding", REJECT, f"field {name!r} cites no source document")
        for name in sorted(output)
        if not citations.get(name)
    ]


def check_vocabulary(
    output: dict[str, Any], allowed: dict[str, Iterable[str]] | None
) -> list[Finding]:
    """Classification outputs must land inside a closed set.

    Free-text where an enum was expected is how a downstream system silently
    receives a status it has no branch for.
    """
    findings: list[Finding] = []
    for name, choices in (allowed or {}).items():
        if name not in output:
            continue
        value, options = output[name], set(choices)
        if value not in options:
            findings.append(
                Finding(
                    "closed_vocabulary",
                    REJECT,
                    f"field {name!r} returned {value!r}, which is outside its allowed set "
                    f"({', '.join(sorted(options))})",
                )
            )
    return findings


def check_confidence(confidence: float | None, floor: float) -> list[Finding]:
    """Below the floor, a person decides. Never a rejection — low confidence is
    not evidence of being wrong, only of not being sure."""
    if confidence is None:
        return [Finding("confidence_floor", REVIEW, "the model reported no confidence")]
    if confidence < floor:
        return [
            Finding(
                "confidence_floor",
                REVIEW,
                f"confidence {confidence:.2f} is below the {floor:.2f} floor for this policy",
            )
        ]
    return []


def _leaf_values(value: Any) -> list[Any]:
    if isinstance(value, dict):
        return [leaf for v in value.values() for leaf in _leaf_values(v)]
    if isinstance(value, (list, tuple)):
        return [leaf for v in value for leaf in _leaf_values(v)]
    return [value]


def gate(
    output: dict[str, Any],
    *,
    sources: Sequence[str] = (),
    citations: dict[str, Any] | None = None,
    allowed: dict[str, Iterable[str]] | None = None,
    confidence: float | None = None,
    confidence_floor: float = 0.80,
) -> Verdict:
    """Run every check. The verdict is the most severe finding."""
    verdict = Verdict()
    for finding in (
        check_figures(output, sources)
        + check_grounding(output, citations)
        + check_vocabulary(output, allowed)
        + check_confidence(confidence, confidence_floor)
    ):
        verdict.add(finding)
    return verdict
