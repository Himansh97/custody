"""Strip borrower PII before anything is persisted.

The audit record has to survive being handed to an examiner, an investor, a GSE
counterparty, and quite possibly opposing counsel. What it must contain is the
loan number — that is the required query key and the whole record is useless
without it. What it must not contain is the borrower.

Two mechanisms, because one is not enough:

* **Patterns** catch PII with a shape — SSN, phone, email, dates, account
  numbers. Reliable, and works on text nobody declared in advance.
* **Declared identifiers** catch PII with no shape. There is no regular
  expression for "is this a person's name", and pretending otherwise is how
  redaction quietly fails. The caller already knows the borrower's name and
  address, so it passes them in and they are scrubbed literally.

The order matters: the loan number is protected first, because a nine-digit loan
number and a nine-digit SSN are indistinguishable to a pattern.
"""
from __future__ import annotations

import re
from typing import Iterable

# Patterned PII, most specific first. Anything matched is replaced by its label
# rather than deleted, so a reader can see that something was removed and what
# kind of thing it was — a blank looks like missing data, which invites someone
# to go and "fix" it.
_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("[SSN]", re.compile(r"\b\d{3}-\d{2}-\d{4}\b")),
    ("[EMAIL]", re.compile(r"\b[\w.+-]+@[\w-]+\.[\w.]{2,}\b")),
    ("[PHONE]", re.compile(r"\b(?:\+1[\s.-]?)?\(?\d{3}\)?[\s.-]?\d{3}[\s.-]?\d{4}\b")),
    ("[DOB]", re.compile(r"\b(?:0?[1-9]|1[0-2])/(?:0?[1-9]|[12]\d|3[01])/(?:19|20)\d{2}\b")),
    ("[ACCOUNT]", re.compile(r"\b\d{9,}\b")),
)

_TOKEN = "\x00CUSTODY_LOAN\x00"


def redact(text: str, *, loan: str, identifiers: Iterable[str] = ()) -> str:
    """Return `text` with borrower PII removed and the loan number preserved.

    `identifiers` are literal strings the caller knows to be personal — borrower
    name, co-borrower, street address. Matching is case-insensitive and
    whole-word so redacting a borrower named "Rose" does not mutilate the word
    "gross" three lines down.
    """
    if not text:
        return text

    # Park the loan number somewhere no pattern can reach before running any of
    # them; [ACCOUNT] would otherwise swallow it and destroy the query key.
    out = text.replace(loan, _TOKEN) if loan else text

    for label, pattern in _PATTERNS:
        out = pattern.sub(label, out)

    for value in identifiers:
        value = (value or "").strip()
        if len(value) < 3:
            # Anything shorter is not identifying on its own and would carve up
            # ordinary words.
            continue
        out = re.sub(rf"\b{re.escape(value)}\b", "[BORROWER]", out, flags=re.IGNORECASE)

    return out.replace(_TOKEN, loan)


def redact_value(value, *, loan: str, identifiers: Iterable[str] = ()):
    """`redact` applied through nested structures, leaving non-text alone.

    Prompts are strings; outcomes are dicts of numbers and strings. Both end up
    in the record, so both go through here rather than only the obvious one.
    """
    if isinstance(value, str):
        return redact(value, loan=loan, identifiers=identifiers)
    if isinstance(value, dict):
        return {k: redact_value(v, loan=loan, identifiers=identifiers) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [redact_value(v, loan=loan, identifiers=identifiers) for v in value]
    return value
