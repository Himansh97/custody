"""Model adapters — the seam between Custody and whoever generates the output.

Custody does not call a model. It wraps a call somebody else makes, which is the
only design that works in a real lender: the AI is already there, chosen and
integrated, and a governance layer that demands you rewrite it will not be
adopted.

An adapter is a callable that returns `(output_dict, confidence, endpoint)`.
That is the whole contract. Bring your own if these do not fit.

The Anthropic adapter here is real — give it a key and it makes a genuine API
call. It asks for structured output with a citation and a confidence per field,
because the gate needs those to do anything useful, and a model that will not
say where a number came from should not be extracting numbers onto loan files.
"""
from __future__ import annotations

import json
import os
import re
from typing import Any, Callable, Sequence

# Asking for a confidence is not asking the model to be honest about itself —
# self-reported confidence is weakly calibrated at best. It is asking for a
# signal that is *better than nothing* for routing, and the gate treats a
# missing one as "unsure" rather than trusting a default.
_SCHEMA_INSTRUCTION = """Return only JSON, no prose around it:

{"fields": {"<name>": <value>, ...},
 "citations": {"<name>": "<the id of the source document this came from>", ...},
 "confidence": <0.0 to 1.0>}

Every field must have a citation naming the document you took it from. Every
number you return must appear in one of the supplied documents; if the value you
want is not written down anywhere, return null for that field rather than
computing or estimating it."""


def _extract_json(text: str) -> dict[str, Any]:
    """Models wrap JSON in prose and fences no matter what you ask.

    Returning the empty shape on a parse failure rather than raising is
    deliberate: the caller is inside an open decision, and a record saying "the
    model returned something unparseable" is worth more than an exception that
    leaves no trace of the attempt.
    """
    fenced = re.search(r"```(?:json)?\s*(.+?)```", text, re.S)
    body = fenced.group(1) if fenced else text
    start, end = body.find("{"), body.rfind("}")
    if start == -1 or end == -1:
        return {}
    try:
        return json.loads(body[start:end + 1])
    except json.JSONDecodeError:
        return {}


def anthropic_extractor(
    *,
    model: str = "claude-sonnet-5",
    api_key: str | None = None,
    max_tokens: int = 2000,
) -> Callable[[str, Sequence[tuple[str, str]]], tuple[dict, float | None, str, dict]]:
    """Build a real Anthropic-backed extractor.

    Returns a callable taking (instruction, documents) where documents are
    `(document_id, text)` pairs, and giving back
    `(fields, confidence, endpoint, citations)`.

    Documents are labelled with their ids in the prompt so the model can cite
    them by name — an uncited field is indistinguishable from an invented one
    once the moment has passed, and after the fact is the only time anyone looks.
    """
    try:
        import anthropic
    except ImportError:  # pragma: no cover - depends on the install extra
        raise RuntimeError(
            "the anthropic package is not installed — `pip install custody-ledger[anthropic]`"
        ) from None

    client = anthropic.Anthropic(api_key=api_key or os.environ.get("ANTHROPIC_API_KEY"))

    def call(instruction: str, documents: Sequence[tuple[str, str]]):
        bundle = "\n\n".join(
            f"--- document id: {doc_id} ---\n{text}" for doc_id, text in documents
        )
        message = client.messages.create(
            model=model,
            max_tokens=max_tokens,
            messages=[{
                "role": "user",
                "content": f"{instruction}\n\n{bundle}\n\n{_SCHEMA_INSTRUCTION}",
            }],
        )
        text = "".join(
            block.text for block in message.content if getattr(block, "type", "") == "text"
        )
        parsed = _extract_json(text)
        fields = {k: v for k, v in (parsed.get("fields") or {}).items() if v is not None}
        confidence = parsed.get("confidence")
        return (
            fields,
            float(confidence) if isinstance(confidence, (int, float)) else None,
            f"anthropic:messages:{model}",
            parsed.get("citations") or {},
        )

    return call


def replay(fields: dict, confidence: float | None = None, citations: dict | None = None):
    """A fixed response, for tests and for demos that must be reproducible.

    The gate neither knows nor cares where an output came from, so a replayed
    response exercises exactly the same path as a live one. That is what lets
    the shipped demo ledger be byte-for-byte reproducible by anyone who clones
    the repo.
    """
    def call(instruction: str, documents: Sequence[tuple[str, str]]):
        return dict(fields), confidence, "replay:fixture", dict(citations or {})
    return call
