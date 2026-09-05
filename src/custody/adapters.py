"""Model adapters — the seam between Custody and whoever generates the output.

Custody does not call a model. It wraps a call somebody else makes, which is the
only design that works in a real lender: the AI is already there, chosen and
integrated, and a governance layer that demands you rewrite it will not be
adopted.

An adapter is a callable taking `(instruction, documents)` and returning
`(fields, confidence, endpoint, citations)`, where documents are `(id, text)`
pairs. That is the whole contract. Bring your own if these do not fit.

Both adapters here are real. Give them credentials and they make genuine API
calls. Both ask for a citation and a confidence per field, because the gate needs
those to do anything useful, and a model that will not say where a number came
from should not be putting numbers on loan files.
"""
from __future__ import annotations

import json
import os
import re
from typing import Any, Callable, Sequence

# Asking a model for its confidence is not asking it to be honest about itself —
# self-reported confidence is weakly calibrated at best. It is asking for a
# signal good enough to *route* on, and the gate treats a missing one as unsure
# rather than trusting a default.
SCHEMA_INSTRUCTION = """Return only JSON, no prose around it:

{"fields": {"<name>": <value>, ...},
 "citations": {"<name>": "<the id of the source document this came from>", ...},
 "confidence": <0.0 to 1.0>}

Every field must have a citation naming the document you took it from. Every
number you return must appear in one of the supplied documents; if the value you
want is not written down anywhere, return null for that field rather than
computing or estimating it."""

Adapter = Callable[[str, Sequence[tuple[str, str]]], tuple[dict, float | None, str, dict]]


def label_documents(documents: Sequence[tuple[str, str]]) -> str:
    """Label each document with its id so the model can cite it by name.

    An uncited field is indistinguishable from an invented one once the moment
    has passed, and after the fact is the only time anybody looks.
    """
    return "\n\n".join(f"--- document id: {doc_id} ---\n{text}" for doc_id, text in documents)


def extract_json(text: str) -> dict[str, Any]:
    """Models wrap JSON in prose and fences no matter what you ask.

    Returning the empty shape on a parse failure rather than raising is
    deliberate: the caller is inside an open decision, and a record saying the
    model returned something unparseable is worth more than an exception that
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


def _unpack(parsed: dict[str, Any]) -> tuple[dict, float | None, dict]:
    fields = {k: v for k, v in (parsed.get("fields") or {}).items() if v is not None}
    confidence = parsed.get("confidence")
    return (
        fields,
        float(confidence) if isinstance(confidence, (int, float)) else None,
        parsed.get("citations") or {},
    )


# ------------------------------------------------------------------ anthropic


def anthropic_extractor(
    *, model: str = "claude-sonnet-5", api_key: str | None = None, max_tokens: int = 2000
) -> Adapter:
    """Anthropic's API directly."""
    try:
        import anthropic
    except ImportError:  # pragma: no cover - depends on the install extra
        raise RuntimeError(
            "the anthropic package is not installed — pip install custody-ledger[anthropic]"
        ) from None

    client = anthropic.Anthropic(api_key=api_key or os.environ.get("ANTHROPIC_API_KEY"))

    def call(instruction: str, documents: Sequence[tuple[str, str]]):
        message = client.messages.create(
            model=model,
            max_tokens=max_tokens,
            messages=[{
                "role": "user",
                "content": f"{instruction}\n\n{label_documents(documents)}\n\n{SCHEMA_INSTRUCTION}",
            }],
        )
        text = "".join(
            block.text for block in message.content if getattr(block, "type", "") == "text"
        )
        fields, confidence, citations = _unpack(extract_json(text))
        # `message.model` is the version that actually answered, which is not
        # always the alias that was asked for.
        return fields, confidence, f"anthropic:messages:{message.model}", citations

    return call


# --------------------------------------------------------------- azure openai


def azure_openai_extractor(
    *,
    deployment: str,
    endpoint: str | None = None,
    api_version: str = "2024-10-21",
    api_key: str | None = None,
    use_managed_identity: bool | None = None,
    max_tokens: int = 2000,
) -> Adapter:
    """Azure OpenAI, which is what a regulated lender is actually running.

    Two things here matter more than they look.

    **Managed identity is the default when no key is supplied.** A stored API key
    is a long-lived credential in a system whose job is being trustworthy, and
    the Information Security Supplement has opinions about those. With a
    user-assigned identity there is no key to leak, rotate, or find in a config
    file in three years.

    **The deployment name is not the model.** Azure gives you a deployment, and
    the model version behind it can be changed — by an auto-update policy or by
    somebody in the portal — without a single line of your code changing. A
    record saying `gpt-4o-prod` therefore does not identify what made the
    decision. The response carries the real version, so that is what gets
    recorded, with the deployment kept alongside it. When an examiner asks which
    model produced a figure eighteen months ago, this is the difference between
    an answer and a shrug.
    """
    try:
        from openai import AzureOpenAI
    except ImportError:  # pragma: no cover - depends on the install extra
        raise RuntimeError(
            "the openai package is not installed — pip install custody-ledger[azure-openai]"
        ) from None

    endpoint = endpoint or os.environ.get("AZURE_OPENAI_ENDPOINT")
    if not endpoint:
        raise ValueError("azure_openai_extractor needs endpoint= or AZURE_OPENAI_ENDPOINT")

    api_key = api_key or os.environ.get("AZURE_OPENAI_API_KEY")
    if use_managed_identity is None:
        use_managed_identity = not api_key

    if use_managed_identity:
        try:
            from azure.identity import DefaultAzureCredential, get_bearer_token_provider
        except ImportError:  # pragma: no cover
            raise RuntimeError(
                "managed identity needs azure-identity — pip install custody-ledger[azure]"
            ) from None
        client = AzureOpenAI(
            azure_endpoint=endpoint,
            api_version=api_version,
            azure_ad_token_provider=get_bearer_token_provider(
                DefaultAzureCredential(), "https://cognitiveservices.azure.com/.default"
            ),
        )
    else:
        client = AzureOpenAI(
            azure_endpoint=endpoint, api_version=api_version, api_key=api_key
        )

    # The resource name identifies which Azure OpenAI instance answered, which
    # is part of "the manner of use" a lender has to be able to disclose.
    resource = re.sub(r"^https?://", "", endpoint).split(".")[0]

    def call(instruction: str, documents: Sequence[tuple[str, str]]):
        completion = client.chat.completions.create(
            model=deployment,                       # Azure routes on the deployment
            max_tokens=max_tokens,
            response_format={"type": "json_object"},
            messages=[
                {"role": "system", "content": SCHEMA_INSTRUCTION},
                {"role": "user",
                 "content": f"{instruction}\n\n{label_documents(documents)}"},
            ],
        )
        text = completion.choices[0].message.content or ""
        fields, confidence, citations = _unpack(extract_json(text))
        # completion.model is the deployed version, e.g. gpt-4o-2024-11-20.
        version = getattr(completion, "model", None) or deployment
        return (
            fields,
            confidence,
            f"azure-openai:{resource}:{deployment}:{version}",
            citations,
        )

    return call


# ---------------------------------------------------------------------- fixed


def replay(fields: dict, confidence: float | None = None,
           citations: dict | None = None, model: str | None = None) -> Adapter:
    """A fixed response, for tests and for demos that must be reproducible.

    The gate neither knows nor cares where an output came from, so a replayed
    response exercises exactly the same path as a live one. That is what lets the
    shipped demo ledger be byte-for-byte reproducible by anyone who clones the
    repo.

    The endpoint names the model whose output is being replayed, not the word
    `fixture`. Both halves matter: a policy approves models, so a replay that
    identified no model could never satisfy one -- and a record that hid the
    replay would claim a call that did not happen. `replay:claude-sonnet-5` says
    both things at once.
    """
    endpoint = f"replay:{model}" if model else "replay:fixture"

    def call(instruction: str, documents: Sequence[tuple[str, str]]):
        return dict(fields), confidence, endpoint, dict(citations or {})
    return call
