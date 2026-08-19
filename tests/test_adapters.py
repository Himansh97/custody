"""Adapter contract, and the two things that decide whether a record is worth anything.

No network. Both providers are driven against fakes shaped like the real SDK
responses, because what is being tested is what Custody does with an answer, not
whether someone else's API works.
"""
from __future__ import annotations

import pathlib
import sys
import types

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent / "src"))

from custody.adapters import (  # noqa: E402
    SCHEMA_INSTRUCTION,
    extract_json,
    label_documents,
    replay,
)

W2 = ("w2-2025", "Box 1 Wages, tips, other compensation 98,410.00")
PAYSTUB = ("paystub-07", "Gross pay 4,206.00")
DOCS = [W2, PAYSTUB]


# ------------------------------------------------------------------- parsing


def test_json_survives_the_prose_models_wrap_it_in() -> None:
    for wrapped in (
        '{"fields":{"a":1}}',
        'Here you go:\n{"fields":{"a":1}}\nHope that helps.',
        '```json\n{"fields":{"a":1}}\n```',
        '```\n{"fields":{"a":1}}\n```',
    ):
        assert extract_json(wrapped) == {"fields": {"a": 1}}, wrapped


def test_unparseable_output_returns_empty_rather_than_raising() -> None:
    """The caller is inside an open decision. A record saying the model returned
    nothing usable beats an exception that leaves no trace of the attempt."""
    for junk in ("I'm afraid I can't help with that", "", "{not json at all"):
        assert extract_json(junk) == {}


def test_documents_are_labelled_so_the_model_can_cite_them() -> None:
    labelled = label_documents(DOCS)
    assert "document id: w2-2025" in labelled
    assert "document id: paystub-07" in labelled
    assert "98,410.00" in labelled


def test_the_schema_forbids_computing_a_number_that_is_not_written_down() -> None:
    """The single most useful line in the prompt: a derived figure appears in no
    document, so it would be indistinguishable from an invented one."""
    assert "return null" in SCHEMA_INSTRUCTION
    assert "must appear in one of the supplied documents" in SCHEMA_INSTRUCTION
    assert "citation" in SCHEMA_INSTRUCTION


# --------------------------------------------------------------- the contract


def test_every_adapter_returns_the_same_four_things() -> None:
    fields, confidence, endpoint, citations = replay(
        {"wages": 98410.0}, 0.9, {"wages": "w2-2025"}
    )("Extract wages.", DOCS)
    assert fields == {"wages": 98410.0}
    assert confidence == 0.9
    assert isinstance(endpoint, str) and endpoint
    assert citations == {"wages": "w2-2025"}


# -------------------------------------------------------------- azure openai


def _fake_azure(model_version: str, content: str):
    """A stand-in shaped like the openai SDK's AzureOpenAI client."""
    captured = {}

    class Completions:
        def create(self, **kwargs):
            captured.update(kwargs)
            message = types.SimpleNamespace(content=content)
            return types.SimpleNamespace(
                choices=[types.SimpleNamespace(message=message)], model=model_version
            )

    client = types.SimpleNamespace(chat=types.SimpleNamespace(completions=Completions()))
    return client, captured


def _azure(monkey_client, **kwargs):
    """Build the adapter with the SDK constructor swapped out."""
    import custody.adapters as adapters

    fake_module = types.SimpleNamespace(AzureOpenAI=lambda **_: monkey_client)
    real_import = __builtins__["__import__"] if isinstance(__builtins__, dict) else __import__

    def fake_import(name, *args, **kw):
        if name == "openai":
            return fake_module
        return real_import(name, *args, **kw)

    import builtins
    builtins.__import__ = fake_import
    try:
        return adapters.azure_openai_extractor(
            endpoint="https://acme-uw.openai.azure.com/",
            api_key="k", use_managed_identity=False, **kwargs
        )
    finally:
        builtins.__import__ = real_import


def test_azure_records_the_model_version_not_the_deployment() -> None:
    """A deployment's model can be changed in the portal without touching a line
    of code, so `gpt-4o-prod` does not identify what made the decision. When an
    examiner asks eighteen months later, this is the difference between an
    answer and a shrug.
    """
    client, _ = _fake_azure(
        "gpt-4o-2024-11-20",
        '{"fields":{"wages":98410.0},"citations":{"wages":"w2-2025"},"confidence":0.94}',
    )
    extract = _azure(client, deployment="gpt-4o-prod")
    fields, confidence, endpoint, citations = extract("Extract wages.", DOCS)

    assert fields == {"wages": 98410.0}
    assert confidence == 0.94
    assert citations == {"wages": "w2-2025"}
    assert "gpt-4o-2024-11-20" in endpoint, endpoint
    assert "gpt-4o-prod" in endpoint, "the deployment is worth keeping alongside it"
    assert "acme-uw" in endpoint, "which Azure resource answered is part of the record"


def test_azure_routes_on_the_deployment_and_asks_for_json() -> None:
    client, captured = _fake_azure("gpt-4o-2024-11-20", '{"fields":{}}')
    _azure(client, deployment="gpt-4o-prod")("Extract wages.", DOCS)

    assert captured["model"] == "gpt-4o-prod", "Azure routes on the deployment name"
    assert captured["response_format"] == {"type": "json_object"}
    assert any("document id: w2-2025" in m["content"] for m in captured["messages"])


def test_azure_needs_an_endpoint() -> None:
    import custody.adapters as adapters
    try:
        adapters.azure_openai_extractor(deployment="d", endpoint="", api_key="k")
    except (ValueError, RuntimeError) as exc:
        assert "endpoint" in str(exc).lower() or "openai" in str(exc).lower()
    else:
        raise AssertionError("it built an adapter with nowhere to send the request")


if __name__ == "__main__":
    failures = 0
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            try:
                fn()
                print(f"PASS {name}")
            except AssertionError as exc:
                failures += 1
                print(f"FAIL {name}: {exc}")
    print(f"\n{failures} failure(s)")
    raise SystemExit(1 if failures else 0)
