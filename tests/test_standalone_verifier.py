"""The standalone verifier must work without the library it is checking.

verify_packet.py exists so an auditor does not have to trust Custody. That is
only true if it genuinely stands alone -- so this runs it as a subprocess, with
the package deliberately kept off the path, and against a packet it did not
help produce.
"""
from __future__ import annotations

import json
import pathlib
import subprocess
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from custody.examiner import packet  # noqa: E402
from custody.ledger import Ledger  # noqa: E402
from custody.signing import ECDSA_P256, ED25519, LocalSigner  # noqa: E402

VERIFIER = ROOT / "verify_packet.py"


def _packet(algorithm: str) -> dict:
    led = Ledger(policy="p", signer=LocalSigner(algorithm=algorithm))
    with led.decision(loan="1000254", principal="a@b.example", purpose="income") as d:
        out = d.call(model="m", prompt="p", sources=["Gross pay 4,206.00"],
                     response={"g": 4206.00})
        d.gate(out, citations={"g": "paystub"}, confidence=0.95)
        d.commit(outcome=out)
    led.human_review(loan="1000254", reviewer="s@b.example",
                     decision_id=led.records()[0]["record_id"], action="approved")
    return packet(led, "1000254")


def _run(data: dict) -> tuple[int, str]:
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as fh:
        json.dump(data, fh, default=str)
        path = fh.name
    # cwd is a temp dir and the package is not installed there, so the verifier
    # cannot accidentally import what it is meant to be independent of.
    result = subprocess.run(
        [sys.executable, str(VERIFIER), path],
        capture_output=True, text=True, cwd=tempfile.gettempdir(),
    )
    return result.returncode, result.stdout


def test_a_clean_packet_verifies_on_both_algorithms() -> None:
    for algorithm in (ED25519, ECDSA_P256):
        code, out = _run(_packet(algorithm))
        assert code == 0, out
        assert "hash chain verified" in out
        assert "signatures verified" in out
        assert algorithm in out


def test_an_edited_record_is_caught_and_located() -> None:
    data = _packet(ED25519)
    data["records"][0]["decision_outcome"] = {"g": 9999.00}
    code, out = _run(data)
    assert code == 1
    assert "BROKEN at record 0" in out


def test_a_deleted_record_is_caught() -> None:
    data = _packet(ED25519)
    del data["records"][0]
    code, out = _run(data)
    assert code == 1 and "BROKEN" in out


def test_a_forged_signature_is_caught() -> None:
    data = _packet(ED25519)
    data["records"][1]["signature"] = "00" * 64
    code, out = _run(data)
    assert code == 1
    assert "signature does not verify" in out


def test_it_never_claims_more_than_it_checked() -> None:
    """Without a public key it must say signatures went unchecked rather than
    printing a bare OK somebody could read as a full verification."""
    data = _packet(ED25519)
    data.pop("public_key")
    code, out = _run(data)
    assert code == 0
    assert "signatures NOT checked" in out
    assert "signatures verified" not in out


def test_it_states_what_it_cannot_prove() -> None:
    """A verifier that only ever says OK teaches people to over-read it."""
    _, out = _run(_packet(ED25519))
    assert "does not prove they are true" in out
    assert "never recorded" in out


def test_it_imports_nothing_from_custody() -> None:
    source = VERIFIER.read_text(encoding="utf-8")
    assert "import custody" not in source
    assert "from custody" not in source


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
