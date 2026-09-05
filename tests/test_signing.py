"""Signing must be pluggable, and the algorithm must not be forgeable.

Azure Key Vault supports EC and RSA and no EdDSA at all; AWS KMS is the same.
So a hardcoded Ed25519 signature is not merely awkward for a regulated
deployment, it makes one impossible -- the key can never leave a file. That is
why the algorithm is a parameter, and why it is written inside the hashed body
rather than beside it.
"""
from __future__ import annotations

import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent / "src"))

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402

from custody.chain import GENESIS, ChainError, compute_hash, seal, verify_chain  # noqa: E402
from custody.ledger import Ledger  # noqa: E402
from custody.signing import (  # noqa: E402
    ECDSA_P256,
    ED25519,
    LocalSigner,
    load_public_key,
    verify_signature,
)

PAYSTUB = "Gross pay 4,206.00"


def _ledger(signer) -> Ledger:
    led = Ledger(policy="p", signer=signer)
    with led.decision(loan="1", principal="a@b.example", purpose="income") as d:
        out = d.call(model="m", prompt="p", sources=[PAYSTUB], response={"g": 4206.00})
        d.gate(out, citations={"g": "paystub"}, confidence=0.95)
        d.commit(outcome=out)
    return led


def test_both_algorithms_produce_verifying_chains() -> None:
    for algorithm in (ED25519, ECDSA_P256):
        led = _ledger(LocalSigner(algorithm=algorithm))
        verify_chain(led.records(), led.public_key)
        assert led.records()[0]["sig_alg"] == algorithm


def test_the_algorithm_is_recorded_on_every_record() -> None:
    """A ledger that cannot say how it was signed is not self-describing, and
    whoever verifies it should not have to be told out of band."""
    led = _ledger(LocalSigner(algorithm=ECDSA_P256))
    assert all(r["sig_alg"] == ECDSA_P256 for r in led.records())


def test_the_algorithm_claim_cannot_be_downgraded_silently() -> None:
    """sig_alg lives in the hashed body. Rewriting it to claim a record was
    signed with something else breaks the chain before any signature is checked
    -- which is the point of putting it there rather than alongside."""
    led = _ledger(LocalSigner(algorithm=ECDSA_P256))
    records = led.records()
    records[0]["sig_alg"] = ED25519
    try:
        verify_chain(records, led.public_key)
    except ChainError as exc:
        assert exc.index == 0
        assert "hash" in exc.reason
    else:
        raise AssertionError("an algorithm downgrade went unnoticed")


def test_a_signature_from_the_wrong_key_is_rejected_on_both_algorithms() -> None:
    for algorithm in (ED25519, ECDSA_P256):
        led = _ledger(LocalSigner(algorithm=algorithm))
        stranger = load_public_key(
            LocalSigner(algorithm=algorithm).public_key_bytes(), algorithm
        )
        try:
            verify_chain(led.records(), stranger)
        except ChainError as exc:
            assert algorithm in exc.reason, exc.reason
        else:
            raise AssertionError(f"a foreign {algorithm} key verified")


def test_p256_signatures_are_the_64_byte_form_a_vault_returns() -> None:
    """Key Vault hands back raw r||s, not DER. Storing one form everywhere means
    a locally-signed packet and a vault-signed packet are byte-compatible and a
    verifier never has to know which produced it."""
    signer = LocalSigner(algorithm=ECDSA_P256)
    digest = bytes.fromhex(compute_hash({"a": 1}, GENESIS))
    signature = signer.sign(digest)
    assert len(signature) == 64, f"expected raw r||s, got {len(signature)} bytes"
    assert verify_signature(
        load_public_key(signer.public_key_bytes(), ECDSA_P256),
        signature, digest, ECDSA_P256,
    )


def test_a_raw_private_key_still_works() -> None:
    """Callers written before signers existed must keep working."""
    key = Ed25519PrivateKey.generate()
    led = Ledger(policy="p", signing_key=key)
    with led.decision(loan="1", principal="a@b.example", purpose="x") as d:
        out = d.call(model="m", prompt="p", sources=[PAYSTUB], response={"g": 4206.00})
        d.gate(out, citations={"g": "paystub"}, confidence=0.95)
        d.commit(outcome=out)
    verify_chain(led.records(), led.public_key)
    assert led.algorithm == ED25519


def test_a_ledger_without_a_key_cannot_write() -> None:
    """A keyless ledger opens for reading and refuses to append.

    Signing every run with an invented key would tie the signature to nothing,
    and writing an unsigned record would break the chain for every reader. But
    *reading* needs no signing key at all -- demanding one would mean whoever
    compiles evidence for an examiner must also be able to write records, which
    is the separation of duties this library argues for everywhere else.
    """
    ledger = Ledger(policy="p")
    assert ledger.read_only
    assert ledger.records() == []

    try:
        with ledger.decision(loan="1", principal="j@l", purpose="x") as d:
            d.call(model="m", prompt="p", response={})
    except ValueError as exc:
        assert "read-only" in str(exc)
    else:
        raise AssertionError("a keyless ledger wrote a record")


def test_a_read_only_ledger_checks_signatures_when_given_a_public_key() -> None:
    """Chain continuity needs no key; signatures need the public one, not the private."""
    signer = LocalSigner(algorithm=ED25519)
    written = Ledger(policy="p", signer=signer)
    with written.decision(loan="1", principal="j@l", purpose="x") as d:
        out = d.call(model="m", prompt="p", sources=["gross 4,206.00"],
                     response={"gross": 4206.00})
        d.gate(out, citations={"gross": "paystub"}, confidence=0.99)
        d.commit(outcome=out)

    reader = Ledger(policy="p", store=written.store)
    assert reader.public_key is None, "a reader invented a key it was not given"
    verify_chain(reader.records(), reader.public_key)          # continuity only

    reader.with_public_key(signer.public_key_bytes().hex())
    assert reader.public_key is not None
    verify_chain(reader.records(), reader.public_key)          # and signatures
    assert reader.algorithm == ED25519


def test_keys_round_trip_through_hex_on_both_algorithms() -> None:
    for algorithm in (ED25519, ECDSA_P256):
        signer = LocalSigner(algorithm=algorithm)
        restored = LocalSigner.from_hex(signer.private_hex(), algorithm)
        assert restored.public_key_bytes() == signer.public_key_bytes()

        digest = bytes.fromhex(compute_hash({"x": 2}, GENESIS))
        assert verify_signature(
            load_public_key(signer.public_key_bytes(), algorithm),
            restored.sign(digest), digest, algorithm,
        )


def test_seal_still_accepts_a_bare_key() -> None:
    sealed = seal({"record_id": "r"}, GENESIS, Ed25519PrivateKey.generate())
    assert sealed["sig_alg"] == ED25519


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
