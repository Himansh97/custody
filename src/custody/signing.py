"""Where the signing key lives, and what it signs with.

Two problems, one interface.

**The key should not be a file.** A regulated lender keeps signing material in a
KMS or HSM and never lets the private bytes exist in an application process.
`LocalSigner` is honest about being a development convenience; `KeyVaultSigner`
sends a digest to Azure and gets a signature back, and the private key never
leaves the vault.

**Ed25519 cannot go in a KMS.** Azure Key Vault supports EC (P-256/384/521,
secp256k1) and RSA, and nothing else. AWS KMS is the same story. So a hardcoded
Ed25519 signature is not merely inconvenient for a real deployment, it is
impossible — the algorithm has to be pluggable.

Which makes the algorithm a security-relevant field. It is written into the
record *body*, so it is covered by the hash: an attacker cannot claim a record
was signed with something weaker than it was, because changing the claim breaks
the chain before anyone checks a signature.
"""
from __future__ import annotations

from typing import Protocol

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, utils

ED25519 = "ed25519"
ECDSA_P256 = "ecdsa-p256-sha256"

SUPPORTED = (ED25519, ECDSA_P256)


class Signer(Protocol):
    """Sign a 32-byte digest. That is the whole contract.

    Deliberately digest-in, signature-out rather than message-in: a KMS signs
    digests, and pretending otherwise would mean shipping record bodies to a
    vault over the network for no reason.
    """

    algorithm: str

    def sign(self, digest: bytes) -> bytes: ...

    def public_key_bytes(self) -> bytes: ...


# --------------------------------------------------------------------- local


class LocalSigner:
    """A key held in this process. Fine for development, tests and the demo.

    Says so in its own name, because the failure mode this guards against is
    somebody reaching production with a private key in a file and no one having
    noticed which signer they were using.
    """

    def __init__(self, key=None, algorithm: str = ED25519):
        if algorithm not in SUPPORTED:
            raise ValueError(f"unsupported algorithm {algorithm!r}; use one of {SUPPORTED}")
        self.algorithm = algorithm
        if key is not None:
            self._key = key
        elif algorithm == ED25519:
            self._key = ed25519.Ed25519PrivateKey.generate()
        else:
            self._key = ec.generate_private_key(ec.SECP256R1())

    @classmethod
    def from_hex(cls, material: str, algorithm: str = ED25519) -> "LocalSigner":
        raw = bytes.fromhex(material.strip())
        if algorithm == ED25519:
            return cls(ed25519.Ed25519PrivateKey.from_private_bytes(raw), ED25519)
        return cls(
            ec.derive_private_key(int.from_bytes(raw, "big"), ec.SECP256R1()), ECDSA_P256
        )

    def private_hex(self) -> str:
        if self.algorithm == ED25519:
            return self._key.private_bytes_raw().hex()
        return self._key.private_numbers().private_value.to_bytes(32, "big").hex()

    def sign(self, digest: bytes) -> bytes:
        if self.algorithm == ED25519:
            return self._key.sign(digest)
        # Prehashed: the digest is already SHA-256 of the thing being signed, and
        # re-hashing it would make the signature unverifiable by anyone
        # following the documented scheme.
        der = self._key.sign(digest, ec.ECDSA(utils.Prehashed(hashes.SHA256())))
        return _der_to_raw(der)

    def public_key_bytes(self) -> bytes:
        return public_bytes(self._key.public_key())


# ----------------------------------------------------------------- key vault


class KeyVaultSigner:
    """Signing delegated to Azure Key Vault. The private key never leaves it.

    This is the answer to the first question a lender's security review asks.
    Nothing here can produce the private material even if the process is
    compromised — the most an attacker gets is the ability to sign while they
    hold the credential, which is auditable in the vault's own logs.

    Key Vault supports no EdDSA, so this is ECDSA over P-256 (`ES256`).
    """

    algorithm = ECDSA_P256

    def __init__(self, vault_url: str, key_name: str, credential=None, version: str | None = None):
        try:
            from azure.identity import DefaultAzureCredential
            from azure.keyvault.keys import KeyClient
            from azure.keyvault.keys.crypto import CryptographyClient
        except ImportError:  # pragma: no cover - depends on the install extra
            raise RuntimeError(
                "Azure signing needs the azure extra: "
                'pip install "custody-ledger[azure] @ git+https://github.com/Himansh97/custody"'
            ) from None

        credential = credential or DefaultAzureCredential()
        key = KeyClient(vault_url=vault_url, credential=credential).get_key(key_name, version)
        if key.key_type not in ("EC", "EC-HSM") or key.key.crv != "P-256":
            raise ValueError(
                f"key {key_name!r} is {key.key_type}/{getattr(key.key, 'crv', '?')}; "
                "Custody signs with ECDSA P-256 (ES256). Create the key with "
                "`az keyvault key create --kty EC --curve P-256`."
            )
        self._crypto = CryptographyClient(key, credential=credential)
        self._public = (
            b"\x04" + key.key.x.rjust(32, b"\x00") + key.key.y.rjust(32, b"\x00")
        )

    def sign(self, digest: bytes) -> bytes:
        from azure.keyvault.keys.crypto import SignatureAlgorithm

        # Key Vault returns r||s already, which is the form this module stores.
        return self._crypto.sign(SignatureAlgorithm.es256, digest).signature

    def public_key_bytes(self) -> bytes:
        return self._public


# ------------------------------------------------------------- verification


def public_bytes(public_key) -> bytes:
    """Serialise a public key to the compact form stored in a packet."""
    if isinstance(public_key, ed25519.Ed25519PublicKey):
        return public_key.public_bytes_raw()
    numbers = public_key.public_numbers()
    return b"\x04" + numbers.x.to_bytes(32, "big") + numbers.y.to_bytes(32, "big")


def load_public_key(material: bytes | str, algorithm: str):
    raw = bytes.fromhex(material) if isinstance(material, str) else material
    if algorithm == ED25519:
        return ed25519.Ed25519PublicKey.from_public_bytes(raw)
    if algorithm == ECDSA_P256:
        return ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), raw)
    raise ValueError(f"unsupported algorithm {algorithm!r}")


def verify_signature(public_key, signature: bytes, digest: bytes, algorithm: str) -> bool:
    """True if `signature` is `public_key`'s signature over `digest`."""
    try:
        if algorithm == ED25519:
            public_key.verify(signature, digest)
        elif algorithm == ECDSA_P256:
            public_key.verify(
                _raw_to_der(signature), digest, ec.ECDSA(utils.Prehashed(hashes.SHA256()))
            )
        else:
            return False
    except (InvalidSignature, ValueError):
        return False
    return True


def _der_to_raw(der: bytes) -> bytes:
    """DER-encoded ECDSA signature to the fixed 64-byte r||s Key Vault uses.

    Storing one form everywhere means a packet signed locally and a packet
    signed by a vault are byte-compatible, and a verifier does not need to know
    which produced it.
    """
    r, s = utils.decode_dss_signature(der)
    return r.to_bytes(32, "big") + s.to_bytes(32, "big")


def _raw_to_der(raw: bytes) -> bytes:
    if len(raw) != 64:
        raise ValueError(f"expected a 64-byte r||s signature, got {len(raw)}")
    return utils.encode_dss_signature(
        int.from_bytes(raw[:32], "big"), int.from_bytes(raw[32:], "big")
    )
