"""Custody -- a signed chain of evidence for AI decisions in mortgage lending.

Fannie Mae Lender Letter LL-2026-04 (issued 8 April 2026, effective 6 August
2026) requires seller/servicers using AI or ML in origination or servicing to
govern its use, extend no-less-protective governance to their vendors, and --
on Fannie Mae's request -- promptly disclose the types of AI/ML in use, the
purpose and manner of that use, and the safeguards implemented.

This package is one way to be able to answer that request with evidence rather
than assertion: a per-decision record, a deterministic gate that acts as a live
safeguard, and a hash chain the recipient can verify without access to your
systems.

The letter does not specify a record schema and does not require append-only or
signed logs; those are this library's design choices. `docs/ll-2026-04.md` marks
the boundary. Not legal advice, and not a statement of what Fannie Mae requires.
"""
from .chain import ChainError, verify_chain
from .examiner import export, packet
from .ledger import MANDATE_FIELDS, Decision, Ledger
from .store import Store
from .signing import ECDSA_P256, ED25519, KeyVaultSigner, LocalSigner, Signer
from .verify import PASS, REJECT, REVIEW, Verdict, gate

__all__ = [
    "Ledger", "Decision", "Store", "gate", "Verdict",
    "PASS", "REVIEW", "REJECT", "packet", "export",
    "verify_chain", "ChainError", "MANDATE_FIELDS",
    "Signer", "LocalSigner", "KeyVaultSigner", "ED25519", "ECDSA_P256",
]
__version__ = "0.3.0"
