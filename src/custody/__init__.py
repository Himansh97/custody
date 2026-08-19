"""Custody — a signed chain of evidence for AI decisions in mortgage lending.

Built against the requirements of Fannie Mae Lender Letter LL-2026-04 (issued
8 April 2026, effective 8 August 2026), which requires seller/servicers using
AI or ML in origination, underwriting, servicing or QC to keep a per-decision
audit record — principal, model, endpoint, redacted prompt, response treatment,
policy version, decision outcome and timestamp — in append-only, signed form,
queryable by loan, date, model and principal.

This package produces that record. It is not legal advice and does not certify
compliance; `docs/ll-2026-04.md` maps each requirement to where it is satisfied
so a reader can judge for themselves.
"""
from .chain import ChainError, verify_chain
from .examiner import export, packet
from .ledger import MANDATE_FIELDS, Decision, Ledger
from .store import Store
from .verify import PASS, REJECT, REVIEW, Verdict, gate

__all__ = [
    "Ledger", "Decision", "Store", "gate", "Verdict",
    "PASS", "REVIEW", "REJECT", "packet", "export",
    "verify_chain", "ChainError", "MANDATE_FIELDS",
]
__version__ = "0.1.0"
