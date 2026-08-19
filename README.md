# Custody

**A signed chain of evidence for AI decisions in mortgage lending.**

Fannie Mae Lender Letter [LL-2026-04](https://singlefamily.fanniemae.com/news-events/lender-letter-ll-2026-04-governance-framework-use-artificial-intelligence-and-machine-learning)
took effect on 6 August 2026. Seller/servicers using AI or ML in origination or
servicing must have policies governing its development, use and maintenance,
must extend governance no less protective to their vendors, and **on Fannie
Mae's request must promptly disclose the types of AI/ML in use, the purpose and
manner of that use, and the safeguards implemented to mitigate the risks.**

There are two ways to answer that request. One is a document describing what you
intend to happen. The other is a record of what did happen, decision by decision,
that the person asking can verify without taking your word for it.

Custody produces the second.

**It is worth being precise, because vendor summaries of this letter are not.**
LL-2026-04 does not specify a record schema, does not name any fields, and does
not require append-only or signed logs. The design below is one implementation of
the letter's disclosure and safeguard obligations — a defensible one, and the one
this library takes. It is not a transcription of Fannie Mae's instructions.
`docs/ll-2026-04.md` sets out the letter's actual requirements and marks the
boundary between them and our choices.

**[Live demo](https://himansh97.github.io/custody.html)** — a synthetic loan file
through five AI steps, with the hash chain re-verified in your own browser. Break
a record and watch it get caught.

---

## The idea

Compliance logging fails when it is a separate step. Someone adds a model call in
a hurry, the `log.write(...)` after it never gets written, and nobody notices
until an examiner asks. So here the call *is* the record:

```python
from custody import Ledger

ledger = Ledger(policy="uw-policy-v3.2", signing_key=key)

with ledger.decision(loan="1000254", principal="jane@lender.com",
                     purpose="income_calculation", identifiers=[borrower]) as d:

    out = d.call(model="claude-sonnet-5", prompt=prompt,
                 sources=[paystub, w2], invoke=call_the_model)

    verdict = d.gate(out, citations={"monthly_income": "paystub-2026-07-15"},
                     confidence=0.91)

    if verdict.ok:
        d.commit(outcome=out)
    else:
        d.route_to_human(queue="uw-review")
```

Every field is filled as a side effect of normal use. A decision
that is opened and abandoned still writes a record. One that raises writes a
record and re-raises. An audit trail with holes where the awkward cases were is
worse than none, because it looks complete.

## The gate

Deterministic checks only — no model judges another model. Given the same output
and the same sources, the verdict is the same forever, and an examiner can re-run
it.

| Check | Rejects |
|---|---|
| Figure binding | a number in the output that appears in no supplied source document |
| Field grounding | an extracted field that cites no source |
| Closed vocabulary | a classification outside its allowed set |
| Confidence floor | *routes to a human* below threshold — not being sure is not being wrong |

Verdicts are `pass` / `review` / `reject`. That verdict is the recorded
`response_treatment` — the evidence that a safeguard ran and what it concluded.

## The chain

Each record's hash covers the previous record's hash, and each hash is Ed25519
signed. The two answer different questions: the chain says *was anything changed
or removed*, the signature says *did this come from the system that claims to
have written it*. The chain is verifiable by anyone with the records and a
SHA-256 implementation — which is why the demo page can re-verify honestly with
no server.

Storage is append-only, enforced by SQLite triggers rather than by convention.

## Run it

```bash
python -m venv .venv && ./.venv/bin/pip install cryptography
./.venv/bin/python demo/pipeline.py      # produces demo/ledger.json
./.venv/bin/python demo/build_page.py    # builds the demo page from that ledger
./.venv/bin/python tests/test_chain.py   # and test_gate, test_ledger, test_crosslang
node tests/verify_like_the_page.js demo/ledger.json
```

The demo's model outputs are fixed rather than live, so the ledger is reproducible
byte-for-byte by anyone who clones this. The gate neither knows nor cares where an
output came from.

`tests/test_crosslang.py` diffs the Python and JavaScript canonicalisers against
every shipped record. If they ever drift, the browser would report tampering on an
honest ledger — the most damaging failure this project could have — so the
agreement is tested rather than assumed.

## What this is not

Not legal advice, it does not certify compliance, and it is not a statement of
what Fannie Mae requires. It does no bias or fair-lending
testing — that is an ECOA and fair-lending obligation rather than something this
letter specifies, it is a separate product, and vendors already occupy it. It writes to no loan origination system. It cannot
inventory models it never sees.

`docs/ll-2026-04.md` sets out what the letter actually says, what Custody helps
with, and the five obligations it does not touch at all.

## Data

All demo data is synthetic — borrower, employer, documents, loan number. There is
no real PII in this repository. The demo signing key is committed on purpose so
the shipped ledger verifies for anyone who clones it; a real deployment keeps its
private key in a KMS and never in source.
