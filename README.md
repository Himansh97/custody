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

Each record's hash covers the previous record's hash, and each hash is signed.
The two answer different questions: the chain says *was anything changed or
removed*, the signature says *did this come from the system that claims to have
written it*. The chain needs no key to verify, which is why the demo page can
re-verify in a visitor's own browser.

Storage is append-only, enforced by SQLite triggers rather than by convention,
and appends are atomic so concurrent writers cannot fork the chain.

## Where the signing key lives

A key in a file is a development convenience, and the first thing a lender's
security review will object to. So the signer is pluggable:

```python
from custody.signing import KeyVaultSigner
ledger = Ledger(policy="uw-v3", signer=KeyVaultSigner(vault_url, "custody"))
```

The private key never enters the process. Custody sends a digest and gets a
signature back; the most an attacker gets from a compromised host is the ability
to sign while they hold the credential, which the vault logs.

**Azure Key Vault has no Ed25519** -- EC and RSA only, and AWS KMS is the same.
So the algorithm is a parameter, not a constant: `ed25519` locally,
`ecdsa-p256-sha256` (ES256) in a vault. It is written into the hashed body of
every record, so a downgraded algorithm claim breaks the chain before anyone
reaches a signature check.

```bash
az keyvault key create --vault-name <vault> --name custody --kty EC --curve P-256
export CUSTODY_KEY_VAULT=https://<vault>.vault.azure.net/
export CUSTODY_KEY_NAME=custody
```

## Verifying without trusting us

`verify_packet.py` is a single file with no dependency on this package and
nothing outside the standard library. An auditor reads it end to end in a few
minutes and satisfies themselves the cryptography is real:

```bash
python3 verify_packet.py packet.json
```

With `cryptography` installed it checks signatures too; without it, it checks
the chain and says plainly that it did not check signatures rather than printing
a bare OK. It also states what it cannot prove -- that the records are *true*,
and that nothing was withheld -- because a verifier that only ever says OK
teaches people to over-read it.

## Install and run it

Not on PyPI yet, so install from the repo:

```bash
pip install "git+https://github.com/Himansh97/custody"   # one dependency: cryptography
custody keygen                                           # Ed25519 signing key, mode 600

custody run --loan 1000254 --principal you@lender.com \
    --instruction "Extract qualifying monthly income." \
    --doc paystub.txt --doc w2.txt \
    --redact "Borrower Name" --model claude-sonnet-5

custody verify custody.db --public-key <hex>   # recompute the chain
custody packet 1000254 --out packet.json       # evidence for one loan
custody serve                                  # prints a URL with a one-time token
```

`custody serve` binds loopback and mints a token unless you supply one, and
refuses outright to bind anywhere else without one &mdash; it is serving an audit
trail containing loan numbers. A shared token is a floor, not a control; put it
behind your SSO before anyone but you uses it.

`custody run` calls a real model when `ANTHROPIC_API_KEY` is set
(`pip install "custody-ledger[anthropic] @ git+https://github.com/Himansh97/custody"`), or replays a fixed response with
`--replay fixture.json`. The gate neither knows nor cares which.

Custody does not call your model on your behalf in library use &mdash; it wraps a
call you already make. A governance layer that requires you to rewrite your AI
does not get adopted.

## From a source checkout

```bash
python demo/pipeline.py      # the synthetic loan, produces demo/ledger.json
python demo/build_page.py    # bakes the review page from that ledger
python tests/test_chain.py   # and test_gate, test_ledger, test_crosslang
node tests/verify_like_the_page.js demo/ledger.json
```

The demo's model outputs are fixed, so the ledger is reproducible byte-for-byte
by anyone who clones this.

`tests/test_crosslang.py` diffs the Python and JavaScript canonicalisers against
every shipped record. If they ever drift, the browser would report tampering on
an honest ledger &mdash; the most damaging failure this project could have &mdash; so
the agreement is tested rather than assumed.

## What this is not

Not legal advice, it does not certify compliance, and it is not a statement of
what Fannie Mae requires. It does no bias or fair-lending
testing — that is an ECOA and fair-lending obligation rather than something this
letter specifies, it is a separate product, and vendors already occupy it. It writes to no loan origination system. It cannot
inventory models it never sees.

`docs/ll-2026-04.md` sets out what the letter actually says, what Custody helps
with, and the obligations it does not touch at all.

`docs/information-security.md` does the same against Fannie Mae's Information
Security and Business Resiliency Supplement, control by control. It says no five
times &mdash; encryption at rest, encryption in transit, real access management, log
retention, and independent review of the cryptography. A buyer should start from
that page rather than from a questionnaire.

## Data

All demo data is synthetic — borrower, employer, documents, loan number. There is
no real PII in this repository. The demo signing key is committed on purpose so
the shipped ledger verifies for anyone who clones it; a real deployment keeps its
private key in a KMS and never in source.
