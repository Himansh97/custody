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

### Start here

```bash
pip install custody-ledger
custody keygen                          # a signing key
custody policy --new uw-policy.json     # a policy to edit
custody run --policy uw-policy.json --purpose income_calculation \
    --data income --data paystub \
    --loan 1000254 --principal you@lender.com \
    --instruction "Extract qualifying monthly income." --doc paystub.txt
custody disclose                        # what you hand someone who asks
```

Five minutes, no model key required if you pass `--replay`. Then:

| If you want | Read |
|---|---|
| What the letter actually says, and what this does not do | [`docs/ll-2026-04.md`](docs/ll-2026-04.md) |
| Where AI governance belongs next to a data platform | [`docs/architecture.md`](docs/architecture.md) |
| The same thing wired to Blue Sage and Microsoft Fabric | [`docs/deployments/blue-sage-fabric.md`](docs/deployments/blue-sage-fabric.md) |
| Whether it clears your security review | [`docs/information-security.md`](docs/information-security.md) |

---

## The idea

Compliance logging fails when it is a separate step. Someone adds a model call in
a hurry, the `log.write(...)` after it never gets written, and nobody notices
until an examiner asks. So here the call *is* the record:

```python
from custody import Ledger, Policy

ledger = Ledger(policy=Policy.load("uw-policy.json"), signing_key=key)

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

## The policy

The gate decides whether an output is safe to use. The policy decides whether
the call was allowed to happen at all, and it is a document rather than code:

```json
{
  "policy_id": "NORTHGATE-UW-001",
  "version": "3.2",
  "owner": "compliance@northgate-lending.example",
  "last_reviewed": "2026-06-15",
  "use_cases": {
    "income_calculation": {
      "approved": true,
      "models": ["claude-sonnet-5"],
      "confidence_floor": 0.85,
      "ai_can_decide": false,
      "allowed_data": ["income", "employment", "paystub", "w2"],
      "prohibited_data": ["ssn", "bank_account_number"]
    },
    "adverse_action_reasoning": { "approved": false, "models": [] }
  }
}
```

Compliance can read that without reading your application code, and every record
carries the `policy_id` and version it ran under, so *which decisions ran under
the old floor* is a query rather than an excavation.

Data rules are enforced two ways, because one is not enough. A caller declares
what a decision touches &mdash; `data=["income", "paystub"]` &mdash; since
"income" has no shape and nothing can find it in a document. Classes that *do*
have a shape, an SSN or an account number, are found in the documents
themselves, so declaring the wrong thing does not launder the right one. If a
use case sets any data rule and a decision declares nothing, the call is
refused: a rule that quietly fails to apply is a control document making a
statement that is not true.

`d.call()` raises before the model is invoked when the policy refuses, and the
refusal is a signed record like any other &mdash; because a ledger showing only
the AI you permitted is a record of your successes, not of your controls. An
unlisted purpose is denied rather than defaulted, and loading is strict: a
misspelled `confidence_flor` is an error at startup, not a control that silently
kept its default.

Two things it deliberately does not do. It does not make an override impossible
&mdash; committing where the policy says AI may recommend but not decide is
recorded as `committed_without_authority`, for the same reason a rejection can be
overridden: a control that cannot be overridden gets bypassed entirely, and then
nothing is recorded at all. And it does not refuse a bare version string, which
still works and records `policy_decision: unevaluated`, because a record saying
nothing checked is honest and a migration nobody adopts is not.

```bash
custody policy uw-policy.json     # does it load, what does it permit, is it overdue
```

LL-2026-04 requires an owner who reviews the policies at least annually. Custody
cannot do the review, but `last_reviewed` plus an interval means an overdue one
shows up in the packet and in the banner on every run rather than during an
audit.

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

Storage is append-only, enforced by database triggers rather than by convention.
The chain cannot fork because `prev_hash` is `UNIQUE` — two writers cannot both
chain onto the same predecessor, and the second one is refused rather than
quietly writing a ledger that will not verify. Locking is an optimisation on top
of that, not the guarantee.

### Proving nothing was removed from the end

A hash chain catches an edit, a deletion from the middle, a reordering. It cannot
catch a truncation: delete the newest records and what remains is a shorter chain
in which every link is genuine, so it verifies. That is what a hash chain is, not
a defect in this one, and no verifier reading only the ledger can close it.

Closing it takes one fact from outside the ledger:

```bash
custody anchor                       # custody-anchor:v1:6:0cf2c799d2d5a25d...
custody verify --expect-anchor "$ANCHOR"
python3 verify_packet.py packet.json "$ANCHOR"
```

`Ledger(on_append=...)` hands you that line after every write so you can ship it
somewhere automatically. Keep it anywhere the ledger's own operator cannot edit
&mdash; a different account, your SIEM, a counterparty. Kept in the same database
it protects nothing, and Custody does not pick the destination for you.

### SQLite or Postgres

SQLite is the default and needs nothing installed. Run more than one application
instance and you want Postgres, where the same guarantees hold and a process
lock would not:

```bash
pip install "custody-ledger[postgres]"
custody run --db postgresql://user:pw@host/custody ...
```

```python
Ledger(policy="income-calc-v3", signer=signer,
       path="postgresql://user:pw@host/custody")
```

One conformance suite runs against both backends, so they cannot drift into
disagreeing about what verifies. On Postgres, also revoke the privileges — the
trigger should be your backstop, not your only defence:

```sql
REVOKE UPDATE, DELETE ON records FROM custody_app;
```

## Callers that are not Python

The library works because there is no way to reach the model that does not go
through a `Decision`. A .NET service in the LOS cannot use it, and the obvious
answer &mdash; publish an authorize endpoint and a validate endpoint and ask the
caller to use both &mdash; gives up the property that made it worth having. A
caller can authorize, ignore the answer, call the model itself, and never
validate. Nothing about that shape prevents it, and the failure is silent.

So the gateway is a proxy, not an advisor. The model call happens on the far
side of the policy check, and the caller gets output only after it has been
gated and recorded:

```bash
custody gateway --policy uw-policy.json --db postgresql://...
```

```
POST /decision
{"loan":"1000254","principal":"jane@lender.com","purpose":"income_calculation",
 "instruction":"Extract qualifying monthly income.",
 "documents":[{"id":"paystub-2026-07-15","text":"..."}]}
```

A refused purpose returns 403 with the reason and no output, because the model
was never asked. There is no request to this service that returns a model's
answer without also having written a record.

The bearer token is a floor, not a control: it carries no identity, and
`principal` is a claim the caller makes about itself. Put it behind your SSO and
set `principal` from the session.

## Getting the records into a warehouse

Dashboards want the records somewhere queryable. That copy is for reading and it
is not the evidence &mdash; it lives in a system whose operators are the subject
of the records. Verify the ledger, chart the replica.

```bash
custody replicate --db custody.db --out records.jsonl        # pull, checkpointed
```

```python
Ledger(..., on_record=jsonl_sink("records.jsonl"),      # the replica
            on_append=anchor_sink("anchors.log"))       # the proof
```

`on_record` and `on_append` are separate because they are separate jobs, and a
lender who sends both to the same place has one of them and believes they have
two. Neither takes a cloud SDK dependency; a sink is a callable, so Event Hubs
into a Fabric Eventstream is about ten lines against your own SDK, written once.
`docs/architecture.md` and `docs/deployments/blue-sage-fabric.md` set out where
each piece belongs.

## Which model you call

Custody wraps a call you already make; it does not choose your model. Adapters
ship for Anthropic and **Azure OpenAI**, and an adapter is just a callable
returning `(fields, confidence, endpoint, citations)` — write your own in twenty
lines if neither fits.

```bash
export AZURE_OPENAI_ENDPOINT=https://acme-uw.openai.azure.com/
custody run --provider azure-openai --deployment gpt-4o-prod \
    --loan 1000254 --principal you@lender.com \
    --instruction "Extract qualifying monthly income." --doc paystub.txt
```

With no `AZURE_OPENAI_API_KEY` set it authenticates with **managed identity** —
no stored key to leak, rotate, or find in a config file in three years.

**It records the model version, not the deployment name.** Azure routes on a
deployment, and the model behind that deployment can be changed by an
auto-update policy or by somebody in the portal without a line of your code
changing. A record saying `gpt-4o-prod` therefore does not identify what made the
decision. The response carries the real version, so that is what lands in the
ledger, with the deployment and the resource kept alongside:

```
endpoint  azure-openai:acme-uw:gpt-4o-prod:gpt-4o-2024-11-20
```

When an examiner asks which model produced a figure eighteen months ago, that is
the difference between an answer and a shrug.

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

## The question the letter actually asks

`custody packet 1000254` answers *what did your AI do to this loan*. The
disclosure clause is not about one loan. It asks what types of AI/ML are in use,
for what purpose and in what manner, and what safeguards are implemented &mdash;
of the whole business, on request, promptly.

```bash
custody disclose --policy uw-policy.json
```

```
AI/ML DISCLOSURE — prepared for Fannie Mae
  period     2026-08-06 to 2026-09-04
  184 decisions attempted across 61 loan(s); 3 refused by policy; 22 human reviews

TYPES OF AI/ML IN USE
  claude-sonnet-5  (171 decisions)
    endpoint  anthropic:messages:claude-sonnet-5
  gpt-4o-2024-11-20  (13 decisions)
    endpoint  azure-openai:acme-uw:gpt-4o-prod:gpt-4o-2024-11-20

PURPOSE AND MANNER OF USE
  income_calculation  (96)
    treatment   81 pass · 11 review · 4 reject · 0 denied
    outcome     81 committed (0 over an objection) · 15 routed to a person
    policy      NORTHGATE-UW-001@3.2
```

It is assembled from the records rather than from a register somebody maintains,
because a register is a claim and the records are what happened. It ends by
saying what it cannot cover &mdash; AI that never went through this ledger
&mdash; because an inventory read as complete when it is not is worse than none.

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

```bash
pip install custody-ledger        # one dependency: cryptography
custody keygen                    # signing key, mode 600
custody policy --new uw-policy.json   # a starter policy to edit

custody run --policy uw-policy.json --purpose income_calculation \
    --data income --data paystub \
    --loan 1000254 --principal you@lender.com \
    --instruction "Extract qualifying monthly income." \
    --doc paystub.txt --doc w2.txt \
    --redact "Borrower Name" --model claude-sonnet-5

custody verify custody.db --public-key <hex>   # recompute the chain
custody packet 1000254 --out packet.json       # evidence for one loan
custody disclose                               # evidence for the whole book
custody policy --new uw-policy.json            # a policy to start from
custody policy uw-policy.json                  # validate it, check its review
custody gateway                                # govern a caller that is not Python
custody replicate --out records.jsonl          # copy to a warehouse
custody serve                                  # prints a URL with a one-time token
                                               # /api/disclose, /api/loan/{loan}
```

`custody serve` binds loopback and mints a token unless you supply one, and
refuses outright to bind anywhere else without one &mdash; it is serving an audit
trail containing loan numbers. A shared token is a floor, not a control; put it
behind your SSO before anyone but you uses it.

`custody run` calls a real model when `ANTHROPIC_API_KEY` is set
(`pip install custody-ledger[anthropic]`), or replays a fixed response with
`--replay fixture.json`. The gate neither knows nor cares which.

Custody does not call your model on your behalf in library use &mdash; it wraps a
call you already make. A governance layer that requires you to rewrite your AI
does not get adopted.

## From a source checkout

```bash
python demo/pipeline.py      # the synthetic loan, produces demo/ledger.json
python demo/build_page.py    # bakes the review page from that ledger
python tests/test_chain.py   # and test_gate, test_ledger, test_crosslang
node tests/verify_like_the_page.js demo/ledger.json   # the page's hashing
node tests/render_like_the_page.js                    # and its rendering
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
`docs/architecture.md` argues where AI governance belongs relative to a data
platform, and `docs/deployments/blue-sage-fabric.md` instantiates that on a Blue
Sage and Microsoft Fabric stack.

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
