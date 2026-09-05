# Where AI governance lives

A lender that has bought Microsoft Fabric asks a reasonable question: the data
platform is already governed, already audited, already has lineage and
classification, so why would AI governance live anywhere else?

Because Fabric governs data. AI governance is about what a model was allowed to
do with that data, whether the safeguard actually ran, and what happened as a
result &mdash; and the answers to those questions have to survive being read by
someone who does not trust the people who produced them.

This document sets out where each piece belongs and why. It is engineering
opinion, not a Fannie Mae requirement; `ll-2026-04.md` marks that boundary.

---

## The short answer

Build AI governance as an independent control plane. Use Fabric as the analytics
surface over a replica of its records, and Purview for data governance alongside
it. Do not make Fabric the system of record for what your AI did.

```
   LOS / CRM / internal assistant
                │
                ▼
   ┌────────────────────────────┐
   │  policy  →  enforcement    │   in the call path
   └─────────────┬──────────────┘
                 │
                 ▼
              model
                 │
                 ▼
   ┌────────────────────────────┐
   │  append-only signed ledger │   the record
   └───────┬────────────┬───────┘
           │            │
      anchor out    replica in
           │            │
           ▼            ▼
     SIEM / other    Fabric  →  Power BI
     account
```

## Why not Fabric

**Fabric is a derived store.** Records arrive after the fact, through pipelines
owned by the same team that owns the AI. Anything the subject of a record can
rewrite is a report, not evidence. That is the load-bearing argument, and it
holds even in an organisation with one AI use case and no plans for a second.

The portability argument &mdash; today Fabric calls the model, tomorrow the LOS
does, then the CRM, then an internal assistant &mdash; is true and secondary. It
predicts a future problem. The derived-store problem is present on day one.

There is a third reason that only shows up under audit. A record in a lakehouse
table is trustworthy exactly as far as the access controls around it, which means
an examiner's confidence in it is a function of your IAM configuration on the day
they ask. A hash-chained signed record is trustworthy because of arithmetic they
can redo themselves. One of those travels; the other does not.

None of this is an argument against Fabric. Put the replica there, build the
dashboards there, run the analytics there. Just do not let the only copy live in
the system whose operators the record is about.

## Three layers, and only one of them is a document

**Policy: what is allowed.** Versioned, reviewed by compliance, kept in git.
Not `if use_case == "income_analysis": allow()` &mdash; a policy compliance can
read without reading your application code, and a version number every decision
carries.

**Enforcement: whether it was allowed.** In the call path. Evaluates the policy,
runs the checks, produces the treatment.

**Evidence: proof that enforcement ran.** Append-only, signed, verifiable by
someone outside the company.

Custody implements the second and third. It does not implement the first, and a
vendor claiming to sell you your policy is selling you a template.

## Governance goes in the data path, not beside it

A common sketch is two API calls: `POST /ai/authorize` before the model,
`POST /ai/validate-output` after it. It is clean, it is RESTful, and it is
advisory. An application can call authorize, ignore the response, call the model
anyway, and never call validate at all. Nothing about the shape prevents it, and
the failure is silent &mdash; you find out when an examiner asks for records of a
use case whose records were never written.

This is the same failure as the `log.write(...)` that was never added after a
model call shipped in a hurry. It is not a discipline problem to be solved with a
code review checklist. It is a design problem, and there are two designs that
solve it:

- **In-process.** The decision is a context manager and the model call goes
  through it. A decision that is opened and abandoned still writes a record; one
  that raises writes a record and re-raises. There is no path to the model that
  does not produce evidence.
- **A proxy.** For callers that are not in your language, the model call is made
  *through* the governance service rather than reported to it. Same property,
  paid for with a network hop.

Two side calls are neither. If you must expose an authorize endpoint for
pre-flight UX, treat its answer as advice and keep the enforcing copy in the
path.

## The gate must be deterministic

Given the same output and the same sources, a check returns the same verdict
forever. An examiner can re-run it and get what you got.

This rules out a model scoring another model's output. A second model's opinion
is not evidence that a safeguard ran; it is a second thing to audit, with its own
version, its own drift, and its own bad day. Keep the checks boring: figures in
the output must appear in a supplied source, extracted fields must cite one,
classifications must fall inside a closed vocabulary, and low confidence routes
to a human rather than failing.

Three outcomes, not two. `pass` and `reject` are easy. `review` is the one that
matters, because a system with only pass and fail either auto-commits things it
should not or blocks things a person would have waved through in seconds, and the
second is how a control gets switched off.

## Record the model that answered, not the one you asked for

A record saying `"model": "claude"` or `"model": "gpt-4o-prod"` does not identify
what made the decision. Azure routes on a deployment name, and the model behind
that deployment can change through an auto-update policy or through somebody in
the portal, with no change to your code and no signal in your logs.

Record the resolved version the response reports, and keep the deployment and
resource alongside it:

```
endpoint  azure-openai:acme-uw:gpt-4o-prod:gpt-4o-2024-11-20
```

This is also the concrete form of the model-agnostic principle. Your policy says
"income analysis is approved for these models", not "Claude is approved". The
registry resolves the rest, and the record proves which one actually answered.

## What proves nothing was removed

A hash chain catches an edit, a deletion from the middle, a reordering. It cannot
catch a truncation: delete the newest records and what remains is a shorter chain
in which every link is genuine. No verifier reading only the ledger can close
that, which means the closing fact has to come from outside it.

Publish an anchor &mdash; a count and the head hash &mdash; somewhere the ledger's
operator cannot edit. A different subscription, your SIEM, a counterparty.
Anchored inside the same database it protects nothing.

## Separation of duties, concretely

Three parties, none of which can rewrite the past alone:

| Who | Can | Cannot |
|---|---|---|
| Engineering | Ship code, append records | Change a policy without compliance approval; edit or delete a record |
| Compliance | Approve policy versions in git | Write to the ledger |
| Platform / security | Hold the anchor and the signing key | Alter a record undetected |

The database enforces the middle row rather than the org chart doing it:

```sql
REVOKE UPDATE, DELETE ON records FROM custody_app;
```

The trigger is the backstop. The revoked grant is the control.

## Where each piece belongs

| Component | Where |
|---|---|
| LOS | The LOS vendor |
| Event backbone | Event Hubs or Kafka |
| Ingestion, raw and curated data | Fabric, OneLake |
| Data catalogue, classification, lineage, DLP | Purview |
| AI policy (use cases, approved models, thresholds) | Git, reviewed by compliance |
| Policy evaluation and the gate | In the call path |
| **AI decision records** | **Append-only signed ledger** |
| Analytics and dashboards over those records | Fabric plus Power BI, from a replica |
| Anchors | Outside the ledger's operator |
| Human review | The LOS or workflow application |

The row that people get wrong is the bolded one. Everything else can sit where
the platform team would naturally put it.

## Purview is not AI governance

Purview classifies data, tracks lineage, and applies DLP. It answers "is this
column NPI and where did it come from". It does not record that a model was asked
a question about that column, what safeguard ran on the answer, or what was
written downstream as a result. It belongs in the architecture, alongside rather
than underneath, and it should not be counted toward the disclosure obligation.

## What this architecture does not cover

Said plainly, because a buyer gets hurt when a vendor is vague here.

- **Bias and fair-lending testing.** Nothing above addresses it. That obligation
  is real and comes chiefly from ECOA and fair-lending law.
- **Retention and legal hold.** An append-only ledger has an unresolved tension
  with deletion obligations, and the answer is a policy decision before it is a
  technical one.
- **Model inventory.** No ledger can inventory models it never sees. A list
  assembled only from what happened to be instrumented is worse than no list,
  because it looks complete.
- **Information security controls.** A ledger holding redacted prompts and
  decision outcomes is in scope of Fannie Mae's Information Security and Business
  Resiliency Supplement. See `information-security.md`, which says no five times.
