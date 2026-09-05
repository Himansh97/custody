# Custody on Blue Sage and Microsoft Fabric

For a lender whose stack is Blue Sage for origination, Event Hubs into a Fabric
medallion for data, and Claude or Azure OpenAI for document and income analysis.

This is `../architecture.md` instantiated on that stack. It assumes the general
argument and gets to the wiring.

---

## What the obligation actually is

LL-2026-04 took effect on **6 August 2026**. The clause that bites is not the one
about having policies, which most lenders can satisfy with a document. It is the
last one: on Fannie Mae's request, **promptly disclose the types of AI/ML in use,
the purpose and manner of that use, and the safeguards implemented.**

A policy document answers what was supposed to happen. What gets asked for is
what did happen, on which loans, checked by whom. The gap between those two
answers is the thing being built here.

Be precise about the letter, because vendor summaries of it are not. LL-2026-04
specifies no record schema, names no fields, and requires neither append-only
storage nor signing. What follows is one implementation of the disclosure and
safeguard obligations. `../ll-2026-04.md` marks the boundary between the letter
and our choices.

## Where it sits

```
  Blue Sage  ──►  integration layer  ──►  Event Hubs  ──►  Fabric
                                                             │
                                                     governed data
                                                             │
                                                             ▼
                                              ┌──────────────────────┐
                                              │   AI application     │
                                              │                      │
                                              │   with ledger        │
                                              │     .decision(...)   │
                                              │       d.call(...) ───┼──► Claude
                                              │       d.gate(...)    │
                                              │       d.commit(...)  │
                                              └──────────┬───────────┘
                                                         │
                          ┌──────────────────────────────┴───────────┐
                          │                                          │
                          ▼                                          ▼
              Azure Database for PostgreSQL              on_append(anchor)
              (append-only, UPDATE/DELETE revoked)                   │
                          │                                          ▼
                    Event Hubs                              SIEM / separate
                          │                                  subscription
                          ▼
                Fabric Eventstream ──► Lakehouse ──► Power BI
```

The governance is in the AI application, in the call path, not a service beside
it that the application can decline to call. That is the whole reason the record
is trustworthy: there is no route to the model that does not produce one.

## The wiring, piece by piece

**Ledger on Azure Database for PostgreSQL.** More than one application instance
means Postgres rather than SQLite; the guarantees are identical and one
conformance suite runs against both so they cannot drift.

```python
from custody import Ledger
from custody.signing import KeyVaultSigner

ledger = Ledger(
    policy="uw-income-v3.2",
    signer=KeyVaultSigner(vault_url, "custody"),
    path="postgresql://custody_app@acme-uw.postgres.database.azure.com/custody",
    on_append=publish_anchor,
)
```

Then take the grants away from the application role. The trigger is the backstop,
not the control:

```sql
REVOKE UPDATE, DELETE ON records FROM custody_app;
```

The chain cannot fork because `prev_hash` is `UNIQUE`, so two instances racing to
append cannot both chain onto the same predecessor. The second is refused rather
than quietly writing a ledger that will not verify later.

**Signing key in Azure Key Vault.** Key Vault has no Ed25519, so the algorithm is
a parameter and a vault deployment signs with ES256:

```bash
az keyvault key create --vault-name acme-uw --name custody --kty EC --curve P-256
export CUSTODY_KEY_VAULT=https://acme-uw.vault.azure.net/
export CUSTODY_KEY_NAME=custody
```

The private key never enters the process. Custody sends a digest and gets a
signature back, so a compromised host buys an attacker the ability to sign while
they hold the credential, which the vault logs. The algorithm is written into the
hashed body of every record, so a downgraded algorithm claim breaks the chain
before anyone reaches a signature check.

**Both models, one ledger.** If Claude does the reasoning and Azure OpenAI does
something else, the shipped Azure adapter authenticates with managed identity
when no API key is set, and records the model version the response reports rather
than the deployment name:

```
endpoint  azure-openai:acme-uw:gpt-4o-prod:gpt-4o-2024-11-20
```

Azure routes on the deployment, and what sits behind that deployment can change
through an auto-update policy or through somebody in the portal without a line of
your code changing. Eighteen months later, when an examiner asks what produced a
figure, that field is the difference between an answer and a shrug.

**Fabric gets a replica, not the record.** `on_append` hands you an anchor line
after every write, and the records themselves stream to Event Hubs, through
Eventstream, into a Lakehouse table. Build the governance dashboard on that:
decisions this month, treatment mix, models in use, review queue depth, override
count. It is analytics over a copy. The ledger stays the record, because the
Fabric copy lives in a system whose operators the records are about.

**The anchor leaves the building.** A hash chain cannot detect truncation of the
newest records; closing that takes one fact held where the ledger's operator
cannot edit it. A separate subscription or the SIEM. Custody deliberately does
not pick the destination, because the place that is genuinely out of reach
differs per lender and guessing wrong would be worse than asking.

## What gets handed over when Fannie Mae asks

```bash
custody packet 1000254 --out packet.json
python3 verify_packet.py packet.json "$ANCHOR"
```

The packet is self-contained: records, public key, verification result. The
recipient does not need access to lender systems, or the lender's word, to check
it. `verify_packet.py` is a single file with no dependency on the package and
nothing outside the standard library, so their auditor can read the whole thing
in a few minutes and satisfy themselves the cryptography is real. Without
`cryptography` installed it checks the chain and says plainly that it did not
check signatures, rather than printing a bare OK.

It also states what it cannot prove: that the records are true, and that nothing
was withheld. A verifier that only ever says OK teaches people to over-read it.

Rejected decisions stay in the packet. Filtering them would produce a cleaner
artifact and a false one.

## What this does not do, before anyone finds it

- **No bias or fair-lending testing.** None, and no disparate-impact claim of any
  kind. That obligation is real, comes chiefly from ECOA and fair-lending law
  rather than from this letter, and established vendors serve it.
- **It writes nothing to Blue Sage.** Human review and workflow stay in the LOS.
- **It cannot inventory models it never sees.** It knows what it was asked to
  wrap. Whatever satisfies "types of AI/ML used" across the whole organisation
  has to come from somewhere else as well.
- **The Fannie Mae Information Security and Business Resiliency Supplement is
  unassessed.** A ledger holding redacted prompts and decision outcomes is
  squarely in its scope. `../information-security.md` goes control by control and
  says no five times: encryption at rest, encryption in transit, real access
  management, log retention, and independent review of the cryptography. Start
  there rather than from a questionnaire.
- **No policy engine yet.** `policy_version` is recorded on every decision but
  nothing evaluates a policy today. See `../architecture.md` for the shape that
  is being built.

## What a pilot looks like

One use case, four weeks, no LOS integration.

1. Pick the narrowest use case with a real figure in it. Income calculation from
   paystubs is the obvious one, because the failure mode is concrete: a number in
   the output that appears in no source document.
2. Wrap the existing model call. Custody does not call the model for you in
   library use, so nothing about the AI application's design has to change.
3. Postgres, Key Vault, grants revoked, anchors to a second subscription.
4. Run it in shadow for a fortnight: the gate records its verdict, humans keep
   deciding, and nobody's throughput changes.
5. Produce a packet for one real loan and hand it to whoever would receive the
   Fannie Mae request. If they cannot answer the disclosure clause from it, that
   is the finding worth having, and it costs four weeks rather than an audit.

Not legal advice, and no certification of compliance. Custody produces records.
Whether the programme meets the letter is a question for the lender and its
counsel.
