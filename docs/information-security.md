# Custody against the Information Security and Business Resiliency Supplement

LL-2026-04 requires seller/servicers to comply with Fannie Mae's **Information
Security and Business Resiliency Supplement** (published 2 September 2025,
mandatory since 12 August 2025). Custody stores loan numbers and derived
financial data, so it lands in scope of that Supplement and a security review
will ask about it.

This is the answer. It is written control by control against the Supplement's
own section numbers, and it says "no" five times.

Source: <https://www.fanniemae.com/media/document/pdf/information-security-and-business-resiliency-supplement>

**The Supplement obliges the Company, not its tools.** Custody cannot comply with
it. What follows is what Custody contributes, what it leaves to you, and where it
would actively fail an assessment today.

---

## §3.3 Audit and Accountability — where Custody is the answer

The Supplement requires a Company to:

> *"Implement controls to ensure logs are protected from access, modification, or
> deletion by unauthorized personnel"* and *"establish processes and controls that
> ensure logs are monitored and reviewed for the unauthorized disclosure,
> modification, deletion, or replications of Confidential Information."*

This is the control Custody exists to satisfy, and it satisfies it unusually well.

| Requirement | How |
|---|---|
| Logs protected from **modification** | SQLite triggers abort any `UPDATE`. Beyond that, each record's hash covers the previous one, so an edit made by any route — a SQL client, a file editor, restoring an altered backup — is detectable by anyone holding the records. |
| Logs protected from **deletion** | Triggers abort `DELETE`; a removed record leaves a gap the chain names. |
| Logs **monitored and reviewed** for unauthorised modification | `custody verify` recomputes the whole chain and reports the first broken record by id. Run it on a schedule and you have continuous detection rather than periodic hope. |
| **Independent** security assessment | `verify_packet.py` is one file, no dependency on this package, nothing outside the standard library. Your assessor verifies the evidence themselves rather than accepting our tooling's word. |
| Log **retention periods** | **Not addressed — see gaps.** |

Worth being precise about the guarantee: this is tamper-*evidence*, not
tamper-*proofing*. Anyone with write access can destroy the file. They cannot
change one record quietly, and that is the property the Supplement is asking for.

## §3.1 Access Management — a floor, and you must build the rest

The Supplement requires unique user IDs, no shared accounts, MFA where
applicable, least privilege, and access limited on a need-to-know basis.

`custody serve` binds loopback, generates a token if you do not supply one, and
**refuses outright** to bind beyond loopback without one. That is a floor. It is
one shared secret with no identity behind it, which satisfies **none** of the
unique-ID, MFA or least-privilege requirements.

A compliant deployment does not expose `custody serve` directly. It sits behind
whatever SSO the rest of the estate uses, and the identity that matters —
`principal` on every record — comes from your authenticated application, which is
why Custody requires it and will not default it.

## §3.10 Data Protection — where Custody fails today

> *"Encrypting data in-transit and at-rest."*

**At rest: no.** The SQLite file is plaintext. Deploy on encrypted storage
(Azure Disk Encryption, an encrypted volume) or the requirement is unmet. There
is a real design tension here worth stating rather than hiding: an audit record
that an assessor can read directly is more useful as evidence, and one that is
encrypted at the application layer is more defensible as storage. Custody
currently chooses readability and pushes encryption to the platform. That is a
defensible choice and it is still a gap you have to close.

**In transit: no.** `custody serve` speaks plain HTTP. On loopback that is
survivable; anywhere else it is not, and the token travels in clear. Terminate
TLS in front of it.

## §3.14 Supply Chain Risk Management

One runtime dependency, `cryptography`, chosen deliberately: this sits in the
call path of a regulated workflow and every package added there is another thing
your review has to clear. Storage is stdlib `sqlite3`, the server is stdlib
`http.server`, and the model adapters are optional extras you install only if you
use them.

**Custody uses no AI/ML itself.** The gate is arithmetic and string comparison,
and there is deliberately no model anywhere in the verification path — so
adopting it adds nothing new under LL-2026-04's vendor-governance clause.

## §4 Cybersecurity Incident Management

Nothing. Incident response is yours. Custody's contribution is narrow but real:
after an incident, the chain tells you whether the audit trail itself was
altered, and names the first record that was — which is otherwise very hard to
establish and exactly what an assessor will ask.

## §5 Business Continuity

Nothing. Back up the database like any other system of record. Backups verify
independently: a restored file either verifies or it does not, so a corrupted or
substituted backup is detectable rather than merely suspected.

---

## The five gaps, plainly

1. **Encryption at rest.** Not implemented. Platform-level encryption required.
2. **Encryption in transit.** `custody serve` is plain HTTP. TLS required.
3. **Access management.** A shared token is not identity. SSO required.
4. **Log retention and destruction.** The Supplement asks for defined retention
   periods. Custody is append-only and never deletes — which is the *opposite*
   failure, and still a failure. There is no retention policy, no archival, and
   no defensible destruction path.
5. **No independent assessment yet.** Nobody outside this project has reviewed
   the cryptography. `verify_packet.py` exists so that is cheap to fix, and until
   somebody does it, treat the design as unreviewed.

## What this is not

Not a security assessment, not a compliance attestation, and not written by
anyone qualified to issue either. It is an engineer's honest reading of a public
document against code they wrote, published so a buyer can start from facts
rather than from a vendor questionnaire.
