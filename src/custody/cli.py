"""`custody` — run it against your own documents and your own model.

The commands are shaped around the questions a lender actually has, in the order
they have them:

    custody keygen                  where does the signing key come from
    custody run     ...             does this work on my documents
    custody verify  ...             has anything been changed
    custody packet  <loan>          what do I hand someone who asks about a loan
    custody disclose                what do I hand someone who asks about the book
    custody policy  <file>          is this policy valid, and reviewed
    custody gateway                 govern a caller that is not Python
    custody replicate               copy the records to a warehouse
    custody serve                   can my team look at this
    custody demo                    show me before I install anything
"""
from __future__ import annotations

import argparse
import json
import os
import pathlib
import sys

from .chain import AnchorError, anchor_for, check_anchor

from .signing import ECDSA_P256, ED25519, LocalSigner

DEFAULT_DB = "custody.db"
DEFAULT_KEY = "custody-signing.key"


# --------------------------------------------------------------------- keys

def load_signer(path: str | None = None, *, vault: str | None = None,
                key_name: str | None = None):
    """Resolve a signer, preferring the one that keeps the key out of this process.

    Order is deliberate: a vault beats an environment variable beats a file. If
    someone has gone to the trouble of configuring Key Vault, a stale key file
    lying around should not silently win.

    Refuses to invent a key. A ledger signed by one generated on the fly is
    signed by nothing in particular — every run would produce a different
    identity, and a signature nobody can tie to a system is decoration.
    """
    vault = vault or os.environ.get("CUSTODY_KEY_VAULT")
    key_name = key_name or os.environ.get("CUSTODY_KEY_NAME")
    if vault and key_name:
        from .signing import KeyVaultSigner
        return KeyVaultSigner(vault, key_name)

    algorithm = os.environ.get("CUSTODY_KEY_ALG", ED25519)
    material = os.environ.get("CUSTODY_SIGNING_KEY")
    if material:
        return LocalSigner.from_hex(material, algorithm)

    target = pathlib.Path(path or DEFAULT_KEY)
    if not target.exists():
        raise SystemExit(
            f"no signing key at {target}. Run `custody keygen` first, set "
            "CUSTODY_SIGNING_KEY, or point CUSTODY_KEY_VAULT and CUSTODY_KEY_NAME "
            "at an Azure Key Vault key."
        )
    text = target.read_text().strip().splitlines()
    if len(text) > 1 and text[0].startswith("alg:"):
        algorithm = text[0].split(":", 1)[1].strip()
        return LocalSigner.from_hex(text[1], algorithm)
    return LocalSigner.from_hex(text[0], algorithm)


# Kept so anything written against the earlier name keeps working.
load_key = load_signer


def open_for_reading(db: str, *, policy: str = "-", key: str | None = None,
                     public_key: str | None = None):
    """Open a ledger for a report, without requiring the private signing key.

    Reading needs no signing key, and demanding one would mean whoever compiles
    evidence for an examiner must also be able to write records. So a key is
    used if one is configured, a public key is used if one is supplied, and
    otherwise the ledger opens read-only and every report says plainly that
    signatures were not checked.
    """
    from .ledger import Ledger

    signer = None
    if key or os.environ.get("CUSTODY_SIGNING_KEY") or os.environ.get("CUSTODY_KEY_VAULT") \
            or pathlib.Path(key or DEFAULT_KEY).exists():
        try:
            signer = load_signer(key)
        except SystemExit:
            signer = None
    ledger = Ledger(policy=policy, signer=signer, path=db)
    if signer is None:
        ledger.with_public_key(public_key)
    return ledger


def signature_note(ledger) -> str:
    if ledger.public_key is not None:
        return f"signatures checked ({ledger.algorithm})"
    return "signatures NOT checked -- no public key supplied; chain continuity only"


def cmd_keygen(args) -> int:
    target = pathlib.Path(args.out)
    if target.exists() and not args.force:
        raise SystemExit(
            f"{target} already exists. Overwriting it would orphan every record "
            "signed with the old key — pass --force if that is genuinely what you want."
        )
    signer = LocalSigner(algorithm=args.algorithm)
    target.write_text(f"alg:{signer.algorithm}\n{signer.private_hex()}\n", encoding="utf-8")
    target.chmod(0o600)
    print(f"algorithm    {signer.algorithm}")
    print(f"private key  {target} (mode 600)")
    print(f"public key   {signer.public_key_bytes().hex()}")
    print()
    print("Give the public key to whoever verifies your ledgers.")
    print()
    print("This key is in a file, which is a development convenience and not how a")
    print("regulated deployment should run. For production, create an EC P-256 key in")
    print("Azure Key Vault and point Custody at it -- the private key then never enters")
    print("this process at all:")
    print()
    print("  az keyvault key create --vault-name <vault> --name custody --kty EC --curve P-256")
    print("  export CUSTODY_KEY_VAULT=https://<vault>.vault.azure.net/")
    print("  export CUSTODY_KEY_NAME=custody")
    return 0


# ---------------------------------------------------------------------- run

def cmd_run(args) -> int:
    """One real decision, against real documents, recorded end to end."""
    from .adapters import anthropic_extractor, azure_openai_extractor, replay
    from .ledger import Ledger
    from .policy import PolicyDenied

    documents: list[tuple[str, str]] = []
    for spec in args.doc:
        path = pathlib.Path(spec)
        if not path.exists():
            raise SystemExit(f"no such document: {path}")
        documents.append((path.stem, path.read_text(encoding="utf-8", errors="replace")))

    if args.replay:
        fixture = json.loads(pathlib.Path(args.replay).read_text())
        extract = replay(fixture.get("fields", {}), fixture.get("confidence"),
                         fixture.get("citations"), model=args.model)
    elif args.provider == "azure-openai":
        extract = azure_openai_extractor(
            deployment=args.deployment or args.model,
            endpoint=args.azure_endpoint,
            api_version=args.api_version,
        )
    else:
        extract = anthropic_extractor(model=args.model)

    ledger = Ledger(policy=args.policy, signer=load_signer(args.key), path=args.db)
    if ledger.policy_doc is not None:
        review = ledger.review_status()
        print(f"policy         : {ledger.policy}")
        if review and review["overdue"]:
            print(f"  WARNING: {review['detail']}"
                  f" (owner: {review.get('owner') or 'unnamed'})")

    denied = False
    got: dict = {}

    def invoke():
        # Inside the decision, so the policy check runs before the model does.
        fields, confidence, endpoint, citations = extract(args.instruction, documents)
        got.update(fields=fields, confidence=confidence, endpoint=endpoint,
                   citations=citations)
        return fields

    with ledger.decision(loan=args.loan, principal=args.principal, purpose=args.purpose,
                         identifiers=args.redact or (), data=args.data or ()) as d:
        try:
            d.call(model=args.model, prompt=args.instruction,
                   sources=[text for _, text in documents], invoke=invoke)
        except PolicyDenied as exc:
            # Printed and swallowed so the block exits normally and the denial
            # record is written. Re-raising would also record it, but a
            # traceback is the wrong way to report a control doing its job.
            denied = True
            print(f"DENIED         : {exc}")
            print("nothing was sent to a model.")
        else:
            # `endpoint` carries the version that actually answered. Recording
            # the flag the operator typed instead would record an intention.
            d.resolved(got["endpoint"])

            # An explicit --floor overrides the policy and is visible in the
            # shell history that did it. Absent one, the approved floor runs.
            overrides = {} if args.floor is None else {"confidence_floor": args.floor}
            verdict = d.gate(got["fields"], citations=got["citations"],
                             confidence=got["confidence"], **overrides)

            print(f"model returned : {json.dumps(got['fields'])}")
            print(f"confidence     : {got['confidence']}")
            print(f"endpoint       : {d.endpoint}")
            print(f"verdict        : {verdict.treatment}")
            for finding in verdict.findings:
                print(f"  - [{finding.check}] {finding.detail}")

            if verdict.ok:
                d.commit(outcome=got["fields"])
                # The disposition, not the word "committed". A policy that says
                # AI may recommend but not decide records this as an override,
                # and a CLI that printed "committed." over that would be hiding
                # the one line worth reading.
                print(f"{d.disposition.replace('_', ' ')}.")
            else:
                d.route_to_human(queue=args.queue)
                print(f"routed to {args.queue} — nothing was committed.")

    print(f"\nrecorded in {args.db}. `custody packet {args.loan} --db {args.db}` to export.")
    return 1 if denied else 0


# ------------------------------------------------------------------- verify

def _load_records(source: str) -> tuple[list[dict], str | None, str]:
    """Accept either a live database or an exported bundle.

    The algorithm comes from the records themselves rather than a flag, because
    a ledger that cannot say how it was signed is not self-describing and the
    person verifying it should not have to be told.
    """
    if str(source).startswith(("postgres://", "postgresql://")):
        from .store import open_store
        records, embedded = open_store(str(source)).all(), None
    else:
        path = pathlib.Path(source)
        if not path.exists():
            raise SystemExit(f"no such ledger: {path}")
        if path.suffix == ".json":
            bundle = json.loads(path.read_text(encoding="utf-8"))
            records = bundle["records"]
            embedded = bundle.get("public_key")
        else:
            from .store import Store
            records, embedded = Store(str(path)).all(), None
    algorithm = records[0].get("sig_alg", ED25519) if records else ED25519
    return records, embedded, algorithm


def cmd_verify(args) -> int:
    from .chain import ChainError, verify_chain
    from .signing import load_public_key

    records, embedded, algorithm = _load_records(args.ledger)
    pub_hex = args.public_key or embedded
    public = load_public_key(pub_hex, algorithm) if pub_hex else None

    try:
        verify_chain(records, public)
    except ChainError as exc:
        print(f"BROKEN at record {exc.index} ({exc.record_id})")
        print(f"  {exc.reason}")
        print(f"\n{len(records)} records read; everything from {exc.index} onward is unreliable.")
        return 1

    how = (f"hash chain and {algorithm} signatures" if public
           else "hash chain only (no public key given)")
    print(f"OK  {len(records)} records verified — {how}")

    current = anchor_for(records)
    if args.expect_anchor:
        try:
            check_anchor(records, args.expect_anchor)
        except AnchorError as exc:
            print(f"\nANCHOR MISMATCH\n  {exc}")
            return 1
        except ValueError as exc:
            print(f"\n{exc}")
            return 2
        print(f"OK  matches the anchor you supplied")
    else:
        print(f"\nanchor  {current}")
        print("  A verifying chain does not prove records were not removed from the END --")
        print("  a truncated chain always verifies. Keep this anchor somewhere this")
        print("  system cannot edit, and pass it back with --expect-anchor.")
    return 0


# ------------------------------------------------------------------- anchor

def cmd_anchor(args) -> int:
    """Print the anchor to record elsewhere. The whole command is one line of
    output on purpose -- it is meant to be piped into something."""
    records, _, _ = _load_records(args.ledger)
    print(anchor_for(records))
    return 0


# ------------------------------------------------------------------- packet

def cmd_packet(args) -> int:
    from .examiner import packet

    # The policy is optional here and only affects the review state reported in
    # the packet. Pass the one the decisions ran under and an examiner sees
    # whether it was inside its review interval; omit it and the packet says
    # nothing rather than guessing.
    ledger = open_for_reading(args.db, policy=args.policy, key=args.key,
                              public_key=args.public_key)
    result = packet(ledger, args.loan, requested_by=args.requested_by)
    if not result["records"]:
        raise SystemExit(f"no records for loan {args.loan} in {args.db}")

    text = json.dumps(result, indent=1, default=str)
    if args.out:
        pathlib.Path(args.out).write_text(text, encoding="utf-8")
        summary = result["summary"]
        print(f"wrote {args.out}")
        print(f"  {summary['ai_decisions']} AI decisions, {summary['human_reviews']} human "
              f"reviews, {summary['rejected']} rejected, "
              f"{summary['denied_by_policy']} denied")
        print(f"  chain: {'verified' if result['chain']['verified'] else result['chain']}")
        print(f"  {signature_note(ledger)}")
    else:
        print(text)
    return 0


# ----------------------------------------------------------------- disclose

def _n(count: int, noun: str) -> str:
    """Pluralise. Small thing; this output is read by an examiner."""
    return f"{count} {noun}" + ("" if count == 1 else "s")


def cmd_disclose(args) -> int:
    """The whole-book answer to LL-2026-04's disclosure clause.

    `packet` answers "what did your AI do to loan 1000254". This answers the
    question the letter actually asks, which is not about one loan: what types
    of AI/ML are in use, for what purpose and in what manner, and what
    safeguards are implemented.
    """
    from .examiner import disclosure

    ledger = open_for_reading(args.db, policy=args.policy, key=args.key,
                              public_key=args.public_key)
    report = disclosure(ledger, requested_by=args.requested_by)

    if args.json:
        text = json.dumps(report, indent=1, default=str)
        if args.out:
            pathlib.Path(args.out).write_text(text, encoding="utf-8")
            print(f"wrote {args.out}")
        else:
            print(text)
        return 0

    totals, period = report["totals"], report["period"]
    print(f"AI/ML DISCLOSURE — prepared for {report['requested_by']}")
    print(f"  generated  {report['generated_at']}")
    if period["first"]:
        print(f"  period     {period['first'][:10]} to {period['last'][:10]}")
    print(f"  {_n(totals['decisions_attempted'], 'decision')} attempted across "
          f"{_n(totals['loans'], 'loan')}; {totals['denied_by_policy']} refused by "
          f"policy; {_n(totals['human_reviews'], 'human review')}")

    print()
    print("TYPES OF AI/ML IN USE")
    if not report["models"]:
        print("  none recorded")
    for entry in report["models"]:
        print(f"  {entry['model']}  ({_n(entry['decisions'], 'decision')})")
        for endpoint in entry["endpoints"]:
            print(f"    endpoint  {endpoint}")

    print()
    print("PURPOSE AND MANNER OF USE")
    for entry in report["purposes"]:
        print(f"  {entry['purpose']}  ({entry['decisions']})")
        print(f"    treatment   {entry['pass']} pass · {entry['review']} review · "
              f"{entry['reject']} reject · {entry['denied']} denied")
        print(f"    outcome     {entry['committed']} committed "
              f"({entry['overrides']} over an objection) · "
              f"{entry['routed_to_human']} routed to a person")
        print(f"    policy      {', '.join(entry['policies']) or '—'}")

    safeguards = report["safeguards"]
    print()
    print("SAFEGUARDS IMPLEMENTED")
    print(f"  gate        {safeguards['gate']}")
    fired = safeguards["checks_that_fired"]
    print(f"  fired       {', '.join(f'{k} x{v}' for k, v in fired.items()) or 'none'}")
    print(f"  policies    {', '.join(safeguards['policies_in_force']) or '—'}")
    if safeguards["decisions_under_no_evaluated_policy"]:
        print(f"  UNGOVERNED  {safeguards['decisions_under_no_evaluated_policy']} "
              "decision(s) ran with no policy evaluated")
    review = safeguards["policy_review"]
    if review:
        print(f"  review      {'OVERDUE — ' if review['overdue'] else ''}{review['detail']}")

    integrity = report["integrity"]
    print()
    print("INTEGRITY")
    chain = integrity["chain"]
    print(f"  chain       {'verified' if chain['verified'] else chain}")
    print(f"  signatures  {signature_note(ledger).split('--')[0].strip()}")
    print(f"  coverage    {'complete' if integrity['mandate_coverage']['complete'] else integrity['mandate_coverage']['missing']}")
    print(f"  anchor      {integrity['anchor']}")

    print()
    print("LIMITS")
    for limit in report["limits"]:
        print(f"  - {limit}")

    if args.out:
        pathlib.Path(args.out).write_text(
            json.dumps(report, indent=1, default=str), encoding="utf-8")
        print(f"\nwrote {args.out}")
    return 0


# ---------------------------------------------------------------- replicate

def cmd_replicate(args) -> int:
    """Copy records to a JSON Lines file for loading into a warehouse.

    A file rather than a connector, because the destination differs per lender
    and a half-supported connector is worse than none. This lands in blob
    storage, Data Factory or Eventstream picks it up, and the lakehouse table
    behind the dashboard is a copy of a ledger that stays the record.
    """
    from .replicate import CheckpointError, jsonl_sink, replicate

    ledger = open_for_reading(args.db, key=args.key)
    try:
        result = replicate(ledger, jsonl_sink(args.out), since=args.since)
    except CheckpointError as exc:
        raise SystemExit(str(exc)) from None

    print(f"copied {result['copied']} record(s) to {args.out}")
    if result["checkpoint"]:
        print(f"checkpoint  {result['checkpoint']}")
        print(f"  pass it back as --since to copy only what is new.")
    print(f"anchor      {result['anchor']}")
    print("  The replica is for reading. This line is the part that proves nothing")
    print("  was removed, and it belongs somewhere this system cannot edit.")
    return 0


# ------------------------------------------------------------------- policy

def cmd_policy(args) -> int:
    """Load a policy the way the ledger would, and say what it permits.

    Worth having as its own command because the failure this prevents is a
    policy that compliance signed off and that nothing could load -- discovered
    at the worst moment otherwise, since a ledger that will not start is not a
    ledger that logs the problem.
    """
    from .policy import Policy, PolicyError, write_starter

    if args.new:
        try:
            target = write_starter(args.new, force=args.force)
        except PolicyError as exc:
            raise SystemExit(str(exc)) from None
        print(f"wrote {target}")
        print()
        print("Edit `owner` and `last_reviewed` -- LL-2026-04 asks for an owner who")
        print("reviews the policy at least annually, and this file claims neither")
        print("until you say so. Then:")
        print()
        print(f"  custody policy {target}")
        print(f"  custody run --policy {target} --purpose income_calculation ...")
        return 0

    if not args.file:
        raise SystemExit(
            "custody policy <file>       validate a policy and show what it permits\n"
            "custody policy --new <file> write a starter policy to edit"
        )

    try:
        policy = Policy.load(args.file)
    except PolicyError as exc:
        print(f"INVALID  {exc}")
        return 2

    print(f"policy   {policy.identifier}")
    print(f"owner    {policy.owner or '(unnamed -- LL-2026-04 asks for one)'}")

    review = policy.review_status()
    flag = "OVERDUE" if review["overdue"] else "ok"
    print(f"review   {flag}: {review['detail']}")

    print()
    for name, case in sorted(policy.use_cases.items()):
        state = "approved" if case.approved else "NOT APPROVED"
        print(f"  {name}  [{state}]")
        if not case.approved:
            continue
        print(f"    models          {', '.join(case.models) or '(none -- no model may be called)'}")
        print(f"    confidence floor {case.confidence_floor:.2f}")
        print(f"    human review    {case.human_review}")
        print(f"    ai may decide   {'yes' if case.ai_can_decide else 'no (recommend only)'}")

    return 1 if review["overdue"] else 0


# ------------------------------------------------------------------ gateway

def _extractor(args):
    """The model call, resolved the same way `custody run` resolves it.

    One function so the gateway and the CLI cannot end up calling models
    differently -- which would mean two things to audit rather than one.
    """
    from .adapters import anthropic_extractor, azure_openai_extractor, replay

    if args.replay:
        fixture = json.loads(pathlib.Path(args.replay).read_text())
        return replay(fixture.get("fields", {}), fixture.get("confidence"),
                      fixture.get("citations"), model=args.model)
    if args.provider == "azure-openai":
        return azure_openai_extractor(
            deployment=args.deployment or args.model,
            endpoint=args.azure_endpoint,
            api_version=args.api_version,
        )
    return anthropic_extractor(model=args.model)


def cmd_gateway(args) -> int:
    from .gateway import serve_gateway
    from .ledger import Ledger

    ledger = Ledger(policy=args.policy, signer=load_signer(args.key), path=args.db)
    serve_gateway(ledger=ledger, extract=_extractor(args), host=args.host,
                  port=args.port, token=args.token, no_token=args.no_token)
    return 0


# -------------------------------------------------------------------- serve

def cmd_serve(args) -> int:
    from .server import serve
    serve(db=args.db, key_path=args.key, host=args.host, port=args.port,
          token=args.token, no_token=args.no_token)
    return 0


# --------------------------------------------------------------------- demo

def cmd_demo(args) -> int:
    """Run the synthetic pipeline shipped with the source checkout."""
    root = pathlib.Path(__file__).resolve().parent.parent.parent
    pipeline = root / "demo" / "pipeline.py"
    if not pipeline.exists():
        raise SystemExit(
            "the demo lives in the source checkout, not the installed package.\n"
            "Clone https://github.com/Himansh97/custody and run `python demo/pipeline.py`,\n"
            "or see the live one at https://himansh97.github.io/custody.html"
        )
    sys.path.insert(0, str(root / "demo"))
    import pipeline as demo_pipeline  # type: ignore
    bundle = demo_pipeline.run(args.out)
    print(f"{len(bundle['records'])} records, chain verified: {bundle['chain']['verified']}")
    print(f"wrote {args.out}")
    return 0


# --------------------------------------------------------------------- main

def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="custody",
        description="A signed chain of evidence for AI decisions on loan files.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("keygen", help="generate a local signing key")
    p.add_argument("--out", default=DEFAULT_KEY)
    p.add_argument("--force", action="store_true")
    p.add_argument("--algorithm", default=ED25519, choices=[ED25519, ECDSA_P256],
                   help="ecdsa-p256-sha256 matches what a KMS can hold")
    p.set_defaults(func=cmd_keygen)

    p = sub.add_parser("run", help="run one gated, recorded decision over your documents")
    p.add_argument("--loan", required=True)
    p.add_argument("--principal", required=True, help="the authenticated user this runs as")
    p.add_argument("--purpose", required=True,
                   help="the use case, matching a key in your policy's use_cases")
    p.add_argument("--instruction", required=True, help="what to ask the model")
    p.add_argument("--doc", action="append", required=True, metavar="PATH",
                   help="a source document; repeat for several")
    p.add_argument("--provider", default="anthropic",
                   choices=["anthropic", "azure-openai"])
    p.add_argument("--model", default="claude-sonnet-5")
    p.add_argument("--deployment", default=None,
                   help="azure-openai: the deployment name (Azure routes on this, "
                        "not on a model name)")
    p.add_argument("--azure-endpoint", default=None,
                   help="defaults to AZURE_OPENAI_ENDPOINT")
    p.add_argument("--api-version", default="2024-10-21")
    p.add_argument("--replay", metavar="JSON",
                   help="use a fixed response instead of calling a model")
    p.add_argument("--redact", action="append", metavar="NAME",
                   help="a literal string to scrub, e.g. the borrower's name; repeat")
    p.add_argument("--data", action="append", metavar="CLASS",
                   help="a data class this decision touches, e.g. income; repeat. "
                        "Required when the policy sets data rules for the use case")
    p.add_argument("--policy", default="default-v1",
                   help="a path to a policy .json, which is enforced, or a bare "
                        "version string, which is only recorded")
    p.add_argument("--floor", type=float, default=None,
                   help="override the policy's confidence floor for this run")
    p.add_argument("--queue", default="review")
    p.add_argument("--db", default=DEFAULT_DB,
                   help="a SQLite path, or a postgresql:// DSN")
    p.add_argument("--key", default=None)
    p.set_defaults(func=cmd_run)

    p = sub.add_parser("verify", help="recompute a chain and report the first break")
    p.add_argument("ledger", nargs="?", default=DEFAULT_DB, help="a .db or an exported .json")
    p.add_argument("--expect-anchor", default=None,
                   help="an anchor recorded earlier, elsewhere; detects truncation")
    p.add_argument("--public-key", default=None, help="hex; omit to check continuity only")
    p.set_defaults(func=cmd_verify)

    p = sub.add_parser("anchor", help="print the anchor to record outside this system")
    p.add_argument("ledger", nargs="?", default=DEFAULT_DB, help="a .db or an exported .json")
    p.set_defaults(func=cmd_anchor)

    p = sub.add_parser("packet", help="export the chain of evidence for one loan")
    p.add_argument("loan")
    p.add_argument("--db", default=DEFAULT_DB,
                   help="a SQLite path, or a postgresql:// DSN")
    p.add_argument("--key", default=None)
    p.add_argument("--out", default=None, help="write to a file instead of stdout")
    p.add_argument("--policy", default="-",
                   help="the policy file these decisions ran under; adds its "
                        "review state to the packet")
    p.add_argument("--public-key", default=None,
                   help="hex; checks signatures without the private key")
    p.add_argument("--requested-by", default="examiner")
    p.set_defaults(func=cmd_packet)

    p = sub.add_parser(
        "gateway",
        help="serve POST /decision so a non-Python caller cannot skip the record",
    )
    p.add_argument("--policy", default="default-v1",
                   help="a path to a policy .json; without one nothing is enforced")
    p.add_argument("--provider", default="anthropic",
                   choices=["anthropic", "azure-openai"])
    p.add_argument("--model", default="claude-sonnet-5")
    p.add_argument("--deployment", default=None)
    p.add_argument("--azure-endpoint", default=None)
    p.add_argument("--api-version", default="2024-10-21")
    p.add_argument("--replay", metavar="JSON",
                   help="answer every request from a fixture instead of a model")
    p.add_argument("--db", default=DEFAULT_DB,
                   help="a SQLite path, or a postgresql:// DSN")
    p.add_argument("--key", default=None)
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=8788)
    p.add_argument("--token", default=None)
    p.add_argument("--no-token", action="store_true")
    p.set_defaults(func=cmd_gateway)

    p = sub.add_parser(
        "disclose",
        help="the whole-book answer to LL-2026-04's disclosure clause",
    )
    p.add_argument("--db", default=DEFAULT_DB,
                   help="a SQLite path, or a postgresql:// DSN")
    p.add_argument("--key", default=None)
    p.add_argument("--policy", default="-",
                   help="the policy in force; adds its review state to the report")
    p.add_argument("--public-key", default=None,
                   help="hex; checks signatures without the private key")
    p.add_argument("--requested-by", default="Fannie Mae")
    p.add_argument("--json", action="store_true", help="machine-readable instead of text")
    p.add_argument("--out", default=None, help="also write the JSON to a file")
    p.set_defaults(func=cmd_disclose)

    p = sub.add_parser("replicate", help="copy records to JSON Lines for a warehouse")
    p.add_argument("--db", default=DEFAULT_DB,
                   help="a SQLite path, or a postgresql:// DSN")
    p.add_argument("--key", default=None)
    p.add_argument("--out", default="custody-records.jsonl")
    p.add_argument("--since", default=None, metavar="RECORD_ID",
                   help="the checkpoint printed by the last run")
    p.set_defaults(func=cmd_replicate)

    p = sub.add_parser("policy", help="validate a policy, or write one to start from")
    p.add_argument("file", nargs="?", default=None)
    p.add_argument("--new", metavar="PATH", default=None,
                   help="write a starter policy to edit, instead of validating one")
    p.add_argument("--force", action="store_true", help="overwrite with --new")
    p.set_defaults(func=cmd_policy)

    p = sub.add_parser("serve", help="browse and verify a ledger in your browser")
    p.add_argument("--db", default=DEFAULT_DB,
                   help="a SQLite path, or a postgresql:// DSN")
    p.add_argument("--key", default=None)
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=8787)
    p.add_argument("--token", default=None,
                   help="shared secret; one is generated for you on loopback")
    p.add_argument("--no-token", action="store_true",
                   help="serve with no authentication at all -- have a reason")
    p.set_defaults(func=cmd_serve)

    p = sub.add_parser("demo", help="run the synthetic loan pipeline")
    p.add_argument("--out", default="ledger.json")
    p.set_defaults(func=cmd_demo)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
