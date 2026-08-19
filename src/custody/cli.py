"""`custody` — run it against your own documents and your own model.

The commands are shaped around the questions a lender actually has, in the order
they have them:

    custody keygen                  where does the signing key come from
    custody run     ...             does this work on my documents
    custody verify  ...             has anything been changed
    custody packet  <loan>          what do I hand someone who asks
    custody serve                   can my team look at this
    custody demo                    show me before I install anything
"""
from __future__ import annotations

import argparse
import json
import os
import pathlib
import sys

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

    documents: list[tuple[str, str]] = []
    for spec in args.doc:
        path = pathlib.Path(spec)
        if not path.exists():
            raise SystemExit(f"no such document: {path}")
        documents.append((path.stem, path.read_text(encoding="utf-8", errors="replace")))

    if args.replay:
        fixture = json.loads(pathlib.Path(args.replay).read_text())
        extract = replay(fixture.get("fields", {}), fixture.get("confidence"),
                         fixture.get("citations"))
    elif args.provider == "azure-openai":
        extract = azure_openai_extractor(
            deployment=args.deployment or args.model,
            endpoint=args.azure_endpoint,
            api_version=args.api_version,
        )
    else:
        extract = anthropic_extractor(model=args.model)

    ledger = Ledger(policy=args.policy, signer=load_signer(args.key), path=args.db)

    with ledger.decision(loan=args.loan, principal=args.principal, purpose=args.purpose,
                         identifiers=args.redact or ()) as d:
        fields, confidence, endpoint, citations = extract(args.instruction, documents)
        # `endpoint` carries the version that actually answered. Recording the
        # flag the operator typed instead would be recording an intention.
        recorded_model = endpoint.rsplit(":", 1)[-1] if ":" in endpoint else args.model
        d.call(model=recorded_model, endpoint=endpoint, prompt=args.instruction,
               sources=[text for _, text in documents], response=fields)
        verdict = d.gate(fields, citations=citations, confidence=confidence,
                         confidence_floor=args.floor)

        print(f"model returned : {json.dumps(fields)}")
        print(f"confidence     : {confidence}")
        print(f"verdict        : {verdict.treatment}")
        for finding in verdict.findings:
            print(f"  - [{finding.check}] {finding.detail}")

        if verdict.ok:
            d.commit(outcome=fields)
            print("committed.")
        else:
            d.route_to_human(queue=args.queue)
            print(f"routed to {args.queue} — nothing was committed.")

    print(f"\nrecorded in {args.db}. `custody packet {args.loan} --db {args.db}` to export.")
    return 0


# ------------------------------------------------------------------- verify

def _load_records(source: str) -> tuple[list[dict], str | None, str]:
    """Accept either a live database or an exported bundle.

    The algorithm comes from the records themselves rather than a flag, because
    a ledger that cannot say how it was signed is not self-describing and the
    person verifying it should not have to be told.
    """
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
    return 0


# ------------------------------------------------------------------- packet

def cmd_packet(args) -> int:
    from .examiner import packet
    from .ledger import Ledger

    ledger = Ledger(policy="-", signer=load_signer(args.key), path=args.db)
    result = packet(ledger, args.loan, requested_by=args.requested_by)
    if not result["records"]:
        raise SystemExit(f"no records for loan {args.loan} in {args.db}")

    text = json.dumps(result, indent=1, default=str)
    if args.out:
        pathlib.Path(args.out).write_text(text, encoding="utf-8")
        summary = result["summary"]
        print(f"wrote {args.out}")
        print(f"  {summary['ai_decisions']} AI decisions, {summary['human_reviews']} human "
              f"reviews, {summary['rejected']} rejected")
        print(f"  chain: {'verified' if result['chain']['verified'] else result['chain']}")
    else:
        print(text)
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
    p.add_argument("--purpose", default="extraction")
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
    p.add_argument("--policy", default="default-v1")
    p.add_argument("--floor", type=float, default=0.80)
    p.add_argument("--queue", default="review")
    p.add_argument("--db", default=DEFAULT_DB)
    p.add_argument("--key", default=None)
    p.set_defaults(func=cmd_run)

    p = sub.add_parser("verify", help="recompute a chain and report the first break")
    p.add_argument("ledger", nargs="?", default=DEFAULT_DB, help="a .db or an exported .json")
    p.add_argument("--public-key", default=None, help="hex; omit to check continuity only")
    p.set_defaults(func=cmd_verify)

    p = sub.add_parser("packet", help="export the chain of evidence for one loan")
    p.add_argument("loan")
    p.add_argument("--db", default=DEFAULT_DB)
    p.add_argument("--key", default=None)
    p.add_argument("--out", default=None, help="write to a file instead of stdout")
    p.add_argument("--requested-by", default="examiner")
    p.set_defaults(func=cmd_packet)

    p = sub.add_parser("serve", help="browse and verify a ledger in your browser")
    p.add_argument("--db", default=DEFAULT_DB)
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
