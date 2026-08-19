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

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

DEFAULT_DB = "custody.db"
DEFAULT_KEY = "custody-signing.key"


# --------------------------------------------------------------------- keys

def load_key(path: str | None) -> Ed25519PrivateKey:
    """Read the signing key from a file or `CUSTODY_SIGNING_KEY`.

    Refuses to invent one. A ledger signed by a key generated on the fly is
    signed by nothing in particular — every run would produce a different
    identity, and a signature nobody can tie to a system is decoration.
    """
    material = os.environ.get("CUSTODY_SIGNING_KEY")
    if material:
        return Ed25519PrivateKey.from_private_bytes(bytes.fromhex(material.strip()))

    target = pathlib.Path(path or DEFAULT_KEY)
    if not target.exists():
        raise SystemExit(
            f"no signing key at {target}. Run `custody keygen` first, "
            "or set CUSTODY_SIGNING_KEY."
        )
    return Ed25519PrivateKey.from_private_bytes(bytes.fromhex(target.read_text().strip()))


def cmd_keygen(args) -> int:
    target = pathlib.Path(args.out)
    if target.exists() and not args.force:
        raise SystemExit(
            f"{target} already exists. Overwriting it would orphan every record "
            "signed with the old key — pass --force if that is genuinely what you want."
        )
    key = Ed25519PrivateKey.generate()
    target.write_text(key.private_bytes_raw().hex() + "\n", encoding="utf-8")
    target.chmod(0o600)
    print(f"private key  {target} (mode 600)")
    print(f"public key   {key.public_key().public_bytes_raw().hex()}")
    print()
    print("Give the public key to whoever needs to verify your ledgers. In production")
    print("the private key belongs in a KMS or HSM, not in a file next to the database.")
    return 0


# ---------------------------------------------------------------------- run

def cmd_run(args) -> int:
    """One real decision, against real documents, recorded end to end."""
    from .adapters import anthropic_extractor, replay
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
    else:
        extract = anthropic_extractor(model=args.model)

    ledger = Ledger(policy=args.policy, signing_key=load_key(args.key), path=args.db)

    with ledger.decision(loan=args.loan, principal=args.principal, purpose=args.purpose,
                         identifiers=args.redact or ()) as d:
        fields, confidence, endpoint, citations = extract(args.instruction, documents)
        d.call(model=args.model, endpoint=endpoint, prompt=args.instruction,
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

def _load_records(source: str) -> tuple[list[dict], str | None]:
    """Accept either a live database or an exported bundle."""
    path = pathlib.Path(source)
    if not path.exists():
        raise SystemExit(f"no such ledger: {path}")
    if path.suffix == ".json":
        bundle = json.loads(path.read_text(encoding="utf-8"))
        return bundle["records"], bundle.get("public_key")
    from .store import Store
    return Store(str(path)).all(), None


def cmd_verify(args) -> int:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    from .chain import ChainError, verify_chain

    records, embedded = _load_records(args.ledger)
    pub_hex = args.public_key or embedded
    public = Ed25519PublicKey.from_public_bytes(bytes.fromhex(pub_hex)) if pub_hex else None

    try:
        verify_chain(records, public)
    except ChainError as exc:
        print(f"BROKEN at record {exc.index} ({exc.record_id})")
        print(f"  {exc.reason}")
        print(f"\n{len(records)} records read; everything from {exc.index} onward is unreliable.")
        return 1

    how = "hash chain and signatures" if public else "hash chain only (no public key given)"
    print(f"OK  {len(records)} records verified — {how}")
    return 0


# ------------------------------------------------------------------- packet

def cmd_packet(args) -> int:
    from .examiner import packet
    from .ledger import Ledger

    ledger = Ledger(policy="-", signing_key=load_key(args.key), path=args.db)
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
    serve(db=args.db, key_path=args.key, host=args.host, port=args.port)
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

    p = sub.add_parser("keygen", help="generate an Ed25519 signing key")
    p.add_argument("--out", default=DEFAULT_KEY)
    p.add_argument("--force", action="store_true")
    p.set_defaults(func=cmd_keygen)

    p = sub.add_parser("run", help="run one gated, recorded decision over your documents")
    p.add_argument("--loan", required=True)
    p.add_argument("--principal", required=True, help="the authenticated user this runs as")
    p.add_argument("--purpose", default="extraction")
    p.add_argument("--instruction", required=True, help="what to ask the model")
    p.add_argument("--doc", action="append", required=True, metavar="PATH",
                   help="a source document; repeat for several")
    p.add_argument("--model", default="claude-sonnet-5")
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
    p.set_defaults(func=cmd_serve)

    p = sub.add_parser("demo", help="run the synthetic loan pipeline")
    p.add_argument("--out", default="ledger.json")
    p.set_defaults(func=cmd_demo)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
