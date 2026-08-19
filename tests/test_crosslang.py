"""Python and JavaScript must produce byte-identical canonical form.

The demo's claim is that a visitor's own browser recomputes the hashes rather
than being shown a green tick somebody drew. That claim is only true if the two
implementations agree exactly — and if they ever drift, the browser will report
tampering on a perfectly honest ledger, which is the most damaging failure this
product could have.

Skips cleanly when node is unavailable rather than failing; the Python side is
still fully tested without it.
"""
from __future__ import annotations

import hashlib
import json
import pathlib
import shutil
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from custody.chain import canonical  # noqa: E402

LEDGER = ROOT / "demo" / "ledger.json"
CANON_JS = ROOT / "tests" / "canon_check.js"


def test_the_two_canonicalisers_agree_on_every_shipped_record() -> None:
    if shutil.which("node") is None:
        print("SKIP node not installed")
        return
    if not LEDGER.exists():
        print("SKIP demo/ledger.json not built — run demo/pipeline.py")
        return

    bundle = json.loads(LEDGER.read_text())
    mine = [canonical(r).decode() for r in bundle["records"]]

    result = subprocess.run(
        ["node", str(CANON_JS), str(LEDGER)], capture_output=True, text=True, check=True
    )
    theirs = json.loads(result.stdout)

    assert len(mine) == len(theirs)
    for i, (a, b) in enumerate(zip(mine, theirs)):
        assert a == b, (
            f"record {i} differs between Python and JavaScript\n"
            f"  py: {a[:200]}\n  js: {b[:200]}"
        )


def test_the_shipped_hashes_are_reproducible_from_the_canonical_bytes() -> None:
    """Recompute every hash the long way, exactly as the browser will."""
    if not LEDGER.exists():
        print("SKIP demo/ledger.json not built")
        return
    bundle = json.loads(LEDGER.read_text())
    for i, record in enumerate(bundle["records"]):
        digest = hashlib.sha256()
        digest.update(record["prev_hash"].encode("ascii"))
        digest.update(canonical(record))
        assert digest.hexdigest() == record["hash"], f"record {i} hash is not reproducible"


if __name__ == "__main__":
    failures = 0
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            try:
                fn()
                print(f"PASS {name}")
            except AssertionError as exc:
                failures += 1
                print(f"FAIL {name}: {exc}")
    print(f"\n{failures} failure(s)")
    raise SystemExit(1 if failures else 0)
