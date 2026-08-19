"""Bake the static demo page from the committed ledger.

Built rather than hand-written so it cannot drift from the ledger it claims to
display: run `pipeline.py`, then this, and the page is showing the records the
library actually produced.
"""
from __future__ import annotations

import json
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from custody.render import build_html  # noqa: E402

LEDGER = ROOT / "demo" / "ledger.json"
DEFAULT_OUT = pathlib.Path.home() / "careeros-portfolio" / "custody-ledger.html"


def build(out: pathlib.Path = DEFAULT_OUT) -> pathlib.Path:
    if not LEDGER.exists():
        raise SystemExit("demo/ledger.json is missing - run demo/pipeline.py first")
    bundle = json.loads(LEDGER.read_text(encoding="utf-8"))
    if not bundle["chain"]["verified"]:
        # Publishing a page whose headline claim is "this verifies" while the
        # ledger behind it does not would be the worst thing this could ship.
        raise SystemExit(f"refusing to build: the ledger does not verify - {bundle['chain']}")
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(build_html(bundle), encoding="utf-8")
    return out


if __name__ == "__main__":
    target = pathlib.Path(sys.argv[1]) if len(sys.argv) > 1 else DEFAULT_OUT
    written = build(target)
    print(f"wrote {written} ({written.stat().st_size:,} bytes)")
