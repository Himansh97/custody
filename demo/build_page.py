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

# Inside this repo by default. Writing straight into the website's checkout was
# the old behaviour and it was worse than useless: the site's own build treated
# that filename as a redirect stub and overwrote the page on every deploy, so a
# rebuilt demo silently never reached anybody. Publishing is now an argument you
# pass on purpose.
DEFAULT_OUT = ROOT / "demo" / "page.html"
SITE_OUT = pathlib.Path.home() / "careeros-portfolio" / "custody-ledger.html"


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


USAGE = """usage: build_page.py [PATH | --site]

  (no argument)   write the page to demo/page.html
  --site          write it into the website checkout, which embeds this exact
                  file rather than keeping its own copy of the demo
  PATH            write it wherever you say"""


if __name__ == "__main__":
    arg = sys.argv[1] if len(sys.argv) > 1 else None
    if arg in ("-h", "--help"):
        raise SystemExit(USAGE)
    target = SITE_OUT if arg == "--site" else (
        pathlib.Path(arg) if arg else DEFAULT_OUT)
    written = build(target)
    print(f"wrote {written} ({written.stat().st_size:,} bytes)")
    if arg == "--site":
        print("now rebuild the site so the case page picks it up:")
        print(f"  python {written.parent}/build.py")
