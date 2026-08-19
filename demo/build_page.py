"""Generate the demo page from the real ledger.

The page is built rather than hand-written so it cannot drift from the ledger it
claims to display. Run `pipeline.py` then this, and the page is guaranteed to be
showing the records the library actually produced.

The ledger is embedded rather than fetched: the page then works from `file://`,
from GitHub Pages, and from anywhere else without a server or a CORS story, and
a reader can see the data they are being asked to verify is really in the file.
"""
from __future__ import annotations

import json
import pathlib
import re
import sys

_SCRIPT = re.compile(r"(<script\b[^>]*>)(.*?)(</script>)", re.S | re.I)


def to_ascii(html: str) -> str:
    """Escape every non-ASCII character, correctly for where it sits.

    HTML entities are not decoded inside a `<script>` block, so escaping an
    em-dash in a JS string literal to `&#8212;` puts those seven literal
    characters on the screen. Markup gets entities; script gets `\\uXXXX`.

    The whole file is reduced to ASCII so it renders identically whatever
    charset a host serves it with — a page whose headline claim is
    verifiability should not be at the mercy of a Content-Type header.
    """

    def esc(text: str, in_script: bool) -> str:
        return "".join(
            c if ord(c) < 128
            else (f"\\u{ord(c):04x}" if in_script else f"&#{ord(c)};")
            for c in text
        )

    out, cursor = [], 0
    for match in _SCRIPT.finditer(html):
        out.append(esc(html[cursor:match.start()], False))
        out.append(match.group(1))
        out.append(esc(match.group(2), True))
        out.append(match.group(3))
        cursor = match.end()
    out.append(esc(html[cursor:], False))
    return "".join(out)

HERE = pathlib.Path(__file__).resolve().parent
TEMPLATE = HERE / "page.template.html"
LEDGER = HERE / "ledger.json"
DEFAULT_OUT = pathlib.Path.home() / "careeros-portfolio" / "custody.html"


def build(out: pathlib.Path = DEFAULT_OUT) -> pathlib.Path:
    if not LEDGER.exists():
        raise SystemExit("demo/ledger.json is missing — run demo/pipeline.py first")

    bundle = json.loads(LEDGER.read_text(encoding="utf-8"))
    if not bundle["chain"]["verified"]:
        # Publishing a page whose headline claim is "this verifies" while the
        # ledger behind it does not would be the single worst thing this project
        # could ship.
        raise SystemExit(f"refusing to build: the ledger does not verify — {bundle['chain']}")

    # `</script>` anywhere inside the JSON would close the host element early and
    # the browser would parse the rest of the ledger as markup.
    payload = json.dumps(bundle, separators=(",", ":")).replace("</", "<\\/")

    html = TEMPLATE.read_text(encoding="utf-8").replace("__LEDGER_JSON__", payload)
    html = to_ascii(html)

    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(html, encoding="utf-8")
    return out


if __name__ == "__main__":
    target = pathlib.Path(sys.argv[1]) if len(sys.argv) > 1 else DEFAULT_OUT
    written = build(target)
    print(f"wrote {written} ({written.stat().st_size:,} bytes)")
