"""Render a ledger bundle into the single-file review page.

One template, two callers: `demo/build_page.py` bakes a static page from a
committed ledger, and `custody serve` renders the same page from a live store.
Keeping them on one template means the thing a lender clicks on the website and
the thing they see after installing are the same product, which is not true of
most demos.
"""
from __future__ import annotations

import json
import pathlib
import re

TEMPLATE = pathlib.Path(__file__).with_name("page.html")

_SCRIPT = re.compile(r"(<script\b[^>]*>)(.*?)(</script>)", re.S | re.I)


def to_ascii(html: str) -> str:
    """Escape non-ASCII correctly for where it sits.

    HTML entities are not decoded inside a `<script>` block, so escaping an
    em-dash in a JS string literal to `&#8212;` puts those seven characters on
    screen. Markup gets entities; script gets `\\uXXXX`. Reducing the whole file
    to ASCII means it renders identically whatever charset a host serves it
    with — a page whose claim is verifiability should not depend on a header.
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


def build_html(bundle: dict) -> str:
    """Inject a ledger bundle into the page."""
    # `</script>` anywhere in the JSON would close the host element early and the
    # browser would parse the rest of the ledger as markup.
    payload = json.dumps(bundle, separators=(",", ":"), default=str).replace("</", "<\\/")
    return to_ascii(TEMPLATE.read_text(encoding="utf-8").replace("__LEDGER_JSON__", payload))
