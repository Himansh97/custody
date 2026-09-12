"""The version is written in two files and released from a third thing.

`pyproject.toml` decides what PyPI serves. `__version__` decides what a running
process reports about itself. They are edited by hand, at a moment when the
interesting work is already finished, and nothing has ever compared them. A
ledger that misreports which version wrote it is a small lie in a project whose
whole claim is that its records can be checked.
"""
from __future__ import annotations

import pathlib
import re
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent / "src"))

import custody  # noqa: E402

ROOT = pathlib.Path(__file__).resolve().parent.parent


def test_the_package_version_matches_pyproject() -> None:
    text = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    declared = re.search(r'^version\s*=\s*"([^"]+)"', text, re.M)
    assert declared, "pyproject.toml declares no version"
    assert custody.__version__ == declared.group(1), (
        f"__init__ says {custody.__version__}, pyproject says {declared.group(1)}"
    )


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
