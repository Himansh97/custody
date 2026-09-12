"""A bad `--replay` path is a typo, and should read like one.

Every way a replay fixture can be wrong is a user error: a person typed the
path. Letting json.loads or read_text raise put a Python traceback in front of
someone whose problem was a missing file, and buried the one line that said so.

These call the loader directly rather than shelling out, because the point is
the message, not the process exit.
"""
from __future__ import annotations

import pathlib
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from custody.cli import _replay_fixture  # noqa: E402


def _fails(path) -> str:
    """Run the loader, insist it exits cleanly, and hand back what it said."""
    try:
        _replay_fixture(str(path))
    except SystemExit as exc:
        message = str(exc)
        assert "Traceback" not in message, message
        return message
    raise AssertionError(f"{path} should not have loaded")


def _written(name: str, text: str) -> pathlib.Path:
    path = pathlib.Path(tempfile.mkdtemp()) / name
    path.write_text(text)
    return path


def test_a_missing_fixture_names_the_path() -> None:
    missing = pathlib.Path(tempfile.mkdtemp()) / "nope.json"
    message = _fails(missing)
    assert "no such replay fixture" in message, message
    assert "nope.json" in message, message


def test_malformed_json_says_where() -> None:
    message = _fails(_written("bad.json", '{"fields": {"a": 1,}'))
    assert "not valid JSON" in message, message
    # The position is the useful part: "invalid JSON" alone makes you re-read
    # the whole file.
    assert "line 1" in message and "column" in message, message


def test_json_that_is_not_an_object_says_what_it_got() -> None:
    message = _fails(_written("list.json", "[1, 2, 3]"))
    assert "should be a JSON object" in message, message
    assert "got list" in message, message


def test_a_directory_is_not_a_fixture() -> None:
    message = _fails(pathlib.Path(tempfile.mkdtemp()))
    assert "is a directory" in message, message


def test_a_good_fixture_still_loads() -> None:
    good = _written("good.json", '{"fields": {"income": 7420.0}, "confidence": 0.91}')
    fixture = _replay_fixture(str(good))
    assert fixture["fields"]["income"] == 7420.0
    assert fixture["confidence"] == 0.91


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
