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

import pytest

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from custody.cli import _replay_fixture  # noqa: E402


def _fails(path) -> str:
    with pytest.raises(SystemExit) as caught:
        _replay_fixture(str(path))
    message = str(caught.value)
    assert "Traceback" not in message
    return message


def test_a_missing_fixture_names_the_path(tmp_path) -> None:
    missing = tmp_path / "nope.json"
    assert "no such replay fixture" in _fails(missing)
    assert "nope.json" in _fails(missing)


def test_malformed_json_says_where(tmp_path) -> None:
    bad = tmp_path / "bad.json"
    bad.write_text('{"fields": {"a": 1,}')
    message = _fails(bad)
    assert "not valid JSON" in message
    # The position is the useful part: "invalid JSON" alone makes you re-read
    # the whole file.
    assert "line 1" in message and "column" in message


def test_json_that_is_not_an_object_says_what_it_got(tmp_path) -> None:
    listy = tmp_path / "list.json"
    listy.write_text("[1, 2, 3]")
    message = _fails(listy)
    assert "should be a JSON object" in message
    assert "got list" in message


def test_a_directory_is_not_a_fixture(tmp_path) -> None:
    assert "is a directory" in _fails(tmp_path)


def test_a_good_fixture_still_loads(tmp_path) -> None:
    good = tmp_path / "good.json"
    good.write_text('{"fields": {"income": 7420.0}, "confidence": 0.91}')
    fixture = _replay_fixture(str(good))
    assert fixture["fields"]["income"] == 7420.0
    assert fixture["confidence"] == 0.91
