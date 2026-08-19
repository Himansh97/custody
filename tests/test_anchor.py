"""Truncation: the one alteration a hash chain cannot see by itself.

Found by an adversarial audit. Every other tampering leaves a mark -- an edit
breaks a hash, a removal from the middle breaks a link, a reorder breaks both.
Removing the newest records breaks nothing: what remains is a shorter chain in
which every link is genuine, and it verifies cleanly.

That is not a flaw in this implementation, it is what a hash chain is. Closing
it needs one fact the ledger cannot supply about itself -- how long it should be
-- recorded somewhere its owner cannot reach. These tests hold the mechanism to
that claim: the chain must still verify after a truncation (otherwise the threat
is imaginary), and the anchor must catch it.
"""
from __future__ import annotations

import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent / "src"))

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402

from custody.chain import (  # noqa: E402
    AnchorError,
    anchor_for,
    check_anchor,
    make_anchor,
    parse_anchor,
    verify_chain,
)
from custody.ledger import Ledger  # noqa: E402


def _ledger(n=5, **kw):
    led = Ledger(policy="p-v1", signing_key=Ed25519PrivateKey.generate(), **kw)
    for i in range(n):
        with led.decision(loan="1000254", principal="a@b.example", purpose="income") as d:
            out = d.call(model="m", prompt=f"s{i}", sources=["s"], response={"g": 1.0})
            d.gate(out, citations={"g": "s"}, confidence=0.95)
            d.commit(outcome=out)
    return led


def test_a_truncated_chain_still_verifies() -> None:
    """The premise. If this ever fails the anchor is solving nothing."""
    records = _ledger().records()
    verify_chain(records[:3])          # must NOT raise


def test_an_anchor_catches_a_truncation_the_chain_cannot() -> None:
    led = _ledger()
    anchor = led.anchor
    truncated = led.records()[:3]

    verify_chain(truncated)            # the chain is happy
    try:
        check_anchor(truncated, anchor)
    except AnchorError as exc:
        assert "2" in str(exc), f"should name how many are missing: {exc}"
    else:
        raise AssertionError("a truncated ledger matched its anchor")


def test_an_intact_ledger_matches_its_own_anchor() -> None:
    led = _ledger()
    check_anchor(led.records(), led.anchor)


def test_appending_after_the_anchor_is_not_a_mismatch() -> None:
    """Ledgers grow. An anchor is a floor, not an equality check."""
    led = _ledger(3)
    anchor = led.anchor
    with led.decision(loan="1000254", principal="a@b.example", purpose="income") as d:
        out = d.call(model="m", prompt="later", sources=["s"], response={"g": 1.0})
        d.commit(outcome=out)
    check_anchor(led.records(), anchor)


def test_rewriting_history_then_appending_is_caught() -> None:
    """The subtle attack: re-sign an altered prefix and pad the length back.

    Count alone would be satisfied. The anchor pins the hash *at that position*,
    so the prefix has to be the same prefix, not merely the same length.
    """
    led = _ledger(3)
    anchor = make_anchor(3, "ab" * 32)      # a head that was never this ledger's
    with led.decision(loan="1000254", principal="a@b.example", purpose="income") as d:
        out = d.call(model="m", prompt="pad", sources=["s"], response={"g": 1.0})
        d.commit(outcome=out)
    try:
        check_anchor(led.records(), anchor)
    except AnchorError as exc:
        assert "rewritten" in str(exc), str(exc)
    else:
        raise AssertionError("a rewritten prefix passed because the count was right")


def test_an_empty_ledger_anchors_to_genesis() -> None:
    led = Ledger(policy="p", signing_key=Ed25519PrivateKey.generate())
    assert parse_anchor(led.anchor) == (0, "0" * 64)


def test_the_anchor_sink_fires_on_every_append() -> None:
    """The sink is how the anchor reaches somewhere the ledger cannot edit. If it
    only fired sometimes, the gap would be open exactly when it mattered."""
    seen: list[str] = []
    led = _ledger(4, on_append=seen.append)
    assert len(seen) == 4, f"got {len(seen)} anchors for 4 records"
    assert seen[-1] == led.anchor
    assert [parse_anchor(a)[0] for a in seen] == [1, 2, 3, 4]


def test_a_malformed_anchor_is_rejected_rather_than_ignored() -> None:
    """Silently treating an unreadable anchor as 'fine' would be the worst
    possible failure mode for this feature."""
    for bad in ("", "nonsense", "custody-anchor:v9:1:ab", "custody-anchor:v1:x:ab"):
        try:
            parse_anchor(bad)
        except ValueError:
            pass
        else:
            raise AssertionError(f"{bad!r} parsed as a valid anchor")


def test_anchor_for_matches_the_ledger_property() -> None:
    led = _ledger(3)
    assert anchor_for(led.records()) == led.anchor


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
