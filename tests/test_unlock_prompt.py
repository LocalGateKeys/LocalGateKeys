"""Unlock prompt layout and actions, driven through fake widgets (no Tk window is created)."""
from __future__ import annotations

from localvault.app.unlock_backoff import locked_subtitle, profile_chips


def test_locked_subtitle():
    assert locked_subtitle(None) == "Your vault is locked"
    assert locked_subtitle(1000.0, now=1010.0) == "Locked just now"
    assert locked_subtitle(1000.0, now=1000.0 + 12 * 60) == "Locked 12 minutes ago"
    assert locked_subtitle(2000.0, now=1000.0) == "Locked just now"

def test_profile_chips_mark_the_active_profile_and_clean_names():
    chips = profile_chips([("p1", "Personal"), ("p2", "  work\x07 account that is far too long for a chip"),
                           ("p3", "")], "p2")
    assert [c.active for c in chips] == [False, True, False]
    assert chips[0].initial == "P"
    assert chips[1].name == "work account that is far…"
    assert "\x07" not in chips[1].name
    assert chips[2].name == "Profile"

