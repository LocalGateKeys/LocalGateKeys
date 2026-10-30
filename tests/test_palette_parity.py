"""UX plan workstream 5: the Windows and Mac palettes list the same commands.

Ids differ in a few places for historic reasons (British spelling on the Mac); ``MAC_IDS`` maps them.
``MAC_PENDING`` is the plan's new commands the Mac does not have yet: when one lands there, this test
fails until it is removed from the list, so the two lists cannot drift apart silently.
"""
from __future__ import annotations

import re
from pathlib import Path

from localvault.shell.commands import COMMANDS

ROOT = Path(__file__).resolve().parents[1]
SWIFT = ROOT / "ios" / "Mac" / "Palette" / "PaletteModel.swift"

# Windows id -> Mac id where they differ.
MAC_IDS = {"security-center": "security-centre", "devices-sync": "devices", "sync-settings": "sync"}
# Commands every desktop palette must offer.
SHARED = {"generate-password", "new-item", "scan-qr", "lock-now", "change-master", "security-center", "reminders",
          "trash", "activity", "devices-sync", "sync-settings", "import", "export", "settings", "shortcuts"}
# New in the UX plan (Security check, Trash, Share item, Sync status, Show setup).
PLAN_COMMANDS = {"security-check", "trash", "sync-status", "show-setup"}
MAC_PENDING: set[str] = set()


def _mac_ids() -> set[str]:
    return set(re.findall(r'PaletteCommand\(id: "([a-z0-9-]+)"', SWIFT.read_text(encoding="utf-8")))


def test_windows_has_the_shared_and_plan_commands():
    ids = {c.id for c in COMMANDS}
    assert SHARED <= ids
    assert PLAN_COMMANDS <= ids


def test_mac_has_the_shared_commands():
    assert {MAC_IDS.get(i, i) for i in SHARED} <= _mac_ids()


def test_mac_pending_list_is_current():
    mac = _mac_ids()
    have = {i for i in PLAN_COMMANDS if MAC_IDS.get(i, i) in mac}
    assert PLAN_COMMANDS - have == MAC_PENDING
