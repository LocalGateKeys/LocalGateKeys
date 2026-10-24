"""Buttons that take the user to the setting a message talks about.

A result or toast that mentions a setting carries ``action`` (see :func:`open_settings`) so the page can show
"Open … settings" next to the text instead of telling the user where to click.
"""
from __future__ import annotations

from typing import Any

SECTION_LABELS = {"privacy": "Privacy", "autofill": "Autofill", "backups": "Backups", "unlocking": "Unlocking"}
CLIPBOARD_OFF = "Clipboard auto-clear is off."


def open_settings(section: str, label: str | None = None) -> dict[str, Any]:
    """A ``{label, route, params}`` action that opens one Settings section."""
    return {"label": label or f"Open {SECTION_LABELS.get(section, 'the')} settings", "route": "settings",
            "params": {"section": section}}


def clipboard_result(copied: str, clipboard: Any) -> dict[str, Any]:
    """``{"message"}`` for a copy, plus a link to the clipboard setting when auto-clear is off."""
    timeout = int(getattr(clipboard, "timeout_seconds", 0) or 0)
    if timeout:
        return {"message": f"{copied} Clipboard clears in {timeout} seconds."}
    return {"message": f"{copied} {CLIPBOARD_OFF}", "action": open_settings("privacy", "Turn on auto-clear")}
