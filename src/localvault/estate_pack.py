"""Estate pack (sub-plan 12, Task 6): the Recovery centre entry that creates the estate note.

The note follows the ``builtin.estate`` template: one heading per field, the "Shard holders" heading pre-filled
with the emergency-access holders' nicknames (sub-plan 08) when there are any. The Recovery centre then offers to
print the emergency kit with its holder page.
"""
from __future__ import annotations

from collections.abc import Iterable
from typing import Any

from .i18n import t
from .templates import BUILTIN_TEMPLATES

TEMPLATE_ID = "builtin.estate"


def template() -> dict[str, Any]:
    return next(row for row in BUILTIN_TEMPLATES if row["id"] == TEMPLATE_ID)


def body(holders: Iterable[str] = ()) -> str:
    """The note body: each field label as a heading with room under it; holders listed by nickname only."""
    names = [str(name).strip() for name in holders if str(name).strip()]
    parts = []
    for field in template()["fields"]:
        text = f"## {field['label']}\n"
        if field["name"] == "shard_holders" and names:
            text += "".join(f"- {name}\n" for name in names)
        parts.append(text)
    return "\n".join(parts)


def create(session: Any, holders: Iterable[str] = ()) -> str:
    """Create the estate note in the unlocked vault; returns its id."""
    return session.item_service.create_note(t("estate.title"), body(holders), tags=["estate"])
