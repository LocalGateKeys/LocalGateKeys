"""Presentation helpers shared by every UI: status texts, avatar colours, safe typed fields.

No UI toolkit here; the Tk modules re-export these names until stage 8.
"""
from __future__ import annotations

from typing import Any

from ..item_schema import PROTECTED_FIELDS_BY_KIND


ENCRYPTED_TEXT = "Local · Encrypted"


SHORTCUT_HINT = "Ctrl K search · Ctrl N new · Ctrl L lock · F1 all shortcuts"


def auto_lock_text(remaining: int | None, *, unlocked: bool) -> str:
    """``Auto-lock in M:SS`` while unlocked, ``Locked`` otherwise."""

    if not unlocked:
        return "Locked"
    if remaining is None:
        return "Auto-lock off"
    remaining = max(0, int(remaining))
    return f"Auto-lock in {remaining // 60}:{remaining % 60:02d}"


def licence_warning_text(st: Any) -> str:
    """Short status-bar warning, only for licence states that need attention."""

    return {
        "expired_for_this_build": "Licence does not cover this version",
        "revoked": "Licence revoked",
        "invalid": "Licence problem",
    }.get(getattr(st, "state", ""), "")


def sync_status_text(view: Any, *, now: float) -> str:
    """``Synced N min ago`` / a warning for the background sync status; empty when sync is off.

    *view* is a ``sync.service.SyncStatusView`` (or None before the first run).
    """

    if view is None or not getattr(view, "configured", False):
        return ""
    if getattr(view, "needs_attention", False):
        return "Sync needs attention"
    last = getattr(view, "last_sync", None)
    if last is None:
        return "Not synced yet"
    age = max(0, int(now) - int(last))
    if age < 60:
        return "Synced just now"
    if age < 3600:
        return f"Synced {age // 60} min ago"
    if age < 86400:
        return f"Synced {age // 3600} h ago"
    return f"Synced {age // 86400} d ago"


# Payload keys that are bookkeeping rather than user-facing values.
_SKIPPED_TYPED_KEYS = frozenset({"template_id", "last4", "brand"})


def _field_label(key: str) -> str:
    return key.replace("_", " ").strip().capitalize()


def safe_typed_fields(kind: str, payload: Any) -> list[tuple[str, str]]:
    """Display rows for a typed item's redacted payload, never protected keys.

    The service already redacts protected values; this filter is a second,
    schema-driven barrier so a leaky projection still cannot reach a widget.
    Identity items treat every field as protected.
    """
    if not isinstance(payload, dict) or kind == "identity":
        return []
    protected = set(PROTECTED_FIELDS_BY_KIND.get(kind, ()))
    rows: list[tuple[str, str]] = []
    if kind == "card":
        brand = str(payload.get("brand", "") or "").strip()
        last4 = str(payload.get("last4", "") or "").strip()
        if last4.isdigit() and len(last4) == 4:
            rows.append(("Card", f"{(brand or 'Card').capitalize()} ending {last4}"))
        elif brand:
            rows.append(("Card", brand.capitalize()))
    for key in sorted(payload):
        if key in protected or key in _SKIPPED_TYPED_KEYS:
            continue
        if key.endswith("_present") or key.endswith("_id") or key.endswith("_ids"):
            continue
        value = payload[key]
        if isinstance(value, bool) or not isinstance(value, (str, int, float)):
            continue
        text = str(value).strip()
        if text:
            rows.append((_field_label(key), text))
    return rows
