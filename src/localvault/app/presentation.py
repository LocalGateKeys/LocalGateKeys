"""Presentation helpers shared by every UI: status texts, avatar colours, safe typed fields.

No UI toolkit here; the Tk modules re-export these names until stage 8.
"""
from __future__ import annotations

from typing import Any

from ..i18n import t
from ..item_schema import PROTECTED_FIELDS_BY_KIND


def encrypted_text() -> str:
    return t("status.encrypted")


def shortcut_hint() -> str:
    return t("status.hint")


def auto_lock_text(remaining: int | None, *, unlocked: bool) -> str:
    """``Auto-lock in M:SS`` while unlocked, ``Locked`` otherwise."""

    if not unlocked:
        return t("status.locked")
    if remaining is None:
        return t("status.autolockOff")
    remaining = max(0, int(remaining))
    return t("status.autolockIn", time=f"{remaining // 60}:{remaining % 60:02d}")


def licence_warning_text(st: Any) -> str:
    """Short status-bar warning, only for licence states that need attention."""

    return {
        "expired_for_this_build": t("status.licence.expiredBuild"),
        "revoked": t("status.licence.revoked"),
        "invalid": t("status.licence.invalid"),
    }.get(getattr(st, "state", ""), "")


def sync_status_text(view: Any, *, now: float) -> str:
    """``Synced N min ago`` / a warning for the background sync status; empty when sync is off.

    *view* is a ``sync.service.SyncStatusView`` (or None before the first run).
    """

    if view is None or not getattr(view, "configured", False):
        return ""
    if getattr(view, "needs_attention", False):
        return t("status.sync.attention")
    last = getattr(view, "last_sync", None)
    if last is None:
        return t("status.sync.never")
    age = max(0, int(now) - int(last))
    if age < 60:
        return t("status.sync.justNow")
    if age < 3600:
        return t("status.sync.minutes", count=age // 60)
    if age < 86400:
        return t("status.sync.hours", count=age // 3600)
    return t("status.sync.days", count=age // 86400)


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
            rows.append((t("presentation.card"), t("presentation.cardEnding", brand=(brand or t("presentation.card")).capitalize(), last4=last4)))
        elif brand:
            rows.append((t("presentation.card"), brand.capitalize()))
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
