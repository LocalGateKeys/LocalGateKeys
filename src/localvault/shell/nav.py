"""Pure view-model for the sidebar navigation (no Tk)."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable

from ..app.catalog import KIND_ORDER, _safe_display, kind_label
from ..i18n import t

RECENT_LIMIT = 30
_FALLBACK_ICON = "nav.tools"

_PLURAL_KINDS = frozenset({"web", "desktop", "card", "bank_account", "identity", "note", "document", "ssh_key", "api_key", "wifi", "license", "purchase", "warranty", "subscription", "bookmark", "passkey"})

# Only names that exist in docs/design/sidebar-v1/icon-manifest.json.
_KIND_ICONS = {
    "web": "row.websiteGlobe",
    "desktop": "row.desktopLogin",
    "identity": "row.identity",
    "note": "row.note",
    "document": "row.document",
}


@dataclass(frozen=True)
class NavEntry:
    label: str
    icon: str
    token: str | None
    count: int | None = None
    action: str | None = None


@dataclass(frozen=True)
class NavGroup:
    name: str
    entries: tuple[NavEntry, ...]


_TOOLS = (
    ("nav.tool.security_health", "nav.securityRecovery", "security_health_clicked"),
    ("nav.tool.reminders", "nav.reminders", "reminders_clicked"),
    ("nav.tool.sync", "nav.devicesConnections", "sync_clicked"),
    ("nav.tool.connections", "nav.devicesConnections", "connections_clicked"),
    ("nav.tool.licence", "nav.settings", "licence_clicked"),
    ("nav.tool.import_export", "nav.tools", "import_export_clicked"),
    ("nav.tool.scan_qr", "nav.tools", "scan_qr_clicked"),
    ("nav.tool.activity", "nav.allItems", "activity_clicked"),
    ("nav.tool.trash", "nav.trash", "trash_clicked"),
)


def tools_entries() -> tuple[NavEntry, ...]:
    """The Tools group, labelled in the active language."""
    return tuple(NavEntry(t(key), icon, None, None, action) for key, icon, action in _TOOLS)


def __getattr__(name: str):  # TOOLS_ENTRIES is built on access so its labels follow the language
    if name == "TOOLS_ENTRIES":
        return tools_entries()
    raise AttributeError(name)


def recent_ids(summaries: Iterable[Any], limit: int = RECENT_LIMIT) -> set[str]:
    """IDs of the ``limit`` most recently updated items (for the "recent" token)."""

    ordered = sorted(summaries, key=lambda s: getattr(s, "updated_at", 0) or 0, reverse=True)
    return {str(s.id) for s in ordered[:limit]}


def type_label(kind: str) -> str:
    return t(f"nav.type.{kind}") if kind in _PLURAL_KINDS else kind_label(kind)


def build_nav(summaries: Iterable[Any], collections: list[dict[str, Any]],
              views: list[dict[str, Any]], *, unlocked: bool) -> list[NavGroup]:
    items = list(summaries) if unlocked else []
    vault = NavGroup(t("nav.group.vault"), (
        NavEntry(t("nav.vault.all"), "nav.allItems", None, len(items) if unlocked else None),
        NavEntry(t("nav.vault.favorites"), "nav.favorite", "favorite",
                 sum(1 for s in items if getattr(s, "favorite", False)) if unlocked else None),
        NavEntry(t("nav.vault.recent"), "nav.allItems", "recent", None),
    ))
    groups = [vault]
    if unlocked:
        counts: dict[str, int] = {}
        for s in items:
            counts[str(s.kind)] = counts.get(str(s.kind), 0) + 1
        kinds = [k for k in KIND_ORDER if k in counts] + sorted(set(counts) - set(KIND_ORDER))
        groups.append(NavGroup(t("nav.group.types"), tuple(
            NavEntry(type_label(k), _KIND_ICONS.get(k, _FALLBACK_ICON), k, counts[k]) for k in kinds)))
        entries = [
            NavEntry(_safe_display(str(row.get("name", "")), 60), "nav.collections", f"collection:{row['id']}")
            for row in sorted(collections, key=lambda r: str(r.get("name", "")).casefold()) if row.get("id")
        ]
        entries += [
            NavEntry(_safe_display(str(row.get("name", "")), 60), "filters.funnel", f"view:{row['id']}")
            for row in views if row.get("pinned") and row.get("id") and not row.get("disabled")
        ]
        groups.append(NavGroup(t("nav.group.collections"), tuple(entries)))
    groups.append(NavGroup(t("nav.group.tools"), tools_entries()))
    return groups
