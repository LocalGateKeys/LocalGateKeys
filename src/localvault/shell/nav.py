"""Pure view-model for the sidebar navigation (no Tk)."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable

from ..app.catalog import KIND_ORDER, _safe_display, kind_label

RECENT_LIMIT = 30
_FALLBACK_ICON = "nav.tools"

_PLURAL = {
    "web": "Logins",
    "desktop": "Desktop apps",
    "card": "Cards",
    "bank_account": "Bank accounts",
    "identity": "Identities",
    "note": "Secure notes",
    "document": "Documents",
    "ssh_key": "SSH keys",
    "api_key": "API keys",
    "wifi": "Wi-Fi",
    "license": "Licenses",
    "purchase": "Purchases",
    "warranty": "Warranties",
    "subscription": "Subscriptions",
    "bookmark": "Bookmarks",
    "passkey": "Passkeys",
}

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


TOOLS_ENTRIES: tuple[NavEntry, ...] = (
    NavEntry("Security center", "nav.securityRecovery", None, None, "security_health_clicked"),
    NavEntry("Reminders", "nav.reminders", None, None, "reminders_clicked"),
    NavEntry("Sync", "nav.devicesConnections", None, None, "sync_clicked"),
    NavEntry("Devices & connections", "nav.devicesConnections", None, None, "connections_clicked"),
    NavEntry("Licence", "nav.settings", None, None, "licence_clicked"),
    NavEntry("Import & export", "nav.tools", None, None, "import_export_clicked"),
    NavEntry("Activity", "nav.allItems", None, None, "activity_clicked"),
    NavEntry("Trash", "nav.trash", None, None, "trash_clicked"),
)


def recent_ids(summaries: Iterable[Any], limit: int = RECENT_LIMIT) -> set[str]:
    """IDs of the ``limit`` most recently updated items (for the "recent" token)."""

    ordered = sorted(summaries, key=lambda s: getattr(s, "updated_at", 0) or 0, reverse=True)
    return {str(s.id) for s in ordered[:limit]}


def type_label(kind: str) -> str:
    return _PLURAL.get(kind) or kind_label(kind)


def build_nav(summaries: Iterable[Any], collections: list[dict[str, Any]],
              views: list[dict[str, Any]], *, unlocked: bool) -> list[NavGroup]:
    items = list(summaries) if unlocked else []
    vault = NavGroup("Vault", (
        NavEntry("All items", "nav.allItems", None, len(items) if unlocked else None),
        NavEntry("Favorites", "nav.favorite", "favorite",
                 sum(1 for s in items if getattr(s, "favorite", False)) if unlocked else None),
        NavEntry("Recently used", "nav.allItems", "recent", None),
    ))
    groups = [vault]
    if unlocked:
        counts: dict[str, int] = {}
        for s in items:
            counts[str(s.kind)] = counts.get(str(s.kind), 0) + 1
        kinds = [k for k in KIND_ORDER if k in counts] + sorted(set(counts) - set(KIND_ORDER))
        groups.append(NavGroup("Types", tuple(
            NavEntry(type_label(k), _KIND_ICONS.get(k, _FALLBACK_ICON), k, counts[k]) for k in kinds)))
        entries = [
            NavEntry(_safe_display(str(row.get("name", "")), 60), "nav.collections", f"collection:{row['id']}")
            for row in sorted(collections, key=lambda r: str(r.get("name", "")).casefold()) if row.get("id")
        ]
        entries += [
            NavEntry(_safe_display(str(row.get("name", "")), 60), "filters.funnel", f"view:{row['id']}")
            for row in views if row.get("pinned") and row.get("id") and not row.get("disabled")
        ]
        groups.append(NavGroup("Collections & views", tuple(entries)))
    groups.append(NavGroup("Tools", TOOLS_ENTRIES))
    return groups
