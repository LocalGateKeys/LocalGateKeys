"""Item labels, list search and filters, and browser-submission classification.

Pure presentation logic shared by every UI (Tk today, WebView next). It must
never import tkinter, ``agent``, ``shell`` or any ``*_ui`` module.
"""
from __future__ import annotations

import difflib
import hmac
import re
import unicodedata
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal

from ..i18n import catalog, t
from ..item_schema import ITEM_KINDS

# Stable presentation vocabulary for the desktop shell.  The strings are kept
# in one place because the shell, empty states, and keyboard paths all need to
# describe the same destinations.
SHELL_LABELS = {
    "all": "All items",
    "favorites": "Favorites",
    "web": "Browser",
    "desktop": "Desktop",
    "security": "Security check",
    "connections": "Devices & connections",
    "collections": "Collections",
    "reminders": "Reminders",
    "recovery": "Backups & recovery",
    "transfer": "Import & transfer",
    "generator": "Password generator",
    "search": "Search this profile",
    "help": "Help & setup",
}


def kind_label(kind: str) -> str:
    """Human label for any catalog kind, including kinds added to the schema later."""

    kind = str(kind or "")
    if f"kind.{kind}" in catalog():
        return t(f"kind.{kind}")
    return kind.replace("_", " ").strip().capitalize() or t("kind.unknown")


# Discovered from the schema at import time so a new item kind shows up in the
# list and the type filter without touching the shell.
DISPLAY_KIND_LABELS = {kind: str(catalog("en").get(f"kind.{kind}") or kind) for kind in sorted(ITEM_KINDS)}  # English: only fixes KIND_ORDER
# Credentials first, then typed kinds alphabetically by label.
KIND_ORDER = ("web", "desktop") + tuple(
    kind for kind, _label in sorted(DISPLAY_KIND_LABELS.items(), key=lambda pair: pair[1].casefold())
    if kind not in {"web", "desktop"}
)


# ------------------------------------------------------------------ search
# ``prefix:value`` tokens restrict one search field; everything else must
# match somewhere in the safe metadata.  Notes and typed payloads are never
# searched: ``search_fields`` only receives the list projection.
SEARCH_PREFIXES = {"tag": "tags", "url": "url", "type": "kind", "user": "username"}
SEARCH_RANK_EXACT, SEARCH_RANK_PREFIX, SEARCH_RANK_CONTAINS, SEARCH_RANK_FUZZY = 0, 1, 2, 3
_FUZZY_CUTOFF = 0.72
_FUZZY_MIN_LENGTH = 3


def parse_search_query(query: str) -> list[tuple[str | None, str]]:
    """Split a query into ``(field, token)`` pairs; unknown prefixes stay literal."""

    tokens: list[tuple[str | None, str]] = []
    for raw in str(query or "").split():
        token = raw.casefold()
        prefix, separator, value = token.partition(":")
        if separator and prefix in SEARCH_PREFIXES:
            if value:
                tokens.append((SEARCH_PREFIXES[prefix], value))
            continue
        tokens.append((None, token))
    return tokens


def search_fields(summary: Any, target: str = "") -> dict[str, str]:
    """Project one list row into the casefolded fields the search may read."""

    kind = str(getattr(summary, "kind", "") or "")
    return {
        "title": _summary_title(summary).casefold(),
        "username": str(getattr(summary, "username", "") or "").casefold(),
        "url": str(target or "").casefold(),
        "kind": f"{kind} {kind_label(kind)}".casefold(),
        "tags": " ".join(str(tag) for tag in (getattr(summary, "tags", ()) or ())).casefold(),
    }


def _words(value: str) -> list[str]:
    return [part for part in re.split(r"[^0-9a-z]+", value) if part]


def _fuzzy_hit(token: str, fields: dict[str, str]) -> bool:
    if len(token) < _FUZZY_MIN_LENGTH:
        return False
    candidates: list[str] = []
    for name in ("title", "username", "url", "tags"):
        value = fields.get(name, "")
        if value:
            candidates.append(value)
            candidates.extend(_words(value))
    return bool(difflib.get_close_matches(token, candidates, n=1, cutoff=_FUZZY_CUTOFF))


def _token_rank(fields: dict[str, str], field: str | None, token: str) -> int | None:
    if field is not None:
        return SEARCH_RANK_CONTAINS if token in fields.get(field, "") else None
    title = fields.get("title", "")
    if title == token:
        return SEARCH_RANK_EXACT
    if title.startswith(token):
        return SEARCH_RANK_PREFIX
    if any(token in value for value in fields.values()):
        return SEARCH_RANK_CONTAINS
    return SEARCH_RANK_FUZZY if _fuzzy_hit(token, fields) else None


def search_rank(fields: dict[str, str], tokens: list[tuple[str | None, str]]) -> int | None:
    """Return the row's rank (lower is better) or ``None`` when a token misses."""

    rank = SEARCH_RANK_EXACT
    for field, token in tokens:
        token_rank = _token_rank(fields, field, token)
        if token_rank is None:
            return None
        rank = max(rank, token_rank)
    return rank


def rank_search_results(rows: list[tuple[Any, dict[str, str]]], query: str) -> list[Any]:
    """Order ``(summary, fields)`` rows by match quality, then most recent first."""

    tokens = parse_search_query(query)
    ranked = []
    for index, (summary, fields) in enumerate(rows):
        rank = search_rank(fields, tokens)
        if rank is None:
            continue
        ranked.append((rank, -int(getattr(summary, "updated_at", 0) or 0), index, summary))
    ranked.sort(key=lambda row: row[:3])
    return [row[3] for row in ranked]


# ------------------------------------------------------------- list sort
#: The vault list sort options (tests/vectors/vault_sort; rule in scripts/make_sort_vectors.py).
SORT_OPTIONS = ("title_asc", "title_desc", "modified_desc", "created_desc")
SORT_LABELS = {"title_asc": "Title A–Z", "title_desc": "Title Z–A",
               "modified_desc": "Date modified", "created_desc": "Date created"}  # English ids; see sort_label()


def sort_label(option: str) -> str:
    """The shown name of a list sort option, in the active language."""
    return t(f"sort.{option}")
DEFAULT_SORT = "title_asc"


def sort_title_key(title: str) -> str:
    """NFKD, combining marks dropped, then lowercased; compared by code points."""
    text = unicodedata.normalize("NFKD", title or "")
    return "".join(c for c in text if unicodedata.category(c) != "Mn").lower()


def _stamp(value: Any) -> int:
    return value if isinstance(value, int) and not isinstance(value, bool) else 0


def sort_items(items: list[Any], option: str, favorites_first: bool, *,
               title: Any = None) -> list[Any]:
    """Order the plain (no search) vault list by the shared sort rule.

    ``title(item)`` gives the display title (default: ``item.title``). Ties go by
    title key, then id, for every option; favorites first keeps each group's order.
    """
    option = option if option in SORT_OPTIONS else DEFAULT_SORT
    get_title = title or (lambda it: str(getattr(it, "title", "") or ""))

    def base(it: Any):
        key = sort_title_key(get_title(it))
        ident = str(getattr(it, "id", ""))
        if option == "title_asc":
            return (key, ident)
        if option == "title_desc":
            return ([-ord(c) for c in key] + [1], ident)
        field = "updated_at" if option == "modified_desc" else "created_at"
        return (-_stamp(getattr(it, field, 0)), key, ident)

    ranked = sorted(items, key=base)
    if favorites_first:
        ranked = ([i for i in ranked if getattr(i, "favorite", False)]
                  + [i for i in ranked if not getattr(i, "favorite", False)])
    return ranked


# ------------------------------------------------------------- list filters
@dataclass(frozen=True)
class FilterOption:
    """One entry of the type-filter dropdown.

    ``kind`` is the filter token understood by :func:`matches_filter`:
    ``None`` (everything), ``"favorite"``, an item kind, ``"collection:<id>"``
    or ``"view:<id>"`` (a pinned smart view).  ``key`` is the page-context key.
    """

    label: str
    kind: str | None
    key: str


_FILTER_LABELS_STATIC = {None: "All types", "favorite": SHELL_LABELS["favorites"],
                         "web": SHELL_LABELS["web"], "desktop": SHELL_LABELS["desktop"]}  # English ids
_FILTER_KEYS = {None: "filter.allTypes", "favorite": "filter.favorites", "web": "filter.web", "desktop": "filter.desktop"}


def filter_kind_label(kind: str | None) -> str:
    if kind in _FILTER_KEYS:
        return t(_FILTER_KEYS[kind])
    return kind_label(str(kind))


def filter_options(summaries: list[Any], collections: list[dict[str, Any]],
                   views: list[dict[str, Any]]) -> list[FilterOption]:
    """Build the dropdown: every kind present, then collections, then pinned views."""

    options = [FilterOption(t("filter.allTypes"), None, "all"), FilterOption(t("filter.favorites"), "favorite", "favorite")]
    present = {str(summary.kind) for summary in summaries}
    for kind in KIND_ORDER:
        if kind in present:
            options.append(FilterOption(filter_kind_label(kind), kind, kind))
    for kind in sorted(present - set(KIND_ORDER)):
        options.append(FilterOption(filter_kind_label(kind), kind, kind))
    for row in sorted(collections, key=lambda row: str(row.get("name", "")).casefold()):
        if row.get("id"):
            options.append(FilterOption(t("filter.collection", name=_safe_display(str(row.get('name', '')), 60)),
                                        f"collection:{row['id']}", "collection"))
    for row in views:
        if row.get("pinned") and row.get("id") and not row.get("disabled"):
            options.append(FilterOption(t("filter.view", name=_safe_display(str(row.get('name', '')), 60)),
                                        f"view:{row['id']}", "view"))
    return options


def matches_filter(summary: Any, filter_kind: str | None, view_ids: set[str], *,
                   flag_ids: dict[str, set[str]] | None = None) -> bool:
    if filter_kind is None:
        return True
    if filter_kind == "recent":
        return str(summary.id) in (flag_ids or {}).get("recent", set())
    if filter_kind in ("attention", "no2fa", "expiring"):
        return str(summary.id) in (flag_ids or {}).get(filter_kind, set())
    if filter_kind == "favorite":
        return bool(getattr(summary, "favorite", False))
    if filter_kind.startswith("collection:"):
        return filter_kind[len("collection:"):] in tuple(getattr(summary, "collection_ids", ()) or ())
    if filter_kind.startswith("view:"):
        return str(summary.id) in view_ids
    return str(summary.kind) == filter_kind


# Safe, non-secret payload fields that identify where a typed item is used.
# Protected fields (card number, keys, passwords) are never read here.
_TARGET_FIELDS = {
    "passkey": ("relying_party_id",),
    "api_key": ("service",),
    "wifi": ("ssid",),
    "bank_account": ("bank",),
    "license": ("vendor", "product"),
    "purchase": ("vendor", "product"),
    "warranty": ("vendor", "product"),
    "subscription": ("vendor", "provider", "product"),
    "ssh_key": ("fingerprint",),
}


def row_target(summary: Any, item: dict[str, Any] | None = None, *, bookmark_host: str = "") -> str:
    """The WEBSITE / APPLICATION column for one list row."""

    kind = str(getattr(summary, "kind", ""))
    scope = getattr(summary, "scope", None) or {}
    if kind == "web":
        return _safe_display(str(scope.get("origin", "")))
    if kind == "desktop":
        return _safe_display(Path(str(scope.get("exe_path", ""))).name)
    if kind == "bookmark":
        return _safe_display(bookmark_host)
    payload = (item or {}).get("payload") if isinstance(item, dict) else None
    if not isinstance(payload, dict):
        return ""
    if kind == "card":
        return _safe_display(str(payload.get("brand", "")).capitalize())
    parts = [str(payload.get(field, "")).strip() for field in _TARGET_FIELDS.get(kind, ())]
    return _safe_display(" · ".join(part for part in parts if part))


@dataclass(frozen=True)
class CatalogItemRef:
    """Discriminated reference used by the mixed All items presentation.

    ``id`` is deliberately not sufficient for dispatch: credentials and typed
    items are owned by different services even though both are displayed in
    one list.
    """

    source: Literal["credential", "typed"]
    id: str
    kind: str


# Friendly compatibility name for callers that use the shorter presentation
# terminology.
ItemRef = CatalogItemRef


def _safe_display(value: str, max_len: int = 120) -> str:
    cleaned = "".join(ch if ch.isprintable() and ch not in "\r\n\t" else " " for ch in value)
    return cleaned[:max_len]


def _summary_title(summary: Any) -> str:
    """Read the shared display title from credential or typed summaries.

    Older browser saves used the full address as the name; show those as the
    short site name without rewriting the stored entry.
    """
    title = str(getattr(summary, "title", getattr(summary, "label", "")))
    scope = getattr(summary, "scope", None)
    if getattr(summary, "kind", None) == "web" and isinstance(scope, dict) and title == scope.get("origin"):
        from ..vault import friendly_origin_label
        return friendly_origin_label(title)
    return title


def _classify_browser_submission(
    entries: list[dict[str, Any]], username: str, password: str
) -> dict[str, str | bool | None]:
    """Classify a submitted browser login without exposing stored passwords.

    The caller supplies only entries already scoped to the exact browser origin.
    The result distinguishes an exact match, a changed password for an existing
    username, and a genuinely new account.
    """

    username_bytes = username.encode("utf-8")
    password_bytes = password.encode("utf-8")
    same_username_id: str | None = None

    for entry in entries:
        saved_username = str(entry.get("username", "")).encode("utf-8")
        if not hmac.compare_digest(saved_username, username_bytes):
            continue
        same_username_id = str(entry.get("id", "")) or None
        saved_password = str(entry.get("password", "")).encode("utf-8")
        if hmac.compare_digest(saved_password, password_bytes):
            return {
                "status": "exact",
                "match": True,
                "entry_id": same_username_id,
            }

    if same_username_id is not None:
        return {
            "status": "password_changed",
            "match": False,
            "entry_id": same_username_id,
        }

    return {"status": "new_account", "match": False, "entry_id": None}
