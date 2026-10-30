"""Home screen data for the WebView UI: list, sidebar, chips, overview cards and status line.

Mirrors ``AgentApp.refresh_entries`` / ``_refresh_overview`` and the status bar.
Read-only: it
never returns a password, a protected payload value or a 2FA secret (only the
current code, as the detail pane shows it).
"""
from __future__ import annotations

import base64
import time
from datetime import date
from typing import Any

from ..access_policy import normalized_policy
from ..api.result import ApiError
from ..origin import host_of
from ..i18n import t
from ..password_tools import vault_health
from ..shell.nav import build_nav, recent_ids
from ..shell.overview_model import backup_status, health_overview, upcoming_lines
from .catalog import (
    _FILTER_LABELS_STATIC,
    _safe_display,
    _summary_title,
    filter_kind_label,
    filter_options,
    kind_label,
    matches_filter,
    DEFAULT_SORT,
    SORT_OPTIONS,
    sort_label,
    rank_search_results,
    row_target,
    search_fields,
    sort_items,
)
from .presentation import auto_lock_text, encrypted_text, shortcut_hint
from .secrets import live_code

SETTINGS_ENTRY = {"label": "home.settings", "action": "settings_clicked"}  # label: catalog key
STALE_BACKUP_SECONDS = 7 * 86400
CHIPS = ("attention", "no2fa", "expiring")

# Catalog keys; the page context and empty states are translated when the list is built.
_CONTEXT_KEYS = {key: f"home.context.{key}" for key in
                 ("all", "favorite", "recent", "web", "desktop", "collection", "view")}
# ``id`` is what the page acts on; the shown action text is translated.
_EMPTY_LOCKED = {"key": "home.empty.locked", "id": "unlock"}
_EMPTY_FILTERED = {"key": "home.empty.filtered", "id": "clear_filters"}
_EMPTY_NONE = {"key": "home.empty.none", "id": "new_item"}


def _empty(spec: dict[str, str]) -> dict[str, str]:
    return {"title": t(spec["key"] + ".title"), "text": t(spec["key"] + ".text"),
            "action": t(spec["key"] + ".action"), "action_id": spec["id"]}


_FLAG_ORDER = ("breached", "weak", "reused")


def _filter_key(token: str | None) -> str:
    if token is None:
        return "all"
    if token.startswith("collection:"):
        return "collection"
    if token.startswith("view:"):
        return "view"
    return token


class HomeService:
    def __init__(self, controller: Any, icons: Any = None) -> None:
        self._controller = controller
        self.icons = icons  # app.icons.IconProvider in the app: desktop app icons and (online) website icons
        self._icon_urls: dict[bytes, str] = {}
        self._health_signature: Any = None
        self._health: Any = None
        self._health_flags: dict[str, frozenset[str]] = {}
        self.breached_ids: set[str] = set()  # filled by the security center (stage 4)

    # ----------------------------------------------------------- quick access
    QUICK_KINDS = {"credentials": {"web", "desktop"}, "note": {"note"}, "bookmark": {"bookmark"},
                   "safe": {"license", "purchase", "warranty", "subscription"}, "document": {"document"},
                   "identity": {"identity"}}

    def quick_search(self, query: str, kind: str) -> dict[str, Any]:
        """Metadata search for Quick access (classic window): favourites first, then title."""
        if kind and kind not in self.QUICK_KINDS:
            raise ValueError(t("home.error.unknownType"))
        profile = self._controller.profiles.active_profile().name
        session = self._session()
        if session is None:
            return {"rows": [], "profile": profile}
        found = session.item_service.search_metadata(query, kinds=self.QUICK_KINDS.get(kind) if kind else None)
        rows = []
        for summary in sorted(found, key=lambda s: (not s.favorite, s.title.casefold())):
            item_kind = str(summary.kind)
            rows.append({"ref": {"source": "credential" if item_kind in ("web", "desktop") else "typed",
                                 "id": str(summary.id), "kind": item_kind},
                         "title": ("★ " if summary.favorite else "") + _safe_display(_summary_title(summary)),
                         "subtitle": _safe_display(str(getattr(summary, "username", "") or "")) or kind_label(item_kind)})
        return {"rows": rows, "profile": profile}

    # --------------------------------------------------------------- session
    def _session(self) -> Any:
        controller = self._controller
        return controller.session if controller.is_unlocked() else None

    def _summaries(self, session: Any) -> list[Any]:
        try:
            return list(session.item_service.all_metadata_summaries())
        except (AttributeError, ValueError):
            return list(session.summaries())

    @staticmethod
    def _signature(session: Any, summaries: list[Any]) -> Any:
        return (id(session), getattr(session, "workspace_session_generation", 0),
                frozenset((str(s.id), getattr(s, "updated_at", 0), getattr(s, "revision", 0)) for s in summaries))

    def _refresh_health(self, session: Any, summaries: list[Any]) -> None:
        signature = self._signature(session, summaries)
        if signature == self._health_signature:
            return
        entries = session.all_entries()
        try:
            result = vault_health(entries)
        finally:
            for entry in entries:
                entry.clear()
        ids = {str(s.id) for s in summaries}
        overview = health_overview(result, self.breached_ids & ids)
        self._health = overview
        self._health_flags = {
            "breached": frozenset(self.breached_ids & ids),
            "weak": frozenset(result.get("weak_ids", ())),
            "reused": frozenset(result.get("reused_ids", ())),
        }
        self._health_signature = signature

    @staticmethod
    def _expiring_ids(session: Any) -> set[str]:
        try:
            rows = [*session.reminders.overdue(), *session.reminders.upcoming(days=30)]
            return {str(row.get("item_id")) for row in rows if row.get("item_id")}
        except Exception:  # noqa: BLE001 - reminders are optional decoration
            return set()

    @staticmethod
    def _collections_and_views(session: Any) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
        try:
            collections = list(session.collections.list())
        except Exception:  # noqa: BLE001
            collections = []
        try:
            views = list(session.smart_views.list())
        except Exception:  # noqa: BLE001
            views = []
        return collections, views

    # ------------------------------------------------------------------ nav
    def nav(self) -> dict[str, Any]:
        session = self._session()
        if session is None:
            groups = build_nav([], [], [], unlocked=False)
        else:
            collections, views = self._collections_and_views(session)
            groups = build_nav(self._summaries(session), collections, views, unlocked=True)
        return {
            "groups": [{"name": g.name, "entries": [
                {"label": e.label, "icon": e.icon, "token": e.token, "count": e.count, "action": e.action}
                for e in g.entries]} for g in groups],
            "settings": {**SETTINGS_ENTRY, "label": t(SETTINGS_ENTRY["label"])},
        }

    # ----------------------------------------------------------------- list
    def items(self, filter_kind: str | None, chip: str | None, query: str) -> dict[str, Any]:
        session = self._session()
        chip = chip if chip in CHIPS else None
        query = str(query or "").strip()
        if session is None:
            return {"items": [], "count": 0, "chips": dict.fromkeys(CHIPS, 0),
                    "context": {"title": t("home.title.all"), "text": t(_CONTEXT_KEYS["all"])}, "empty": _empty(_EMPTY_LOCKED), "import_card": False}
        summaries = self._summaries(session)
        self._refresh_health(session, summaries)
        collections, views = self._collections_and_views(session)
        options = filter_options(summaries, collections, views)
        labels = {option.kind: option.label for option in options}
        labels["recent"] = t("home.title.recent")
        valid = set(labels) | {None}
        if filter_kind not in valid:
            filter_kind = None
        present = {str(s.id) for s in summaries}
        health = self._health
        flag_ids = {
            "attention": set(health.attention_ids) & present if health else set(),
            "no2fa": set(health.no_2fa_ids) & present if health else set(),
            "expiring": self._expiring_ids(session) & present,
        }
        if filter_kind == "recent":
            flag_ids["recent"] = recent_ids(summaries)
        view_ids: set[str] = set()
        if filter_kind and filter_kind.startswith("view:"):
            try:
                view_ids = {str(row["id"]) for row in session.smart_views.evaluate(filter_kind[5:])}
            except Exception:  # noqa: BLE001
                view_ids = set()
        chips = {name: len(flag_ids[name]) for name in CHIPS}
        if chip and not chips[chip]:
            chip = None

        projections = self._projections(session)
        icons = self._captured_icons(session)
        rows: list[tuple[Any, str]] = []
        for summary in summaries:
            if not matches_filter(summary, filter_kind, view_ids, flag_ids=flag_ids):
                continue
            if chip and not matches_filter(summary, chip, view_ids, flag_ids=flag_ids):
                continue
            target = row_target(summary, projections.get(str(summary.id)),
                                bookmark_host=self._bookmark_host(session, summary))
            rows.append((summary, target))
        if query:
            targets = {id(s): t for s, t in rows}
            ordered = rank_search_results([(s, search_fields(s, t)) for s, t in rows], query)
            rows = [(s, targets[id(s)]) for s in ordered]
        else:
            option, favorites_first = self._sort_choice()
            targets = {id(s): t for s, t in rows}
            ordered = sort_items([s for s, _t in rows], option, favorites_first, title=_summary_title)
            rows = [(s, targets[id(s)]) for s in ordered]

        items = [self._row(summary, target, icons) for summary, target in rows]
        key = _filter_key(filter_kind)
        title = t("home.title.all") if filter_kind is None else labels.get(filter_kind) or (
            filter_kind_label(filter_kind) if filter_kind in _FILTER_LABELS_STATIC or ":" not in filter_kind
            else t("home.title.allTypes"))
        text = (t(_CONTEXT_KEYS[key]) if key in _CONTEXT_KEYS
                else t("home.context.kind", kind=kind_label(filter_kind or "")))
        empty = None
        if not items:
            empty = _empty(_EMPTY_FILTERED if (query or filter_kind or chip) else _EMPTY_NONE)
        return {"items": items, "count": len(items), "chips": chips,
                "context": {"title": title, "text": text}, "empty": empty, "sort": self.sort_state(),
                "import_card": not summaries and not self._import_card_dismissed()}

    # ---------------------------------------------------------- import card
    def _import_card_dismissed(self) -> bool:
        settings = getattr(self._controller, "settings", None)
        return getattr(settings, "import_card_dismissed", False) is True

    def dismiss_import_card(self) -> dict[str, Any]:
        """Hide the empty-vault import card on this device ("Not now")."""
        settings = getattr(self._controller, "settings", None)
        if settings is not None:
            settings.import_card_dismissed = True
            try:
                settings.save()
            except OSError:
                pass  # hidden until the app closes
        return {"import_card": False}

    # ----------------------------------------------------------------- sort
    def _sort_choice(self) -> tuple[str, bool]:
        settings = getattr(self._controller, "settings", None)
        option = getattr(settings, "list_sort", DEFAULT_SORT)
        favorites_first = getattr(settings, "list_favorites_first", True)
        return (option if option in SORT_OPTIONS else DEFAULT_SORT,
                favorites_first if isinstance(favorites_first, bool) else True)

    def sort_state(self) -> dict[str, Any]:
        """The list sort choice (this device only) and the menu's options."""
        option, favorites_first = self._sort_choice()
        return {"option": option, "favorites_first": favorites_first,
                "options": [{"value": value, "label": sort_label(value)} for value in SORT_OPTIONS]}

    def set_sort(self, option: Any, favorites_first: Any) -> dict[str, Any]:
        """Remember the list sort in this device's settings (never synced)."""
        if option not in SORT_OPTIONS:
            raise ApiError("invalid", t("home.error.chooseSort"))
        if not isinstance(favorites_first, bool):
            raise ApiError("invalid", t("home.error.favoritesFirst"))
        settings = getattr(self._controller, "settings", None)
        if settings is not None:
            settings.list_sort = option
            settings.list_favorites_first = favorites_first
            try:
                settings.save()
            except OSError:
                pass  # the choice still applies until the app closes
        return self.sort_state()

    # ---------------------------------------------------------------- codes
    def codes(self) -> dict[str, Any]:
        """Live 2FA codes for every login that has one, for the strip above the list.

        A login that needs the master password is listed without its code, like
        the detail pane ("Hidden · click to show").
        """
        session = self._session()
        if session is None:
            return {"codes": []}
        icons = self._captured_icons(session)
        codes: list[dict[str, Any]] = []
        for summary in self._summaries(session):
            if str(summary.kind) not in ("web", "desktop"):
                continue
            detail = session.credential_detail(str(summary.id))
            if detail is None:
                continue
            try:
                totp = detail.get("totp")
                if not (isinstance(totp, dict) and totp.get("secret")):
                    continue
                strict = bool(normalized_policy(detail.get("policy")).get("require_master_password"))
                config = None if strict else dict(totp)
            finally:
                detail.clear()
            row = self._row(summary, "", icons)
            entry = {key: row[key] for key in ("ref", "title", "username", "origin", "icon")}
            if config is None:
                entry["hidden"] = True
            else:
                try:
                    entry.update(live_code(config))
                except ApiError as exc:
                    entry["error"] = exc.message
            codes.append(entry)
        codes.sort(key=lambda c: (c["title"].casefold(), c["username"].casefold()))
        return {"codes": codes}

    def _row(self, summary: Any, target: str, icons: dict[str, str]) -> dict[str, Any]:
        kind = str(summary.kind)
        title = _safe_display(_summary_title(summary))
        flag = next((name for name in _FLAG_ORDER if str(summary.id) in self._health_flags.get(name, ())), None)
        scope = getattr(summary, "scope", None) or {}
        origin = str(scope.get("origin", "")) if kind == "web" else ""
        icon = icons.get(origin) if origin else None
        if icon is None and self.icons is not None:
            if kind == "web" and origin:
                # Downloading a favicon tells the site this vault has an account there:
                # only with "Show website icons" on (off by default) and strict offline mode off.
                if getattr(getattr(self._controller, "settings", None), "website_icons", False) is True:
                    icon = self.icons.website(origin)
            elif kind == "desktop" and scope.get("exe_path"):
                icon = self.icons.desktop(str(scope.get("exe_path")))
        return {
            "ref": {"source": "credential" if kind in ("web", "desktop") else "typed", "id": str(summary.id),
                    "kind": kind},
            "title": title,
            "username": _safe_display(str(getattr(summary, "username", "") or "")),
            "kind_label": kind_label(kind),
            "flag": flag,
            "target": target,
            "favorite": bool(getattr(summary, "favorite", False)),
            # The UI draws the tile: icon, else the bundled site logo for origin, else the kind's glyph.
            "origin": origin or None,
            "icon": icon,
        }

    @staticmethod
    def _projections(session: Any) -> dict[str, dict[str, Any]]:
        try:
            return {str(item["id"]): item for item in session.item_service.list_items()}
        except Exception:  # noqa: BLE001
            return {}

    def _bookmark_host(self, session: Any, summary: Any) -> str:
        """Host of a bookmark's protected URL, decrypted once per item revision and session."""
        if summary.kind != "bookmark":
            return ""
        cache = getattr(self, "_host_cache", None)
        if cache is None or cache[0] is not session:
            cache = (session, {})
            self._host_cache = cache
        key = (str(summary.id), getattr(summary, "updated_at", 0), getattr(summary, "revision", 0))
        if key in cache[1]:
            return cache[1][key]
        try:
            item = session.item_service.get_item(summary.id, include_protected=True)
            url = str((item or {}).get("payload", {}).get("url", ""))
            host = host_of(url) if url else ""
        except Exception:  # noqa: BLE001
            host = ""
        cache[1][key] = host
        return host

    def _captured_icons(self, session: Any) -> dict[str, str]:
        """Icons the browser extension captured, read fresh each time (a newly saved one shows at once)."""
        try:
            raw = session.captured_site_icons()
        except Exception:  # noqa: BLE001
            raw = {}
        icons: dict[str, str] = {}
        cache = self._icon_urls
        for origin, png in raw.items():
            if not isinstance(png, (bytes, bytearray)) or len(png) > 32 * 1024:
                continue
            key = bytes(png)
            url = cache.get(key)
            if url is None:
                if len(cache) > 512:
                    cache.clear()
                url = cache[key] = "data:image/png;base64," + base64.b64encode(key).decode("ascii")
            icons[origin] = url
        return icons

    # -------------------------------------------------------------- overview
    def overview(self) -> dict[str, Any]:
        session = self._session()
        if session is None:
            return {"health": None, "reminders": [], "backup": None}
        summaries = self._summaries(session)
        self._refresh_health(session, summaries)
        health = self._health
        titles = {str(s.id): _summary_title(s) for s in summaries}
        try:
            rows = {str(r.get("id")): r for r in [*session.reminders.overdue(), *session.reminders.upcoming(days=90)]}
        except Exception:  # noqa: BLE001
            rows = {}
        reminder_rows = [{"due_date": r.get("due_date"), "label": r.get("label") or titles.get(str(r.get("item_id")), "")}
                         for r in rows.values()]
        lines = upcoming_lines(reminder_rows, date.today())
        backup_dir = getattr(session, "backup_dir", None) or self._controller.profiles.backups_dir(
            self._controller.profiles.active_profile().id)
        warning = t("home.backupFailed") if getattr(session, "backup_warning", None) else ""
        backup = backup_status(backup_dir, warning)
        return {
            "health": None if health is None else {"score": health.score, "label": health.label, "weak": health.weak,
                                                   "reused": health.reused, "no_2fa": health.no_2fa},
            "reminders": [{"date": line.date_text, "label": line.label, "meta": line.meta, "overdue": line.overdue}
                          for line in lines],
            "backup": {"last_at": backup.last_at, "count": backup.count, "warning": backup.warning,
                       "stale": backup.last_at is None or time.time() - backup.last_at > STALE_BACKUP_SECONDS},
        }

    # ---------------------------------------------------------------- status
    def status(self) -> dict[str, Any]:
        controller = self._controller
        unlocked = controller.is_unlocked()
        clipboard = getattr(controller, "clipboard", None)
        left = clipboard.remaining() if clipboard is not None else None
        return {
            "autolock": auto_lock_text(controller.idle_lock_remaining(), unlocked=unlocked),
            "clipboard": t("status.clipboard", seconds=left) if left is not None else "",
            "encrypted": encrypted_text(),
            "hint": shortcut_hint(),
        }
