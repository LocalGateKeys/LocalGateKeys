"""Reminders, activity, keyboard shortcuts, collections and the catalog update for the WebView UI.

Ports ``FeatureUI.reminders_clicked``, ``activity_clicked``, the F1 cheat
sheet, collection management from the safe workspace, and
``_legacy_catalog_gate``. Only safe metadata reaches the page.
"""
from __future__ import annotations

import time
from typing import Any, Callable

from ..api.result import ApiError
from ..vault import VaultError
from .setting_links import open_settings
from ..i18n import t

CATALOG_TITLE = "workspace.thisVaultUsesTheLegacy"
CATALOG_TEXT = ("workspace.typedItemsCollectionsTemplatesAnd")


class _Unlocked:
    def __init__(self, controller: Any) -> None:
        self._controller = controller

    def _session(self) -> Any:
        controller = self._controller
        if not controller.is_unlocked():
            raise ApiError("locked", t("error.lockedProfile"))
        controller.require_lease(controller.guard.lease())
        return controller.session


class RemindersService(_Unlocked):
    def __init__(self, controller: Any, changed: Callable[[], None]) -> None:
        super().__init__(controller)
        self._changed = changed

    def list(self) -> dict[str, Any]:
        session = self._session()
        titles = {str(s.id): str(getattr(s, "title", "") or "") for s in session.item_service.all_metadata_summaries()}
        rows = [{"id": str(r["id"]), "title": titles.get(str(r["item_id"])) or t("workspace.deletedItem"),
                 "due": str(r["due_date"]), "status": str(r["status"])}
                for r in session.reminders.upcoming(3650)]
        return {"title": t("command.reminders.title"), "subtitle": t("workspace.dueDatesStayEncryptedThis"), "rows": rows}

    def _act(self, fn: Callable[[], Any]) -> dict[str, Any]:
        try:
            fn()
        except (VaultError, ValueError, KeyError) as exc:
            raise ApiError("invalid", str(exc) or t("workspace.theReminderCouldNotBe")) from None
        self._controller.touch()
        self._changed()  # "Coming up" and the Expiring chip follow reminders
        return self.list()

    def complete(self, reminder_id: str) -> dict[str, Any]:
        session = self._session()
        return self._act(lambda: session.reminders.complete(reminder_id))

    def snooze(self, reminder_id: str) -> dict[str, Any]:
        session = self._session()
        return self._act(lambda: session.reminders.snooze(reminder_id, days=1))


class ActivityService(_Unlocked):
    def list(self) -> dict[str, Any]:
        session = self._session()
        rows = [{"when": time.strftime("%Y-%m-%d %H:%M", time.localtime(int(e["timestamp"]))),
                 "event": str(e["event_type"]), "result": str(e["result"]), "count": int(e.get("count") or 0)}
                for e in session.activity.history()]
        return {"title": t("workspacePages.activity"), "subtitle": t("workspace.onlyBoundedEventTypesResults"), "rows": rows}


def shortcuts(settings: Any) -> dict[str, Any]:
    from ..hotkey import shortcut_cheat_sheet_rows

    rows = shortcut_cheat_sheet_rows(getattr(settings, "quick_access_hotkey", "Ctrl+Alt+K") or "Ctrl+Alt+K")
    return {"title": t("command.shortcuts.title"),
            "subtitle": t("workspace.pressEscToClose"),
            "action": open_settings("autofill", t("workspace.changeTheQuickAccessKey")),
            "rows": [{"group": g, "keys": k, "description": d} for g, k, d in rows]}


class CollectionsService(_Unlocked):
    def __init__(self, controller: Any, changed: Callable[[], None]) -> None:
        super().__init__(controller)
        self._changed = changed

    def list(self) -> dict[str, Any]:
        session = self._session()
        try:
            rows = session.collections.list()
        except VaultError as exc:
            raise ApiError("catalog", str(exc)) from None
        return {"collections": [{"id": str(c.get("id")), "name": str(c.get("name", "")),
                                 "description": str(c.get("description", "") or ""),
                                 "archived": bool(c.get("archived"))} for c in rows]}

    def _act(self, fn: Callable[[], Any]) -> dict[str, Any]:
        try:
            fn()
        except (VaultError, ValueError, KeyError) as exc:
            raise ApiError("invalid", str(exc) or t("workspace.theCollectionCouldNotBe")) from None
        self._controller.touch()
        self._changed()
        return self.list()

    def create(self, name: str, description: str = "") -> dict[str, Any]:
        session = self._session()
        return self._act(lambda: session.collections.create(name, description=description))

    def rename(self, collection_id: str, name: str, description: str | None = None) -> dict[str, Any]:
        session = self._session()
        return self._act(lambda: session.collections.rename(collection_id, name, description=description))

    def archive(self, collection_id: str) -> dict[str, Any]:
        session = self._session()
        return self._act(lambda: session.collections.archive(collection_id))


class CatalogService(_Unlocked):
    def __init__(self, controller: Any, port: Any, changed: Callable[[], None]) -> None:
        super().__init__(controller)
        self._port = port
        self._changed = changed

    def status(self) -> dict[str, Any]:
        session = self._session()
        try:
            session._require_typed_catalog()
        except VaultError:
            return {"needs_update": True, "title": t(CATALOG_TITLE), "text": t(CATALOG_TEXT)}
        return {"needs_update": False}

    def update(self) -> dict[str, Any]:
        from ..session_guard import StaleSession

        session = self._session()
        if not self.status()["needs_update"]:
            return {"updated": False}
        lease = self._controller.guard.lease()  # taken before the dialog: a lock while it is open ends it
        if not self._port.confirm(t(CATALOG_TITLE), t(CATALOG_TEXT)):
            raise ApiError("cancelled", t("error.cancelled"))
        try:
            self._controller.require_lease(lease)
        except StaleSession:
            raise ApiError("session_changed", t("documents.theVaultLockedOrChanged")) from None
        if self._controller.session is not session:
            raise ApiError("session_changed", t("documents.theVaultLockedOrChanged"))
        try:
            session.migrate_to_v2()
        except (VaultError, OSError, ValueError):
            raise ApiError("catalog", t("workspace.theVaultWasNotUpdated")) from None
        result = session.last_catalog_migration_result or {}
        if result.get("success") is not True:
            raise ApiError("catalog", t("workspace.theVaultUpdateCouldNot"))
        self._controller.touch()
        self._changed()
        return {"updated": True}
