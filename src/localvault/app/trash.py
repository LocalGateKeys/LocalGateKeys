"""Recently deleted (trash) for the WebView UI: list, restore, permanently delete, empty.

Texts and rules follow ``FeatureUI.trash_clicked``.
"""
from __future__ import annotations

from typing import Any

from ..api.result import ApiError
from ..vault import VaultError
from .catalog import _safe_display, kind_label
from .setting_links import open_settings
from .trash_restore import restore_trash_entries
from ..i18n import t


class TrashService:
    def __init__(self, controller: Any, port: Any) -> None:
        self._controller = controller
        self._port = port

    def _session(self) -> Any:
        if not self._controller.is_unlocked():
            raise ApiError("locked", t("error.lockedProfile"))
        return self._controller.session

    def _rows(self, session: Any) -> list[dict[str, Any]]:
        rows = []
        for row in session.trash_summaries():
            rows.append({"id": str(row["id"]), "source": "credential", "title": _safe_display(str(row.get("label") or "")),
                         "kind_label": "Login", "username": _safe_display(str(row.get("username") or "")),
                         "deleted_at": int(row.get("deleted_at") or 0)})
        for row in session.item_service.trash_summaries():
            rows.append({"id": str(row["id"]), "source": "typed", "title": _safe_display(str(row.get("title") or "")),
                         "kind_label": kind_label(str(row.get("kind") or "")), "username": "",
                         "deleted_at": int(row.get("deleted_at") or 0)})
        rows.sort(key=lambda r: r["deleted_at"], reverse=True)
        return rows

    def list(self) -> dict[str, Any]:
        session = self._session()
        settings = self._controller.settings
        if settings.trash_auto_purge:
            text = (t("trash.entriesStayEncryptedForDays", trash_retention_days=settings.trash_retention_days))
        else:
            text = (t("trash.automaticEmptyingIsOffSo"))
        return {"rows": self._rows(session), "retention_text": text,
                "retention_action": open_settings("privacy", t("trash.changeInSettings"))}

    def restore(self, ids: list[str]) -> dict[str, Any]:
        session = self._session()
        rows = {r["id"]: r for r in self._rows(session)}
        wanted = [i for i in ids if i in rows]
        lease = self._controller.guard.lease()
        result = restore_trash_entries(session, wanted, {i: rows[i]["source"] for i in wanted},
                                       lambda: self._controller.require_lease(lease))
        if result.limit is not None:
            self._port.show_upgrade(limit=result.limit.limit, message=str(result.limit), on_enter=lambda: None)
        self._controller.touch()
        return {"message": t("trash.restoredItems", count=result.restored),
                "failed": [{"title": rows[i]["title"], "message": str(exc)} for i, exc in result.failed]}

    def purge(self, ids: list[str]) -> dict[str, Any]:
        session = self._session()
        rows = {r["id"]: r for r in self._rows(session)}
        wanted = [i for i in ids if i in rows]
        if not wanted:
            return {"message": t("trash.permanentlyDeletedItems", count=0)}
        if len(wanted) == 1:
            text = (t("trash.permanentlyDeleteThisCannotBe", v1=rows[wanted[0]]['title']))
        else:
            text = t("trash.permanentlyDeleteItemsConfirm", count=len(wanted))
        # Take the lease before the dialog: a lock or profile switch while it
        # is open invalidates it, so the delete below cannot hit another vault.
        lease = self._controller.guard.lease()
        if not self._port.confirm(t("trash.permanentlyDelete"), text):
            raise ApiError("cancelled", t("error.cancelled"))
        self._controller.require_lease(lease)
        try:
            count = session.purge_deleted_many(wanted)
        except VaultError as exc:
            raise ApiError("vault_error", str(exc)) from None
        return {"message": t("trash.permanentlyDeletedItems", count=count)}

    def empty(self) -> dict[str, Any]:
        return self.purge([r["id"] for r in self._rows(self._session())])
