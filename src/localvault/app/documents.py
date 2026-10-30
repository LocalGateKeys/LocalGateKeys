"""Encrypted documents for the WebView UI: create, replace, preview, open and save a copy.

The page never sends a file path: Python opens the native dialogs (``dialogs``,
implemented by ``web/window.py`` with pywebview's file dialog) and file bytes
never cross the bridge. Texts follow the Tk app verbatim.
"""
from __future__ import annotations

import mimetypes
from pathlib import Path
from typing import Any, Protocol

from ..api.result import ApiError
from ..attachments import (
    OPEN_NOT_ALLOWED_TEXT,
    can_open_externally,
    cleanup_open_copies,
    strip_format_controls,
)
from ..vault import ItemLimitReached, ProFeatureRequired, VaultError
from .licence_view import pro_required
from ..i18n import t

OPEN_OFF_TITLE = "documents.openingDocumentsIsOff"
OPEN_OFF_TEXT = ("documents.openDocumentsInOtherApps")
OPEN_WARNING_TITLE = "documents.openADecryptedCopy"
OPEN_WARNING_TEXT = (
    "documents.toOpenThisFileIn"
)
COPY_SAVED_TEXT = "documents.aDecryptedCopyWasWritten"


class Dialogs(Protocol):
    def open_file(self, title: str, file_types: tuple[str, ...] | None = None) -> Path | None: ...

    def save_file(self, title: str, name: str) -> Path | None: ...


class DocumentService:
    def __init__(self, controller: Any, port: Any, dialogs: Dialogs) -> None:
        self._controller = controller
        self._port = port
        self._dialogs = dialogs
        self._sweep_generation = 0
        controller.on_lock.append(self._sweep_open_copies)
        controller.on_unlock.append(self._stop_sweeping)

    def _stop_sweeping(self) -> None:
        self._sweep_generation += 1  # a new unlock may open documents again: old retries stop

    def _sweep_open_copies(self, generation: int | None = None, profile_dir: Any = None) -> None:
        """Delete decrypted copies opened in other apps; retry every 30 s while one is still in use.

        The retry keeps the profile that was locked, even after a switch to another profile.
        A lost race on the generation counter costs at most one extra or one skipped sweep.
        """
        if generation is None:
            self._sweep_generation += 1
            generation = self._sweep_generation
            try:
                profile_dir = self._controller.profiles.profile_dir()
            except Exception:  # noqa: BLE001 - no profile: nothing to sweep
                return
        elif generation != self._sweep_generation or self._controller.is_unlocked():
            return
        try:
            remaining = cleanup_open_copies(profile_dir)
        except Exception:  # noqa: BLE001 - try again later
            remaining = [None]
        if remaining:
            self._controller._scheduler.call_later(30, lambda: self._sweep_open_copies(generation, profile_dir))

    def _session(self) -> Any:
        if not self._controller.is_unlocked():
            raise ApiError("locked", t("error.lockedProfile"))
        return self._controller.session

    @staticmethod
    def _id(ref: dict[str, Any]) -> str:
        if ref.get("source") != "typed" or ref.get("kind") != "document":
            raise ApiError("invalid", t("documents.chooseADocument"))
        return ref["id"]

    def _pick(self, title: str) -> Path:
        path = self._dialogs.open_file(title)
        if not path:
            raise ApiError("cancelled", t("recovery.noFileWasChosen"))
        return Path(path)

    def _lease(self) -> Any:
        from ..session_guard import StaleSession

        try:
            lease = self._controller.guard.lease()
            self._controller.require_lease(lease)
        except StaleSession:
            raise ApiError("session_changed", t("recovery.theVaultLockedOrChanged")) from None
        return lease

    def _still(self, lease: Any) -> None:
        """After a dialog: the session the user started with must still be the current one."""
        from ..session_guard import StaleSession

        try:
            self._controller.require_lease(lease)
        except StaleSession:
            raise ApiError("session_changed", t("documents.theVaultLockedOrChanged")) from None

    def create(self, title: str, description: str) -> dict[str, Any]:
        session = self._session()
        lease = self._lease()
        source = self._pick(t("documents.chooseEncryptedDocumentSource"))
        self._still(lease)
        try:
            # The default title is the file name, without bidi tricks that disguise it in the list.
            default = strip_format_controls(source.name).strip() or "Document"
            item_id = session.documents.create(source, title=(title or "").strip() or default,
                                               description=description or "")
        except ItemLimitReached as exc:
            self._port.show_upgrade(limit=exc.limit, message=str(exc), on_enter=lambda: None)
            raise ApiError("item_limit", str(exc)) from None
        except ProFeatureRequired as exc:
            raise pro_required(self._port, exc) from None
        except (VaultError, OSError, ValueError) as exc:
            raise ApiError("vault_error", str(exc)) from None
        self._controller.touch()
        return {"ref": {"source": "typed", "id": item_id, "kind": "document"}}

    def replace(self, ref: dict[str, Any]) -> dict[str, Any]:
        session = self._session()
        item_id = self._id(ref)
        lease = self._lease()
        source = self._pick(t("documents.chooseAReplacementFile"))
        self._still(lease)
        try:
            # The replacement keeps its own file name (Tk kept the old one, mislabelling the file).
            session.documents.replace(item_id, source, name=source.name,
                                      mime_type=mimetypes.guess_type(source.name)[0] or "application/octet-stream")
        except ProFeatureRequired as exc:
            raise pro_required(self._port, exc) from None
        except (VaultError, OSError, ValueError) as exc:
            raise ApiError("vault_error", str(exc)) from None
        self._controller.touch()
        return {"ref": ref}

    def info(self, ref: dict[str, Any]) -> dict[str, Any]:
        session = self._session()
        try:
            record = session.documents.attachment_for(self._id(ref))
        except (VaultError, ValueError) as exc:
            raise ApiError("vault_error", t("documents.attachmentUnavailable", exc=exc)) from None
        name = record.get("name")
        if isinstance(name, str):
            name = strip_format_controls(name)  # shown and suggested without bidi tricks
        return {"name": name, "mime": record.get("mime_type"), "size": record.get("size")}

    def preview(self, ref: dict[str, Any]) -> dict[str, Any]:
        session = self._session()
        try:
            result = session.documents.preview(self._id(ref))
        except (VaultError, ValueError) as exc:
            raise ApiError("vault_error", str(exc)) from None
        if result.get("kind") == "text":
            return {"kind": "text", "content": str(result.get("content", "")), "truncated": bool(result.get("truncated"))}
        return {"kind": "metadata", "reason": str(result.get("reason", "")),
                "metadata": {k: v for k, v in dict(result.get("metadata") or {}).items() if k != "key"}}

    def open_externally(self, ref: dict[str, Any]) -> dict[str, Any]:
        session = self._session()
        item_id = self._id(ref)
        settings = self._controller.settings
        if not settings.document_open_enabled:
            raise ApiError("needs_setting", t(OPEN_OFF_TEXT), fix={
                "section": "privacy", "key": "document_open_enabled", "value": True, "label": t("documents.turnOnAndOpen")})
        # Refuse a type outside the allow-list before the one-time warning is shown.
        if not can_open_externally(str(self.info(ref).get("name") or "")):
            raise ApiError("unsupported_type", t(OPEN_NOT_ALLOWED_TEXT))
        lease = self._controller.guard.lease()
        if not settings.document_open_warning_seen:
            if not self._port.confirm(t(OPEN_WARNING_TITLE), t(OPEN_WARNING_TEXT)):
                raise ApiError("cancelled", t("error.cancelled"))
            settings.document_open_warning_seen = True
            try:
                settings.save()
            except Exception:  # noqa: BLE001, S110 - asked again next time at worst
                pass
        self._controller.require_lease(lease)  # a lock or profile switch during the warning cancels
        try:
            path = session.documents.open_externally(item_id)
        except (VaultError, OSError, ValueError) as exc:
            raise ApiError("vault_error", str(exc)) from None
        return {"message": t("documents.openedItsDecryptedCopyIs", name=Path(path).name)}

    def save_copy(self, ref: dict[str, Any]) -> dict[str, Any]:
        session = self._session()
        item_id = self._id(ref)
        name = self.info(ref).get("name") or "document"
        lease = self._lease()
        target = self._dialogs.save_file(t("documents.saveADecryptedCopy"), str(name))
        if not target:
            raise ApiError("cancelled", t("recovery.noFileWasChosen"))
        self._still(lease)
        try:
            session.documents.export(item_id, Path(target), overwrite=True)
        except (VaultError, OSError, ValueError) as exc:
            raise ApiError("vault_error", str(exc)) from None
        self._port.notify("info", t("documents.copySaved"), t(COPY_SAVED_TEXT))
        return {"message": t("documents.copySaved")}
