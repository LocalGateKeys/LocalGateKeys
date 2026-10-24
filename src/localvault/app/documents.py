"""Encrypted documents for the WebView UI: create, replace, preview, open and save a copy.

The page never sends a file path: Python opens the native dialogs (``dialogs``,
implemented by ``web/window.py`` with pywebview's file dialog) and file bytes
never cross the bridge. Texts follow the Tk app verbatim
(docs/superpowers/specs/2026-10-17-webview-items-dataflow.md §2).
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

OPEN_OFF_TITLE = "Opening documents is off"
OPEN_OFF_TEXT = ('"Open documents in other apps" is off. Turn it on to open this file, or use Save a copy… instead.')
OPEN_WARNING_TITLE = "Open a decrypted copy?"
OPEN_WARNING_TEXT = (
    "To open this file in another app, LocalGateKeys puts a decrypted copy in your profile folder on this PC. "
    "It is deleted as soon as you close the file in that app (and at the latest when the vault locks). "
    "The other app may keep its own recent-files list or backups.\n\nYou won't be asked again."
)
COPY_SAVED_TEXT = "A decrypted copy was written outside the vault. Protect or delete it when finished."


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
            raise ApiError("locked", "Unlock this profile first.")
        return self._controller.session

    @staticmethod
    def _id(ref: dict[str, Any]) -> str:
        if ref.get("source") != "typed" or ref.get("kind") != "document":
            raise ApiError("invalid", "Choose a document.")
        return ref["id"]

    def _pick(self, title: str) -> Path:
        path = self._dialogs.open_file(title)
        if not path:
            raise ApiError("cancelled", "No file was chosen.")
        return Path(path)

    def _lease(self) -> Any:
        from ..session_guard import StaleSession

        try:
            lease = self._controller.guard.lease()
            self._controller.require_lease(lease)
        except StaleSession:
            raise ApiError("session_changed", "The vault locked or changed. Try again.") from None
        return lease

    def _still(self, lease: Any) -> None:
        """After a dialog: the session the user started with must still be the current one."""
        from ..session_guard import StaleSession

        try:
            self._controller.require_lease(lease)
        except StaleSession:
            raise ApiError("session_changed", "The vault locked or changed while the dialog was open.") from None

    def create(self, title: str, description: str) -> dict[str, Any]:
        session = self._session()
        lease = self._lease()
        source = self._pick("Choose encrypted document source")
        self._still(lease)
        try:
            item_id = session.documents.create(source, title=(title or "").strip() or source.name,
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
        source = self._pick("Choose a replacement file")
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
            raise ApiError("vault_error", f"Attachment unavailable: {exc}") from None
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
            raise ApiError("needs_setting", OPEN_OFF_TEXT, fix={
                "section": "privacy", "key": "document_open_enabled", "value": True, "label": "Turn on and open"})
        # Refuse a type outside the allow-list before the one-time warning is shown.
        if not can_open_externally(str(self.info(ref).get("name") or "")):
            raise ApiError("unsupported_type", OPEN_NOT_ALLOWED_TEXT)
        lease = self._controller.guard.lease()
        if not settings.document_open_warning_seen:
            if not self._port.confirm(OPEN_WARNING_TITLE, OPEN_WARNING_TEXT):
                raise ApiError("cancelled", "Cancelled.")
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
        return {"message": f"Opened {Path(path).name}. Its decrypted copy is deleted when you close it."}

    def save_copy(self, ref: dict[str, Any]) -> dict[str, Any]:
        session = self._session()
        item_id = self._id(ref)
        name = self.info(ref).get("name") or "document"
        lease = self._lease()
        target = self._dialogs.save_file("Save a decrypted copy", str(name))
        if not target:
            raise ApiError("cancelled", "No file was chosen.")
        self._still(lease)
        try:
            session.documents.export(item_id, Path(target), overwrite=True)
        except (VaultError, OSError, ValueError) as exc:
            raise ApiError("vault_error", str(exc)) from None
        self._port.notify("info", "Copy saved", COPY_SAVED_TEXT)
        return {"message": "Copy saved"}
