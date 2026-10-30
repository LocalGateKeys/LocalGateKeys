"""Encrypted transfer packages for the WebView UI, following ``transfer_ui.TransferWindow``.

Preview first, then commit. A preview token binds the exact inputs (mode,
package path, scope, conflict policy) and a salted digest of the transfer
password, never the password itself; a commit with anything changed is
refused and needs a fresh preview. Package paths come only from Python's
file dialogs. Export asks for the master password (never Windows Hello) before
its save dialog, once per export.
"""
from __future__ import annotations

import hashlib
import hmac
import secrets
import threading
from pathlib import Path
from typing import Any

from ..api.result import ApiError
from .transfer_controller import CONFLICT_POLICIES, TransferSelection, import_limit_lines, notify_item_limit, \
    summarize_manifest
from ..i18n import t

INTRO = ("transferWeb.previewFirstPackagesStayEncrypted")
SCOPE_NOTE = "transferWeb.useCommaSeparatedIdsKinds"
DONE = "transferWeb.transferCompleteTheLocalPackage"
FAILED = "transferWeb.theTransferDidNotComplete"


def _split(value: Any) -> tuple[str, ...]:
    return tuple(part.strip() for part in str(value or "").split(",") if part.strip())


class TransferService:
    def __init__(self, controller: Any, port: Any, dialogs: Any) -> None:
        from .secrets import SecretService

        self._controller = controller
        self._port = port
        self._dialogs = dialogs
        self._auth = SecretService(controller, port)
        self._paths: dict[str, tuple[str, Path]] = {}
        self._previews: dict[str, dict[str, Any]] = {}
        self._cancel = threading.Event()
        controller.on_lock.append(self._drop)

    def _drop(self) -> None:
        self._cancel.set()
        self._paths.clear()
        self._previews.clear()

    def _core(self) -> Any:
        from .transfer_controller import TransferController

        controller = self._controller
        if not controller.is_unlocked():
            raise ApiError("locked", t("error.lockedProfile"))
        lease = controller.guard.lease()
        controller.require_lease(lease)
        return TransferController(controller.session, lease=lease, guard=controller.guard,
                                  session_provider=lambda: controller.session)

    def info(self) -> dict[str, Any]:
        offline = t("transferWeb.offlineStrict" if self._controller.settings.strict_offline_mode else "transferWeb.offlineLocal")
        return {"title": t("transferWeb.encryptedTransfer", offline=offline), "intro": t(INTRO), "scope_note": t(SCOPE_NOTE),
                "policies": list(CONFLICT_POLICIES), "status": t("transferWeb.readyPackagesStayEncryptedAnd")}

    # ---------------------------------------------------------------- paths
    def choose(self, mode: str) -> dict[str, Any]:
        if mode not in ("export", "import"):
            raise ApiError("invalid", t("transferWeb.chooseExportOrImport"))
        self._core()
        if mode == "export":
            # A package carries every selected secret, so export asks for the master password once per export,
            # before the file dialog (the handle is single-use: commit consumes it, a lock drops it). Strict
            # like reveal of a strict item: no Windows Hello, no routine grace window.
            lease = self._controller.guard.lease()
            self._auth.reauthenticate(t("importExport.confirmToExportPasswords"), lease, allow_hello=False)
            self._controller.require_lease(lease)
            chosen = self._dialogs.save_file(t("transferWeb.exportEncryptedTransferPackageLgt"), "localgatekeys-transfer.lgt")
        else:
            chosen = self._dialogs.open_file(t("transferWeb.importEncryptedTransferPackageLgt"))
        if not chosen:
            raise ApiError("cancelled", t("recovery.noFileWasChosen"))
        path = Path(chosen)
        if mode == "export" and path.suffix.lower() != ".lgt":
            path = path.with_suffix(".lgt")
        handle = secrets.token_urlsafe(12)
        self._paths[handle] = (mode, path)
        return {"handle": handle, "path": str(path)}

    def _path(self, handle: str, mode: str) -> Path:
        entry = self._paths.get(str(handle or ""))
        if entry is None or entry[0] != mode:
            raise ApiError("invalid", t("transferWeb.chooseALocalPackagePath"))
        return entry[1]

    # -------------------------------------------------------------- helpers
    @staticmethod
    def _lines(summary: dict[str, Any], mode: str) -> list[str]:
        safe = summarize_manifest(summary.get("manifest", summary))
        lines = [
            t("transferWeb.recordsLine", records=safe['record_count'], items=safe['item_count'], credentials=safe['credential_count']),
            t("transferWeb.attachmentsLine", count=safe['attachment_count'], bytes=safe['attachment_bytes']),
            t("transferWeb.dependenciesLine", count=len(safe['manifest'].get('collections', []))),
            t("transferWeb.kindsLine", kinds=", ".join(f"{key}={value}" for key, value in sorted(safe["kind_counts"].items()))
              or t("transferWeb.kindsNone")),
        ]
        if summary.get("operation") == "import" or mode == "import":
            lines.append(t("transferWeb.conflictOutcomes", add=len(summary.get('imported_ids', [])), skip=len(summary.get('skipped_ids', [])),
                         copy=len(summary.get('copied_ids', [])), replace=len(summary.get('replaced_ids', []))))
            lines.extend(import_limit_lines(summary))
            if summary.get("requires_confirmation"):
                lines.append(t("transferWeb.noDestinationChangesHaveBeen"))
        return lines

    @staticmethod
    def _digest(salt: bytes, password: str) -> bytes:
        return hmac.new(salt, password.encode("utf-8"), hashlib.sha256).digest()

    def _error(self, exc: BaseException) -> ApiError:
        from ..transfer import TransferCancelled
        from ..vault import ItemLimitReached

        if isinstance(exc, ItemLimitReached):
            self._port.show_upgrade(limit=exc.limit, message=str(exc), on_enter=lambda: None)
            return ApiError("item_limit", str(exc))
        if isinstance(exc, TransferCancelled):
            return ApiError("cancelled", t("transferWeb.transferCancelledBeforeCompletionNo"))
        return ApiError("transfer_failed", str(exc) or t(FAILED))

    def _selection(self, scope: dict[str, Any]) -> Any:
        try:
            return TransferSelection.from_values(
                ids=_split(scope.get("ids")), kinds=_split(scope.get("kinds")), tags=_split(scope.get("tags")),
                favorite=True if scope.get("favorite") is True else None,
                include_attachments=scope.get("include_attachments", True) is not False)
        except (ValueError, TypeError) as exc:
            raise ApiError("invalid", str(exc) or t(FAILED)) from None

    # ------------------------------------------------------------ preview
    def _errors(self) -> tuple[type, ...]:
        from ..session_guard import StaleSession
        from ..transfer import TransferCancelled, TransferConflictError, TransferError
        from ..vault import ItemLimitReached

        return (TransferCancelled, TransferConflictError, TransferError, StaleSession, ItemLimitReached, OSError,
                ValueError)

    def inspect(self, handle: str) -> dict[str, Any]:
        core = self._core()
        path = self._path(handle, "import")
        try:
            result = core.inspect_package(path)
        except self._errors() as exc:
            raise self._error(exc) from None
        return {"lines": self._lines(result, "inspect"),
                "status": t("transferWeb.manifestMetadataInspectedEnterThe")}

    def preview(self, mode: str, handle: str, password: str, scope: dict[str, Any], policy: str,
                allow_replace: bool) -> dict[str, Any]:
        core = self._core()
        path = self._path(handle, mode)
        if not password:
            raise ApiError("invalid", t("transferWeb.enterTheTransferPassword"))
        if mode == "import" and policy not in CONFLICT_POLICIES:
            raise ApiError("invalid", t("transferWeb.chooseHowConflictsAreHandled"))
        self._cancel.clear()
        try:
            if mode == "export":
                selection = self._selection(scope)
                preview = core.preview_export(selection, cancel=self._cancel)
                inputs: dict[str, Any] = {"mode": mode, "handle": handle, "selection": selection}
            else:
                preview = core.preview_import(path, password, conflict_policy=policy,
                                              allow_replace=bool(allow_replace), cancel=self._cancel)
                inputs = {"mode": mode, "handle": handle, "policy": policy, "allow_replace": bool(allow_replace)}
        except self._errors() as exc:
            raise self._error(exc) from None
        salt = secrets.token_bytes(16)
        token = secrets.token_urlsafe(12)
        self._previews.clear()  # only the latest preview can be committed
        self._previews[token] = {**inputs, "salt": salt, "digest": self._digest(salt, password)}
        password = ""
        return {"token": token, "lines": self._lines(preview, mode),
                "status": t("transferWeb.previewIsReadyReviewThe")}

    def commit(self, token: str, mode: str, handle: str, password: str, confirm: str, scope: dict[str, Any],
               policy: str, allow_replace: bool) -> dict[str, Any]:
        core = self._core()
        export_path = None
        if mode == "export":
            # The export handle is single-use from here on, whatever happens next: a failed check must not leave
            # an authorized path behind for a later export without a new master-password prompt.
            entry = self._paths.get(str(handle or ""))
            if entry is not None and entry[0] == "export":
                self._paths.pop(str(handle or ""), None)
                export_path = entry[1]
        if mode == "export" and password != confirm:
            raise ApiError("invalid", t("transferWeb.transferPasswordConfirmationDoesNot"))
        preview = self._previews.pop(str(token or ""), None)
        stale = ApiError("stale", t("transferWeb.inputsChangedSincePreviewRun"))
        if preview is None or preview["mode"] != mode or preview["handle"] != handle:
            raise stale
        if not hmac.compare_digest(preview["digest"], self._digest(preview["salt"], password or "")):
            raise stale
        if mode == "export":
            if export_path is None:
                raise ApiError("invalid", t("transferWeb.chooseALocalPackagePath"))
            path = export_path
        else:
            path = self._path(handle, mode)
        try:
            if mode == "export":
                selection = self._selection(scope)
                if selection != preview["selection"]:
                    raise stale
                self._cancel.clear()
                result = core.export(path, password, selection, cancel=self._cancel)
            else:
                if policy != preview["policy"] or bool(allow_replace) != preview["allow_replace"]:
                    raise stale
                self._cancel.clear()
                result = core.import_package(path, password, confirm=True, conflict_policy=policy,
                                             allow_replace=bool(allow_replace), cancel=self._cancel)
        except ApiError:
            raise
        except self._errors() as exc:
            raise self._error(exc) from None
        finally:
            password = confirm = ""
            self._paths.pop(str(handle), None)
        notify_item_limit(lambda limit: self._port.show_upgrade(limit=limit.limit, message=str(limit),
                                                                on_enter=lambda: None), result)
        self._controller.touch()
        return {"lines": self._lines(result, mode), "status": t(DONE), "changed": mode == "import"}

    def cancel(self) -> dict[str, Any]:
        self._cancel.set()
        self._previews.clear()
        return {"status": t("transferSheet.cancelled")}
