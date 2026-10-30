"""Restoring a phone backup (.lgkm) into this vault, for the WebView UI.

Choose a file, preview with the backup password, then restore. The preview
decrypts once and keeps only the restore plan under a random token; the
password is never stored. A lock drops every handle and plan. Licences the
restore brought in are offered to the licence store as sync does, so a verified
Pro licence on the phone makes this computer Pro.
"""
from __future__ import annotations

import logging
import secrets
import threading
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .. import licensing
from ..api.result import ApiError
from ..phone_backup import MAX_FILE_BYTES, PhoneBackupError, inspect_phone_backup, read_phone_backup
from ..session_guard import StaleSession
from ..sync.phone_restore import QUARANTINE_KINDS, PhoneRestoreError, plan_restore, restore
from ..sync.vault_bridge import BridgeError, published_licenses
from ..vault import VaultLockedError
from ..i18n import t

_log = logging.getLogger(__name__)

FILE_TYPES = ("phoneBackupWeb.localgatekeysPhoneBackupLgkm", "phoneBackupWeb.allFiles")
# Sync issue kinds that skip single records while the rest is applied; any other kind means nothing was applied.
# A document whose file is missing or refused is left out; everything else is still applied.
QUARANTINE = QUARANTINE_KINDS | {"attachment-missing", "attachment-refused"}
FATAL_REASONS = {
    "trash-full": "phoneBackupWeb.theTrashIsFull",
    "history-quota": "phoneBackupWeb.itemHistoryIsFull",
    "busy": "phoneBackupWeb.theVaultChangedWhileRestoring",
}
MAX_WRONG = 5
LOCKOUT_SECONDS = 30.0
STALE = "phoneBackupWeb.previewAgainBeforeRestoring"
DONE = "phoneBackupWeb.phoneBackupRestored"
UNREADABLE = "phoneBackupWeb.theVaultCouldNotBe"


def _skipped_text(count: int, verb: str) -> str:
    return t("phoneBackupWeb.skippedWillBe" if verb == "will be" else "phoneBackupWeb.skippedWere", count=count)


def _missing_text(count: int, verb: str) -> str:
    return t("phoneBackupWeb.missingWillBe" if verb == "will be" else "phoneBackupWeb.missingWere", count=count)


def _deleted_text(count: int) -> str:
    return t("phoneBackupWeb.itemsMovedToTheTrash", count=count)


class PhoneBackupService:
    def __init__(self, controller: Any, port: Any, dialogs: Any,
                 on_licence: Any = None) -> None:
        self._controller = controller
        self._port = port
        self._dialogs = dialogs
        self._on_licence = on_licence  # called after a restored licence was installed
        self._paths: dict[str, Path] = {}
        self._plans: dict[str, tuple[str, Any]] = {}
        self._wrong = 0
        self._blocked_until = 0.0
        self._lock = threading.Lock()
        controller.on_lock.append(self._drop)

    def _drop(self) -> None:
        self._paths.clear()
        self._plans.clear()

    def _lease(self) -> Any:
        controller = self._controller
        if not controller.is_unlocked():
            raise ApiError("locked", t("error.lockedProfile"))
        lease = controller.guard.lease()
        controller.require_lease(lease)
        guard = controller.guard
        return lambda: guard.require(lease)  # the sync merge calls this before it touches the vault

    @staticmethod
    def _read(path: Path) -> bytes:
        try:
            with path.open("rb") as handle:
                data = handle.read(MAX_FILE_BYTES + 1)
        except OSError:
            raise ApiError("invalid", t("licence.thatFileCouldNotBe")) from None
        if len(data) > MAX_FILE_BYTES:
            raise ApiError("invalid", str(PhoneBackupError("too-large")))
        return data

    def choose(self) -> dict[str, Any]:
        self._lease()
        chosen = self._dialogs.open_file(t("phoneBackupWeb.restorePhoneBackupLgkm"), tuple(t(x) for x in FILE_TYPES))
        if not chosen:
            raise ApiError("cancelled", t("recovery.noFileWasChosen"))
        path = Path(chosen)
        data = self._read(path)
        try:
            header = inspect_phone_backup(data)
        except PhoneBackupError as exc:
            raise ApiError("invalid", str(exc)) from None
        handle = secrets.token_urlsafe(12)
        self._paths[handle] = path
        created = datetime.fromtimestamp(header.created_at, tz=UTC).strftime("%Y-%m-%d")
        return {"handle": handle, "name": path.name, "platform": header.platform, "created": created}

    def preview(self, handle: str, password: str) -> dict[str, Any]:
        lease = self._lease()
        path = self._paths.get(str(handle or ""))
        if path is None:
            raise ApiError("invalid", t("phoneBackupWeb.chooseABackupFileFirst"))
        if not password:
            raise ApiError("invalid", t("phoneBackupWeb.enterTheBackupPassword"))
        with self._lock:
            if time.monotonic() < self._blocked_until:
                raise ApiError("busy", t("phoneBackupWeb.tooManyAttemptsTryAgain"))
        data = self._read(path)
        now = int(time.time())
        try:
            backup = read_phone_backup(data, password)
        except PhoneBackupError as exc:
            if exc.reason == "wrong-password-or-damaged":
                with self._lock:
                    self._wrong += 1
                    if self._wrong >= MAX_WRONG:
                        self._wrong = 0
                        self._blocked_until = time.monotonic() + LOCKOUT_SECONDS
            raise ApiError("invalid", str(exc)) from None
        with self._lock:
            self._wrong = 0
        try:
            plan = plan_restore(self._controller.session, lease, backup, now=now)
        except PhoneRestoreError as exc:
            raise ApiError("invalid", str(exc)) from None
        except (StaleSession, VaultLockedError):
            raise ApiError("locked", t("error.lockedProfile")) from None
        except BridgeError:
            raise ApiError("invalid", t(UNREADABLE)) from None
        token = secrets.token_urlsafe(12)
        self._plans.clear()  # only the latest preview can be restored
        self._plans[token] = (str(handle), plan)
        lines = [t("phoneBackupWeb.newItems", new=plan.new), t("phoneBackupWeb.itemsUpdatedFromTheBackup", updated=plan.updated),
                 t("phoneBackupWeb.alreadyUpToDate", unchanged=plan.unchanged)]
        if plan.deleted:
            lines.append(_deleted_text(plan.deleted))
        if plan.files:
            lines.append(t("phoneBackupWeb.documentFilesFromTheBackup", v1=len(plan.files)))
        if plan.files_missing:
            lines.append(_missing_text(plan.files_missing, "will be"))
        if plan.skipped:
            lines.append(_skipped_text(plan.skipped, "will be"))
        if plan.held_back:
            lines.append(t("phoneBackupWeb.itemsHeldBackByThe", held_back=plan.held_back))
        if plan.totp_as_field:
            lines.append(t("phoneBackupWeb.twoFactorKeysKeptAs", totp_as_field=plan.totp_as_field))
        return {"token": token, "lines": lines, "status": t("phoneBackupWeb.previewIsReadyReviewIt")}

    def commit(self, token: str, handle: str) -> dict[str, Any]:
        lease = self._lease()
        entry = self._plans.pop(str(token or ""), None)
        if entry is None or entry[0] != str(handle or "") or str(handle) not in self._paths:
            raise ApiError("invalid", t(STALE))
        plan = entry[1]
        self._paths.pop(str(handle), None)
        try:
            report = restore(self._controller.session, lease, plan, now=int(time.time()))
        except (StaleSession, VaultLockedError):
            raise ApiError("locked", t("error.lockedProfile")) from None
        except BridgeError:
            raise ApiError("invalid", t(UNREADABLE)) from None
        fatal = [kind for kind in report.issues if kind not in QUARANTINE]
        if fatal:
            reason = t(FATAL_REASONS.get(fatal[0], "phoneBackupWeb.theVaultCouldNotBeUpdated"))
            return {"lines": [], "status": t("phoneBackupWeb.nothingWasRestored2", reason=reason), "changed": False}
        adopted = self._adopt_licences(lease, report.licenses)
        changed = bool(report.new or report.updated or report.deleted)
        lines = [t("phoneBackupWeb.newItems", new=report.new), t("phoneBackupWeb.itemsUpdatedFromTheBackup", updated=report.updated)]
        if report.deleted:
            lines.append(_deleted_text(report.deleted))
        if report.files:
            lines.append(t("phoneBackupWeb.documentFilesRestored", files=report.files))
        refused = sum(1 for kind in report.issues if kind == "attachment-refused")
        if refused:
            lines.append(t("phoneBackupWeb.documentFilesWereDamagedAnd", refused=refused))
        if report.files_missing:
            lines.append(_missing_text(report.files_missing, "were"))
        if report.held_back:
            lines.append(t("phoneBackupWeb.itemsHeldBackByThe", held_back=report.held_back))
        if report.totp_as_field:
            lines.append(t("phoneBackupWeb.twoFactorKeysKeptAs", totp_as_field=report.totp_as_field))
        if report.skipped and not changed and not adopted:
            status = t("phoneBackupWeb.nothingWasRestored", v1=_skipped_text(report.skipped, 'were'))
        else:
            status = t(DONE)
            if report.skipped:
                status += f" {_skipped_text(report.skipped, 'were')}."
            if adopted:
                status += " " + t("phoneBackupWeb.yourProLicenceWasRestored")
                if report.held_back:
                    status += " " + t("phoneBackupWeb.restoreAgainToBringBack", held_back=report.held_back)
        changed = changed or adopted
        if changed:
            self._controller.touch()
        return {"lines": lines, "status": status, "changed": changed}

    def _adopt_licences(self, lease: Any, received: tuple[dict[str, Any], ...]) -> bool:
        """Offer the restored licences, and every verified one the vault keeps, to the licence store.

        As ``SyncService._adopt_licenses``: under the lease, then the new item
        limit applies at once.  Never raises.
        """
        session = self._controller.session
        bundles = list(received)
        try:
            lease()  # locked meanwhile: install nothing
            try:
                bundles.extend(published_licenses(session))
            except BridgeError:
                _log.warning("Stored licences could not be read for adoption", exc_info=True)
            if not bundles or licensing.adopt_synced_license(session, bundles) is None:
                return False
        except (StaleSession, VaultLockedError):
            return False
        try:
            session.item_limit = licensing.item_limit()
            session.pro_features = licensing.pro_features()
        except Exception:  # noqa: BLE001 - the licence is installed; the next unlock applies the limit
            _log.warning("Item limit could not be applied", exc_info=True)
        if self._on_licence is not None:
            try:
                self._on_licence()
            except Exception:  # noqa: BLE001 - a listener never breaks the restore
                _log.warning("Licence listener failed", exc_info=True)
        return True

    def cancel(self) -> dict[str, Any]:
        self._plans.clear()
        self._paths.clear()
        return {}
