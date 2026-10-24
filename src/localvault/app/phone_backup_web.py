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

_log = logging.getLogger(__name__)

FILE_TYPES = ("LocalGateKeys phone backup (*.lgkm)", "All files (*.*)")
# Sync issue kinds that skip single records while the rest is applied; any other kind means nothing was applied.
QUARANTINE = QUARANTINE_KINDS
FATAL_REASONS = {
    "trash-full": "the trash is full",
    "history-quota": "item history is full",
    "busy": "the vault changed while restoring. Try again",
}
MAX_WRONG = 5
LOCKOUT_SECONDS = 30.0
STALE = "Preview again before restoring."
DONE = "Phone backup restored."
UNREADABLE = "The vault could not be read for the restore."


def _skipped_text(count: int, verb: str) -> str:
    return f"{count} items this version cannot read {verb} skipped"


def _deleted_text(count: int) -> str:
    return f"{count} items moved to the trash (deleted on the phone)"


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
            raise ApiError("locked", "Unlock this profile first.")
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
            raise ApiError("invalid", "That file could not be read.") from None
        if len(data) > MAX_FILE_BYTES:
            raise ApiError("invalid", str(PhoneBackupError("too-large")))
        return data

    def choose(self) -> dict[str, Any]:
        self._lease()
        chosen = self._dialogs.open_file("Restore phone backup (.lgkm)", FILE_TYPES)
        if not chosen:
            raise ApiError("cancelled", "No file was chosen.")
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
            raise ApiError("invalid", "Choose a backup file first.")
        if not password:
            raise ApiError("invalid", "Enter the backup password.")
        with self._lock:
            if time.monotonic() < self._blocked_until:
                raise ApiError("busy", "Too many attempts. Try again in 30 seconds.")
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
            raise ApiError("locked", "Unlock this profile first.") from None
        except BridgeError:
            raise ApiError("invalid", UNREADABLE) from None
        token = secrets.token_urlsafe(12)
        self._plans.clear()  # only the latest preview can be restored
        self._plans[token] = (str(handle), plan)
        lines = [f"{plan.new} new items", f"{plan.updated} items updated from the backup",
                 f"{plan.unchanged} already up to date"]
        if plan.deleted:
            lines.append(_deleted_text(plan.deleted))
        if plan.skipped:
            lines.append(_skipped_text(plan.skipped, "will be"))
        if plan.held_back:
            lines.append(f"{plan.held_back} items held back by the free plan's 4-item limit")
        if plan.totp_as_field:
            lines.append(f"{plan.totp_as_field} two-factor keys kept as hidden fields "
                         "(two-factor codes need Pro)")
        return {"token": token, "lines": lines, "status": "Preview is ready. Review it, then restore."}

    def commit(self, token: str, handle: str) -> dict[str, Any]:
        lease = self._lease()
        entry = self._plans.pop(str(token or ""), None)
        if entry is None or entry[0] != str(handle or "") or str(handle) not in self._paths:
            raise ApiError("invalid", STALE)
        plan = entry[1]
        self._paths.pop(str(handle), None)
        try:
            report = restore(self._controller.session, lease, plan, now=int(time.time()))
        except (StaleSession, VaultLockedError):
            raise ApiError("locked", "Unlock this profile first.") from None
        except BridgeError:
            raise ApiError("invalid", UNREADABLE) from None
        fatal = [kind for kind in report.issues if kind not in QUARANTINE]
        if fatal:
            reason = FATAL_REASONS.get(fatal[0], "the vault could not be updated")
            return {"lines": [], "status": f"Nothing was restored: {reason}.", "changed": False}
        adopted = self._adopt_licences(lease, report.licenses)
        changed = bool(report.new or report.updated or report.deleted)
        lines = [f"{report.new} new items", f"{report.updated} items updated from the backup"]
        if report.deleted:
            lines.append(_deleted_text(report.deleted))
        if report.held_back:
            lines.append(f"{report.held_back} items held back by the free plan's 4-item limit")
        if report.totp_as_field:
            lines.append(f"{report.totp_as_field} two-factor keys kept as hidden fields "
                         "(two-factor codes need Pro)")
        if report.skipped and not changed and not adopted:
            status = f"Nothing was restored: {_skipped_text(report.skipped, 'were')}."
        else:
            status = DONE
            if report.skipped:
                status += f" {_skipped_text(report.skipped, 'were')}."
            if adopted:
                status += " Your Pro licence was restored."
                if report.held_back:
                    status += f" Restore again to bring back the {report.held_back} held-back items."
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
