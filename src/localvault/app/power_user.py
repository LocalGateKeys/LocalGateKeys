"""Sub-plan 12 for the WebView UI: restore test, change-password page, health report, estate pack.

Thin page-facing layer over ``restore_test``, ``change_password``, ``health_report`` and ``estate_pack``. Every
method needs an unlocked vault and its lease; passwords arrive as ``SecretText`` and are wiped by the bridge.
"""
from __future__ import annotations

import time
import webbrowser
from pathlib import Path
from typing import Any

from .. import change_password, estate_pack, health_report, restore_test
from ..api.result import ApiError
from ..i18n import t


class PowerUserService:
    def __init__(self, controller: Any, port: Any, dialogs: Any, *, clock: Any = time.time,
                 open_url: Any = webbrowser.open) -> None:
        self._controller = controller
        self._port = port
        self._dialogs = dialogs
        self._clock = clock
        self._open_url = open_url

    # ------------------------------------------------------------------ helpers
    def _session(self) -> Any:
        if not self._controller.is_unlocked():
            raise ApiError("locked", t("error.lockedProfile"))
        self._controller.require_lease(self._controller.guard.lease())
        return self._controller.session

    def _profile_dir(self) -> Path:
        profile = self._controller.profiles.active_profile()
        if profile is None:
            raise ApiError("locked", t("error.lockedProfile"))
        return Path(self._controller.profiles.profile_dir(profile.id))

    def _state(self) -> Path:
        return restore_test.state_path(self._profile_dir())

    # ------------------------------------------------------------- restore test
    def restore_status(self) -> dict[str, Any]:
        self._session()
        now = int(self._clock())
        last = restore_test.load(self._state())
        enabled = bool(getattr(self._controller.settings, "restore_test_weekly", True))
        return {"text": restore_test.row_text(last, now), "ok": bool(last and last.ok),
                "due": restore_test.due(last, now, enabled=enabled), "enabled": enabled}

    def restore_pick(self) -> dict[str, Any]:
        self._session()
        path = self._dialogs.open_file(t("restoreTest.pickTitle"), (t("restoreTest.fileTypes") + " (*.lgk;*.lgkfull)", t("phoneBackupWeb.allFiles")))
        if not path:
            raise ApiError("cancelled", t("error.cancelled"))
        return {"path": str(path), "name": Path(str(path)).name}

    def restore_run(self, path: str, backup_password: Any, vault_password: Any = None) -> dict[str, Any]:
        self._session()
        source = Path(path)
        if source.suffix.lower() not in (".lgkfull", ".lgk") or not source.is_file():
            raise ApiError("invalid", t("restoreTest.reason.unreadable"))
        result = restore_test.run(self._controller.settings, int(self._clock()), backup_path=source,
                                  backup_password=backup_password, vault_password=vault_password)
        restore_test.save(self._state(), result)
        return {**self.restore_status(), "passed": result.ok}

    # ------------------------------------------------------- change password page
    def change_password_open(self, entry_id: str) -> dict[str, Any]:
        session = self._session()
        entry = session.get_entry(entry_id)
        if not entry:
            raise ApiError("not_found", t("share.thisItemNoLongerExists"))
        try:
            url, source = change_password.change_url(entry)
        finally:
            entry.clear()
        if not url:
            raise ApiError("no_website", t("changePassword.noPage"))
        note = t("changePassword.loginUrlNote") if source == "login-url" else ""
        self._open_url(url)
        return {"url": url, "source": source, "note": note}

    # ------------------------------------------------------------ health report
    def health_facts(self) -> dict[str, Any]:
        facts: dict[str, Any] = {}
        now = int(self._clock())
        last = restore_test.load(self._state())
        facts["restore_test"] = restore_test.row_text(last, now)
        try:
            from .. import licensing

            facts["licence"] = licensing.status().state
        except Exception:  # noqa: BLE001, S110 - a fact, never a failure
            pass
        try:
            from ..backup_schedule import SCHEDULED_DIR_NAME, read_last_success

            when = read_last_success(self._controller.profiles.backups_dir(self._controller.profiles.active_profile().id) / SCHEDULED_DIR_NAME)
            if when is not None:
                facts["backup_age"] = t("healthReport.daysAgo", days=max(0, (now - int(when.timestamp())) // 86400))
        except Exception:  # noqa: BLE001, S110
            pass
        return facts

    def health_print(self, page: str = "a4") -> dict[str, Any]:
        session = self._session()
        if page not in health_report.PAGE_SIZES:
            page = "a4"
        target = self._dialogs.save_file(t("healthReport.title"), "vault-health-report.pdf")
        if not target:
            raise ApiError("cancelled", t("error.cancelled"))
        data = health_report.render(session, self._controller.settings, now=int(self._clock()),
                                    facts=self.health_facts(), page=page)
        Path(str(target)).write_bytes(data)
        return {"message": t("healthReport.saved"), "path": str(target)}

    # -------------------------------------------------------------- estate pack
    def estate_create(self) -> dict[str, Any]:
        session = self._session()
        try:
            from .. import heir

            holders = heir.holder_nicknames(session)
        except Exception:  # noqa: BLE001 - no emergency access set up: the heading stays empty
            holders = []
        item_id = estate_pack.create(session, holders)
        try:
            self._controller._publish()
        except Exception:  # noqa: BLE001, S110
            pass
        return {"id": item_id, "message": t("estate.created")}
