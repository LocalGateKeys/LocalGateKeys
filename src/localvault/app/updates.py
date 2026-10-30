"""Update checks for the WebView UI, following ``FeatureUI.check_updates_clicked``.

Strict offline mode asks before each check (and stays on). One check runs at a
time; it blocks only the bridge worker thread that pywebview gave the call.
"""
from __future__ import annotations

import threading
from typing import Any, Callable

from .. import licensing, updates
from ..api.result import ApiError
from ..config import BRAND_NAME
from ..i18n import t

OFFLINE_TEXT = ("updates.checkForUpdatesOnceAnyway")


class UpdatesService:
    def _refresh_revocations(self) -> None:
        """After a successful check: refresh the signed licence revocation list (never surfaced)."""
        try:
            self._revocations()
        except Exception as exc:  # noqa: BLE001 - the cached list stays in force
            from ..error_log import log_exception

            log_exception("revocation-fetch", exc)

    def __init__(self, controller: Any, port: Any, *,
                 configuration: Callable[[], Any] = updates.release_configuration,
                 check: Callable[[], Any] = updates.check_for_updates,
                 managed: Callable[[], str | None] = updates.managed_update_channel,
                 revocations: Callable[[], Any] = updates.fetch_revocations) -> None:
        self._controller = controller
        self._port = port
        self._configuration = configuration
        self._check = check
        self._managed = managed
        self._revocations = revocations
        self._in_flight = threading.Lock()
        self._snooze_lock = threading.Lock()

    def check(self) -> dict[str, Any]:
        """Run one update check. In strict offline mode Python itself asks first, every time.

        There is deliberately no caller-supplied consent flag: the page (or a
        script injected into it) can never waive the strict offline question.
        """
        try:
            config = self._configuration()
        except updates.UpdateCheckError as exc:
            raise ApiError("invalid", str(exc)) from None
        if config is None:
            managed_by = self._managed()
            if managed_by and not bool(getattr(self._controller.settings, "strict_offline_mode", True)):
                # Store/MSIX builds have no release check, but still refresh the signed licence
                # revocation list when the user asks and network use is allowed.
                self._refresh_revocations()
            return {"available": False,
                    "message": t("updates.updatesAreInstalledBy", BRAND_NAME=BRAND_NAME, managed_by=managed_by) if managed_by
                    else t("updates.updateChecksAreNotConfigured2")}
        if bool(getattr(self._controller.settings, "strict_offline_mode", True)):
            if not self._port.confirm(t("updates.strictOfflineModeIsOn"), t(OFFLINE_TEXT)):
                raise ApiError("cancelled", t("error.cancelled"))
        if not self._in_flight.acquire(blocking=False):
            raise ApiError("busy", t("updates.anUpdateCheckIsAlready"))
        try:
            result = self._check()
        except updates.UpdateCheckError as exc:
            raise ApiError("update_failed", str(exc) or t("updates.theReleaseFeedCouldNot")) from None
        except Exception:  # noqa: BLE001
            raise ApiError("update_failed", t("updates.theReleaseFeedCouldNot")) from None
        finally:
            self._in_flight.release()
        self._refresh_revocations()
        if result is None:
            return {"available": False, "message": t("updates.updateChecksAreNotConfigured")}
        if result.is_newer:
            try:
                note = licensing.update_coverage_note(result.published)
            except Exception:  # noqa: BLE001
                note = None
            return {"available": True, "current": result.current_version, "latest": result.latest_version,
                    "note": note or "", "message": t("updates.aNewerVersionIsAvailable")}
        return {"available": False,
                "message": t("updates.localgatekeysIsUpToDate", current_version=result.current_version)}

    def open_release_page(self) -> dict[str, Any]:
        try:
            opened = updates.open_release_page()
        except Exception:  # noqa: BLE001
            opened = False
        if not opened:
            raise ApiError("invalid", t("updates.theConfiguredReleasePageCould"))
        return {}

    def reminder(self) -> dict[str, Any]:
        """After unlock: is this build old enough to suggest a check? Uses no network."""
        try:
            if self._configuration() is None:
                return {"due": False}
        except updates.UpdateCheckError:
            return {"due": False}
        if not updates.update_reminder_due(self._controller.settings.update_reminder_snoozed_until):
            return {"due": False}
        days = updates.build_age_days()
        return {"due": True, "title": t("updates.checkForUpdates"), "text": (
            t("updates.thisVersionOfLocalgatekeysIs", days=days))}

    def snooze(self) -> dict[str, Any]:
        with self._snooze_lock:
            settings = self._controller.settings
            settings.update_reminder_snoozed_until = updates.reminder_snooze_date()
            try:
                settings.save()
            except OSError:
                raise ApiError("invalid", t("settings.error.notSaved")) from None
        return {}
