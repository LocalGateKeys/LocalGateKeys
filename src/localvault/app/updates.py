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

OFFLINE_TEXT = ("Check for updates once anyway?\n\nThis check sends two requests: one for release information and "
                "one for the licence revocation list. Both contain only the app version, never vault data. Strict "
                "offline mode stays on.")


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
                    "message": f"{BRAND_NAME} updates are installed by {managed_by}." if managed_by
                    else "Update checks are not configured yet. Release hosting has not been published."}
        if bool(getattr(self._controller.settings, "strict_offline_mode", True)):
            if not self._port.confirm("Strict offline mode is on", OFFLINE_TEXT):
                raise ApiError("cancelled", "Cancelled.")
        if not self._in_flight.acquire(blocking=False):
            raise ApiError("busy", "An update check is already running.")
        try:
            result = self._check()
        except updates.UpdateCheckError as exc:
            raise ApiError("update_failed", str(exc) or "The release feed could not be checked.") from None
        except Exception:  # noqa: BLE001
            raise ApiError("update_failed", "The release feed could not be checked.") from None
        finally:
            self._in_flight.release()
        self._refresh_revocations()
        if result is None:
            return {"available": False, "message": "Update checks are not configured yet."}
        if result.is_newer:
            try:
                note = licensing.update_coverage_note(result.published)
            except Exception:  # noqa: BLE001
                note = None
            return {"available": True, "current": result.current_version, "latest": result.latest_version,
                    "note": note or "", "message": "A newer version is available."}
        return {"available": False,
                "message": f"LocalGateKeys is up to date. Current version: {result.current_version}."}

    def open_release_page(self) -> dict[str, Any]:
        try:
            opened = updates.open_release_page()
        except Exception:  # noqa: BLE001
            opened = False
        if not opened:
            raise ApiError("invalid", "The configured release page could not be opened.")
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
        return {"due": True, "title": "Check for updates?", "text": (
            f"This version of LocalGateKeys is {days} days old and may be missing security fixes.\n\nCheck for a "
            "newer version now? This check sends two requests (release information and the licence revocation "
            "list). Both contain only the app version, never vault data.")}

    def snooze(self) -> dict[str, Any]:
        with self._snooze_lock:
            settings = self._controller.settings
            settings.update_reminder_snoozed_until = updates.reminder_snooze_date()
            try:
                settings.save()
            except OSError:
                raise ApiError("invalid", "The setting could not be saved.") from None
        return {}
