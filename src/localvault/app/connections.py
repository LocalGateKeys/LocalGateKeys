"""Devices & connections (browser-extension status) for the WebView UI, from ``FeatureUI.connections_clicked``."""
from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, Callable

from ..api.result import ApiError
from ..i18n import t

FRIENDLY = {
    "ready": "connections.ready", "not_registered": "connections.notRegistered", "not_registered_or_manifest_missing": "connections.notRegistered",
    "launcher_missing": "connections.launcherMissing", "manifest_mismatch": "connections.needsRepair",
    "invalid_registration": "connections.invalidRegistration",
}
FOOTER = ("connections.noRecentConnectionOpenThe")


def _collect(**kwargs: Any) -> dict[str, Any]:
    from ..diagnostics import collect

    return collect(**kwargs)


def _repair() -> Any:
    from ..browser_bridge import repair_browser_bridge

    return repair_browser_bridge()


class ConnectionsService:
    def __init__(self, port: Any, dialogs: Any, *, collect: Callable[..., dict[str, Any]] = _collect,
                 repair: Callable[[], Any] = _repair,
                 extension: Callable[[], tuple[str, float]] = lambda: ("", 0.0)) -> None:
        self._port = port
        self._dialogs = dialogs
        self._collect = collect
        self._repair = repair
        self._extension = extension

    def _report(self) -> dict[str, Any]:
        version, seen = self._extension()
        return self._collect(extension_version=version, extension_seen=seen)

    def view(self) -> dict[str, Any]:
        report = self._report()
        registrations = report.get("registration", {}) if isinstance(report.get("registration"), dict) else {}
        ready = [name for name, state in registrations.items() if state == "ready"]
        host_ready = bool(report.get("native_host_exists") and report.get("native_host_hash_matches"))
        if not report.get("windows"):
            headline, summary, status, tone = (
                t("connections.windowsBrowserConnection"),
                t("connections.browserExtensionConnectionsAreAvailable"),
                t("connections.thisEnvironmentIsLocalOnly"), "neutral")
        elif ready and report.get("extension_recent"):
            headline, summary, status, tone = (
                t("connections.connectedToYourBrowser"), t("connections.theExtensionCheckedInRecently", v1=', '.join(ready)),
                "Ready", "success")
        elif ready and host_ready:
            headline, summary, status, tone = (
                t("connections.bridgeIsReady"),
                t("connections.theNativeBridgeIsInstalled"),
                t("connections.waitingForExtension"), "warning")
        elif not report.get("configured") or not report.get("native_host_exists"):
            headline, summary, status, tone = (
                t("connections.connectionNeedsSetup"), t("connections.theNativeBridgeIsNot"),
                t("connections.actionNeeded"), "warning")
        else:
            headline, summary, status, tone = (
                t("connections.connectionNeedsAttention"),
                t("connections.refreshTheBridgeRegistrationThen"),
                t("connections.actionNeeded"), "warning")
        browsers = []
        if registrations:
            for browser in ("Chrome", "Edge"):
                state = str(registrations.get(browser, "not_registered"))
                browsers.append({"browser": browser, "state": t(FRIENDLY[state]) if state in FRIENDLY else state.replace("_", " ").title(),
                                 "ok": state == "ready"})
        return {"headline": headline, "summary": summary, "status": status, "tone": tone, "browsers": browsers,
                "empty": "" if registrations else t("connections.useTheWindowsDesktopBuild"),
                "can_repair": bool(report.get("windows")), "details": json.dumps(report, indent=2), "footer": t(FOOTER)}

    def repair(self) -> dict[str, Any]:
        if os.name != "nt":
            raise ApiError("unsupported", t("connections.bridgeRegistrationRepairIsAvailable"))
        if not self._port.confirm(t("connections.repairCurrentUserBridge"),
                                  t("connections.recreatesTheLocalgatekeysNativeHost")):
            raise ApiError("cancelled", t("error.cancelled"))
        try:
            self._repair()
        except Exception as exc:  # noqa: BLE001 - details go to the local error log, not the page
            from ..error_log import log_exception

            log_exception("browser-bridge-repair", exc)
            raise ApiError("repair_failed", t("connections.repairFailedDetailsAreIn")) from None
        return {"title": t("connections.browserConnectionRepaired"),
                "message": t("connections.nativeHostRegistrationWasRefreshed")}

    def export(self) -> dict[str, Any]:
        target = self._dialogs.save_file(t("connectionsPage.export"), "localgatekeys-diagnostics.json")
        if not target:
            raise ApiError("cancelled", t("recovery.noFileWasChosen"))
        # Serialise the whitelist-only report, never text from the page.
        Path(target).write_text(json.dumps(self._report(), indent=2), encoding="utf-8")
        return {"message": t("connections.reportSaved")}
