"""Devices & connections (browser-extension status) for the WebView UI, from ``FeatureUI.connections_clicked``."""
from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, Callable

from ..api.result import ApiError

FRIENDLY = {
    "ready": "Ready", "not_registered": "Not registered", "not_registered_or_manifest_missing": "Not registered",
    "launcher_missing": "Launcher missing", "manifest_mismatch": "Needs repair",
    "invalid_registration": "Invalid registration",
}
FOOTER = ("No recent connection? Open the browser extension → Connection test. Keep this app running. Version "
          "mismatch? Update both the desktop files and extension, then reload the page.")


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
                "Windows browser connection",
                "Browser extension connections are available in the Windows desktop build.",
                "This environment is local-only.", "neutral")
        elif ready and report.get("extension_recent"):
            headline, summary, status, tone = (
                "Connected to your browser", f"The extension checked in recently through {', '.join(ready)}.",
                "Ready", "success")
        elif ready and host_ready:
            headline, summary, status, tone = (
                "Bridge is ready",
                "The native bridge is installed. Open the extension on a website to test the connection.",
                "Waiting for extension", "warning")
        elif not report.get("configured") or not report.get("native_host_exists"):
            headline, summary, status, tone = (
                "Connection needs setup", "The native bridge is not configured for this installation yet.",
                "Action needed", "warning")
        else:
            headline, summary, status, tone = (
                "Connection needs attention",
                "Refresh the bridge registration, then reload the browser extension and run its connection test.",
                "Action needed", "warning")
        browsers = []
        if registrations:
            for browser in ("Chrome", "Edge"):
                state = str(registrations.get(browser, "not_registered"))
                browsers.append({"browser": browser, "state": FRIENDLY.get(state, state.replace("_", " ").title()),
                                 "ok": state == "ready"})
        return {"headline": headline, "summary": summary, "status": status, "tone": tone, "browsers": browsers,
                "empty": "" if registrations else "Use the Windows desktop build to connect Chrome or Edge.",
                "can_repair": bool(report.get("windows")), "details": json.dumps(report, indent=2), "footer": FOOTER}

    def repair(self) -> dict[str, Any]:
        if os.name != "nt":
            raise ApiError("unsupported", "Bridge registration repair is available on Windows.")
        if not self._port.confirm("Repair current-user bridge?",
                                  "Recreates the LocalGateKeys native-host manifest and Chrome/Edge registration for "
                                  "this installation. Vault data is not changed. Reload the extension afterward."):
            raise ApiError("cancelled", "Cancelled.")
        try:
            self._repair()
        except Exception as exc:  # noqa: BLE001 - details go to the local error log, not the page
            from ..error_log import log_exception

            log_exception("browser-bridge-repair", exc)
            raise ApiError("repair_failed", "Repair failed. Details are in the error log.") from None
        return {"title": "Browser connection repaired",
                "message": "Native-host registration was refreshed. Fully close and reopen the browser, then run "
                           "the extension Connection test."}

    def export(self) -> dict[str, Any]:
        target = self._dialogs.save_file("Export report", "localgatekeys-diagnostics.json")
        if not target:
            raise ApiError("cancelled", "No file was chosen.")
        # Serialise the whitelist-only report, never text from the page.
        Path(target).write_text(json.dumps(self._report(), indent=2), encoding="utf-8")
        return {"message": "Report saved."}
