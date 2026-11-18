"""Passkey doctor (feature idea 3, Windows slice): read-only checks of how passkeys reach this app.

* Is LocalGateKeys the active Windows passkey provider? From the cached ``--state`` Windows last reported
  (``windows_passkey_provider.REGISTRATION``); asking for the page only starts a background re-read, never a write.
* Which browsers have the native host registered, and has the extension checked in recently?
* A button opens the Windows passkeys settings page (fixed ``ms-settings`` URI).

Nothing here registers, repairs or changes anything; the Connections page and the provider switch do that.
"""
from __future__ import annotations

from typing import Any, Callable

from ..i18n import t


def _collect(**kwargs: Any) -> dict[str, Any]:
    from ..diagnostics import collect

    return collect(**kwargs)


def _provider() -> dict[str, Any]:
    from .. import windows_passkey_provider as provider

    available = provider.available()
    if available:
        provider.REGISTRATION.refresh_later()
    return {"available": available, "state": provider.REGISTRATION.current() if available else None}


def _open_settings() -> None:
    from ..windows_passkey_provider import open_windows_settings

    open_windows_settings()


def provider_status(available: bool, setting_on: bool, state: str | None) -> tuple[str, str]:
    """(code, one-line text) for Settings › Autofill and the doctor: active / not_active / off / unavailable /
    checking."""
    if not available:
        return "unavailable", t("passkeyDoctor.providerUnavailable")
    if not setting_on:
        return "off", t("passkeyDoctor.providerOff")
    if state == "enabled":
        return "active", t("passkeyDoctor.providerActive")
    if state in {"disabled", "not_registered"}:
        return "not_active", t("passkeyDoctor.providerNotActive")
    return "checking", t("passkeyDoctor.providerChecking")


def _host_detail(report: dict[str, Any]) -> str:
    """The host row's text, matching its mark: installed and matching, missing, or not this version's host."""
    if not report.get("native_host_exists"):
        return t("passkeyDoctor.hostMissing")
    if not report.get("native_host_hash_matches"):
        return t("passkeyDoctor.hostMismatch")
    return t("passkeyDoctor.yes")


BROWSER_STATES = {"ready":"passkeyDoctor.browserReady", "not_registered": "passkeyDoctor.browserNotRegistered"}


class PasskeyDoctorService:
    def __init__(self, settings: Callable[[], Any], *, collect: Callable[..., dict[str, Any]] = _collect,
                 provider: Callable[[], dict[str, Any]] = _provider,
                 extension: Callable[[], tuple[str, float]] = lambda: ("", 0.0),
                 open_settings: Callable[[], None] = _open_settings) -> None:
        self._settings = settings
        self._collect = collect
        self._provider = provider
        self.extension = extension
        self._open = open_settings

    def status_line(self) -> dict[str, Any]:
        """Quick win 3: the one-line provider status shown in Settings › Autofill."""
        info = self._provider()
        code, text = provider_status(bool(info.get("available")),
                                     getattr(self._settings(), "windows_passkey_provider", False) is True,
                                     info.get("state"))
        return {"code": code, "text": text}

    def view(self) -> dict[str, Any]:
        settings = self._settings()
        line = self.status_line()
        version, seen = self.extension()
        report = self._collect(extension_version=version, extension_seen=seen)
        registrations = report.get("registration") if isinstance(report.get("registration"), dict) else {}
        browsers = []
        for browser in ("Chrome", "Edge", "Firefox"):
            state = str(registrations.get(browser, "not_registered"))
            browsers.append({"browser": browser, "ok": state == "ready",
                             "state": t(BROWSER_STATES.get(state, "passkeyDoctor.browserNeedsRepair"))})
        checks = [
            {"key": "provider", "ok": line["code"] == "active", "label": t("passkeyDoctor.checkProvider"),
             "detail": line["text"]},
            {"key": "passkeys", "ok": getattr(settings, "passkeys_enabled", False) is True,
             "label": t("passkeyDoctor.checkPasskeysOn"),
             "detail": t("passkeyDoctor.yes") if getattr(settings, "passkeys_enabled", False) is True
             else t("passkeyDoctor.passkeysOff")},
            {"key": "host", "ok": bool(report.get("native_host_exists") and report.get("native_host_hash_matches")),
             "label": t("passkeyDoctor.checkHost"),
             "detail": _host_detail(report)},
            {"key": "extension", "ok": bool(report.get("extension_recent")), "label": t("passkeyDoctor.checkExtension"),
             "detail": t("passkeyDoctor.extensionRecent") if report.get("extension_recent")
             else t("passkeyDoctor.extensionNotSeen")},
        ]
        return {"provider": line, "browsers": browsers, "checks": checks, "windows": bool(report.get("windows")),
                "note": t("passkeyDoctor.readOnlyNote")}

    def open_settings(self) -> dict[str, Any]:
        self._open()
        return {}
