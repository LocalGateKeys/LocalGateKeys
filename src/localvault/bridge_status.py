"""Non-secret, stable diagnostics for the local browser bridge.

Messages are fixed strings, never exception text or request data. This module
uses only the standard library so the native host can report missing packages.
"""
from __future__ import annotations

from typing import Any

from .version import RELEASE_ID

BRIDGE_REVISION = RELEASE_ID

MESSAGES = {
    "agent_state_missing": "No running-agent connection file was found. Finish choosing a profile in LocalGateKeys. If the main window is already open, restart it from the same repository as the browser bridge.",
    "agent_state_invalid": "The saved bridge connection is invalid or from an older app. Exit LocalGateKeys fully, then restart it from the current repository.",
    "agent_access_denied": "Windows denied access to the local bridge. Run the app and browser as the same Windows user, without Administrator mode, then repair the current-user bridge.",
    "agent_unavailable": "The registered local connection is not accepting requests. If LocalGateKeys is open, exit it fully (including the tray), then restart the repository copy.",
    "agent_busy": "The local bridge is busy. Finish any open LocalGateKeys dialog, then try again.",
    "agent_connection_lost": "The bridge disconnected before replying. Keep LocalGateKeys open; repair the bridge if this repeats. The request was not automatically retried.",
    "agent_connection_changed": "The running agent does not match this connection. Restart LocalGateKeys from the same repository as the repaired browser bridge.",
    "client_not_allowed": "The running app rejected the native-host identity. Exit LocalGateKeys, run scripts\\repair_browser_bridge.ps1 from the repository, then restart the app.",
    "client_pin_unregistered": "No browser native-messaging registration for LocalGateKeys was found for this Windows user, so the app cannot verify which native host to trust. Repair the browser bridge from Connections, then restart the app.",
    "client_pin_mismatch": "The connecting native host is not the executable registered with the browser (or install.json disagrees with that registration). Repair the browser bridge so both point at the same current installation, then restart the app.",
    "client_signer_mismatch": "The native host is outside the installed app folder or is not signed by the same publisher as the running app. Reinstall LocalGateKeys from the official installer and repair the browser bridge.",
    "tcp_fallback_disabled": "The loopback TCP transport is disabled. It is a non-Windows development fallback; set LOCALGATEKEYS_ALLOW_TCP_FALLBACK=1 to enable it deliberately.",
    "unauthorized": "The app rejected a stale bridge token. Exit LocalGateKeys fully and restart the repository copy; then reload the login page.",
    "bridge_dependencies_missing": "The native host cannot load its required packages. In the repository run .\\.venv\\Scripts\\python.exe -m pip install -e . and repair the browser bridge.",
    "bridge_protocol_error": "The local bridge returned an invalid response. Update the desktop bridge files together and restart LocalGateKeys.",
    "caller_not_browser": "LocalGateKeys accepts browser requests only from a native host started by a signed Chrome, Edge, Brave, Firefox, Vivaldi or Opera. Restart the browser; if this repeats, repair the browser bridge from Connections.",
    "rate_limited": "Too many password checks from this site in a short time. Wait a minute and try again.",
    "bridge_internal_error": "The bridge encountered an internal error, not proof that the app is closed. Run scripts\\test_browser_bridge.ps1 and share its sanitized report.",
}


_WARNINGS: list[str] = []
_WARNING_CODES = {"agent_token_unprotected", "legacy_gesture_compat_used", "tcp_fallback_enabled"}


def record_warning(code: str) -> None:
    """Remember a fixed, non-secret diagnostics warning code (deduplicated)."""
    if code in _WARNING_CODES and code not in _WARNINGS:
        _WARNINGS.append(code)


def warnings() -> list[str]:
    return list(_WARNINGS)


def clear_warnings() -> None:
    _WARNINGS.clear()


class BridgeFailure(Exception):
    def __init__(self, code: str, stage: str, winerror: int | None = None):
        self.code = code if code in MESSAGES else "bridge_internal_error"
        self.stage = stage
        self.winerror = winerror
        super().__init__(MESSAGES[self.code])


def error_number(exc: BaseException) -> int | None:
    """pywintypes.error may put its numeric code in args, not .winerror."""
    value = getattr(exc, "winerror", None)
    if type(value) is int:
        return value
    if exc.args and type(exc.args[0]) is int:
        return exc.args[0]
    value = getattr(exc, "errno", None)
    return value if type(value) is int else None


def failure_response(code: str, *, stage: str = "forward", winerror: int | None = None) -> dict[str, Any]:
    code = code if code in MESSAGES else "bridge_internal_error"
    stages = {"state", "imports", "connect", "peer", "send", "receive", "forward", "listener", "diagnostic"}
    response: dict[str, Any] = {"ok": False, "error": code, "message": MESSAGES[code],
                                "bridge_revision": BRIDGE_REVISION,
                                "stage": stage if stage in stages else "forward"}
    if type(winerror) is int and 0 <= winerror <= 65535:
        response["winerror"] = winerror
    return response


def classify_failure(exc: BaseException, stage: str) -> dict[str, Any]:
    if isinstance(exc, BridgeFailure):
        return failure_response(exc.code, stage=exc.stage, winerror=exc.winerror)
    number = error_number(exc)
    if isinstance(exc, ImportError):
        code = "bridge_dependencies_missing"
    elif isinstance(exc, PermissionError) or number == 5:
        code = "agent_access_denied"
    elif stage == "state":
        code = "agent_state_missing" if isinstance(exc, FileNotFoundError) else "agent_state_invalid"
    elif isinstance(exc, (EOFError, BrokenPipeError, ConnectionResetError)) or number in (109, 232, 233):
        code = "agent_connection_lost"
    elif stage == "connect" and (isinstance(exc, FileNotFoundError) or number in (2, 3)):
        code = "agent_unavailable"
    elif isinstance(exc, TimeoutError) or number in (121, 231):
        code = "agent_busy"
    elif isinstance(exc, ConnectionRefusedError):
        code = "agent_unavailable"
    elif isinstance(exc, ValueError):
        code = "agent_state_invalid" if stage in ("state", "connect") else "bridge_protocol_error"
    else:
        code = "bridge_internal_error"
    return failure_response(code, stage=stage, winerror=number)
