"""Read-only connection test through the pinned native-host executable.

Use ``python -m localvault.bridge_diagnostics`` from the repository environment.
Only a protocol ping is sent. Credentials are never requested. Profile names and
session tokens present in the ping reply are discarded, not logged or printed.
"""
from __future__ import annotations

import io
import json
import os
import re
import subprocess
from pathlib import Path
from typing import Any

from .bridge_status import BRIDGE_REVISION, MESSAGES, error_number, record_warning, warnings
from .config import (
    EXTENSION_ORIGINS,
    NATIVE_HOST_NAME,
    agent_state_path,
    install_config_path,
    read_json,
)
from .distribution import resolve_native_host_path
from .native_host import _read_native_message, _write_native_message
from .pipe_transport import ClientPinPolicy, _sha256_file
from .version import APP_VERSION, PROTOCOL_VERSION


def _pin_matches(path: Any, expected: Any) -> bool:
    if not isinstance(path, str) or not isinstance(expected, str) or not re.fullmatch(r"[0-9a-fA-F]{64}", expected):
        return False
    try:
        return Path(path).is_file() and _sha256_file(path) == expected.upper()
    except OSError:
        return False


def _same_path(left: str, right: str) -> bool:
    return os.path.normcase(os.path.abspath(left)) == os.path.normcase(os.path.abspath(right))


def _registered_host_status(browser: str, config: dict[str, Any]) -> str:
    import winreg
    sub = {"Chrome": r"Google\Chrome", "Edge": r"Microsoft\Edge", "Firefox": "Mozilla"}[browser]
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, f"Software\\{sub}\\NativeMessagingHosts\\{NATIVE_HOST_NAME}") as key:
            manifest_path = winreg.QueryValue(key, None)
        manifest = read_json(Path(manifest_path))
        if manifest.get("name") != NATIVE_HOST_NAME or manifest.get("type") != "stdio":
            return "invalid_manifest"
        registered = resolve_native_host_path(str(manifest.get("path", "")))
        if not _same_path(registered, str(config.get("native_host_path", ""))):
            return "different_native_host_copy"
        if browser == "Firefox":
            from .native_host import FIREFOX_EXTENSION_ID
            allowed = manifest.get("allowed_extensions", [])
            if FIREFOX_EXTENSION_ID not in allowed:
                return "extension_id_mismatch"
            return "ready"
        allowed = manifest.get("allowed_origins", [])
        if not any(origin in allowed for origin in EXTENSION_ORIGINS):
            return "extension_id_mismatch"
        return "ready"
    except FileNotFoundError:
        return "not_registered_or_missing_manifest"
    except PermissionError:
        return "access_denied"
    except (OSError, ValueError, TypeError):
        return "invalid_registration"


def _redacted_ping(response: dict[str, Any]) -> dict[str, Any]:
    """Allowlist-only output, including for hostile/unexpected error replies."""
    if response.get("ok") is True:
        result: dict[str, Any] = {"status": "connected"}
        v = response.get("version")
        if isinstance(v, str) and re.fullmatch(r"\d{1,3}\.\d{1,3}\.\d{1,3}", v):
            result["desktop_version"] = v
        if type(response.get("protocol")) is int:
            result["protocol"] = response["protocol"]
        if type(response.get("locked")) is bool:
            result["vault_locked"] = response["locked"]
        if type(response.get("browser_enabled")) is bool:
            result["browser_integration_enabled"] = response["browser_enabled"]
        return result
    code = response.get("error")
    allowed = set(MESSAGES) | {"agent_offline", "protocol_error", "version_mismatch", "caller_not_allowed", "busy"}
    result = {"status": "failed", "error": code if isinstance(code, str) and code in allowed else "unexpected_native_reply"}
    if result["error"] in MESSAGES:
        result["message"] = MESSAGES[result["error"]]
    stage = response.get("stage")
    if stage in ("state", "imports", "connect", "peer", "send", "receive", "forward", "listener"):
        result["stage"] = stage
    n = response.get("winerror")
    if type(n) is int and 0 <= n <= 65535:
        result["winerror"] = n
    return result


def _kill_test_process(process: subprocess.Popen) -> None:
    """Stop only the launcher tree created for this ping, never the app/browser."""
    try:
        import psutil
        children = psutil.Process(process.pid).children(recursive=True)
        for child in reversed(children):
            try:
                child.kill()
            except psutil.Error:
                pass
    except Exception:
        pass
    try:
        process.kill()
        process.communicate(timeout=2)
    except Exception:
        pass


def _ping_host(config: dict[str, Any], *, timeout: float = 12.0) -> dict[str, Any]:
    if not _pin_matches(config.get("native_host_path"), config.get("native_host_sha256")):
        return {"status": "not_launched", "error": "native_host_pin_mismatch"}
    allowed = config.get("allowed_extension_origins", [])
    origin = next((v for v in EXTENSION_ORIGINS if v in allowed), None)
    if origin is None:
        return {"status": "not_launched", "error": "extension_id_mismatch"}
    payload = io.BytesIO()
    _write_native_message(payload, {"action": "ping", "protocol": PROTOCOL_VERSION,
                                    "extension_version": APP_VERSION})
    process = None
    try:
        process = subprocess.Popen([str(config["native_host_path"]), origin],
                                   stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                   creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        stdout, _stderr = process.communicate(payload.getvalue(), timeout=timeout)
        # Do not print the raw stdout or stderr; either may contain personal data.
        source = io.BytesIO(stdout)
        response = _read_native_message(source)
        if not response or source.read(1):
            return {"status": "failed", "error": "invalid_native_frame"}
        result = _redacted_ping(response)
        response.clear()
        return result
    except subprocess.TimeoutExpired:
        if process:
            _kill_test_process(process)
        return {"status": "failed", "error": "ping_timeout", "message": "Finish any open LocalGateKeys dialog and try again. The test did not request a fill."}
    except Exception as exc:
        if process and process.poll() is None:
            _kill_test_process(process)
        result = {"status": "failed", "error": "native_launch_or_framing_failed"}
        number = error_number(exc)
        if number is not None and 0 <= number <= 65535:
            result["winerror"] = number
        return result


def collect_report() -> dict[str, Any]:
    result: dict[str, Any] = {"bridge_revision": BRIDGE_REVISION, "local_app_version": APP_VERSION,
                              "protocol": PROTOCOL_VERSION, "windows": os.name == "nt"}
    if os.name != "nt":
        result["connection"] = {"status": "not_tested", "error": "windows_required"}
        return result
    try:
        state = read_json(agent_state_path())
        result["agent_connection_file"] = "present"
        result["running_listener_patch"] = BRIDGE_REVISION if state.get("bridge_revision") == BRIDGE_REVISION else "older_or_unknown"
        import psutil
        pid = state.get("pid")
        result["recorded_agent_pid_alive"] = type(pid) is int and pid > 0 and psutil.pid_exists(pid)
        result["transport"] = "named_pipe" if state.get("transport") == "named_pipe" else "older_or_unknown"
        protection = state.get("protection", "none")
        result["agent_token_protection"] = protection if protection in ("none", "dpapi-user") else "unknown"
        if result["agent_token_protection"] == "none":  # noqa: S105 (field name, not a secret)
            record_warning("agent_token_unprotected")
        state.clear()
    except FileNotFoundError:
        result["agent_connection_file"] = "missing"
    except PermissionError:
        result["agent_connection_file"] = "access_denied"
    except (OSError, ValueError, TypeError):
        result["agent_connection_file"] = "invalid"
    try:
        config = read_json(install_config_path())
    except (OSError, ValueError, TypeError):
        result["bridge_registration_config"] = "missing_or_unreadable"
        result["client_pin_policy"] = ClientPinPolicy().describe()
        result["connection"] = {"status": "not_launched", "error": "repair_required"}
        result["warnings"] = warnings()
        return result
    result["bridge_registration_config"] = "present"
    result["client_pin_policy"] = ClientPinPolicy(install_config=config).describe()
    result["pins"] = {label: _pin_matches(config.get(path), config.get(digest)) for label, path, digest in [
        ("native_host", "native_host_path", "native_host_sha256"),
        ("python_interpreter", "interpreter_path", "interpreter_sha256"),
        ("venv_redirector", "venv_redirector_path", "venv_redirector_sha256"),
    ]}
    root = str(Path(__file__).resolve().parents[2])
    result["repair_targets_this_repository"] = _same_path(root, str(config.get("install_root", "")))
    result["browser_registration"] = {b: _registered_host_status(b, config) for b in ("Chrome", "Edge", "Firefox")}
    result["connection"] = _ping_host(config)
    result["warnings"] = warnings()
    return result


def main() -> None:
    try:
        report = collect_report()
    except Exception:
        report = {"bridge_revision": BRIDGE_REVISION, "connection": {"status": "failed", "error": "diagnostic_failed"}}
    print(json.dumps(report, indent=2))
    # No log files, tokens, raw state, user paths or exception strings are printed.
    raise SystemExit(0 if report["connection"].get("status") == "connected" else 1)


if __name__ == "__main__":
    main()
