from __future__ import annotations

"""Chromium native-messaging bridge for LocalGateKeys.

This module intentionally keeps startup dependencies to the Python standard
library.  Chromium reports the fairly unhelpful "Native host has exited" when a
host crashes before it can write a response.  By delaying LocalGateKeys imports
until after the stdio bridge is alive, startup/import failures become a useful
structured browser error and a local diagnostic log instead of a silent exit.

The diagnostic log never records request payloads, usernames, passwords, vault
contents, or tokens.
"""

import hmac
import json
import os
import socket
import struct
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, BinaryIO

_DEFAULT_EXTENSION_ID = "hojebpmbiibhbhhkohgongojilojijmb"
_DEFAULT_ALLOWED_ORIGINS = {
    f"chrome-extension://{_DEFAULT_EXTENSION_ID}/",
    f"extension://{_DEFAULT_EXTENSION_ID}/",
}
# Firefox launches the host as ``host <manifest path> <extension id>``; the
# Gecko add-on id is fixed in browser-extension/manifest.json.
FIREFOX_EXTENSION_ID = "localgatekeys@localgatekeys.app"
_MAX_NATIVE_MESSAGE = 1024 * 1024

# Peer-identity rejections from the agent that the browser should see as a
# bridge configuration problem (stage "peer"), never as "app offline".
_PEER_REJECTION_CODES = frozenset({
    "client_not_allowed", "unauthorized",
    "client_pin_unregistered", "client_pin_mismatch", "client_signer_mismatch",
})


class NativeBridgeError(Exception):
    pass


def _diagnostic_path() -> Path:
    override = os.environ.get("LOCALGATEKEYS_DATA_DIR")
    if override:
        path = Path(override).expanduser() / "native-host.log"
    elif os.name == "nt":
        root = Path(os.environ.get("LOCALAPPDATA", Path.home() / "AppData" / "Local"))
        path = root / "LocalGateKeys" / "native-host.log"
    else:
        root = Path(os.environ.get("XDG_DATA_HOME", Path.home() / ".local" / "share"))
        path = root / "localgatekeys" / "native-host.log"
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
    except OSError:
        pass
    return path


# The browser starts a host per connection, so the log grows without bound
# unless capped: past this size it moves to native-host.log.1 (replacing the
# previous one), keeping at most about twice this on disk.
_LOG_MAX_BYTES = 1024 * 1024


def _rotate_log(path: Path) -> None:
    """Best effort; hosts run concurrently, so a lost race just skips a rotation."""

    try:
        if path.stat().st_size < _LOG_MAX_BYTES:
            return
        os.replace(path, path.with_name(path.name + ".1"))
    except OSError:
        pass


def _log(event: str, exc: BaseException | None = None) -> None:
    """Best-effort diagnostic logging without credential material."""

    try:
        stamp = datetime.now(UTC).isoformat(timespec="seconds")
        line = f"{stamp} pid={os.getpid()} {event}"
        if exc is not None:
            line += f" | {type(exc).__name__}"
            # Numeric Windows error only. Never log str(exc), paths or payloads.
            number = getattr(exc, "winerror", None)
            if number is None and exc.args and type(exc.args[0]) is int:
                number = exc.args[0]
            if type(number) is int and 0 <= number <= 65535:
                line += f" winerror={number}"
        path = _diagnostic_path()
        _rotate_log(path)
        with path.open("a", encoding="utf-8", newline="\n") as handle:
            handle.write(line[:4000] + "\n")
    except Exception:
        pass


def _configure_binary_stdio() -> None:
    if sys.platform != "win32":
        return
    import msvcrt  # type: ignore[import-not-found]

    msvcrt.setmode(sys.stdin.fileno(), os.O_BINARY)
    msvcrt.setmode(sys.stdout.fileno(), os.O_BINARY)


def _read_exact(stream: BinaryIO, length: int) -> bytes:
    chunks: list[bytes] = []
    remaining = length
    while remaining:
        chunk = stream.read(remaining)
        if not chunk:
            raise EOFError("Unexpected end of native messaging stream")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def _read_native_message(stream: BinaryIO) -> dict[str, Any] | None:
    header = stream.read(4)
    if not header:
        return None
    if len(header) != 4:
        raise NativeBridgeError("Truncated native message header")
    (length,) = struct.unpack("=I", header)
    if length > _MAX_NATIVE_MESSAGE:
        raise NativeBridgeError("Native message is too large")
    payload = _read_exact(stream, length)
    try:
        value = json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
        # RecursionError: Python 3.14's C decoder raises it for deeply nested input.
        raise NativeBridgeError("Invalid native message JSON") from exc
    if not isinstance(value, dict):
        raise NativeBridgeError("Native message must be a JSON object")
    return value


def _write_native_message(stream: BinaryIO, value: dict[str, Any]) -> None:
    payload = json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    if len(payload) > _MAX_NATIVE_MESSAGE:
        raise NativeBridgeError("Native response is too large")
    stream.write(struct.pack("=I", len(payload)))
    stream.write(payload)
    stream.flush()


def _caller_trust() -> Any:
    """``config.extension_trust()`` for this build; ``None`` if config cannot load."""

    try:
        from .config import extension_trust

        return extension_trust()
    except Exception as exc:
        _log("config_import_failed; using built-in extension origin", exc)
        return None


def _allowed_callers(trust: Any = None) -> set[str]:
    """Caller origins for this build's channel (audit 2026-10-18, M6).

    The same list the manifest was written from, computed here on its own:
    install.json is user-writable and never widens it, and a stale manifest
    from an older build (still listing the developer ID) gains nothing.
    """

    trust = trust if trust is not None else _caller_trust()
    if trust is None:
        # Config failed to import, so nothing could be forwarded anyway. A
        # frozen build fails closed; a source run keeps the developer origin
        # so the import failure reaches the browser as a structured error.
        return set() if getattr(sys, "frozen", False) else set(_DEFAULT_ALLOWED_ORIGINS)
    return set(trust.caller_origins())


def _verify_caller(argv: list[str]) -> bool:
    if len(argv) < 2:
        return False
    caller = argv[1]
    trust = _caller_trust()
    if any(hmac.compare_digest(caller, allowed) for allowed in _allowed_callers(trust)):
        reason = getattr(trust, "developer_id_reason", None)
        if reason is not None and reason != "developer_install" and caller in _DEFAULT_ALLOWED_ORIGINS:
            # Report a frozen build serving the developer ID (opt-in, or a
            # store ID that is still an unassigned placeholder).
            _log(f"caller_developer_extension_id reason={reason}")
        return True
    # Firefox: argv[1] is the manifest path, argv[2] the extension id. The
    # Gecko id is the AMO-signed id too: Firefox passes no signature state,
    # so a temporary add-on declaring it cannot be told apart here.
    return len(argv) >= 3 and hmac.compare_digest(argv[2], FIREFOX_EXTENSION_ID)


# Requests a host started by something other than a browser may still relay:
# the Connections test launches the host from the app itself and only pings.
_UNVERIFIED_CALLER_ACTIONS = frozenset({"ping"})


def _self_images() -> set[str]:
    """Executables that may sit between this process and the browser.

    The running image, ``sys.executable`` and the launcher/interpreter chain
    pinned in install.json (a repository install runs host launcher -> venv
    redirector -> interpreter).  Listing a path here only lets the walk pass
    through it; a signed browser must still be the launcher above it.
    """
    from .browser_ancestry import process_image

    images = {str(sys.executable), process_image(os.getpid())}
    try:
        from .config import install_config_path, read_json

        config = read_json(install_config_path())
        for key in ("native_host_path", "interpreter_path", "venv_redirector_path"):
            value = config.get(key)
            if isinstance(value, str) and value:
                images.add(value)
    except Exception:
        pass
    return {image for image in images if image}


def _verify_browser_parent() -> Any:
    """Whether this process was launched by an allow-listed, signed browser.

    Fails closed (on non-Windows too).  Tests replace this function.
    """
    from .browser_ancestry import verify_browser_ancestry

    return verify_browser_ancestry(os.getpid(), self_images=_self_images())


def _unverified_caller_response() -> dict[str, Any]:
    from .browser_ancestry import BROWSER_UNVERIFIED_CODE, BROWSER_UNVERIFIED_MESSAGE

    return {"ok": False, "error": BROWSER_UNVERIFIED_CODE, "message": BROWSER_UNVERIFIED_MESSAGE,
            "stage": "peer"}


def tcp_fallback_allowed() -> bool:
    """Loopback TCP is a non-Windows development transport, opt-in only.

    Enabled by ``LOCALGATEKEYS_ALLOW_TCP_FALLBACK=1`` (exactly "1") or
    implicitly inside pytest, where the portable framing tests use it.
    """
    environ = os.environ
    if environ.get("PYTEST_CURRENT_TEST"):
        return True
    return environ.get("LOCALGATEKEYS_ALLOW_TCP_FALLBACK") == "1"


def require_tcp_fallback_allowed() -> None:
    """Refuse to start/use the TCP transport unless it was enabled deliberately."""
    if not tcp_fallback_allowed():
        raise RuntimeError("Loopback TCP fallback is disabled; set LOCALGATEKEYS_ALLOW_TCP_FALLBACK=1 to enable it")


def _forward_legacy_socket(request: dict[str, Any], state: dict[str, Any]) -> dict[str, Any]:
    from .bridge_status import BridgeFailure
    from .protocol import recv_local_message, send_local_message

    if not tcp_fallback_allowed():
        raise BridgeFailure("tcp_fallback_disabled", "connect")
    host = str(state.get("host", "127.0.0.1"))
    port = state.get("port")
    token = state.get("token")
    if state.get("protection", "none") != "none":
        # The TCP state file is plaintext by design; a protected token cannot be
        # used here and must not be guessed at.
        raise BridgeFailure("agent_state_invalid", "state")
    if (host != "127.0.0.1" or type(port) is not int or not (1 <= port <= 65535)
            or not isinstance(token, str) or len(token) < 32):
        raise ValueError("Agent state is invalid")
    # Every frame carries the token; the agent authenticates each request on its own.
    outbound = dict(request)
    outbound["token"] = token
    try:
        with socket.create_connection((host, port), timeout=5) as sock:
            sock.settimeout(185)
            send_local_message(sock, outbound)
            return recv_local_message(sock)
    finally:
        outbound.clear()


def _forward(request: dict[str, Any]) -> dict[str, Any]:
    # State absence, ACL failures, import errors and peer rejections are not all
    # "app offline". Keep stable, non-sensitive diagnostic codes for each case.
    stage = "imports"
    try:
        from .bridge_status import BridgeFailure, failure_response
        from .config import agent_state_path, read_json

        stage = "state"
        state = read_json(agent_state_path())
        stage = "imports"
        if os.name == "nt":
            from .pipe_transport import forward_named_pipe
            if state.get("transport") != "named_pipe":
                raise BridgeFailure("agent_state_invalid", "state")
            # Read the state once; do not mix a token/pipe from another app run.
            stage = "connect"
            response = forward_named_pipe(request, timeout_ms=5000, state=state)
        else:
            stage = "connect"
            response = _forward_legacy_socket(request, state)
        if response.get("ok") is False:
            code = response.get("error")
            if code in _PEER_REJECTION_CODES:
                _log(f"agent_rejected code={code}")
                return failure_response(code, stage="peer")
        return response
    except Exception as exc:
        # Even a partially applied patch must return a structured native frame.
        try:
            from .bridge_status import classify_failure
            response = classify_failure(exc, stage)
        except Exception:
            response = {"ok": False, "error": "bridge_internal_error",
                        "message": "The native bridge files are incomplete. Update the desktop app and restart it."}
        _log(f"forward_failed code={response['error']} stage={response.get('stage', stage)}", exc)
        return response


def self_test() -> dict[str, Any]:
    """Return safe bridge diagnostics for the repair script."""

    result: dict[str, Any] = {
        "bridge_revision": __import__("localvault.version", fromlist=["RELEASE_ID"]).RELEASE_ID,
        "python": sys.executable,
        "native_host_import": True,
        "allowed_origin_count": len(_allowed_callers()),
        "diagnostic_log": str(_diagnostic_path()),
    }
    try:
        from .config import agent_state_path

        result["agent_state_exists"] = agent_state_path().exists()
    except Exception:
        result["config_error"] = "Native host internal error. Use Connections for diagnostics."
    try:
        from .pipe_transport import forward_named_pipe  # noqa: F401

        result["pipe_transport_import"] = True
    except Exception:
        result["pipe_transport_import"] = False
        result["pipe_transport_error"] = "Native host internal error. Use Connections for diagnostics."
    return result


def main() -> None:
    try:
        _configure_binary_stdio()
    except Exception as exc:
        _log("binary_stdio_failed", exc)
        # Continue: stdio is already binary on some launcher/runtime combinations.

    caller = sys.argv[1] if len(sys.argv) > 1 else "<missing>"
    _log("host_started")

    if not _verify_caller(sys.argv):
        _log("caller_not_allowed")
        try:
            _write_native_message(sys.stdout.buffer, {"ok": False, "error": "caller_not_allowed"})
        except Exception as exc:
            _log("caller_rejection_write_failed", exc)
        return

    try:
        browser = _verify_browser_parent()
    except Exception as exc:
        _log("browser_parent_check_failed", exc)
        browser = None
    browser_verified = bool(browser)
    if not browser_verified:
        # Fixed code only; never the parent's path.
        _log(f"caller_not_browser code={getattr(browser, 'code', 'error')}")

    while True:
        try:
            request = _read_native_message(sys.stdin.buffer)
            if request is None:
                _log("browser_closed_native_stream")
                return
            if not browser_verified and request.get("action") not in _UNVERIFIED_CALLER_ACTIONS:
                # A same-user program launched the registered host itself and
                # is speaking native messaging on its stdin.  The agent applies
                # the same rule to the pipe peer; this is the early refusal.
                _write_native_message(sys.stdout.buffer, _unverified_caller_response())
                continue
            response = _forward(request)
            _write_native_message(sys.stdout.buffer, response)
        except (EOFError, NativeBridgeError) as exc:
            _log("native_protocol_error", exc)
            try:
                _write_native_message(
                    sys.stdout.buffer,
                    {"ok": False, "error": "protocol_error", "message": str(exc)},
                )
            except Exception as write_exc:
                _log("protocol_error_write_failed", write_exc)
            return
        except BaseException as exc:  # last-resort protection against silent Chrome errors
            _log("unhandled_native_host_error", exc)
            try:
                _write_native_message(
                    sys.stdout.buffer,
                    {
                        "ok": False,
                        "error": "native_host_internal_error",
                        "message": "Native host internal error. Use Connections for diagnostics.",
                    },
                )
            except Exception as write_exc:
                _log("internal_error_write_failed", write_exc)
            return


if __name__ == "__main__":
    main()
