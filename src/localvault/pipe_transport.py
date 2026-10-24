from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
import struct
import sys
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .bridge_status import (
    BridgeFailure,
    classify_failure,
    error_number,
    failure_response,
    record_warning,
)
from .config import (
    NATIVE_HOST_NAME,
    agent_state_path,
    atomic_write_json,
    install_config_path,
    read_json,
)
from .distribution import resolve_native_host_path
from .protocol import MAX_LOCAL_MESSAGE, ProtocolError
from .version import RELEASE_ID

PIPE_PREFIX = r"\\.\pipe\LocalGateKeys-"

# CreateFile flags for the client end: SECURITY_SQOS_PRESENT (0x00100000) |
# SECURITY_IDENTIFICATION (0x00010000).
PIPE_CLIENT_SQOS_FLAGS = 0x00100000 | 0x00010000

# Frames are a 4-byte big-endian length followed by one UTF-8 JSON object.
MAX_FRAME_PAYLOAD = MAX_LOCAL_MESSAGE

# Fixed application entropy mixed into DPAPI so another same-user program that
# merely calls CryptUnprotectData on the file still needs to know this value.
# It is not a secret; the user-scope DPAPI master key is the protection.
AGENT_TOKEN_ENTROPY = b"LocalGateKeys.agent-token.v1"
AGENT_STATE_VERSION = 3

# HKCU native-messaging registrations consulted for the client pin. The
# manifest ``path`` written there is the executable the browser launches, so it
# is the only authority for which process may speak to the agent.
_NATIVE_MESSAGING_KEYS = (
    ("Chrome", r"Software\Google\Chrome\NativeMessagingHosts"),
    ("Edge", r"Software\Microsoft\Edge\NativeMessagingHosts"),
    ("Firefox", r"Software\Mozilla\NativeMessagingHosts"),
)


def _sha256_file(path: str) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest().upper()


def _named_pipe_client_pid(handle: Any) -> int | None:
    if os.name != "nt":
        return None
    try:
        import ctypes
        from ctypes import wintypes

        pid = wintypes.ULONG()
        kernel32 = ctypes.windll.kernel32
        function = kernel32.GetNamedPipeClientProcessId
        function.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.ULONG)]
        function.restype = wintypes.BOOL
        raw = int(handle)  # PyHANDLE is an OS handle, not a CRT descriptor
        if not function(raw, ctypes.byref(pid)):
            return None
        return int(pid.value)
    except Exception:
        return None


def _same_file_path(left: str, right: str) -> bool:
    return bool(left) and bool(right) and (
        os.path.normcase(os.path.abspath(left)) == os.path.normcase(os.path.abspath(right)))


def _registered_native_host_paths() -> dict[str, str]:
    """Return {browser: native host exe} from this user's native-messaging registrations.

    Only a readable manifest with our host name and ``type: stdio`` counts.
    Registry/manifest problems are treated as "not registered" for that browser.
    """
    if os.name != "nt":
        return {}
    import winreg

    found: dict[str, str] = {}
    for browser, root in _NATIVE_MESSAGING_KEYS:
        try:
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, f"{root}\\{NATIVE_HOST_NAME}") as key:
                manifest_path = winreg.QueryValue(key, None)
            with open(str(manifest_path), encoding="utf-8") as handle:
                manifest = json.load(handle)
            if (not isinstance(manifest, dict) or manifest.get("name") != NATIVE_HOST_NAME
                    or manifest.get("type") != "stdio"):
                continue
            path = manifest.get("path")
            if isinstance(path, str) and path:
                # A packaged build registers its execution alias; pin the
                # package executable the alias launches.
                found[browser] = resolve_native_host_path(path)
        except (OSError, ValueError, TypeError):
            continue
    return found


def _agent_executable() -> str:
    return str(sys.executable)


def _authenticode_thumbprint(path: str) -> str:
    """Signer thumbprint of a validly signed file, or "" (read-only, best effort)."""
    try:
        from .signature import authenticode_info
        info = authenticode_info(str(path))
    except Exception:
        return ""
    if not info or info.get("status") != "Valid":
        return ""
    return str(info.get("thumbprint", "")).upper()


def _is_frozen() -> bool:
    return bool(getattr(sys, "frozen", False))


# Actions a pinned host may relay when no signed browser launched it (the
# Connections test starts the host from the app itself).
DIAGNOSTIC_ACTIONS = frozenset({"ping"})


def _browser_ancestry(pid: int, self_images: set[str]) -> Any:
    """Browser-launcher check for the pipe peer; see browser_ancestry. Tests replace it."""
    from .browser_ancestry import verify_browser_ancestry

    return verify_browser_ancestry(pid, self_images=self_images)


@dataclass(frozen=True)
class PinDecision:
    allowed: bool
    code: str = "ok"
    authority: str = "registry"
    # "browser" only when an allow-listed, signed browser launched the pinned
    # host; anything else may relay DIAGNOSTIC_ACTIONS only.
    scope: str = "diagnostic"

    def __bool__(self) -> bool:
        return self.allowed


class ClientPinPolicy:
    """Decide whether a pipe peer is the browser-registered native host.

    Authority order: the HKCU native-messaging registration (what the browser
    actually launches) is the pin. install.json is a secondary cross-check that
    can only veto, never redirect trust. Frozen builds additionally require the
    host to live in the app's install directory and, when the running agent is
    Authenticode-signed, to carry the same signer thumbprint. Repository builds
    keep the explicitly pinned Python launcher chain (host -> interpreter, or
    host -> venv redirector -> interpreter) from install.json.
    """

    def __init__(self, install_config: dict[str, Any] | None = None) -> None:
        self._install_config = install_config

    # -- inputs -----------------------------------------------------------
    def _install(self) -> tuple[dict[str, Any] | None, str]:
        if self._install_config is not None:
            return self._install_config, "present"
        try:
            value = read_json(install_config_path())
        except FileNotFoundError:
            return None, "missing"
        except (OSError, ValueError, TypeError):
            return None, "unreadable"
        return (value if isinstance(value, dict) else None), "present"

    @staticmethod
    def _registered_host(registrations: dict[str, str]) -> str | None:
        """The single registered executable, or None when browsers disagree."""
        paths = list(registrations.values())
        if not paths:
            return None
        if any(not _same_file_path(paths[0], other) for other in paths[1:]):
            return None
        return paths[0]

    @staticmethod
    def _cross_check(registered: str, config: dict[str, Any] | None) -> str:
        """install.json may veto (mismatch) but never pick a different host."""
        if config is None:
            return "missing"
        configured_path = str(config.get("native_host_path", "") or "")
        configured_hash = str(config.get("native_host_sha256", "") or "")
        if configured_path and not _same_file_path(configured_path, registered):
            return "mismatch"
        if configured_hash:
            if len(configured_hash) != 64:
                return "mismatch"
            try:
                if not hmac.compare_digest(_sha256_file(registered), configured_hash.upper()):
                    return "mismatch"
            except (OSError, ValueError):
                return "mismatch"
        return "match"

    # -- evaluation -------------------------------------------------------
    def evaluate(self, handle: Any) -> PinDecision:
        if os.name != "nt":
            return PinDecision(True, "ok", "none")
        try:
            registrations = _registered_native_host_paths()
            if not registrations:
                return PinDecision(False, "client_pin_unregistered")
            registered = self._registered_host(registrations)
            if registered is None:
                return PinDecision(False, "client_pin_mismatch")
            config, _state = self._install()
            if self._cross_check(registered, config) == "mismatch":
                return PinDecision(False, "client_pin_mismatch")
            pid = _named_pipe_client_pid(handle)
            if not pid:
                return PinDecision(False, "client_not_allowed")
            import psutil

            process = psutil.Process(pid)
            exe = str(process.exe())
            if _is_frozen():
                if not _same_file_path(exe, registered):
                    return PinDecision(False, "client_pin_mismatch")
                return self._with_browser_scope(self._frozen_checks(registered), pid, {registered})
            if _same_file_path(exe, registered):
                return self._with_browser_scope(PinDecision(True), pid, {registered})
            if self._pinned_interpreter_chain(process, registered, config or {}):
                chain = {registered, str((config or {}).get("interpreter_path", "")),
                         str((config or {}).get("venv_redirector_path", ""))}
                return self._with_browser_scope(PinDecision(True), pid, chain)
            return PinDecision(False, "client_pin_mismatch")
        except Exception:
            return PinDecision(False, "client_not_allowed")

    @staticmethod
    def _with_browser_scope(decision: PinDecision, pid: int, self_images: set[str]) -> PinDecision:
        """Extend the host pin to its launcher: a signed browser earns full scope."""
        if not decision.allowed:
            return decision
        try:
            browser = _browser_ancestry(pid, {path for path in self_images if path})
        except Exception:
            browser = None
        scope = "browser" if browser else "diagnostic"
        return PinDecision(True, decision.code, decision.authority, scope)

    def _frozen_checks(self, registered: str) -> PinDecision:
        agent = _agent_executable()
        install_dir = os.path.normcase(os.path.abspath(os.path.dirname(agent)))
        host_abs = os.path.normcase(os.path.abspath(registered))
        try:
            same_tree = os.path.commonpath([install_dir, host_abs]) == install_dir
        except ValueError:
            same_tree = False
        if not same_tree:
            return PinDecision(False, "client_signer_mismatch")
        agent_signer = _authenticode_thumbprint(agent)
        if agent_signer:
            host_signer = _authenticode_thumbprint(registered)
            if not host_signer or not hmac.compare_digest(host_signer, agent_signer):
                return PinDecision(False, "client_signer_mismatch")
        return PinDecision(True)

    @staticmethod
    def _pinned_interpreter_chain(process: Any, registered: str, config: dict[str, Any]) -> bool:
        def matches(path: str, expected: str, digest: str) -> bool:
            return (bool(expected) and len(digest) == 64 and _same_file_path(path, expected) and
                    hmac.compare_digest(_sha256_file(path), digest.upper()))

        if not matches(process.exe(), str(config.get("interpreter_path", "")),
                       str(config.get("interpreter_sha256", ""))):
            return False
        parent = process.parent()
        if not parent:
            return False
        if _same_file_path(parent.exe(), registered):
            return True
        # CPython's venv python.exe can be a redirector process, leaving the
        # console launcher as the interpreter's grandparent rather than parent.
        if not matches(parent.exe(), str(config.get("venv_redirector_path", "")),
                       str(config.get("venv_redirector_sha256", ""))):
            return False
        grandparent = parent.parent()
        return bool(grandparent and _same_file_path(grandparent.exe(), registered))

    # -- diagnostics ------------------------------------------------------
    def describe(self) -> dict[str, Any]:
        """Path-free summary for the Connections diagnostics report."""
        entry: dict[str, Any] = {"authority": "registry", "registered_browsers": [],
                                 "registrations_consistent": False, "install_json_cross_check": "unknown",
                                 "frozen": _is_frozen(), "signer_check": "not_applicable"}
        if os.name != "nt":
            entry["authority"] = "none"
            return entry
        try:
            registrations = _registered_native_host_paths()
            entry["registered_browsers"] = sorted(registrations)
            registered = self._registered_host(registrations)
            entry["registrations_consistent"] = registered is not None
            config, state = self._install()
            if registered is None:
                entry["install_json_cross_check"] = state if config is None else "no_registration"
            else:
                entry["install_json_cross_check"] = self._cross_check(registered, config)
            if _is_frozen():
                entry["signer_check"] = ("enforced" if _authenticode_thumbprint(_agent_executable())
                                         else "skipped_unsigned_agent")
        except Exception:
            entry["install_json_cross_check"] = "error"
        return entry


def _verify_native_host_client(handle: Any) -> PinDecision:
    """Registry-anchored client pin; see ClientPinPolicy. Fails closed."""
    return ClientPinPolicy().evaluate(handle)


def _named_pipe_server_pid(handle: Any) -> int | None:
    """Validate the actual endpoint before sending a token or credentials."""
    if os.name != "nt":
        return None
    try:
        import ctypes
        from ctypes import wintypes
        pid = wintypes.ULONG()
        fn = ctypes.windll.kernel32.GetNamedPipeServerProcessId
        fn.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.ULONG)]
        fn.restype = wintypes.BOOL
        if not fn(int(handle), ctypes.byref(pid)):
            return None
        return int(pid.value)
    except Exception:
        return None


def _pipe_log(event: str, exc: BaseException | None = None) -> None:
    # These call sites supply fixed event names; never request values.
    from .native_host import _log
    _log(event, exc)


def _encode(value: dict[str, Any]) -> bytes:
    try:
        payload = json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    except (TypeError, ValueError, RecursionError) as exc:
        raise ProtocolError("Local agent message is not encodable") from exc
    if len(payload) > MAX_FRAME_PAYLOAD:
        raise ProtocolError("Local agent message is too large")
    return struct.pack("!I", len(payload)) + payload


def _decode(blob: bytes) -> dict[str, Any]:
    """Parse one complete frame. Only ProtocolError escapes for hostile input."""
    if not isinstance(blob, (bytes, bytearray, memoryview)):
        raise ProtocolError("Local agent frame must be bytes")
    blob = bytes(blob)
    if len(blob) < 4:
        raise ProtocolError("Truncated local agent message")
    (length,) = struct.unpack("!I", blob[:4])
    if length > MAX_FRAME_PAYLOAD or len(blob) != length + 4:
        raise ProtocolError("Invalid local agent message length")
    try:
        text = blob[4:].decode("utf-8")  # strict: rejects surrogates and malformed sequences
        value = json.loads(text)
        if not isinstance(value, dict):
            raise ProtocolError("Local message must be a JSON object")
        # Lone surrogates can arrive as JSON escapes; make sure the object can
        # be re-encoded so nothing downstream fails on it.
        json.dumps(value, ensure_ascii=False).encode("utf-8")
    except ProtocolError:
        raise
    except (ValueError, TypeError, RecursionError) as exc:  # includes Unicode and JSON errors
        raise ProtocolError("Invalid local agent JSON") from exc
    return value


def _dpapi_available() -> bool:
    if os.name != "nt":
        return False
    try:
        import win32crypt  # noqa: F401
    except Exception:
        return False
    return True


def protect_agent_token(token: str) -> dict[str, Any]:
    """Return the ``token``/``protection`` fields for agent-state.json.

    DPAPI user scope with fixed app entropy and no UI; plaintext only when
    pywin32 is unavailable, which is surfaced as a diagnostics warning.
    """
    if not _dpapi_available():
        record_warning("agent_token_unprotected")
        return {"token": token, "protection": "none"}
    import win32crypt

    flags = getattr(win32crypt, "CRYPTPROTECT_UI_FORBIDDEN", 0x1)
    blob = win32crypt.CryptProtectData(token.encode("utf-8"), None, AGENT_TOKEN_ENTROPY, None, None, flags)
    return {"token": base64.b64encode(bytes(blob)).decode("ascii"), "protection": "dpapi-user"}


def unprotect_agent_token(state: dict[str, Any]) -> str:
    """Recover the plaintext token from a state file; BridgeFailure on any problem."""
    token = state.get("token")
    protection = state.get("protection", "none")
    if not isinstance(token, str) or not token:
        raise BridgeFailure("agent_state_invalid", "state")
    if protection == "none":
        return token
    if protection != "dpapi-user":
        raise BridgeFailure("agent_state_invalid", "state")
    if not _dpapi_available():
        raise BridgeFailure("bridge_dependencies_missing", "state")
    try:
        import win32crypt

        blob = base64.b64decode(token, validate=True)
        flags = getattr(win32crypt, "CRYPTPROTECT_UI_FORBIDDEN", 0x1)
        _description, data = win32crypt.CryptUnprotectData(blob, AGENT_TOKEN_ENTROPY, None, None, flags)
        return bytes(data).decode("utf-8")
    except Exception as exc:
        raise BridgeFailure("agent_state_invalid", "state") from exc


def _current_user_sid_string() -> str:
    import win32api
    import win32con
    import win32security

    token = win32security.OpenProcessToken(win32api.GetCurrentProcess(), win32con.TOKEN_QUERY)
    sid = win32security.GetTokenInformation(token, win32security.TokenUser)[0]
    return win32security.ConvertSidToStringSid(sid)


def _security_attributes_for_current_user():
    import win32con
    import win32security

    sid_text = _current_user_sid_string()
    sid = win32security.ConvertStringSidToSid(sid_text)
    dacl = win32security.ACL()
    dacl.AddAccessAllowedAce(win32security.ACL_REVISION, win32con.GENERIC_ALL, sid)
    sd = win32security.SECURITY_DESCRIPTOR()
    sd.SetSecurityDescriptorDacl(1, dacl, 0)
    sa = win32security.SECURITY_ATTRIBUTES()
    sa.SECURITY_DESCRIPTOR = sd
    return sa, sid_text


def _restrict_file_to_current_user(path: Path | str) -> bool:
    """Replace the file DACL with an owner-only, non-inherited one. Best effort."""
    if os.name != "nt":
        return False
    try:
        import win32security

        sa, _sid = _security_attributes_for_current_user()
        info = win32security.DACL_SECURITY_INFORMATION | win32security.PROTECTED_DACL_SECURITY_INFORMATION
        win32security.SetFileSecurity(str(path), info, sa.SECURITY_DESCRIPTOR)
        return True
    except Exception:
        return False


def _read_exact_pipe(handle: Any, length: int) -> bytes:
    import win32file

    chunks: list[bytes] = []
    remaining = length
    while remaining:
        _hr, data = win32file.ReadFile(handle, remaining)
        if not data:
            raise EOFError("Unexpected end of named pipe")
        chunks.append(bytes(data))
        remaining -= len(data)
    return b"".join(chunks)


def _recv_pipe(handle: Any) -> dict[str, Any]:
    header = _read_exact_pipe(handle, 4)
    (length,) = struct.unpack("!I", header)
    if length > MAX_LOCAL_MESSAGE:
        raise ProtocolError("Local agent message is too large")
    payload = _read_exact_pipe(handle, length)
    return _decode(header + payload)


def _send_pipe(handle: Any, value: dict[str, Any]) -> None:
    import win32file

    blob = _encode(value)
    written = 0
    while written < len(blob):
        _hr, count = win32file.WriteFile(handle, blob[written:])
        # pywin32 WriteFile commonly returns (err, bytesWritten) for sync handles;
        # some versions return (err, overlapped). In the latter case the whole
        # buffer has been accepted synchronously here.
        if isinstance(count, int):
            if count <= 0:
                raise OSError("Named pipe write made no progress")
            written += count
        else:
            written = len(blob)


def _flush_reply(handle: Any, timeout: float = 2.0) -> None:
    """Let clients consume error replies before disconnecting.

    Request cancellation if a client never reads. The cancellation thread is
    stopped/joined before any other I/O on this dedicated worker thread, so it
    cannot cancel a later unrelated file operation. Windows cancellation is
    best-effort, not a guarantee about every underlying driver.
    """
    import win32file
    if os.name != "nt":  # deterministic portable test harness
        win32file.FlushFileBuffers(handle)
        return
    import ctypes
    from ctypes import wintypes
    kernel32 = ctypes.windll.kernel32
    open_thread = kernel32.OpenThread
    open_thread.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    open_thread.restype = wintypes.HANDLE
    cancel = kernel32.CancelSynchronousIo
    cancel.argtypes = [wintypes.HANDLE]
    cancel.restype = wintypes.BOOL
    close = kernel32.CloseHandle
    close.argtypes = [wintypes.HANDLE]
    close.restype = wintypes.BOOL
    thread = open_thread(0x0001, False, threading.get_native_id())  # THREAD_TERMINATE
    if not thread:
        raise OSError("Cannot prepare pipe reply cancellation")
    done = threading.Event()
    def watch() -> None:
        if not done.wait(timeout):
            while not done.is_set():
                cancel(thread)
                done.wait(0.05)
    watcher = threading.Thread(target=watch, name="localgatekeys-pipe-flush", daemon=True)
    try:
        watcher.start()
        win32file.FlushFileBuffers(handle)
    finally:
        done.set()
        if watcher.ident is not None:
            watcher.join()
        close(thread)


def _browser_unverified_response() -> dict[str, Any]:
    from .browser_ancestry import BROWSER_UNVERIFIED_CODE, BROWSER_UNVERIFIED_MESSAGE

    response = failure_response("client_not_allowed", stage="peer")
    response.update(error=BROWSER_UNVERIFIED_CODE, message=BROWSER_UNVERIFIED_MESSAGE)
    return response


class NamedPipeAgentServer:
    def __init__(self, dispatcher: Callable[[dict[str, Any]], dict[str, Any]]) -> None:
        self.dispatcher = dispatcher
        self.token = secrets.token_urlsafe(32)
        self.pipe_name = PIPE_PREFIX + secrets.token_hex(16)
        self.stop_event = threading.Event()
        self.thread: threading.Thread | None = None
        self.user_sid = ""

    def start(self) -> None:
        if os.name != "nt":
            raise RuntimeError("Named pipes are available only on Windows")
        if self.thread and self.thread.is_alive():
            return
        self.stop_event.clear()
        _sa, self.user_sid = _security_attributes_for_current_user()
        handle = None
        try:
            # Fail synchronously instead of leaving a running GUI advertising
            # a pipe that its listener thread never managed to create.
            handle = self._create_pipe(first=True)
            state_path = agent_state_path()
            atomic_write_json(
                state_path,
                {"version": AGENT_STATE_VERSION, "transport": "named_pipe", "pipe": self.pipe_name,
                 **protect_agent_token(self.token), "pid": os.getpid(), "user_sid": self.user_sid,
                 "bridge_revision": RELEASE_ID},
            )
            if not _restrict_file_to_current_user(state_path):
                _pipe_log("agent_state_acl_not_restricted")
            self.thread = threading.Thread(target=self._run, args=(handle,),
                                           name="localgatekeys-pipe-server", daemon=True)
            self.thread.start()
            handle = None  # listener owns the handle now
            _pipe_log(f"pipe_listener_ready revision={RELEASE_ID}")
        except Exception as exc:
            _pipe_log("pipe_listener_start_failed", exc)
            self._remove_owned_state()
            raise
        finally:
            if handle is not None:
                import win32file
                win32file.CloseHandle(handle)

    def _remove_owned_state(self) -> None:
        try:
            state_path = agent_state_path()
            state = read_json(state_path)
            if int(state.get("pid", -1)) == os.getpid() and hmac.compare_digest(
                    unprotect_agent_token(state), self.token):
                state_path.unlink(missing_ok=True)
        except (OSError, ValueError, TypeError, BridgeFailure):
            pass

    def stop(self) -> None:
        self.stop_event.set()
        # Connect once to unblock ConnectNamedPipe.
        try:
            if os.name == "nt":
                forward_named_pipe({"action": "ping"}, timeout_ms=200)
        except Exception:
            pass
        if self.thread and self.thread.is_alive():
            self.thread.join(timeout=1.5)
        self._remove_owned_state()

    def _create_pipe(self, *, first: bool = False):
        import win32pipe

        sa, _sid = _security_attributes_for_current_user()
        return win32pipe.CreateNamedPipe(
            self.pipe_name,
            win32pipe.PIPE_ACCESS_DUPLEX | (0x00080000 if first else 0),  # FILE_FLAG_FIRST_PIPE_INSTANCE
            win32pipe.PIPE_TYPE_BYTE | win32pipe.PIPE_READMODE_BYTE | win32pipe.PIPE_WAIT | 0x8,  # reject remote clients
            win32pipe.PIPE_UNLIMITED_INSTANCES,
            MAX_LOCAL_MESSAGE + 4,
            MAX_LOCAL_MESSAGE + 4,
            5000,
            sa,
        )

    def _run(self, prepared_handle: Any = None) -> None:
        import pywintypes
        import win32file
        import win32pipe

        handle = prepared_handle
        try:
            while not self.stop_event.is_set():
                if handle is None:
                    handle = self._create_pipe()
                try:
                    win32pipe.ConnectNamedPipe(handle, None)
                except pywintypes.error as exc:
                    if error_number(exc) != 535:  # client connected before ConnectNamedPipe
                        raise
                if self.stop_event.is_set():
                    break
                worker = threading.Thread(target=self._handle_client, args=(handle,),
                                          name="localgatekeys-pipe-client", daemon=True)
                worker.start()
                handle = None
        except Exception as exc:
            _pipe_log("pipe_listener_stopped_unexpectedly", exc)
        finally:
            if handle is not None:
                try:
                    win32file.CloseHandle(handle)
                except Exception:
                    pass
            self._remove_owned_state()

    def _handle_client(self, handle: Any) -> None:
        import win32file
        import win32pipe

        try:
            try:
                decision = _verify_native_host_client(handle)
                if not decision:
                    code = getattr(decision, "code", "client_not_allowed")
                    _pipe_log(f"pipe_peer_rejected code={code}")
                    response = failure_response(code, stage="peer")
                else:
                    request = _recv_pipe(handle)
                    supplied = request.pop("token", None)
                    if not isinstance(supplied, str) or not hmac.compare_digest(supplied, self.token):
                        response = failure_response("unauthorized", stage="peer")
                    elif (getattr(decision, "scope", "diagnostic") != "browser"
                          and request.get("action") not in DIAGNOSTIC_ACTIONS):
                        # The pinned host binary was started by something other
                        # than a signed browser (SEC-I1): never relay vault actions.
                        _pipe_log("pipe_peer_not_browser")
                        response = _browser_unverified_response()
                    else:
                        response = self.dispatcher(request)
            except Exception as exc:
                _pipe_log("pipe_request_failed", exc)
                response = failure_response("bridge_protocol_error", stage="receive")
            _send_pipe(handle, response)
            # Applies to rejected identities too. DisconnectNamedPipe discards
            # unread bytes; the old early return hid client_not_allowed as EOF.
            _flush_reply(handle)
        except Exception as exc:
            # Never append a second frame after a potentially partial reply.
            _pipe_log("pipe_reply_failed", exc)
        finally:
            try:
                win32pipe.DisconnectNamedPipe(handle)
            except Exception:
                pass
            try:
                win32file.CloseHandle(handle)
            except Exception:
                pass


def _open_pipe(pipe_name: str, timeout_ms: int) -> Any:
    """Retry only pre-send connection races, never a dispatched operation."""
    import win32con
    import win32file
    import win32pipe

    deadline = time.monotonic() + max(1, min(int(timeout_ms), 10000)) / 1000
    while True:
        try:
            remaining = max(1, int((deadline - time.monotonic()) * 1000))
            win32pipe.WaitNamedPipe(pipe_name, remaining)
            # SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION: a server that is
            # not the agent may identify this client but never impersonate it.
            return win32file.CreateFile(
                pipe_name, win32con.GENERIC_READ | win32con.GENERIC_WRITE,
                0, None, win32con.OPEN_EXISTING, PIPE_CLIENT_SQOS_FLAGS, None)
        except Exception as exc:
            number = error_number(exc)
            # A listener can be between instances; WaitNamedPipe may return
            # immediately even with a nonzero timeout when none exists yet.
            if number in (2, 3, 121, 231) and time.monotonic() < deadline:
                time.sleep(min(0.025, max(0, deadline - time.monotonic())))
                continue
            response = classify_failure(exc, "connect")
            raise BridgeFailure(response["error"], "connect", number) from exc


def forward_named_pipe(request: dict[str, Any], timeout_ms: int = 5000, *,
                       state: dict[str, Any] | None = None) -> dict[str, Any]:
    if os.name != "nt":
        raise RuntimeError("Named pipes are available only on Windows")
    import win32file

    if state is None:
        state = read_json(agent_state_path())
    pipe_name = state.get("pipe")
    try:
        token = unprotect_agent_token(state) if isinstance(state.get("token"), str) else None
    except BridgeFailure:
        token = None
    expected_sid = state.get("user_sid")
    expected_pid = state.get("pid")
    if (state.get("transport") != "named_pipe" or
            not isinstance(pipe_name, str) or not pipe_name.startswith(PIPE_PREFIX) or
            len(pipe_name) != len(PIPE_PREFIX) + 32 or
            any(c not in "0123456789abcdef" for c in pipe_name[len(PIPE_PREFIX):]) or
            not isinstance(token, str) or not 32 <= len(token) <= 256 or
            not isinstance(expected_sid, str) or not expected_sid or
            type(expected_pid) is not int or expected_pid <= 0):
        raise BridgeFailure("agent_state_invalid", "state")
    if expected_sid != _current_user_sid_string():
        raise BridgeFailure("agent_access_denied", "peer")

    handle = _open_pipe(pipe_name, timeout_ms)
    try:
        if _named_pipe_server_pid(handle) != expected_pid:
            raise BridgeFailure("agent_connection_changed", "peer")
        outbound = dict(request)
        outbound["token"] = token
        # No automatic retry after this point: a save/fill/sign-in may already
        # have reached the app even if its reply is lost.
        try:
            _send_pipe(handle, outbound)
        except Exception as exc:
            result = classify_failure(exc, "send")
            raise BridgeFailure(result["error"], "send", error_number(exc)) from exc
        finally:
            outbound.clear()
        try:
            return _recv_pipe(handle)
        except Exception as exc:
            result = classify_failure(exc, "receive")
            if isinstance(exc, ProtocolError):
                result = failure_response("bridge_protocol_error", stage="receive")
            raise BridgeFailure(result["error"], "receive", error_number(exc)) from exc
    finally:
        win32file.CloseHandle(handle)
