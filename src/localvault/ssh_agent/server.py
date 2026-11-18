"""The SSH agent's named pipe (Windows): ``\\\\.\\pipe\\localgatekeys-ssh-<user SID>``.

Same hardening as the app pipe (``pipe_transport``): FIRST_PIPE_INSTANCE, a current-user-only DACL and remote clients
rejected. Unlike the app pipe, a connection stays open: ``ssh`` sends several requests on one connection. Each
connection has its own daemon thread, at most 16 at once; a client beyond that is closed at once.

A connection bound with ``session-bind@openssh.com`` remembers the host for the prompt. A connection that was ever
bound for forwarding (``ssh -A``) lists nothing and signs nothing: the vault's keys are never served to other hosts.
"""
from __future__ import annotations

import logging
import threading
import time
from collections.abc import Callable
from typing import Any

from ..bridge_status import error_number
from ..local_clients import identify
from ..pipe_transport import (
    PIPE_CLIENT_SQOS_FLAGS,
    _current_user_sid_string,
    _named_pipe_client_pid,
    _named_pipe_server_pid,
    _process_user_sid,
    _security_attributes_for_current_user,
)
from . import protocol as p

_log = logging.getLogger(__name__)
PIPE_PREFIX = "\\\\.\\pipe\\localgatekeys-ssh-"
MAX_CONNECTIONS = 16
FILE_FLAG_FIRST_PIPE_INSTANCE = 0x00080000
PIPE_REJECT_REMOTE_CLIENTS = 0x00000008
BUFFER_SIZE = 64 * 1024
STOP_TIMEOUT = 2.0
IDLE_TIMEOUT = 300.0  # a connection with no request for this long is closed, so idle clients cannot hold all slots
_ERROR_PIPE_CONNECTED = 535
_EOF_ERRORS = (109, 232, 233)  # broken pipe, no data, not connected: the client went away


def default_pipe_name() -> str:
    return PIPE_PREFIX + _current_user_sid_string()


def pipe_held_by_current_user(pipe_name: str) -> bool:
    """Whether the process serving ``pipe_name`` runs as this Windows user; False when that cannot be shown.

    Opened with SQOS identification (the server may identify this probe, never impersonate it); nothing is sent.
    """
    try:
        import win32con
        import win32file

        handle = win32file.CreateFile(pipe_name, win32con.GENERIC_READ, 0, None, win32con.OPEN_EXISTING,
                                      PIPE_CLIENT_SQOS_FLAGS, None)
    except Exception:  # noqa: BLE001 - busy, gone or refused: not shown to be ours
        return False
    try:
        pid = _named_pipe_server_pid(handle)
        return bool(pid) and _process_user_sid(pid) == _current_user_sid_string()
    except Exception:  # noqa: BLE001
        return False
    finally:
        try:
            handle.Close()
        except Exception:  # noqa: BLE001
            _log.debug("SSH agent probe handle was already closed")


def _cancel_thread_io(native_id: int) -> None:
    """Cancel a blocking ReadFile/ConnectNamedPipe on another thread (synchronous handles serialise other calls)."""
    import ctypes
    from ctypes import wintypes

    kernel32 = ctypes.windll.kernel32
    kernel32.OpenThread.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    kernel32.OpenThread.restype = wintypes.HANDLE
    kernel32.CancelSynchronousIo.argtypes = [wintypes.HANDLE]
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    handle = kernel32.OpenThread(0x0001, False, int(native_id))  # THREAD_TERMINATE, which CancelSynchronousIo needs
    if handle:
        try:
            kernel32.CancelSynchronousIo(handle)
        finally:
            kernel32.CloseHandle(handle)


class _Connection:
    def __init__(self, handle: Any, pid: int | None) -> None:
        self.handle = handle
        self.pid = pid
        self.client: Any = None
        self.bound_host: str | None = None
        self.bound = False
        self.forwarding = False


class _IdleWatch:
    """Cancel a connection's blocking header read once it has waited ``timeout`` seconds for a request."""

    def __init__(self, timeout: float) -> None:
        self._timeout = timeout
        self._cond = threading.Condition()
        self._waiting_since: float | None = None
        self._native_id: int | None = None
        self._done = False
        self.expired = False
        self._thread = threading.Thread(target=self._watch, name="lgk-ssh-agent-idle", daemon=True)

    def start(self) -> None:
        self._native_id = threading.get_native_id()
        self._thread.start()

    def waiting(self, value: bool) -> None:
        with self._cond:
            self._waiting_since = time.monotonic() if value else None
            self._cond.notify_all()

    def close(self) -> None:
        with self._cond:
            self._done = True
            self._cond.notify_all()

    def _watch(self) -> None:
        with self._cond:
            while not self._done:
                since = self._waiting_since
                if since is None:
                    self._cond.wait()
                    continue
                remaining = since + self._timeout - time.monotonic()
                if remaining > 0:
                    self._cond.wait(remaining)
                    continue
                # Still waiting for a header: cancel the read, and again shortly in case it had not started yet.
                self.expired = True
                try:
                    _cancel_thread_io(self._native_id)
                except Exception:  # noqa: BLE001
                    _log.debug("SSH agent could not cancel an idle read", exc_info=True)
                self._cond.wait(0.05)


class SshAgentServer:
    def __init__(self, pipe_name: str, service: Any, *, identify_client: Callable[[int], Any] | None = None,
                 idle_timeout: float = IDLE_TIMEOUT,
                 held_by_current_user: Callable[[str], bool] = pipe_held_by_current_user) -> None:
        self.pipe_name = pipe_name
        self.service = service
        self._identify = identify_client or identify
        self._held_by_current_user = held_by_current_user
        self._idle_timeout = idle_timeout
        self._stop = threading.Event()
        self._lock = threading.Lock()
        self._workers: set[threading.Thread] = set()
        self.thread: threading.Thread | None = None
        # "running", "unavailable" (name held by this user's own process, or not creatable), "taken" (held by a
        # process of another account or one that cannot be checked: ssh must not be pointed at it), "stopped".
        self.status = "stopped"

    # ---------------------------------------------------------------- lifecycle
    def start(self) -> None:
        if self.thread is not None and self.thread.is_alive():
            return
        self._stop.clear()
        try:
            handle = self._create_pipe(first=True)
        except Exception as exc:  # noqa: BLE001 - another process holds the name: report, never crash the app
            try:
                ours = self._held_by_current_user(self.pipe_name) is True
            except Exception:  # noqa: BLE001
                ours = False
            self.status = "unavailable" if ours else "taken"
            _log.warning("SSH agent pipe is %s (error %s)", self.status, error_number(exc))
            return
        self.status = "running"
        self.thread = threading.Thread(target=self._run, args=(handle,), name="lgk-ssh-agent", daemon=True)
        self.thread.start()

    def stop(self) -> None:
        self._stop.set()
        deadline = time.monotonic() + STOP_TIMEOUT
        while time.monotonic() < deadline:
            with self._lock:
                threads = [w for w in self._workers if w.is_alive()]
            if self.thread is not None and self.thread.is_alive():
                threads.append(self.thread)
            if not threads:
                break
            for thread in threads:
                if thread.native_id is not None:
                    try:
                        _cancel_thread_io(thread.native_id)
                    except Exception:  # noqa: BLE001
                        _log.debug("SSH agent could not cancel a pipe wait", exc_info=True)
            for thread in threads:
                thread.join(0.05)
        else:
            _log.warning("SSH agent threads did not stop in time")
        if self.status == "running":
            self.status = "stopped"

    def active_connections(self) -> int:
        with self._lock:
            return len(self._workers)

    # ---------------------------------------------------------------- pipe
    def _create_pipe(self, *, first: bool = False) -> Any:
        import win32pipe

        sa, _sid = _security_attributes_for_current_user()
        return win32pipe.CreateNamedPipe(
            self.pipe_name,
            win32pipe.PIPE_ACCESS_DUPLEX | (FILE_FLAG_FIRST_PIPE_INSTANCE if first else 0),
            win32pipe.PIPE_TYPE_BYTE | win32pipe.PIPE_READMODE_BYTE | win32pipe.PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
            win32pipe.PIPE_UNLIMITED_INSTANCES,
            BUFFER_SIZE,
            BUFFER_SIZE,
            5000,
            sa,
        )

    @staticmethod
    def _close(handle: Any) -> None:
        import win32file
        import win32pipe

        try:
            win32pipe.DisconnectNamedPipe(handle)
        except Exception:  # noqa: BLE001 - already disconnected
            _log.debug("SSH agent pipe was already disconnected")
        try:
            win32file.CloseHandle(handle)
        except Exception:  # noqa: BLE001
            _log.debug("SSH agent pipe handle was already closed")

    def _run(self, handle: Any) -> None:
        """Accept clients. The next listening instance is always created before the current one is handed to a
        worker or closed, so the name never has zero instances that another user could squat."""
        import pywintypes
        import win32pipe

        try:
            while not self._stop.is_set():
                connected = True
                try:
                    win32pipe.ConnectNamedPipe(handle, None)
                except pywintypes.error as exc:
                    if error_number(exc) != _ERROR_PIPE_CONNECTED:  # connected before ConnectNamedPipe: fine
                        connected = False  # the client left before it was accepted
                if self._stop.is_set():
                    break
                current, handle = handle, None
                try:
                    handle = self._create_pipe()
                finally:
                    if handle is None:
                        self._close(current)
                if not connected:
                    self._close(current)
                    time.sleep(0.01)
                    continue
                with self._lock:
                    full = len(self._workers) >= MAX_CONNECTIONS
                    if not full:
                        worker = threading.Thread(target=self._serve, args=(current,),
                                                  name="lgk-ssh-agent-client", daemon=True)
                        self._workers.add(worker)
                if full:
                    _log.info("SSH agent refused a connection: %d already open", MAX_CONNECTIONS)
                    self._close(current)
                    continue
                worker.start()
        except Exception as exc:  # noqa: BLE001
            if not self._stop.is_set():
                self.status = "unavailable"
                _log.warning("SSH agent listener stopped (error %s)", error_number(exc))
        finally:
            if handle is not None:
                self._close(handle)

    # ---------------------------------------------------------------- one connection
    @staticmethod
    def _read(handle: Any, length: int, *, eof_ok: bool = False) -> bytes | None:
        import pywintypes
        import win32file

        chunks: list[bytes] = []
        remaining = length
        while remaining:
            try:
                _hr, data = win32file.ReadFile(handle, remaining)
            except pywintypes.error as exc:
                if eof_ok and not chunks and error_number(exc) in _EOF_ERRORS:
                    return None
                raise
            if not data:
                if eof_ok and not chunks:
                    return None
                raise p.AgentProtocolError("truncated frame")
            chunks.append(bytes(data))
            remaining -= len(data)
        return b"".join(chunks)

    @staticmethod
    def _write(handle: Any, blob: bytes) -> None:
        import win32file

        written = 0
        while written < len(blob):
            _hr, count = win32file.WriteFile(handle, blob[written:])
            if count <= 0:
                raise OSError("SSH agent pipe write failed")
            written += count

    def _serve(self, handle: Any) -> None:
        connection = _Connection(handle, _named_pipe_client_pid(handle))
        idle = _IdleWatch(self._idle_timeout)
        try:
            idle.start()
            while not self._stop.is_set():
                idle.waiting(True)
                try:
                    header = self._read(handle, 4, eof_ok=True)
                finally:
                    idle.waiting(False)
                if header is None:
                    break
                body = self._read(handle, p.check_length(header))
                message = p.decode(header + (body or b""))
                if self._stop.is_set():
                    break
                reply = self._reply(message, connection)
                if self._stop.is_set():
                    break  # turned off while a prompt was open: the answer is not sent
                self._write(handle, p.encode(reply))
        except p.AgentProtocolError as exc:
            _log.info("SSH agent closed a connection: %s", exc)
        except Exception as exc:  # noqa: BLE001 - client gone, cancelled by stop(), or a broken pipe
            if idle.expired:
                _log.info("SSH agent closed an idle connection")
            else:
                _log.debug("SSH agent connection ended (error %s)", error_number(exc))
        finally:
            idle.close()
            with self._lock:
                self._workers.discard(threading.current_thread())
            self._close(handle)

    def _reply(self, message: p.AgentMessage, connection: _Connection) -> p.AgentMessage:
        try:
            if message.type == p.REQUEST_IDENTITIES:
                identities = () if connection.forwarding else tuple(self.service.identities())
                return p.AgentMessage(p.IDENTITIES_ANSWER, identities=identities)
            if message.type == p.SIGN_REQUEST:
                if connection.forwarding:
                    _log.info("SSH agent refused a signature on a forwarded connection")
                    return p.AgentMessage(p.FAILURE)
                if connection.client is None:
                    connection.client = self._identify(connection.pid or 0)
                signature = self.service.sign(message.key_blob, message.data, message.flags, connection.client,
                                              connection.bound_host)
                if signature is None:
                    return p.AgentMessage(p.FAILURE)
                return p.AgentMessage(p.SIGN_RESPONSE, signature=signature)
            if message.type == p.EXTENSION and message.bind is not None:
                bind = message.bind
                # Fail closed, before anything else: ssh keeps forwarding after a refused bind, so a forwarding
                # bind marks the connection even when its host signature cannot be checked. Once forwarded,
                # always forwarded.
                connection.forwarding = connection.forwarding or bind.forwarding
                if connection.bound:
                    return p.AgentMessage(p.FAILURE)  # one bind per connection: a rebind is refused, as in OpenSSH
                if not self.service.verify_bind(bind.host_key, bind.session_id, bind.signature):
                    return p.AgentMessage(p.FAILURE)  # only the host name depends on the signature
                connection.bound = True
                connection.bound_host = self.service.host_name_for(bind.host_key) or None
                return p.AgentMessage(p.SUCCESS)
        except Exception as exc:  # noqa: BLE001 - the client gets FAILURE
            _log.warning("SSH agent request failed: %s", type(exc).__name__)
            return p.AgentMessage(p.FAILURE)
        return p.reply_for_unsupported(message)
