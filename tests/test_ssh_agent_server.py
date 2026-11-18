"""SSH agent pipe server: pipe flags and DACL, persistent connections, the 16-connection cap, stop.

The unit tests fake win32pipe/win32file/pywintypes. The integration test runs Windows OpenSSH's own ssh-add and
ssh-keygen against a server on a unique test pipe, with a fake service holding a test-only key; it never touches the
user's real agent or ~/.ssh.
"""
from __future__ import annotations

import json
import os
import queue
import struct
import subprocess
import sys
import threading
import time
import uuid
from pathlib import Path
from types import SimpleNamespace as NS

import pytest

from localvault.ssh_agent import protocol as p
from localvault.ssh_agent import server as srv
from localvault.ssh_keys import load_private_key

VECTORS = Path(__file__).parent / "vectors" / "ssh"
EXPECTED = json.loads((VECTORS / "expected.json").read_text(encoding="utf-8"))


class WinError(Exception):
    pass


class FakeHandle:
    def __init__(self, number: int) -> None:
        self.number = number
        self.incoming: queue.Queue = queue.Queue()
        self.written = bytearray()
        self.closed = False
        self.disconnected = False


class FakePipes:
    """win32pipe + win32file stand-ins: CreateNamedPipe hands out FakeHandles, ConnectNamedPipe waits for a client."""

    PIPE_ACCESS_DUPLEX = 0x3
    PIPE_TYPE_BYTE = 0x0
    PIPE_READMODE_BYTE = 0x0
    PIPE_WAIT = 0x0
    PIPE_UNLIMITED_INSTANCES = 255

    def __init__(self) -> None:
        self.created: list[tuple] = []
        self.handles: list[FakeHandle] = []
        self.clients: queue.Queue = queue.Queue()
        self.create_error: Exception | None = None
        self.events: list[tuple[str, int]] = []

    # win32pipe
    def CreateNamedPipe(self, name, open_mode, pipe_mode, max_instances, out_size, in_size, timeout, sa):
        if self.create_error is not None:
            raise self.create_error
        self.created.append((name, open_mode, pipe_mode, max_instances, sa))
        handle = FakeHandle(len(self.handles) + 1)
        self.events.append(("create", handle.number))
        self.handles.append(handle)
        return handle

    def ConnectNamedPipe(self, handle, overlapped):
        frames = self.clients.get()
        if frames is CANCEL:
            raise WinError(995, "ConnectNamedPipe", "cancelled")
        if isinstance(frames, Exception):
            raise frames
        for frame in frames:
            handle.incoming.put(frame)
        return 0

    def DisconnectNamedPipe(self, handle):
        handle.disconnected = True

    # win32file
    def ReadFile(self, handle, size):
        data = handle.incoming.get()
        if data is CANCEL or data is None:
            handle.incoming.put(data)  # stays at EOF
            raise WinError(109 if data is None else 995, "ReadFile", "ended")
        if len(data) > size:
            handle.incoming.queue.appendleft(data[size:])
            data = data[:size]
        return 0, data

    def WriteFile(self, handle, data):
        handle.written += bytes(data)
        return 0, len(data)

    def CloseHandle(self, handle):
        if not handle.closed:
            self.events.append(("close", handle.number))
        handle.closed = True

    def FlushFileBuffers(self, handle):
        pass

    def cancel_all(self, _native_id=None):
        self.clients.put(CANCEL)
        for handle in self.handles:
            handle.incoming.put(CANCEL)


CANCEL = object()


@pytest.fixture
def fake(monkeypatch):
    pipes = FakePipes()
    monkeypatch.setitem(sys.modules, "win32pipe", pipes)
    monkeypatch.setitem(sys.modules, "win32file", pipes)
    monkeypatch.setitem(sys.modules, "pywintypes", NS(error=WinError))
    monkeypatch.setattr(srv, "_security_attributes_for_current_user", lambda: ("USER-ONLY-SA", "S-1-5-21-1"))
    monkeypatch.setattr(srv, "_named_pipe_client_pid", lambda handle: 4242)
    monkeypatch.setattr(srv, "_cancel_thread_io", pipes.cancel_all)
    return pipes


class FakeService:
    def __init__(self, gate: threading.Event | None = None) -> None:
        self.gate = gate
        self.signed: list = []

    def identities(self):
        if self.gate is not None:
            self.gate.wait(5)
        return [(b"BLOB", "comment")]

    def sign(self, blob, data, flags, client, bound_host):
        self.signed.append((blob, data, flags, client, bound_host))
        return b"SIG"

    def verify_bind(self, host_key, session_id, signature):
        return signature == b"good"

    def host_name_for(self, host_key):
        return "github.com"


def _frames(*messages: p.AgentMessage) -> list[bytes]:
    return [p.encode(message) for message in messages]


def _replies(data: bytes) -> list[p.AgentMessage]:
    out, pos = [], 0
    while pos < len(data):
        (length,) = struct.unpack_from(">I", data, pos)
        out.append(p.decode(data[pos:pos + 4 + length]))
        pos += 4 + length
    return out


def _wait(condition, seconds=3.0):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if condition():
            return True
        time.sleep(0.01)
    return False


def test_default_pipe_name_is_per_user(monkeypatch):
    monkeypatch.setattr(srv, "_current_user_sid_string", lambda: "S-1-5-21-7")
    assert srv.default_pipe_name() == r"\\.\pipe\localgatekeys-ssh-S-1-5-21-7"


def test_pipe_created_first_instance_with_user_dacl(fake):
    server = srv.SshAgentServer(r"\\.\pipe\localgatekeys-ssh-test", FakeService())
    server.start()
    try:
        assert server.status == "running"
        name, open_mode, pipe_mode, _max, sa = fake.created[0]
        assert name == r"\\.\pipe\localgatekeys-ssh-test"
        assert open_mode & srv.FILE_FLAG_FIRST_PIPE_INSTANCE and open_mode & FakePipes.PIPE_ACCESS_DUPLEX
        assert pipe_mode & srv.PIPE_REJECT_REMOTE_CLIENTS
        assert sa == "USER-ONLY-SA"
    finally:
        server.stop()


def test_name_taken_reports_unavailable(fake):
    fake.create_error = WinError(5, "CreateNamedPipe", "Access is denied.")
    server = srv.SshAgentServer(r"\\.\pipe\localgatekeys-ssh-test", FakeService(),
                                held_by_current_user=lambda name: True)
    server.start()  # never raises
    assert server.status == "unavailable" and server.thread is None


@pytest.mark.skipif(sys.platform != "win32", reason="named pipes")
def test_probe_recognises_a_pipe_of_this_user():
    import uuid

    import win32file
    import win32pipe

    name = r"\\.\pipe\lgk-test-probe-" + uuid.uuid4().hex
    assert srv.pipe_held_by_current_user(name) is False  # nothing there
    handle = win32pipe.CreateNamedPipe(name, win32pipe.PIPE_ACCESS_DUPLEX, win32pipe.PIPE_TYPE_BYTE, 1,
                                       1024, 1024, 0, None)
    try:
        assert srv.pipe_held_by_current_user(name) is True
    finally:
        win32file.CloseHandle(handle)


@pytest.mark.parametrize("check", [lambda name: False, lambda name: 1 / 0])
def test_name_held_by_another_account_reports_taken(fake, check):
    """F2: a squatter of another account (or an owner that cannot be checked) is a warning state."""
    fake.create_error = WinError(5, "CreateNamedPipe", "Access is denied.")
    server = srv.SshAgentServer(r"\\.\pipe\localgatekeys-ssh-test", FakeService(), held_by_current_user=check)
    server.start()
    assert server.status == "taken" and server.thread is None


def test_persistent_connection_multiple_frames(fake):
    service = FakeService()
    server = srv.SshAgentServer("pipe", service)
    handle = FakeHandle(1)
    bind = p.SessionBind(b"HK", b"SID", b"good", False)
    for frame in _frames(p.AgentMessage(p.REQUEST_IDENTITIES),
                         p.AgentMessage(p.EXTENSION, extension=p.SESSION_BIND, bind=bind),
                         p.AgentMessage(p.SIGN_REQUEST, key_blob=b"BLOB", data=b"D", flags=2),
                         p.AgentMessage(17),  # ADD_IDENTITY: refused
                         p.AgentMessage(p.EXTENSION, extension="query"),
                         p.AgentMessage(p.SIGN_REQUEST, key_blob=b"BLOB", data=b"E", flags=0)):
        handle.incoming.put(frame)
    handle.incoming.put(None)  # client closes
    identities = []
    server._identify = lambda pid: identities.append(pid) or NS(pid=pid)
    server._serve(handle)
    replies = _replies(bytes(handle.written))
    assert [r.type for r in replies] == [p.IDENTITIES_ANSWER, p.SUCCESS, p.SIGN_RESPONSE, p.FAILURE, p.FAILURE,
                                         p.SIGN_RESPONSE]
    assert replies[0].identities == ((b"BLOB", "comment"),) and replies[2].signature == b"SIG"
    assert [s[4] for s in service.signed] == ["github.com", "github.com"]
    assert identities == [4242]  # identified once per connection
    assert handle.disconnected and handle.closed


def test_forwarded_connection_never_signs(fake):
    service = FakeService()
    server = srv.SshAgentServer("pipe", service)
    handle = FakeHandle(1)
    for frame in _frames(p.AgentMessage(p.EXTENSION, extension=p.SESSION_BIND,
                                        bind=p.SessionBind(b"HK", b"SID", b"good", True)),
                         p.AgentMessage(p.EXTENSION, extension=p.SESSION_BIND,
                                        bind=p.SessionBind(b"HK", b"SID2", b"good", False)),
                         p.AgentMessage(p.REQUEST_IDENTITIES),
                         p.AgentMessage(p.SIGN_REQUEST, key_blob=b"BLOB", data=b"D", flags=2)):
        handle.incoming.put(frame)
    handle.incoming.put(None)
    server._identify = lambda pid: NS(pid=pid)
    server._serve(handle)
    replies = _replies(bytes(handle.written))
    # The second bind is a rebind (refused) and cannot lift the forwarding mark.
    assert [r.type for r in replies] == [p.SUCCESS, p.FAILURE, p.IDENTITIES_ANSWER, p.FAILURE]
    assert replies[2].identities == () and service.signed == []


def test_unverifiable_forwarding_bind_still_marks_forwarding(fake):
    # e.g. a host key type or signature algorithm the agent cannot check: ssh keeps forwarding after the refusal.
    service = FakeService()
    server = srv.SshAgentServer("pipe", service)
    handle = FakeHandle(1)
    for frame in _frames(p.AgentMessage(p.EXTENSION, extension=p.SESSION_BIND,
                                        bind=p.SessionBind(b"HK", b"SID", b"unverifiable", True)),
                         p.AgentMessage(p.SIGN_REQUEST, key_blob=b"BLOB", data=b"D", flags=2),
                         p.AgentMessage(p.REQUEST_IDENTITIES)):
        handle.incoming.put(frame)
    handle.incoming.put(None)
    server._identify = lambda pid: NS(pid=pid)
    server._serve(handle)
    replies = _replies(bytes(handle.written))
    assert [r.type for r in replies] == [p.FAILURE, p.FAILURE, p.IDENTITIES_ANSWER]
    assert replies[2].identities == () and service.signed == []


def test_second_bind_refused_and_host_kept(fake):
    service = FakeService()
    names = iter(["first.example", "second.example"])
    service.host_name_for = lambda host_key: next(names)
    server = srv.SshAgentServer("pipe", service)
    handle = FakeHandle(1)
    for frame in _frames(p.AgentMessage(p.EXTENSION, extension=p.SESSION_BIND,
                                        bind=p.SessionBind(b"HK", b"SID", b"good", False)),
                         p.AgentMessage(p.EXTENSION, extension=p.SESSION_BIND,
                                        bind=p.SessionBind(b"HK2", b"SID2", b"good", False)),
                         p.AgentMessage(p.SIGN_REQUEST, key_blob=b"BLOB", data=b"D", flags=2)):
        handle.incoming.put(frame)
    handle.incoming.put(None)
    server._identify = lambda pid: NS(pid=pid)
    server._serve(handle)
    replies = _replies(bytes(handle.written))
    assert [r.type for r in replies] == [p.SUCCESS, p.FAILURE, p.SIGN_RESPONSE]
    assert service.signed[0][4] == "first.example"


def test_next_instance_created_before_hand_off(fake):
    server = srv.SshAgentServer("pipe", FakeService())
    seen = []
    real_serve = server._serve
    server._serve = lambda handle: seen.append(list(fake.events)) or real_serve(handle)
    server.start()
    try:
        fake.clients.put([])  # an idle client
        assert _wait(lambda: seen)
        # Handle 2 (the next listener) existed before handle 1 reached its worker.
        assert ("create", 2) in seen[0]
    finally:
        server.stop()


def test_next_instance_created_before_closing_a_failed_accept(fake):
    server = srv.SshAgentServer("pipe", FakeService())
    server.start()
    try:
        fake.clients.put(WinError(232, "ConnectNamedPipe", "The pipe is being closed."))
        assert _wait(lambda: ("close", 1) in fake.events)
        assert fake.events.index(("create", 2)) < fake.events.index(("close", 1))
        assert server.status == "running"
    finally:
        server.stop()


def test_idle_connection_closed(fake, monkeypatch):
    handle = FakeHandle(1)
    monkeypatch.setattr(srv, "_cancel_thread_io", lambda native_id: handle.incoming.put(CANCEL))
    server = srv.SshAgentServer("pipe", FakeService(), idle_timeout=0.2)
    handle.incoming.put(p.encode(p.AgentMessage(p.REQUEST_IDENTITIES)))  # one request, then silence
    worker = threading.Thread(target=server._serve, args=(handle,), daemon=True)
    started = time.monotonic()
    worker.start()
    worker.join(3)
    assert not worker.is_alive() and handle.closed
    assert 0.2 <= time.monotonic() - started < 3
    assert [r.type for r in _replies(bytes(handle.written))] == [p.IDENTITIES_ANSWER]


def test_bad_frames_close_the_connection(fake):
    server = srv.SshAgentServer("pipe", FakeService())
    for bad in (struct.pack(">I", p.MAX_FRAME + 1), struct.pack(">I", 0),
                p.encode(p.AgentMessage(p.REQUEST_IDENTITIES))[:4] + b"\x0d" * 0):
        handle = FakeHandle(1)
        handle.incoming.put(bad)
        handle.incoming.put(None)
        server._serve(handle)
        assert bytes(handle.written) == b"" and handle.closed


def test_connection_cap_16(fake):
    gate = threading.Event()
    server = srv.SshAgentServer("pipe", FakeService(gate))
    server.start()
    try:
        # 16 clients each wait inside REQUEST_IDENTITIES; the 17th is closed at once.
        for _ in range(srv.MAX_CONNECTIONS + 1):
            fake.clients.put(_frames(p.AgentMessage(p.REQUEST_IDENTITIES)))
        assert _wait(lambda: len(fake.handles) >= srv.MAX_CONNECTIONS + 2)
        extra = fake.handles[srv.MAX_CONNECTIONS]
        assert _wait(lambda: extra.closed)
        assert extra.written == b"" and server.active_connections() == srv.MAX_CONNECTIONS
        gate.set()
        assert _wait(lambda: all(h.written for h in fake.handles[:srv.MAX_CONNECTIONS]))
    finally:
        gate.set()
        server.stop()


def test_stop_closes_listeners(fake):
    server = srv.SshAgentServer("pipe", FakeService())
    server.start()
    fake.clients.put([])  # one idle client stays connected
    assert _wait(lambda: server.active_connections() == 1)
    server.stop()
    assert server.status == "stopped"
    assert not server.thread.is_alive() and server.active_connections() == 0
    assert all(h.closed for h in fake.handles)


# ------------------------------------------------------------------ integration (real pipe, real OpenSSH)
OPENSSH = Path(r"C:\Windows\System32\OpenSSH")


class VectorService:
    """A fake service over the test-only ed25519 vector key; approves every signature."""

    def __init__(self) -> None:
        self.key = load_private_key((VECTORS / "ed25519.key").read_text(encoding="ascii"), None)
        self.signed = 0

    def identities(self):
        return [(self.key.public_blob, "test-only ed25519")]

    def sign(self, blob, data, flags, client, bound_host):
        if blob != self.key.public_blob:
            return None
        self.signed += 1
        return self.key.sign(data, flags)

    def verify_bind(self, host_key, session_id, signature):
        return False

    def host_name_for(self, host_key):
        return ""


def _openssh_env(pipe_name: str, home: Path) -> dict:
    env = {k: v for k, v in os.environ.items() if k.upper() not in ("SSH_AUTH_SOCK", "HOME", "USERPROFILE")}
    env["SSH_AUTH_SOCK"] = pipe_name
    env["HOME"] = env["USERPROFILE"] = str(home)  # never the real ~/.ssh
    return env


@pytest.mark.skipif(os.name != "nt" or not (OPENSSH / "ssh-add.exe").exists(), reason="Windows OpenSSH not installed")
def test_openssh_lists_and_signs_through_the_pipe(tmp_path):
    pipe_name = rf"\\.\pipe\localgatekeys-ssh-test-{uuid.uuid4().hex}"
    service = VectorService()
    server = srv.SshAgentServer(pipe_name, service)
    server.start()
    try:
        assert server.status == "running"
        env = _openssh_env(pipe_name, tmp_path)
        listed = subprocess.run([str(OPENSSH / "ssh-add.exe"), "-L"], env=env, capture_output=True, text=True,
                                timeout=30)
        assert listed.returncode == 0, listed.stderr
        assert EXPECTED["keys"]["ed25519"]["public_line"] in listed.stdout
        print("ssh-add -L:", listed.stdout.strip())

        pub = tmp_path / "id.pub"
        pub.write_text(EXPECTED["keys"]["ed25519"]["public_line"] + "\n", encoding="ascii")
        message = tmp_path / "message.txt"
        message.write_text("signed through the LocalGateKeys test agent\n", encoding="ascii")
        signed = subprocess.run([str(OPENSSH / "ssh-keygen.exe"), "-Y", "sign", "-f", str(pub), "-n", "git",
                                 str(message)], env=env, capture_output=True, text=True, timeout=30)
        assert signed.returncode == 0, signed.stderr
        assert (tmp_path / "message.txt.sig").read_text().startswith("-----BEGIN SSH SIGNATURE-----")
        assert service.signed == 1
        allowed = tmp_path / "allowed"
        allowed.write_text("me@test " + EXPECTED["keys"]["ed25519"]["public_line"] + "\n", encoding="ascii")
        with message.open("rb") as stdin:
            verified = subprocess.run([str(OPENSSH / "ssh-keygen.exe"), "-Y", "verify", "-f", str(allowed),
                                       "-I", "me@test", "-n", "git", "-s", str(tmp_path / "message.txt.sig")],
                                      env=env, stdin=stdin, capture_output=True, text=True, timeout=30)
        assert verified.returncode == 0, verified.stdout + verified.stderr
        print("ssh-keygen -Y sign/verify:", verified.stdout.strip())
    finally:
        server.stop()
    assert server.status == "stopped"
    # Stopped cleanly: the name is free again, so a new first instance can be created.
    again = srv.SshAgentServer(pipe_name, service)
    again.start()
    try:
        assert again.status == "running"
    finally:
        again.stop()
