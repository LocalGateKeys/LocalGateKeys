"""Security audit: local IPC and the browser-to-vault bridge.

Every test is one attack attempt (docstring ``SEC-I<n>: <attack>``).  Tests
that pass show the defense holding.  Confirmed weaknesses assert the secure
behaviour and are marked ``xfail(strict=True)`` so a fix flips them to pass.

Everything runs with fakes (no real pipe, registry, DPAPI or browser), so the
file is portable.  It deliberately avoids re-testing what
test_ipc_hardening.py, test_bridge023.py, test_origin.py, test_native_host.py,
test_broker_multi_url.py and test_phase2c_identity_broker.py already cover.
"""
from __future__ import annotations

import io
import json
import struct
import sys
import time
import zlib
from types import SimpleNamespace as NS

import pytest

import localvault.browser_ancestry as ancestry
import localvault.native_host as host
import localvault.pipe_transport as pipe
from localvault.browser_broker import BrowserBroker
from localvault.config import EXTENSION_ORIGINS
from localvault.site_icon import IconDecodeError, normalize_site_icon
from localvault.origin import base_domain, canonicalize_origin
from localvault.protocol import ProtocolError
from broker_host import BrokerHostBase as RuntimeActions
from localvault.session_guard import SessionGuard
from localvault.settings import AppSettings
from localvault.uia import (
    ControlDescriptor,
    UIAutomationError,
    WindowSnapshot,
    validate_desktop_entry,
)
from localvault.vault import create_vault

KDF = {"time_cost": 1, "memory_cost_kib": 8192, "parallelism": 1, "hash_len": 32}
MASTER = "audit-only-master-password"
SITE = "https://example.test"


# ---------------------------------------------------------------------------
# Harness
# ---------------------------------------------------------------------------

def _ctx(origin, tab: int = 17, document: str = "doc-audit-a", op: str = "op-audit-1") -> str:
    return json.dumps([tab, document, origin, op])


class _Broker(RuntimeActions, BrowserBroker):
    def __init__(self, session, **settings) -> None:
        self.session = session
        self.guard = SessionGuard("audit-profile")
        self.guard.open(3600)
        self.root = None
        self.settings = AppSettings(auto_lock_seconds=0)
        for key, value in settings.items():
            setattr(self.settings, key, value)
        self.active_profile = NS(id="audit-profile", name="Audit", color="#123456")
        self._remote_busy = False
        self.last_extension_seen = 0.0
        self.last_extension_version = ""
        self.last_secret_use = 0.0
        self._closing = False
        self.unlock_prompts = 0

    def ensure_unlocked(self):
        self.unlock_prompts += 1
        return self._session_available()

    def run_on_ui(self, function, timeout=0):
        return function()

    def refresh_entries(self):
        return None

    def _touch_secret(self):
        self.last_secret_use = time.monotonic()

    def reauthenticate(self, *args):
        return True

    @staticmethod
    def _validate_remote_text(value, field, max_len, allow_empty):
        if not isinstance(value, str) or (not allow_empty and not value) or len(value) > max_len:
            raise ValueError(field)
        return value

    def request(self, action, *, origin=SITE, context=None, **payload):
        return self.dispatch_remote({
            "action": action, "protocol": 2, "extension_version": "0.3.3", "origin": origin,
            "context": context if context is not None else _ctx(origin), **payload,
        })

    def nonce(self, *, origin=SITE, context=None):
        """A fresh broker gesture nonce for this origin and tab, as the extension mints per click."""
        return self.request("begin_gesture_browser", origin=origin, context=context,
                            user_gesture=True)["gesture_nonce"]


@pytest.fixture
def session(tmp_path):
    s = create_vault(tmp_path / "audit-ipc.json", MASTER, kdf_overrides=KDF)
    yield s
    if s.is_unlocked:
        s.lock()


def _no_secret(response, *secrets: str) -> bool:
    blob = json.dumps(response)
    return all(secret not in blob for secret in secrets)


# ---------------------------------------------------------------------------
# Native host as a confused deputy
# ---------------------------------------------------------------------------

def _frame(obj) -> bytes:
    payload = json.dumps(obj).encode("utf-8")
    return struct.pack("=I", len(payload)) + payload


def _run_native_host(monkeypatch, argv, *frames: bytes) -> list[dict]:
    out = io.BytesIO()
    monkeypatch.setattr(sys, "argv", argv)
    monkeypatch.setattr(sys, "stdin", NS(buffer=io.BytesIO(b"".join(frames))))
    monkeypatch.setattr(sys, "stdout", NS(buffer=out))
    host.main()
    data, replies = out.getvalue(), []
    while data:
        (length,) = struct.unpack("=I", data[:4])
        replies.append(json.loads(data[4:4 + length]))
        data = data[4 + length:]
    return replies


def test_sec_i1_local_process_spawns_registered_native_host_to_exfiltrate(monkeypatch, tmp_path, session):
    """SEC-I1: an arbitrary same-user process (no agent token, not a browser)
    launches the browser-registered native host itself with a forged
    ``chrome-extension://<id>/`` argv and drives begin_browser/get_browser for
    any origin it likes.  The host passes the client pin (it *is* the
    registered executable) and attaches the DPAPI-unwrapped token, so the agent
    releases the password silently while the vault is unlocked."""
    monkeypatch.setenv("LOCALGATEKEYS_DATA_DIR", str(tmp_path))
    bank = "https://bank.example"
    entry_id = session.upsert_web(origin=bank, username="victim", password="bank-secret-audit")
    broker = _Broker(session)
    # Stand-in for the pipe hop: the real _forward adds the agent token, which
    # the pin policy accepts because the peer is the registered host binary.
    monkeypatch.setattr(host, "_forward", lambda request: broker.dispatch_remote(dict(request)))
    forged_argv = ["LocalGateKeysNativeHost.exe", EXTENSION_ORIGINS[0]]
    context = json.dumps([1, "attacker-doc", bank, "attacker-op"])
    base = {"protocol": 2, "extension_version": "0.3.3", "origin": bank, "context": context}

    begin = _run_native_host(monkeypatch, forged_argv,
                             _frame({**base, "action": "begin_browser", "user_gesture": True}))
    grant = begin[0].get("grant")
    nonce = begin[0].get("gesture_nonce")
    released = _run_native_host(monkeypatch, forged_argv, _frame({
        **base, "action": "get_browser", "grant": grant, "entry_id": entry_id, "gesture_nonce": nonce}))

    # Secure behaviour: a host whose parent is not a browser refuses to relay.
    assert begin[0].get("ok") is not True
    assert _no_secret(released, "bank-secret-audit")
    assert begin[0].get("error") == "caller_not_browser" and released[0].get("error") == "caller_not_browser"


def test_sec_i1_browser_launched_host_still_relays_and_unverified_host_may_only_ping(monkeypatch, tmp_path, session):
    """SEC-I1 (fix): the parent check gates everything but ``ping`` (used by the
    app's own Connections test); a host a signed browser launched relays as before."""
    monkeypatch.setenv("LOCALGATEKEYS_DATA_DIR", str(tmp_path))
    entry_id = session.upsert_web(origin=SITE, username="alice", password="pw-audit-relay")
    broker = _Broker(session)
    forwarded = []
    monkeypatch.setattr(host, "_forward", lambda request: forwarded.append(request["action"]) or
                        broker.dispatch_remote(dict(request)))
    argv = ["LocalGateKeysNativeHost.exe", EXTENSION_ORIGINS[0]]
    base = {"protocol": 2, "extension_version": "0.3.3", "origin": SITE, "context": _ctx(SITE)}

    monkeypatch.setattr(host, "_verify_browser_parent", lambda: ancestry.AncestryDecision(False, "browser_parent_unverified"))
    replies = _run_native_host(monkeypatch, argv, _frame({**base, "action": "ping"}),
                               _frame({**base, "action": "begin_browser", "user_gesture": True}))
    assert replies[0]["ok"] is True and replies[1]["error"] == "caller_not_browser"
    assert replies[1]["message"] == ancestry.BROWSER_UNVERIFIED_MESSAGE and forwarded == ["ping"]

    monkeypatch.setattr(host, "_verify_browser_parent", lambda: (_ for _ in ()).throw(OSError("boom")))
    assert _run_native_host(monkeypatch, argv, _frame({**base, "action": "begin_browser",
                                                       "user_gesture": True}))[0]["error"] == "caller_not_browser"

    monkeypatch.setattr(host, "_verify_browser_parent", lambda: ancestry.AncestryDecision(True, "ok", "chrome.exe"))
    begin = _run_native_host(monkeypatch, argv, _frame({**base, "action": "begin_browser", "user_gesture": True}))[0]
    got = _run_native_host(monkeypatch, argv, _frame({**base, "action": "get_browser", "grant": begin["grant"],
                                                      "entry_id": entry_id, "gesture_nonce": begin["gesture_nonce"]}))
    assert got[0]["credential"]["password"] == "pw-audit-relay"


def _pipe_server(monkeypatch, decision, request):
    replies, seen = [], []
    monkeypatch.setitem(sys.modules, "win32file", NS(CloseHandle=lambda h: None))
    monkeypatch.setitem(sys.modules, "win32pipe", NS(DisconnectNamedPipe=lambda h: None))
    monkeypatch.setattr(pipe, "_flush_reply", lambda h: None)
    monkeypatch.setattr(pipe, "_pipe_log", lambda *a: None)
    monkeypatch.setattr(pipe, "_verify_native_host_client", lambda h: decision)
    server = pipe.NamedPipeAgentServer(lambda r: seen.append(dict(r)) or {"ok": True})
    monkeypatch.setattr(pipe, "_recv_pipe", lambda h: {**request, "token": server.token})
    monkeypatch.setattr(pipe, "_send_pipe", lambda h, r: replies.append(r))
    server._handle_client(5)
    return replies, seen


@pytest.mark.parametrize("action", ["begin_browser", "get_browser", "check_browser", "save_browser", None])
def test_sec_i1_agent_relays_only_ping_for_a_pinned_host_without_a_browser_launcher(monkeypatch, action):
    """SEC-I1 (fix, agent side): the registered host binary connects with the
    right token, but no signed browser launched it; only ``ping`` is dispatched."""
    for scope in ("diagnostic", "", "browser-ish"):
        replies, seen = _pipe_server(monkeypatch, pipe.PinDecision(True, scope=scope), {"action": action})
        assert seen == [] and replies[0]["error"] == "caller_not_browser" and replies[0]["stage"] == "peer"
    replies, seen = _pipe_server(monkeypatch, pipe.PinDecision(True), {"action": "ping"})
    assert seen == [{"action": "ping"}] and replies == [{"ok": True}]
    replies, seen = _pipe_server(monkeypatch, pipe.PinDecision(True, scope="browser"), {"action": action})
    assert seen == [{"action": action}]


def test_sec_i1_client_pin_extends_to_the_browser_launcher(monkeypatch):
    """SEC-I1 (fix, agent side): the pin policy grants ``browser`` scope only when
    the ancestry check passes, and passes it the pinned launcher chain."""
    monkeypatch.setattr(pipe, "os", NS(name="nt", path=pipe.os.path))
    monkeypatch.setattr(sys, "frozen", False, raising=False)
    monkeypatch.setattr(pipe, "_registered_native_host_paths", lambda: {"Chrome": "host.exe"})
    config = {"native_host_path": "host.exe", "native_host_sha256": "A" * 64,
              "interpreter_path": "python.exe", "interpreter_sha256": "B" * 64}
    monkeypatch.setattr(pipe, "read_json", lambda path: config)
    monkeypatch.setattr(pipe, "install_config_path", lambda: "unused")
    monkeypatch.setattr(pipe, "_named_pipe_client_pid", lambda h: 321)
    monkeypatch.setattr(pipe, "_sha256_file", lambda path: {"host.exe": "A" * 64, "python.exe": "B" * 64}[path])
    chain = NS(exe=lambda: "python.exe", parent=lambda: NS(exe=lambda: "host.exe", parent=lambda: None))
    monkeypatch.setitem(sys.modules, "psutil", NS(Process=lambda pid: chain))
    calls = []
    verdict = [ancestry.AncestryDecision(True, "ok", "msedge.exe")]
    monkeypatch.setattr(pipe, "_browser_ancestry", lambda pid, images: calls.append((pid, images)) or verdict[0])
    decision = pipe.ClientPinPolicy().evaluate(1)
    assert decision.allowed and decision.scope == "browser"
    assert calls == [(321, {"host.exe", "python.exe"})]
    verdict[0] = ancestry.AncestryDecision(False, "browser_parent_unverified")
    decision = pipe.ClientPinPolicy().evaluate(1)
    assert decision.allowed and decision.scope == "diagnostic"
    monkeypatch.setattr(pipe, "_browser_ancestry", lambda pid, images: (_ for _ in ()).throw(OSError()))
    assert pipe.ClientPinPolicy().evaluate(1).scope == "diagnostic"
    # A host-pin failure never reaches the browser check.
    monkeypatch.setattr(pipe, "_registered_native_host_paths", lambda: {})
    assert pipe.ClientPinPolicy().evaluate(1).code == "client_pin_unregistered"


# Fake process trees for browser_ancestry: pid -> (parent pid, image, created).
SYS32 = "C:/Windows/System32"
HOST = "C:/Apps/LGK/LocalGateKeysNativeHost.exe"
CHROME = "C:/Program Files/Google/Chrome/Application/chrome.exe"
FIREFOX = "C:/Program Files/Mozilla Firefox/firefox.exe"
SIGNERS = {CHROME: "Google LLC", FIREFOX: "Mozilla Corporation",
           "C:/Users/me/AppData/chrome.exe": "Mallory Ltd", "C:/x/msedge.exe": None}


def _ancestry(tree, pid=10, *, self_images=(HOST,)):
    def lookup(p):
        row = tree.get(p)
        return ancestry.ProcessInfo(p, row[0], row[1], row[2]) if row else None
    return ancestry.verify_browser_ancestry(
        pid, self_images=self_images, lookup=lookup, signer=SIGNERS.get,
        is_system_cmd=lambda image: image == f"{SYS32}/cmd.exe")


@pytest.mark.parametrize("tree,expected", [
    # Chrome / Edge / Brave on Windows: browser -> cmd.exe /d /s /c -> host.
    ({10: (9, HOST, 300), 9: (8, f"{SYS32}/cmd.exe", 200), 8: (1, CHROME, 100)}, "ok"),
    # Firefox (and Chromium with NativeHostsExecutablesLaunchDirectly): direct.
    ({10: (8, HOST, 300), 8: (1, FIREFOX, 100)}, "ok"),
    # Repository install: interpreter <- redirector <- launcher <- cmd <- chrome.
    ({10: (11, HOST, 400), 11: (9, HOST, 300), 9: (8, f"{SYS32}/cmd.exe", 200), 8: (1, CHROME, 100)}, "ok"),
    # Any other launcher: explorer, a script host, an attacker's process.
    ({10: (9, HOST, 300), 9: (1, "C:/Windows/explorer.exe", 100)}, "browser_parent_unverified"),
    ({10: (9, HOST, 300), 9: (8, f"{SYS32}/cmd.exe", 200), 8: (1, "C:/evil/attacker.exe", 100)},
     "browser_parent_unverified"),
    # Two shells, or a cmd.exe outside the system directory, are not the browser's hop.
    ({10: (9, HOST, 300), 9: (7, f"{SYS32}/cmd.exe", 200), 7: (8, f"{SYS32}/cmd.exe", 150),
      8: (1, CHROME, 100)}, "browser_parent_unverified"),
    ({10: (9, HOST, 300), 9: (8, "C:/evil/cmd.exe", 200), 8: (1, CHROME, 100)}, "browser_parent_unverified"),
    # A process merely named chrome.exe without Google's valid signature.
    ({10: (8, HOST, 300), 8: (1, "C:/Users/me/AppData/chrome.exe", 100)}, "browser_signer_mismatch"),
    ({10: (8, HOST, 300), 8: (1, "C:/x/msedge.exe", 100)}, "browser_signer_mismatch"),
    # PID reuse: the browser that launched us exited and its PID now belongs to
    # a newer process (created after the host) - never the launcher.
    ({10: (8, HOST, 300), 8: (1, CHROME, 500)}, "browser_parent_unverified"),
    ({10: (9, HOST, 300), 9: (8, f"{SYS32}/cmd.exe", 200), 8: (1, CHROME, 250)}, "browser_parent_unverified"),
    # Parent gone, unreadable, or the process itself unknown.
    ({10: (8, HOST, 300)}, "browser_parent_unverified"),
    ({}, "ancestry_unavailable"),
    # A loop of self images cannot be climbed forever.
    ({10: (11, HOST, 900), 11: (12, HOST, 800), 12: (13, HOST, 700), 13: (14, HOST, 600),
      14: (15, HOST, 500), 15: (16, HOST, 400), 16: (1, CHROME, 100)}, "browser_parent_unverified"),
])
def test_sec_i1_browser_ancestry_policy(tree, expected):
    """SEC-I1 (fix): the parent chain must reach an allow-listed, vendor-signed
    browser through at most one System32 cmd.exe, with creation times ordered."""
    decision = _ancestry(tree)
    assert decision.code == expected and bool(decision) is (expected == "ok")


def test_sec_i1_self_images_are_only_skipped_when_listed():
    tree = {10: (11, HOST, 400), 11: (8, "C:/venv/python.exe", 300), 8: (1, FIREFOX, 100)}
    assert _ancestry(tree).code == "browser_parent_unverified"
    assert _ancestry(tree, self_images=(HOST, "C:/venv/python.exe")).browser == "firefox.exe"


def test_sec_i1_ancestry_fails_closed_off_windows_and_on_errors(monkeypatch):
    monkeypatch.setattr(ancestry.os, "name", "posix")
    assert ancestry.verify_browser_ancestry(1).code == "ancestry_unavailable"
    boom = ancestry.verify_browser_ancestry(1, lookup=lambda pid: (_ for _ in ()).throw(OSError()))
    assert not boom and boom.code == "ancestry_unavailable"


@pytest.mark.skipif(sys.platform != "win32", reason="real Toolhelp/WinVerifyTrust")
def test_sec_i1_real_windows_ancestry_rejects_the_test_runner():
    """The live walk works on this machine and pytest's launcher is no browser."""
    import os

    decision = ancestry.verify_browser_ancestry(os.getpid(), self_images=(sys.executable,))
    assert decision.code == "browser_parent_unverified"
    assert ancestry.process_image(os.getpid())


def test_sec_i2_native_host_json_bombs_never_reach_the_agent(monkeypatch, tmp_path):
    """SEC-I2: a 100k-digit integer, 100k-deep nesting and a 4 GiB declared
    length in native-messaging frames; the host must answer with one
    structured error frame and never forward anything."""
    monkeypatch.setenv("LOCALGATEKEYS_DATA_DIR", str(tmp_path))
    monkeypatch.setattr(host, "_forward", lambda request: pytest.fail("bomb reached the agent"))
    argv = ["host.exe", EXTENSION_ORIGINS[0]]
    big_int = b'{"action":"ping","n":' + b"9" * 100_000 + b"}"
    deep = b'{"a":' + b"[" * 100_000 + b"]" * 100_000 + b"}"
    for payload in (big_int, deep):
        started = time.monotonic()
        replies = _run_native_host(monkeypatch, argv, struct.pack("=I", len(payload)) + payload)
        assert len(replies) == 1 and replies[0]["ok"] is False
        assert time.monotonic() - started < 5
    huge = _run_native_host(monkeypatch, argv, struct.pack("=I", 0xFFFFFFFF) + b"{}")
    assert len(huge) == 1 and huge[0]["error"] == "protocol_error"


def test_sec_i3_pipe_frame_with_huge_integer_is_a_protocol_error():
    """SEC-I3: CPU DoS on the agent with a JSON integer of ~1 MB digits inside
    an otherwise valid pipe frame."""
    payload = b'{"action":"ping","n":' + b"7" * 900_000 + b"}"
    started = time.monotonic()
    with pytest.raises(ProtocolError):
        pipe._decode(struct.pack("!I", len(payload)) + payload)
    assert time.monotonic() - started < 5


# ---------------------------------------------------------------------------
# Named pipe: token, ACL, squatting
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("make_token", [
    lambda t: None, lambda t: "", lambda t: 123, lambda t: [t], lambda t: {"token": t},
    lambda t: t.upper() if t.upper() != t else t.lower(), lambda t: t[:-1], lambda t: t + "A",
    lambda t: " " + t,
], ids=["missing", "empty", "int", "list", "dict", "case", "prefix", "suffix", "padded"])
def test_sec_i4_pipe_rejects_every_token_variant_without_dispatch(monkeypatch, make_token):
    """SEC-I4: a pinned peer presents a missing, mistyped, truncated,
    extended, case-flipped or container-wrapped token."""
    replies = []
    monkeypatch.setitem(sys.modules, "win32file", NS(CloseHandle=lambda h: None))
    monkeypatch.setitem(sys.modules, "win32pipe", NS(DisconnectNamedPipe=lambda h: None))
    monkeypatch.setattr(pipe, "_flush_reply", lambda h: None)
    monkeypatch.setattr(pipe, "_verify_native_host_client", lambda h: pipe.PinDecision(True))
    server = pipe.NamedPipeAgentServer(lambda r: pytest.fail("bad token reached the vault"))
    request = {"action": "get_browser"}
    token = make_token(server.token)
    if token is not None:
        request["token"] = token
    monkeypatch.setattr(pipe, "_recv_pipe", lambda h: dict(request))
    monkeypatch.setattr(pipe, "_send_pipe", lambda h, r: replies.append(r))
    server._handle_client(5)
    assert replies and replies[0]["error"] == "unauthorized"


def test_sec_i5_valid_token_is_stripped_and_tokens_have_full_entropy(monkeypatch):
    """SEC-I5: the dispatcher (and so any handler/log) sees the agent token;
    tokens or pipe names are guessable or reused across agent runs."""
    seen = []
    monkeypatch.setitem(sys.modules, "win32file", NS(CloseHandle=lambda h: None))
    monkeypatch.setitem(sys.modules, "win32pipe", NS(DisconnectNamedPipe=lambda h: None))
    monkeypatch.setattr(pipe, "_flush_reply", lambda h: None)
    monkeypatch.setattr(pipe, "_verify_native_host_client", lambda h: pipe.PinDecision(True))
    monkeypatch.setattr(pipe, "_send_pipe", lambda h, r: None)
    server = pipe.NamedPipeAgentServer(lambda r: seen.append(dict(r)) or {"ok": True})
    monkeypatch.setattr(pipe, "_recv_pipe", lambda h: {"action": "ping", "token": server.token})
    server._handle_client(5)
    assert seen == [{"action": "ping"}]
    other = pipe.NamedPipeAgentServer(lambda r: {})
    assert len(server.token) >= 43 and server.token != other.token  # 256-bit urlsafe
    suffix = server.pipe_name[len(pipe.PIPE_PREFIX):]
    assert server.pipe_name.startswith(pipe.PIPE_PREFIX) and len(suffix) == 32
    assert int(suffix, 16) >= 0 and server.pipe_name != other.pipe_name


def test_sec_i6_pipe_dacl_is_user_only_remote_rejected_and_first_instance(monkeypatch):
    """SEC-I6: squat or widen the pipe: NULL DACL / Everyone ACE, remote SMB
    clients, or a pre-created pipe instance accepted by the agent."""
    class ACL:
        def __init__(self):
            self.aces = []

        def AddAccessAllowedAce(self, revision, mask, sid):
            self.aces.append((mask, sid))

    class Descriptor:
        def SetSecurityDescriptorDacl(self, present, dacl, defaulted):
            self.present, self.dacl, self.defaulted = present, dacl, defaulted

    monkeypatch.setitem(sys.modules, "win32con", NS(GENERIC_ALL=0x10000000))
    monkeypatch.setitem(sys.modules, "win32security", NS(
        ACL=ACL, ACL_REVISION=2, ConvertStringSidToSid=lambda s: ("sid", s),
        SECURITY_DESCRIPTOR=Descriptor, SECURITY_ATTRIBUTES=lambda: NS()))
    monkeypatch.setattr(pipe, "_current_user_sid_string", lambda: "S-1-5-21-AUDIT-1001")
    calls = []
    monkeypatch.setitem(sys.modules, "win32pipe", NS(
        PIPE_ACCESS_DUPLEX=0x3, PIPE_TYPE_BYTE=0, PIPE_READMODE_BYTE=0, PIPE_WAIT=0,
        PIPE_UNLIMITED_INSTANCES=255, CreateNamedPipe=lambda *a: calls.append(a) or 9))
    server = pipe.NamedPipeAgentServer(lambda r: {})
    server._create_pipe(first=True)
    server._create_pipe()
    first, later = calls
    sa = first[-1]
    descriptor = sa.SECURITY_DESCRIPTOR
    assert descriptor.present == 1 and descriptor.dacl is not None
    assert descriptor.dacl.aces == [(0x10000000, ("sid", "S-1-5-21-AUDIT-1001"))]
    assert first[0] == server.pipe_name
    assert first[1] & 0x00080000  # FILE_FLAG_FIRST_PIPE_INSTANCE: fails if squatted
    assert first[2] & 0x8 and later[2] & 0x8  # PIPE_REJECT_REMOTE_CLIENTS on every instance


# ---------------------------------------------------------------------------
# Origin confusion at the broker boundary
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("origin", [
    "null", "data:text/html,<form>", "blob:https://example.test/0b1c2d3e",
    "file:///C:/Users/victim/login.html", "chrome-extension://hojebpmbiibhbhhkohgongojilojijmb",
    "javascript:alert(1)", "ws://example.test", "ftp://example.test", "about:blank",
    "https://user@example.test", "https://evil.test\\@example.test", "https://evil.test#@example.test",
    "https://example.test/login", "https://example.test?x=1", "http://example.test",
    "http://0.0.0.0:8000", "http://127.1", "http://2130706433", "http://10.0.0.1",
    "http://localhost.evil.test", "https://example.test:99999", "", 42,
])
def test_sec_i7_non_http_or_malformed_origins_fail_before_any_vault_access(session, origin):
    """SEC-I7: page-controlled or opaque origins (data:, blob:, file:, null,
    extension, userinfo/backslash tricks, public HTTP downgrade, non-loopback
    IP spellings) reach begin_browser."""
    session.upsert_web(origin=SITE, username="alice", password="pw-audit-origin")
    broker = _Broker(session)
    reply = broker.request("begin_browser", origin=origin, context=_ctx(SITE), user_gesture=True)
    assert reply == {"ok": False, "error": "invalid_request",
                     "message": "The operation could not be validated."}
    assert broker.unlock_prompts == 0


@pytest.mark.parametrize("attacker", [
    "https://example.test:8443", "https://example.test.evil.test", "https://evil-example.test",
    "https://login.example.test", "https://\u0435xample.test", "https://example.test%2eevil.test",
    "https://examp1e.test",
])
def test_sec_i8_lookalike_port_and_subdomain_origins_get_no_exact_origin_choice(session, attacker):
    """SEC-I8: Cyrillic homograph, port change, suffix append, subdomain and
    percent-encoded-dot origins ask for an exact-origin credential."""
    session.upsert_web(origin=SITE, username="alice", password="pw-audit-lookalike")
    reply = _Broker(session).request("begin_browser", origin=attacker, user_gesture=True)
    assert reply.get("ok") is not True and "choices" not in reply


def test_sec_i9_loopback_origins_are_not_interchangeable(session):
    """SEC-I9: a different local listener (other port, IPv6 or IPv4-mapped
    loopback, ``localhost`` name) asks for a 127.0.0.1 credential."""
    session.upsert_web(origin="http://127.0.0.1:8000", username="dev", password="pw-audit-loop")
    broker = _Broker(session)
    for origin in ("http://127.0.0.1:8001", "http://[::1]:8000", "http://localhost:8000",
                   "https://127.0.0.1:8000", "http://a.localhost:8000"):
        assert broker.request("begin_browser", origin=origin, user_gesture=True) == {
            "ok": False, "error": "not_found"}, origin
    # IPv4-mapped IPv6 loopback is refused outright as an origin (stream D),
    # so it can never be matched to the 127.0.0.1 row either.
    mapped = broker.request("begin_browser", origin="http://[::ffff:127.0.0.1]:8000", user_gesture=True)
    assert mapped["ok"] is False and mapped["error"] == "invalid_request" and "choices" not in mapped
    assert broker.request("begin_browser", origin="http://127.0.0.1:8000", user_gesture=True)["ok"]


def test_sec_i10_host_mode_rows_cannot_be_used_for_a_public_http_downgrade(session):
    """SEC-I10: a login with a ``host`` row (scheme-agnostic) is requested
    from ``http://`` on the same public host."""
    entry = session.upsert_web(origin=SITE, username="alice", password="pw-audit-host")
    session.items.set_web_urls(entry, [{"url": SITE, "match": "exact_origin"},
                                       {"url": SITE, "match": "host"}])
    broker = _Broker(session)
    assert broker.request("begin_browser", origin="http://example.test", user_gesture=True)[
        "error"] == "invalid_request"
    start = broker.request("begin_browser", origin=SITE, user_gesture=True)
    downgraded = broker.request("get_browser", origin="http://example.test", grant=start["grant"],
                                entry_id=entry)
    assert downgraded.get("ok") is not True and "credential" not in downgraded


def test_sec_i11_idna2003_deviation_offers_strasse_de_the_strasse_credential(session):
    """SEC-I11: a login typed or imported for ``https://straße.de`` is stored
    as ``https://strasse.de`` (Python's IDNA 2003 codec maps ß to ss).  Browsers
    serialize the real site as ``xn--strae-oqa.de``, so the attacker-registered
    ``strasse.de`` receives an exact-origin offer for the victim's account."""
    session.upsert_web(origin="https://straße.de", username="victim", password="pw-audit-idna")
    reply = _Broker(session).request("begin_browser", origin="https://strasse.de", user_gesture=True)
    assert reply == {"ok": False, "error": "not_found"}
    assert canonicalize_origin("https://straße.de") == "https://xn--strae-oqa.de"


@pytest.mark.parametrize("victim,attacker", [
    ("https://alice.us-east-1.elasticbeanstalk.com", "https://mallory.us-east-1.elasticbeanstalk.com"),
    ("https://alice.z13.web.core.windows.net", "https://mallory.z13.web.core.windows.net"),
    ("https://alice.s3-website-us-east-1.amazonaws.com", "https://mallory.s3-website-us-east-1.amazonaws.com"),
])
def test_sec_i12_base_domain_row_leaks_across_tenants_of_unlisted_platform_suffix(session, victim, attacker):
    """SEC-I12: a ``base_domain`` row saved for a tenant on a shared hosting
    platform whose suffix is missing from the curated list (Elastic
    Beanstalk, Azure static sites, S3 website endpoints) is offered to any
    other tenant of that platform."""
    entry = session.upsert_web(origin=victim, username="victim", password="pw-audit-psl")
    session.items.set_web_urls(entry, [{"url": victim, "match": "exact_origin"},
                                       {"url": victim, "match": "base_domain"}])
    reply = _Broker(session).request("begin_browser", origin=attacker, user_gesture=True)
    assert reply == {"ok": False, "error": "not_found"}
    assert base_domain(victim.split("//")[1]) != base_domain(attacker.split("//")[1])


# ---------------------------------------------------------------------------
# Grants, nonces, locking and replay
# ---------------------------------------------------------------------------

def test_sec_i13_grant_replay_across_origin_entry_and_document_fails(session):
    """SEC-I13: reuse a grant from site A on site B, swap in another site's
    entry id, or replay it from a different tab/document of site A."""
    mine = session.upsert_web(origin=SITE, username="alice", password="pw-audit-a")
    other = session.upsert_web(origin="https://other.test", username="bob", password="pw-audit-b")
    broker = _Broker(session)
    start = broker.request("begin_browser", user_gesture=True)
    # Each replay carries a valid gesture nonce of its own origin and tab, so
    # it is the grant check (not the nonce check) that refuses it.
    other_site = "https://other.test"
    tab_b = _ctx(SITE, tab=18, document="doc-audit-b")
    navigated = _ctx(SITE, document="doc-audit-after-navigation")
    attempts = [
        broker.request("get_browser", origin=other_site, grant=start["grant"], entry_id=other,
                       gesture_nonce=broker.nonce(origin=other_site)),
        broker.request("get_browser", origin=other_site, grant=start["grant"], entry_id=mine,
                       gesture_nonce=broker.nonce(origin=other_site)),
        broker.request("get_browser", grant=start["grant"], entry_id=other, gesture_nonce=broker.nonce()),
        broker.request("get_browser", grant=start["grant"], entry_id=mine,
                       context=tab_b, gesture_nonce=broker.nonce(context=tab_b)),
        broker.request("get_browser", grant=start["grant"], entry_id=mine,
                       context=navigated, gesture_nonce=broker.nonce(context=navigated)),
        broker.request("get_browser", grant="forged-" + start["grant"][7:], entry_id=mine,
                       gesture_nonce=broker.nonce()),
    ]
    for reply in attempts:
        assert reply.get("ok") is not True and _no_secret(reply, "pw-audit-a", "pw-audit-b")
        assert not str(reply.get("error", "")).startswith("gesture_nonce")
    legit = broker.request("get_browser", grant=start["grant"], entry_id=mine,
                           gesture_nonce=start["gesture_nonce"])
    assert legit["ok"] and legit["credential"]["password"] == "pw-audit-a"
    assert "pw-audit-b" not in json.dumps(legit) and list(legit["credential"]) == [
        "entry_id", "username", "origin", "password"]


def test_sec_i14_fill_after_lock_profile_switch_or_relock_is_refused(tmp_path):
    """SEC-I14: an in-flight grant (and gesture nonce) is used after the vault
    locked, after a profile switch, or after lock + unlock (new lease)."""
    for change in ("lock", "profile", "relock"):
        s = create_vault(tmp_path / f"audit-{change}.json", MASTER, kdf_overrides=KDF)
        entry = s.upsert_web(origin=SITE, username="alice", password="pw-audit-lock")
        broker = _Broker(s)
        start = broker.request("begin_browser", user_gesture=True)
        if change == "lock":
            broker.guard.invalidate()
            s.lock()
        elif change == "profile":
            broker.guard.invalidate("someone-else")
            broker.guard.open(3600)
        else:
            broker.guard.invalidate()
            broker.guard.open(3600)
        reply = broker.request("get_browser", grant=start["grant"], entry_id=entry,
                               gesture_nonce=start["gesture_nonce"])
        assert reply.get("ok") is not True and _no_secret(reply, "pw-audit-lock"), change
        if s.is_unlocked:
            s.lock()


def test_sec_i15_gesture_nonce_minted_on_one_origin_cannot_authorize_another(session, monkeypatch):
    """SEC-I15: a save-flow gesture nonce from site A is presented by site B
    (strict mode, no legacy boolean fallback) and must not be burned by B."""
    prompts = []
    # Only the legitimate new login reaches the desktop confirmation (INFO-1).
    monkeypatch.setattr("broker_host.confirm", lambda *a: prompts.append(a[2]) or True)
    broker = _Broker(session, legacy_gesture_compat=False)
    nonce = broker.request("begin_gesture_browser", user_gesture=True)["gesture_nonce"]
    stolen = broker.request("save_browser", origin="https://other.test", username="planted",
                            password="pw-audit-plant", gesture_nonce=nonce)
    assert stolen["error"] == "gesture_nonce_invalid"
    assert not session.find_web("https://other.test")
    assert broker.request("save_browser", username="mine", password="pw-audit-save",
                          gesture_nonce=nonce) == {"ok": True, "status": "created"}
    assert len(prompts) == 1 and SITE in prompts[0] and "other.test" not in prompts[0]


def test_sec_i16_totp_never_widens_beyond_exact_origin(session):
    """SEC-I16: a subdomain matched only through a ``base_domain`` row asks
    for the login's 2FA code (TOTP is exact-origin only)."""
    entry = session.upsert_web(origin=SITE, username="alice", password="pw-audit-totp")
    session.items.set_web_urls(entry, [{"url": SITE, "match": "exact_origin"},
                                       {"url": SITE, "match": "base_domain"}])
    session.set_details(entry, totp={"secret": "JBSWY3DPEHPK3PXP", "digits": 6, "period": 30,
                                     "algorithm": "SHA1"})
    broker = _Broker(session)
    sub = "https://login.example.test"
    assert broker.request("begin_totp_browser", origin=sub, user_gesture=True)["error"] == "totp_not_found"
    start = broker.request("begin_totp_browser", user_gesture=True)
    crossed = broker.request("get_totp_browser", origin=sub, grant=start["grant"], entry_id=entry,
                             gesture_nonce=broker.nonce(origin=sub))
    assert crossed.get("ok") is not True and "code" not in crossed


def test_sec_i17_pending_capture_is_private_to_its_tab(session, monkeypatch):
    """SEC-I17: another tab on the same origin reads a pending captured
    login or replays its pending token to save it."""
    monkeypatch.setattr("broker_host.confirm", lambda *a: pytest.fail("no prompt expected"))
    broker = _Broker(session)
    captured = broker.request("capture_browser", username="alice", password="pw-audit-pending")
    assert captured["stored"] is True
    other_tab = _ctx(SITE, tab=18, document="doc-audit-b")
    peek = broker.request("pending_browser", context=other_tab)
    assert peek == {"ok": True, "pending": False}
    replay = broker.request("save_pending_browser", context=other_tab,
                            gesture_nonce=broker.nonce(context=other_tab),
                            pending_token=captured["pending_token"])
    assert replay["error"] == "session_changed" and not session.find_web(SITE)
    wrong_token = broker.request("save_pending_browser", gesture_nonce=broker.nonce(), pending_token="x" * 32)
    assert wrong_token["error"] == "session_changed"


def test_sec_i18_check_browser_oracle_never_returns_secrets(session):
    """SEC-I18: probe check_browser for the stored password or entry id, and
    probe it while the vault is locked."""
    entry = session.upsert_web(origin=SITE, username="alice", password="pw-audit-oracle")
    broker = _Broker(session)
    for guess in ("wrong", "pw-audit-oracle"):
        reply = broker.request("check_browser", username="alice", password=guess)
        assert set(reply) <= {"ok", "locked", "match", "status", "prompt"}
        assert _no_secret(reply, "pw-audit-oracle", entry)
    broker.guard.invalidate()
    assert broker.request("check_browser", username="alice", password="pw-audit-oracle") == {
        "ok": True, "locked": True, "status": "locked", "match": False}


def test_sec_i19_site_icon_decompression_bomb_is_rejected_before_decode():
    """SEC-I19: a tiny PNG whose header declares 60000x60000 pixels is sent
    as ``site_icon`` to exhaust agent memory during re-encoding."""
    def chunk(kind: bytes, data: bytes) -> bytes:
        return struct.pack("!I", len(data)) + kind + data + struct.pack("!I", zlib.crc32(kind + data))
    ihdr = struct.pack("!IIBBBBB", 60000, 60000, 8, 6, 0, 0, 0)
    png = b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", ihdr) + chunk(b"IDAT", zlib.compress(b"")) + chunk(b"IEND", b"")
    with pytest.raises(IconDecodeError):
        normalize_site_icon(png)


# ---------------------------------------------------------------------------
# Desktop fill: spoofed process / window / signer
# ---------------------------------------------------------------------------

def _control(index, automation_id, *, password=False):
    return ControlDescriptor(index=index, name="" if password else automation_id, automation_id=automation_id,
                             class_name="Edit", framework_id="Win32", is_password=password, enabled=True,
                             visible=True, rectangle=(0, 0, 100, 20))


def _desktop(exe_path, *, title="Sign in", sha="A" * 64, signer=None, mode="strict"):
    controls = [_control(0, "user"), _control(1, "pass", password=True)]
    snapshot = WindowSnapshot(hwnd=1, pid=2, title=title, exe_path=exe_path, exe_sha256=sha,
                              controls=controls, signer=signer)
    entry = {"username": "alice", "password": "pw-audit-desktop", "scope": {
        "exe_path": exe_path, "exe_sha256": sha, "window_title": title, "binding_mode": mode,
        "control_fingerprint": [c.fingerprint() for c in controls],
        "username_selector": controls[0].selector(), "password_selector": controls[1].selector()}}
    return entry, snapshot


def test_sec_i20_identical_binary_copy_or_title_spoof_from_other_path_is_refused(tmp_path):
    """SEC-I20: an attacker copies the bound executable (same SHA-256) to its
    own folder, or shows a window with the bound title and identical control
    layout from another executable."""
    entry, good = _desktop(str(tmp_path / "Apps" / "Bank" / "bank.exe"))
    validate_desktop_entry(entry, good)
    for spoof_path in (tmp_path / "Temp" / "bank.exe", tmp_path / "Apps" / "Bank" / "bank.exe.evil.exe"):
        _e, spoof = _desktop(str(spoof_path))
        with pytest.raises(UIAutomationError, match="Executable mismatch"):
            validate_desktop_entry(entry, spoof)


@pytest.mark.parametrize("signer", [
    None,
    {"status": "Valid", "subject": "CN=Discord Inc.evil, O=Evil"},
    {"status": "Valid", "subject": "CN=Not Discord Inc."},
    {"status": "Valid", "subject": "OU=Discord Inc., CN=Mallory"},
    {"status": "HashMismatch", "subject": "CN=Discord Inc., O=Discord Inc."},
    {"status": "NotSigned", "subject": "CN=Discord Inc."},
])
def test_sec_i21_discord_exception_needs_a_genuinely_valid_discord_signer(monkeypatch, tmp_path, signer):
    """SEC-I21: a binary dropped into the user-writable
    ``%LOCALAPPDATA%\\Discord\\app-*`` folder with a lookalike, tampered or
    missing Authenticode signer abuses the relaxed Discord binding."""
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path))
    saved, _snap = _desktop(str(tmp_path / "Discord" / "app-1.0.9" / "Discord.exe"), mode="discord_stable")
    _e, dropped = _desktop(str(tmp_path / "Discord" / "app-1.0.10" / "Discord.exe"), sha="B" * 64,
                           title="anything", signer=signer)
    with pytest.raises(UIAutomationError):
        validate_desktop_entry(saved, dropped)


def test_sec_i22_discord_path_traversal_does_not_escape_into_relaxed_mode(monkeypatch, tmp_path):
    """SEC-I22: ``..`` segments make an executable outside the Discord folder
    look like ``Discord\\app-*\\Discord.exe`` to get the relaxed checks."""
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path))
    saved, _snap = _desktop(str(tmp_path / "Discord" / "app-1.0.9" / "Discord.exe"), mode="discord_stable")
    sneaky = str(tmp_path / "Discord" / "app-1.0.9" / ".." / ".." / "Evil" / "app-1.0.9" / "Discord.exe")
    _e, spoof = _desktop(sneaky, sha="C" * 64,
                         signer={"status": "Valid", "subject": "CN=Discord Inc., O=Discord Inc."})
    with pytest.raises(UIAutomationError, match="Executable mismatch"):
        validate_desktop_entry(saved, spoof)


# ---------------------------------------------------------------------------
# Informational findings (fixed)
# ---------------------------------------------------------------------------

def test_info1_new_browser_login_needs_the_desktop_confirmation(session, monkeypatch):
    """INFO-1: a page (or a clickjacked in-page Save) creates a new login via
    save_browser without the desktop confirmation SECURITY.md promises."""
    prompts, answer = [], [False]
    monkeypatch.setattr("broker_host.confirm", lambda *a: prompts.append(a[1:]) or answer[0])
    broker = _Broker(session)
    nonce = broker.request("begin_gesture_browser", user_gesture=True)["gesture_nonce"]
    refused = broker.request("save_browser", username="planted", password="pw-info1", gesture_nonce=nonce)
    assert refused == {"ok": False, "error": "user_cancelled"} and not session.find_web(SITE)
    title, body = prompts[0]
    assert title == "Save new login?" and SITE in body and "planted" in body and "pw-info1" not in body
    answer[0] = True
    nonce = broker.request("begin_gesture_browser", user_gesture=True)["gesture_nonce"]
    assert broker.request("save_browser", username="mine", password="pw-info1",
                          gesture_nonce=nonce) == {"ok": True, "status": "created"}
    assert [e["username"] for e in session.find_web(SITE)] == ["mine"]


def test_info1_new_pending_login_needs_the_desktop_confirmation(session, monkeypatch):
    """INFO-1: the automatic save flow (capture -> save_pending_browser) for a
    new account also asks on the desktop; refusing keeps the vault unchanged."""
    prompts, answer = [], [False]
    monkeypatch.setattr("broker_host.confirm", lambda *a: prompts.append(a[1]) or answer[0])
    broker = _Broker(session)
    captured = broker.request("capture_browser", username="new-user", password="pw-info1-pending")
    nonce = broker.request("begin_gesture_browser", user_gesture=True)["gesture_nonce"]
    refused = broker.request("save_pending_browser", pending_token=captured["pending_token"], gesture_nonce=nonce)
    assert refused["error"] == "user_cancelled" and prompts == ["Save new login?"] and not session.find_web(SITE)
    answer[0] = True
    nonce = broker.request("begin_gesture_browser", user_gesture=True)["gesture_nonce"]
    saved = broker.request("save_pending_browser", pending_token=captured["pending_token"], gesture_nonce=nonce)
    assert saved == {"ok": True, "status": "created"} and prompts == ["Save new login?"] * 2


def test_info1_update_and_existing_saves_keep_their_behaviour(session, monkeypatch):
    prompts = []
    monkeypatch.setattr("broker_host.confirm", lambda *a: prompts.append(a[1]) or True)
    session.upsert_web(origin=SITE, username="alice", password="pw-old")
    broker = _Broker(session)
    assert broker.request("save_browser", username="alice", password="pw-old",
                          gesture_nonce=broker.nonce()) == {"ok": True, "status": "existing"}
    assert prompts == []
    assert broker.request("save_browser", username="alice", password="pw-new",
                          gesture_nonce=broker.nonce()) == {"ok": True, "status": "updated"}
    assert prompts == ["Update password?"]


@pytest.mark.parametrize("action", ["check_browser", "capture_browser"])
def test_info2_password_probes_are_rate_limited_per_origin_and_overall(session, monkeypatch, action):
    """INFO-2: check_browser / capture_browser answer (username, password)
    guesses without a gesture; a burst of guesses must hit a limit."""
    session.upsert_web(origin=SITE, username="alice", password="pw-info2-secret")
    broker = _Broker(session)
    now = [1000.0]
    monkeypatch.setattr("localvault.browser_broker.time.monotonic", lambda: now[0])
    limit = broker.PROBE_LIMIT_PER_ORIGIN
    for attempt in range(limit):
        reply = broker.request(action, username="alice", password=f"guess-{attempt}",
                               context=_ctx(SITE, op=f"op-{attempt}"))
        assert reply["ok"] is True, attempt
    blocked = broker.request(action, username="alice", password="pw-info2-secret")
    assert blocked == {"ok": False, "error": "rate_limited",
                       "message": "Too many login checks from this site. Wait a minute and try again."}
    # Another origin has its own budget, but the overall budget is shared.
    other = "https://other.test"
    assert broker.request(action, origin=other, username="bob", password="x")["ok"] is True
    now[0] += broker.PROBE_WINDOW + 1
    assert broker.request(action, username="alice", password="pw-info2-secret")["ok"] is True
    for index in range(broker.PROBE_LIMIT_TOTAL - 1):
        broker.request(action, origin=f"https://site{index}.test", username="u", password="p")
    # Audit 2026-10-24 L-14: past the overall backstop a fresh site keeps only
    # its small reserved share, so busy sites cannot silence it entirely.
    for _ in range(broker.PROBE_RESERVE_PER_SITE):
        assert broker.request(action, origin="https://fresh.test", username="u", password="p")["ok"] is True
    assert broker.request(action, origin="https://fresh.test", username="u", password="p")["error"] == "rate_limited"


def test_info2_locked_vault_probes_do_not_consume_or_reveal(session):
    broker = _Broker(session)
    broker.guard.invalidate()
    for _ in range(broker.PROBE_LIMIT_TOTAL + 5):
        assert broker.request("check_browser", username="a", password="b")["status"] == "locked"


def test_info4_pipe_client_cannot_be_impersonated_by_the_server(monkeypatch):
    """INFO-4: the native host opens the agent pipe with
    SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION, so a squatting server
    can at most identify, never impersonate, the browser user's token."""
    opened = []
    monkeypatch.setitem(sys.modules, "win32con", NS(GENERIC_READ=0x80000000, GENERIC_WRITE=0x40000000,
                                                    OPEN_EXISTING=3))
    monkeypatch.setitem(sys.modules, "win32pipe", NS(WaitNamedPipe=lambda name, timeout: None))
    monkeypatch.setitem(sys.modules, "win32file", NS(CreateFile=lambda *a: opened.append(a) or 77))
    assert pipe._open_pipe(pipe.PIPE_PREFIX + "0" * 32, 100) == 77
    flags = opened[0][5]
    assert flags & 0x00100000 and flags & 0x00030000 == 0x00010000  # SQOS present, Identification level
    assert flags == pipe.PIPE_CLIENT_SQOS_FLAGS
