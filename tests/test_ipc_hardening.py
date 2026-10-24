"""Local IPC hardening: DPAPI-protected agent token, registry-anchored client pin,
lease-free ping, broker-issued gesture nonces, gated TCP fallback and a bounded
frame parser.  Everything here runs with fakes so it is portable.
"""
from __future__ import annotations

import base64
import json
import os
import random
import struct
import sys
import time
from types import SimpleNamespace as NS

import pytest

import localvault.bridge_diagnostics as diag
import localvault.bridge_status as status
import localvault.config as config
import localvault.native_host as host
import localvault.pipe_transport as pipe
from localvault.browser_broker import BrowserBroker
from localvault.protocol import MAX_LOCAL_MESSAGE, ProtocolError
from broker_host import BrokerHostBase as RuntimeActions
from localvault.session_guard import SessionGuard
from localvault.settings import AppSettings
from localvault.vault import create_vault

KDF = {"memory_cost_kib": 8192, "time_cost": 1, "parallelism": 1}
MASTER = "Demo-only-master-ipc!"


# --------------------------------------------------------------------------
# Task 1: DPAPI protection of the agent token
# --------------------------------------------------------------------------

class FakeWin32Crypt:
    """Reversible stand-in for win32crypt; records the arguments it was given."""

    CRYPTPROTECT_UI_FORBIDDEN = 0x1

    def __init__(self):
        self.calls = []

    def CryptProtectData(self, data, description, entropy, reserved, prompt, flags):
        self.calls.append(("protect", description, entropy, reserved, prompt, flags))
        return b"BLOB:" + bytes(entropy) + b":" + bytes(data)[::-1]

    def CryptUnprotectData(self, blob, entropy, reserved, prompt, flags):
        self.calls.append(("unprotect", entropy, reserved, prompt, flags))
        prefix = b"BLOB:" + bytes(entropy) + b":"
        if not bytes(blob).startswith(prefix):
            raise OSError(13, "The data is invalid")
        return None, bytes(blob)[len(prefix):][::-1]


@pytest.fixture
def fake_dpapi(monkeypatch):
    api = FakeWin32Crypt()
    monkeypatch.setitem(sys.modules, "win32crypt", api)
    monkeypatch.setattr(pipe, "_dpapi_available", lambda: True)
    return api


def test_token_is_dpapi_protected_with_fixed_entropy_and_no_ui(fake_dpapi):
    fields = pipe.protect_agent_token("t" * 43)
    assert fields["protection"] == "dpapi-user"
    assert "t" * 43 not in json.dumps(fields)
    blob = base64.b64decode(fields["token"], validate=True)
    assert blob.startswith(b"BLOB:" + pipe.AGENT_TOKEN_ENTROPY)
    kind, description, entropy, reserved, prompt, flags = fake_dpapi.calls[0]
    assert (kind, description, reserved, prompt) == ("protect", None, None, None)
    assert entropy == pipe.AGENT_TOKEN_ENTROPY and flags == FakeWin32Crypt.CRYPTPROTECT_UI_FORBIDDEN
    assert pipe.unprotect_agent_token({"protection": "dpapi-user", "token": fields["token"]}) == "t" * 43


def test_unprotect_rejects_foreign_blob_and_wrong_protection(fake_dpapi):
    bad = base64.b64encode(b"BLOB:other-entropy:xyz").decode()
    with pytest.raises(status.BridgeFailure) as e:
        pipe.unprotect_agent_token({"protection": "dpapi-user", "token": bad})
    assert e.value.code == "agent_state_invalid"
    with pytest.raises(status.BridgeFailure):
        pipe.unprotect_agent_token({"protection": "dpapi-user", "token": "not base64!"})
    with pytest.raises(status.BridgeFailure):
        pipe.unprotect_agent_token({"protection": "unknown", "token": "x" * 40})


def test_plaintext_fallback_when_pywin32_missing(monkeypatch):
    monkeypatch.setattr(pipe, "_dpapi_available", lambda: False)
    fields = pipe.protect_agent_token("p" * 43)
    assert fields == {"token": "p" * 43, "protection": "none"}
    assert pipe.unprotect_agent_token(fields) == "p" * 43
    assert "agent_token_unprotected" in status.warnings()


def test_legacy_state_without_protection_field_is_plaintext():
    assert pipe.unprotect_agent_token({"token": "q" * 43}) == "q" * 43


def test_server_start_publishes_protected_token_and_restricts_acl(monkeypatch, tmp_path, fake_dpapi):
    published = {}
    acl = []
    monkeypatch.setattr(pipe, "os", NS(name="nt", getpid=lambda: 12, path=os.path))
    monkeypatch.setattr(pipe, "_security_attributes_for_current_user", lambda: (None, "S-1-TEST"))
    monkeypatch.setattr(pipe, "agent_state_path", lambda: tmp_path / "state.json")
    monkeypatch.setattr(pipe, "atomic_write_json", lambda p, d: published.update(d))
    monkeypatch.setattr(pipe, "_restrict_file_to_current_user", lambda p: acl.append(p) or True)
    monkeypatch.setattr(pipe, "_pipe_log", lambda *a: None)
    monkeypatch.setitem(sys.modules, "win32file", NS(CloseHandle=lambda h: None))
    monkeypatch.setattr(pipe.threading, "Thread", lambda **kw: NS(start=lambda: None))
    server = pipe.NamedPipeAgentServer(lambda r: {})
    monkeypatch.setattr(server, "_create_pipe", lambda **kw: 7)
    server.start()
    assert published["protection"] == "dpapi-user" and published["version"] == 3
    assert server.token not in json.dumps(published)
    assert pipe.unprotect_agent_token(published) == server.token
    assert acl == [tmp_path / "state.json"]


def test_forward_unprotects_token_before_sending(monkeypatch, fake_dpapi):
    sent = []
    monkeypatch.setattr(pipe, "os", NS(name="nt"))
    monkeypatch.setitem(sys.modules, "win32file", NS(CloseHandle=lambda h: None))
    monkeypatch.setattr(pipe, "_current_user_sid_string", lambda: "S-1-TEST")
    monkeypatch.setattr(pipe, "_open_pipe", lambda *a: 7)
    monkeypatch.setattr(pipe, "_named_pipe_server_pid", lambda h: 123)
    monkeypatch.setattr(pipe, "_send_pipe", lambda h, r: sent.append(dict(r)))
    monkeypatch.setattr(pipe, "_recv_pipe", lambda h: {"ok": True})
    state = {"transport": "named_pipe", "pipe": pipe.PIPE_PREFIX + "a" * 32, "user_sid": "S-1-TEST", "pid": 123,
             **pipe.protect_agent_token("z" * 43)}
    assert pipe.forward_named_pipe({"action": "ping"}, state=state) == {"ok": True}
    assert sent[0]["token"] == "z" * 43


def test_owned_state_removal_handles_protected_token(monkeypatch, tmp_path, fake_dpapi):
    monkeypatch.setattr(pipe, "agent_state_path", lambda: tmp_path / "state.json")
    server = pipe.NamedPipeAgentServer(lambda r: {})
    config.atomic_write_json(tmp_path / "state.json", {"pid": os.getpid(), **pipe.protect_agent_token(server.token)})
    server._remove_owned_state()
    assert not (tmp_path / "state.json").exists()


def test_restrict_file_uses_protected_owner_only_dacl(monkeypatch, tmp_path):
    calls = []
    sec = NS(DACL_SECURITY_INFORMATION=4, PROTECTED_DACL_SECURITY_INFORMATION=0x80000000,
             SetFileSecurity=lambda path, info, sd: calls.append((path, info, sd)))
    monkeypatch.setitem(sys.modules, "win32security", sec)
    monkeypatch.setattr(pipe, "os", NS(name="nt", path=os.path))
    monkeypatch.setattr(pipe, "_security_attributes_for_current_user", lambda: (NS(SECURITY_DESCRIPTOR="SD"), "S-1-TEST"))
    assert pipe._restrict_file_to_current_user(tmp_path / "state.json") is True
    assert calls == [(str(tmp_path / "state.json"), 4 | 0x80000000, "SD")]


def test_restrict_file_is_best_effort(monkeypatch, tmp_path):
    monkeypatch.setattr(pipe, "os", NS(name="nt", path=os.path))
    monkeypatch.setattr(pipe, "_security_attributes_for_current_user", lambda: (_ for _ in ()).throw(ImportError("no pywin32")))
    assert pipe._restrict_file_to_current_user(tmp_path / "state.json") is False


# --------------------------------------------------------------------------
# Task 2: registry-anchored client pin policy
# --------------------------------------------------------------------------

@pytest.fixture
def pinned(monkeypatch):
    """A Windows environment whose registry registers host.exe for Chrome and Edge."""
    monkeypatch.setattr(pipe, "os", NS(name="nt", path=os.path))
    monkeypatch.setattr(pipe, "_registered_native_host_paths", lambda: {"Chrome": "host.exe", "Edge": "host.exe"})
    monkeypatch.setattr(pipe, "read_json", lambda p: {"native_host_path": "host.exe", "native_host_sha256": "A" * 64})
    monkeypatch.setattr(pipe, "install_config_path", lambda: "unused")
    monkeypatch.setattr(pipe, "_named_pipe_client_pid", lambda h: 1)
    monkeypatch.setattr(pipe, "_sha256_file", lambda p: {"host.exe": "A" * 64}.get(p, "D" * 64))
    monkeypatch.setitem(sys.modules, "psutil", NS(Process=lambda pid: NS(exe=lambda: "host.exe", parent=lambda: None)))
    monkeypatch.setattr(sys, "frozen", False, raising=False)


def test_registered_host_is_allowed(pinned):
    decision = pipe.ClientPinPolicy().evaluate(1)
    assert decision.allowed and decision.code == "ok" and bool(decision) is True
    assert pipe._verify_native_host_client(1)


def test_no_registration_fails_closed_even_if_install_json_matches(pinned, monkeypatch):
    monkeypatch.setattr(pipe, "_registered_native_host_paths", lambda: {})
    decision = pipe.ClientPinPolicy().evaluate(1)
    assert not decision and decision.code == "client_pin_unregistered"
    assert decision.code in status.MESSAGES


def test_browsers_disagreeing_about_host_fail_closed(pinned, monkeypatch):
    monkeypatch.setattr(pipe, "_registered_native_host_paths", lambda: {"Chrome": "host.exe", "Edge": "other.exe"})
    assert pipe.ClientPinPolicy().evaluate(1).code == "client_pin_mismatch"


def test_install_json_is_only_a_cross_check(pinned, monkeypatch):
    # install.json pointing somewhere else cannot redirect trust...
    monkeypatch.setattr(pipe, "read_json", lambda p: {"native_host_path": "evil.exe", "native_host_sha256": "A" * 64})
    assert pipe.ClientPinPolicy().evaluate(1).code == "client_pin_mismatch"
    # ...and a wrong hash in install.json also fails closed...
    monkeypatch.setattr(pipe, "read_json", lambda p: {"native_host_path": "host.exe", "native_host_sha256": "F" * 64})
    assert pipe.ClientPinPolicy().evaluate(1).code == "client_pin_mismatch"
    # ...while a missing install.json leaves the registry pin in charge.
    def missing(p):
        raise FileNotFoundError(p)
    monkeypatch.setattr(pipe, "read_json", missing)
    assert pipe.ClientPinPolicy().evaluate(1).allowed


def test_peer_executable_must_equal_registered_path(pinned, monkeypatch):
    monkeypatch.setitem(sys.modules, "psutil", NS(Process=lambda pid: NS(exe=lambda: "C:/elsewhere/host.exe", parent=lambda: None)))
    assert pipe.ClientPinPolicy().evaluate(1).code == "client_pin_mismatch"
    monkeypatch.setattr(pipe, "_named_pipe_client_pid", lambda h: None)
    assert pipe.ClientPinPolicy().evaluate(1).code == "client_not_allowed"


def test_frozen_requires_same_install_directory(pinned, monkeypatch, tmp_path):
    install = tmp_path / "App"
    agent = install / "LocalGateKeys.exe"
    inside = install / "NativeHost" / "LocalGateKeysNativeHost.exe"
    outside = tmp_path / "Other" / "LocalGateKeysNativeHost.exe"
    monkeypatch.setattr(sys, "frozen", True, raising=False)
    monkeypatch.setattr(pipe, "_agent_executable", lambda: str(agent))
    monkeypatch.setattr(pipe, "_sha256_file", lambda p: "A" * 64)
    monkeypatch.setattr(pipe, "_authenticode_thumbprint", lambda p: "")
    for target, expected in ((inside, "ok"), (outside, "client_signer_mismatch")):
        monkeypatch.setattr(pipe, "_registered_native_host_paths", lambda t=target: {"Chrome": str(t)})
        monkeypatch.setattr(pipe, "read_json", lambda p, t=target: {"native_host_path": str(t), "native_host_sha256": "A" * 64})
        monkeypatch.setitem(sys.modules, "psutil", NS(Process=lambda pid, t=target: NS(exe=lambda: str(t), parent=lambda: None)))
        assert pipe.ClientPinPolicy().evaluate(1).code == expected


def test_frozen_requires_matching_signer_when_agent_is_signed(pinned, monkeypatch, tmp_path):
    install = tmp_path / "App"
    agent, hostexe = install / "LocalGateKeys.exe", install / "NativeHost" / "host.exe"
    monkeypatch.setattr(sys, "frozen", True, raising=False)
    monkeypatch.setattr(pipe, "_agent_executable", lambda: str(agent))
    monkeypatch.setattr(pipe, "_sha256_file", lambda p: "A" * 64)
    monkeypatch.setattr(pipe, "_registered_native_host_paths", lambda: {"Chrome": str(hostexe)})
    monkeypatch.setattr(pipe, "read_json", lambda p: {"native_host_path": str(hostexe), "native_host_sha256": "A" * 64})
    monkeypatch.setitem(sys.modules, "psutil", NS(Process=lambda pid: NS(exe=lambda: str(hostexe), parent=lambda: None)))
    thumbs = {str(agent): "AA11", str(hostexe): "AA11"}
    monkeypatch.setattr(pipe, "_authenticode_thumbprint", lambda p: thumbs.get(str(p), ""))
    assert pipe.ClientPinPolicy().evaluate(1).allowed
    thumbs[str(hostexe)] = "BB22"
    assert pipe.ClientPinPolicy().evaluate(1).code == "client_signer_mismatch"
    thumbs[str(hostexe)] = ""
    assert pipe.ClientPinPolicy().evaluate(1).code == "client_signer_mismatch"
    # Unsigned agent (development build): signer check is skipped, not failed.
    thumbs[str(agent)] = ""
    assert pipe.ClientPinPolicy().evaluate(1).allowed


def test_frozen_agent_rejects_interpreter_chain(pinned, monkeypatch, tmp_path):
    install = tmp_path / "App"
    hostexe = install / "NativeHost" / "host.exe"
    monkeypatch.setattr(sys, "frozen", True, raising=False)
    monkeypatch.setattr(pipe, "_agent_executable", lambda: str(install / "LocalGateKeys.exe"))
    monkeypatch.setattr(pipe, "_authenticode_thumbprint", lambda p: "")
    monkeypatch.setattr(pipe, "_sha256_file", lambda p: "A" * 64)
    monkeypatch.setattr(pipe, "_registered_native_host_paths", lambda: {"Chrome": str(hostexe)})
    monkeypatch.setattr(pipe, "read_json", lambda p: {"native_host_path": str(hostexe), "native_host_sha256": "A" * 64,
                                                      "interpreter_path": "python.exe", "interpreter_sha256": "A" * 64})
    chain = NS(exe=lambda: "python.exe", parent=lambda: NS(exe=lambda: str(hostexe), parent=lambda: None))
    monkeypatch.setitem(sys.modules, "psutil", NS(Process=lambda pid: chain))
    assert pipe.ClientPinPolicy().evaluate(1).code == "client_pin_mismatch"


def test_rejected_peer_receives_specific_pin_code(monkeypatch):
    received = []
    monkeypatch.setitem(sys.modules, "win32file", NS(CloseHandle=lambda h: None, FlushFileBuffers=lambda h: None))
    monkeypatch.setitem(sys.modules, "win32pipe", NS(DisconnectNamedPipe=lambda h: None))
    monkeypatch.setattr(pipe, "_flush_reply", lambda h: None)
    monkeypatch.setattr(pipe, "_pipe_log", lambda *a: None)
    monkeypatch.setattr(pipe, "_verify_native_host_client",
                        lambda h: pipe.PinDecision(False, "client_pin_unregistered", "registry"))
    monkeypatch.setattr(pipe, "_send_pipe", lambda h, r: received.append(r))
    pipe.NamedPipeAgentServer(lambda r: pytest.fail("must not dispatch"))._handle_client(3)
    assert received[0]["error"] == "client_pin_unregistered" and received[0]["stage"] == "peer"


def test_policy_describe_is_a_safe_diagnostics_entry(pinned):
    entry = pipe.ClientPinPolicy().describe()
    assert entry["authority"] == "registry"
    assert entry["registered_browsers"] == ["Chrome", "Edge"]
    assert entry["registrations_consistent"] is True
    assert entry["install_json_cross_check"] == "match"
    assert entry["frozen"] is False
    assert "host.exe" not in json.dumps(entry)


def test_native_host_maps_pin_codes_to_peer_failures(monkeypatch):
    monkeypatch.setattr(config, "agent_state_path", lambda: "unused")
    monkeypatch.setattr(config, "read_json", lambda p: {"transport": "named_pipe"})
    monkeypatch.setattr(host, "os", NS(name="nt"))
    monkeypatch.setattr(host, "_log", lambda *a: None)
    monkeypatch.setattr(pipe, "forward_named_pipe", lambda req, timeout_ms, *, state: {"ok": False, "error": "client_pin_mismatch", "message": "PRIVATE"})
    r = host._forward({"action": "ping"})
    assert r["error"] == "client_pin_mismatch" and r["stage"] == "peer" and "PRIVATE" not in json.dumps(r)


def test_registry_reader_uses_hkcu_native_messaging_hosts(monkeypatch, tmp_path):
    manifest = tmp_path / "manifest.json"
    manifest.write_text(json.dumps({"name": config.NATIVE_HOST_NAME, "type": "stdio", "path": "C:/x/host.exe",
                                    "allowed_origins": list(config.EXTENSION_ORIGINS)}), encoding="utf-8")
    opened = []

    class Key:
        def __enter__(self): return self
        def __exit__(self, *a): return False

    def open_key(root, sub):
        opened.append((root, sub))
        if "Edge" in sub or "Mozilla" in sub:
            raise FileNotFoundError()
        return Key()
    fake = NS(HKEY_CURRENT_USER="HKCU", OpenKey=open_key, QueryValue=lambda key, name: str(manifest))
    monkeypatch.setitem(sys.modules, "winreg", fake)
    monkeypatch.setattr(pipe, "os", NS(name="nt", path=os.path))
    assert pipe._registered_native_host_paths() == {"Chrome": "C:/x/host.exe"}
    assert opened == [("HKCU", rf"Software\Google\Chrome\NativeMessagingHosts\{config.NATIVE_HOST_NAME}"),
                      ("HKCU", rf"Software\Microsoft\Edge\NativeMessagingHosts\{config.NATIVE_HOST_NAME}"),
                      ("HKCU", rf"Software\Mozilla\NativeMessagingHosts\{config.NATIVE_HOST_NAME}")]
    # A manifest for another host name or a non-stdio type is not a pin.
    manifest.write_text(json.dumps({"name": "com.other", "type": "stdio", "path": "C:/x/host.exe"}), encoding="utf-8")
    assert pipe._registered_native_host_paths() == {}


# --------------------------------------------------------------------------
# Tasks 3 and 4: broker responses and gesture nonces
# --------------------------------------------------------------------------

class Broker(RuntimeActions, BrowserBroker):
    def __init__(self, vault, **settings):
        self.session = vault
        self.guard = SessionGuard("a")
        self.guard.open(28800)
        self.settings = AppSettings(auto_lock_seconds=0)
        for key, value in settings.items():
            setattr(self.settings, key, value)
        self.active_profile = NS(id="a", name="Alice", color="#12ABCD")
        self._remote_busy = False
        self.last_extension_seen = 0
        self.last_extension_version = ""
        self.last_secret_use = 1234
        self._closing = False
        self.root = None

    def ensure_unlocked(self): return self._session_available()
    def run_on_ui(self, f, timeout=0): return f()
    def _touch_secret(self): self.last_secret_use = time.monotonic()
    def reauthenticate(self, *args): return True
    def refresh_entries(self): pass

    def _validate_remote_text(self, v, *args):
        if not isinstance(v, str): raise ValueError()
        return v

    def request(self, action, *, context="tab-1-document-1-operation-1", **kw):
        return self.dispatch_remote({"action": action, "protocol": 2, "extension_version": "0.3.0",
                                     "origin": "https://example.test", "context": context, **kw})


@pytest.fixture
def vault(tmp_path):
    s = create_vault(tmp_path / "vault.json", MASTER, kdf_overrides=KDF)
    yield s
    s.lock()


def add(s, user="alice", password="Test-only-password-ipc!"):
    return s.upsert_web(origin="https://example.test", username=user, password=password, label=user)


def test_ping_never_returns_lease_or_profile(vault):
    add(vault)
    b = Broker(vault)
    r = b.request("ping")
    assert r["ok"] is True and r["locked"] is False and r["version"]
    assert "session_id" not in r and "profile_name" not in r
    assert b.guard.lease().token not in json.dumps(r)
    b.guard.invalidate()
    assert b.request("ping")["locked"] is True


def test_lease_only_in_responses_that_bind_a_later_request(vault, monkeypatch):
    one = add(vault)
    b = Broker(vault)
    lease = b.guard.lease().token
    start = b.request("begin_browser", user_gesture=True)
    assert start["session_id"] == lease  # bound into save_browser/approve requests
    got = b.request("get_browser", grant=start["grant"], entry_id=one, gesture_nonce=start["gesture_nonce"])
    assert got["ok"] and "session_id" not in got and lease not in json.dumps(got)
    assert "session_id" not in b.request("validate_browser", grant=start["grant"], entry_id=one)
    check = b.request("check_browser", username="alice", password="x")
    assert check["ok"] and "session_id" not in check


def test_begin_browser_issues_single_use_nonce_bound_to_origin_and_context(vault):
    one = add(vault)
    b = Broker(vault)
    start = b.request("begin_browser", user_gesture=True)
    nonce = start["gesture_nonce"]
    assert len(nonce) == 32 and int(nonce, 16) >= 0 and start["gesture_expires_in"] == 30
    other = b.request("get_browser", grant=start["grant"], entry_id=one, gesture_nonce=nonce, context="tab-2-document-9-operation-1")
    assert other["error"] in ("gesture_nonce_invalid", "session_changed")
    assert b.request("get_browser", grant=start["grant"], entry_id=one, gesture_nonce=nonce)["ok"]
    replay = b.request("get_browser", grant=start["grant"], entry_id=one, gesture_nonce=nonce)
    assert not replay["ok"] and "credential" not in replay


def test_gesture_nonce_expires_after_thirty_seconds(vault, monkeypatch):
    one = add(vault)
    b = Broker(vault)
    now = [1000.0]
    monkeypatch.setattr("localvault.browser_broker.time.monotonic", lambda: now[0])
    start = b.request("begin_browser", user_gesture=True)
    now[0] += 31
    r = b.request("get_browser", grant=start["grant"], entry_id=one, gesture_nonce=start["gesture_nonce"])
    assert r["error"] == "gesture_nonce_invalid"


def test_dedicated_gesture_action_for_save_flows(vault, monkeypatch):
    b = Broker(vault)
    monkeypatch.setattr("broker_host.confirm", lambda *a: True)
    issued = b.request("begin_gesture_browser", user_gesture=True)
    assert issued["ok"] and len(issued["gesture_nonce"]) == 32 and "session_id" not in issued
    saved = b.request("save_browser", username="new", password="pw-ipc", gesture_nonce=issued["gesture_nonce"])
    assert saved == {"ok": True, "status": "created"}
    again = b.request("save_browser", username="new2", password="pw-ipc", gesture_nonce=issued["gesture_nonce"])
    assert again["error"] == "gesture_nonce_invalid"


def test_legacy_user_gesture_accepted_only_with_compat_and_warns(vault, monkeypatch):
    status.clear_warnings()
    monkeypatch.setattr("broker_host.confirm", lambda *a: True)  # new-login confirmation
    assert Broker(vault).settings.legacy_gesture_compat is False  # strict by default (L-16)
    b = Broker(vault, legacy_gesture_compat=True)
    r = b.request("save_browser", username="legacy", password="pw-ipc", user_gesture=True)
    assert r["ok"] and "legacy_gesture_compat_used" in status.warnings()
    strict = Broker(vault)
    r = strict.request("save_browser", username="legacy2", password="pw-ipc", user_gesture=True)
    assert r["error"] == "gesture_nonce_required"
    assert strict.request("save_browser", username="legacy3", password="pw-ipc")["error"] == "user_gesture_required"
    assert vault.find_web("https://example.test") and all(e["username"] != "legacy2" for e in vault.find_web("https://example.test"))


def test_legacy_grant_bound_fill_without_nonce_only_with_compat(vault):
    one = add(vault)
    b = Broker(vault, legacy_gesture_compat=True)
    start = b.request("begin_browser", user_gesture=True)
    assert b.request("get_browser", grant=start["grant"], entry_id=one)["ok"]
    strict = Broker(vault)
    assert strict.settings.legacy_gesture_compat is False  # strict by default (L-16)
    start = strict.request("begin_browser", user_gesture=True)
    r = strict.request("get_browser", grant=start["grant"], entry_id=one)
    assert r["error"] == "gesture_nonce_required" and "credential" not in r


def test_totp_release_is_gated_by_nonce_without_touching_totp_code(vault):
    one = add(vault)
    vault.set_details(one, totp={"secret": "JBSWY3DPEHPK3PXP", "digits": 6, "period": 30, "algorithm": "SHA1"})
    strict = Broker(vault, legacy_gesture_compat=False)
    start = strict.request("begin_totp_browser", user_gesture=True)
    assert start["ok"] and "gesture_nonce" in start
    denied = strict.request("get_totp_browser", grant=start["grant"], entry_id=one)
    assert denied["error"] == "gesture_nonce_required" and "code" not in denied
    code = strict.request("get_totp_browser", grant=start["grant"], entry_id=one, gesture_nonce=start["gesture_nonce"])
    assert code["ok"] and len(code["code"]) == 6


def test_nonce_store_is_bounded(vault):
    b = Broker(vault)
    first = b.request("begin_gesture_browser", user_gesture=True)["gesture_nonce"]
    for _ in range(BrowserBroker.GESTURE_NONCE_MAX):
        b.request("begin_gesture_browser", user_gesture=True)
    assert len(b._gesture_store()) <= BrowserBroker.GESTURE_NONCE_MAX
    assert first not in b._gesture_store()


# --------------------------------------------------------------------------
# Task 5: loopback TCP fallback gate
# --------------------------------------------------------------------------

def test_tcp_fallback_requires_opt_in_outside_pytest(monkeypatch):
    monkeypatch.delenv("PYTEST_CURRENT_TEST", raising=False)
    monkeypatch.delenv("LOCALGATEKEYS_ALLOW_TCP_FALLBACK", raising=False)
    assert host.tcp_fallback_allowed() is False
    monkeypatch.setenv("LOCALGATEKEYS_ALLOW_TCP_FALLBACK", "1")
    assert host.tcp_fallback_allowed() is True
    monkeypatch.setenv("LOCALGATEKEYS_ALLOW_TCP_FALLBACK", "yes")
    assert host.tcp_fallback_allowed() is False
    monkeypatch.setenv("PYTEST_CURRENT_TEST", "x")
    assert host.tcp_fallback_allowed() is True


def test_disabled_tcp_fallback_never_connects(monkeypatch):
    monkeypatch.setattr(host, "tcp_fallback_allowed", lambda: False)
    monkeypatch.setattr(host.socket, "create_connection", lambda *a, **k: pytest.fail("must not connect"))
    with pytest.raises(status.BridgeFailure) as e:
        host._forward_legacy_socket({"action": "ping"}, {"host": "127.0.0.1", "port": 4321, "token": "t" * 40})
    assert e.value.code == "tcp_fallback_disabled"
    with pytest.raises(RuntimeError):
        host.require_tcp_fallback_allowed()


@pytest.mark.parametrize("state", [
    {"host": "0.0.0.0", "port": 4321, "token": "t" * 40},  # noqa: S104 - rejected on purpose
    {"host": "localhost", "port": 4321, "token": "t" * 40},
    {"host": "127.0.0.1", "port": 0, "token": "t" * 40},
    {"host": "127.0.0.1", "port": 4321, "token": "short"},
    {"host": "127.0.0.1", "port": 4321, "token": "t" * 40, "protection": "dpapi-user"},
])
def test_tcp_fallback_rejects_non_loopback_or_weak_state(monkeypatch, state):
    monkeypatch.setattr(host, "tcp_fallback_allowed", lambda: True)
    monkeypatch.setattr(host.socket, "create_connection", lambda *a, **k: pytest.fail("must not connect"))
    with pytest.raises((ValueError, status.BridgeFailure)):
        host._forward_legacy_socket({"action": "ping"}, state)


def test_tcp_fallback_sends_token_on_every_frame(monkeypatch):
    frames = []

    class Sock:
        def __enter__(self): return self
        def __exit__(self, *a): return False
        def settimeout(self, t): pass
        def sendall(self, data): frames.append(data)
        def recv(self, n):
            from localvault.protocol import send_local_message  # noqa: F401
            payload = json.dumps({"ok": True}).encode()
            blob = struct.pack("!I", len(payload)) + payload
            chunk, Sock.buffer = blob[:n], blob[n:]
            return chunk if not hasattr(Sock, "sent") else Sock.buffer[:n]
    monkeypatch.setattr(host, "tcp_fallback_allowed", lambda: True)
    monkeypatch.setattr(host.socket, "create_connection", lambda addr, timeout: (frames.append(addr), Sock())[1])
    monkeypatch.setattr(host, "_recv_local", lambda sock: {"ok": True}, raising=False)
    monkeypatch.setattr("localvault.protocol.recv_local_message", lambda sock: {"ok": True})
    for _ in range(2):
        assert host._forward_legacy_socket({"action": "ping"}, {"host": "127.0.0.1", "port": 4321, "token": "t" * 40}) == {"ok": True}
    sent = [json.loads(f[4:]) for f in frames if isinstance(f, bytes)]
    assert len(sent) == 2 and all(f["token"] == "t" * 40 for f in sent)
    assert all(a == ("127.0.0.1", 4321) for a in frames if isinstance(a, tuple))


# --------------------------------------------------------------------------
# Task 6: frame parser bounds and fuzzing
# --------------------------------------------------------------------------

def test_frame_limit_is_documented_and_enforced():
    assert pipe.MAX_FRAME_PAYLOAD == MAX_LOCAL_MESSAGE == 1024 * 1024
    with pytest.raises(ProtocolError):
        pipe._decode(struct.pack("!I", MAX_LOCAL_MESSAGE + 1) + b"x")
    with pytest.raises(ProtocolError):
        pipe._encode({"blob": "x" * (MAX_LOCAL_MESSAGE + 1)})


@pytest.mark.parametrize("payload", [
    b"\xff\xfe\x00bad utf8",
    b"[1,2,3]",
    b"null",
    b"\"string\"",
    b"{\"a\":1} trailing",
    "{\"a\":\ud800}".encode("utf-8", "surrogatepass"),
    b"[" * 50000 + b"]" * 50000,
    b"{\"a\":" * 20000 + b"1" + b"}" * 20000,
], ids=["bad-utf8", "array", "null", "string", "trailing", "lone-surrogate", "deep-array", "deep-object"])
def test_decode_rejects_invalid_payloads_with_protocol_error(payload):
    with pytest.raises(ProtocolError):
        pipe._decode(struct.pack("!I", len(payload)) + payload)


def test_decode_rejects_non_bytes():
    with pytest.raises(ProtocolError):
        pipe._decode("not bytes")  # type: ignore[arg-type]


@pytest.mark.fuzz
def test_frame_parser_mutation_fuzz_only_raises_protocol_error():
    rng = random.Random(20261005)  # noqa: S311 - seeded mutation fuzzing, not secrets
    seeds = [
        pipe._encode({"action": "ping"}),
        pipe._encode({"action": "get_browser", "grant": "g" * 43, "entry_id": "e", "gesture_nonce": "0" * 32,
                      "origin": "https://example.test", "context": "[1,\"doc\",\"https://example.test\",\"op\"]"}),
        pipe._encode({"nested": {"deep": [1, 2.5, None, True, {"x": "\u00fc\U0001f512"}]}, "n": -1}),
        pipe._encode({}),
    ]

    def mutate(blob: bytes) -> bytes:
        data = bytearray(blob)
        for _ in range(rng.randint(1, 4)):
            kind = rng.randrange(7)
            if kind == 0 and data:
                i = rng.randrange(len(data)); data[i] ^= 1 << rng.randrange(8)
            elif kind == 1 and data:
                i = rng.randrange(len(data)); data[i] = rng.randrange(256)
            elif kind == 2 and data:
                del data[rng.randrange(len(data)):]
            elif kind == 3:
                i = rng.randrange(len(data) + 1); data[i:i] = bytes(rng.randrange(256) for _ in range(rng.randint(1, 8)))
            elif kind == 4 and len(data) >= 4:
                data[0:4] = struct.pack("!I", rng.choice([0, 1, len(data) - 4, len(data) - 3, len(data) - 5,
                                                          MAX_LOCAL_MESSAGE, MAX_LOCAL_MESSAGE + 1, 2**32 - 1]))
            elif kind == 5 and len(data) > 8:
                a, b = sorted(rng.sample(range(4, len(data)), 2)); data[b:b] = data[a:b]
            elif kind == 6 and len(data) > 4:
                i = rng.randrange(4, len(data)); data[i:i + 1] = rng.choice([b"{", b"}", b"[", b"]", b"\"", b"\\", b",", b":", b"\x00"])
        return bytes(data[:MAX_LOCAL_MESSAGE + 4])

    survivors = 0
    for i in range(1000):
        frame = mutate(rng.choice(seeds))
        try:
            value = pipe._decode(frame)
        except ProtocolError:
            continue
        except Exception as exc:  # noqa: BLE001 - the assertion below names the leak
            raise AssertionError(f"iteration {i}: {type(exc).__name__} escaped _decode") from exc
        assert isinstance(value, dict)
        survivors += 1
    assert survivors < 1000


# --------------------------------------------------------------------------
# Diagnostics
# --------------------------------------------------------------------------

def test_collect_report_includes_protection_pin_policy_and_warnings(monkeypatch, tmp_path):
    status.clear_warnings()
    status.record_warning("legacy_gesture_compat_used")
    monkeypatch.setattr(diag, "os", NS(name="nt", path=os.path))
    monkeypatch.setattr(diag, "agent_state_path", lambda: tmp_path / "state.json")
    monkeypatch.setattr(diag, "install_config_path", lambda: tmp_path / "install.json")
    config.atomic_write_json(tmp_path / "state.json", {"transport": "named_pipe", "pid": 1, "token": "SECRET" * 8,
                                                        "protection": "none", "bridge_revision": status.BRIDGE_REVISION})
    config.atomic_write_json(tmp_path / "install.json", {"native_host_path": "host.exe", "native_host_sha256": "A" * 64,
                                                          "allowed_extension_origins": list(config.EXTENSION_ORIGINS)})
    monkeypatch.setitem(sys.modules, "psutil", NS(pid_exists=lambda pid: False))
    monkeypatch.setattr(diag, "_registered_host_status", lambda b, c: "ready")
    monkeypatch.setattr(diag, "_ping_host", lambda c: {"status": "not_launched", "error": "skipped"})
    monkeypatch.setattr(pipe, "_registered_native_host_paths", lambda: {})
    report = diag.collect_report()
    assert report["agent_token_protection"] == "none"
    assert "agent_token_unprotected" in report["warnings"] and "legacy_gesture_compat_used" in report["warnings"]
    assert report["client_pin_policy"]["authority"] == "registry"
    assert report["client_pin_policy"]["registered_browsers"] == []
    assert "SECRET" not in json.dumps(report)
