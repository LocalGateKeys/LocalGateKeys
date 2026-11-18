"""The app pipe's ``cli`` scope: only the installed lgk.exe gets it, its requests reach only the CLI service, and
the browser path is unchanged."""
from __future__ import annotations

import sys
from types import SimpleNamespace as NS

import pytest

import localvault.pipe_transport as pipe
from localvault import browser_ancestry as ancestry

APP = "C:/Program Files/LocalGateKeys/LocalGateKeys.exe"
LGK = "C:/Program Files/LocalGateKeys/cli/lgk.exe"
DEV_LGK = "C:/src/lgk/dist-personal/lgk/lgk.exe"


def _norm(path):
    return pipe.os.path.normcase(pipe.os.path.abspath(path))


def _policy(monkeypatch, *, exe, frozen=False, config=None, thumbprints=None, registrations=None):
    monkeypatch.setattr(pipe, "os", NS(name="nt", path=pipe.os.path))
    monkeypatch.setattr(sys, "frozen", frozen, raising=False)
    monkeypatch.setattr(pipe, "_agent_executable", lambda: APP)
    monkeypatch.setattr(pipe, "read_json", lambda path: dict(config or {}))
    monkeypatch.setattr(pipe, "install_config_path", lambda: "unused")
    monkeypatch.setattr(pipe, "_named_pipe_client_pid", lambda h: 4321)
    monkeypatch.setattr(pipe, "_registered_native_host_paths", lambda: dict(registrations or {}))
    signers = {_norm(path): value for path, value in (thumbprints or {}).items()}
    monkeypatch.setattr(pipe, "_authenticode_thumbprint", lambda path: signers.get(_norm(path), ""))
    monkeypatch.setattr(pipe, "_browser_ancestry", lambda pid, images: ancestry.AncestryDecision(True, "ok", "x"))
    monkeypatch.setitem(sys.modules, "psutil", NS(Process=lambda pid: NS(exe=lambda: exe, parent=lambda: None)))
    return pipe.ClientPinPolicy()


def test_cli_scope_for_installed_lgk_exe(monkeypatch):
    # Development: the lgk.exe named in install.json; no native-messaging registration is needed.
    decision = _policy(monkeypatch, exe=DEV_LGK, config={"cli_path": DEV_LGK}).evaluate(1)
    assert decision.allowed and decision.scope == "cli" and decision.pid == 4321
    assert decision.authority == "install_json"
    # Frozen, signed: <install dir>/cli/lgk.exe with the agent's signer. install.json is ignored.
    signed = {APP: "AB" * 20, LGK: "AB" * 20}
    decision = _policy(monkeypatch, exe=LGK, frozen=True, config={"cli_path": "C:/elsewhere/lgk.exe"},
                       thumbprints=signed).evaluate(1)
    assert decision.allowed and decision.scope == "cli" and decision.authority == "install_dir"
    # Frozen, unsigned agent (a local build): the install directory is the pin, as for the native host.
    assert _policy(monkeypatch, exe=LGK, frozen=True).evaluate(1).scope == "cli"


def test_cli_scope_rejects_other_executable(monkeypatch):
    registrations = {"Chrome": "C:/host/LocalGateKeysNativeHost.exe"}
    others = ["C:/Python314/python.exe", "C:/Users/me/Downloads/lgk.exe", "C:/src/lgk/lgk.exe.bak"]
    for exe in others:
        decision = _policy(monkeypatch, exe=exe, config={"cli_path": DEV_LGK}, registrations=registrations).evaluate(1)
        assert not decision.allowed and decision.scope != "cli", exe
        decision = _policy(monkeypatch, exe=exe, frozen=True, registrations=registrations).evaluate(1)
        assert not decision.allowed and decision.scope != "cli", exe
    # install.json may only name a file called lgk.exe, never an interpreter that runs any script.
    python = "C:/Python314/python.exe"
    decision = _policy(monkeypatch, exe=python, config={"cli_path": python}).evaluate(1)
    assert not decision.allowed and decision.code == "client_pin_unregistered"
    # Without a cli_path there is no cli scope at all in development.
    assert _policy(monkeypatch, exe=DEV_LGK, config={}).evaluate(1).scope != "cli"
    # Process lookup failures fall back to the unchanged native-host pin (which fails closed).
    _policy(monkeypatch, exe=DEV_LGK, config={"cli_path": DEV_LGK})
    monkeypatch.setitem(sys.modules, "psutil", NS(Process=lambda pid: (_ for _ in ()).throw(OSError())))
    assert not pipe.ClientPinPolicy().evaluate(1).allowed


def test_cli_scope_frozen_requires_same_thumbprint(monkeypatch):
    for signers in ({APP: "AB" * 20, LGK: "CD" * 20}, {APP: "AB" * 20}):
        decision = _policy(monkeypatch, exe=LGK, frozen=True, thumbprints=signers,
                           registrations={"Chrome": "C:/host/LocalGateKeysNativeHost.exe"}).evaluate(1)
        assert not decision.allowed and decision.code == "client_signer_mismatch"


def _server(monkeypatch, decision, request, cli=None):
    replies, browser, cli_seen = [], [], []
    monkeypatch.setitem(sys.modules, "win32file", NS(CloseHandle=lambda h: None))
    monkeypatch.setitem(sys.modules, "win32pipe", NS(DisconnectNamedPipe=lambda h: None))
    monkeypatch.setattr(pipe, "_flush_reply", lambda h: None)
    monkeypatch.setattr(pipe, "_pipe_log", lambda *a: None)
    monkeypatch.setattr(pipe, "_verify_native_host_client", lambda h: decision)
    server = pipe.NamedPipeAgentServer(
        lambda r: browser.append(dict(r)) or {"ok": True, "from": "broker"},
        cli_dispatcher=cli if cli is not None else (lambda r, pid: cli_seen.append((dict(r), pid)) or
                                                    {"ok": True, "from": "cli"}))
    token = request.pop("token", server.token)
    monkeypatch.setattr(pipe, "_recv_pipe", lambda h: {**request, "token": token})
    monkeypatch.setattr(pipe, "_send_pipe", lambda h, r: replies.append(r))
    server._handle_client(5)
    return replies, browser, cli_seen


@pytest.mark.parametrize("action", ["status", "read", "resolve_many", "get_credentials", "begin_browser", "ping"])
def test_cli_requests_reach_only_the_cli_service(monkeypatch, action):
    cli = pipe.PinDecision(True, "ok", "install_json", "cli", 4321)
    replies, browser, cli_seen = _server(monkeypatch, cli, {"action": action, "scope_hint": "cli"})
    assert browser == [] and cli_seen == [({"action": action}, 4321)] and replies == [{"ok": True, "from": "cli"}]
    # A wrong token never reaches the CLI service either.
    replies, browser, cli_seen = _server(monkeypatch, cli, {"action": action, "token": "x" * 43})
    assert browser == cli_seen == [] and replies[0]["error"] == "unauthorized"
    # No CLI service (or no pid): refused, never the broker.
    replies, browser, _ = _server(monkeypatch, pipe.PinDecision(True, scope="cli", pid=0), {"action": action})
    assert browser == [] and replies[0]["ok"] is False


@pytest.mark.parametrize("action", ["status", "read", "resolve_many"])
def test_cli_actions_from_a_non_cli_peer_are_refused(monkeypatch, action):
    # python.exe replaying the protocol is at best the diagnostic scope: refused before any prompt.
    replies, browser, cli_seen = _server(monkeypatch, pipe.PinDecision(True), {"action": action, "scope_hint": "cli"})
    assert browser == cli_seen == [] and replies[0]["error"] == "caller_not_browser"


def test_browser_scope_unchanged(monkeypatch):
    request = {"action": "get_browser", "origin": "https://example.com", "nonce": "n" * 16}
    replies, browser, cli_seen = _server(monkeypatch, pipe.PinDecision(True, scope="browser"), dict(request))
    assert browser == [request] and cli_seen == [] and replies == [{"ok": True, "from": "broker"}]
    # The policy still grants the browser scope to the browser-launched native host, cli_path or not.
    host = "C:/host/LocalGateKeysNativeHost.exe"
    for config in ({}, {"cli_path": DEV_LGK}):
        decision = _policy(monkeypatch, exe=host, config=config, registrations={"Chrome": host}).evaluate(1)
        assert decision.allowed and decision.scope == "browser" and decision.authority == "registry"
    decision = _policy(monkeypatch, exe=host, frozen=True, registrations={"Chrome": host}).evaluate(1)
    assert not decision.allowed and decision.code == "client_signer_mismatch"  # outside the install tree, as before


def test_registered_host_exe_not_started_by_a_browser_gets_the_host_scope(monkeypatch):
    # `LocalGateKeysNativeHost.exe lgk ...` (Store): the host exe itself, launched from a terminal.
    host = "C:/host/LocalGateKeysNativeHost.exe"
    policy = _policy(monkeypatch, exe=host, registrations={"Chrome": host})
    monkeypatch.setattr(pipe, "_browser_ancestry", lambda pid, images: ancestry.AncestryDecision(False, "no"))
    decision = policy.evaluate(1)
    assert decision.allowed and decision.scope == pipe.HOST_SCOPE and decision.pid == 4321
