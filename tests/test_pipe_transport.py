import sys
from types import SimpleNamespace as NS

import pytest

import localvault.pipe_transport as pipe
from localvault import browser_ancestry as ancestry
from localvault.pipe_transport import _decode, _encode
from localvault.protocol import ProtocolError


def test_named_pipe_framing_round_trip() -> None:
    payload = {"action": "ping", "value": "ok"}
    assert _decode(_encode(payload)) == payload


def test_named_pipe_framing_rejects_trailing_bytes() -> None:
    with pytest.raises(ProtocolError):
        _decode(_encode({"a": 1}) + b"x")


# -- the Windows passkey provider's ``system_passkey`` scope -------------------------------------

APP = "C:/Program Files/LocalGateKeys/LocalGateKeys.exe"
PROVIDER = "C:/Program Files/LocalGateKeys/PasskeyProvider/LocalGateKeysPasskeyProvider.exe"
DEV_PROVIDER = "C:/src/lgk/provider/bin/LocalGateKeysPasskeyProvider.exe"
HOST = "C:/host/LocalGateKeysNativeHost.exe"
USER = "S-1-5-21-1-2-3-1001"


def _norm(path):
    return pipe.os.path.normcase(pipe.os.path.abspath(path))


FAMILY = "IliasPel.LocalGateKeys_abcdefghjkmnp"
UNSET = object()


def _policy(monkeypatch, *, exe, frozen=False, config=None, thumbprints=None, registrations=None, peer_sid=USER,
            own_family=UNSET, peer_family=UNSET, package_root=UNSET):
    monkeypatch.setattr(pipe, "os", NS(name="nt", path=pipe.os.path))
    monkeypatch.setattr(sys, "frozen", frozen, raising=False)
    # Frozen defaults: a packaged build whose peer carries the same package family.
    own = (FAMILY if frozen else "") if own_family is UNSET else own_family
    peer = (FAMILY if frozen else "") if peer_family is UNSET else peer_family
    root = (pipe.os.path.dirname(APP) if frozen else "") if package_root is UNSET else package_root
    monkeypatch.setattr(pipe, "_own_package_family_name", lambda: own)
    monkeypatch.setattr(pipe, "_package_root", lambda: root)
    family_calls = []
    monkeypatch.setattr(pipe, "_process_package_family_name",
                        lambda pid: family_calls.append(pid) or (peer() if callable(peer) else peer))
    monkeypatch.setattr(pipe, "_agent_executable", lambda: APP)
    monkeypatch.setattr(pipe, "read_json", lambda path: dict(config or {}))
    monkeypatch.setattr(pipe, "install_config_path", lambda: "unused")
    monkeypatch.setattr(pipe, "_named_pipe_client_pid", lambda h: 4321)
    monkeypatch.setattr(pipe, "_registered_native_host_paths", lambda: dict(registrations or {}))
    monkeypatch.setattr(pipe, "_process_user_sid", lambda pid: peer_sid)
    monkeypatch.setattr(pipe, "_current_user_sid_string", lambda: USER)
    signers = {_norm(path): value for path, value in (thumbprints or {}).items()}
    monkeypatch.setattr(pipe, "_authenticode_thumbprint", lambda path: signers.get(_norm(path), ""))
    monkeypatch.setattr(pipe, "_browser_ancestry", lambda pid, images: ancestry.AncestryDecision(True, "ok", "x"))
    monkeypatch.setitem(sys.modules, "psutil", NS(Process=lambda pid: NS(exe=lambda: exe, parent=lambda: None)))
    return pipe.ClientPinPolicy()


def test_provider_exe_gets_system_scope_in_development(monkeypatch):
    decision = _policy(monkeypatch, exe=DEV_PROVIDER, config={"passkey_provider_path": DEV_PROVIDER}).evaluate(1)
    assert decision.allowed and decision.scope == "system_passkey" and decision.pid == 4321
    assert decision.authority == "install_json"
    # Frozen and signed: <install dir>/PasskeyProvider/... with the agent signer; install.json is ignored.
    signed = {APP: "AB" * 20, PROVIDER: "AB" * 20}
    decision = _policy(monkeypatch, exe=PROVIDER, frozen=True, thumbprints=signed,
                       config={"passkey_provider_path": DEV_PROVIDER}).evaluate(1)
    assert decision.allowed and decision.scope == "system_passkey" and decision.authority == "install_dir"
    # The provider running as another user (the pipe DACL should already stop it) is refused outright.
    for sid in ("S-1-5-18", ""):
        decision = _policy(monkeypatch, exe=DEV_PROVIDER, config={"passkey_provider_path": DEV_PROVIDER},
                           peer_sid=sid).evaluate(1)
        assert not decision.allowed and decision.scope != "system_passkey"


def test_provider_path_with_other_basename_is_ignored(monkeypatch):
    for path in ("C:/Python314/python.exe", "C:/src/lgk/LocalGateKeysPasskeyProvider.exe.bak",
                 "C:/src/lgk/lgk.exe"):
        decision = _policy(monkeypatch, exe=path, config={"passkey_provider_path": path}).evaluate(1)
        assert not decision.allowed and decision.scope != "system_passkey", path
    # A copy of the provider elsewhere is not the pinned one.
    other = "C:/Users/me/Downloads/LocalGateKeysPasskeyProvider.exe"
    decision = _policy(monkeypatch, exe=other, config={"passkey_provider_path": DEV_PROVIDER}).evaluate(1)
    assert not decision.allowed and decision.scope != "system_passkey"
    # The browser-launched native host keeps its browser scope.
    decision = _policy(monkeypatch, exe=HOST, config={"passkey_provider_path": DEV_PROVIDER},
                       registrations={"Chrome": HOST}).evaluate(1)
    assert decision.allowed and decision.scope == "browser"


SIGNED = {APP: "AB" * 20, PROVIDER: "AB" * 20}


def test_packaged_provider_needs_the_same_package_family(monkeypatch):
    # Started by COM activation (same family): allowed.
    decision = _policy(monkeypatch, exe=PROVIDER, frozen=True, thumbprints=SIGNED).evaluate(1)
    assert decision.allowed and decision.scope == "system_passkey"
    # The genuine exe started by path (no identity), another package, or an unreadable peer: refused.
    for peer in ("", "Other.Package_abcdefghjkmnp", FAMILY.upper() + "x"):
        decision = _policy(monkeypatch, exe=PROVIDER, frozen=True, thumbprints=SIGNED, peer_family=peer,
                           registrations={"Chrome": HOST}).evaluate(1)
        assert not decision.allowed and decision.code == "client_not_allowed", peer

    def boom():
        raise OSError("access denied")

    decision = _policy(monkeypatch, exe=PROVIDER, frozen=True, thumbprints=SIGNED, peer_family=boom).evaluate(1)
    assert not decision.allowed and decision.code == "client_not_allowed"
    # Development (unpackaged, not frozen): the family is not consulted.
    decision = _policy(monkeypatch, exe=DEV_PROVIDER, config={"passkey_provider_path": DEV_PROVIDER},
                       peer_family=boom).evaluate(1)
    assert decision.allowed and decision.scope == "system_passkey"


def test_frozen_build_without_package_identity_has_no_provider(monkeypatch):
    # Installer (Inno) build: no package root, so no provider path; a dropped exe never gets the scope.
    for root in ("",):
        decision = _policy(monkeypatch, exe=PROVIDER, frozen=True, thumbprints=SIGNED, own_family="",
                           peer_family="", package_root=root, config={"passkey_provider_path": PROVIDER},
                           registrations={"Chrome": HOST}).evaluate(1)
        assert decision.scope != "system_passkey"
    monkeypatch.setattr(pipe, "_package_root", lambda: "")
    assert pipe.ClientPinPolicy()._provider_path() == ""
    assert pipe.ClientPinPolicy()._system_passkey_decision(1) is None
    # Packaged: the path is built from the package root, not from sys.executable.
    monkeypatch.setattr(pipe, "_package_root", lambda: "C:/Program Files/WindowsApps/Pkg_1.0_x64__abc")
    monkeypatch.setattr(pipe, "_agent_executable", lambda: "C:/elsewhere/LocalGateKeys.exe")
    assert _norm(pipe.ClientPinPolicy()._provider_path()) == _norm(
        "C:/Program Files/WindowsApps/Pkg_1.0_x64__abc/PasskeyProvider/LocalGateKeysPasskeyProvider.exe")


def test_frozen_provider_outside_install_tree_is_rejected(monkeypatch):
    elsewhere = "C:/Temp/PasskeyProvider/LocalGateKeysPasskeyProvider.exe"
    decision = _policy(monkeypatch, exe=elsewhere, frozen=True, registrations={"Chrome": HOST},
                       config={"passkey_provider_path": elsewhere}).evaluate(1)
    assert not decision.allowed and decision.scope != "system_passkey"
    # In the tree but signed by someone else (or unsigned while the agent is signed).
    for signers in ({APP: "AB" * 20, PROVIDER: "CD" * 20}, {APP: "AB" * 20}):
        decision = _policy(monkeypatch, exe=PROVIDER, frozen=True, thumbprints=signers).evaluate(1)
        assert not decision.allowed and decision.code == "client_signer_mismatch"


# -- diagnostics: which pin sub-check refused the provider (fixed words only) ---------------------

def _logged(monkeypatch):
    lines = []
    monkeypatch.setattr(pipe, "_pipe_log", lambda event, exc=None: lines.append(event))
    return lines


def _refusals(lines):
    return [line for line in lines if line.startswith("system_passkey_refused")]


def test_refusal_names_the_sub_check(monkeypatch):
    cases = [
        (dict(exe=PROVIDER, frozen=True, thumbprints=SIGNED, peer_family=""), "check=peer_package_family"),
        (dict(exe=PROVIDER, frozen=True, thumbprints=SIGNED, peer_family="Other.Package_abc"), "check=package_family"),
        (dict(exe=PROVIDER, frozen=True, thumbprints=SIGNED, own_family=""), "check=own_package_family"),
        (dict(exe=PROVIDER, frozen=True, thumbprints={APP: "AB" * 20, PROVIDER: "CD" * 20}), "check=signer"),
        (dict(exe=PROVIDER, frozen=True, thumbprints=SIGNED, peer_sid="S-1-5-18"), "check=sid"),
        (dict(exe="C:/Temp/LocalGateKeysPasskeyProvider.exe", frozen=True, thumbprints=SIGNED,
              registrations={"Chrome": HOST}), "check=path"),
        (dict(exe=PROVIDER, frozen=True, thumbprints=SIGNED, package_root="", registrations={"Chrome": HOST}),
         "check=no_provider_path"),
    ]
    for kwargs, expected in cases:
        lines = _logged(monkeypatch)
        policy = _policy(monkeypatch, **kwargs)
        lines = _logged(monkeypatch)
        policy.evaluate(1)
        assert _refusals(lines) == [f"system_passkey_refused {expected}"], (kwargs, lines)


def test_allowed_provider_and_other_peers_log_no_refusal(monkeypatch):
    policy = _policy(monkeypatch, exe=PROVIDER, frozen=True, thumbprints=SIGNED)
    lines = _logged(monkeypatch)
    assert policy.evaluate(1).scope == "system_passkey"
    assert _refusals(lines) == []
    policy = _policy(monkeypatch, exe=HOST, config={"passkey_provider_path": DEV_PROVIDER},
                     registrations={"Chrome": HOST})
    lines = _logged(monkeypatch)
    policy.evaluate(1)
    assert _refusals(lines) == []  # a native host is not the provider: no provider line


def test_refusal_lines_carry_no_path_sid_or_family(monkeypatch):
    policy = _policy(monkeypatch, exe=PROVIDER, frozen=True, thumbprints=SIGNED, peer_family="Other.Package_abc")
    lines = _logged(monkeypatch)
    policy.evaluate(1)
    text = "\n".join(lines)
    for secret in ("Other.Package", FAMILY, USER, "Program Files", "PasskeyProvider", "4321"):
        assert secret not in text
    assert pipe._system_log_word("C:/x y") == "other"
    assert pipe._system_log_word("client_not_allowed") == "client_not_allowed"


def test_system_requests_are_logged_with_their_result(monkeypatch):
    lines = []
    original = pipe._pipe_log
    try:
        monkeypatch.setitem(sys.modules, "win32file", NS(CloseHandle=lambda h: None))
        monkeypatch.setitem(sys.modules, "win32pipe", NS(DisconnectNamedPipe=lambda h: None))
        monkeypatch.setattr(pipe, "_flush_reply", lambda h: None)
        monkeypatch.setattr(pipe, "_verify_native_host_client", lambda h: SYSTEM)
        server = pipe.NamedPipeAgentServer(lambda r: {"ok": False}, system_dispatcher=lambda r, pid: {
            "ok": False, "error": "busy", "message": "example.test"})
        monkeypatch.setattr(pipe, "_pipe_log", lambda event, exc=None: lines.append(event))
        monkeypatch.setattr(pipe, "_recv_pipe", lambda h: {"action": "passkey_create_system", "rp_id": "example.test",
                                                             "token": server.token})
        monkeypatch.setattr(pipe, "_send_pipe", lambda h, r: None)
        server._handle_client(5)
        assert lines == ["system_passkey action=passkey_create_system result=busy"]
        # A wrong token for the provider scope names the check.
        lines.clear()
        monkeypatch.setattr(pipe, "_recv_pipe", lambda h: {"action": "passkey_create_system", "token": "x" * 43})
        server._handle_client(5)
        assert lines == ["system_passkey_refused check=token"]
    finally:
        monkeypatch.setattr(pipe, "_pipe_log", original)


def _server(monkeypatch, decision, request, *, system_dispatcher=True):
    replies, browser, cli, system = [], [], [], []
    monkeypatch.setitem(sys.modules, "win32file", NS(CloseHandle=lambda h: None))
    monkeypatch.setitem(sys.modules, "win32pipe", NS(DisconnectNamedPipe=lambda h: None))
    monkeypatch.setattr(pipe, "_flush_reply", lambda h: None)
    monkeypatch.setattr(pipe, "_pipe_log", lambda *a: None)
    monkeypatch.setattr(pipe, "_verify_native_host_client", lambda h: decision)
    server = pipe.NamedPipeAgentServer(
        lambda r: browser.append(dict(r)) or {"ok": False, "error": "unsupported_action"},
        cli_dispatcher=lambda r, pid: cli.append(dict(r)) or {"ok": True, "from": "cli"},
        system_dispatcher=(lambda r, pid: system.append((dict(r), pid)) or {"ok": True, "from": "system"})
        if system_dispatcher else None)
    token = request.pop("token", server.token)
    monkeypatch.setattr(pipe, "_recv_pipe", lambda h: {**request, "token": token})
    monkeypatch.setattr(pipe, "_send_pipe", lambda h, r: replies.append(r))
    server._handle_client(5)
    return replies, browser, cli, system


SYSTEM = pipe.PinDecision(True, "ok", "install_json", "system_passkey", 4321)


def test_system_scope_reaches_only_the_system_dispatcher(monkeypatch):
    for action in sorted(pipe.SYSTEM_PASSKEY_ACTIONS):
        replies, browser, cli, system = _server(monkeypatch, SYSTEM, {"action": action, "system_protocol": 1})
        assert browser == cli == [] and system == [({"action": action, "system_protocol": 1}, 4321)]
        assert replies == [{"ok": True, "from": "system"}]
    # A wrong token never reaches it.
    replies, _b, _c, system = _server(monkeypatch, SYSTEM, {"action": "passkey_get_system", "token": "x" * 43})
    assert system == [] and replies[0]["error"] == "unauthorized"
    # No dispatcher attached: disabled, never the broker.
    replies, browser, _c, _s = _server(monkeypatch, SYSTEM, {"action": "passkey_get_system"},
                                       system_dispatcher=False)
    assert browser == [] and replies == [{"ok": False, "error": "disabled"}]


@pytest.mark.parametrize("action", ["get_browser", "begin_browser", "ping", "status", "read", "passkey_get_browser"])
def test_system_scope_cannot_send_browser_actions(monkeypatch, action):
    replies, browser, cli, system = _server(monkeypatch, SYSTEM, {"action": action})
    assert browser == cli == system == [] and replies[0]["error"] == "client_not_allowed"


@pytest.mark.parametrize("action", sorted(pipe.SYSTEM_PASSKEY_ACTIONS))
def test_browser_scope_cannot_send_system_actions(monkeypatch, action):
    # Refused at the pipe; the browser dispatcher itself also answers unsupported_action
    # (tests/test_passkey_system_broker.py::test_browser_dispatcher_does_not_serve_system_actions).
    for decision in (pipe.PinDecision(True, scope="browser"), pipe.PinDecision(True)):
        replies, browser, cli, system = _server(monkeypatch, decision, {"action": action})
        assert browser == cli == system == [] and replies[0]["error"] == "client_not_allowed"


@pytest.mark.parametrize("action", sorted(pipe.SYSTEM_PASSKEY_ACTIONS))
def test_cli_scope_cannot_send_system_actions(monkeypatch, action):
    cli_decision = pipe.PinDecision(True, "ok", "install_json", "cli", 4321)
    replies, browser, cli, system = _server(monkeypatch, cli_decision, {"action": action})
    assert browser == cli == system == [] and replies[0]["error"] == "client_not_allowed"


HOST_UNVERIFIED = pipe.PinDecision(True, "ok", "registry", pipe.HOST_SCOPE, 4321)


@pytest.mark.parametrize("action", ["status", "list", "read", "totp", "agent_list_sites", "agent_fill_login"])
def test_native_host_as_lgk_reaches_only_the_cli_service(monkeypatch, action):
    replies, browser, cli, system = _server(monkeypatch, HOST_UNVERIFIED, {"action": action, "scope_hint": "cli"})
    assert browser == system == [] and cli == [{"action": action}] and replies == [{"ok": True, "from": "cli"}]
    replies, _b, cli, _s = _server(monkeypatch, HOST_UNVERIFIED,
                                   {"action": action, "scope_hint": "cli", "token": "x" * 43})
    assert cli == [] and replies[0]["error"] == "unauthorized"


@pytest.mark.parametrize("action", ["read", "get_browser", "begin_browser", "fill", "passkey_get_browser"])
def test_native_host_without_cli_hint_keeps_the_diagnostic_refusal(monkeypatch, action):
    replies, browser, cli, system = _server(monkeypatch, HOST_UNVERIFIED, {"action": action})
    assert browser == cli == system == [] and replies[0]["ok"] is False


def test_native_host_as_lgk_never_reaches_system_actions(monkeypatch):
    replies, browser, cli, system = _server(monkeypatch, HOST_UNVERIFIED,
                                            {"action": "passkey_get_system", "scope_hint": "cli"})
    assert browser == cli == system == [] and replies[0]["error"] == "client_not_allowed"


@pytest.mark.parametrize("action", ["read", "agent_fill_login"])
def test_browser_launched_host_ignores_the_cli_hint(monkeypatch, action):
    replies, browser, cli, _s = _server(monkeypatch, pipe.PinDecision(True, scope="browser", pid=4321),
                                        {"action": action, "scope_hint": "cli"})
    assert cli == [] and len(browser) == 1


def test_host_pin_keeps_the_peer_pid(monkeypatch):
    monkeypatch.setattr(pipe, "_browser_ancestry", lambda pid, images: None)
    decision = pipe.ClientPinPolicy._with_browser_scope(pipe.PinDecision(True), 4321, {"h.exe"})
    assert decision.scope == "diagnostic" and decision.pid == 4321
    decision = pipe.ClientPinPolicy._with_browser_scope(pipe.PinDecision(True), 4321, {"h.exe"}, pipe.HOST_SCOPE)
    assert decision.scope == pipe.HOST_SCOPE


def test_interpreter_chain_peer_does_not_get_the_cli_service(monkeypatch):
    # The repository interpreter chain stays "diagnostic": its cli hint is refused.
    replies, browser, cli, _s = _server(monkeypatch, pipe.PinDecision(True, pid=4321),
                                        {"action": "read", "scope_hint": "cli"})
    assert browser == cli == [] and replies[0]["ok"] is False
