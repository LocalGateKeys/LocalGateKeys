"""Windows Firewall help for Wi-Fi sync. Everything is mocked: no test touches the real firewall."""
from __future__ import annotations

import json

import pytest

from localvault.sync import firewall
from localvault.sync.firewall import (
    ERROR_CANCELLED,
    RULE_NAME,
    allow_inbound,
    firewall_status,
    parse_status,
    rule_arguments,
)

REAL_RUN_POWERSHELL = firewall._run_powershell  # saved before the autouse fixture patches it
APP = r"C:\Program Files\LocalGateKeys\LocalGateKeys.exe"
PY = r"C:\python314\python.exe"


def rule(name=RULE_NAME, program=APP, port="47821", profile="Private", action="Allow", enabled="True",
         protocol="TCP"):
    return {"Name": name, "Enabled": enabled, "Direction": "Inbound", "Action": action, "Profile": profile,
            "Protocol": protocol, "LocalPort": port, "Program": program}


def doc(rules=(), profiles=({"InterfaceAlias": "Ethernet", "NetworkCategory": "Private"},)):
    return json.dumps({"rules": list(rules), "profiles": list(profiles)})


@pytest.fixture(autouse=True)
def no_real_system(monkeypatch):
    def refuse(*a, **k):
        raise AssertionError("tests must never run the real firewall tools")

    monkeypatch.setattr(firewall, "_run_powershell", refuse)
    monkeypatch.setattr(firewall, "_shell_execute_elevated", refuse)
    monkeypatch.setattr(firewall.subprocess, "run", refuse)


def test_no_rule_is_not_allowed_and_shows_the_profile():
    status = parse_status(doc(), program=APP, port=47821, interface="Ethernet")
    assert status.supported and not status.allowed and not status.rule_present and status.profile == "Private"


def test_our_rule_allows_on_private():
    status = parse_status(doc([rule()]), program=APP, port=47821, interface="Ethernet")
    assert status.allowed and status.rule_present


def test_installer_rule_for_any_port_on_private_counts():
    status = parse_status(doc([rule(name="localgatekeys.exe", port="Any", protocol="TCP")]), program=APP,
                          port=47821, interface="Ethernet")
    assert status.allowed and not status.rule_present


def test_a_block_rule_for_python_wins_and_is_named():
    status = parse_status(doc([rule(program=PY), rule(name="python.exe", program=PY, action="Block", port="Any")]),
                          program=PY, port=47821, interface="Ethernet")
    assert not status.allowed and status.blocked_by == "python.exe"


def test_wrong_port_program_disabled_or_public_only_rules_do_not_count():
    for r in (rule(port="5000"), rule(program=PY), rule(enabled="False"), rule(profile="Public")):
        assert not parse_status(doc([r]), program=APP, port=47821, interface="Ethernet").allowed, r
    assert parse_status(doc([rule(port="47000-48000")]), program=APP, port=47821).allowed


def test_public_network_needs_a_rule_on_public():
    public = ({"InterfaceAlias": "Wi-Fi", "NetworkCategory": "Public"},)
    status = parse_status(doc([rule()], public), program=APP, port=47821, interface="Wi-Fi")
    assert status.profile == "Public" and not status.allowed


def test_single_objects_and_garbage_are_handled():
    one = json.dumps({"rules": rule(), "profiles": {"InterfaceAlias": "Ethernet", "NetworkCategory": "Private"}})
    assert parse_status(one, program=APP, port=47821, interface="Ethernet").allowed
    assert not parse_status("not json", program=APP, port=47821).supported


def test_status_is_windows_only_and_passes_program_through_env():
    assert not firewall_status(47821, platform="darwin").supported
    seen = {}

    def run(script, env):
        seen.update(env)
        return doc([rule()])

    status = firewall_status(47821, interface="Ethernet", platform="win32", program=APP, run=run)
    assert status.allowed and seen == {"LGK_PROGRAM": APP, "LGK_RULE": RULE_NAME}
    assert not firewall_status(47821, platform="win32", program=APP, run=lambda s, e: None).supported


def test_rule_arguments_are_private_inbound_tcp_for_the_program():
    args = rule_arguments(PY, 47821)
    assert args[:4] == ["advfirewall", "firewall", "add", "rule"]
    for part in (f'name="{RULE_NAME}"', "dir=in", "action=allow", "protocol=TCP", "localport=47821",
                 f'program="{PY}"', "profile=private", "remoteip=localsubnet", "enable=yes"):
        assert part in args
    assert rule_arguments(PY, 47821, replace=True)[2:6] == ["set", "rule", f'name="{RULE_NAME}"', "new"]
    with pytest.raises(ValueError):
        rule_arguments('C:\\x"y.exe', 47821)
    with pytest.raises(ValueError):
        rule_arguments(PY, 80)


def test_allow_runs_netsh_elevated_and_reports_cancel():
    runs = []
    result = allow_inbound(47821, program=APP, platform="win32",
                           elevate=lambda exe, params: runs.append((exe, params)) or 0)
    assert result.ok and runs[0][0].lower().endswith("netsh.exe") and "add rule" in runs[0][1]
    assert "profile=private" in runs[0][1] and f'program="{APP}"' in runs[0][1]
    cancelled = allow_inbound(47821, program=APP, platform="win32", elevate=lambda e, p: ERROR_CANCELLED)
    assert cancelled.cancelled and not cancelled.ok
    failed = allow_inbound(47821, program=APP, platform="win32", elevate=lambda e, p: 1)
    assert not failed.ok and "exit code 1" in failed.message
    assert not allow_inbound(47821, platform="darwin", elevate=lambda e, p: 0).ok


def test_allow_updates_an_existing_rule_instead_of_adding_a_second():
    runs = []
    present = parse_status(doc([rule(port="5000")]), program=APP, port=47821)
    allow_inbound(47821, status=present, program=APP, platform="win32",
                  elevate=lambda exe, params: runs.append(params) or 0)
    assert "set rule" in runs[0] and " new " in runs[0]


def test_unknown_interface_reports_an_unknown_profile():
    public = ({"InterfaceAlias": "Wi-Fi", "NetworkCategory": "Public"},)
    assert parse_status(doc([rule()], public), program=APP, port=47821, interface="").profile == ""
    assert parse_status(doc(), program=APP, port=47821, interface="Ethernet 9").profile == ""


def test_powershell_output_is_read_as_utf8_with_non_ascii_rule_names(monkeypatch):
    seen = {}
    text = doc([rule(name="Règle Python — bloqué", program=PY, action="Block", port="Any")],
               ({"InterfaceAlias": "Ethernet (Câble)", "NetworkCategory": "Private"},))

    class Done:
        returncode = 0
        stdout = text

    def run(args, **kwargs):
        seen.update(kwargs, script=args[-1])
        return Done()

    monkeypatch.setattr(firewall.subprocess, "run", run)
    document = REAL_RUN_POWERSHELL(firewall._STATUS_SCRIPT, {"LGK_PROGRAM": PY, "LGK_RULE": RULE_NAME})
    assert seen["encoding"] == "utf-8" and seen["errors"] == "replace"
    assert "[Console]::OutputEncoding = [Text.Encoding]::UTF8" in seen["script"]
    status = parse_status(document, program=PY, port=47821, interface="Ethernet (Câble)")
    assert status.blocked_by == "Règle Python — bloqué" and status.profile == "Private"


def test_powershell_decoding_errors_are_contained(monkeypatch):
    def broken(args, **kwargs):
        raise UnicodeDecodeError("utf-8", b"\xff", 0, 1, "bad")

    monkeypatch.setattr(firewall.subprocess, "run", broken)
    assert REAL_RUN_POWERSHELL("x", {}) is None
