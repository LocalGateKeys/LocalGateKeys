"""System32 paths come from GetSystemWindowsDirectoryW, never from %SystemRoot% / %windir%.

A same-user process that controls the app's environment must not be able to point
an elevated ``netsh`` or the PowerShell behind Authenticode checks at its own folder.
"""
from __future__ import annotations

import ctypes
import os
import subprocess
import sys
from types import SimpleNamespace

import pytest

from localvault import browser_ancestry, export, winpaths
from localvault.sync import firewall, lan_interfaces

BOGUS = r"Z:\attacker\Windows"
windows_only = pytest.mark.skipif(os.name != "nt", reason="GetSystemWindowsDirectoryW is Windows-only")


@pytest.fixture
def bogus_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SystemRoot", BOGUS)
    monkeypatch.setenv("windir", BOGUS)


def _fake_windll(monkeypatch: pytest.MonkeyPatch, answer: str | None) -> list[int]:
    calls: list[int] = []

    def get_system_windows_directory(buffer, size):
        calls.append(size)
        if answer is None:
            return 0
        buffer.value = answer
        return len(answer)

    kernel32 = SimpleNamespace(GetSystemWindowsDirectoryW=get_system_windows_directory)
    monkeypatch.setattr(ctypes, "windll", SimpleNamespace(kernel32=kernel32), raising=False)
    return calls


@windows_only
@pytest.mark.usefixtures("bogus_environment")
def test_real_api_ignores_bogus_environment() -> None:
    root = winpaths.system_windows_directory()
    assert root and os.path.isdir(root)
    assert BOGUS.lower() not in root.lower()
    assert winpaths.system32("netsh.exe") == os.path.join(root, "System32", "netsh.exe")
    assert os.path.isfile(winpaths.system32("netsh.exe"))
    assert os.path.isfile(winpaths.windows_powershell())


@windows_only
@pytest.mark.usefixtures("bogus_environment")
def test_mocked_api_answer_is_used(monkeypatch: pytest.MonkeyPatch) -> None:
    calls = _fake_windll(monkeypatch, r"D:\WinFromApi")
    assert winpaths.system32("route.exe") == os.path.join(r"D:\WinFromApi", "System32", "route.exe")
    assert winpaths.windows_powershell() == os.path.join(r"D:\WinFromApi", "System32", "WindowsPowerShell",
                                                         "v1.0", "powershell.exe")
    assert calls


@windows_only
@pytest.mark.usefixtures("bogus_environment")
def test_api_failure_falls_back_to_constant_not_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    _fake_windll(monkeypatch, None)
    assert winpaths.system_windows_directory() is None
    assert winpaths.system32("netsh.exe") == os.path.join(r"C:\Windows", "System32", "netsh.exe")


@windows_only
@pytest.mark.usefixtures("bogus_environment")
def test_relative_api_answer_is_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    _fake_windll(monkeypatch, "Windows")
    assert winpaths.system_windows_directory() is None
    assert winpaths.system32("netsh.exe").startswith(r"C:\Windows")


def test_non_windows_never_reads_environment(monkeypatch: pytest.MonkeyPatch,
                                             bogus_environment: None) -> None:
    monkeypatch.setattr(winpaths, "system_windows_directory", lambda: None)
    assert BOGUS not in winpaths.system32("netsh.exe")


@pytest.fixture
def api_root(monkeypatch: pytest.MonkeyPatch, bogus_environment: None) -> str:
    root = r"D:\WinFromApi"
    monkeypatch.setattr(winpaths, "system_windows_directory", lambda: root)
    return root


def test_private_copies_are_gone() -> None:
    assert not hasattr(export, "_system32")
    assert not hasattr(firewall, "_system32")
    assert export.system32 is winpaths.system32


def test_firewall_netsh_uses_api_path(api_root: str) -> None:
    seen: list[str] = []

    def elevate(executable: str, parameters: str) -> int:
        seen.append(executable)
        return 0

    firewall.allow_inbound(47821, program=r"C:\app\LocalGateKeys.exe", platform="win32", elevate=elevate)
    assert seen == [os.path.join(api_root, "System32", "netsh.exe")]


def _capture_run(monkeypatch: pytest.MonkeyPatch, module) -> list[list[str]]:
    seen: list[list[str]] = []

    def fake_run(args, **kwargs):
        seen.append(list(args))
        return subprocess.CompletedProcess(args, 0, stdout="", stderr="")

    monkeypatch.setattr(module.subprocess, "run", fake_run)
    return seen


def test_firewall_powershell_uses_api_path(monkeypatch: pytest.MonkeyPatch, api_root: str) -> None:
    seen = _capture_run(monkeypatch, firewall)
    firewall._run_powershell("1", {})
    assert seen[-1][0] == os.path.join(api_root, "System32", "WindowsPowerShell", "v1.0", "powershell.exe")


def test_route_print_uses_api_path(monkeypatch: pytest.MonkeyPatch, api_root: str) -> None:
    seen = _capture_run(monkeypatch, lan_interfaces)
    lan_interfaces._route_print()
    assert seen == [[os.path.join(api_root, "System32", "route.exe"), "print", "-4"]]


def test_browser_ancestry_uses_api_root(api_root: str) -> None:
    assert browser_ancestry._system_directories() == (os.path.join(api_root, "System32"),
                                                      os.path.join(api_root, "SysWOW64"))


def test_browser_ancestry_without_api_root_trusts_nothing(monkeypatch: pytest.MonkeyPatch,
                                                          bogus_environment: None) -> None:
    monkeypatch.setattr(winpaths, "system_windows_directory", lambda: None)
    assert browser_ancestry._system_directories() == ()
    assert not browser_ancestry._is_system_cmd(os.path.join(BOGUS, "System32", "cmd.exe"))


def test_signature_powershell_uses_api_path(api_root: str) -> None:
    from localvault import signature

    assert signature.windows_powershell() == os.path.join(api_root, "System32", "WindowsPowerShell", "v1.0",
                                                          "powershell.exe")
    assert sys.modules["localvault.signature"].system32 is winpaths.system32
