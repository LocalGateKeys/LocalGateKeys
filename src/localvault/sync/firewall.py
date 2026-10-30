"""Windows Firewall help for Wi-Fi sync: look for an inbound rule, and add one only when the user asks.

Nothing here changes the firewall on its own.  :func:`allow_inbound` is called
only from the explicit "Allow through Windows Firewall" button; it runs
``netsh advfirewall firewall add rule`` elevated (Windows shows its UAC
prompt).  The rule allows inbound TCP on the sync port, for this program only
(the packaged ``LocalGateKeys.exe``, or the ``python.exe`` that runs the app
from source), on the Private profile, from the local subnet.

:func:`firewall_status` reads the rules and network profiles with PowerShell
(``Get-NetFirewallRule`` / ``Get-NetConnectionProfile``) and parses JSON, so
it does not depend on the Windows display language.  Every system call is
injectable; the tests never touch the real firewall.
"""
from __future__ import annotations

import json
import os
import subprocess  # noqa: S404 - fixed System32 tools, arguments built here
import sys
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from ..winpaths import system32, windows_powershell
from ..i18n import t

RULE_NAME = "LocalGateKeys Wi-Fi sync"
ERROR_CANCELLED = 1223  # the user said No at the UAC prompt


def program_path() -> str:
    """The executable Windows Firewall sees accept connections: the app, or python.exe from source.

    The process image is asked for first: in a Windows venv ``sys.executable`` is the
    ``Scripts\\python.exe`` redirector, while the process that listens is the base interpreter.
    """
    try:
        import psutil  # type: ignore[import-not-found]

        image = psutil.Process().exe()
        if image:
            return os.path.abspath(image)
    except Exception:  # noqa: BLE001, S110 - fall back to sys.executable
        pass
    return os.path.abspath(sys.executable)


@dataclass(frozen=True)
class FirewallStatus:
    supported: bool  # False off Windows, or when the status could not be read
    allowed: bool = False  # an enabled Allow rule covers this program and port on the network's profile
    rule_present: bool = False  # our own rule exists (it may not match the port or program)
    profile: str = ""  # "Private", "Public", "DomainAuthenticated" or "" when unknown
    interface: str = ""
    blocked_by: str = ""  # name of an enabled Block rule for this program, when found
    detail: str = ""
    rules: tuple[dict[str, Any], ...] = field(default=())


# PowerShell: our rules, any rule for this program, and the connection profiles, as one JSON document.
_STATUS_SCRIPT = r"""
[Console]::OutputEncoding = [Text.Encoding]::UTF8
$ErrorActionPreference = 'SilentlyContinue'
$program = $env:LGK_PROGRAM
function Describe($r) {
  $p = $r | Get-NetFirewallPortFilter; $a = $r | Get-NetFirewallApplicationFilter
  [pscustomobject]@{ Name = [string]$r.DisplayName; Enabled = [string]$r.Enabled; Direction = [string]$r.Direction;
    Action = [string]$r.Action; Profile = [string]$r.Profile; Protocol = [string]$p.Protocol;
    LocalPort = [string]($p.LocalPort -join ','); Program = [string]$a.Program }
}
$rules = @()
$rules += Get-NetFirewallRule -DisplayName $env:LGK_RULE | ForEach-Object { Describe $_ }
$rules += Get-NetFirewallApplicationFilter -Program $program | Get-NetFirewallRule |
  Where-Object { $_.Direction -eq 'Inbound' } | ForEach-Object { Describe $_ }
$profiles = @(Get-NetConnectionProfile | ForEach-Object {
  [pscustomobject]@{ InterfaceAlias = [string]$_.InterfaceAlias; NetworkCategory = [string]$_.NetworkCategory } })
[pscustomobject]@{ rules = $rules; profiles = $profiles } | ConvertTo-Json -Depth 4 -Compress
"""


def _profiles_of(text: str) -> set[str]:
    value = (text or "").strip()
    if not value or value.lower() == "any":
        return {"Domain", "Private", "Public"}
    return {part.strip() for part in value.replace(";", ",").split(",") if part.strip()}


def _covers_port(local_port: str, port: int) -> bool:
    value = (local_port or "").strip()
    if not value or value.lower() == "any":
        return True
    for part in value.split(","):
        part = part.strip()
        if "-" in part:
            low, _, high = part.partition("-")
            if low.isdigit() and high.isdigit() and int(low) <= port <= int(high):
                return True
        elif part.isdigit() and int(part) == port:
            return True
    return False


def _same_program(rule_program: str, program: str) -> bool:
    value = (rule_program or "").strip()
    if not value or value.lower() == "any":
        return True
    return os.path.normcase(os.path.normpath(value)) == os.path.normcase(os.path.normpath(program))


def parse_status(document: str, *, program: str, port: int, interface: str = "") -> FirewallStatus:
    """Interpret the PowerShell JSON for *program* listening on TCP *port* via *interface*."""
    try:
        data = json.loads(document or "{}")
    except ValueError:
        return FirewallStatus(supported=False, detail=t("firewall.theFirewallStatusCouldNot"))
    if not isinstance(data, dict):
        return FirewallStatus(supported=False, detail=t("firewall.theFirewallStatusCouldNot"))
    rules = data.get("rules") or []
    profiles = data.get("profiles") or []
    rules = [rules] if isinstance(rules, dict) else [r for r in rules if isinstance(r, dict)]
    profiles = [profiles] if isinstance(profiles, dict) else [p for p in profiles if isinstance(p, dict)]
    profile = ""  # unknown unless the sync address's own adapter is listed
    if interface:
        for entry in profiles:
            if str(entry.get("InterfaceAlias", "")) == interface:
                profile = str(entry.get("NetworkCategory", ""))
                break
    wanted = {"DomainAuthenticated": "Domain"}.get(profile, profile) or "Private"
    allowed = False
    blocked_by = ""
    present = False
    seen: list[dict[str, Any]] = []
    for rule in rules:
        if rule in seen:
            continue
        seen.append(rule)
        if str(rule.get("Name", "")) == RULE_NAME:
            present = True
        if (str(rule.get("Enabled", "")).lower() != "true" or str(rule.get("Direction", "")) != "Inbound"
                or wanted not in _profiles_of(str(rule.get("Profile", "")))
                or not _same_program(str(rule.get("Program", "")), program)
                or str(rule.get("Protocol", "TCP")).upper() not in ("TCP", "ANY", "6", "")
                or not _covers_port(str(rule.get("LocalPort", "")), port)):
            continue
        action = str(rule.get("Action", ""))
        if action == "Block":
            blocked_by = blocked_by or str(rule.get("Name", ""))
        elif action == "Allow":
            allowed = True
    return FirewallStatus(supported=True, allowed=allowed and not blocked_by, rule_present=present,
                          profile=profile, interface=interface, blocked_by=blocked_by, rules=tuple(seen))


def _run_powershell(script: str, env: dict[str, str]) -> str | None:
    exe = windows_powershell()
    try:
        result = subprocess.run([exe, "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",  # noqa: S603
                                 "-Command", script], capture_output=True, text=True, encoding="utf-8",
                                errors="replace", timeout=20, check=False, env={**os.environ, **env},
                                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    except (OSError, subprocess.SubprocessError, ValueError, UnicodeDecodeError):
        return None
    return result.stdout if result.returncode == 0 else None


def firewall_status(port: int, *, interface: str = "", platform: str = sys.platform,
                    program: str | None = None,
                    run: Callable[[str, dict[str, str]], str | None] = _run_powershell) -> FirewallStatus:
    if platform != "win32":
        return FirewallStatus(supported=False)
    program = program or program_path()
    document = run(_STATUS_SCRIPT, {"LGK_PROGRAM": program, "LGK_RULE": RULE_NAME})
    if document is None:
        return FirewallStatus(supported=False, detail=t("firewall.theFirewallStatusCouldNot"))
    return parse_status(document, program=program, port=port, interface=interface)


def rule_arguments(program: str, port: int, *, replace: bool = False) -> list[str]:
    """``netsh`` arguments that add (or, with *replace*, update) our Private-profile inbound rule."""
    if not 1024 <= int(port) <= 65535:
        raise ValueError("port out of range")
    if '"' in program:
        raise ValueError("program path contains a quote")
    settings = ["dir=in", "action=allow", "protocol=TCP", f"localport={int(port)}", f'program="{program}"',
                "profile=private", "remoteip=localsubnet", "enable=yes"]
    if replace:
        return ["advfirewall", "firewall", "set", "rule", f'name="{RULE_NAME}"', "new", *settings]
    return ["advfirewall", "firewall", "add", "rule", f'name="{RULE_NAME}"', *settings]


def _shell_execute_elevated(executable: str, parameters: str) -> int:
    """Run *executable* elevated (UAC prompt), wait, and return its exit code (ERROR_CANCELLED on No)."""
    import ctypes
    from ctypes import wintypes

    class SHELLEXECUTEINFOW(ctypes.Structure):
        _fields_ = [("cbSize", wintypes.DWORD), ("fMask", wintypes.ULONG), ("hwnd", wintypes.HWND),
                    ("lpVerb", wintypes.LPCWSTR), ("lpFile", wintypes.LPCWSTR), ("lpParameters", wintypes.LPCWSTR),
                    ("lpDirectory", wintypes.LPCWSTR), ("nShow", ctypes.c_int), ("hInstApp", wintypes.HINSTANCE),
                    ("lpIDList", ctypes.c_void_p), ("lpClass", wintypes.LPCWSTR), ("hkeyClass", wintypes.HKEY),
                    ("dwHotKey", wintypes.DWORD), ("hIconOrMonitor", wintypes.HANDLE),
                    ("hProcess", wintypes.HANDLE)]

    SEE_MASK_NOCLOSEPROCESS = 0x00000040  # noqa: N806
    SEE_MASK_NO_CONSOLE = 0x00008000  # noqa: N806
    info = SHELLEXECUTEINFOW()
    info.cbSize = ctypes.sizeof(info)
    info.fMask = SEE_MASK_NOCLOSEPROCESS | SEE_MASK_NO_CONSOLE
    info.lpVerb = "runas"
    info.lpFile = executable
    info.lpParameters = parameters
    info.nShow = 0  # SW_HIDE
    shell32 = ctypes.WinDLL("shell32", use_last_error=True)  # type: ignore[attr-defined]
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)  # type: ignore[attr-defined]
    shell32.ShellExecuteExW.argtypes = [ctypes.POINTER(SHELLEXECUTEINFOW)]
    shell32.ShellExecuteExW.restype = wintypes.BOOL
    kernel32.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
    kernel32.WaitForSingleObject.restype = wintypes.DWORD
    kernel32.GetExitCodeProcess.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD)]
    kernel32.GetExitCodeProcess.restype = wintypes.BOOL
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel32.CloseHandle.restype = wintypes.BOOL
    if not shell32.ShellExecuteExW(ctypes.byref(info)):
        error = ctypes.get_last_error()  # type: ignore[attr-defined]
        return ERROR_CANCELLED if error == ERROR_CANCELLED else (error or -1)
    if not info.hProcess:
        return -1  # started, but no process handle to wait on: the caller re-checks the rule
    try:
        if kernel32.WaitForSingleObject(info.hProcess, 60_000) != 0:  # WAIT_OBJECT_0
            return -1
        code = wintypes.DWORD()
        if not kernel32.GetExitCodeProcess(info.hProcess, ctypes.byref(code)):
            return -1
        return int(code.value)
    finally:
        kernel32.CloseHandle(info.hProcess)


@dataclass(frozen=True)
class AllowResult:
    ok: bool
    cancelled: bool = False
    message: str = ""


def allow_inbound(port: int, *, status: FirewallStatus | None = None, program: str | None = None,
                  platform: str = sys.platform,
                  elevate: Callable[[str, str], int] = _shell_execute_elevated) -> AllowResult:
    """Add (or update) our rule through an elevated ``netsh``. Only call it from the user's button."""
    if platform != "win32":
        return AllowResult(False, message=t("sync.windowsFirewallSettingsAreOnly"))
    program = program or program_path()
    args = rule_arguments(program, port, replace=bool(status and status.rule_present))
    code = elevate(system32("netsh.exe"), " ".join(args))
    if code == ERROR_CANCELLED:
        return AllowResult(False, cancelled=True, message=t("firewall.windowsFirewallWasNotChanged"))
    if code != 0:
        return AllowResult(False, message=t("firewall.couldNotBeChanged", code=code))
    return AllowResult(True, message=t("firewall.localgatekeysMayNowReceiveWi"))
