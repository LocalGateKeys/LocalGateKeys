"""Developer setup helpers (Windows): the user environment and the global Git config.

Both are changed only by an explicit button on Settings > Developer, and both hand back what they replaced so Undo can
put it back. ``HKCU\\Environment`` goes through ``winreg`` and is announced with ``WM_SETTINGCHANGE``; Git is driven
through ``git config --global`` (never a shell, never a config file edit). Nothing here logs values.
"""
from __future__ import annotations

import os
import re
import shutil
import subprocess
from typing import Any

ENV_KEY = "Environment"
GIT_TIMEOUT = 10
_HWND_BROADCAST = 0xFFFF
_WM_SETTINGCHANGE = 0x001A
_SMTO_ABORTIFHUNG = 0x0002
_BROADCAST_TIMEOUT_MS = 2000


class DevSetupError(Exception):
    """A setup step failed; ``code`` is a short stable identifier (git_missing, git_failed, env_failed)."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def _registry() -> Any:
    import winreg

    return winreg


def _user32() -> Any:
    import ctypes

    return ctypes.windll.user32


# ------------------------------------------------------------------ environment
def get_user_env(name: str) -> str | None:
    """The value of ``name`` in HKCU\\Environment, or None when it is not set."""
    winreg = _registry()
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, ENV_KEY) as key:
            value, _kind = winreg.QueryValueEx(key, name)
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise DevSetupError("env_failed") from exc
    return value if isinstance(value, str) else None


def _broadcast_environment() -> None:
    """Tell running programs (Explorer, new terminals) that the environment changed. Failure is harmless."""
    import ctypes

    try:
        result = ctypes.c_ulong()
        _user32().SendMessageTimeoutW(_HWND_BROADCAST, _WM_SETTINGCHANGE, 0, "Environment", _SMTO_ABORTIFHUNG,
                                      _BROADCAST_TIMEOUT_MS, ctypes.byref(result))
    except (OSError, AttributeError):
        # Expected failure for this optional step: fall back to the default behaviour.
        pass


def _write_user_env(name: str, value: str | None) -> None:
    winreg = _registry()
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, ENV_KEY, 0, winreg.KEY_SET_VALUE) as key:
            if value is None:
                try:
                    winreg.DeleteValue(key, name)
                except FileNotFoundError:
                    # Best-effort file/OS step: failure is harmless here, so it is ignored.
                    pass
            else:
                winreg.SetValueEx(key, name, 0, winreg.REG_SZ, value)
    except OSError as exc:
        raise DevSetupError("env_failed") from exc
    _broadcast_environment()


def set_user_env(name: str, value: str) -> str | None:
    """Set ``name`` in HKCU\\Environment; returns the previous value (None when it was not set)."""
    previous = get_user_env(name)
    _write_user_env(name, value)
    return previous


def restore_user_env(name: str, previous: str | None) -> None:
    """Put ``previous`` back (None removes the variable)."""
    _write_user_env(name, previous)


# ------------------------------------------------------------------ git
def _git(args: list[str]) -> subprocess.CompletedProcess[str]:
    # A bare name makes Windows look in the current folder first (for example the
    # folder of an opened .lgkshare file); resolve through PATH only.
    git = shutil.which("git", path=os.environ.get("PATH") or os.defpath)
    if not git or not os.path.isabs(git):
        raise DevSetupError("git_missing")
    try:
        # Semgrep: argv list, shell=False: fixed git binary.
        # nosemgrep
        return subprocess.run([git, *args], shell=False, timeout=GIT_TIMEOUT, capture_output=True, text=True,
                              encoding="utf-8", errors="replace", stdin=subprocess.DEVNULL)
    except FileNotFoundError:
        raise DevSetupError("git_missing") from None
    except (OSError, subprocess.SubprocessError) as exc:
        raise DevSetupError("git_failed") from exc


def git_available() -> bool:
    try:
        return _git(["--version"]).returncode == 0
    except DevSetupError:
        return False


def git_version() -> tuple[int, int] | None:
    """(major, minor) from ``git --version``, or None when Git is missing or the output is not understood."""
    try:
        done = _git(["--version"])
    except DevSetupError:
        return None
    match = re.search(r"(\d+)\.(\d+)", done.stdout) if done.returncode == 0 else None
    return (int(match.group(1)), int(match.group(2))) if match else None


def git_config_get(key: str) -> str | None:
    """The global value of ``key``, or None when unset or Git is missing (use ``git_available`` to tell)."""
    try:
        done = _git(["config", "--global", "--get", key])
    except DevSetupError:
        return None
    return done.stdout.strip() or None if done.returncode == 0 else None


def git_config_set(key: str, value: str | None) -> None:
    """Set the global ``key`` (None unsets it). Raises ``DevSetupError`` when Git is missing or refuses."""
    if value is None:
        done = _git(["config", "--global", "--unset", key])
        ok = done.returncode in (0, 5)  # 5: it was not set
    else:
        done = _git(["config", "--global", key, value])
        ok = done.returncode == 0
    if not ok:
        raise DevSetupError("git_failed")
