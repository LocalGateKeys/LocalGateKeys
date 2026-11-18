r"""dev_setup: HKCU\Environment through winreg + WM_SETTINGCHANGE, and ``git config --global`` (everything faked)."""
from __future__ import annotations

import os
import subprocess
import winreg

import pytest

from localvault import dev_setup


class FakeKey:
    def __init__(self, registry):
        self.registry = registry

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


class FakeRegistry:
    """Just enough of winreg, backed by a dict (never the real registry)."""
    HKEY_CURRENT_USER = object()
    KEY_SET_VALUE = winreg.KEY_SET_VALUE
    REG_SZ = winreg.REG_SZ

    def __init__(self, values=None):
        self.values = dict(values or {})
        self.opened = []

    def OpenKey(self, root, path, reserved=0, access=0):
        assert root is self.HKEY_CURRENT_USER and path == "Environment"
        self.opened.append(access)
        return FakeKey(self)

    def QueryValueEx(self, key, name):
        if name not in self.values:
            raise FileNotFoundError(name)
        return self.values[name], winreg.REG_SZ

    def SetValueEx(self, key, name, reserved, kind, value):
        assert kind == winreg.REG_SZ
        self.values[name] = value

    def DeleteValue(self, key, name):
        if name not in self.values:
            raise FileNotFoundError(name)
        del self.values[name]


class FakeUser32:
    def __init__(self):
        self.calls = []

    def SendMessageTimeoutW(self, *args):
        self.calls.append(args)
        return 1


@pytest.fixture
def machine(monkeypatch):
    registry, user32 = FakeRegistry({"PATH": "x"}), FakeUser32()
    monkeypatch.setattr(dev_setup, "_registry", lambda: registry)
    monkeypatch.setattr(dev_setup, "_user32", lambda: user32)
    return registry, user32


def test_set_user_env_returns_previous_and_broadcasts(machine):
    registry, user32 = machine
    assert dev_setup.set_user_env("SSH_AUTH_SOCK", r"\.\pipe\x") is None
    assert registry.values["SSH_AUTH_SOCK"] == r"\.\pipe\x"
    assert dev_setup.set_user_env("SSH_AUTH_SOCK", r"\.\pipe\y") == r"\.\pipe\x"
    assert len(user32.calls) == 2
    hwnd, message, _wparam, lparam = user32.calls[0][:4]
    assert (hwnd, message, lparam) == (0xFFFF, 0x001A, "Environment")
    assert registry.values["PATH"] == "x"


def test_restore_user_env_none_deletes_and_broadcasts(machine):
    registry, user32 = machine
    dev_setup.set_user_env("SSH_AUTH_SOCK", "a")
    dev_setup.restore_user_env("SSH_AUTH_SOCK", None)
    assert "SSH_AUTH_SOCK" not in registry.values
    dev_setup.restore_user_env("SSH_AUTH_SOCK", None)  # already gone is fine
    dev_setup.restore_user_env("SSH_AUTH_SOCK", "old")
    assert registry.values["SSH_AUTH_SOCK"] == "old"
    assert len(user32.calls) == 4


class FakeGit:
    def __init__(self, config=None, missing=False, version="2.50"):
        self.version = version
        self.config = dict(config or {})
        self.missing = missing
        self.calls = []

    def __call__(self, args, **kwargs):
        assert kwargs.get("shell") is False and kwargs.get("timeout") == 10
        # An absolute path: a bare name would let Windows run a git.exe from the current folder.
        assert os.path.isabs(args[0]) and os.path.basename(args[0]).lower().startswith("git")
        self.calls.append(args)
        if self.missing:
            raise FileNotFoundError("git")
        rest = args[1:]
        if rest == ["--version"]:
            return subprocess.CompletedProcess(args, 0, f"git version {self.version}\n", "")
        assert rest[:2] == ["config", "--global"]
        if rest[2] == "--get":
            value = self.config.get(rest[3])
            return subprocess.CompletedProcess(args, 0 if value is not None else 1, (value or "") + "\n", "")
        if rest[2] == "--unset":
            existed = self.config.pop(rest[3], None) is not None
            return subprocess.CompletedProcess(args, 0 if existed else 5, "", "")
        self.config[rest[2]] = rest[3]
        return subprocess.CompletedProcess(args, 0, "", "")


def test_git_get_set_unset(monkeypatch):
    git = FakeGit({"user.name": "A"})
    monkeypatch.setattr(dev_setup.subprocess, "run", git)
    assert dev_setup.git_available()
    assert dev_setup.git_config_get("user.name") == "A"
    assert dev_setup.git_config_get("gpg.format") is None
    dev_setup.git_config_set("gpg.format", "ssh")
    assert git.config["gpg.format"] == "ssh"
    dev_setup.git_config_set("gpg.format", None)
    dev_setup.git_config_set("gpg.format", None)  # unsetting an unset key is fine
    assert "gpg.format" not in git.config


def test_git_missing_reports_unavailable(monkeypatch):
    monkeypatch.setattr(dev_setup.subprocess, "run", FakeGit(missing=True))
    assert not dev_setup.git_available()
    assert dev_setup.git_config_get("user.name") is None
    with pytest.raises(dev_setup.DevSetupError) as info:
        dev_setup.git_config_set("user.name", "x")
    assert info.value.code == "git_missing"


def test_git_failure_raises(monkeypatch):
    def refuse(args, **kwargs):
        return subprocess.CompletedProcess(args, 128, "", "fatal")

    monkeypatch.setattr(dev_setup.subprocess, "run", refuse)
    with pytest.raises(dev_setup.DevSetupError) as info:
        dev_setup.git_config_set("user.name", "x")
    assert info.value.code == "git_failed"


def test_git_is_never_run_by_bare_name(monkeypatch):
    monkeypatch.setattr(dev_setup.shutil, "which", lambda name, path=None: None)
    monkeypatch.setattr(dev_setup.subprocess, "run", lambda *a, **k: (_ for _ in ()).throw(AssertionError("ran")))
    assert not dev_setup.git_available()
