"""Item icons without a UI toolkit: the safety checks of the classic entry_icons module, unchanged."""
from __future__ import annotations

import ctypes
import os
import sys
import threading
import time
from pathlib import Path

import pytest

from localvault import item_icons as entry_icons



@pytest.mark.parametrize("path", [
    r"\\server\share\program.exe",
    r"\\?\C:\program.exe",
    r"\\.\C:\program.exe",
    r"\??\C:\program.exe",
])
def test_desktop_extraction_rejects_network_and_device_paths_before_stat(monkeypatch, path) -> None:
    monkeypatch.setattr(Path, "is_file", lambda self: pytest.fail("network/device path was probed"))
    assert entry_icons.extract_desktop_icon(path) is None


def test_desktop_extraction_smoke_uses_a_local_executable() -> None:
    if os.name != "nt":
        pytest.skip("Windows shell icon APIs are unavailable")
    image = entry_icons.extract_desktop_icon(sys.executable, size=22)
    assert image is not None
    assert image.size[0] <= 22
    assert image.size[1] <= 22


def test_dns_resolution_is_bounded_and_uses_daemon_resolver(monkeypatch) -> None:
    release = threading.Event()
    resolver_started = threading.Event()

    def stalled_getaddrinfo(*_args, **_kwargs):
        resolver_started.set()
        release.wait(2)
        return []

    monkeypatch.setattr(entry_icons.socket, "getaddrinfo", stalled_getaddrinfo)
    deadline = time.monotonic() + 0.03
    started = time.monotonic()
    with pytest.raises(TimeoutError):
        entry_icons._public_addresses("example.test", 443, deadline=deadline)
    elapsed = time.monotonic() - started
    assert resolver_started.is_set()
    assert elapsed < 0.5
    release.set()


def test_bounded_reader_rejects_a_slow_drip_after_deadline() -> None:
    class SlowResponse:
        def getheader(self, _name):
            return None

        def read(self, _size):
            time.sleep(0.03)
            return b"x"

    with pytest.raises(TimeoutError):
        entry_icons._read_bounded(
            SlowResponse(), deadline=time.monotonic() + 0.005)


def test_desktop_extraction_rejects_a_reparse_parent_before_leaf_stat(monkeypatch) -> None:
    class Api:
        def __init__(self, callback):
            self.callback = callback

        def __call__(self, *args):
            return self.callback(*args)

    class Kernel32:
        GetDriveTypeW = Api(lambda _root: 3)

        GetFileAttributesW = Api(
            lambda path: 0x400
            if str(path).replace("/", "\\").casefold().endswith("\\junction")
            else 0
        )

    real_windll = ctypes.WinDLL

    def fake_windll(name, *args, **kwargs):
        if str(name).casefold() == "kernel32":
            return Kernel32()
        return real_windll(name, *args, **kwargs)

    monkeypatch.setattr(entry_icons.ctypes, "WinDLL", fake_windll)
    monkeypatch.setattr(Path, "is_file", lambda self: pytest.fail("reparse child was probed"))
    assert entry_icons.extract_desktop_icon(r"C:\junction\child.exe") is None

"""Squirrel-style apps (Discord, Slack) move to a new app-<version> folder on update."""



from localvault.item_icons import current_versioned_executable


@pytest.mark.skipif(os.name != "nt", reason="Windows path rules")
def test_missing_versioned_exe_follows_newest_folder(tmp_path):
    for version in ("1.0.9", "1.0.10", "0.9.99"):
        folder = tmp_path / f"app-{version}"
        folder.mkdir()
        (folder / "Discord.exe").write_bytes(b"MZ")
    stale = tmp_path / "app-1.0.8" / "Discord.exe"
    assert current_versioned_executable(stale) == tmp_path / "app-1.0.10" / "Discord.exe"
    present = tmp_path / "app-1.0.9" / "Discord.exe"
    assert current_versioned_executable(present) == present
    plain = tmp_path / "Other" / "tool.exe"
    assert current_versioned_executable(plain) == plain
