from __future__ import annotations

import xml.etree.ElementTree as ET
from pathlib import Path

from localvault import ui_assets


class _NativeFunction:
    def __init__(self, callback):
        self.callback = callback

    def __call__(self, *args):
        return self.callback(*args)


def test_dpi_awareness_is_a_noop_off_windows(monkeypatch) -> None:
    monkeypatch.setattr(ui_assets.sys, "platform", "linux")
    monkeypatch.setattr(
        ui_assets.ctypes,
        "WinDLL",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("loaded user32")),
        raising=False,
    )

    assert ui_assets.enable_dpi_awareness() is False


def test_dpi_awareness_preserves_manifest_setting_or_sets_system_awareness(monkeypatch) -> None:
    monkeypatch.setattr(ui_assets.sys, "platform", "win32")
    calls: list[str] = []
    user32 = type(
        "User32",
        (),
        {
            "IsProcessDPIAware": _NativeFunction(lambda: False),
            "SetProcessDPIAware": _NativeFunction(lambda: calls.append("set") or True),
        },
    )()
    monkeypatch.setattr(ui_assets.ctypes, "WinDLL", lambda *_args, **_kwargs: user32, raising=False)

    assert ui_assets.enable_dpi_awareness() is True
    assert calls == ["set"]

    calls.clear()
    user32.IsProcessDPIAware = _NativeFunction(lambda: True)
    assert ui_assets.enable_dpi_awareness() is True
    assert calls == []


def test_desktop_manifest_declares_system_dpi_awareness() -> None:
    manifest_path = Path(__file__).resolve().parents[1] / "build-personal" / "LocalGateKeys.manifest"
    root = ET.fromstring(manifest_path.read_text(encoding="utf-8"))
    windows_settings = root.find(".//{urn:schemas-microsoft-com:asm.v3}windowsSettings")
    assert windows_settings is not None
    assert windows_settings.find(
        "{http://schemas.microsoft.com/SMI/2016/WindowsSettings}dpiAwareness"
    ).text == "System"
    assert windows_settings.find(
        "{http://schemas.microsoft.com/SMI/2005/WindowsSettings}dpiAware"
    ).text == "true"
