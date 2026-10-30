"""Stage 1: window host helpers and the --web-ui entrypoint (no window is opened here)."""
from __future__ import annotations

import sys

import pytest

from localvault.web import window as web_window


def test_is_app_url_accepts_only_the_app_origin():
    origin = "http://127.0.0.1:51234"
    assert web_window.is_app_url("http://127.0.0.1:51234/index.html", origin)
    assert web_window.is_app_url("http://127.0.0.1:51234/assets/index-x.js", origin)
    for url in ("https://evil.test/", "http://127.0.0.1:9999/index.html", "file:///C:/other.html",
                "javascript:alert(1)", "about:blank", "", "http://127.0.0.1:51234.evil.test/"):
        assert not web_window.is_app_url(url, origin), url


def test_origin_of():
    assert web_window.origin_of("http://127.0.0.1:51234/index.html?x=1") == "http://127.0.0.1:51234"
    assert web_window.origin_of("not a url") == ""


def test_ui_index_missing_message(tmp_path, monkeypatch):
    monkeypatch.setattr(web_window, "UI_DIR", tmp_path / "ui")
    with pytest.raises(FileNotFoundError) as missing:
        web_window.ui_index_path()
    assert "cd webui && npm ci && npm run build" in str(missing.value)


def test_main_flag_dispatches_before_tk(monkeypatch):
    from localvault import agent

    calls = []
    monkeypatch.setattr("localvault.web.main.run", lambda: calls.append("run"))
    monkeypatch.setattr(agent, "_acquire_windows_instance_mutex", lambda: 1)
    monkeypatch.setattr(sys, "argv", ["localgatekeys", "--web-ui"])
    agent.main()  # under nowin_guard any Tk root would raise
    assert calls == ["run"]


def test_main_flag_second_instance_exits_without_tk(monkeypatch, capsys):
    from localvault import agent

    monkeypatch.setattr("localvault.web.main.run", lambda: pytest.fail("must not start"))
    monkeypatch.setattr(agent, "_acquire_windows_instance_mutex", lambda: None)
    shown = []
    if sys.platform == "win32":
        import ctypes

        # The foreground second instance shows a modal message box; never block the test run on it.
        monkeypatch.setattr(ctypes.windll.user32, "MessageBoxW", lambda *args: shown.append(args[1]) or 1)
    monkeypatch.setattr(sys, "argv", ["localgatekeys", "--web-ui"])
    agent.main()
    assert "already running" in capsys.readouterr().err
    if sys.platform == "win32":
        assert shown == [agent.ALREADY_RUNNING]


def test_theme_choice_overrides_windows(monkeypatch):
    from localvault.web import window

    monkeypatch.setattr(window, "system_prefers_dark", lambda: True)
    assert window.theme_is_dark("light") is False
    assert window.theme_is_dark("dark") is True
    assert window.theme_is_dark("system") is True


class _FakeAffinity:
    """Stands in for ctypes.windll.user32.SetWindowDisplayAffinity; fails the modes listed in `refuse`."""

    def __init__(self, refuse=()):
        self.calls = []
        self.refuse = set(refuse)
        self.argtypes = self.restype = None

    def __call__(self, hwnd, mode):
        self.calls.append(mode)
        return 0 if mode in self.refuse else 1


def _fake_windll(monkeypatch, fake):
    class User32:
        SetWindowDisplayAffinity = fake

    class Windll:
        user32 = User32()

    monkeypatch.setattr(web_window.ctypes, "windll", Windll(), raising=False)
    monkeypatch.setattr(web_window.os, "name", "nt")


def test_display_affinity_excludes_the_window_from_capture(monkeypatch):
    fake = _FakeAffinity()
    _fake_windll(monkeypatch, fake)
    assert web_window.set_display_affinity(1234, True)
    assert fake.calls == [0x11]


def test_display_affinity_falls_back_to_monitor_on_older_windows(monkeypatch):
    fake = _FakeAffinity(refuse={0x11})
    _fake_windll(monkeypatch, fake)
    assert web_window.set_display_affinity(1234, True)
    assert fake.calls == [0x11, 0x1]


def test_display_affinity_reports_failure_and_can_be_turned_off(monkeypatch):
    fake = _FakeAffinity(refuse={0x11, 0x1})
    _fake_windll(monkeypatch, fake)
    assert not web_window.set_display_affinity(1234, True)
    fake.calls.clear()
    assert web_window.set_display_affinity(1234, False)
    assert fake.calls == [0x0]


def test_display_affinity_is_a_no_op_without_a_handle_or_off_windows(monkeypatch):
    fake = _FakeAffinity()
    _fake_windll(monkeypatch, fake)
    assert not web_window.set_display_affinity(None, True)
    monkeypatch.setattr(web_window.os, "name", "posix")
    assert not web_window.set_display_affinity(1234, True)
    assert fake.calls == []


def test_capture_protection_uses_the_native_handle(monkeypatch):
    seen = []
    monkeypatch.setattr(web_window, "native_handle", lambda window: 77)
    monkeypatch.setattr(web_window, "set_display_affinity", lambda hwnd, hide: seen.append((hwnd, hide)) or True)
    assert web_window.WindowOps(object()).set_capture_protection(True)
    popup = web_window.PopupWindow(object())
    assert popup.set_capture_protection(False)
    assert popup.hide_from_capture is False
    assert seen == [(77, True), (77, False)]
