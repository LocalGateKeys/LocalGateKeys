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
