"""Audit 2026-10-18 M1: page script reaches only the public bridge calls, through pywebview's real dispatcher."""
from __future__ import annotations

import inspect
from pathlib import Path

import pytest
import webview
import webview.util as util

from localvault.api.bridge import PAGE_CALLS, Api, page_api
from localvault.web import window as web_window

MAIN = Path(web_window.__file__).with_name("main.py")


class FakeApi:
    """Stands in for Api: records every call, including ones on private collaborators."""

    def __init__(self):
        self.calls = []
        self._controller = self

    def lock(self, *args):
        self.calls.append(("lock", args))

    def vault_status(self, *args):
        self.calls.append(("vault_status", args))
        return {"ok": True}

    def some_public(self, *args):
        self.calls.append(("some_public", args))
        return {"ok": True}


class FakeWindow:
    def __init__(self, js_api):
        self._js_api = js_api
        self._functions = {}
        self.evaluated = []
        self.moved = []

    def evaluate_js(self, script):
        self.evaluated.append(script)

    def move(self, x, y):
        self.moved.append((x, y))


class InlineThread:
    """js_bridge_call runs the call on a thread; run it inline so the test sees the result."""

    def __init__(self, target, args=()):
        self._target = target
        self._args = args

    def start(self):
        self._target(*self._args)


@pytest.fixture
def dispatch(monkeypatch):
    monkeypatch.setattr(util, "Thread", InlineThread)
    original = util.js_bridge_call
    names = frozenset({"vault_status", "some_public"})
    yield web_window.guard_js_bridge_call(original, names)


@pytest.mark.parametrize("name", [
    "_controller.lock", "__class__.__init__", "vault_status.__globals__", "some_public.__self__",
    "_controller", "vault_status.__func__", "some_public.__closure__", "lock", "vault_status.", ".vault_status",
    "pywebview_unknown", None, 5,
])
def test_guard_refuses_private_dotted_and_unknown_names(dispatch, name):
    api = FakeApi()
    win = FakeWindow(api)
    dispatch(win, name, [], "1")
    assert api.calls == []
    assert win.evaluated == []


def test_unguarded_pywebview_walks_private_paths(monkeypatch):
    """The finding itself: the stock dispatcher calls api._controller.lock from a page message."""
    monkeypatch.setattr(util, "Thread", InlineThread)
    api = FakeApi()
    win = FakeWindow(api)
    util.js_bridge_call(win, "_controller.lock", [], "1")
    assert api.calls == [("lock", ())]


def test_guard_dispatches_a_public_name(dispatch):
    api = FakeApi()
    win = FakeWindow(api)
    dispatch(win, "vault_status", ["a"], "7")
    assert api.calls == [("vault_status", ("a",))]
    assert len(win.evaluated) == 1 and '["vault_status"]["7"]' in win.evaluated[0]


def test_guard_keeps_pywebview_own_messages(dispatch):
    win = FakeWindow(FakeApi())
    dispatch(win, "pywebviewMoveWindow", [10, 20], "1")
    assert win.moved == [(10, 20)]


def test_install_patches_util_and_loaded_platform_modules(monkeypatch):
    import sys
    import types

    original = util.js_bridge_call
    platform = types.ModuleType("webview.platforms.fake_for_test")
    platform.js_bridge_call = original
    monkeypatch.setitem(sys.modules, "webview.platforms.fake_for_test", platform)
    monkeypatch.setattr(util, "js_bridge_call", original)
    web_window.install_call_guard({"vault_status"})
    try:
        assert util.js_bridge_call is not original
        assert util.js_bridge_call.lgk_original is original
        assert platform.js_bridge_call is util.js_bridge_call
        web_window.install_call_guard({"vault_status"})  # idempotent: wraps the original, not the wrapper
        assert util.js_bridge_call.lgk_original is original
        assert platform.js_bridge_call is util.js_bridge_call
    finally:
        util.js_bridge_call = original


def test_page_calls_match_what_pywebview_listed_for_api():
    public = {name for name, member in vars(Api).items() if callable(member) and not name.startswith("_")}
    assert PAGE_CALLS == public
    assert all("." not in name and not name.startswith("_") for name in PAGE_CALLS)


def test_page_api_exposes_only_the_calls_with_their_params():
    api = FakeApi()
    facade = page_api(api)
    public = {name for name in dir(facade) if not name.startswith("_")}
    assert public == set(PAGE_CALLS)
    assert not hasattr(facade, "__dict__")
    # pywebview's own listing (inject_pywebview.get_functions) sees the same names and Api's params.
    params = inspect.getfullargspec(facade.vault_unlock).args[1:]
    assert params == ["password"]
    assert inspect.getfullargspec(facade.items_list).args[1:] == ["filter_kind", "chip", "query"]


def test_page_api_forwards_to_the_api(monkeypatch):
    seen = []

    class Target:
        def __getattr__(self, name):
            return lambda *args, **kwargs: seen.append((name, args, kwargs)) or {"ok": True}

    facade = page_api(Target())
    assert facade.vault_unlock("pw") == {"ok": True}
    assert seen == [("vault_unlock", ("pw",), {})]


def test_real_dispatch_through_guard_and_facade(monkeypatch):
    monkeypatch.setattr(util, "Thread", InlineThread)
    seen = []

    class Target:
        _controller = FakeApi()

        def __getattr__(self, name):
            return lambda *args: seen.append((name, args)) or {"ok": True}

    target = Target()
    win = FakeWindow(page_api(target))
    guarded = web_window.guard_js_bridge_call(util.js_bridge_call, PAGE_CALLS)
    for name in ("_controller.lock", "vault_state.__globals__", "vault_state.__closure__", "__class__.__init__"):
        guarded(win, name, [], "1")
    assert seen == [] and target._controller.calls == [] and win.evaluated == []
    guarded(win, "vault_state", [], "2")
    assert seen == [("vault_state", ())]
    assert len(win.evaluated) == 1


def test_main_turns_off_pywebview_external_links_and_installs_the_guard():
    source = MAIN.read_text(encoding="utf-8")
    assert 'webview.settings["OPEN_EXTERNAL_LINKS_IN_BROWSER"] = False' in source
    assert "js_api=api" not in source and source.count("js_api=js_api") == 2
    assert "install_call_guard(PAGE_CALLS)" in source
    # The setting and the guard come before webview.start.
    start = source.index("webview.start(")
    assert source.index('webview.settings["OPEN_EXTERNAL_LINKS_IN_BROWSER"] = False') < start
    assert source.index("install_call_guard(PAGE_CALLS)") < start


def test_external_links_setting_is_a_known_pywebview_key():
    assert "OPEN_EXTERNAL_LINKS_IN_BROWSER" in webview.settings


def test_system_open_url_still_opens_web_links(monkeypatch):
    opened = []
    monkeypatch.setattr("localvault.api.bridge.webbrowser.open", lambda url: opened.append(url))

    class Target:
        pass

    target = Target()
    target.system_open_url = lambda url: Api.system_open_url(target, url)
    facade = page_api(target)
    assert facade.system_open_url("https://localgatekeys.app/help")["ok"] is True
    assert facade.system_open_url("javascript:alert(1)")["error"]["code"] == "invalid"
    assert opened == ["https://localgatekeys.app/help"]
