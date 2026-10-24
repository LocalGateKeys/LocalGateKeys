"""Audit 2026-10-18 M5: a page's passkey request never brings up the unlock window while the vault is locked."""
from __future__ import annotations

from test_passkey_broker import _broker, _create_options, _get_options, _register

import localvault.passkey_broker as passkey_module


class _Port:
    def __init__(self):
        self.notices: list[tuple[str, str, str]] = []

    def notify(self, kind, title, message):
        self.notices.append((kind, title, message))


def _locked(tmp_path, *, with_passkey: bool = True):
    broker = _broker(tmp_path)
    if with_passkey:
        _register(broker)
        broker.prompts.clear()
        broker.reauths.clear()
    unlocks = []

    def ensure_unlocked():  # the real host raises the window / unlock popup (and may auto-start Hello)
        unlocks.append(1)
        return True
    broker.ensure_unlocked = ensure_unlocked
    port = _Port()
    broker.ui = port
    broker.session.lock()
    return broker, unlocks, port


def test_locked_get_falls_back_without_unlock_or_prompt(tmp_path) -> None:
    broker, unlocks, port = _locked(tmp_path)
    assert broker.request("passkey_get_browser", options=_get_options()) == {"ok": False, "error": "fallback"}
    assert unlocks == [] and broker.prompts == [] and broker.reauths == []
    assert port.notices == [("info", "Passkeys", passkey_module.LOCKED_NOTICE)]


def test_locked_create_falls_back_without_unlock_or_prompt(tmp_path) -> None:
    broker, unlocks, port = _locked(tmp_path, with_passkey=False)
    assert broker.request("passkey_create_browser", options=_create_options()) == {"ok": False, "error": "fallback"}
    assert unlocks == [] and broker.prompts == [] and broker.reauths == []
    assert len(port.notices) == 1


def test_locked_notice_is_throttled_per_origin_and_no_cooldown_is_started(tmp_path) -> None:
    broker, unlocks, port = _locked(tmp_path)
    for _ in range(3):
        assert broker.request("passkey_get_browser", options=_get_options())["error"] == "fallback"
    assert len(port.notices) == 1 and unlocks == []
    # No prompt was shown, so the origin is not cooling down: right after an unlock it is served normally.
    assert broker._passkey_cooldowns() == {}


def test_locked_request_does_not_steal_focus(tmp_path) -> None:
    broker, _unlocks, _port = _locked(tmp_path)
    restored = []
    broker._passkey_foreground = lambda: 4242
    broker._passkey_return_focus = restored.append
    broker.request("passkey_get_browser", options=_get_options())
    assert restored == []


def test_unlocked_get_is_unchanged(tmp_path) -> None:
    broker = _broker(tmp_path)
    _register(broker)
    broker.prompts.clear()
    broker.answer = ("approve", broker.session.items.passkey_records("example.test")[0]["id"])
    port = _Port()
    broker.ui = port
    reply = broker.request("passkey_get_browser", options=_get_options())
    assert reply["ok"] is True and broker.prompts[0]["mode"] == "get"
    assert port.notices == []
