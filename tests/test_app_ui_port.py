"""Stage 0: the UiPort seam between the broker logic and whichever UI shows prompts."""
from __future__ import annotations

import json
from types import SimpleNamespace

import pytest

from localvault.app.ui_port import UiPortHost, safe_confirm
from localvault.browser_broker import BrowserBroker
from broker_host import BrokerHostBase as RuntimeActions
from localvault.session_guard import SessionGuard
from localvault.settings import AppSettings
from localvault.vault import create_vault

KDF = {"time_cost": 1, "memory_cost_kib": 8192, "parallelism": 1, "hash_len": 32}
ORIGIN = "https://example.test"


class FakePort:
    def __init__(self, answer: bool = True, raises: BaseException | None = None) -> None:
        self.answer, self.raises, self.asked = answer, raises, []

    def confirm(self, title, message):
        self.asked.append(title)
        if self.raises:
            raise self.raises
        return self.answer

    def notify(self, kind, title, message):
        self.asked.append(f"{kind}:{title}")

    def ask_passkey(self, mode, **kwargs):
        return ("cancel", None)

    def show_upgrade(self, *, limit, message, on_enter):
        self.asked.append(f"upgrade:{limit}")


def test_safe_confirm_denies_on_timeout():
    assert safe_confirm(FakePort(raises=TimeoutError()), "T", "M") is False


def test_safe_confirm_passes_answer_through():
    assert safe_confirm(FakePort(answer=True), "T", "M") is True
    assert safe_confirm(FakePort(answer=False), "T", "M") is False


def test_host_uses_assigned_port():
    host, port = UiPortHost(), FakePort()
    host.ui = port
    assert host.ui is port


class _Broker(RuntimeActions, BrowserBroker):
    def __init__(self, session) -> None:
        self.session = session
        self.guard = SessionGuard("redacted-profile")
        self.guard.open(3600)
        self.root = None
        self.settings = AppSettings(auto_lock_seconds=0)
        self.active_profile = SimpleNamespace(id="redacted-profile", name="Redacted", color="#123456")
        self._remote_busy = False
        self.last_extension_seen = 0.0
        self.last_extension_version = ""
        self.last_secret_use = 0.0
        self._closing = False

    def ensure_unlocked(self):
        return self._session_available()

    def run_on_ui(self, function, timeout=0):
        return function()

    def refresh_entries(self):
        return None

    def _touch_secret(self):
        self.last_secret_use = 1.0

    def _validate_remote_text(self, value, *args):
        from localvault.web.host import WebAgentHost
        return WebAgentHost._validate_remote_text(value, *args)


@pytest.fixture
def vault(tmp_path):
    return create_vault(tmp_path / "port.json", "redacted-master", kdf_overrides=KDF)


def test_broker_save_prompt_goes_through_port(vault, monkeypatch):
    monkeypatch.setattr("broker_host.confirm", lambda *a: pytest.fail("shim dialog used instead of the port"))
    broker = _Broker(vault)
    port = FakePort(answer=False)
    broker.ui = port
    base = {"protocol": 2, "extension_version": "0.3.3", "origin": ORIGIN,
            "context": json.dumps([17, "document-redacted", ORIGIN, "operation-redacted"])}
    nonce = broker.dispatch_remote({"action": "begin_gesture_browser", "user_gesture": True, **base})
    reply = broker.dispatch_remote({
        "action": "save_browser", **base,
        "username": "bob", "password": "pw-new", "gesture_nonce": nonce["gesture_nonce"],
    })
    assert port.asked == ["Save new login?"]
    assert reply.get("ok") is False
    assert vault.find_web(ORIGIN) == []


def test_safe_confirm_logs_a_failed_prompt(monkeypatch):
    logged = []
    monkeypatch.setattr("localvault.error_log.log_exception", lambda where, exc: logged.append((where, type(exc))))
    assert safe_confirm(FakePort(raises=RuntimeError("dialog gone")), "T", "M") is False
    assert logged == [("approval", RuntimeError)]
