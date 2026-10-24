"""Stage 4a: changing the master password from the WebView UI."""
from __future__ import annotations

import pytest

from localvault.api.result import ApiError
from localvault.app.controller import WebController
from localvault.app.master import MasterService
from localvault.profiles import ProfileManager
from localvault.settings import AppSettings

KDF = {"time_cost": 1, "memory_cost_kib": 8192, "parallelism": 1, "hash_len": 32}
MASTER = "correct horse battery"
NEW = "a brand new master pw"


class Bus:
    def emit(self, name, detail):
        pass


class Sched:
    def call_later(self, delay, fn):
        return fn

    def cancel(self, handle):
        pass


class Port:
    def __init__(self):
        self.asked, self.answers = [], []

    def confirm(self, title, message):
        self.asked.append(title)
        return self.answers.pop(0) if self.answers else True


class FakeClipboard:
    timeout_seconds = 30

    def __init__(self):
        self.value = "secret"

    def clear(self):
        self.value = None


@pytest.fixture
def env(tmp_path, monkeypatch):
    marked = []
    monkeypatch.setattr("localvault.app.controller.clear_master_unlock_requirement", lambda _pid: None)
    monkeypatch.setattr("localvault.app.master.require_master_unlock", lambda pid: marked.append(pid) or True)
    profiles = ProfileManager(tmp_path / "data")
    profiles.ensure_profile()
    controller = WebController(profiles=profiles, settings=AppSettings(idle_source="vault"), bus=Bus(),
                               scheduler=Sched(), create_kwargs={"kdf_overrides": KDF})
    controller.create(MASTER, MASTER)
    controller.clipboard = FakeClipboard()
    port = Port()
    return MasterService(controller, port), controller, port, marked


def test_mismatch_is_refused_before_confirm(env):
    service, controller, port, _ = env
    with pytest.raises(ApiError) as refused:
        service.change(MASTER, NEW, NEW + "x", None)
    assert refused.value.message == "The new passwords did not match." and port.asked == []
    assert controller.is_unlocked()


def test_wrong_current_password_keeps_the_vault(env):
    service, controller, _port, marked = env
    with pytest.raises(ApiError) as refused:
        service.change("not the password", NEW, NEW, None)
    assert refused.value.code == "invalid" and controller.is_unlocked() and marked == []


def test_too_short_is_the_vault_message(env):
    service, controller, _port, _ = env
    with pytest.raises(ApiError) as refused:
        service.change(MASTER, "short", "short", None)
    assert "12" in refused.value.message and controller.is_unlocked()


def test_declined_confirm_changes_nothing(env):
    service, controller, port, _ = env
    port.answers = [False]
    with pytest.raises(ApiError) as declined:
        service.change(MASTER, NEW, NEW, None)
    assert declined.value.code == "cancelled" and port.asked == ["Change master password?"]
    controller.lock()
    controller.unlock(MASTER)


def test_success_locks_marks_and_unlocks_with_new(env):
    service, controller, _port, marked = env
    profile_id = controller.profiles.active_profile().id
    result = service.change(MASTER, NEW, NEW, None)
    assert not controller.is_unlocked() and marked == [profile_id]
    assert controller.clipboard.value is None
    assert controller.state()["status"] == ("Master password changed. Camera verification and Windows Hello must be "
                                            "set up again; unlock with the new password.")
    assert result["notes"] == []
    controller.unlock(NEW)
    assert controller.is_unlocked()


def test_needs_phrase_reflects_enrollment(env):
    service, _controller, _port, _ = env
    assert service.info() == {"needs_phrase": False}


class _Ops:
    def minimize(self):
        pass

    def toggle_maximize(self):
        pass

    def close(self):
        pass


def test_change_wipes_all_three_after_declined_confirm(env, monkeypatch):
    from localvault.api.bridge import Api
    from localvault.secret_text import SecretText

    _service, controller, port, _ = env
    api = Api(controller, port, _Ops())
    created, alive_at_confirm = [], []
    original_from_str = SecretText.from_str.__func__

    def from_str(cls, value):
        secret = original_from_str(cls, value)
        created.append(secret)
        return secret

    def confirm(title, message):
        # The service holds SecretText values while the prompt is open; none is wiped yet.
        alive_at_confirm.extend(s.char_count for s in created)
        return False

    monkeypatch.setattr(SecretText, "from_str", classmethod(from_str))
    monkeypatch.setattr(port, "confirm", confirm)
    result = api.master_change(MASTER, NEW, NEW)
    assert result["error"]["code"] == "cancelled"
    assert alive_at_confirm == [len(MASTER), len(NEW), len(NEW)]
    assert len(created) == 3
    for secret in created:
        with pytest.raises(ValueError, match="secret was wiped"):
            _ = secret.buffer
    controller.lock()
    controller.unlock(MASTER)
