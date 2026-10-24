"""Stage 4b: Windows Hello and camera verification services (Windows parts faked)."""
from __future__ import annotations

from types import SimpleNamespace

import pytest

from localvault.api.result import ApiError
from localvault.app.controller import WebController
from localvault.app.secrets import SecretService
from localvault.app.unlock_methods import FaceService, HelloService
from localvault.face_unlock import FaceCancelled, FaceError
from localvault.hello_unlock import HelloError
from localvault.profiles import ProfileManager
from localvault.secret_text import SecretText
from localvault.settings import AppSettings
from localvault.vault import unlock_vault
from localvault.windows_hello import HelloCancelled

KDF = {"time_cost": 1, "memory_cost_kib": 8192, "parallelism": 1, "hash_len": 32}
MASTER = "correct horse battery"


class Bus:
    def __init__(self):
        self.events = []

    def emit(self, name, detail):
        self.events.append((name, detail))


class Sched:
    def call_later(self, delay, fn):
        return fn

    def cancel(self, handle):
        pass


class Port:
    def __init__(self):
        self.asked, self.answers, self.passwords = [], [], []

    def confirm(self, title, message):
        self.asked.append(title)
        return self.answers.pop(0) if self.answers else True

    def ask_password(self, title, message):
        self.asked.append(title)
        answer = self.passwords.pop(0) if self.passwords else None
        return None if answer is None else SecretText.from_str(answer)

    def notify(self, kind, title, message):
        self.asked.append(title)


@pytest.fixture
def env(tmp_path, monkeypatch):
    state = {"required": False, "cleared": [], "hello_env": True, "face_env": True, "failures": []}
    monkeypatch.setattr("localvault.app.controller.clear_master_unlock_requirement",
                        lambda pid: state["cleared"].append(pid))
    monkeypatch.setattr("localvault.app.controller.master_unlock_required", lambda pid: state["required"])
    monkeypatch.setattr("localvault.app.unlock_methods.master_unlock_required", lambda pid: state["required"])
    monkeypatch.setattr("localvault.app.unlock_methods.hello_supported", lambda: True)
    monkeypatch.setattr("localvault.app.unlock_methods.face_supported", lambda: True)
    monkeypatch.setattr("localvault.hello_unlock.has_envelope", lambda path, pid: state["hello_env"])
    monkeypatch.setattr("localvault.face_unlock.has_envelope", lambda path, pid: state["face_env"])
    monkeypatch.setattr("localvault.face_unlock.record_failure", lambda rid, **k: state["failures"].append(rid))
    monkeypatch.setattr(AppSettings, "save", lambda self, path=None: None)
    profiles = ProfileManager(tmp_path / "data")
    profiles.ensure_profile()
    bus = Bus()
    controller = WebController(profiles=profiles, settings=AppSettings(idle_source="vault"), bus=bus,
                               scheduler=Sched(), create_kwargs={"kdf_overrides": KDF})
    controller.create(MASTER, MASTER)
    port = Port()
    hello = HelloService(controller, port, hwnd=lambda: 1234, timeout=5)
    capture = SimpleNamespace(result=True, error=None, calls=[])

    class FakeCapture:
        def __init__(self, mode, **kw):
            capture.calls.append((mode, kw))
            self.mode = mode

        def run(self):
            if capture.error:
                raise capture.error
            return capture.result

        def cancel(self):
            pass

    face = FaceService(controller, port, bus, capture_factory=FakeCapture, engine_factory=lambda: None)
    return SimpleNamespace(controller=controller, port=port, hello=hello, face=face, state=state,
                           capture=capture, bus=bus, path=profiles.vault_path(profiles.active_profile().id))


def _fake_hello_unlock(env, monkeypatch, error=None):
    def unlock(path, pid, hwnd, cancelled, **kw):
        if error:
            raise error
        assert hwnd == 1234
        return unlock_vault(path, MASTER)

    monkeypatch.setattr("localvault.hello_unlock.unlock_with_hello", unlock)


def test_state_offers_hello_and_camera_only_without_the_marker(env):
    env.controller.lock()
    state = env.controller.state()
    assert state["hello"] is True and state["camera"] is True
    env.state["required"] = True
    env.controller._extras_cache = None
    state = env.controller.state()
    assert state["hello"] is False and state["camera"] is False


def test_hello_unlock_keeps_the_marker(env, monkeypatch):
    _fake_hello_unlock(env, monkeypatch)
    env.controller.lock()
    env.state["cleared"].clear()
    env.hello.unlock()
    assert env.controller.is_unlocked() and env.state["cleared"] == []


def test_hello_unlock_refused_under_the_marker(env, monkeypatch):
    _fake_hello_unlock(env, monkeypatch)
    env.controller.lock()
    env.state["required"] = True
    with pytest.raises(ApiError) as refused:
        env.hello.unlock()
    assert refused.value.code == "master_required" and not env.controller.is_unlocked()


def test_hello_unlock_errors_read_like_the_classic_window(env, monkeypatch):
    env.controller.lock()
    _fake_hello_unlock(env, monkeypatch, HelloCancelled("x"))
    with pytest.raises(ApiError) as cancelled:
        env.hello.unlock()
    assert cancelled.value.message == "Unlock cancelled. Try again or use your master password."
    _fake_hello_unlock(env, monkeypatch, HelloError("Setup is damaged."))
    with pytest.raises(ApiError) as failed:
        env.hello.unlock()
    assert failed.value.message == "Setup is damaged. You can retry or use your master password."


def test_password_unlock_still_clears_the_marker(env):
    env.controller.lock()
    env.state["cleared"].clear()
    env.controller.unlock(MASTER)
    assert env.state["cleared"]


def test_hello_enable_reauths_confirms_and_commits(env, monkeypatch):
    calls = []
    monkeypatch.setattr("localvault.hello_unlock.prepare_enrollment",
                        lambda pid, ctx, hwnd, cancelled, **kw: calls.append(("prepare", hwnd)) or SimpleNamespace(discard=lambda: None))
    monkeypatch.setattr("localvault.hello_unlock.commit_enrollment", lambda session, prepared: calls.append(("commit",)))
    env.port.passwords = [MASTER]
    result = env.hello.enable()
    assert env.port.asked == ["Authorize Windows Hello setup", "Enable local Windows Hello?"]
    assert calls == [("prepare", 1234), ("commit",)]
    assert result["message"].startswith("Windows Hello is enabled.")


def test_hello_enable_without_a_window(env, monkeypatch):
    env.hello._hwnd = lambda: None
    env.port.passwords = [MASTER]
    with pytest.raises(ApiError) as refused:
        env.hello.enable()
    assert refused.value.message == "A visible LocalGateKeys window is required for Windows Hello."


def test_hello_disable(env, monkeypatch):
    removed = []
    monkeypatch.setattr("localvault.hello_unlock.disable_enrollment", lambda session, **kw: removed.append(1))
    env.port.passwords = [MASTER]
    assert env.hello.disable()["message"] == "Removed for this profile. Your Windows Hello enrollment was not changed."
    assert removed and env.port.asked == ["Remove Windows Hello from this profile"]


def test_reauth_uses_hello_then_falls_back_to_password(env, monkeypatch):
    secrets = SecretService(env.controller, env.port)
    env.controller.hello_reauth = env.hello.reauthenticate
    _fake_hello_unlock(env, monkeypatch)
    lease = env.controller.guard.lease()
    secrets.reauthenticate("Confirm to reveal", lease, allow_hello=True)
    assert env.port.asked == []
    env.controller.routine_reauth = (None, 0.0)
    _fake_hello_unlock(env, monkeypatch, HelloCancelled("x"))
    env.port.passwords = [MASTER]
    secrets.reauthenticate("Confirm to reveal", lease, allow_hello=True)
    assert env.port.asked == ["Confirm to reveal"]


def test_reauth_skips_hello_under_the_marker(env, monkeypatch):
    secrets = SecretService(env.controller, env.port)
    env.controller.hello_reauth = env.hello.reauthenticate
    _fake_hello_unlock(env, monkeypatch)
    env.state["required"] = True
    env.port.passwords = [MASTER]
    secrets.reauthenticate("Confirm to reveal", env.controller.guard.lease(), allow_hello=True)
    assert env.port.asked == ["Confirm to reveal"]


def test_offer_shows_once(env, monkeypatch):
    env.state["hello_env"] = False
    assert env.hello.offer()["offer"] is True
    env.hello.answer_offer(False)
    assert env.controller.settings.hello_offer_answered is True
    assert env.hello.offer()["offer"] is False


def _material(env, monkeypatch):
    discarded = []
    material = SimpleNamespace(templates=[[0.1] * 128], threshold=0.45, record_id="r1",
                               discard=lambda: discarded.append(1))
    monkeypatch.setattr("localvault.face_unlock.load_face_material", lambda path, pid, **kw: material)
    monkeypatch.setattr("localvault.face_unlock.unlock_verified_face",
                        lambda m, cancelled=None, **kw: unlock_vault(env.path, MASTER))
    return discarded


def test_face_unlock_success_keeps_marker_and_discards(env, monkeypatch):
    discarded = _material(env, monkeypatch)
    env.controller.lock()
    env.state["cleared"].clear()
    env.face.unlock()
    assert env.controller.is_unlocked() and env.state["cleared"] == [] and discarded
    assert env.capture.calls[0][0] == "verify"


def test_face_mismatch_records_a_failure_but_cancel_does_not(env, monkeypatch):
    discarded = _material(env, monkeypatch)
    env.controller.lock()
    env.capture.error = FaceCancelled("Camera verification was cancelled. Your vault is still locked.")
    with pytest.raises(ApiError):
        env.face.unlock()
    assert env.state["failures"] == []
    env.capture.error = FaceError("Face not recognised in time.")
    with pytest.raises(ApiError) as failed:
        env.face.unlock()
    assert env.state["failures"] == ["r1"] and len(discarded) == 2
    assert failed.value.message == "Face not recognised in time."


def test_face_enable_and_disable(env, monkeypatch):
    calls = []
    env.capture.result = [[0.2] * 128 for _ in range(8)]
    monkeypatch.setattr("localvault.face_unlock.prepare_enrollment", lambda pid, ctx, samples, **kw: calls.append(len(samples)) or "prepared")
    monkeypatch.setattr("localvault.face_unlock.commit_enrollment", lambda session, prepared: calls.append(prepared))
    monkeypatch.setattr("localvault.face_unlock.disable_enrollment", lambda session, password=None: calls.append("off"))
    env.port.passwords = [MASTER]
    assert env.face.enable()["message"] == "Camera verification enabled. Lock the vault and test it before relying on it."
    assert env.port.asked == ["Authorize camera verification setup", "Enable ordinary-webcam verification?"]
    assert calls == [8, "prepared"]
    env.port.asked.clear()
    env.port.passwords = [MASTER]
    env.controller.routine_reauth = (None, 0.0)
    assert env.face.disable()["message"] == "Camera verification removed."
    assert env.port.asked == ["Remove camera verification", "Remove camera verification?"] and calls[-1] == "off"


def test_only_one_camera_at_a_time(env, monkeypatch):
    env.face._busy.acquire()
    with pytest.raises(ApiError) as busy:
        env.face.unlock()
    assert busy.value.code == "busy"


def test_camera_unavailable_is_not_a_failed_match(env, monkeypatch):
    from localvault.face_unlock import FaceUnavailable
    _material(env, monkeypatch)
    env.controller.lock()
    env.capture.error = FaceUnavailable("No usable webcam was found.")
    with pytest.raises(ApiError):
        env.face.unlock()
    assert env.state["failures"] == []


def test_lock_before_the_camera_starts_still_cancels(env):
    cancelled = []

    class Slow:
        def __init__(self, mode, **kw):
            env.face.cancel()  # a lock lands while the capture is being built

        def cancel(self):
            cancelled.append(1)

        def run(self):
            return [] if not cancelled else (_ for _ in ()).throw(FaceCancelled("x"))

    env.face._capture_factory = Slow
    with pytest.raises(FaceCancelled):
        env.face._capture("verify")
    assert cancelled


def test_hung_hello_prompt_keeps_later_prompts_out(env, monkeypatch):
    import threading
    release = threading.Event()

    def hang(path, pid, hwnd, cancelled, **kw):
        release.wait(5)
        raise HelloCancelled("x")

    monkeypatch.setattr("localvault.hello_unlock.unlock_with_hello", hang)
    env.hello._timeout = 0.2
    env.controller.lock()
    with pytest.raises(ApiError) as first:
        env.hello.unlock()
    assert first.value.code == "timeout"
    with pytest.raises(ApiError) as second:
        env.hello.unlock()
    assert second.value.code == "busy"
    release.set()


def test_marker_written_elsewhere_refreshes_the_offer(env, tmp_path, monkeypatch):
    marker = tmp_path / "marker"
    monkeypatch.setattr("localvault.app.controller._marker_stamp", lambda pid: marker.stat().st_mtime_ns if marker.exists() else None)
    env.controller.lock()
    assert env.controller.state()["hello"] is True
    env.state["required"] = True
    marker.write_text("x")
    assert env.controller.state()["hello"] is False
