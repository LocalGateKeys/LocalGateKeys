"""Task 5: key file and YubiKey in Settings › Unlocking and on the unlock screen (Windows, no hardware)."""
from __future__ import annotations

import hashlib
import hmac
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from localvault import keyfile, yubikey_hid
from localvault import vault as vault_module
from localvault.api.result import ApiError
from localvault.app import factors as factors_module
from localvault.app.controller import WebController
from localvault.app.factors import FactorService, read_keyfile
from localvault.app.recovery import RecoveryWebService
from localvault.app.secrets import SecretService
from localvault.app.unlock_methods import FaceService, HelloService
from localvault.backup import DEVICE_ONLY_SETTINGS
from localvault.i18n import t
from localvault.profiles import ProfileManager
from localvault.secret_text import SecretText
from localvault.settings import AppSettings
from localvault.vault import vault_factors, vault_identifier

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
        self.asked, self.answers, self.passwords, self.texts, self.toasts = [], [], [], [], []

    def confirm(self, title, message):
        self.asked.append(title)
        self.texts.append(message)
        return self.answers.pop(0) if self.answers else True

    def ask_password(self, title, message):
        self.asked.append(title)
        answer = self.passwords.pop(0) if self.passwords else None
        return None if answer is None else SecretText.from_str(answer)

    def notify(self, kind, title, message):
        self.toasts.append((kind, title, message))


class Dialogs:
    def __init__(self):
        self.opened, self.saved = [], []

    def open_file(self, title, file_types=None):
        return self.opened.pop(0) if self.opened else None

    def save_file(self, title, name):
        return self.saved.pop(0) if self.saved else None


class FakeHid:
    """``yubikey_hid`` without hardware: HMAC-SHA1 in variable-input mode, scripted error codes."""

    def __init__(self, secret=b"yubikey-secret-one"):
        self.secret = secret
        self.calls: list[tuple[int, bytes]] = []
        self.errors: list[str] = []
        self.devices = [yubikey_hid.YubiKeyInfo("hid#1", 1234, (5, 4, 3))]

    def list_devices(self):
        return list(self.devices)

    def challenge_response(self, path, slot, challenge64, *, timeout=15.0, cancel=None):
        self.calls.append((slot, bytes(challenge64)))
        if self.errors:
            raise yubikey_hid.YubiKeyError(self.errors.pop(0))
        return hmac.new(self.secret, challenge64.rstrip(challenge64[-1:]), hashlib.sha1).digest()


@pytest.fixture
def env(tmp_path, monkeypatch):
    vault_module._reset_unlock_throttle_state_for_tests()
    monkeypatch.setattr("localvault.app.controller.clear_master_unlock_requirement", lambda pid: None)
    monkeypatch.setattr("localvault.app.controller.master_unlock_required", lambda pid: False)
    monkeypatch.setattr("localvault.app.unlock_methods.master_unlock_required", lambda pid: False)
    monkeypatch.setattr(AppSettings, "save", lambda self, path=None: None)
    hid = FakeHid()
    monkeypatch.setattr(yubikey_hid, "list_devices", hid.list_devices)
    monkeypatch.setattr(yubikey_hid, "challenge_response", hid.challenge_response)
    profiles = ProfileManager(tmp_path / "data")
    profiles.ensure_profile()
    bus = Bus()
    controller = WebController(profiles=profiles, settings=AppSettings(idle_source="vault"), bus=bus,
                               scheduler=Sched(), create_kwargs={"kdf_overrides": KDF})
    controller.create(MASTER, MASTER)
    port, dialogs = Port(), Dialogs()
    service = FactorService(controller, port, dialogs, bus=bus, sleep=lambda seconds: None)
    keys = tmp_path / "keys"
    keys.mkdir()
    key_path = keys / "vault.keyx"
    key_path.write_bytes(keyfile.new_keepass_xml_v2())
    yield SimpleNamespace(controller=controller, port=port, dialogs=dialogs, service=service, hid=hid, bus=bus,
                          path=profiles.vault_path(profiles.active_profile().id), key_path=key_path, keys=keys)
    vault_module._reset_unlock_throttle_state_for_tests()


def _add_keyfile(env):
    env.port.passwords.append(MASTER)
    env.dialogs.opened.append(str(env.key_path))
    return env.service.add_keyfile()


def _kinds(env):
    return [spec.kind for spec in vault_factors(env.path)]


def _vault_id(env):
    return vault_identifier(env.path)


def test_add_keyfile_requires_reauth_and_confirm(env):
    before = env.path.read_bytes()
    # Cancelled at the confirmation: nothing changes.
    env.port.passwords.append(MASTER)
    env.port.answers.append(False)
    env.dialogs.opened.append(str(env.key_path))
    with pytest.raises(ApiError) as caught:
        env.service.add_keyfile()
    assert caught.value.code == "cancelled" and env.path.read_bytes() == before
    # The wrong master password: not authorised, nothing changes.
    env.port.passwords.append("not the master password")
    env.dialogs.opened.append(str(env.key_path))
    with pytest.raises(ApiError) as caught:
        env.service.add_keyfile()
    assert caught.value.code == "not_authorized" and _kinds(env) == []
    env.port.asked.clear()
    env.port.texts.clear()
    result = _add_keyfile(env)
    assert env.port.asked == [t("factors.addKeyFileTitle"), t("factors.addKeyFileTitle")]  # password, then confirm
    notice = env.port.texts[0]
    assert "recovery phrase still opens the vault" in notice and "rolling backups" in notice
    assert "change the master password" in notice
    assert _kinds(env) == ["keyfile"] and "vault.keyx" in result["message"]
    assert json.loads(env.path.read_bytes())["version"] == 4
    assert env.controller.settings.unlock_keyfile_paths == {_vault_id(env): str(env.key_path)}
    assert env.service.status()["factors"] == [{"kind": "keyfile", "slot": None}]


def test_create_keyfile_writes_xml_v2_with_user_acl(env, monkeypatch):
    restricted = []

    def restrict(path):
        restricted.append((Path(path), Path(path).stat().st_size))  # still empty when the ACL is applied
        return True

    monkeypatch.setattr(factors_module, "_restrict_to_current_user", restrict)
    target = env.keys / "new.keyx"
    env.dialogs.saved.append(str(target))
    env.port.passwords.append(MASTER)
    result = env.service.create_keyfile()
    assert restricted == [(target, 0)]
    data = target.read_bytes()
    assert b'<Version>2.0</Version>' in data and data.lstrip().startswith(b"<?xml")
    assert len(keyfile.key_from_bytes(data)) == 32
    assert _kinds(env) == ["keyfile"] and "new.keyx" in result["message"]
    # The vault opens with the created file.
    env.controller.lock()
    env.controller.settings.unlock_keyfile_paths = {}
    env.controller.unlock(MASTER, keyfile_path=str(target))
    assert env.controller.is_unlocked()


def test_create_keyfile_refuses_app_data_existing_files_and_failed_acl(env, monkeypatch):
    from localvault.config import data_dir

    monkeypatch.setattr(factors_module, "_restrict_to_current_user", lambda path: True)
    with pytest.raises(ApiError) as caught:
        env.service.create_keyfile(str(data_dir() / "inside.keyx"))
    assert caught.value.code == "keyfile_location" and not (data_dir() / "inside.keyx").exists()
    existing = env.keys / "existing.keyx"
    existing.write_bytes(b"someone else's key file")
    with pytest.raises(ApiError) as caught:
        env.service.create_keyfile(str(existing))
    assert caught.value.code == "keyfile_exists" and existing.read_bytes() == b"someone else's key file"
    monkeypatch.setattr(factors_module, "_restrict_to_current_user", lambda path: False)
    with pytest.raises(ApiError) as caught:
        env.service.create_keyfile(str(env.keys / "open.keyx"))
    assert caught.value.code == "keyfile_unwritable" and not (env.keys / "open.keyx").exists()
    # A cancelled add leaves no unused key file behind.
    monkeypatch.setattr(factors_module, "_restrict_to_current_user", lambda path: True)
    env.port.passwords.append(MASTER)
    env.port.answers.append(False)
    with pytest.raises(ApiError):
        env.service.create_keyfile(str(env.keys / "unused.keyx"))
    assert not (env.keys / "unused.keyx").exists() and _kinds(env) == []


def test_add_yubikey_checks_two_touches_match(env, monkeypatch):
    env.port.passwords.append(MASTER)
    result = env.service.add_yubikey(2)
    assert _kinds(env) == ["yubikey-hmac"] and vault_factors(env.path)[0].slot == 2
    assert "slot 2" in result["message"]
    assert len(env.hid.calls) == 2 and env.hid.calls[0] == env.hid.calls[1]  # one challenge, two touches
    assert any(name == "factors.touch_again" for name, _detail in env.bus.events)
    assert ("factors.touch", {"waiting": True, "slot": 2}) in env.bus.events
    assert env.port.toasts == []  # the Unlocking page shows its own prompt: no toast
    # A later password check with the held responder has no prompt on screen: a toast then.
    env.port.passwords.append(MASTER)
    SecretService(env.controller, env.port).reauthenticate("Reveal", env.controller.guard.lease())
    assert ("info", t("factors.touchTitle"), t("factors.touchText")) in env.port.toasts
    # Two touches that disagree (a different key the second time): nothing is added.
    env.controller.session.remove_factor(MASTER, "yubikey-hmac")
    env.port.passwords.append(MASTER)
    secrets = iter([b"key-one", b"key-two"])
    real = env.hid.challenge_response

    def swapped(path, slot, challenge64, **kwargs):
        env.hid.secret = next(secrets)
        return real(path, slot, challenge64, **kwargs)

    monkeypatch.setattr(yubikey_hid, "challenge_response", swapped)
    before = env.path.read_bytes()
    with pytest.raises(ApiError) as caught:
        env.service.add_yubikey(1)
    assert caught.value.message == t("factors.yubikeyTouchesDiffer") and env.path.read_bytes() == before


def test_add_second_yubikey_must_match_response(env):
    env.port.passwords.append(MASTER)
    env.service.add_yubikey(2)
    before = env.path.read_bytes()
    with pytest.raises(ApiError) as caught:
        env.service.add_yubikey(2)  # one YubiKey factor per vault; a backup key is only checked
    assert caught.value.code == "exists" and env.path.read_bytes() == before
    env.hid.secret = b"programmed-differently"
    with pytest.raises(ApiError) as caught:
        env.service.check_backup_yubikey()
    assert caught.value.code == "factor_mismatch" and caught.value.message == t("factors.backupYubikeyDiffers")
    assert env.path.read_bytes() == before
    env.hid.secret = b"yubikey-secret-one"  # a backup key programmed with the same secret
    result = env.service.check_backup_yubikey()
    assert result["message"] == t("factors.backupYubikeyMatches") and env.path.read_bytes() == before
    assert env.port.asked.count(t("factors.addYubikeyTitle")) == 2  # password + confirm of the first add only


def test_remove_factor(env):
    _add_keyfile(env)
    env.port.passwords.append(MASTER)
    result = env.service.remove("keyfile")
    assert result["message"] == t("factors.keyFileRemoved")
    assert _kinds(env) == [] and json.loads(env.path.read_bytes())["version"] == 3
    assert env.controller.settings.unlock_keyfile_paths == {}
    with pytest.raises(ApiError) as caught:
        env.service.remove("keyfile")
    assert caught.value.code == "invalid"
    with pytest.raises(ApiError):
        env.service.remove("password")


def test_always_ask_hides_shortcuts(env, monkeypatch):
    port = env.port
    hello = HelloService(env.controller, port, hwnd=lambda: 1, timeout=5)
    monkeypatch.setattr("localvault.app.unlock_methods.hello_supported", lambda: True)
    env.controller.offers["camera"] = lambda: True
    env.controller.offers["security_key"] = lambda: True
    removed = []
    state = {"hello": True, "fido": True, "face": True}
    monkeypatch.setattr("localvault.hello_unlock.has_envelope", lambda path, pid: state["hello"])
    monkeypatch.setattr("localvault.fido_unlock.has_envelope", lambda path, pid: state["fido"])
    monkeypatch.setattr("localvault.face_unlock.has_envelope", lambda path, pid: state["face"])
    monkeypatch.setattr("localvault.face_unlock.enrollment_present", lambda session: state["face"])
    monkeypatch.setattr("localvault.face_unlock.rotation_on_disable", lambda session: True)

    def disable(name, key):
        def run(session, *args, **kwargs):
            removed.append((name, args))
            state[key] = False
        return run

    monkeypatch.setattr("localvault.hello_unlock.disable_enrollment", disable("hello", "hello"))
    monkeypatch.setattr("localvault.fido_unlock.disable_enrollment", disable("fido", "fido"))
    monkeypatch.setattr("localvault.face_unlock.disable_enrollment", disable("face", "face"))
    with pytest.raises(ApiError) as caught:
        env.service.set_always_ask(True)  # no factor yet
    assert caught.value.code == "no_factors" and not env.controller.settings.unlock_factors_always_ask
    _add_keyfile(env)
    env.controller.lock()
    assert env.controller.state()["hello"] is True  # offered before "Always ask"
    env.controller.unlock(MASTER)
    port.passwords.append(MASTER)
    result = env.service.set_always_ask(True)
    assert result["always_ask"] is True and env.controller.settings.unlock_factors_always_ask is True
    # The sidecars are deleted, not just hidden; the camera's removal rotates with the master password.
    assert [name for name, _args in removed] == ["hello", "fido", "face"]
    assert isinstance(removed[2][1][0], SecretText)
    assert t("factors.alwaysAskConfirm") in port.texts
    env.controller.lock()
    state.update(hello=True, fido=True, face=True)  # even if a sidecar were back, nothing is offered
    env.controller._extras_cache = None
    locked = env.controller.state()
    assert (locked["hello"], locked["camera"], locked["security_key"]) == (False, False, False)
    env.controller.unlock(MASTER)
    with pytest.raises(ApiError) as caught:
        hello.enable()
    assert caught.value.code == "always_ask"
    assert hello.offer() == {"offer": False}
    # On an unlock with "Always ask" on, a sidecar that is still there is removed (and said).
    assert ("notice", {"kind": "info", "title": t("factors.alwaysAskTitle"),
                       "message": t("factors.shortcutsRemovedOnUnlock")}) in env.bus.events
    env.service.set_always_ask(False)
    assert env.controller.settings.unlock_factors_always_ask is False


def test_unlock_uses_remembered_keyfile(env):
    _add_keyfile(env)
    env.controller.lock()
    env.controller.unlock(MASTER)  # the remembered path
    assert env.controller.is_unlocked()
    assert env.controller.session.held_factor_secrets().keyfile is not None
    env.controller.lock()
    state = env.controller.state()
    assert state["factors"] == [{"kind": "keyfile", "slot": None}]
    assert state["keyfile_name"] == "vault.keyx" and state["keyfile_remember"] is True
    assert str(env.key_path) not in json.dumps(state)  # only the name reaches the page
    env.controller.settings.unlock_keyfile_paths = {}
    with pytest.raises(ApiError) as caught:
        env.controller.unlock(MASTER)
    assert caught.value.code == "factor_required"
    env.controller.unlock(MASTER, keyfile_path=str(env.key_path))  # picked: remembered again
    assert env.controller.settings.unlock_keyfile_paths == {_vault_id(env): str(env.key_path)}


def test_dont_remember_clears_path(env):
    _add_keyfile(env)
    status = env.service.set_remember(False)
    assert status["remember"] is False and status["keyfile_name"] is None
    assert env.controller.settings.unlock_keyfile_paths == {_vault_id(env): ""}
    env.controller.lock()
    with pytest.raises(ApiError) as caught:
        env.controller.unlock(MASTER)
    assert caught.value.code == "factor_required"
    env.controller.unlock(MASTER, keyfile_path=str(env.key_path))
    assert env.controller.settings.unlock_keyfile_paths == {_vault_id(env): ""}  # still not remembered
    status = env.service.set_remember(True)  # remembers the key file this unlock used
    assert status["remember"] is True and status["keyfile_name"] == "vault.keyx"
    assert env.controller.settings.unlock_keyfile_paths == {_vault_id(env): str(env.key_path)}


@pytest.mark.parametrize(("errors", "code", "message"), [
    (["removed"], "yubikey_removed", "Touch your YubiKey again."),
    (["touch_timeout"], "yubikey_touch_timeout", "No touch detected. Touch your YubiKey when it blinks."),
    (["slot_not_configured"], "yubikey_slot_not_configured", None),
    (["cancelled"], "cancelled", None),
    (["busy", "busy"], "yubikey_busy", None),
    (["not_found"], "yubikey_not_found", None),
])
def test_unlock_error_messages_per_code(env, errors, code, message):
    env.port.passwords.append(MASTER)
    env.service.add_yubikey(2)
    env.controller.lock()
    env.hid.errors = list(errors)
    for _attempt in range(vault_module.THROTTLE_FREE_ATTEMPTS + 2):
        env.hid.errors = list(errors)
        with pytest.raises(ApiError) as caught:
            env.controller.unlock(MASTER)
        assert caught.value.code == code
    if message:
        assert caught.value.message == message
    if code == "yubikey_slot_not_configured":
        assert "Yubico Authenticator" in caught.value.message and "HMAC-SHA1" in caught.value.message
    # Never counted as a password failure.
    assert vault_module.remaining_backoff_seconds(env.path) == 0 and env.controller.backoff.remaining() == 0
    env.hid.errors = []
    env.controller.unlock(MASTER)
    assert env.controller.is_unlocked()


def test_busy_yubikey_is_retried_once(env):
    env.port.passwords.append(MASTER)
    env.service.add_yubikey(2)
    env.controller.lock()
    env.hid.errors = ["busy"]
    env.controller.unlock(MASTER)
    assert env.controller.is_unlocked()


def test_unlock_factor_messages(env):
    _add_keyfile(env)
    env.controller.lock()
    other = env.keys / "other.keyx"
    other.write_bytes(keyfile.new_keepass_xml_v2())
    with pytest.raises(ApiError) as caught:
        env.controller.unlock(MASTER, keyfile_path=str(other))
    assert caught.value.code == "factor_mismatch" and caught.value.message == "This isn't the key file used for this vault."
    with pytest.raises(ApiError) as caught:
        env.controller.unlock(MASTER, keyfile_path=str(env.keys / "missing.keyx"))
    assert caught.value.code == "keyfile_unreadable" and "missing.keyx" in caught.value.message
    assert vault_module.remaining_backoff_seconds(env.path) == 0


def test_keyfile_too_large_and_unreadable(env, monkeypatch):
    monkeypatch.setattr(factors_module, "MAX_KEYFILE_BYTES", 16)
    big = env.keys / "big.bin"
    big.write_bytes(b"x" * 64)
    with pytest.raises(ApiError) as caught:
        read_keyfile(big)
    assert caught.value.code == "keyfile_too_large"
    reads = []

    class Handle:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def read(self, size=-1):
            reads.append(size)
            return b"x" * (64 if size < 0 else min(size, 64))

    monkeypatch.setattr(factors_module, "open", lambda path, mode: Handle(), raising=False)
    with pytest.raises(ApiError):
        read_keyfile(big)
    assert reads == [17]  # bounded: never more than MAX + 1 bytes from the open handle
    monkeypatch.delattr(factors_module, "open")
    with pytest.raises(ApiError) as caught:
        read_keyfile(env.keys)  # a folder
    assert caught.value.code == "keyfile_unreadable"
    with pytest.raises(ApiError) as caught:
        read_keyfile(env.keys / "nope.keyx")
    assert caught.value.code == "keyfile_unreadable"
    # The backups' key-file picker uses the same bounded reader.
    recovery = RecoveryWebService(env.controller, env.port, env.dialogs)
    env.dialogs.opened.append(str(env.keys / "nope.keyx"))
    with pytest.raises(ApiError) as caught:
        recovery.choose_keyfile()
    assert caught.value.message == t("recovery.couldNotReadKeyFile")


def test_lock_wipes_held_factors(env):
    _add_keyfile(env)
    session = env.controller.session
    held = session._held_factors.keyfile_secret
    assert session.held_factor_secrets() is not None and any(held)
    recovery = RecoveryWebService(env.controller, env.port, env.dialogs)
    env.dialogs.opened.append(str(env.key_path))
    recovery.choose_keyfile()
    picked = recovery._keyfile
    env.controller.lock()
    assert not any(held) and session.held_factor_secrets() is None
    assert env.controller.keyfile_used is None
    assert recovery._keyfile is None and not any(picked)


def test_hello_session_password_check_asks_for_the_factors(env):
    """A session opened by Hello / security key / camera holds no factors: the key file is asked for then."""
    _add_keyfile(env)
    session = env.controller.session
    session._held_factors.wipe()
    session._held_factors = None
    env.controller.settings.unlock_keyfile_paths = {}
    auth = SecretService(env.controller, env.port)
    lease = env.controller.guard.lease()
    env.port.passwords.append(MASTER)
    env.dialogs.opened.append(str(env.key_path))
    auth.reauthenticate("Reveal", lease)
    assert session.held_factor_secrets() is not None  # now held for later checks
    # Without a key file the check says what is missing, not "password did not match".
    session._held_factors.wipe()
    session._held_factors = None
    env.port.passwords.append(MASTER)
    with pytest.raises(ApiError) as caught:
        auth.reauthenticate("Reveal", lease)
    assert caught.value.code == "factor_required"


def test_face_disable_reports_factor_errors_by_name(env):
    _add_keyfile(env)
    session = env.controller.session
    session._held_factors.wipe()
    session._held_factors = None
    env.controller.settings.unlock_keyfile_paths = {}
    face = FaceService(env.controller, env.port, env.bus, capture_factory=object, engine_factory=lambda: None)
    other = env.keys / "other.keyx"
    other.write_bytes(keyfile.new_keepass_xml_v2())
    env.port.passwords.append(MASTER)
    env.dialogs.opened.append(str(other))
    with pytest.raises(ApiError) as caught:
        face.disable()
    assert caught.value.code == "factor_mismatch"
    assert caught.value.message == "This isn't the key file used for this vault."


def test_recovery_service_uses_public_accessor_and_default_slot(env):
    env.port.passwords.append(MASTER)
    env.service.add_yubikey(2)
    asked = []
    recovery = RecoveryWebService(env.controller, env.port, env.dialogs,
                                  yubikey=lambda slot: asked.append(slot) or (lambda challenge: b""))
    recovery._factor_need = {"kinds": ["yubikey-hmac"], "yubikey_slot": None}
    factors = recovery._factors()
    assert asked == [2] and factors.yubikey_response is not None
    recovery.clear_factors()
    asked.clear()
    held = recovery._factors(session_fallback=True)
    assert held.yubikey_response is env.controller.session.held_factor_secrets().yubikey_response
    recovery._factor_need = {"kinds": ["keyfile"], "yubikey_slot": None}
    recovery.cancel_trial()
    assert recovery._factor_need is None


def test_factor_settings_are_device_only():
    assert {"unlock_keyfile_paths", "unlock_factors_always_ask"} <= set(DEVICE_ONLY_SETTINGS)
    from localvault.settings import validated_keyfile_paths

    assert validated_keyfile_paths({"v1": "C:\\keys\\a.keyx", "v2": "", 3: "x", "v4": 5, "v\n": "x"}) == {
        "v1": "C:\\keys\\a.keyx", "v2": ""}


def test_bridge_wires_factors_and_the_backup_yubikey(env, monkeypatch):
    from localvault.api.bridge import Api

    class Ops:
        def minimize(self):
            pass

        def toggle_maximize(self):
            pass

        def close(self):
            pass

    api = Api(env.controller, env.port, Ops(), dialogs=env.dialogs)
    # The backups' YubiKey seam is the factor service's HID responder (no longer "not ready yet").
    assert api._recovery._yubikey == api._factors.responder
    assert api.factors_add_yubikey(3)["error"]["code"] == "invalid"
    assert api.factors_add_yubikey(True)["error"]["code"] == "invalid"
    assert api.factors_set_always_ask("yes")["error"]["code"] == "invalid"
    env.port.passwords.append(MASTER)
    env.dialogs.opened.append(str(env.key_path))
    assert api.factors_add_keyfile()["ok"] is True
    status = api.factors_status()
    assert status["factors"] == [{"kind": "keyfile", "slot": None}] and status["keyfile_name"] == "vault.keyx"
    api.vault_lock()
    env.controller.settings.unlock_keyfile_paths = {}
    env.dialogs.opened.append(str(env.key_path))
    picked = api.factors_pick_keyfile()
    assert picked == {"ok": True, "name": "vault.keyx"}  # the path stays in Python
    assert api.vault_unlock(MASTER, True)["state"] == "unlocked"
    assert api._factors.picked_keyfile() is None  # forgotten once used
    assert api.factors_cancel()["ok"] is True


# ------------------------------------------------------------------ fix round 1
def test_always_ask_refuses_shortcut_unlocks_on_the_server(env, monkeypatch):
    from localvault.app.unlock_methods import SecurityKeyService

    monkeypatch.setattr("localvault.app.unlock_methods.hello_supported", lambda: True)
    hello = HelloService(env.controller, env.port, hwnd=lambda: 1, timeout=5)
    key = SecurityKeyService(env.controller, env.port, hwnd=lambda: 1, availability=lambda: (True, ""))
    face = FaceService(env.controller, env.port, env.bus, capture_factory=object, engine_factory=lambda: None)
    _add_keyfile(env)
    env.service.set_always_ask(True)
    env.controller.lock()
    for service in (hello, key, face):
        with pytest.raises(ApiError) as caught:
            service.unlock()
        assert caught.value.code == "always_ask"
    assert not env.controller.is_unlocked()


def test_always_ask_removes_other_profiles_sidecars(env, monkeypatch):
    from localvault import face_unlock, fido_unlock, hello_unlock
    from localvault.vault import FactorInput, add_factor, create_vault

    profiles = env.controller.profiles
    other = profiles.create_profile("Other")
    other_path = profiles.vault_path(other.id)
    create_vault(other_path, MASTER, kdf_overrides=KDF).lock()
    add_factor(other_path, MASTER, None, FactorInput("keyfile", keyfile_bytes=env.key_path.read_bytes()))
    third = profiles.create_profile("No factors")
    third_path = profiles.vault_path(third.id)
    create_vault(third_path, MASTER, kdf_overrides=KDF).lock()
    sidecars = [module.envelope_path(path) for path in (other_path, third_path)
                for module in (hello_unlock, fido_unlock, face_unlock)]
    for sidecar in sidecars:
        sidecar.write_bytes(b"sidecar")
    _add_keyfile(env)
    result = env.service.set_always_ask(True)
    assert t("factors.otherProfilesShortcutsRemoved") in result["message"]
    assert "turn it off in that profile" in t("factors.otherProfilesShortcutsRemoved")
    assert [p.exists() for p in sidecars] == [False, False, False, True, True, True]  # only vaults with factors
    # In the other profile: nothing is offered, and its next unlock finishes the job (bindings) and says
    # how to retire camera unlock completely (Settings, with the data-key rotation).
    env.controller.select_profile(other.id)
    state = env.controller.state()
    assert (state["hello"], state["camera"], state["security_key"]) == (False, False, False)
    monkeypatch.setattr(vault_module.VaultSession, "face_binding", lambda self: "camera-record")
    env.bus.events.clear()
    env.controller.unlock(MASTER, keyfile_path=str(env.key_path))
    notices = [detail for name, detail in env.bus.events if name == "notice"]
    assert any(t("factors.cameraFinishInSettings") in notice["message"] for notice in notices)


def test_lock_cancels_a_pending_touch_promptly(env, monkeypatch):
    import threading
    import time

    env.port.passwords.append(MASTER)
    env.service.add_yubikey(2)
    entered = threading.Event()

    def waiting_for_touch(path, slot, challenge64, *, timeout=15.0, cancel=None):
        entered.set()
        if cancel is not None and cancel.wait(10):
            raise yubikey_hid.YubiKeyError("cancelled")
        raise yubikey_hid.YubiKeyError("touch_timeout")

    monkeypatch.setattr(yubikey_hid, "challenge_response", waiting_for_touch)
    outcome = {}

    def remove():
        env.port.passwords.append(MASTER)
        try:
            env.service.remove("yubikey-hmac")  # asks the YubiKey inside the vault's session lock
        except ApiError as exc:
            outcome["code"] = exc.code

    worker = threading.Thread(target=remove)
    worker.start()
    assert entered.wait(5)
    started = time.monotonic()
    env.controller.lock()
    elapsed = time.monotonic() - started
    worker.join(5)
    assert elapsed < 2 and not worker.is_alive()
    assert outcome == {"code": "cancelled"} and not env.controller.is_unlocked()
    assert _kinds(env) == ["yubikey-hmac"]  # nothing changed


def test_keyfile_paths_must_be_regular_files(env, monkeypatch):
    for device in ("\\\\.\\pipe\\lgk-test", "\\\\?\\GLOBALROOT\\Device\\Null", "//./NUL"):
        with pytest.raises(ApiError) as caught:
            read_keyfile(device)
        assert caught.value.code == "keyfile_unreadable"
    opened = []
    monkeypatch.setattr(factors_module, "open", lambda *a, **k: opened.append(a), raising=False)
    monkeypatch.setattr(factors_module.os, "stat", lambda path: SimpleNamespace(st_mode=0o010644))  # a FIFO
    with pytest.raises(ApiError) as caught:
        read_keyfile(env.keys / "fifo")
    assert caught.value.code == "keyfile_unreadable" and opened == []  # refused before anything is opened


def test_remembered_network_path_is_not_read_unasked(env, monkeypatch):
    from localvault.app.factors import is_unc, remembered_keyfile

    assert is_unc("\\\\server\\share\\vault.keyx") and is_unc("//server/share/k")
    assert not is_unc("\\\\.\\pipe\\x") and not is_unc("C:\\keys\\vault.keyx")
    _add_keyfile(env)
    vault_id = _vault_id(env)
    env.controller.settings.unlock_keyfile_paths = {vault_id: "\\\\server\\share\\vault.keyx"}
    assert remembered_keyfile(env.controller.settings, vault_id) is None
    reads = []
    monkeypatch.setattr(factors_module, "read_keyfile", lambda path: reads.append(path) or bytearray())
    env.controller.lock()
    with pytest.raises(ApiError) as caught:
        env.controller.unlock(MASTER)
    assert caught.value.code == "factor_required" and reads == []
