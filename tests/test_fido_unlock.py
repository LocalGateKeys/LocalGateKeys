"""Security key (FIDO2 hmac-secret) unlock. webauthn.dll is replaced by a simulated key.

The simulated key computes hmac-secret the way a CTAP2 key does behind Windows'
PRF salt hashing: HMAC-SHA256(per-credential random, SHA-256("WebAuthn PRF" || 0 || salt)).
It does not simulate the PIN, touch or the Windows Security dialog.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import threading
from pathlib import Path
from types import SimpleNamespace

import pytest

import localvault.vault as vault_module
from localvault import fido_unlock, security_key
from localvault.api.result import ApiError
from localvault.app.controller import WebController
from localvault.app.unlock_methods import SecurityKeyService
from localvault.config import read_json
from localvault.profiles import ProfileManager
from localvault.secret_text import SecretText
from localvault.security_key import (
    RP_ID,
    SecurityKeyCancelled,
    SecurityKeyError,
    SecurityKeyUnavailable,
)
from localvault.settings import AppSettings
from localvault.vault import VaultError, create_vault, unlock_vault

MASTER = "Local-Only-Test-Master-0001"
KDF = {"memory_cost_kib": 8192, "time_cost": 1, "parallelism": 1}
PROFILE = "test-profile"
HWND = 4321


class SimulatedKey:
    """A FIDO2 key with hmac-secret; ``secrets`` maps credential id -> CredRandom."""

    def __init__(self, version: int = 9):
        self.version = version
        self.secrets: dict[bytes, bytes] = {}
        self.calls: list[str] = []
        self.outputs: list[bytearray] = []

    def api_version(self) -> int:
        return self.version

    def make_credential(self, hwnd, rp_id, user_id):
        self.calls.append("make")
        assert hwnd == HWND and rp_id == RP_ID and len(user_id) == 16
        credential_id = os.urandom(64)
        self.secrets[credential_id] = os.urandom(32)
        return credential_id

    def hmac_secret(self, hwnd, rp_id, credential_id, salt):
        self.calls.append("get")
        assert hwnd == HWND and rp_id == RP_ID and len(salt) == 32
        if credential_id not in self.secrets:
            raise SecurityKeyError("This is not the security key set up for this profile.")
        prf_salt = hashlib.sha256(b"WebAuthn PRF\x00" + salt).digest()
        output = bytearray(hmac.new(self.secrets[credential_id], prf_salt, hashlib.sha256).digest())
        self.outputs.append(output)
        return output


@pytest.fixture
def vault(tmp_path):
    session = create_vault(tmp_path / "vault.json", MASTER, kdf_overrides=KDF)
    session.upsert_web(origin="https://example.test", username="local-user", password="Test-Only-Site-Secret")
    yield session
    session.lock()


@pytest.fixture
def key():
    return SimulatedKey()


def enroll(session, key):
    prepared = fido_unlock.prepare_enrollment(PROFILE, session.unlock_context(), HWND, threading.Event(),
                                              provider_factory=lambda: key)
    fido_unlock.commit_enrollment(session, prepared)
    return prepared


def key_unlock(path: Path, key, profile=PROFILE):
    return fido_unlock.unlock_with_security_key(path, profile, HWND, threading.Event(),
                                                provider_factory=lambda: key)


def sidecar(session) -> dict:
    return json.loads(fido_unlock.envelope_path(session.path).read_text(encoding="utf-8"))


def test_enroll_then_unlock_opens_the_vault(vault, key):
    prepared = enroll(vault, key)
    assert key.calls == ["make", "get"]
    assert prepared.committed and not any(prepared.wrapping_key)
    assert all(not any(output) for output in key.outputs)  # hmac-secret outputs are wiped
    record = sidecar(vault)
    assert record["rp_id"] == RP_ID and record["profile"] == PROFILE
    assert vault.fido_binding() == record["id"]
    assert len(base64.b64decode(record["ciphertext"])) == 48
    vault.lock()

    session = key_unlock(vault.path, key)
    try:
        assert session.find_web("https://example.test")[0]["password"] == "Test-Only-Site-Secret"
    finally:
        session.lock()
    assert all(not any(output) for output in key.outputs)


def test_sidecar_holds_no_key_material_in_the_clear(vault, key):
    enroll(vault, key)
    raw = fido_unlock.envelope_path(vault.path).read_bytes()
    data_key = bytes(vault._key)
    assert data_key not in raw and base64.b64encode(data_key) not in raw


def test_another_security_key_cannot_unlock(vault, key):
    enroll(vault, key)
    vault.lock()
    stranger = SimulatedKey()
    with pytest.raises(SecurityKeyError, match="not the security key"):
        key_unlock(vault.path, stranger)
    # Same credential id, different key secret (a cloned id on another key).
    stranger.secrets = {credential: os.urandom(32) for credential in key.secrets}
    with pytest.raises(SecurityKeyError) as failed:
        key_unlock(vault.path, stranger)
    assert "did not open this vault" in str(failed.value)


def test_unsupported_api_version_refuses_setup_and_unlock(vault, key):
    old = SimulatedKey(version=3)
    with pytest.raises(SecurityKeyUnavailable, match="version 3"):
        fido_unlock.prepare_enrollment(PROFILE, vault.unlock_context(), HWND, threading.Event(),
                                       provider_factory=lambda: old)
    assert old.calls == []
    enroll(vault, key)
    vault.lock()
    key.version = 3
    with pytest.raises(SecurityKeyUnavailable):
        key_unlock(vault.path, key)
    assert key.calls == ["make", "get"]


def test_availability_reports_a_reason(monkeypatch):
    assert security_key.availability(lambda: SimulatedKey(version=4)) == (True, "")
    supported, reason = security_key.availability(lambda: SimulatedKey(version=2))
    assert not supported and "version 2" in reason
    monkeypatch.setattr(security_key, "supported_platform", lambda: False)
    supported, reason = security_key.availability(lambda: SimulatedKey())
    assert not supported and "only on Windows" in reason


def test_sidecar_from_another_vault_is_refused(tmp_path, key):
    first = create_vault(tmp_path / "a" / "vault.json", MASTER, kdf_overrides=KDF)
    second = create_vault(tmp_path / "b" / "vault.json", MASTER, kdf_overrides=KDF)
    enroll(first, key)
    enroll(second, key)
    planted = sidecar(first)
    second_context = second.unlock_context()
    first.lock()
    second.lock()
    target = fido_unlock.envelope_path(second.path)
    target.write_text(json.dumps(planted), encoding="utf-8")
    with pytest.raises(SecurityKeyError, match="changed after the security key"):
        key_unlock(second.path, key)
    # Even with its (unauthenticated) unlock_context forged to match, it opens nothing.
    planted["unlock_context"] = second_context
    target.write_text(json.dumps(planted), encoding="utf-8")
    with pytest.raises(VaultError):
        key_unlock(second.path, key)


def test_tampered_record_fields_fail_authentication(vault, key):
    enroll(vault, key)
    vault.lock()
    path = fido_unlock.envelope_path(vault.path)
    original = json.loads(path.read_text(encoding="utf-8"))
    for name in ("salt", "id"):
        record = dict(original)
        record[name] = base64.b64encode(os.urandom(32)).decode() if name == "salt" else os.urandom(16).hex()
        path.write_text(json.dumps(record), encoding="utf-8")
        with pytest.raises(SecurityKeyError):
            key_unlock(vault.path, key)


def test_sidecar_without_the_vault_binding_is_refused(vault, key):
    enroll(vault, key)
    kept = fido_unlock.envelope_path(vault.path).read_bytes()
    fido_unlock.disable_enrollment(vault)
    vault.lock()
    fido_unlock.envelope_path(vault.path).write_bytes(kept)  # resurrected copy
    with pytest.raises(VaultError, match="revoked"):
        key_unlock(vault.path, key)


def test_removal_revokes_and_deletes_the_sidecar(vault, key):
    enroll(vault, key)
    fido_unlock.disable_enrollment(vault)
    assert vault.fido_binding() == ""
    assert not fido_unlock.envelope_path(vault.path).exists()
    assert not fido_unlock.has_envelope(vault.path, PROFILE)
    vault.lock()
    with pytest.raises(SecurityKeyError, match="not set up"):
        key_unlock(vault.path, key)
    # The master password is unaffected.
    unlock_vault(vault.path, MASTER).lock()


def test_second_enrollment_needs_removal_first(vault, key):
    enroll(vault, key)
    prepared = fido_unlock.prepare_enrollment(PROFILE, vault.unlock_context(), HWND, threading.Event(),
                                              provider_factory=lambda: key)
    with pytest.raises(SecurityKeyError, match="Remove the current"):
        fido_unlock.commit_enrollment(vault, prepared)


def test_wrong_profile_and_cancellation(vault, key):
    enroll(vault, key)
    vault.lock()
    with pytest.raises(SecurityKeyError, match="not set up"):
        key_unlock(vault.path, key, profile="other-profile")
    cancelled = threading.Event()
    cancelled.set()
    with pytest.raises(SecurityKeyCancelled):
        fido_unlock.unlock_with_security_key(vault.path, PROFILE, HWND, cancelled, provider_factory=lambda: key)


def test_password_change_revokes_the_security_key(vault, key):
    enroll(vault, key)
    result = vault.change_master_password(MASTER, "Another-Local-Master-0002")
    assert "fido" in result["reenroll_required"] and vault.fido_binding() == ""
    assert fido_unlock.envelope_path(vault.path).exists()  # left for the caller's cleanup
    vault.lock()
    with pytest.raises(SecurityKeyError):
        key_unlock(vault.path, key)
    assert fido_unlock.cleanup_after_password_change(vault.path)
    assert not fido_unlock.envelope_path(vault.path).exists()


def test_data_key_rotation_removes_the_sidecar(vault, key):
    enroll(vault, key)
    result = vault.rotate_data_key(MASTER)
    assert "fido" in result["reenroll_required"]
    assert not fido_unlock.envelope_path(vault.path).exists()


# --------------------------------------------------------------------------
# KDF upgrade (WP-C): the sidecar moves to the new unlock context
# --------------------------------------------------------------------------

@pytest.fixture
def fast_upgrade(monkeypatch):
    monkeypatch.setattr(vault_module, "DEFAULT_KDF", {**vault_module.DEFAULT_KDF, "time_cost": 1,
                                                      "memory_cost_kib": 16384, "parallelism": 1})
    monkeypatch.setattr(vault_module, "_total_physical_memory_bytes", lambda: 16 * 1024 ** 3)


@pytest.mark.kdf_upgrade
def test_security_key_survives_the_kdf_upgrade(tmp_path, key, fast_upgrade):
    session = create_vault(tmp_path / "vault.json", MASTER, kdf_overrides=KDF)
    session.upsert_web(origin="https://example.test", username="u", password="Site-Secret-1")
    enroll(session, key)
    old_context = session.unlock_context()
    session.lock()

    upgraded = unlock_vault(session.path, MASTER, upgrade_kdf=True)
    result = upgraded.last_kdf_upgrade_result
    assert result["outcome"] == "upgraded" and result["converted"] == ["fido"]
    new_context = upgraded.unlock_context()
    upgraded.lock()
    assert new_context != old_context
    assert read_json(session.path)["kdf"]["memory_cost_kib"] == 16384
    record = json.loads(fido_unlock.envelope_path(session.path).read_text(encoding="utf-8"))
    assert record["context"] == old_context and record["unlock_context"] == new_context
    opened = key_unlock(session.path, key)
    assert opened.find_web("https://example.test")[0]["password"] == "Site-Secret-1"
    opened.lock()


@pytest.mark.kdf_upgrade
def test_interrupted_kdf_upgrade_sidecar_move_is_repaired(tmp_path, key, fast_upgrade, monkeypatch):
    session = create_vault(tmp_path / "vault.json", MASTER, kdf_overrides=KDF)
    enroll(session, key)
    session.lock()
    real = fido_unlock.upgrade_envelope_context
    monkeypatch.setattr(fido_unlock, "upgrade_envelope_context", lambda *_args: False)
    upgraded = unlock_vault(session.path, MASTER, upgrade_kdf=True)
    assert upgraded.last_kdf_upgrade_result["sidecars_pending"] == ["fido"]
    upgraded.lock()
    with pytest.raises(SecurityKeyError):
        key_unlock(session.path, key)
    monkeypatch.setattr(fido_unlock, "upgrade_envelope_context", real)
    unlock_vault(session.path, MASTER, upgrade_kdf=True).lock()
    key_unlock(session.path, key).lock()


def test_restore_style_sanitising_clears_the_binding(vault, key):
    enroll(vault, key)
    with vault.transaction():
        vault.set_fido_binding(None)
    assert vault.fido_binding() == ""
    with pytest.raises(VaultError):
        vault.set_fido_binding("not-hex")


# --------------------------------------------------------------------------
# WebView service
# --------------------------------------------------------------------------

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


class Sched:
    def call_later(self, delay, fn):
        return fn

    def cancel(self, handle):
        pass


@pytest.fixture
def env(tmp_path, monkeypatch, key):
    state = {"required": False, "supported": (True, "")}
    monkeypatch.setattr("localvault.app.controller.clear_master_unlock_requirement", lambda pid: None)
    monkeypatch.setattr("localvault.app.controller.master_unlock_required", lambda pid: state["required"])
    monkeypatch.setattr("localvault.app.unlock_methods.master_unlock_required", lambda pid: state["required"])
    monkeypatch.setattr(AppSettings, "save", lambda self, path=None: None)
    profiles = ProfileManager(tmp_path / "data")
    profiles.ensure_profile()
    controller = WebController(profiles=profiles, settings=AppSettings(idle_source="vault"),
                               bus=SimpleNamespace(emit=lambda *a: None), scheduler=Sched(),
                               create_kwargs={"kdf_overrides": {**KDF, "hash_len": 32}})
    controller.create(MASTER, MASTER)
    port = Port()
    service = SecurityKeyService(controller, port, hwnd=lambda: HWND, timeout=5, enroll_timeout=5,
                                 provider_factory=lambda: key, availability=lambda: state["supported"])
    return SimpleNamespace(controller=controller, port=port, service=service, state=state)


def test_service_enrol_needs_the_master_password(env):
    with pytest.raises(ApiError):
        env.service.enable()  # no password given
    assert env.service.status()["enabled"] is False
    env.port.passwords.append("wrong password here")
    with pytest.raises(ApiError) as refused:
        env.service.enable()
    assert refused.value.code == "not_authorized"


def test_service_enrol_unlock_and_remove(env):
    env.port.passwords.append(MASTER)
    assert "enabled" in env.service.enable()["message"]
    status = env.service.status()
    assert status["enabled"] and status["tone"] == "success"
    env.controller.lock()
    assert env.controller.state()["security_key"] is True
    env.service.unlock()
    assert env.controller.is_unlocked()
    env.port.passwords.append(MASTER)
    env.service.disable()
    assert env.service.status()["enabled"] is False
    env.controller.lock()
    assert env.controller.state()["security_key"] is False


def test_service_refuses_under_the_master_password_marker(env):
    env.port.passwords.append(MASTER)
    env.service.enable()
    env.controller.lock()
    env.state["required"] = True
    env.controller._extras_cache = None
    assert env.controller.state()["security_key"] is False
    with pytest.raises(ApiError) as refused:
        env.service.unlock()
    assert refused.value.code == "master_required"


def test_service_unsupported_shows_the_reason_and_refuses_setup(env):
    env.state["supported"] = (False, "Too old: version 3")
    status = env.service.status()
    assert status == {**status, "supported": False, "enabled": False, "status": "Too old: version 3"}
    with pytest.raises(ApiError) as refused:
        env.service.enable()
    assert refused.value.code == "unsupported" and "version 3" in refused.value.message
    assert env.service.offered() is False


# --------------------------------------------------------------------------
# Settings > Unlocking row and the Security center panel
# --------------------------------------------------------------------------

def _unlocking_rows(methods):
    from localvault.app.settings import _Recorder
    from localvault.shell.settings_sections import build_unlocking

    app = SimpleNamespace(_unlock_methods=lambda: methods,
                          _settings_face_state=lambda: {"label": "Set up", "status": "Not set up"},
                          **{name: (lambda: {"route": "hello", "params": {}}) for name in (
                              "hello_settings_clicked", "face_settings_clicked", "change_master_clicked",
                              "recovery_center_clicked")})
    form = _Recorder(app, AppSettings())
    build_unlocking(form)
    return [row for row in form.rows if row.get("title") == "Security key"]


def test_settings_row_shows_status_or_the_unsupported_reason():
    from localvault.shell.security_model import UnlockMethods

    [row] = _unlocking_rows(UnlockMethods(security_key_available=True))
    assert row["route"] == "hello" and row["label"] == "Set up" and "FIDO2" in row["description"]
    [row] = _unlocking_rows(UnlockMethods(security_key_available=True, security_key_enrolled=True))
    assert row["label"] == "Manage"
    [row] = _unlocking_rows(UnlockMethods(security_key_available=False, security_key_reason="Too old: version 3"))
    assert row["description"] == "Too old: version 3"
    # Older status objects without the fields add no row.
    assert _unlocking_rows(SimpleNamespace(hello_available=False, hello_enrolled=False, recovery_phrase=None)) == []


def test_security_center_lists_the_key_only_where_supported():
    from localvault.shell.security_model import UnlockMethods, unlock_panel

    settings = AppSettings()
    titles = [row.label for row in unlock_panel(UnlockMethods(security_key_available=True), settings).rows]
    assert "Security key" in titles
    titles = [row.label for row in unlock_panel(UnlockMethods(), settings).rows]
    assert "Security key" not in titles
