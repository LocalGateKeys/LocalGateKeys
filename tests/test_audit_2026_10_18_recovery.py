"""Audit 2026-10-18 M7: a recovery-phrase reset rotates the data key and revokes Hello / camera envelopes."""
from __future__ import annotations

import base64
import threading
from pathlib import Path

import pytest
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from test_face_unlock import enroll as face_enroll
from test_face_unlock import unlock_face
from test_hello_unlock import SimulatedProvider
from test_hello_unlock import enroll as hello_enroll

import localvault.vault as vault_module
from localvault.i18n import t
from localvault import face_unlock as face
from localvault import hello_unlock as hello
from localvault.app import recovery_center
from localvault.app.controller import RECOVERY_RESET_TITLE, WebController
from localvault.attachments import AttachmentStore
from localvault.config import read_json
from localvault.profiles import ProfileManager
from localvault.settings import AppSettings
from localvault.vault import (
    DEFAULT_KDF,
    InvalidMasterPassword,
    VaultError,
    create_vault,
    unlock_vault,
    unlock_with_recovery_phrase,
)

TEST_KDF = {"time_cost": 1, "memory_cost_kib": 8192, "parallelism": 1, "hash_len": 32}
MASTER = "correct horse battery staple"
NEW_MASTER = "replacement master password 0002"
HELLO_PROFILE = "test-profile"


@pytest.fixture(autouse=True)
def _fast_default_kdf(monkeypatch):
    monkeypatch.setattr(vault_module, "DEFAULT_KDF", {**DEFAULT_KDF, **TEST_KDF})
    vault_module._reset_unlock_throttle_state_for_tests()
    yield
    vault_module._reset_unlock_throttle_state_for_tests()


def _vault(tmp_path: Path, **kwargs):
    session = create_vault(tmp_path / "vault.json", MASTER, kdf_overrides=TEST_KDF, **kwargs)
    entry = session.upsert_web(origin="https://example.com", username="a", password="pw-one")
    phrase = session.create_recovery_phrase(MASTER)
    return session, entry, phrase


def _opens_with_key(path: Path, key: bytes) -> bool:
    header = read_json(path)
    cipher = header["cipher"]
    try:
        AESGCM(key).decrypt(base64.b64decode(cipher["nonce"]), base64.b64decode(cipher["ciphertext"]),
                            vault_module._aad(header))
    except InvalidTag:
        return False
    return True


def test_recovery_reset_rotates_the_data_key_and_keeps_the_phrase(tmp_path: Path) -> None:
    backups = tmp_path / "Backups"
    session, entry, phrase = _vault(tmp_path, backup_dir=backups, backup_count=10)
    session.upsert_web(origin="https://example.org", username="b", password="pw-two")
    path = session.path
    old_key = bytes(session._key)
    old_generation = read_json(path)["key_generation"]
    assert len(list(backups.glob("vault-*.json"))) >= 1
    session.lock()

    report: dict = {}
    recovered = recovery_center.recover_with_phrase(path, phrase, NEW_MASTER, backup_dir=backups,
                                                    backup_count=10, report=report)
    assert not recovered.recovery_unlocked and recovered._recovery_entropy is None
    new_key = bytes(recovered._key)
    assert new_key != old_key
    document = read_json(path)
    assert document["key_generation"] == old_generation + 1 == report["key_generation"]
    assert report["recovery_phrase_invalidated"] is False
    assert report["purged_backups"] >= 1
    assert report["unlock_cleanup_complete"] is True
    # The old data key no longer opens the current vault; old rolling backups are gone.
    assert not _opens_with_key(path, old_key) and _opens_with_key(path, new_key)
    remaining = list(backups.glob("vault-*.json"))
    assert remaining and all(read_json(b)["key_generation"] == old_generation + 1 for b in remaining)
    assert recovered.rollback_anchor_generation() == document["generation"]
    recovered.lock()

    with pytest.raises(InvalidMasterPassword):
        unlock_vault(path, MASTER)
    reopened = unlock_vault(path, NEW_MASTER)
    assert reopened.get_entry(entry)["password"] == "pw-one"
    assert bytes(reopened._key) == new_key
    reopened.lock()
    # The phrase that was just used is re-wrapped under the new key.
    again = unlock_with_recovery_phrase(path, phrase)
    assert bytes(again._key) == new_key
    again.lock()


def test_attachments_stay_readable_after_recovery_rotation(tmp_path: Path) -> None:
    session, _entry, phrase = _vault(tmp_path)
    path = session.path
    attachment_id = AttachmentStore(session).add_bytes("notes.txt", b"attachment body\n", mime_type="text/plain")
    session.lock()
    recovered = recovery_center.recover_with_phrase(path, phrase, NEW_MASTER)
    assert AttachmentStore(recovered).read_bytes(attachment_id) == b"attachment body\n"
    recovered.lock()
    reopened = unlock_vault(path, NEW_MASTER)
    assert AttachmentStore(reopened).read_bytes(attachment_id) == b"attachment body\n"
    reopened.lock()


def test_recovery_reset_deletes_the_windows_hello_key_and_envelope(tmp_path: Path, monkeypatch) -> None:
    session, _entry, phrase = _vault(tmp_path)
    path = session.path
    provider = SimulatedProvider()
    prepared = hello_enroll(session, provider)
    record_id = prepared.record["id"]
    assert record_id in provider.keys and hello.envelope_path(path).exists()
    session.lock()
    monkeypatch.setattr(hello, "WindowsHello", lambda: provider)

    report: dict = {}
    recovered = recovery_center.recover_with_phrase(path, phrase, NEW_MASTER, report=report)
    assert report["reenroll_required"] == ["hello"] and report["unlock_cleanup_complete"] is True
    assert recovered.hello_binding() == ""
    assert not hello.envelope_path(path).exists()
    assert record_id not in provider.keys and "delete" in provider.calls
    recovered.lock()
    with pytest.raises((hello.HelloError, VaultError)):
        hello.unlock_with_hello(path, HELLO_PROFILE, 123, threading.Event(), provider_factory=lambda: provider)


def test_an_old_hello_envelope_cannot_unlock_the_recovered_vault(tmp_path: Path, monkeypatch) -> None:
    """Even if the OS key and the sidecar survive (cleanup failed), they only hold the retired key."""
    session, _entry, phrase = _vault(tmp_path)
    path = session.path
    provider = SimulatedProvider()
    prepared = hello_enroll(session, provider)
    old_envelope = hello.envelope_path(path).read_bytes()
    old_key = bytes(session._key)
    session.lock()
    provider.fail_delete = True
    monkeypatch.setattr(hello, "WindowsHello", lambda: provider)

    report: dict = {}
    recovered = recovery_center.recover_with_phrase(path, phrase, NEW_MASTER, report=report)
    assert report["unlock_cleanup_complete"] is False
    # Put the old setup back, including the binding inside the vault.
    hello.envelope_path(path).write_bytes(old_envelope)
    recovered.set_hello_binding(prepared.record["id"])
    recovered.lock()
    with pytest.raises((hello.HelloError, VaultError)):
        hello.unlock_with_hello(path, HELLO_PROFILE, 123, threading.Event(), provider_factory=lambda: provider)
    assert not _opens_with_key(path, old_key)
    unlock_vault(path, NEW_MASTER).lock()


def test_recovery_reset_revokes_the_camera_envelope(tmp_path: Path) -> None:
    session, _entry, phrase = _vault(tmp_path)
    path = session.path
    prepared = face_enroll(session)
    old_envelope = face.envelope_path(path).read_bytes()
    old_key = bytes(session._key)
    session.lock()

    report: dict = {}
    recovered = recovery_center.recover_with_phrase(path, phrase, NEW_MASTER, report=report)
    assert report["reenroll_required"] == ["face"]
    assert recovered.face_binding() == ""
    assert not face.envelope_path(path).exists()
    # Restoring the old sidecar and binding does not open the vault.
    face.envelope_path(path).write_bytes(old_envelope)
    recovered.set_face_binding(prepared.record["id"])
    recovered.lock()
    with pytest.raises((face.FaceError, VaultError)):
        unlock_face(path)
    assert not _opens_with_key(path, old_key)


def test_crash_before_the_recovery_commit_leaves_the_old_vault_openable(tmp_path: Path, monkeypatch) -> None:
    session, entry, phrase = _vault(tmp_path)
    path = session.path
    session.lock()
    recovered = unlock_with_recovery_phrase(path, phrase)

    def crash(*_args, **_kwargs):
        raise KeyboardInterrupt("simulated crash before the vault commit")

    real_write = vault_module._write_generation_anchor

    def write(anchor_path, generation, anchor_key, vault_id="", **kwargs):
        # Write the dual anchor, then drop the failure-path restore (as a crash would).
        if kwargs.get("previous_key") is not None:
            real_write(anchor_path, generation, anchor_key, vault_id, **kwargs)

    monkeypatch.setattr(recovered, "_commit_header_change", crash)
    monkeypatch.setattr(vault_module, "_write_generation_anchor", write)
    with pytest.raises(KeyboardInterrupt):
        recovered.set_master_password_after_recovery(NEW_MASTER)
    monkeypatch.setattr(vault_module, "_write_generation_anchor", real_write)
    assert "previous" in read_json(vault_module._generation_anchor_path(path))
    recovered.lock()
    reopened = unlock_vault(path, MASTER)
    assert reopened.get_entry(entry)["password"] == "pw-one"
    reopened.lock()
    assert "previous" not in read_json(vault_module._generation_anchor_path(path))
    unlock_with_recovery_phrase(path, phrase).lock()


def test_crash_after_the_recovery_commit_leaves_the_new_vault_openable(tmp_path: Path, monkeypatch) -> None:
    backups = tmp_path / "Backups"
    session, entry, phrase = _vault(tmp_path, backup_dir=backups, backup_count=10)
    path = session.path
    session.lock()
    recovered = unlock_with_recovery_phrase(path, phrase, backup_dir=backups, backup_count=10)

    def crash(*_args, **_kwargs):
        raise KeyboardInterrupt("simulated crash after the vault commit")

    monkeypatch.setattr(recovered, "purge_rolling_backups_older_than", crash)
    with pytest.raises(KeyboardInterrupt):
        recovered.set_master_password_after_recovery(NEW_MASTER)
    recovered.lock()
    reopened = unlock_vault(path, NEW_MASTER, backup_dir=backups, backup_count=10)
    assert reopened.get_entry(entry)["password"] == "pw-one"
    assert reopened.rollback_anchor_generation() == read_json(path)["generation"]
    reopened.lock()
    unlock_with_recovery_phrase(path, phrase).lock()


def test_recovery_entropy_is_kept_only_until_reset_or_lock(tmp_path: Path) -> None:
    session, _entry, phrase = _vault(tmp_path)
    path = session.path
    session.lock()
    recovered = unlock_with_recovery_phrase(path, phrase)
    buffer = recovered._recovery_entropy
    assert isinstance(buffer, bytearray) and any(buffer)
    recovered.lock()
    assert recovered._recovery_entropy is None and not any(buffer)
    recovered = unlock_with_recovery_phrase(path, phrase)
    buffer = recovered._recovery_entropy
    recovered.set_master_password_after_recovery(NEW_MASTER)
    assert recovered._recovery_entropy is None and not any(buffer)
    recovered.lock()


def test_password_change_and_recovery_require_the_right_session(tmp_path: Path) -> None:
    session, _entry, _phrase = _vault(tmp_path)
    with pytest.raises(VaultError):
        session.set_master_password_after_recovery(NEW_MASTER)
    session.lock()


class _Bus:
    def __init__(self):
        self.events = []

    def emit(self, name, detail):
        self.events.append((name, detail))


class _Sched:
    def call_later(self, delay, fn):
        return fn

    def cancel(self, handle):
        pass


def test_controller_recover_cleans_envelopes_and_says_so(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr("localvault.app.controller.clear_master_unlock_requirement", lambda _pid: None)
    profiles = ProfileManager(tmp_path / "data")
    profiles.ensure_profile()
    bus = _Bus()
    controller = WebController(profiles=profiles, settings=AppSettings(idle_source="vault"), bus=bus,
                               scheduler=_Sched(), create_kwargs={"kdf_overrides": TEST_KDF})
    controller.create(MASTER, MASTER)
    session = controller.session
    phrase = session.create_recovery_phrase(MASTER)
    face_enroll(session)
    path = session.path
    old_key = bytes(session._key)
    controller.lock()
    assert face.envelope_path(path).exists()

    controller.recover(phrase, NEW_MASTER, NEW_MASTER)
    assert controller.is_unlocked()
    assert bytes(controller.session._key) != old_key
    assert not face.envelope_path(path).exists() and controller.session.face_binding() == ""
    notices = [detail for name, detail in bus.events if name == "notice"]
    assert [notice["title"] for notice in notices] == [t(RECOVERY_RESET_TITLE)]
    assert "Windows Hello and camera verification were removed" in notices[0]["message"]
    controller.lock()
    controller.unlock(NEW_MASTER)
    assert controller.is_unlocked()
    controller.lock()
