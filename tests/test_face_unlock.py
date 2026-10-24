"""Local RGB-webcam envelope tests. Camera/model inference is tested separately."""
from __future__ import annotations

import base64
import json
import os
import struct
import threading
from pathlib import Path

import pytest
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from localvault import face_unlock as face
from localvault.face_models import EMBEDDING_SIZE, normalize_embedding
from localvault.vault import InvalidMasterPassword, VaultError, create_vault, unlock_vault

MASTER = "Local Face Test Master Password 0001"
NEW_MASTER = "Local Face Test Master Password 0002"
PROFILE = "face-test-profile"
KDF = {"memory_cost_kib": 8192, "time_cost": 1, "parallelism": 1}


class SimulatedProtector:
    """Test-only AEAD stand-in for current-user DPAPI; does not simulate Windows."""

    key = bytes.fromhex("42" * 32)

    def protect(self, value, entropy, description):
        nonce = os.urandom(12)
        aad = bytes(entropy) + description.encode("utf-8")
        return nonce + AESGCM(self.key).encrypt(nonce, bytes(value), aad)

    def unprotect(self, value, entropy):
        raw = bytes(value)
        nonce, ciphertext = raw[:12], raw[12:]
        # Both enrollment fields use stable, known descriptions.
        for description in ("LocalGateKeys face template", "LocalGateKeys local unlock key"):
            try:
                return bytearray(AESGCM(self.key).decrypt(
                    nonce, ciphertext, bytes(entropy) + description.encode("utf-8")
                ))
            except InvalidTag:
                continue
        raise face.FaceError("Simulated protected value did not authenticate")


def protector():
    return SimulatedProtector()


def embeddings():
    values = []
    for offset in (0.00, 0.02, -0.02, 0.01, -0.01, 0.03):
        raw = [0.0] * EMBEDDING_SIZE
        raw[0], raw[1], raw[2] = 1.0, offset, offset / 2
        values.append(list(normalize_embedding(raw)))
    return values


@pytest.fixture
def vault(tmp_path: Path):
    session = create_vault(tmp_path / "vault.json", MASTER, kdf_overrides=KDF)
    session.upsert_web(
        origin="https://example.test", username="local-user", password="Local-Site-Secret"
    )
    yield session
    if session.is_unlocked:
        session.lock()


def enroll(session):
    prepared = face.prepare_enrollment(
        PROFILE, session.unlock_context(), embeddings(), protector_factory=protector
    )
    face.commit_enrollment(session, prepared)
    return prepared


def unlock_face(path: Path):
    material = face.load_face_material(path, PROFILE, protector_factory=protector)
    try:
        return face.unlock_verified_face(material, threading.Event(), protector_factory=protector)
    finally:
        material.discard()


def test_opt_in_roundtrip_is_local_encrypted_and_password_remains_primary(vault):
    original = vault.path.read_bytes()
    raw_key = bytes(vault._key)
    raw_template = struct.pack(f"<{EMBEDDING_SIZE}f", *embeddings()[0])
    prepared = face.prepare_enrollment(
        PROFILE, vault.unlock_context(), embeddings(), protector_factory=protector
    )
    raw_secret = bytes(prepared.secret)
    assert not vault.face_binding()
    assert vault.path.read_bytes() == original
    assert not face.envelope_path(vault.path).exists()

    face.commit_enrollment(vault, prepared)
    assert prepared.committed and not any(prepared.secret)
    sidecar = face.envelope_path(vault.path).read_bytes()
    for secret in (
        MASTER.encode(), b"Local-Site-Secret", raw_key, raw_secret, raw_template,
        base64.b64encode(raw_key), base64.b64encode(raw_secret), base64.b64encode(raw_template),
    ):
        assert secret not in sidecar
    assert b"face_binding" not in vault.path.read_bytes()
    assert face.has_envelope(vault.path, PROFILE)

    vault.lock()
    by_password = unlock_vault(vault.path, MASTER)
    assert by_password.face_binding()
    by_password.lock()
    with pytest.raises(InvalidMasterPassword):
        unlock_vault(vault.path, "incorrect master password")

    by_face = unlock_face(vault.path)
    assert by_face.find_web("https://example.test")[0]["password"] == "Local-Site-Secret"
    by_face.lock()


@pytest.mark.parametrize("field", ["template", "protected_secret", "nonce", "ciphertext"])
def test_tampered_sidecar_never_unlocks(vault, field):
    enroll(vault)
    path = face.envelope_path(vault.path)
    record = json.loads(path.read_text())
    raw = bytearray(base64.b64decode(record[field])); raw[0] ^= 1
    record[field] = base64.b64encode(raw).decode("ascii")
    path.write_text(json.dumps(record))
    vault.lock()
    with pytest.raises((face.FaceError, VaultError)):
        unlock_face(vault.path)
    check = unlock_vault(vault.path, MASTER); check.lock()


def test_encrypted_vault_binding_not_sidecar_is_authority(vault):
    enroll(vault)
    vault.set_face_binding(None)
    vault.lock()
    with pytest.raises(VaultError, match="revoked"):
        unlock_face(vault.path)


def test_copied_setup_rejected_for_other_vault_and_profile(vault, tmp_path):
    enroll(vault)
    other = create_vault(tmp_path / "other.json", MASTER, kdf_overrides=KDF)
    face.envelope_path(other.path).write_bytes(face.envelope_path(vault.path).read_bytes())
    with pytest.raises(face.FaceError):
        face.load_face_material(other.path, PROFILE, protector_factory=protector)
    with pytest.raises(face.FaceError):
        face.load_face_material(vault.path, "another-profile", protector_factory=protector)
    other.lock()


def test_master_password_change_revokes_old_camera_setup(vault, monkeypatch):
    import localvault.vault as vault_module
    monkeypatch.setattr(vault_module, "DEFAULT_KDF", {**vault_module.DEFAULT_KDF, **KDF})
    enroll(vault)
    vault.change_master_password(MASTER, NEW_MASTER)
    assert not vault.face_binding()
    assert not face.has_envelope(vault.path, PROFILE)
    vault.lock()
    with pytest.raises(InvalidMasterPassword):
        unlock_vault(vault.path, MASTER)
    check = unlock_vault(vault.path, NEW_MASTER); check.lock()


def test_disable_revokes_binding_and_removes_sidecar(vault):
    enroll(vault)
    old = face.envelope_path(vault.path).read_bytes()
    face.disable_enrollment(vault)
    assert not vault.face_binding()
    assert not face.envelope_path(vault.path).exists()
    face.envelope_path(vault.path).write_bytes(old)
    vault.lock()
    with pytest.raises((face.FaceError, VaultError)):
        unlock_face(vault.path)
    check = unlock_vault(vault.path, MASTER); check.lock()


def test_sidecar_write_failure_rolls_back_opt_in(vault, monkeypatch):
    prepared = face.prepare_enrollment(
        PROFILE, vault.unlock_context(), embeddings(), protector_factory=protector
    )
    monkeypatch.setattr(face, "atomic_write_json", lambda *_: (_ for _ in ()).throw(OSError("disk full")))
    with pytest.raises(OSError):
        face.commit_enrollment(vault, prepared)
    assert not any(prepared.secret)
    assert not vault.face_binding()
    assert not face.envelope_path(vault.path).exists()


def test_failed_attempt_throttling_and_clear():
    record_id = "a" * 32
    face.clear_failures(record_id)
    face.record_failure(record_id, now=100.0)
    face.record_failure(record_id, now=101.0)
    face.check_attempt(record_id, now=102.0)
    face.record_failure(record_id, now=102.0)
    with pytest.raises(face.FaceError, match="Try again"):
        face.check_attempt(record_id, now=103.0)
    face.clear_failures(record_id)
    face.check_attempt(record_id, now=103.0)
