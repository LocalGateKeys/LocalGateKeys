"""L-4 (audit 2026-10-24): a revoked camera sidecar must not keep opening the vault."""
from __future__ import annotations

import json
from pathlib import Path

import pytest
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from localvault import face_unlock as face
from localvault import vault as V
from localvault.app import unlock_methods
from localvault.profiles import ProfileManager
from tests.test_app_unlock_methods import MASTER as APP_MASTER
from tests.test_app_unlock_methods import env  # noqa: F401 - pytest fixture
from tests.test_face_unlock import KDF, MASTER, PROFILE, embeddings, protector


@pytest.fixture(autouse=True)
def cheap_kdf(monkeypatch):
    monkeypatch.setattr(V, "DEFAULT_KDF", {**V.DEFAULT_KDF, **KDF})
    V._reset_unlock_throttle_state_for_tests()
    yield
    V._reset_unlock_throttle_state_for_tests()


@pytest.fixture
def vault(tmp_path: Path):
    session = V.create_vault(tmp_path / "vault.json", MASTER, kdf_overrides=KDF)
    session.upsert_web(origin="https://example.test", username="local-user", password="Local-Site-Secret")
    yield session
    if session.is_unlocked:
        session.lock()


def _enroll(session) -> None:
    prepared = face.prepare_enrollment(PROFILE, session.unlock_context(), embeddings(), protector_factory=protector)
    face.commit_enrollment(session, prepared)


def _key_from_sidecar(record: dict) -> bytes:
    """What an attacker signed in to the Windows account gets from a kept sidecar copy."""
    secret = protector().unprotect(base64_decode(record["protected_secret"]), face._entropy(record))
    return AESGCM(bytes(secret)).decrypt(base64_decode(record["nonce"]), base64_decode(record["ciphertext"]),
                                         face._context(record))


def base64_decode(value: str) -> bytes:
    import base64

    return base64.b64decode(value)


def _opens_current(path: Path, key: bytes) -> bool:
    header = json.loads(path.read_text())
    try:
        AESGCM(key).decrypt(V._b64d(header["cipher"]["nonce"]), V._b64d(header["cipher"]["ciphertext"]),
                            V._aad(header))
        return True
    except InvalidTag:
        return False


def test_disable_with_password_rotates_so_an_old_sidecar_copy_is_useless(vault) -> None:
    _enroll(vault)
    stolen = json.loads(face.envelope_path(vault.path).read_text())
    assert _opens_current(vault.path, _key_from_sidecar(stolen))
    generation = vault._header["key_generation"]
    result = face.disable_enrollment(vault, MASTER)
    assert result is not None and vault._header["key_generation"] == generation + 1
    assert not vault.face_binding() and not face.envelope_path(vault.path).exists()
    vault.upsert_web(origin="https://after.example", username="u", password="added-after-disable")
    vault.lock()
    assert not _opens_current(vault.path, _key_from_sidecar(stolen))
    check = V.unlock_vault(vault.path, MASTER)
    assert len(check.summaries()) == 2
    check.lock()


def test_disable_without_setup_does_not_rotate(vault) -> None:
    generation = vault._header.get("key_generation")
    assert face.disable_enrollment(vault, MASTER) is None
    assert vault._header.get("key_generation") == generation


def test_disable_with_wrong_password_keeps_camera_unlock(vault) -> None:
    _enroll(vault)
    with pytest.raises(V.InvalidMasterPassword):
        face.disable_enrollment(vault, "not the master password")
    assert vault.face_binding()


def test_deleted_profile_archive_has_no_camera_sidecar(tmp_path: Path) -> None:
    profiles = ProfileManager(tmp_path / "data")
    first = profiles.ensure_profile()
    profiles.create_profile("Second")
    vault_path = profiles.vault_path(first.id)
    session = V.create_vault(vault_path, MASTER, kdf_overrides=KDF)
    _enroll(session)
    session.lock()
    assert face.envelope_path(vault_path).exists()
    profiles.delete_profile(first.id)
    archived = list((tmp_path / "data" / "DeletedProfiles").glob(f"*-{first.id}"))
    assert len(archived) == 1
    assert (archived[0] / "vault.json").exists()
    assert not (archived[0] / "vault.face.json").exists()


def test_camera_consent_states_the_windows_password_strength() -> None:
    assert "only as strong as your Windows account password" in unlock_methods.FACE_CONFIRM


def test_settings_disable_rotates_and_reports(env) -> None:  # noqa: F811 - the imported fixture
    session = env.controller.session
    session.set_face_binding("a" * 32)
    generation = session._header.get("key_generation")
    env.port.passwords = [APP_MASTER]
    message = env.face.disable()["message"]
    assert message.startswith("Camera verification removed.")
    assert session._header.get("key_generation") == (generation or 1) + 1
    assert not session.face_binding()
    assert env.port.asked == ["Remove camera verification", "Remove camera verification?"]


def test_settings_disable_wrong_password_changes_nothing(env) -> None:  # noqa: F811 - the imported fixture
    from localvault.api.result import ApiError

    session = env.controller.session
    session.set_face_binding("a" * 32)
    env.port.passwords = ["not the master password"]
    with pytest.raises(ApiError) as refused:
        env.face.disable()
    assert refused.value.code == "not_authorized" and session.face_binding() == "a" * 32


def test_disable_keeps_the_key_and_the_recovery_phrase_when_one_exists(vault) -> None:
    phrase = vault.create_recovery_phrase(MASTER)
    _enroll(vault)
    generation = vault._header["key_generation"]
    assert face.rotation_on_disable(vault) is False
    assert face.disable_enrollment(vault, MASTER) is None
    assert vault._header["key_generation"] == generation
    assert not vault.face_binding() and not face.envelope_path(vault.path).exists()
    vault.lock()
    opened = V.unlock_with_recovery_phrase(vault.path, phrase)
    assert opened.is_unlocked
    opened.lock()


def test_settings_disable_with_a_phrase_explains_the_kept_key(env) -> None:  # noqa: F811 - the imported fixture
    session = env.controller.session
    env.port.passwords = [APP_MASTER]
    session.create_recovery_phrase(APP_MASTER)
    session.set_face_binding("a" * 32)
    generation = session._header.get("key_generation")
    env.port.passwords = [APP_MASTER]
    message = env.face.disable()["message"]
    assert session._header.get("key_generation") == generation
    assert session.has_recovery_phrase() and not session.face_binding()
    assert unlock_methods.FACE_DISABLE_KEPT_KEY_NOTE in message
    assert "Windows account or its password" in message
