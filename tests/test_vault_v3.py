"""Vault format v3: key hierarchy, recovery phrase, authenticated rollback anchor, throttling."""
from __future__ import annotations

import hashlib
import os
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

import localvault.vault as vault_module
from localvault.config import atomic_write_json, read_json
from localvault.vault import (
    DEFAULT_KDF,
    FORMAT_VERSION,
    InvalidMasterPassword,
    RecoveryPhraseError,
    RollbackRequiresConfirmation,
    UnlockThrottled,
    VaultError,
    _aad,
    _b64e,
    _canonical_json,
    _derive_key,
    create_vault,
    remaining_backoff_seconds,
    unlock_vault,
    unlock_with_recovery_phrase,
    vault_migration_journal_path,
)

TEST_KDF = {"time_cost": 1, "memory_cost_kib": 8192, "parallelism": 1, "hash_len": 32}
MASTER = "correct horse battery staple"
NEW_MASTER = "replacement master password 0002"


@pytest.fixture(autouse=True)
def _fast_default_kdf(monkeypatch):
    monkeypatch.setattr(vault_module, "DEFAULT_KDF", {**DEFAULT_KDF, **TEST_KDF})
    vault_module._reset_unlock_throttle_state_for_tests()
    yield
    vault_module._reset_unlock_throttle_state_for_tests()


def _write_v2_vault(path: Path, password: str, payload_extra: dict | None = None) -> bytearray:
    """Hand-build a format-2 vault whose Argon2 output is the catalog key."""
    kdf = {**DEFAULT_KDF, **TEST_KDF, "salt": _b64e(os.urandom(16))}
    header = {
        "version": 2,
        "format": "localgatekeys-vault-v2",
        "catalog": vault_module.CATALOG_FORMAT,
        "kdf": kdf,
        "cipher": {"name": "aes-256-gcm", "nonce": "", "ciphertext": ""},
    }
    payload = vault_module._empty_payload()
    payload["generation"] = 3
    payload.update(payload_extra or {})
    nonce = os.urandom(12)
    header["cipher"]["nonce"] = _b64e(nonce)
    key = _derive_key(password, kdf)
    header["cipher"]["ciphertext"] = _b64e(AESGCM(bytes(key)).encrypt(nonce, _canonical_json(payload), _aad(header)))
    atomic_write_json(path, header)
    return key


# --------------------------------------------------------------------------
# Format v3 and key hierarchy
# --------------------------------------------------------------------------

def test_new_vault_uses_format_v3_with_wrapped_random_data_key(tmp_path: Path) -> None:
    path = tmp_path / "vault.json"
    session = create_vault(path, MASTER, kdf_overrides=TEST_KDF)
    document = read_json(path)
    assert document["version"] == FORMAT_VERSION == 3
    assert document["format"] == "localgatekeys-vault-v3"
    assert document["catalog_version"] == 2
    assert len(document["vault_id"]) == 32
    assert set(document["wrappers"]) == {"password"}
    assert document["kdf"]["name"] == "argon2id"
    # The Argon2 output is a KEK now: it must not be the catalog key.
    kek = _derive_key(MASTER, document["kdf"])
    assert bytes(kek) != bytes(session._key)
    assert len(session._key) == 32
    session.lock()
    reopened = unlock_vault(path, MASTER)
    assert reopened.is_unlocked
    reopened.lock()


def test_wrapper_metadata_is_authenticated(tmp_path: Path) -> None:
    path = tmp_path / "vault.json"
    create_vault(path, MASTER, kdf_overrides=TEST_KDF).lock()
    document = read_json(path)
    document["kdf"]["memory_cost_kib"] = 16384  # still in range, but changes the wrapper AAD
    atomic_write_json(path, document)
    with pytest.raises(InvalidMasterPassword):
        unlock_vault(path, MASTER)
    document = read_json(path)
    document["kdf"]["memory_cost_kib"] = 8192
    document["key_generation"] = 7
    atomic_write_json(path, document)
    with pytest.raises(InvalidMasterPassword):
        unlock_vault(path, MASTER)


def test_header_parsing_is_bounded(tmp_path: Path) -> None:
    path = tmp_path / "vault.json"
    create_vault(path, MASTER, kdf_overrides=TEST_KDF).lock()
    document = read_json(path)
    document["wrappers"]["extra"] = {"nonce": "A" * 20_000}
    atomic_write_json(path, document)
    with pytest.raises(VaultError):
        unlock_vault(path, MASTER)
    document = read_json(path)
    document["wrappers"]["password"]["ciphertext"] = _b64e(b"x" * 4096)
    atomic_write_json(path, document)
    with pytest.raises(VaultError):
        unlock_vault(path, MASTER)


def test_password_change_rotates_the_data_key(tmp_path: Path) -> None:
    path = tmp_path / "vault.json"
    session = create_vault(path, MASTER, kdf_overrides=TEST_KDF)
    entry = session.upsert_web(origin="https://example.com", username="a", password="pw-one")
    before = read_json(path)
    data_key = bytes(session._key)
    result = session.change_master_password(MASTER, NEW_MASTER)
    after = read_json(path)
    assert bytes(session._key) != data_key  # SEC-V12: old password + old copy cannot open the new vault
    assert after["kdf"]["salt"] != before["kdf"]["salt"]
    assert after["key_generation"] == before["key_generation"] + 1 == result["key_generation"]
    assert after["vault_id"] == before["vault_id"]
    assert result["recovery_phrase_invalidated"] is False
    new_key = bytes(session._key)
    session.lock()
    with pytest.raises(InvalidMasterPassword):
        unlock_vault(path, MASTER)
    reopened = unlock_vault(path, NEW_MASTER)
    assert reopened.get_entry(entry)["password"] == "pw-one"
    assert bytes(reopened._key) == new_key
    assert reopened.rollback_anchor_generation() == read_json(path)["generation"]
    reopened.lock()


def test_password_change_keeps_recovery_phrase_only_when_supplied(tmp_path: Path) -> None:
    path = tmp_path / "vault.json"
    session = create_vault(path, MASTER, kdf_overrides=TEST_KDF)
    phrase = session.create_recovery_phrase(MASTER)
    result = session.change_master_password(MASTER, NEW_MASTER, recovery_phrase=phrase)
    assert result["recovery_phrase_invalidated"] is False and session.has_recovery_phrase()
    result = session.change_master_password(NEW_MASTER, MASTER)
    assert result["recovery_phrase_invalidated"] is True and not session.has_recovery_phrase()
    session.lock()
    with pytest.raises(RecoveryPhraseError):
        unlock_with_recovery_phrase(path, phrase)
    unlock_vault(path, MASTER).lock()


def test_password_change_crash_before_commit_leaves_old_vault_openable(tmp_path: Path, monkeypatch) -> None:
    """The anchor is re-minted for both keys before the commit, so a crash in between is recoverable."""
    path = tmp_path / "vault.json"
    session = create_vault(path, MASTER, kdf_overrides=TEST_KDF)
    session.upsert_web(origin="https://example.com", username="a", password="pw-one")

    def crash(*_args, **_kwargs):
        raise KeyboardInterrupt("simulated crash before the vault commit")

    real_write = vault_module._write_generation_anchor
    monkeypatch.setattr(session, "_commit_header_change", crash)
    monkeypatch.setattr(vault_module, "_write_generation_anchor", _no_old_anchor_restore(vault_module))
    with pytest.raises(KeyboardInterrupt):
        session.change_master_password(MASTER, NEW_MASTER)
    monkeypatch.setattr(vault_module, "_write_generation_anchor", real_write)
    assert "previous" in read_json(vault_module._generation_anchor_path(path))
    session.lock()
    reopened = unlock_vault(path, MASTER)
    assert len(reopened.find_web("https://example.com")) == 1
    reopened.lock()
    assert "previous" not in read_json(vault_module._generation_anchor_path(path))


def _no_old_anchor_restore(module):
    """Let the dual anchor be written, then drop the failure-path restore (as a crash would)."""
    real = module._write_generation_anchor

    def write(path, generation, anchor_key, vault_id="", **kwargs):
        if kwargs.get("previous_key") is not None:
            real(path, generation, anchor_key, vault_id, **kwargs)

    return write


def test_rotate_data_key_reencrypts_and_purges_rolling_backups(tmp_path: Path) -> None:
    path = tmp_path / "vault.json"
    backups = tmp_path / "Backups"
    session = create_vault(path, MASTER, kdf_overrides=TEST_KDF, backup_dir=backups, backup_count=10)
    entry = session.upsert_web(origin="https://example.com", username="a", password="pw-one")
    session.upsert_web(origin="https://example.org", username="b", password="pw-two")
    assert len(list(backups.glob("vault-*.json"))) >= 1
    old_key = bytes(session._key)
    old_generation = read_json(path)["key_generation"]
    result = session.rotate_data_key(MASTER)
    assert bytes(session._key) != old_key
    assert read_json(path)["key_generation"] == old_generation + 1
    assert result["purged_backups"] >= 1
    # Only backups written with the new data key remain.
    for backup in backups.glob("vault-*.json"):
        assert read_json(backup)["key_generation"] == old_generation + 1
    with pytest.raises(InvalidMasterPassword):
        session.rotate_data_key("wrong password here")
    session.lock()
    reopened = unlock_vault(path, MASTER)
    assert reopened.get_entry(entry)["password"] == "pw-one"
    reopened.lock()


def test_rotate_requires_password_and_invalidates_recovery_and_biometric_wrappers(tmp_path: Path) -> None:
    path = tmp_path / "vault.json"
    session = create_vault(path, MASTER, kdf_overrides=TEST_KDF)
    phrase = session.create_recovery_phrase(MASTER)
    session.set_hello_binding("a" * 32)
    result = session.rotate_data_key(MASTER)
    assert result["recovery_phrase_invalidated"] is True
    assert "hello" in result["reenroll_required"]
    assert not session.has_recovery_phrase()
    assert session.hello_binding() == ""
    session.lock()
    with pytest.raises(RecoveryPhraseError):
        unlock_with_recovery_phrase(path, phrase)


def test_lock_zeroes_the_data_key_buffer(tmp_path: Path) -> None:
    path = tmp_path / "vault.json"
    session = create_vault(path, MASTER, kdf_overrides=TEST_KDF)
    buffer = session._key
    assert any(buffer)
    session.lock()
    assert not any(buffer) and session._key is None and not session.is_unlocked


def test_session_never_keeps_an_immutable_copy_of_the_data_key(tmp_path: Path) -> None:
    path = tmp_path / "vault.json"
    session = create_vault(path, MASTER, kdf_overrides=TEST_KDF)
    session.upsert_web(origin="https://example.com", username="a", password="pw")
    session.verify_master_password(MASTER)
    session.change_master_password(MASTER, MASTER + "-2")
    key = bytes(session._key)

    def holds_key(value: object, depth: int = 0) -> bool:
        if isinstance(value, (bytes, bytearray)) and value is not session._key:
            return bytes(value) == key
        if depth > 3:
            return False
        if isinstance(value, dict):
            return any(holds_key(item, depth + 1) for item in value.values())
        if isinstance(value, (list, tuple, set)):
            return any(holds_key(item, depth + 1) for item in value)
        return False

    assert isinstance(session._key, bytearray)
    assert not any(holds_key(value) for value in vars(session).values())
    assert not holds_key(session._header)
    session.lock()


def test_wrong_password_does_not_leave_key_material(tmp_path: Path) -> None:
    path = tmp_path / "vault.json"
    create_vault(path, MASTER, kdf_overrides=TEST_KDF).lock()
    seen = []
    original = vault_module._unwrap_key

    def spy(wrapping_key, *args, **kwargs):
        seen.append(wrapping_key)
        return original(wrapping_key, *args, **kwargs)

    vault_module._unwrap_key = spy
    try:
        with pytest.raises(InvalidMasterPassword):
            unlock_vault(path, "definitely not the password")
    finally:
        vault_module._unwrap_key = original
    assert seen and all(not any(key) for key in seen)  # KEK wiped after the failed unwrap


# --------------------------------------------------------------------------
# Forward migration from v2
# --------------------------------------------------------------------------

def test_v2_vault_is_upgraded_to_v3_on_first_unlock_with_journal(tmp_path: Path) -> None:
    path = tmp_path / "vault.json"
    old_key = _write_v2_vault(path, MASTER)
    session = unlock_vault(path, MASTER, backup_dir=tmp_path / "Backups")
    document = read_json(path)
    assert document["version"] == 3 and document["catalog_version"] == 2
    assert bytes(session._key) == bytes(old_key)  # inherited so sidecars stay convertible
    assert session.catalog_version == 2
    result = session.last_envelope_upgrade_result
    assert result["outcome"] == "upgraded" and result["from_version"] == 2
    assert Path(result["backup_path"]).is_file()
    assert not vault_migration_journal_path(path).exists()
    assert session.upsert_web(origin="https://example.com", username="a", password="pw")
    session.lock()
    reopened = unlock_vault(path, MASTER)
    assert reopened.last_envelope_upgrade_result is None
    assert len(reopened.find_web("https://example.com")) == 1
    reopened.lock()


def test_v2_upgrade_failure_restores_source_and_still_unlocks(tmp_path: Path) -> None:
    from localvault.config import atomic_write_faults

    path = tmp_path / "vault.json"
    _write_v2_vault(path, MASTER)
    source = path.read_bytes()

    def fail(stage: str, target: Path) -> None:
        if stage == "after_replace" and target.name == "vault.json":
            raise OSError("synthetic publication fault")

    with atomic_write_faults(fail):
        session = unlock_vault(path, MASTER, backup_dir=tmp_path / "Backups")
    assert session.is_unlocked
    assert path.read_bytes() == source
    assert not vault_migration_journal_path(path).exists()
    assert session.last_envelope_upgrade_result["outcome"] == "failed"
    session.lock()
    reopened = unlock_vault(path, MASTER, backup_dir=tmp_path / "Backups")
    assert read_json(path)["version"] == 3
    reopened.lock()


def test_unknown_future_version_is_rejected(tmp_path: Path) -> None:
    path = tmp_path / "vault.json"
    create_vault(path, MASTER, kdf_overrides=TEST_KDF).lock()
    document = read_json(path)
    document["version"] = 4
    atomic_write_json(path, document)
    with pytest.raises(VaultError, match="Unsupported vault format version"):
        unlock_vault(path, MASTER)


# --------------------------------------------------------------------------
# Recovery phrase
# --------------------------------------------------------------------------

def test_bip39_word_list_is_intact() -> None:
    words = vault_module.bip39_words()
    assert len(words) == 2048 and words[0] == "abandon" and words[-1] == "zoo"
    data = ("\n".join(words) + "\n").encode("utf-8")
    assert hashlib.sha256(data).hexdigest() == vault_module.BIP39_ENGLISH_SHA256


def test_recovery_phrase_roundtrip_and_new_master_password(tmp_path: Path) -> None:
    path = tmp_path / "vault.json"
    session = create_vault(path, MASTER, kdf_overrides=TEST_KDF)
    entry = session.upsert_web(origin="https://example.com", username="a", password="pw-one")
    assert not session.has_recovery_phrase()
    phrase = session.create_recovery_phrase(MASTER)
    words = phrase.split()
    assert len(words) == 24 and all(word in vault_module.bip39_words() for word in words)
    assert session.has_recovery_phrase()
    assert vault_module.recovery_phrase_enrolled(path)
    raw = path.read_text(encoding="utf-8")
    # Single BIP39 words such as "salt" or "version" can legitimately occur in
    # header keys; the phrase itself and any three consecutive words must not.
    assert phrase not in raw
    assert all(" ".join(words[i:i + 3]) not in raw for i in range(len(words) - 2))
    session.lock()

    recovered = unlock_with_recovery_phrase(path, "  " + phrase.upper().replace(" ", "   ") + "\n")
    assert recovered.recovery_unlocked
    assert recovered.get_entry(entry)["password"] == "pw-one"
    recovered.set_master_password_after_recovery(NEW_MASTER)
    recovered.lock()
    with pytest.raises(InvalidMasterPassword):
        unlock_vault(path, MASTER)
    reopened = unlock_vault(path, NEW_MASTER)
    assert reopened.has_recovery_phrase()
    with pytest.raises(VaultError):
        reopened.set_master_password_after_recovery("not allowed without recovery")
    reopened.lock()
    # The phrase survives a password change: it wraps the data key, not the KEK.
    again = unlock_with_recovery_phrase(path, phrase)
    again.lock()


def test_recovery_phrase_rejects_wrong_or_malformed_input(tmp_path: Path) -> None:
    path = tmp_path / "vault.json"
    session = create_vault(path, MASTER, kdf_overrides=TEST_KDF)
    with pytest.raises(InvalidMasterPassword):
        session.create_recovery_phrase("not the master password")
    phrase = session.create_recovery_phrase(MASTER)
    session.lock()
    words = phrase.split()
    wrong = list(words)
    wrong[3] = "zoo" if wrong[3] != "zoo" else "zebra"
    for bad in (" ".join(wrong), " ".join(words[:23]), " ".join(words + ["abandon"]),
                "notaword " + " ".join(words[1:]), ""):
        with pytest.raises(RecoveryPhraseError):
            unlock_with_recovery_phrase(path, bad)
    other = create_vault(tmp_path / "other.json", MASTER, kdf_overrides=TEST_KDF)
    other.lock()
    with pytest.raises(RecoveryPhraseError):
        unlock_with_recovery_phrase(other.path, phrase)


def test_regenerating_recovery_phrase_invalidates_the_previous_one(tmp_path: Path) -> None:
    path = tmp_path / "vault.json"
    session = create_vault(path, MASTER, kdf_overrides=TEST_KDF)
    first = session.create_recovery_phrase(MASTER)
    second = session.create_recovery_phrase(MASTER)
    assert first != second
    session.remove_recovery_phrase(MASTER)
    assert not session.has_recovery_phrase()
    third = session.create_recovery_phrase(MASTER)
    session.lock()
    for stale in (first, second):
        with pytest.raises(RecoveryPhraseError):
            unlock_with_recovery_phrase(path, stale)
    unlock_with_recovery_phrase(path, third).lock()


def test_recovery_phrase_checksum_is_enforced() -> None:
    words = vault_module.bip39_words()
    entropy = os.urandom(32)
    phrase = vault_module.phrase_from_entropy(entropy)
    assert vault_module.entropy_from_phrase(phrase) == entropy
    tokens = phrase.split()
    tokens[-1] = words[(words.index(tokens[-1]) + 1) % 2048]
    with pytest.raises(RecoveryPhraseError):
        vault_module.entropy_from_phrase(" ".join(tokens))


# --------------------------------------------------------------------------
# Rollback anchor
# --------------------------------------------------------------------------

def _anchor_path(path: Path) -> Path:
    return vault_module._generation_anchor_path(path)


def test_rollback_anchor_is_authenticated(tmp_path: Path) -> None:
    path = tmp_path / "vault.json"
    session = create_vault(path, MASTER, kdf_overrides=TEST_KDF)
    session.upsert_web(origin="https://example.com", username="a", password="pw")
    session.lock()
    anchor = read_json(_anchor_path(path))
    assert anchor["version"] == 1 and type(anchor["generation"]) is int
    assert anchor["anchor"]["scheme"].startswith("hkdf-hmac-sha256")
    assert anchor["anchor"]["mac"]
    anchor["generation"] = 0  # try to let an older file through
    atomic_write_json(_anchor_path(path), anchor)
    with pytest.raises(VaultError, match="rollback-protection metadata failed authentication"):
        unlock_vault(path, MASTER)


def test_rollback_of_the_vault_file_is_still_detected(tmp_path: Path) -> None:
    path = tmp_path / "vault.json"
    session = create_vault(path, MASTER, kdf_overrides=TEST_KDF)
    session.upsert_web(origin="https://example.com", username="a", password="pw")
    older = path.read_bytes()
    session.upsert_web(origin="https://example.org", username="b", password="pw")
    session.lock()
    path.write_bytes(older)
    with pytest.raises(VaultError, match="rollback detected"):
        unlock_vault(path, MASTER)


def test_legacy_plaintext_anchor_is_read_once_and_upgraded(tmp_path: Path) -> None:
    path = tmp_path / "vault.json"
    _write_v2_vault(path, MASTER)
    # A legacy anchor that is newer than a v2 file is still a rollback.
    atomic_write_json(_anchor_path(path), {"version": 1, "generation": 50})
    with pytest.raises(VaultError, match="rollback detected"):
        unlock_vault(path, MASTER, backup_dir=tmp_path / "Backups")
    atomic_write_json(_anchor_path(path), {"version": 1, "generation": 3})
    session = unlock_vault(path, MASTER, backup_dir=tmp_path / "Backups")
    assert session.last_envelope_upgrade_result["outcome"] == "upgraded"
    assert not session.rollback_anchor_missing
    session.lock()
    upgraded = read_json(_anchor_path(path))
    assert upgraded["generation"] >= 3 and "anchor" in upgraded
    unlock_vault(path, MASTER).lock()


def test_plaintext_anchor_next_to_a_v3_vault_is_refused(tmp_path: Path) -> None:
    """SEC-V14: v3 vaults have always had MAC anchors, so the plaintext form is a downgrade."""
    path = tmp_path / "vault.json"
    session = create_vault(path, MASTER, kdf_overrides=TEST_KDF)
    session.upsert_web(origin="https://example.com", username="a", password="pw")
    session.lock()
    generation = read_json(_anchor_path(path))["generation"]
    atomic_write_json(_anchor_path(path), {"version": 1, "generation": generation})
    with pytest.raises(VaultError, match="downgraded"):
        unlock_vault(path, MASTER)


def test_missing_anchor_is_reported_and_reminted(tmp_path: Path) -> None:
    """SEC-V14: the encrypted payload records that an anchor is required."""
    path = tmp_path / "vault.json"
    session = create_vault(path, MASTER, kdf_overrides=TEST_KDF)
    session.upsert_web(origin="https://example.com", username="a", password="pw")
    assert session._payload[vault_module.ANCHOR_REQUIRED_KEY] is True
    session.lock()
    clean = unlock_vault(path, MASTER)
    assert clean.rollback_anchor_missing is False
    clean.lock()
    _anchor_path(path).unlink()
    reopened = unlock_vault(path, MASTER)
    assert reopened.rollback_anchor_missing is True
    reopened.lock()
    assert "anchor" in read_json(_anchor_path(path))
    again = unlock_vault(path, MASTER)
    assert again.rollback_anchor_missing is False
    again.lock()


def test_planted_migration_journal_cannot_lower_the_anchor(tmp_path: Path) -> None:
    """SEC-V25: an unauthenticated journal pointing at an old copy is discarded, not restored."""
    import hashlib as _hashlib

    path = tmp_path / "vault.json"
    session = create_vault(path, MASTER, kdf_overrides=TEST_KDF)
    session.upsert_web(origin="https://example.com", username="a", password="old")
    older = path.read_bytes()
    older_generation = read_json(path)["generation"]
    session.upsert_web(origin="https://example.org", username="b", password="new")
    session.lock()
    current = path.read_bytes()
    anchor_before = _anchor_path(path).read_bytes()
    planted = tmp_path / "Backups" / "migration-v2-1.json"
    planted.parent.mkdir()
    planted.write_bytes(older)
    journal = {
        "version": vault_module.VAULT_MIGRATION_JOURNAL_VERSION, "operation": "envelope-v2-to-v3",
        "status": "publishing", "vault_path": str(path.resolve()), "backup_path": str(planted.resolve()),
        "source_sha256": "0" * 64, "backup_sha256": _hashlib.sha256(older).hexdigest(),
        "source_generation": older_generation, "source_anchor": None,
    }
    atomic_write_json(vault_migration_journal_path(path), journal)
    reopened = unlock_vault(path, MASTER)
    assert len(reopened.find_web("https://example.org")) == 1
    reopened.lock()
    assert not vault_migration_journal_path(path).exists()
    assert path.read_bytes() == current and _anchor_path(path).read_bytes() == anchor_before
    # Even a journal that lies about its source generation cannot remove the anchor.
    atomic_write_json(vault_migration_journal_path(path), {**journal, "source_generation": 10**6})
    with pytest.raises(VaultError, match="rollback detected"):
        unlock_vault(path, MASTER)
    assert _anchor_path(path).read_bytes() == anchor_before


def test_verified_restore_of_an_older_backup_requires_confirmation(tmp_path: Path) -> None:
    from localvault.backup import export_encrypted_backup, restore_verified_backup

    profile = tmp_path / "profile"
    profile.mkdir()
    path = profile / "vault.json"
    session = create_vault(path, MASTER, kdf_overrides=TEST_KDF)
    session.upsert_web(origin="https://example.com", username="a", password="pw")
    session.lock()
    backup = tmp_path / "older.lgk"
    export_encrypted_backup(backup, vault_file=path, settings_file=None, profile_name="P",
                            backup_password="independent backup password", kdf_overrides=TEST_KDF)
    session = unlock_vault(path, MASTER)
    session.upsert_web(origin="https://example.org", username="b", password="pw")
    session.upsert_web(origin="https://example.net", username="c", password="pw")
    session.lock()
    newest = path.read_bytes()
    with pytest.raises(RollbackRequiresConfirmation) as info:
        restore_verified_backup(backup, vault_file=path, settings_file=None,
                                backup_password="independent backup password", vault_password=MASTER,
                                replace=True)
    assert info.value.restored_generation < info.value.current_generation
    assert path.read_bytes() == newest  # nothing was replaced
    result = restore_verified_backup(backup, vault_file=path, settings_file=None,
                                     backup_password="independent backup password", vault_password=MASTER,
                                     replace=True, allow_rollback=True)
    assert result["verified"] is True
    restored = unlock_vault(path, MASTER)
    assert len(restored.summaries()) == 1
    restored.lock()


def test_legacy_restore_never_resets_the_anchor(tmp_path: Path) -> None:
    import warnings

    from localvault.backup import export_encrypted_backup, restore_encrypted_backup

    path = tmp_path / "vault.json"
    session = create_vault(path, MASTER, kdf_overrides=TEST_KDF)
    session.upsert_web(origin="https://example.com", username="a", password="pw")
    session.lock()
    backup = tmp_path / "older.lgk"
    export_encrypted_backup(backup, vault_file=path, settings_file=None, profile_name="P",
                            backup_password="independent backup password", kdf_overrides=TEST_KDF)
    session = unlock_vault(path, MASTER)
    session.upsert_web(origin="https://example.org", username="b", password="pw")
    session.lock()
    anchor_before = _anchor_path(path).read_bytes()
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", DeprecationWarning)
        restore_encrypted_backup(backup, vault_file=path, settings_file=None,
                                 backup_password="independent backup password")
    assert _anchor_path(path).read_bytes() == anchor_before
    with pytest.raises(VaultError, match="rollback detected"):
        unlock_vault(path, MASTER)


# --------------------------------------------------------------------------
# Unlock throttling
# --------------------------------------------------------------------------

class FakeClock:
    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now


@pytest.fixture
def clock(monkeypatch):
    fake = FakeClock()
    monkeypatch.setattr(vault_module, "_monotonic", fake)
    return fake


def test_unlock_backoff_after_five_failures_doubles_to_sixty_seconds(tmp_path: Path, clock: FakeClock) -> None:
    path = tmp_path / "vault.json"
    create_vault(path, MASTER, kdf_overrides=TEST_KDF).lock()
    for _ in range(5):
        with pytest.raises(InvalidMasterPassword):
            unlock_vault(path, "wrong password attempt")
    assert remaining_backoff_seconds(path) == pytest.approx(2.0)
    with pytest.raises(UnlockThrottled) as info:
        unlock_vault(path, MASTER)  # even the right password waits
    assert info.value.retry_after == pytest.approx(2.0)
    expected = [2.0, 4.0, 8.0, 16.0, 32.0, 60.0, 60.0]
    for delay in expected[1:]:
        clock.now += remaining_backoff_seconds(path)
        with pytest.raises(InvalidMasterPassword):
            unlock_vault(path, "wrong password attempt")
        assert remaining_backoff_seconds(path) == pytest.approx(delay)
    clock.now += 60.0
    assert remaining_backoff_seconds(path) == 0.0
    session = unlock_vault(path, MASTER)
    session.lock()
    assert remaining_backoff_seconds(path) == 0.0
    with pytest.raises(InvalidMasterPassword):
        unlock_vault(path, "wrong password attempt")
    assert remaining_backoff_seconds(path) == 0.0  # counter was reset by the success


def test_throttle_state_is_persisted_and_mac_protected(tmp_path: Path, clock: FakeClock) -> None:
    path = tmp_path / "vault.json"
    create_vault(path, MASTER, kdf_overrides=TEST_KDF).lock()
    for _ in range(6):
        clock.now += 100
        with pytest.raises(InvalidMasterPassword):
            unlock_vault(path, "wrong password attempt")
    state_path = vault_module._unlock_throttle_path(path)
    state = read_json(state_path)
    assert state["failures"] == 6 and state["mac"]
    vault_module._reset_unlock_throttle_state_for_tests()  # simulate a process restart
    assert remaining_backoff_seconds(path) > 0
    state["failures"] = 0
    atomic_write_json(state_path, state)
    vault_module._reset_unlock_throttle_state_for_tests()
    # A forged counter fails closed to the maximum delay instead of resetting.
    assert remaining_backoff_seconds(path) == pytest.approx(60.0)


def test_verify_master_password_is_throttled_without_touching_disk(tmp_path: Path, clock: FakeClock) -> None:
    path = tmp_path / "vault.json"
    session = create_vault(path, MASTER, kdf_overrides=TEST_KDF)
    on_disk = path.read_bytes()
    for _ in range(5):
        with pytest.raises(InvalidMasterPassword):
            session.verify_master_password("wrong password attempt")
    with pytest.raises(UnlockThrottled):
        session.verify_master_password(MASTER)
    clock.now += 2.0
    assert session.verify_master_password(MASTER) is True
    assert path.read_bytes() == on_disk
    session.lock()


def test_hello_and_face_envelopes_are_converted_at_v3_upgrade(tmp_path: Path) -> None:
    import threading

    from localvault import face_unlock as face
    from localvault import hello_unlock as hello
    from tests.test_face_unlock import PROFILE as FACE_PROFILE
    from tests.test_face_unlock import embeddings, protector
    from tests.test_hello_unlock import PROFILE, SimulatedProvider

    path = tmp_path / "vault.json"
    old_key = _write_v2_vault(path, MASTER, {"preferences": {"hello_binding": "a" * 32, "face_binding": "b" * 32}})
    header = read_json(path)
    v2_context = hashlib.sha256(_aad(header)).hexdigest()
    # Emulate a v2-era Hello enrollment: the OS key wraps a secret that wraps the v2 key.
    provider = SimulatedProvider()
    secret = bytearray(os.urandom(32))
    provider.create("a" * 32, 1)
    record = {"version": 1, "scheme": hello.SCHEME, "profile": PROFILE, "context": v2_context, "id": "a" * 32,
              "wrapped_secret": hello._encode(provider.wrap("a" * 32, secret))}
    nonce = os.urandom(12)
    record["nonce"] = hello._encode(nonce)
    record["ciphertext"] = hello._encode(AESGCM(bytes(secret)).encrypt(nonce, bytes(old_key), hello._context(record)))
    atomic_write_json(hello.envelope_path(path), record)
    # And a v2-era camera enrollment protected by the simulated DPAPI stand-in.
    face_record = {"version": 1, "scheme": face.SCHEME, "profile": FACE_PROFILE, "context": v2_context,
                   "id": "b" * 32, "model": face.MODEL_ID}
    entropy = face._entropy(face_record)
    template_plain = face._encode_templates(embeddings(), face.DEFAULT_MATCH_THRESHOLD)
    face_secret = bytearray(os.urandom(32))
    face_record["template"] = face._encode(protector().protect(template_plain, entropy, "LocalGateKeys face template"))
    face_record["protected_secret"] = face._encode(protector().protect(face_secret, entropy, "LocalGateKeys local unlock key"))
    nonce = os.urandom(12)
    face_record["nonce"] = face._encode(nonce)
    face_record["ciphertext"] = face._encode(AESGCM(bytes(face_secret)).encrypt(nonce, bytes(old_key), face._context(face_record)))
    atomic_write_json(face.envelope_path(path), face_record)

    session = unlock_vault(path, MASTER, backup_dir=tmp_path / "Backups")
    assert read_json(path)["version"] == 3
    assert session.last_envelope_upgrade_result["converted"] == ["face", "hello"]
    assert session.reenroll_required == ()
    session.lock()
    by_hello = hello.unlock_with_hello(path, PROFILE, 1, threading.Event(), provider_factory=lambda: provider)
    assert by_hello.is_unlocked
    by_hello.lock()
    material = face.load_face_material(path, FACE_PROFILE, protector_factory=protector)
    by_face = face.unlock_verified_face(material, threading.Event(), protector_factory=protector)
    assert by_face.is_unlocked
    by_face.lock()


def test_unconvertible_hello_envelope_requires_reenrollment(tmp_path: Path) -> None:
    import threading

    from localvault import hello_unlock as hello
    from localvault.windows_hello import HelloError
    from tests.test_hello_unlock import PROFILE, SimulatedProvider

    path = tmp_path / "vault.json"
    _write_v2_vault(path, MASTER, {"preferences": {"hello_binding": "a" * 32}})
    hello.envelope_path(path).write_bytes(b"{not json")
    session = unlock_vault(path, MASTER, backup_dir=tmp_path / "Backups")
    assert session.reenroll_required == ("hello",)
    assert session.hello_binding() == ""  # the stale grant was revoked inside the vault
    session.lock()
    with pytest.raises(HelloError):
        hello.unlock_with_hello(path, PROFILE, 1, threading.Event(), provider_factory=SimulatedProvider)


# --------------------------------------------------------------------------
# SecretText end to end
# --------------------------------------------------------------------------

def test_unlock_accepts_secret_text_and_leaves_it_to_the_caller(tmp_path: Path) -> None:
    from localvault.secret_text import SecretText

    path = tmp_path / "vault.json"
    create_vault(path, MASTER, kdf_overrides=TEST_KDF).lock()
    secret = SecretText.from_str(MASTER)
    before = bytes(secret.buffer)
    session = unlock_vault(path, secret)
    session.lock()
    assert bytes(secret.buffer) == before and before != bytes(len(before))
    secret.wipe()


def test_str_password_copies_are_wiped(tmp_path: Path, monkeypatch) -> None:
    from localvault.secret_text import SecretText

    path = tmp_path / "vault.json"
    create_vault(path, MASTER, kdf_overrides=TEST_KDF).lock()
    wiped: list[int] = []
    original = SecretText.wipe

    def spy(self) -> None:
        wiped.append(id(self))
        original(self)

    monkeypatch.setattr(SecretText, "wipe", spy)
    unlock_vault(path, MASTER).lock()
    assert len(wiped) == 1
    wiped.clear()
    with pytest.raises(InvalidMasterPassword):
        unlock_vault(path, "wrong master password")
    assert len(wiped) == 1


def test_v2_upgrade_runs_kdf_on_the_same_buffer(tmp_path: Path, monkeypatch) -> None:
    from localvault import secret_text

    path = tmp_path / "vault.json"
    _write_v2_vault(path, MASTER)
    seen: list[bytearray] = []
    original = secret_text.argon2id_raw

    def spy(secret, salt, **kwargs):
        seen.append(secret)
        return original(secret, salt, **kwargs)

    monkeypatch.setattr(secret_text, "argon2id_raw", spy)
    unlock_vault(path, MASTER, backup_dir=tmp_path / "Backups").lock()
    assert len(seen) >= 2 and all(buffer is seen[0] for buffer in seen)


def test_change_master_password_with_secret_text(tmp_path: Path) -> None:
    from localvault.secret_text import SecretText

    path = tmp_path / "vault.json"
    session = create_vault(path, MASTER, kdf_overrides=TEST_KDF)
    old, new = SecretText.from_str(MASTER), SecretText.from_str(NEW_MASTER)
    session.change_master_password(old, new)
    assert bytes(old.buffer) == MASTER.encode() and bytes(new.buffer) == NEW_MASTER.encode()
    session.lock()
    with pytest.raises(InvalidMasterPassword):
        unlock_vault(path, old)
    unlock_vault(path, new).lock()
    old.wipe()
    new.wipe()


def test_secret_text_length_rules_count_characters(tmp_path: Path) -> None:
    from localvault.secret_text import SecretText

    path = tmp_path / "vault.json"
    with pytest.raises(VaultError):
        create_vault(path, SecretText.from_str("é" * 11), kdf_overrides=TEST_KDF)
    session = create_vault(path, SecretText.from_str("é" * 12), kdf_overrides=TEST_KDF)  # 24 bytes
    with pytest.raises(VaultError, match="between 12 and 4096"):
        session.change_master_password("é" * 12, SecretText.from_str("x" * 4097))
    session.lock()


def test_unencodable_master_password_text_fails_with_a_fixed_message(tmp_path: Path) -> None:
    path = tmp_path / "vault.json"
    bad = "valid prefix \ud800 tail"
    with pytest.raises(VaultError) as info:
        create_vault(path, bad, kdf_overrides=TEST_KDF)
    assert str(info.value) == "Invalid master password text" and info.value.__cause__ is None
    session = create_vault(path, MASTER, kdf_overrides=TEST_KDF)
    with pytest.raises(VaultError) as info:
        session.verify_master_password(bad)
    assert str(info.value) == "Invalid master password text"
    with pytest.raises(VaultError) as info:
        session.change_master_password(MASTER, bad)
    assert str(info.value) == "Invalid master password text"
    session.lock()
    with pytest.raises(VaultError) as info:
        unlock_vault(path, bad)
    assert str(info.value) == "Invalid master password text"


def test_secret_text_through_rotation_recovery_and_backup(tmp_path: Path) -> None:
    from localvault.backup import export_encrypted_backup, restore_verified_backup, verify_encrypted_backup
    from localvault.secret_text import SecretText

    path = tmp_path / "vault.json"
    secret = SecretText.from_str(MASTER)
    session = create_vault(path, secret, kdf_overrides=TEST_KDF)
    session.upsert_web(origin="https://example.com", username="a", password="pw")
    assert session.verify_master_password(secret)
    phrase = session.create_recovery_phrase(secret)
    session.rotate_data_key(secret)
    session.remove_recovery_phrase(secret)
    assert phrase and secret.buffer == bytearray(MASTER.encode())
    session.lock()
    backup = tmp_path / "b.lgk"
    export_encrypted_backup(backup, vault_file=path, settings_file=None, profile_name="P",
                            backup_password="independent backup password", kdf_overrides=TEST_KDF)
    assert verify_encrypted_backup(backup, backup_password="independent backup password",
                                   vault_password=secret)["verified"]
    restored = tmp_path / "restored" / "vault.json"
    restored.parent.mkdir()
    restore_verified_backup(backup, vault_file=restored, settings_file=None,
                            backup_password="independent backup password", vault_password=secret)
    assert bytes(secret.buffer) == MASTER.encode()
    unlock_vault(restored, secret).lock()
    secret.wipe()


def test_restore_unlocks_with_one_converted_buffer(tmp_path: Path, monkeypatch) -> None:
    from localvault import secret_text
    from localvault.backup import export_encrypted_backup, restore_verified_backup

    path = tmp_path / "vault.json"
    create_vault(path, MASTER, kdf_overrides=TEST_KDF).lock()
    backup = tmp_path / "b.lgk"
    export_encrypted_backup(backup, vault_file=path, settings_file=None, profile_name="P",
                            backup_password="independent backup password", kdf_overrides=TEST_KDF)
    seen: list[bytearray] = []
    original = secret_text.argon2id_raw

    def spy(secret, salt, **kwargs):
        seen.append(secret)
        return original(secret, salt, **kwargs)

    monkeypatch.setattr(secret_text, "argon2id_raw", spy)
    restore_verified_backup(backup, vault_file=tmp_path / "new" / "vault.json", settings_file=None,
                            backup_password="independent backup password", vault_password=MASTER)
    assert len(seen) >= 3 and all(buffer is seen[0] for buffer in seen)
