"""Security audit: vault cryptography and at-rest storage.

Every test is an attack attempt.  A passing test means the defense held; a
strict ``xfail`` documents a confirmed weakness and flips to XPASS (failing the
suite) once it is fixed, so the marker must then be removed.
"""
from __future__ import annotations

import base64
import json
import os
import zipfile
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

import localvault.export as export_module
import localvault.vault as vault_module
from localvault.i18n import t
from localvault.attachments import AttachmentError, AttachmentStore
from localvault.backup import (
    BackupError,
    export_encrypted_backup,
    export_full_backup,
    restore_full_backup,
    verify_encrypted_backup,
)
from localvault.config import atomic_write_json, read_json
from localvault.vault import (
    DEFAULT_KDF,
    InvalidMasterPassword,
    RecoveryPhraseError,
    VaultError,
    VaultLockedError,
    _decrypt_vault,
    _read_vault_header,
    _unwrap_password_wrapper,
    create_vault,
    unlock_vault,
    unlock_with_recovery_phrase,
)

KDF = {"time_cost": 1, "memory_cost_kib": 8192, "parallelism": 1, "hash_len": 32}
MASTER = "correct horse battery staple"
NEW_MASTER = "replacement master password 0002"
BACKUP_PASSWORD = "independent backup password 01"
SECRET = "Sup3r-Secret-Canary-Password-7f3a91"


@pytest.fixture(autouse=True)
def _fast_default_kdf(monkeypatch):
    monkeypatch.setattr(vault_module, "DEFAULT_KDF", {**DEFAULT_KDF, **KDF})
    vault_module._reset_unlock_throttle_state_for_tests()
    yield
    vault_module._reset_unlock_throttle_state_for_tests()


def _vault(tmp_path: Path, name: str = "vault.json", **kwargs):
    directory = tmp_path / name.replace(".json", "")
    directory.mkdir(parents=True, exist_ok=True)
    return create_vault(directory / "vault.json", MASTER, kdf_overrides=KDF, **kwargs)


def _all_bytes_under(root: Path) -> list[tuple[Path, bytes]]:
    return [(path, path.read_bytes()) for path in root.rglob("*") if path.is_file()]


# --------------------------------------------------------------------------
# Header / KDF / AEAD binding
# --------------------------------------------------------------------------

@pytest.mark.parametrize(
    "mutation",
    [
        {"memory_cost_kib": 1024},           # below the 8 MiB floor
        {"time_cost": 0},
        {"parallelism": 0},
        {"hash_len": 16},
        {"name": "argon2i"},                 # algorithm swap
        {"salt": base64.b64encode(b"short").decode()},
    ],
)
def test_kdf_downgrade_below_floor_is_refused_before_argon2_runs(tmp_path: Path, monkeypatch, mutation) -> None:
    """SEC-V1: attacker rewrites the public KDF block to a trivially cheap or different KDF."""
    session = _vault(tmp_path)
    path = session.path
    session.lock()
    document = read_json(path)
    document["kdf"].update(mutation)
    atomic_write_json(path, document)
    calls: list[int] = []
    monkeypatch.setattr("localvault.secret_text.argon2id_raw",
                        lambda secret, salt, **kw: calls.append(1) or bytearray(32))
    with pytest.raises(VaultError):
        unlock_vault(path, MASTER)
    assert calls == []


def test_in_range_kdf_change_breaks_wrapper_authentication(tmp_path: Path) -> None:
    """SEC-V2: attacker lowers Argon2 cost to another in-range value so future rewraps are weaker."""
    session = _vault(tmp_path)
    path = session.path
    session.lock()
    document = read_json(path)
    document["kdf"]["parallelism"] = 2
    document["kdf"]["time_cost"] = 2
    atomic_write_json(path, document)
    with pytest.raises(InvalidMasterPassword):
        unlock_vault(path, MASTER)


def test_password_wrapper_transplanted_from_another_vault_fails(tmp_path: Path) -> None:
    """SEC-V3: attacker copies a wrapper + KDF block (same password) from a vault they control."""
    victim = _vault(tmp_path, "victim.json")
    victim.upsert_web(origin="https://example.com", username="v", password=SECRET)
    victim.lock()
    attacker = _vault(tmp_path, "attacker.json")
    attacker.lock()
    victim_doc = read_json(victim.path)
    attacker_doc = read_json(attacker.path)
    victim_doc["kdf"] = attacker_doc["kdf"]
    victim_doc["wrappers"]["password"] = attacker_doc["wrappers"]["password"]
    atomic_write_json(victim.path, victim_doc)
    with pytest.raises(InvalidMasterPassword):
        unlock_vault(victim.path, MASTER)


def test_recovery_wrapper_transplanted_from_another_vault_fails(tmp_path: Path) -> None:
    """SEC-V4: attacker grafts their own recovery wrapper (phrase they know) onto the victim vault."""
    victim = _vault(tmp_path, "victim.json")
    victim.lock()
    attacker = _vault(tmp_path, "attacker.json")
    phrase = attacker.create_recovery_phrase(MASTER)
    attacker.lock()
    victim_doc = read_json(victim.path)
    victim_doc["wrappers"]["recovery"] = read_json(attacker.path)["wrappers"]["recovery"]
    atomic_write_json(victim.path, victim_doc)
    with pytest.raises(RecoveryPhraseError):
        unlock_with_recovery_phrase(victim.path, phrase)


@pytest.mark.parametrize("field,value", [("generation", 999), ("vault_id", "f" * 32), ("catalog_version", 1)])
def test_unauthenticated_header_field_tamper_is_detected(tmp_path: Path, field, value) -> None:
    """SEC-V5: attacker edits public header identity fields (generation, vault id, catalog version)."""
    session = _vault(tmp_path)
    session.upsert_web(origin="https://example.com", username="a", password=SECRET)
    path = session.path
    session.lock()
    document = read_json(path)
    document[field] = value
    if field == "catalog_version":
        document["catalog"] = vault_module.LEGACY_CATALOG_IDENTIFIER
    atomic_write_json(path, document)
    with pytest.raises(VaultError):
        unlock_vault(path, MASTER)


def test_format_version_downgrade_to_v2_is_rejected(tmp_path: Path) -> None:
    """SEC-V6: attacker relabels a v3 envelope as v2 so the KEK would be used directly as catalog key."""
    session = _vault(tmp_path)
    path = session.path
    session.lock()
    document = read_json(path)
    document["version"] = 2
    document["format"] = "localgatekeys-vault-v2"
    atomic_write_json(path, document)
    with pytest.raises(VaultError):
        unlock_vault(path, MASTER)


def test_ciphertext_bit_flip_and_truncation_are_rejected(tmp_path: Path) -> None:
    """SEC-V7: attacker flips/truncates catalog ciphertext hoping for partial plaintext acceptance."""
    session = _vault(tmp_path)
    session.upsert_web(origin="https://example.com", username="a", password=SECRET)
    path = session.path
    session.lock()
    original = read_json(path)
    raw = bytearray(base64.b64decode(original["cipher"]["ciphertext"]))
    raw[5] ^= 0x01
    atomic_write_json(path, {**original, "cipher": {**original["cipher"], "ciphertext": base64.b64encode(bytes(raw)).decode()}})
    with pytest.raises(InvalidMasterPassword):
        unlock_vault(path, MASTER)
    truncated = base64.b64encode(bytes(raw[:-16])).decode()
    atomic_write_json(path, {**original, "cipher": {**original["cipher"], "ciphertext": truncated}})
    with pytest.raises(InvalidMasterPassword):
        unlock_vault(path, MASTER)


def test_catalog_and_wrapper_nonces_are_never_reused(tmp_path: Path) -> None:
    """SEC-V8: look for AES-GCM nonce reuse across saves and wrapper rewrites under one key."""
    session = _vault(tmp_path)
    nonces = {read_json(session.path)["cipher"]["nonce"]}
    for index in range(12):
        session.upsert_web(origin=f"https://site{index}.example", username="a", password=SECRET)
        nonces.add(read_json(session.path)["cipher"]["nonce"])
    assert len(nonces) == 13
    wrapper_nonces = {read_json(session.path)["wrappers"]["password"]["nonce"]}
    session.change_master_password(MASTER, NEW_MASTER)
    session.change_master_password(NEW_MASTER, MASTER)
    session.create_recovery_phrase(MASTER)
    document = read_json(session.path)
    wrapper_nonces.add(document["wrappers"]["password"]["nonce"])
    wrapper_nonces.add(document["wrappers"]["recovery"]["nonce"])
    assert len(wrapper_nonces) == 3
    session.lock()


# --------------------------------------------------------------------------
# Key material and plaintext at rest
# --------------------------------------------------------------------------

def test_no_plaintext_secret_key_or_phrase_reaches_disk(tmp_path: Path) -> None:
    """SEC-V9: scan every file the vault writes (vault, anchor, rolling backups) for secrets/keys/phrase."""
    backups = tmp_path / "Backups"
    session = _vault(tmp_path, backup_dir=backups, backup_count=5)
    session.upsert_web(origin="https://example.com", username="canary-user", password=SECRET)
    phrase = session.create_recovery_phrase(MASTER)
    session.change_master_password(MASTER, NEW_MASTER)
    data_key = bytes(session._key)
    session.upsert_web(origin="https://example.org", username="b", password=SECRET + "2")
    session.lock()
    needles = [SECRET.encode(), b"canary-user", MASTER.encode(), NEW_MASTER.encode(), phrase.encode(),
               phrase.split()[0].encode() + b" " + phrase.split()[1].encode(), data_key,
               base64.b64encode(data_key)]
    files = _all_bytes_under(tmp_path)
    assert any(path.parent == backups for path, _ in files)
    for path, blob in files:
        for needle in needles:
            assert needle not in blob, f"{needle[:12]!r} found in {path}"


def test_lock_scrubs_key_buffers_and_refuses_further_use(tmp_path: Path) -> None:
    """SEC-V10: secrets linger in the session object after lock()."""
    session = _vault(tmp_path)
    session.upsert_web(origin="https://example.com", username="a", password=SECRET)
    key_buffer = session._key
    token_buffer = session._edit_token_key
    session.lock()
    assert key_buffer == bytearray(32) and token_buffer == bytearray(32)
    assert session._key is None and session._payload is None and session._committed_payload is None
    with pytest.raises(VaultLockedError):
        session.all_entries()
    with pytest.raises(VaultLockedError):
        session.save()
    assert SECRET not in json.dumps(session._header)


def test_backup_verification_leaves_no_plaintext_in_temp(tmp_path: Path, monkeypatch) -> None:
    """SEC-V11: verifying an .lgk backup stages plaintext in the system temp directory."""
    import tempfile

    session = _vault(tmp_path)
    session.upsert_web(origin="https://example.com", username="a", password=SECRET)
    session.lock()
    backup = tmp_path / "b.lgk"
    export_encrypted_backup(backup, vault_file=session.path, settings_file=None, profile_name="P",
                            backup_password=BACKUP_PASSWORD, kdf_overrides=KDF)
    assert SECRET.encode() not in backup.read_bytes()
    scratch = tmp_path / "systemp"
    scratch.mkdir()
    monkeypatch.setattr(tempfile, "tempdir", str(scratch))
    assert verify_encrypted_backup(backup, backup_password=BACKUP_PASSWORD, vault_password=MASTER)["verified"]
    for path, blob in _all_bytes_under(scratch):
        assert SECRET.encode() not in blob, path


# --------------------------------------------------------------------------
# Password change / key lineage
# --------------------------------------------------------------------------

def test_old_master_password_cannot_decrypt_vault_after_password_change(tmp_path: Path) -> None:
    """SEC-V12: attacker with a leaked OLD master password reads a rolling backup the app itself keeps
    (or any older copy of the vault), unwraps the data key, and decrypts the CURRENT vault written
    after the user changed the password."""
    backups = tmp_path / "Backups"
    session = _vault(tmp_path, backup_dir=backups, backup_count=5)
    session.upsert_web(origin="https://example.com", username="a", password="before-change")
    stolen_copy = session.path.read_bytes()  # e.g. a synced or exported copy the attacker holds
    session.change_master_password(MASTER, NEW_MASTER)  # victim reacts to the leak
    session.upsert_web(origin="https://example.org", username="b", password=SECRET)
    path = session.path
    session.lock()
    old_keys = []
    candidates = [stolen_copy] + [backup.read_bytes() for backup in sorted(backups.glob("vault-*.json"))]
    for blob in candidates:
        header = json.loads(blob)
        try:
            old_keys.append(_unwrap_password_wrapper(header, MASTER))  # the OLD password
        except InvalidMasterPassword:
            continue
    assert old_keys, "precondition: the attacker's old copy opens with the old password"
    # No rolling backup kept by the app still opens with the old password.
    assert len(old_keys) == 1
    header, source = _read_vault_header(path)
    for recovered_key in old_keys:
        with pytest.raises((InvalidMasterPassword, VaultError)):
            _decrypt_vault(path, header, source, recovered_key, check_anchor=False).lock()


# --------------------------------------------------------------------------
# Rollback anchor
# --------------------------------------------------------------------------

def test_replayed_anchor_from_another_vault_is_rejected(tmp_path: Path) -> None:
    """SEC-V13: attacker copies an authenticated anchor (generation 0 path) from a different vault."""
    victim = _vault(tmp_path, "victim.json")
    older = victim.path.read_bytes()
    for index in range(3):
        victim.upsert_web(origin=f"https://s{index}.example", username="a", password=SECRET)
    victim.lock()
    other = _vault(tmp_path, "other.json")
    other.lock()
    victim.path.write_bytes(older)
    anchor = vault_module._generation_anchor_path(victim.path)
    anchor.write_bytes(vault_module._generation_anchor_path(other.path).read_bytes())
    with pytest.raises(VaultError):
        unlock_vault(victim.path, MASTER)


def test_authenticated_anchor_cannot_be_downgraded_to_plaintext(tmp_path: Path) -> None:
    """SEC-V14: attacker replaces the HMAC anchor with the legacy plaintext form {generation: 0} and
    restores an older vault copy, without ever unlocking the vault."""
    session = _vault(tmp_path)
    session.upsert_web(origin="https://example.com", username="a", password="old")
    older = session.path.read_bytes()
    session.upsert_web(origin="https://example.com", username="a", password=SECRET)
    session.upsert_web(origin="https://example.org", username="b", password=SECRET)
    path = session.path
    session.lock()
    assert "anchor" in read_json(vault_module._generation_anchor_path(path))
    path.write_bytes(older)
    atomic_write_json(vault_module._generation_anchor_path(path), {"version": 1, "generation": 0})
    with pytest.raises(VaultError):
        unlock_vault(path, MASTER).lock()


def test_planted_migration_journal_cannot_roll_the_vault_back(tmp_path: Path) -> None:
    """SEC-V25: attacker plants an unauthenticated migration journal pointing at an old encrypted copy
    (e.g. a rolling backup) with no anchor, so the pre-unlock recovery restores the old copy."""
    import hashlib

    backups = tmp_path / "Backups"
    session = _vault(tmp_path, backup_dir=backups, backup_count=5)
    session.upsert_web(origin="https://example.com", username="a", password="old")
    older = session.path.read_bytes()
    older_generation = read_json(session.path)["generation"]
    session.upsert_web(origin="https://example.com", username="a", password=SECRET)
    session.upsert_web(origin="https://example.org", username="b", password=SECRET)
    path = session.path
    session.lock()
    planted = backups / "migration-v2-0.json"
    planted.write_bytes(older)
    for claimed_generation in (older_generation, 2**40):
        atomic_write_json(vault_module.vault_migration_journal_path(path), {
            "version": vault_module.VAULT_MIGRATION_JOURNAL_VERSION, "operation": "envelope-v2-to-v3",
            "status": "publishing", "vault_path": str(path.resolve()), "backup_path": str(planted.resolve()),
            "source_sha256": "0" * 64, "backup_sha256": hashlib.sha256(older).hexdigest(),
            "source_generation": claimed_generation, "source_anchor": None,
        })
        try:
            reopened = unlock_vault(path, MASTER)
        except VaultError:
            continue  # secure: the restored old copy fails the (kept) anchor
        try:
            passwords = [entry["password"] for entry in reopened.all_entries()]
        finally:
            reopened.lock()
        assert SECRET in passwords


# --------------------------------------------------------------------------
# Backup containers
# --------------------------------------------------------------------------

def _v2_era_vault(path: Path, password: str) -> None:
    """Hand-build a format-2 vault (Argon2 output used directly as the catalog key)."""
    kdf = {**DEFAULT_KDF, **KDF, "salt": base64.b64encode(os.urandom(16)).decode()}
    header = {"version": 2, "format": "localgatekeys-vault-v2", "catalog": vault_module.CATALOG_FORMAT,
              "kdf": kdf, "cipher": {"name": "aes-256-gcm", "nonce": "", "ciphertext": ""}}
    payload = vault_module._empty_payload()
    payload["entries"] = []
    nonce = os.urandom(12)
    header["cipher"]["nonce"] = base64.b64encode(nonce).decode()
    key = vault_module._derive_key(password, kdf)
    ciphertext = AESGCM(bytes(key)).encrypt(nonce, vault_module._canonical_json(payload), vault_module._aad(header))
    header["cipher"]["ciphertext"] = base64.b64encode(ciphertext).decode()
    atomic_write_json(path, header)


def test_verifying_a_v2_era_backup_leaves_nothing_in_temp(tmp_path: Path, monkeypatch) -> None:
    """SEC-V26: the verification probe upgraded a v2 envelope and left a migration copy in %TEMP%."""
    import tempfile

    profile = tmp_path / "profile"
    profile.mkdir()
    _v2_era_vault(profile / "vault.json", MASTER)
    backup = tmp_path / "v2.lgk"
    export_encrypted_backup(backup, vault_file=profile / "vault.json", settings_file=None, profile_name="P",
                            backup_password=BACKUP_PASSWORD, kdf_overrides=KDF)
    scratch = tmp_path / "systemp"
    scratch.mkdir()
    monkeypatch.setattr(tempfile, "tempdir", str(scratch))
    assert verify_encrypted_backup(backup, backup_password=BACKUP_PASSWORD, vault_password=MASTER)["verified"]
    assert list(scratch.rglob("*")) == []
    assert read_json(profile / "vault.json")["version"] == 2  # the source was never touched


def _full_profile(profile: Path) -> str:
    profile.mkdir()
    session = create_vault(profile / "vault.json", MASTER, kdf_overrides=KDF)
    entry_id = session.upsert_web(origin="https://example.com", username="a", password=SECRET)
    session.set_entry_extras(entry_id, policy={"fill": "click", "sign_in": "enabled"})
    session.set_fill_and_sign_in_enabled(True)
    session.lock()
    atomic_write_json(profile / "settings.json",
                      {"start_with_windows": True, "fill_and_sign_in": True, "breach_check_enabled": True})
    return entry_id


def test_full_backup_replace_requires_rollback_confirmation_and_sanitises(tmp_path: Path) -> None:
    """SEC-V27: restore_full_backup(replace=True) silently rolled a newer vault back and kept automatic
    sign-in approvals and autostart, unlike the verified .lgk restore and the UI path."""
    profile = tmp_path / "profile"
    entry_id = _full_profile(profile)
    backup = tmp_path / "full.lgk"
    export_full_backup(backup, profile_dir=profile, backup_password=BACKUP_PASSWORD, kdf_overrides=KDF)
    newer = unlock_vault(profile / "vault.json", MASTER)
    newer.upsert_web(origin="https://example.org", username="b", password="written after the backup")
    newer.lock()
    before = {path: path.read_bytes() for path in profile.rglob("*") if path.is_file()}

    with pytest.raises(BackupError, match="master password"):
        restore_full_backup(backup, profile_dir=profile, backup_password=BACKUP_PASSWORD, replace=True)
    with pytest.raises(vault_module.RollbackRequiresConfirmation):
        restore_full_backup(backup, profile_dir=profile, backup_password=BACKUP_PASSWORD,
                            vault_password=MASTER, replace=True)
    assert {path: path.read_bytes() for path in profile.rglob("*") if path.is_file()} == before

    restore_full_backup(backup, profile_dir=profile, backup_password=BACKUP_PASSWORD, vault_password=MASTER,
                        replace=True, allow_rollback=True)
    settings = read_json(profile / "settings.json")
    assert settings["start_with_windows"] is False and settings["fill_and_sign_in"] is False
    assert settings["breach_check_enabled"] is False
    restored = unlock_vault(profile / "vault.json", MASTER)
    try:
        assert restored.get_entry(entry_id)["policy"]["sign_in"] == "never"
        assert restored.fill_and_sign_in_enabled() is False
        assert restored.find_web("https://example.org") == []
        # The confirmed rollback re-minted the anchor under the restored key.
        assert restored.rollback_anchor_generation() == read_json(profile / "vault.json")["generation"]
    finally:
        restored.lock()


def test_lgk_backup_header_kdf_or_version_tamper_is_rejected(tmp_path: Path) -> None:
    """SEC-V15: attacker lowers the .lgk KDF cost or relabels v2 as v1 (constant-AAD) envelope."""
    session = _vault(tmp_path)
    session.lock()
    backup = tmp_path / "b.lgk"
    export_encrypted_backup(backup, vault_file=session.path, settings_file=None, profile_name="P",
                            backup_password=BACKUP_PASSWORD, kdf_overrides={**KDF, "time_cost": 2})
    original = read_json(backup)
    for mutate in (lambda d: d["kdf"].update(time_cost=1), lambda d: d.update(version=1),
                   lambda d: d["kdf"].update(memory_cost_kib=1024)):
        document = json.loads(json.dumps(original))
        mutate(document)
        atomic_write_json(backup, document)
        with pytest.raises(BackupError):
            verify_encrypted_backup(backup, backup_password=BACKUP_PASSWORD, vault_password=MASTER)


def test_full_backup_member_swap_is_rejected(tmp_path: Path) -> None:
    """SEC-V16: attacker reorders authenticated ZIP members (vault <-> generation) in a full backup."""
    profile = tmp_path / "profile"
    profile.mkdir()
    session = create_vault(profile / "vault.json", MASTER, kdf_overrides=KDF)
    session.upsert_web(origin="https://example.com", username="a", password=SECRET)
    session.lock()
    atomic_write_json(profile / "settings.json", {})
    backup = tmp_path / "full.lgk"
    export_full_backup(backup, profile_dir=profile, backup_password=BACKUP_PASSWORD, kdf_overrides=KDF)
    assert SECRET.encode() not in backup.read_bytes()
    swapped = tmp_path / "swapped.lgk"
    with zipfile.ZipFile(backup) as source, zipfile.ZipFile(swapped, "w", compression=zipfile.ZIP_STORED) as out:
        members = {info.filename: source.read(info) for info in source.infolist()}
        for info in source.infolist():
            data = members[info.filename]
            if info.filename == "data/00000000.bin":
                data = members["data/00000002.bin"]
            elif info.filename == "data/00000002.bin":
                data = members["data/00000000.bin"]
            out.writestr(info, data)
    with pytest.raises(BackupError):
        restore_full_backup(swapped, profile_dir=tmp_path / "restored", backup_password=BACKUP_PASSWORD,
                            vault_password=MASTER, dry_run=True)


# --------------------------------------------------------------------------
# Attachments
# --------------------------------------------------------------------------

def test_attachment_sidecar_swap_and_traversal_ids_are_rejected(tmp_path: Path) -> None:
    """SEC-V17: attacker swaps two encrypted sidecars on disk, or feeds a path-traversal attachment id."""
    session = _vault(tmp_path)
    store = AttachmentStore(session)
    first = store.add_bytes("a.txt", b"first secret attachment")
    second = store.add_bytes("b.txt", b"second secret attachment")
    a_path, b_path = store._path(first), store._path(second)
    a_bytes, b_bytes = a_path.read_bytes(), b_path.read_bytes()
    assert b"secret attachment" not in a_bytes + b_bytes
    a_path.write_bytes(b_bytes)
    b_path.write_bytes(a_bytes)
    with pytest.raises(AttachmentError):
        store.read_bytes(first)
    for hostile in ("../vault", "..\\..\\vault", "/etc/passwd", "C:\\Windows\\win.ini", ""):
        with pytest.raises(AttachmentError):
            store._path(hostile)
    with pytest.raises(AttachmentError):
        store.add_bytes("..\\evil.txt", b"x")
    session.lock()


# --------------------------------------------------------------------------
# Selective transfer packages
# --------------------------------------------------------------------------

def test_crafted_transfer_package_cannot_import_auto_sign_in_trust(tmp_path: Path) -> None:
    """SEC-V18: attacker-built transfer package carries sign_in=enabled and desktop approvals."""
    from localvault import transfer

    session = _vault(tmp_path)
    entry_id = session.upsert_web(origin="https://example.com", username="a", password=SECRET)
    entry = json.loads(json.dumps(session.get_entry(entry_id)))
    session.lock()
    entry["policy"] = {"fill": "click", "sign_in": "enabled", "require_master_password": False}
    manifest = {"item_count": 0, "credential_count": 1, "attachment_count": 0, "attachment_bytes": 0,
                "attachments": []}
    payload = {"version": transfer.TRANSFER_VERSION, "items": [], "credentials": [entry], "collections": [],
               "attachments": []}
    envelope = transfer._build_envelope(manifest, payload, BACKUP_PASSWORD, KDF)
    decrypted = transfer._decrypt_payload(envelope, BACKUP_PASSWORD)
    _items, credentials, _collections, _attachments = transfer._validate_package_payload(envelope, decrypted)
    assert credentials[0]["policy"]["sign_in"] == "never"
    # The public manifest is authenticated: inflating counts breaks decryption.
    envelope["manifest"]["credential_count"] = 0
    with pytest.raises(transfer.TransferError):
        transfer._decrypt_payload(envelope, BACKUP_PASSWORD)


# --------------------------------------------------------------------------
# Plaintext exports
# --------------------------------------------------------------------------

def test_plaintext_export_is_never_readable_before_acl_restriction(tmp_path: Path, monkeypatch) -> None:
    """SEC-V19: another local user opens the export temp file during the write; a handle opened before
    icacls keeps read access, so plaintext must not be written until the ACL is restricted."""
    session = _vault(tmp_path)
    session.upsert_web(origin="https://example.com", username="a", password=SECRET)
    observed: list[int] = []

    def spy(path: Path) -> bool:
        observed.append(Path(path).stat().st_size)
        return True

    monkeypatch.setattr(export_module, "_restrict_permissions", spy)
    destination = tmp_path / "export.csv"
    export_module.export_csv(session, destination)
    session.lock()
    assert SECRET.encode() in destination.read_bytes()  # precondition: it is a plaintext export
    assert observed and observed[0] == 0


def test_plaintext_export_warns_when_acl_cannot_be_applied(tmp_path: Path, monkeypatch) -> None:
    """SEC-V20: ACL restriction silently fails and the user is not told the export is world-readable."""
    session = _vault(tmp_path)
    session.upsert_web(origin="https://example.com", username="a", password=SECRET)
    monkeypatch.setattr(export_module, "_restrict_permissions", lambda path: False)
    summary = export_module.export_csv(session, tmp_path / "export.csv")
    session.lock()
    assert summary.permissions_restricted is False
    assert t(export_module.ExportWarning.PERMISSIONS) in summary.warnings
    assert t(export_module.ExportWarning.PLAINTEXT) in summary.warnings
    assert summary.encrypted is False


def test_export_never_overwrites_without_consent(tmp_path: Path) -> None:
    """SEC-V21: export targets an existing file (e.g. the vault) to clobber it with plaintext."""
    session = _vault(tmp_path)
    before = session.path.read_bytes()
    with pytest.raises(export_module.ExportError):
        export_module.export_csv(session, session.path)
    assert session.path.read_bytes() == before
    session.lock()


# --------------------------------------------------------------------------
# Recovery phrase
# --------------------------------------------------------------------------

def test_recovery_phrase_entropy_is_fresh_and_full_strength(tmp_path: Path, monkeypatch) -> None:
    """SEC-V22: predictable or reused recovery phrases (weak RNG / static salt)."""
    session = _vault(tmp_path)
    drawn: list[int] = []
    real = os.urandom

    def counting(size: int) -> bytes:
        drawn.append(size)
        return real(size)

    monkeypatch.setattr(vault_module.os, "urandom", counting)
    phrases = {session.create_recovery_phrase(MASTER) for _ in range(3)}
    salts = {read_json(session.path)["wrappers"]["recovery"]["salt"]}
    session.create_recovery_phrase(MASTER)
    salts.add(read_json(session.path)["wrappers"]["recovery"]["salt"])
    assert len(phrases) == 3 and len(salts) == 2
    assert all(len(phrase.split()) == 24 for phrase in phrases)
    assert drawn.count(32) >= 3  # 256-bit entropy per phrase from the OS CSPRNG
    session.lock()


def test_wrong_recovery_phrase_attempts_are_throttled(tmp_path: Path) -> None:
    """SEC-V23: online guessing of recovery phrases without backoff."""
    session = _vault(tmp_path)
    session.create_recovery_phrase(MASTER)
    path = session.path
    session.lock()
    other = vault_module.phrase_from_entropy(os.urandom(32))
    for _ in range(vault_module.THROTTLE_FREE_ATTEMPTS):
        with pytest.raises(RecoveryPhraseError):
            unlock_with_recovery_phrase(path, other)
    assert vault_module.UnlockThrottle(path).failures >= vault_module.THROTTLE_FREE_ATTEMPTS
    with pytest.raises((vault_module.UnlockThrottled, RecoveryPhraseError)):
        unlock_with_recovery_phrase(path, other)
    assert vault_module.remaining_backoff_seconds(path) > 0


def test_wrap_unlock_key_is_bound_to_context(tmp_path: Path) -> None:
    """SEC-V24: a Hello/camera sidecar wrapped for one context is replayed under another context."""
    session = _vault(tmp_path)
    wrapping = bytearray(os.urandom(32))
    nonce, ciphertext = session.wrap_unlock_key(wrapping, b"context-A")
    from cryptography.exceptions import InvalidTag

    with pytest.raises(InvalidTag):
        AESGCM(bytes(wrapping)).decrypt(nonce, ciphertext, b"context-B")
    assert AESGCM(bytes(wrapping)).decrypt(nonce, ciphertext, b"context-A") == bytes(session._key)
    session.lock()
