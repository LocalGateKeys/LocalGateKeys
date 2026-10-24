from pathlib import Path

import pytest

from localvault.backup import BackupError, export_encrypted_backup, restore_encrypted_backup
from localvault.config import atomic_write_json, read_json


def test_encrypted_backup_round_trip(tmp_path: Path) -> None:
    vault = tmp_path / "vault.json"
    settings = tmp_path / "settings.json"
    backup = tmp_path / "profile.lgk"
    atomic_write_json(vault, {"cipher": {"ciphertext": "secret"}})
    atomic_write_json(settings, {"version": 2, "auto_lock_seconds": 300})
    export_encrypted_backup(
        backup,
        vault_file=vault,
        settings_file=settings,
        profile_name="Alice",
        backup_password="correct horse battery staple",
    )
    outer = read_json(backup)
    assert outer["format"] == "localgatekeys-backup"
    assert "Alice" not in backup.read_text(encoding="utf-8")
    vault.unlink()
    settings.unlink()
    restored_name = restore_encrypted_backup(
        backup,
        vault_file=vault,
        settings_file=settings,
        backup_password="correct horse battery staple",
    )
    assert restored_name == "Alice"
    assert read_json(vault)["cipher"]["ciphertext"] == "secret"
    assert read_json(settings)["auto_lock_seconds"] == 300


def test_wrong_backup_password_rejected(tmp_path: Path) -> None:
    vault = tmp_path / "vault.json"
    backup = tmp_path / "profile.lgk"
    atomic_write_json(vault, {"cipher": {"ciphertext": "secret"}})
    export_encrypted_backup(
        backup,
        vault_file=vault,
        settings_file=None,
        profile_name="Alice",
        backup_password="correct horse battery staple",
    )
    with pytest.raises(BackupError):
        restore_encrypted_backup(
            backup,
            vault_file=tmp_path / "restore.json",
            settings_file=None,
            backup_password="wrong password here",
        )


FAST_KDF = {"time_cost": 1, "memory_cost_kib": 8192, "parallelism": 1}
PASSWORD = "correct horse battery staple"


def _export(tmp_path: Path, **kwargs) -> Path:
    vault = tmp_path / "vault.json"
    backup = tmp_path / f"profile-{len(list(tmp_path.iterdir()))}.lgk"
    if not vault.exists():
        atomic_write_json(vault, {"cipher": {"ciphertext": "secret"}})
    export_encrypted_backup(backup, vault_file=vault, settings_file=None, profile_name="Alice",
                            backup_password=PASSWORD, **kwargs)
    return backup


def test_backup_header_records_vault_default_kdf_and_accepts_bounded_overrides(tmp_path: Path) -> None:
    default = read_json(_export(tmp_path))
    assert default["version"] == 2
    assert {key: default["kdf"][key] for key in ("name", "time_cost", "memory_cost_kib", "parallelism")} == {
        "name": "argon2id", "time_cost": 3, "memory_cost_kib": 65536, "parallelism": 4}

    fast = _export(tmp_path, kdf_overrides=FAST_KDF)
    header = read_json(fast)
    assert header["kdf"]["memory_cost_kib"] == 8192 and header["kdf"]["time_cost"] == 1
    assert restore_encrypted_backup(fast, vault_file=tmp_path / "restored.json", settings_file=None,
                                    backup_password=PASSWORD) == "Alice"
    for bad in ({"memory_cost_kib": 4096}, {"memory_cost_kib": 1024 * 1024}, {"time_cost": 0},
                {"time_cost": 11}, {"parallelism": 0}, {"parallelism": 17}):
        with pytest.raises(BackupError):
            _export(tmp_path, kdf_overrides={**FAST_KDF, **bad})


def test_backup_rejects_kdf_parameters_outside_bounds_before_deriving(tmp_path: Path, monkeypatch) -> None:
    import localvault.backup as backup_module

    source = _export(tmp_path, kdf_overrides=FAST_KDF)
    envelope = read_json(source)

    def restore(modified: dict) -> None:
        candidate = tmp_path / "candidate.lgk"
        atomic_write_json(candidate, modified)
        restore_encrypted_backup(candidate, vault_file=tmp_path / "out.json", settings_file=None,
                                 backup_password=PASSWORD)

    def refuse(*_args, **_kwargs):
        raise AssertionError("KDF must not run for out-of-range parameters")

    monkeypatch.setattr(backup_module, "hash_secret_raw", refuse)
    for bad in ({"memory_cost_kib": 4096}, {"memory_cost_kib": 1024 * 1024}, {"time_cost": 0},
                {"time_cost": 11}, {"parallelism": 0}, {"parallelism": 17}, {"time_cost": "3"},
                {"name": "scrypt"}):
        with pytest.raises(BackupError):
            restore({**envelope, "kdf": {**envelope["kdf"], **bad}})
    monkeypatch.undo()
    # An in-range change to an authenticated header field is still rejected.
    with pytest.raises(BackupError):
        restore({**envelope, "kdf": {**envelope["kdf"], "memory_cost_kib": 16384}})


def test_legacy_v1_backup_envelope_still_restores(tmp_path: Path) -> None:
    import base64
    import json
    import os

    from argon2.low_level import Type, hash_secret_raw
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    payload = {"version": 1, "exported_at": 1, "profile_name": "Legacy",
               "vault": {"cipher": {"ciphertext": "legacy"}}, "settings": None}
    salt, nonce = os.urandom(16), os.urandom(12)
    key = hash_secret_raw(secret=PASSWORD.encode(), salt=salt, time_cost=3,
                          memory_cost=32768, parallelism=2, hash_len=32, type=Type.ID)
    ciphertext = AESGCM(key).encrypt(nonce, json.dumps(payload, separators=(",", ":"), sort_keys=True).encode(),
                                     b"localgatekeys|encrypted-profile-backup|v1")
    legacy = tmp_path / "legacy.lgk"
    atomic_write_json(legacy, {
        "format": "localgatekeys-backup", "version": 1,
        "kdf": {"name": "argon2id", "salt": base64.b64encode(salt).decode(), "time_cost": 3,
                "memory_cost_kib": 32768, "parallelism": 2},
        "cipher": {"name": "aes-256-gcm", "nonce": base64.b64encode(nonce).decode(),
                   "ciphertext": base64.b64encode(ciphertext).decode()},
    })
    assert restore_encrypted_backup(legacy, vault_file=tmp_path / "legacy-vault.json", settings_file=None,
                                    backup_password=PASSWORD) == "Legacy"
    assert read_json(tmp_path / "legacy-vault.json")["cipher"]["ciphertext"] == "legacy"
