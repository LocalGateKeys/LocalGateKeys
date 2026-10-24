from __future__ import annotations

import json
import os
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from localvault.config import atomic_write_faults, atomic_write_json
from localvault.migration import (
    MigrationError,
    import_legacy_data,
    migration_decision,
    migration_journal_path,
    recover_legacy_migration,
)
from localvault.vault import (
    DEFAULT_KDF,
    LEGACY_FORMAT_VERSION,
    VaultError,
    _aad,
    _b64e,
    _canonical_json,
    _derive_key,
    unlock_vault,
    vault_migration_journal_path,
)


def test_atomic_write_fault_before_replace_preserves_previous_value(workspace_tmp: Path) -> None:
    path = workspace_tmp / "state.json"
    atomic_write_json(path, {"value": "old"})

    def fail(stage: str, target: Path) -> None:
        if stage == "before_replace":
            raise OSError("synthetic disk full")

    with pytest.raises(OSError, match="disk full"), atomic_write_faults(fail):
        atomic_write_json(path, {"value": "new"})
    assert json.loads(path.read_text(encoding="utf-8")) == {"value": "old"}


def test_atomic_write_fault_hook_is_scoped(workspace_tmp: Path) -> None:
    path = workspace_tmp / "state.json"
    seen: list[str] = []
    with atomic_write_faults(lambda stage, target: seen.append(stage)):
        atomic_write_json(path, {"value": 1})
    atomic_write_json(path, {"value": 2})
    assert seen == ["before_replace", "after_replace"]


def test_legacy_import_before_replace_rolls_back_to_pre_migration_state(workspace_tmp: Path) -> None:
    root = workspace_tmp / "localgatekeys"
    legacy = workspace_tmp / "legacy"
    root.mkdir()
    legacy.mkdir()
    source = b"legacy-vault"
    (legacy / "vault.json").write_bytes(source)

    def fail(stage: str, target: Path) -> None:
        if stage == "before_replace" and target.name == "profiles.json":
            raise OSError("synthetic profile-index commit fault")

    with pytest.raises(OSError, match="profile-index"), atomic_write_faults(fail):
        import_legacy_data(root, legacy)

    assert (legacy / "vault.json").read_bytes() == source
    assert not (root / "profiles.json").exists()
    assert not (root / "Profiles").exists()
    assert not migration_journal_path(root).exists()
    assert not (root / "legacy-migration.json").exists()


def test_future_legacy_migration_state_is_rejected(workspace_tmp: Path) -> None:
    root = workspace_tmp / "localgatekeys"
    root.mkdir()
    atomic_write_json(root / "legacy-migration.json", {"version": 999, "decision": "imported"})

    with pytest.raises(MigrationError, match="newer"):
        migration_decision(root)


def test_future_vault_migration_journal_is_rejected(workspace_tmp: Path) -> None:
    path = workspace_tmp / "vault.json"
    atomic_write_json(vault_migration_journal_path(path), {"version": 999})

    with pytest.raises(VaultError, match="newer"):
        unlock_vault(path, "migration-test-password")


def test_interrupted_legacy_import_is_rolled_back_on_restart(workspace_tmp: Path) -> None:
    root = workspace_tmp / "localgatekeys"
    root.mkdir()
    profile_id = "00000000-0000-4000-8000-000000000001"
    staging = root / "Profiles" / f".migration-{profile_id}"
    staging.mkdir(parents=True)
    (staging / "vault.json").write_bytes(b"copied-before-crash")
    atomic_write_json(
        migration_journal_path(root),
        {
            "version": 1,
            "operation": "legacy-import",
            "status": "staged",
            "profile_id": profile_id,
        },
    )

    assert recover_legacy_migration(root) == "rolled_back"
    assert not staging.exists()
    assert not (root / "Profiles").exists()
    assert not migration_journal_path(root).exists()


def _write_legacy_vault(path: Path, password: str) -> None:
    kdf = {
        **DEFAULT_KDF,
        "time_cost": 1,
        "memory_cost_kib": 8192,
        "parallelism": 1,
        "salt": _b64e(os.urandom(16)),
    }
    header = {
        "version": LEGACY_FORMAT_VERSION,
        "kdf": kdf,
        "cipher": {"name": "aes-256-gcm", "nonce": "", "ciphertext": ""},
    }
    payload = {"version": LEGACY_FORMAT_VERSION, "generation": 1, "entries": [], "trash": []}
    nonce = b"v1-nonce-123"
    header["cipher"]["nonce"] = _b64e(nonce)
    key = _derive_key(password, kdf)
    header["cipher"]["ciphertext"] = _b64e(AESGCM(bytes(key)).encrypt(
        nonce, _canonical_json(payload), _aad(header)
    ))
    atomic_write_json(path, header)


def test_v1_migration_commit_fault_restores_encrypted_source(workspace_tmp: Path) -> None:
    path = workspace_tmp / "vault.json"
    password = "migration-test-password"
    _write_legacy_vault(path, password)
    source = path.read_bytes()
    session = unlock_vault(path, password, backup_dir=workspace_tmp / "Backups")

    def fail(stage: str, target: Path) -> None:
        if stage == "after_replace" and target.name in {"vault.json", "vault.generation.json"}:
            raise OSError("synthetic vault commit fault")

    with pytest.raises(VaultError, match="Could not write the vault"), atomic_write_faults(fail):
        session.migrate_to_v2()
    assert path.read_bytes() == source
    assert not vault_migration_journal_path(path).exists()
    session.lock()

    reopened = unlock_vault(path, password, backup_dir=workspace_tmp / "Backups")
    assert reopened.catalog_version == LEGACY_FORMAT_VERSION
    reopened.lock()
