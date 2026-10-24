from __future__ import annotations

import json
from pathlib import Path

import pytest

from localvault.migration import (
    MigrationError,
    choose_start_fresh,
    import_legacy_data,
    legacy_user_data_exists,
    localgatekeys_user_data_exists,
    migration_decision,
    migration_prompt_required,
)
from localvault.profiles import ProfileManager


def _legacy_vault(root: Path, payload: str = "legacy-vault") -> Path:
    root.mkdir(parents=True, exist_ok=True)
    path = root / "vault.json"
    path.write_text(payload, encoding="utf-8")
    return path


def test_fresh_install_without_legacy_uses_normal_first_run(tmp_path: Path) -> None:
    current = tmp_path / "LocalGateKeys"
    legacy = tmp_path / "LocalVaultPrototype"

    assert not migration_prompt_required(current, legacy)
    manager = ProfileManager(current)
    assert manager.list_profiles() == []
    assert (current / "profiles.json").is_file()


def test_legacy_is_detected_but_never_loaded_silently(tmp_path: Path) -> None:
    current = tmp_path / "LocalGateKeys"
    legacy = tmp_path / "LocalVaultPrototype"
    source = _legacy_vault(legacy)

    assert legacy_user_data_exists(legacy)
    assert migration_prompt_required(current, legacy)

    manager = ProfileManager(current)
    assert manager.list_profiles() == []
    assert source.read_text(encoding="utf-8") == "legacy-vault"
    assert not list((current / "Profiles").glob("*/vault.json")) if (current / "Profiles").exists() else True


def test_start_fresh_is_persistent_and_preserves_legacy(tmp_path: Path) -> None:
    current = tmp_path / "LocalGateKeys"
    legacy = tmp_path / "LocalVaultPrototype"
    source = _legacy_vault(legacy)

    choose_start_fresh(current, legacy)

    assert migration_decision(current) == "start_fresh"
    assert not migration_prompt_required(current, legacy)
    assert source.read_text(encoding="utf-8") == "legacy-vault"
    assert not localgatekeys_user_data_exists(current)


def test_explicit_import_copies_legacy_and_preserves_source(tmp_path: Path) -> None:
    current = tmp_path / "LocalGateKeys"
    legacy = tmp_path / "LocalVaultPrototype"
    source = _legacy_vault(legacy)
    (legacy / "settings.json").write_text('{"theme":"legacy"}', encoding="utf-8")
    backups = legacy / "Backups"
    backups.mkdir()
    (backups / "backup.lgk").write_text("backup", encoding="utf-8")

    profile_id = import_legacy_data(current, legacy)

    assert migration_decision(current) == "imported"
    assert not migration_prompt_required(current, legacy)
    assert (current / "Profiles" / profile_id / "vault.json").read_text(encoding="utf-8") == "legacy-vault"
    assert (current / "Profiles" / profile_id / "settings.json").is_file()
    assert (current / "Profiles" / profile_id / "Backups" / "backup.lgk").is_file()
    assert source.read_text(encoding="utf-8") == "legacy-vault"
    assert (legacy / "settings.json").is_file()
    assert (legacy / "Backups" / "backup.lgk").is_file()


def test_existing_localgatekeys_profiles_win_over_legacy(tmp_path: Path) -> None:
    current = tmp_path / "LocalGateKeys"
    legacy = tmp_path / "LocalVaultPrototype"
    _legacy_vault(legacy)
    manager = ProfileManager(current)
    created = manager.create_profile("Current profile")
    (manager.vault_path(created.id)).write_text("current-vault", encoding="utf-8")

    assert localgatekeys_user_data_exists(current)
    assert not migration_prompt_required(current, legacy)
    with pytest.raises(MigrationError):
        import_legacy_data(current, legacy)
    assert manager.vault_path(created.id).read_text(encoding="utf-8") == "current-vault"


def test_install_metadata_alone_does_not_suppress_legacy_prompt(tmp_path: Path) -> None:
    current = tmp_path / "LocalGateKeys"
    legacy = tmp_path / "LocalVaultPrototype"
    current.mkdir()
    (current / "install.json").write_text(json.dumps({"product": "LocalGateKeys"}), encoding="utf-8")
    _legacy_vault(legacy)

    assert not localgatekeys_user_data_exists(current)
    assert migration_prompt_required(current, legacy)
