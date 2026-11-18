"""Backups made before ``restore_test_weekly`` existed (main's vectors, kept in ``tests/vectors/legacy``) still
verify and restore with the current code; the missing setting reads as its default."""
from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

from localvault.backup import restore_full_backup
from localvault.settings import AppSettings
from localvault.vault import unlock_vault

LEGACY = Path(__file__).resolve().parent / "vectors" / "legacy" / "pre-restore-test"


def _expected(version: str) -> dict:
    return json.loads((LEGACY / "backup" / version / "expected.json").read_text(encoding="utf-8"))


@pytest.mark.parametrize("version", ["v2", "v3"])
def test_old_full_backup_restores_with_default_new_setting(tmp_path: Path, version: str) -> None:
    expected = _expected(version)
    profile = tmp_path / "restored"
    restore_full_backup(LEGACY / "backup" / version / "full.lgkfull", profile_dir=profile,
                        backup_password=expected["backup_password"], vault_password=expected["master_password"],
                        validate_vault_password=True)
    raw = json.loads((profile / "settings.json").read_text(encoding="utf-8"))
    assert AppSettings.load(profile / "settings.json").restore_test_weekly is True
    assert raw.get("restore_test_weekly", True) is True
    session = unlock_vault(profile / "vault.json", expected["master_password"])
    try:
        ids = {r["id"] for r in session._require_payload()["entries"] + session._require_payload()["items"]}
        assert ids == {r["id"] for r in expected["records"]}
    finally:
        session.lock()


def test_old_recovery_kit_manifest_still_verifies(tmp_path: Path) -> None:
    from localvault.recovery import verify_sha256_manifest

    shutil.copy(LEGACY / "backup" / "v2" / "full.lgkfull", tmp_path / "full.lgkfull")
    shutil.copy(LEGACY / "recovery" / "kit" / "full.lgkfull.sha256.json", tmp_path / "full.lgkfull.sha256.json")
    assert verify_sha256_manifest(tmp_path / "full.lgkfull")["verified"] is True


def test_settings_without_the_new_key_load_as_default(tmp_path: Path) -> None:
    path = tmp_path / "settings.json"
    path.write_text(json.dumps({"version": 1}), encoding="utf-8")
    assert AppSettings.load(path).restore_test_weekly is True
