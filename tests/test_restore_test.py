from __future__ import annotations

import os
from pathlib import Path

import pytest

from localvault import restore_test
from localvault.backup import export_encrypted_backup
from localvault.vault import create_vault

TEST_KDF = {"time_cost": 1, "memory_cost_kib": 8192, "parallelism": 1, "hash_len": 32}
CHEAP = {"time_cost": 1, "memory_cost_kib": 8192, "parallelism": 1}
MASTER = "synthetic restore master 01"
NEW = "synthetic restore master 02"


@pytest.fixture()
def backup(tmp_path: Path) -> Path:
    profile = tmp_path / "profile"
    profile.mkdir()
    session = create_vault(profile / "vault.json", MASTER, kdf_overrides=TEST_KDF)
    for n in range(3):
        session.upsert_web(origin=f"https://site{n}.test", username="u", password="synthetic-pw", label=f"L{n}")
    session.lock()
    out = tmp_path / "b.lgk"
    export_encrypted_backup(out, vault_file=profile / "vault.json", settings_file=None, profile_name="P",
                            backup_password=MASTER, kdf_overrides=CHEAP)
    return out


def _scratch_empty() -> bool:
    root = restore_test.scratch_root()
    return not root.exists() or not any(root.iterdir())


def test_good_backup_passes_with_item_count(backup: Path) -> None:
    result = restore_test.run(None, 2_000_000_000, backup_path=backup, backup_password=MASTER)
    assert result.ok and result.items == 3 and result.reason == ""
    assert _scratch_empty()


def test_corrupted_backup_is_unreadable(tmp_path: Path) -> None:
    bad = tmp_path / "bad.lgk"
    bad.write_bytes(b"not a backup at all")
    result = restore_test.run(None, 1, backup_path=bad, backup_password=MASTER)
    assert not result.ok and result.reason == "unreadable"
    assert _scratch_empty()


def test_changed_password_reports_old_password(backup: Path) -> None:
    result = restore_test.run(None, 1, backup_path=backup, backup_password=NEW)
    assert result.reason == "old_password"
    result = restore_test.run(None, 1, backup_path=backup, backup_password=MASTER, vault_password=NEW)
    assert result.reason == "old_password"
    assert _scratch_empty()


def test_scratch_lives_under_data_dir() -> None:
    assert str(restore_test.scratch_root()).startswith(os.environ["LOCALGATEKEYS_DATA_DIR"])


def test_no_backup() -> None:
    assert restore_test.run(None, 1, backup_path=None, backup_password=MASTER).reason == "no_backup"


def test_row_text_per_state(tmp_path: Path) -> None:
    now = 10 * 86400
    assert "never" in restore_test.row_text(None, now).lower()
    ok = restore_test.RestoreTestResult(True, "b", 0, 3, "", now - 3 * 86400)
    assert "3" in restore_test.row_text(ok, now)
    bad = restore_test.RestoreTestResult(False, "b", 0, 0, "old_password", now)
    assert "old password" in restore_test.row_text(bad, now)
    restore_test.save(tmp_path / "s.json", ok)
    assert restore_test.load(tmp_path / "s.json") == ok


def test_due_weekly() -> None:
    last = restore_test.RestoreTestResult(True, "b", 0, 1, "", 0)
    assert restore_test.due(None, 5, enabled=True)
    assert not restore_test.due(last, restore_test.WEEK - 1, enabled=True)
    assert restore_test.due(last, restore_test.WEEK, enabled=True)
    assert not restore_test.due(None, 5, enabled=False)


def _rolling_session(tmp_path: Path):
    profile = tmp_path / "rolling"
    profile.mkdir()
    session = create_vault(profile / "vault.json", MASTER, kdf_overrides=TEST_KDF,
                           backup_dir=profile / "backups", backup_count=3)
    for n in range(3):
        session.upsert_web(origin=f"https://r{n}.test", username="u", password="synthetic-pw", label=f"R{n}")
    return session, profile


def test_unlock_test_reads_the_newest_rolling_backup_with_the_unlocked_key(tmp_path: Path) -> None:
    session, profile = _rolling_session(tmp_path)
    state = restore_test.state_path(profile)
    result = restore_test.run_at_unlock(session, state, 1_800_000_000, enabled=True)
    assert result is not None and result.ok and result.items >= 2
    assert restore_test.load(state) == result
    assert session.summaries()  # the live session's key is untouched
    # Not due again within the week; never with the setting off.
    assert restore_test.run_at_unlock(session, state, 1_800_000_100, enabled=True) is None
    assert restore_test.run_at_unlock(session, state, 1_800_000_000 + restore_test.WEEK, enabled=False) is None
    session.lock()


def test_unlock_test_reports_a_damaged_rolling_backup(tmp_path: Path) -> None:
    session, profile = _rolling_session(tmp_path)
    newest = max((profile / "backups").glob("vault-*.json"), key=lambda p: p.stat().st_mtime_ns)
    newest.write_text("{not json", encoding="utf-8")
    result = restore_test.run_at_unlock(session, restore_test.state_path(profile), 1_800_000_000, enabled=True)
    assert result is not None and not result.ok and result.reason == "unreadable"
    session.lock()


def test_unlock_test_skips_without_rolling_backups(tmp_path: Path) -> None:
    profile = tmp_path / "none"
    profile.mkdir()
    session = create_vault(profile / "vault.json", MASTER, kdf_overrides=TEST_KDF)
    assert restore_test.run_at_unlock(session, restore_test.state_path(profile), 1_800_000_000, enabled=True) is None
    session.lock()
