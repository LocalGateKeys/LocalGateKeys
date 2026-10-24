from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest

from localvault.backup_filename import (
    BackupFilenameError,
    backup_save_as_options,
    default_backup_filename,
    normalize_backup_filename,
)


def test_save_as_options_have_visible_timestamped_lgk_name_and_filter() -> None:
    options = backup_save_as_options(clock=lambda: datetime(2026, 9, 20, 23, 0, 0, tzinfo=UTC))
    assert options["initialfile"] == "LocalGateKeys-backup-2026-09-20-230000.lgk"
    assert options["defaultextension"] == ".lgk"
    assert options["filetypes"] == (("LocalGateKeys backup (*.lgk)", "*.lgk"),)


@pytest.mark.parametrize(
    ("selected", "expected"),
    (("backup", "backup.lgk"), ("backup.lgk", "backup.lgk"), ("backup.LGK", "backup.LGK")),
)
def test_normalize_backup_filename_appends_suffix_once(selected: str, expected: str) -> None:
    assert normalize_backup_filename(selected) == Path(expected)


def test_normalize_backup_filename_preserves_unicode_parent() -> None:
    path = normalize_backup_filename(Path("安全な保存先") / "回復")
    assert path == Path("安全な保存先") / "回復.lgk"


@pytest.mark.parametrize("selected", ("backup.txt", "backup.json", "backup.lgt"))
def test_normalize_backup_filename_rejects_incompatible_suffix(selected: str) -> None:
    with pytest.raises(BackupFilenameError, match=r"\.lgk"):
        normalize_backup_filename(selected)


def test_default_filename_accepts_an_injected_date() -> None:
    assert default_backup_filename(now=datetime(2026, 1, 2, 3, 4, 5, tzinfo=UTC)).endswith("2026-01-02-030405.lgk")


