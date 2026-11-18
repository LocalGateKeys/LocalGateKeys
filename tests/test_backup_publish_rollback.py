"""A failed full restore that cannot put the old profile back keeps the rollback copy."""
from __future__ import annotations

import os

import pytest

from localvault import backup


def test_rollback_copy_is_kept_when_old_profile_cannot_be_put_back(tmp_path, monkeypatch):
    monkeypatch.setenv("LOCALGATEKEYS_DATA_DIR", str(tmp_path / "data"))
    live = tmp_path / "live"
    live.mkdir()
    vault_file = live / "vault.json"
    vault_file.write_text("old vault", "utf-8")
    attachments = live / "attachments"
    stage = tmp_path / "stage"
    stage.mkdir()
    (stage / "vault.json").write_text("new vault", "utf-8")  # attachments missing -> staging incomplete
    real_replace = os.replace
    calls = {"n": 0}

    def flaky(src, dst):
        calls["n"] += 1
        if calls["n"] > 1 and str(dst) == str(vault_file):
            raise OSError("locked")
        return real_replace(src, dst)

    monkeypatch.setattr(backup.os, "replace", flaky)
    with pytest.raises(backup.BackupError, match="kept in"):
        backup._full_publish(stage, profile_dir=None, vault_file=vault_file, settings_file=None,
                             attachment_dir=attachments, anchor=live / "anchor", replace=True)
    kept = [p for p in live.iterdir() if p.name.startswith(".lgk-full-rollback-")]
    assert kept and any(f.read_text("utf-8") == "old vault" for f in kept[0].iterdir())
