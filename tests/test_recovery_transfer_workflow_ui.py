from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

from localvault.app import recovery_center


def test_recovery_center_preview_drops_forwarded_confirm_flag(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    from localvault.recovery import sha256_file
    from localvault.app.recovery_center import RecoveryCenter

    source = tmp_path / "full.lgk"
    source.write_bytes(b"PK\x03\x04synthetic full backup")
    destination = tmp_path / "new-profile"
    seen: dict[str, object] = {}

    def plan(_source, _destination, **kwargs):
        seen.update(kwargs)
        return {"operation": "restore", "backup_sha256": sha256_file(source),
                "requires_confirmation": True, "dry_run": True}

    monkeypatch.setattr(recovery_center, "plan_restore_as_new_profile", plan)
    center = RecoveryCenter(service=SimpleNamespace())
    center.restore(source, destination, confirm=False, backup_password="synthetic backup password",
                   vault_password="synthetic vault password")

    assert "confirm" not in seen


def test_recovery_center_requires_current_backup_fingerprint_before_mutation(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from localvault.app.recovery_center import RecoveryCenter

    source = tmp_path / "catalog.lgk"
    source.write_text("{}", encoding="utf-8")
    calls: list[object] = []
    monkeypatch.setattr(recovery_center, "restore_verified_backup", lambda *_args, **_kwargs: calls.append("restore"))
    center = RecoveryCenter(service=SimpleNamespace())

    with pytest.raises(recovery_center.RecoveryError, match="confirmation is out of date"):
        center.restore(source, tmp_path / "restore-test", confirm=True,
                      backup_password="synthetic backup password", vault_password="synthetic vault password")
    assert calls == []

    with pytest.raises(recovery_center.RecoveryError, match="changed after preview"):
        center.restore(source, tmp_path / "restore-test", confirm=True, expected_sha256="0" * 64,
                      backup_password="synthetic backup password", vault_password="synthetic vault password")
    assert calls == []


def test_recovery_center_catalog_trial_restores_snapshot_only_after_current_check(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    from localvault.recovery import sha256_file
    from localvault.app.recovery_center import RecoveryCenter

    source = tmp_path / "catalog.lgk"
    source.write_text('{"format":"synthetic"}', encoding="utf-8")
    destination = tmp_path / "trial-profile"
    expected = sha256_file(source)
    calls: list[Path] = []
    checks = 0

    def current_check() -> None:
        nonlocal checks
        checks += 1

    def restore(snapshot: Path, *, vault_file: Path, settings_file: Path, **_kwargs):
        calls.append(snapshot)
        assert snapshot != source
        assert snapshot.read_bytes() == source.read_bytes()
        vault_file.parent.mkdir(parents=True, exist_ok=True)
        vault_file.write_text("encrypted", encoding="utf-8")
        return {"verified": True}

    monkeypatch.setattr(recovery_center, "restore_verified_backup", restore)
    center = RecoveryCenter(service=SimpleNamespace(), current_check=current_check)
    result = center.restore(source, destination, confirm=True, expected_sha256=expected,
                            backup_password="synthetic backup password", vault_password="synthetic vault password")

    assert len(calls) == 1
    assert checks >= 3
    assert result["committed"] is True
    assert result["source"] == str(source.absolute())


def test_recovery_center_stale_stamp_stops_before_restore(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from localvault.recovery import sha256_file
    from localvault.app.recovery_center import RecoveryCenter

    source = tmp_path / "catalog.lgk"
    source.write_text("{}", encoding="utf-8")
    calls: list[str] = []
    checks = 0

    def current_check() -> None:
        nonlocal checks
        checks += 1
        if checks == 2:
            raise recovery_center.RecoveryError("selected profile changed")

    monkeypatch.setattr(recovery_center, "restore_verified_backup", lambda *_args, **_kwargs: calls.append("restore"))
    center = RecoveryCenter(service=SimpleNamespace(), current_check=current_check)
    with pytest.raises(recovery_center.RecoveryError, match="selected profile changed"):
        center.restore(source, tmp_path / "trial-profile", confirm=True, expected_sha256=sha256_file(source),
                       backup_password="synthetic backup password", vault_password="synthetic vault password")
    assert calls == []


