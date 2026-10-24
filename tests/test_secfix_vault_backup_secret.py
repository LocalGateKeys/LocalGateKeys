"""L-24 (audit 2026-10-24): a SecretText backup password flows through the recovery services unconverted."""
from __future__ import annotations

import pytest

from localvault import backup as backup_module
from localvault.api.result import ApiError
from localvault.secret_text import SecretText
from tests.test_app_recovery import BACKUP, MASTER, env  # noqa: F401 - pytest fixture


@pytest.fixture
def derived(monkeypatch):
    seen: list[type] = []
    original = backup_module._derive

    def recording(password, salt, kdf):
        seen.append(type(password))
        return original(password, salt, kdf)

    monkeypatch.setattr(backup_module, "_derive", recording)
    return seen


def _secret(value: str) -> SecretText:
    return SecretText.from_str(value)


def test_secret_backup_password_round_trip(env, derived) -> None:  # noqa: F811 - the imported fixture
    service, controller, _port, dialogs, tmp = env
    dialogs.save_to = tmp / "b.lgk"
    created = service.create_backup(_secret(BACKUP), _secret(BACKUP), _secret(MASTER))
    assert created["message"].startswith("Encrypted backup created.")
    dialogs.open_from = tmp / "b.lgk"
    assert service.verify(_secret(BACKUP), _secret(MASTER))["message"] == (
        "Backup verified. No profile data was changed.")
    before = {p.id for p in controller.profiles.list_profiles()}
    service.restore("Restored", _secret(BACKUP), _secret(MASTER))
    assert len({p.id for p in controller.profiles.list_profiles()} - before) == 1
    assert derived and all(kind is SecretText for kind in derived), derived


def test_secret_backup_password_mismatch_and_blank_are_refused(env) -> None:  # noqa: F811
    service, _c, _p, dialogs, tmp = env
    dialogs.save_to = tmp / "b.lgk"
    with pytest.raises(ApiError) as mismatch:
        service.create_backup(_secret(BACKUP), _secret(BACKUP + "x"), _secret(MASTER))
    assert mismatch.value.message == "Backup passwords do not match."
    with pytest.raises(ApiError) as blank:
        service.create_backup(_secret(""), _secret(""), _secret(MASTER))
    assert blank.value.message == "Enter both passwords and confirm the backup password."
    with pytest.raises(ApiError):
        service.verify(_secret(""), _secret(MASTER))
    assert not (tmp / "b.lgk").exists()


def test_secret_backup_password_equal_to_master_is_refused(env) -> None:  # noqa: F811
    service, _c, _p, dialogs, tmp = env
    dialogs.save_to = tmp / "b.lgk"
    with pytest.raises(ApiError):
        service.create_backup(_secret(MASTER), _secret(MASTER), _secret(MASTER))
    assert not (tmp / "b.lgk").exists()


def test_secret_backup_password_test_restore(env, derived) -> None:  # noqa: F811
    service, _controller, _port, dialogs, tmp = env
    dialogs.save_to = tmp / "b.lgk"
    service.create_backup(BACKUP, BACKUP, MASTER)
    derived.clear()
    dialogs.open_from = tmp / "b.lgk"
    result = service.test_restore(_secret(BACKUP), _secret(MASTER))
    assert "message" in result
    assert derived and all(kind is SecretText for kind in derived), derived
    service.cancel_trial()
