"""Stage 4a: backups, restore as a new profile, the recovery phrase and phrase recovery."""
from __future__ import annotations

import json

import pytest

from localvault.api.result import ApiError
from localvault.app.controller import WebController
from localvault.app.recovery import RecoveryWebService
from localvault.profiles import ProfileManager
from localvault.settings import AppSettings

KDF = {"time_cost": 1, "memory_cost_kib": 8192, "parallelism": 1, "hash_len": 32}
MASTER = "correct horse battery"
BACKUP = "a separate backup pw"


class Bus:
    def emit(self, name, detail):
        pass


class Sched:
    def call_later(self, delay, fn):
        return fn

    def cancel(self, handle):
        pass


class Port:
    def __init__(self):
        self.asked, self.answers = [], []

    def confirm(self, title, message):
        self.asked.append(title)
        return self.answers.pop(0) if self.answers else True


class Dialogs:
    def __init__(self):
        self.save_to = None
        self.open_from = None

    def save_file(self, title, name):
        return self.save_to

    def open_file(self, title):
        return self.open_from


@pytest.fixture
def env(tmp_path, monkeypatch):
    monkeypatch.setattr("localvault.app.controller.clear_master_unlock_requirement", lambda _pid: None)
    profiles = ProfileManager(tmp_path / "data")
    profiles.ensure_profile()
    controller = WebController(profiles=profiles, settings=AppSettings(idle_source="vault"), bus=Bus(),
                               scheduler=Sched(), create_kwargs={"kdf_overrides": KDF})
    controller.create(MASTER, MASTER)
    controller.session.create_web_login(urls=[{"url": "https://a.test", "match": "exact_origin"}], username="a",
                                        password="pw-1234567890", label="Alpha")
    dialogs = Dialogs()
    port = Port()
    service = RecoveryWebService(controller, port, dialogs)
    return service, controller, port, dialogs, tmp_path


def test_create_backup_validates_passwords(env):
    service, _c, _p, dialogs, tmp = env
    dialogs.save_to = tmp / "b.lgk"
    with pytest.raises(ApiError) as mismatch:
        service.create_backup(BACKUP, BACKUP + "x", MASTER)
    assert mismatch.value.message == "Backup passwords do not match."
    with pytest.raises(ApiError) as empty:
        service.create_backup("", "", MASTER)
    assert empty.value.message == "Enter both passwords and confirm the backup password."
    assert not (tmp / "b.lgk").exists()


def test_create_verify_and_restore_round_trip(env):
    service, controller, port, dialogs, tmp = env
    dialogs.save_to = tmp / "b.lgk"
    created = service.create_backup(BACKUP, BACKUP, MASTER)
    assert created["message"] == "Encrypted backup created. Your vault password was not stored in the backup."
    dialogs.open_from = tmp / "b.lgk"
    assert service.verify(BACKUP, MASTER)["message"] == "Backup verified. No profile data was changed."
    before = {p.id for p in controller.profiles.list_profiles()}
    restored = service.restore("Restored", BACKUP, MASTER)
    assert port.asked == ["Restore as a new profile?"]
    assert restored["message"] == "“Restored” was restored as a new profile. Your existing vault is unchanged."
    assert len({p.id for p in controller.profiles.list_profiles()} - before) == 1
    assert controller.is_unlocked()


def test_declined_restore_creates_nothing(env):
    service, controller, port, dialogs, tmp = env
    dialogs.save_to = tmp / "b.lgk"
    service.create_backup(BACKUP, BACKUP, MASTER)
    dialogs.open_from = tmp / "b.lgk"
    port.answers = [False]
    before = {p.id for p in controller.profiles.list_profiles()}
    result = service.restore("Restored", BACKUP, MASTER)
    assert result["message"] == ("Nothing was restored as a new profile. Your existing profiles and current vault "
                                 "are unchanged.")
    assert {p.id for p in controller.profiles.list_profiles()} == before


def test_cancelled_dialog_is_cancelled(env):
    service, *_ = env
    with pytest.raises(ApiError) as cancelled:
        service.verify(BACKUP, MASTER)
    assert cancelled.value.code == "cancelled"


def test_phrase_is_returned_once_and_confirmed_by_words(env):
    service, controller, _p, _d, _t = env
    card = service.phrase_create(MASTER)
    words = card["words"]
    assert len(words) == 24 and len(card["positions"]) == 3
    wrong = service.phrase_confirm(card["token"], ["x", "y", "z"])
    assert wrong["confirmed"] is False and wrong["message"].startswith("Those words do not match")
    right = service.phrase_confirm(card["token"], [words[p - 1] for p in card["positions"]])
    assert right == {"confirmed": True, "message": "Recovery phrase confirmed. Keep the written copy sealed and "
                     "separate from your backups; it is not stored anywhere by LocalGateKeys."}
    with pytest.raises(ApiError):
        service.phrase_confirm(card["token"], [words[p - 1] for p in card["positions"]])
    assert " ".join(words) not in json.dumps(service.__dict__, default=str)
    assert controller.session.has_recovery_phrase()


def test_recover_with_phrase_unlocks_with_new_password(env):
    service, controller, _p, _d, _t = env
    phrase = " ".join(service.phrase_create(MASTER)["words"])
    controller.lock()
    assert service.status()["phrase_enrolled"] is True
    new = "recovered master pw 1"
    with pytest.raises(ApiError) as mismatch:
        controller.recover(phrase, new, new + "x")
    assert mismatch.value.message == "The new passwords did not match."
    controller.recover(phrase, new, new)
    assert controller.is_unlocked()
    controller.lock()
    controller.unlock(new)
    assert controller.is_unlocked()


def test_challenge_keeps_only_the_challenged_words():
    from localvault.app.recovery_center import RecoveryPhraseChallenge
    words = [f"w{i}" for i in range(1, 25)]
    challenge = RecoveryPhraseChallenge(" ".join(words))
    kept = [v for v in vars(challenge).values() if isinstance(v, (tuple, list, dict))]
    flat = repr(kept)
    assert sum(1 for w in words if f"'{w}'" in flat) == 3
    assert challenge.verify([words[p - 1] for p in challenge.positions])


class _Ops:
    def minimize(self):
        pass

    def toggle_maximize(self):
        pass

    def close(self):
        pass


def test_restore_closure_wipes_vault_password_after_confirm(env, monkeypatch):
    import gc

    import localvault.api.bridge as bridge

    service, controller, port, dialogs, tmp = env
    dialogs.save_to = tmp / "b.lgk"
    service.create_backup(BACKUP, BACKUP, MASTER)
    dialogs.open_from = tmp / "b.lgk"
    api = bridge.Api(controller, port, _Ops(), dialogs=dialogs)
    created, seen_at_confirm = [], []
    original_secret = bridge._secret

    def recording_secret(value, name, *args):
        secret = original_secret(value, name, *args)
        created.append(secret)
        return secret

    def confirm(title, message):
        port.asked.append(title)
        seen_at_confirm.append([s.char_count for s in created])
        return True

    monkeypatch.setattr(bridge, "_secret", recording_secret)
    monkeypatch.setattr(port, "confirm", confirm)
    before = {p.id for p in controller.profiles.list_profiles()}
    result = api.backup_restore("Restored", BACKUP, MASTER)
    assert result["ok"] is True, result
    assert port.asked == ["Restore as a new profile?"]
    assert len({p.id for p in controller.profiles.list_profiles()} - before) == 1
    # The bridge made two SecretTexts (the backup password, then the vault password).
    # Both were alive at the prompt and are wiped once the call returns.
    assert seen_at_confirm == [[len(BACKUP), len(MASTER)]] and len(created) == 2
    for secret in created:
        with pytest.raises(ValueError, match="secret was wiped"):
            _ = secret.buffer
    # Nothing in the services keeps either secret after the call returns.
    gc.collect()
    for secret in created:
        assert [r for r in gc.get_referrers(secret) if r is not created] == []
