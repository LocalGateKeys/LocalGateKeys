"""Restoring a phone backup (.lgkm) through the WebView service."""
from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest
from test_sync_vault_bridge import NOW, FakeLease, _vault

from localvault import licensing
from localvault.api.result import ApiError
from localvault.app import phone_backup_web
from localvault.app.controller import WebController
from localvault.app.phone_backup_web import PhoneBackupService
from localvault.phone_backup import write_phone_backup
from localvault.profiles import ProfileManager
from localvault.session_guard import StaleSession
from localvault.settings import AppSettings
from localvault.sync.engine import ItemState
from localvault.sync.phone_restore import RestoreReport
from localvault.sync.vault_bridge import BridgeError, local_view

KDF = {"time_cost": 1, "memory_cost_kib": 8192, "parallelism": 1, "hash_len": 32}
FAST_KDF = {"name": "argon2id", "time_cost": 1, "memory_cost_kib": 8192, "parallelism": 1}
MASTER = "correct horse battery"
BACKUP_PW = "a phone backup pw"


class Bus:
    def emit(self, name, detail):
        pass


class Sched:
    def call_later(self, delay, fn):
        return fn

    def cancel(self, handle):
        pass


class Dialogs:
    def __init__(self):
        self.path = None

    def open_file(self, title, file_types=None):
        assert title == "Restore phone backup (.lgkm)"
        assert file_types == ("LocalGateKeys phone backup (*.lgkm)", "All files (*.*)")
        return self.path


SYNC_VECTORS = Path(__file__).parent / "vectors" / "sync"
BACKUP_VECTORS = Path(__file__).parent / "vectors" / "backup"


def _vector_licence_keys(monkeypatch) -> dict:
    """Trust the TEST licence key of the sync vectors, as tests/test_sync_vectors.py does."""
    state = json.loads((SYNC_VECTORS / "license_state.json").read_text(encoding="utf-8"))
    monkeypatch.setattr(licensing, "LICENSE_KEYS", {state["key_id"]: state["public_key_b64"]})
    monkeypatch.setattr(licensing, "_cached_revoked_ids", lambda: frozenset())
    return state


def _make_backup(tmp_path, notes: int, name: str = "phone.lgkm", extra=()) -> str:
    phone = _vault(tmp_path, "phone-" + name)
    for index in range(notes):
        phone.item_service.create_note(f"Note {index}", "body")
    states = [*local_view(phone, FakeLease(), device_id="phone", now=NOW).values(), *extra]
    data = write_phone_backup(states, password=BACKUP_PW, device_id="phone", platform="android",
                              app_version="1.0", created_at=NOW, pro_hint=False, kdf=FAST_KDF)
    path = tmp_path / name
    path.write_bytes(data)
    return str(path)


@pytest.fixture
def env(tmp_path, monkeypatch):
    monkeypatch.setattr("localvault.app.controller.clear_master_unlock_requirement", lambda pid: None)
    profiles = ProfileManager(tmp_path / "data")
    profiles.ensure_profile()
    controller = WebController(profiles=profiles, settings=AppSettings(idle_source="vault"), bus=Bus(),
                               scheduler=Sched(), create_kwargs={"kdf_overrides": KDF})
    controller.create(MASTER, MASTER)
    dialogs = Dialogs()
    dialogs.path = _make_backup(tmp_path, 2)
    return SimpleNamespace(controller=controller, dialogs=dialogs, tmp=tmp_path,
                           service=PhoneBackupService(controller, object(), dialogs))


def test_choose_preview_commit_restores_items(env):
    chosen = env.service.choose()
    assert chosen["name"] == "phone.lgkm" and chosen["platform"] == "android"
    assert len(chosen["created"]) == 10 and chosen["created"][4] == "-"
    preview = env.service.preview(chosen["handle"], BACKUP_PW)
    assert preview["lines"][:3] == ["2 new items", "0 items updated from the backup", "0 already up to date"]
    assert env.controller.session.live_item_count() == 0
    done = env.service.commit(preview["token"], chosen["handle"])
    assert done["status"] == "Phone backup restored." and done["changed"] is True
    assert env.controller.session.live_item_count() == 2


def test_commit_refuses_a_stale_or_foreign_token(env):
    chosen = env.service.choose()
    preview = env.service.preview(chosen["handle"], BACKUP_PW)
    for token, handle in (("nope", chosen["handle"]), (preview["token"], "other")):
        with pytest.raises(ApiError) as err:
            env.service.commit(token, handle)
        assert err.value.message == "Preview again before restoring."
    preview = env.service.preview(chosen["handle"], BACKUP_PW)
    env.service.commit(preview["token"], chosen["handle"])
    with pytest.raises(ApiError):  # a token is single use
        env.service.commit(preview["token"], chosen["handle"])


def test_lock_between_preview_and_restore_refuses(env):
    chosen = env.service.choose()
    preview = env.service.preview(chosen["handle"], BACKUP_PW)
    env.controller.lock()
    assert env.service._plans == {} and env.service._paths == {}
    with pytest.raises(ApiError):
        env.service.commit(preview["token"], chosen["handle"])


def test_password_is_never_kept(env):
    chosen = env.service.choose()
    env.service.preview(chosen["handle"], BACKUP_PW)
    assert BACKUP_PW not in repr(env.service.__dict__)


def test_five_wrong_passwords_then_wait(env, monkeypatch):
    clock = [1000.0]
    monkeypatch.setattr(phone_backup_web.time, "monotonic", lambda: clock[0])
    chosen = env.service.choose()
    for _ in range(5):
        with pytest.raises(ApiError) as err:
            env.service.preview(chosen["handle"], "wrong password")
        assert err.value.code == "invalid"
    with pytest.raises(ApiError) as busy:
        env.service.preview(chosen["handle"], BACKUP_PW)
    assert busy.value.code == "busy" and busy.value.message == "Too many attempts. Try again in 30 seconds."
    clock[0] += 31
    assert env.service.preview(chosen["handle"], BACKUP_PW)["token"]


def test_success_resets_the_wrong_count(env):
    chosen = env.service.choose()
    for _ in range(4):
        with pytest.raises(ApiError):
            env.service.preview(chosen["handle"], "wrong password")
    env.service.preview(chosen["handle"], BACKUP_PW)
    for _ in range(4):
        with pytest.raises(ApiError) as err:
            env.service.preview(chosen["handle"], "wrong password")
        assert err.value.code == "invalid"


def test_free_plan_lines_mention_held_back_items(env):
    env.dialogs.path = _make_backup(env.tmp, 6, "big.lgkm")
    chosen = env.service.choose()
    preview = env.service.preview(chosen["handle"], BACKUP_PW)
    assert preview["lines"][0] == "4 new items"
    assert "2 items held back by the free plan's 4-item limit" in preview["lines"]


def test_not_a_backup_file_is_refused_at_choose(env):
    junk = env.tmp / "junk.lgkm"
    junk.write_bytes(b"this is not a backup")
    env.dialogs.path = str(junk)
    with pytest.raises(ApiError) as err:
        env.service.choose()
    assert err.value.code == "invalid"


def test_oversized_file_is_refused(env, monkeypatch):
    monkeypatch.setattr(phone_backup_web, "MAX_FILE_BYTES", 10)
    with pytest.raises(ApiError) as err:
        env.service.choose()
    assert err.value.code == "invalid"


def test_cancelled_dialog(env):
    env.dialogs.path = None
    with pytest.raises(ApiError) as err:
        env.service.choose()
    assert err.value.code == "cancelled"


def _previewed(env):
    chosen = env.service.choose()
    return chosen["handle"], env.service.preview(chosen["handle"], BACKUP_PW)["token"]


def test_stale_session_during_plan_is_locked(env, monkeypatch):
    chosen = env.service.choose()

    def stale(*args, **kwargs):
        raise StaleSession("gone")

    monkeypatch.setattr(phone_backup_web, "plan_restore", stale)
    with pytest.raises(ApiError) as err:
        env.service.preview(chosen["handle"], BACKUP_PW)
    assert err.value.code == "locked" and err.value.message == "Unlock this profile first."
    assert env.controller.session.live_item_count() == 0


def test_stale_session_during_restore_is_locked_and_writes_nothing(env, monkeypatch):
    handle, token = _previewed(env)
    monkeypatch.setattr(phone_backup_web, "restore", lambda *a, **k: (_ for _ in ()).throw(StaleSession("gone")))
    with pytest.raises(ApiError) as err:
        env.service.commit(token, handle)
    assert err.value.code == "locked"
    assert env.controller.session.live_item_count() == 0


def test_other_bridge_errors_hide_the_raw_text(env, monkeypatch):
    chosen = env.service.choose()
    monkeypatch.setattr(phone_backup_web, "plan_restore",
                        lambda *a, **k: (_ for _ in ()).throw(BridgeError("secret detail")))
    with pytest.raises(ApiError) as err:
        env.service.preview(chosen["handle"], BACKUP_PW)
    assert err.value.code == "invalid" and "secret" not in err.value.message
    assert err.value.message == "The vault could not be read for the restore."


@pytest.mark.parametrize("kind,reason", [
    ("trash-full", "the trash is full"),
    ("history-quota", "item history is full"),
    ("busy", "the vault changed while restoring. Try again"),
    ("local-data", "the vault could not be updated"),
    ("apply-failed", "the vault could not be updated"),
])
def test_fatal_issue_gives_a_plain_reason(env, monkeypatch, kind, reason):
    handle, token = _previewed(env)
    monkeypatch.setattr(phone_backup_web, "restore", lambda *a, **k: RestoreReport(0, 0, 0, 0, (kind,)))
    done = env.service.commit(token, handle)
    assert done["status"] == f"Nothing was restored: {reason}." and done["changed"] is False


def test_quarantined_records_are_counted_not_fatal(env, monkeypatch):
    handle, token = _previewed(env)
    monkeypatch.setattr(phone_backup_web, "restore", lambda *a, **k: RestoreReport(
        1, 0, 0, 0, ("bad-peer-record", "update-needed"), skipped=2))
    done = env.service.commit(token, handle)
    assert done["status"] == "Phone backup restored. 2 items this version cannot read were skipped."
    assert done["changed"] is True


def test_quarantine_only_restore_says_nothing_was_restored(env, monkeypatch):
    handle, token = _previewed(env)
    monkeypatch.setattr(phone_backup_web, "restore",
                        lambda *a, **k: RestoreReport(0, 0, 0, 0, ("bad-peer-record",), skipped=1))
    done = env.service.commit(token, handle)
    assert done["status"] == "Nothing was restored: 1 items this version cannot read were skipped."
    assert done["changed"] is False


def test_unreadable_records_are_announced_in_the_preview(env):
    source = _vault(env.tmp, "copy-src")
    source.item_service.create_note("Engine form", "body")
    state = next(iter(local_view(source, FakeLease(), device_id="phone", now=NOW).values()))
    engine_copy = ItemState("engine-copy-1", state.vv, False, None, {**state.item, "id": "engine-copy-1"})
    env.dialogs.path = _make_backup(env.tmp, 1, "bad.lgkm", extra=[engine_copy])
    chosen = env.service.choose()
    preview = env.service.preview(chosen["handle"], BACKUP_PW)
    assert preview["lines"][0] == "1 new items"
    assert "1 items this version cannot read will be skipped" in preview["lines"]
    done = env.service.commit(preview["token"], chosen["handle"])
    assert done["status"] == "Phone backup restored. 1 items this version cannot read were skipped."
    assert env.controller.session.live_item_count() == 1


def _write(path, states) -> str:
    path.write_bytes(write_phone_backup(states, password=BACKUP_PW, device_id="phone", platform="android",
                                        app_version="1.0", created_at=NOW, pro_hint=False, kdf=FAST_KDF))
    return str(path)


def test_phone_deletions_move_items_to_the_trash(env):
    phone = _vault(env.tmp, "phone-del")
    keep = phone.item_service.create_note("Keep", "body")
    gone = phone.item_service.create_note("Gone", "body")
    lease = FakeLease()
    env.dialogs.path = _write(env.tmp / "first.lgkm", list(local_view(phone, lease, device_id="phone",
                                                                      now=NOW).values()))
    chosen = env.service.choose()
    env.service.commit(env.service.preview(chosen["handle"], BACKUP_PW)["token"], chosen["handle"])
    phone.item_service.delete_item(gone)
    env.dialogs.path = _write(env.tmp / "second.lgkm", list(local_view(phone, lease, device_id="phone",
                                                                       now=NOW).values()))
    chosen = env.service.choose()
    preview = env.service.preview(chosen["handle"], BACKUP_PW)
    assert "1 items moved to the trash (deleted on the phone)" in preview["lines"]
    done = env.service.commit(preview["token"], chosen["handle"])
    assert "1 items moved to the trash (deleted on the phone)" in done["lines"]
    assert done["changed"] is True
    payload = env.controller.session._require_typed_catalog()
    assert {r["id"] for r in payload["items"]} == {keep}


def test_restored_licence_is_adopted_and_asks_to_restore_again(env, monkeypatch):
    state = _vector_licence_keys(monkeypatch)
    calls = []
    service = PhoneBackupService(env.controller, object(), env.dialogs, on_licence=lambda: calls.append(1))
    devices = json.loads((SYNC_VECTORS / "identities.json").read_text(encoding="utf-8"))["devices"]
    licence = ItemState(state["state_id"], {devices["A"]["device_id"]: 1}, False, None, state["wrapper"])
    env.dialogs.path = _make_backup(env.tmp, 6, "pro.lgkm", extra=[licence])
    assert licensing.status().state == "free"
    chosen = service.choose()
    preview = service.preview(chosen["handle"], BACKUP_PW)
    assert "2 items held back by the free plan's 4-item limit" in preview["lines"]
    done = service.commit(preview["token"], chosen["handle"])
    assert done["status"] == ("Phone backup restored. Your Pro licence was restored. "
                              "Restore again to bring back the 2 held-back items.")
    assert licensing.status().state == "pro" and calls == [1]
    session = env.controller.session
    assert session.item_limit is None and session.live_item_count() == 4
    assert state["state_id"] in session._require_typed_catalog()["sync_licenses"]
    chosen = service.choose()
    again = service.preview(chosen["handle"], BACKUP_PW)
    assert again["lines"][0] == "2 new items"
    service.commit(again["token"], chosen["handle"])
    assert session.live_item_count() == 6


def test_oversized_file_at_preview_is_refused(env, monkeypatch):
    chosen = env.service.choose()
    monkeypatch.setattr(phone_backup_web, "MAX_FILE_BYTES", 10)
    with pytest.raises(ApiError) as err:
        env.service.preview(chosen["handle"], BACKUP_PW)
    assert err.value.code == "invalid"


def test_cancel_drops_plans_and_handles(env):
    handle, token = _previewed(env)
    assert env.service.cancel() == {}
    assert env.service._plans == {} and env.service._paths == {}
    with pytest.raises(ApiError):
        env.service.commit(token, handle)


def test_published_vector_backup_restores_end_to_end(env, monkeypatch):
    """The committed cross-platform vector file, production KDF, through choose, preview and commit."""
    state = _vector_licence_keys(monkeypatch)
    expected = json.loads((BACKUP_VECTORS / "expected.json").read_text(encoding="utf-8"))
    states = json.loads(expected["payload_canonical"])["states"]
    live = {s["id"]: s["item"]["record"] for s in states
            if not s["deleted"] and s["item"]["ns"] in ("entry", "item")}
    assert len(live) == 8  # logins, notes, a bookmark, a desktop login and two conflict copies
    assert all(record["id"] == item_id for item_id, record in live.items())  # the stored form

    env.controller.session.item_limit = None  # a Pro vault: no 4-item cap, two-factor keys kept
    env.controller.session.pro_features = None
    env.dialogs.path = str(BACKUP_VECTORS / "backup.lgkm")
    chosen = env.service.choose()
    assert chosen["platform"] == "android"
    preview = env.service.preview(chosen["handle"], expected["password"])
    assert preview["lines"] == [f"{len(live)} new items", "0 items updated from the backup",
                                "0 already up to date"]
    done = env.service.commit(preview["token"], chosen["handle"])
    assert done["changed"] is True
    assert done["status"].startswith("Phone backup restored.") and "skipped" not in done["status"]
    assert done["lines"] == [f"{len(live)} new items", "0 items updated from the backup"]
    assert set(env.controller.session._require_typed_catalog().get("sync_licenses", {})) == {state["state_id"]}

    payload = env.controller.session._require_typed_catalog()
    restored = {r["id"]: r for key in ("entries", "items") for r in payload.get(key, [])}
    assert env.controller.session.live_item_count() == len(live)
    assert set(restored) == set(live)
    for item_id, record in live.items():
        assert restored[item_id]["updated_at"] == record["updated_at"]
        for field in ("kind", "label", "title", "username", "password", "notes"):
            assert restored[item_id].get(field) == record.get(field), (item_id, field)
