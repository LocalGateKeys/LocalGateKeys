"""The desktop opens the phone backup the Android Kotlin core wrote (tests/vectors/backup/from_android).

Written by ``LGK_WRITE_FROM_ANDROID=1 android/gradlew -p android :lgk-core:test --tests "*FromAndroidTest*"``
together with tests/vectors/sync/from_android: the backup holds the states of the phone's own local view after
its second sync run, so they equal the states of its device file.  Production Argon2id costs (128 MiB).
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from test_sync_vault_bridge import FakeLease, _vault

from localvault.phone_backup import PhoneBackupError, inspect_phone_backup, read_phone_backup
from localvault.sync.group import GroupKey, decode_view
from localvault.sync.phone_restore import plan_restore, restore

ROOT = Path(__file__).resolve().parents[1]
SYNC = ROOT / "tests" / "vectors" / "sync"
BACKUP = ROOT / "tests" / "vectors" / "backup" / "from_android" / "backup.lgkm"
ANDROID_DEVICE_ID = "7086dd0d-47e4-4d5c-864a-d61f6196ab85"
PASSWORD = "correct horse battery staple 42"
T0 = 1_790_000_000
NEW_WEB_LOGIN = "f1050000-0000-4000-8000-000000000201"
NEW_PASSKEY = "f1050000-0000-4000-8000-000000000202"


@pytest.fixture(scope="module")
def backup():
    return read_phone_backup(BACKUP.read_bytes(), PASSWORD)


@pytest.fixture(scope="module")
def device_states():
    expected = json.loads((SYNC / "expected.json").read_text(encoding="utf-8"))
    entry = expected["epochs"]["1"]
    key = GroupKey(expected["group_id"], 1, bytes.fromhex(entry["group_key_hex"]))
    raw = (SYNC / "from_android" / "devices" / f"{ANDROID_DEVICE_ID}.lgksync").read_bytes()
    return decode_view(key, raw, expected_device_id=ANDROID_DEVICE_ID).states


def test_header_is_the_documented_one():
    header = inspect_phone_backup(BACKUP.read_bytes())
    assert header.platform == "android"
    assert header.created_at == T0 + 1030
    assert header.kdf["time_cost"] == 4 and header.kdf["memory_cost_kib"] == 131072
    assert header.kdf["parallelism"] == 4


def test_desktop_opens_the_android_backup(backup):
    assert backup.device_id == ANDROID_DEVICE_ID
    assert backup.app_version == "1.0.0"
    assert backup.pro_hint is False
    assert {NEW_WEB_LOGIN, NEW_PASSKEY} <= {s.item_id for s in backup.states}


def test_wrong_password_is_refused():
    with pytest.raises(PhoneBackupError) as err:
        read_phone_backup(BACKUP.read_bytes(), "wrong")
    assert err.value.reason == "wrong-password-or-damaged"


def test_backup_states_equal_the_device_file_states(backup, device_states):
    mine = sorted(backup.states, key=lambda s: s.item_id)
    theirs = sorted(device_states, key=lambda s: s.item_id)
    assert [s.item_id for s in mine] == [s.item_id for s in theirs]
    for a, b in zip(mine, theirs, strict=True):
        assert (a.vv, a.deleted, a.deleted_at, a.item) == (b.vv, b.deleted, b.deleted_at, b.item), a.item_id


def test_restore_into_a_scratch_pro_vault_has_no_issues(tmp_path, backup):
    desk = _vault(tmp_path, "desk")
    desk.item_limit = None  # a Pro vault: no 4-item cap
    desk.pro_features = None
    lease = FakeLease()
    live = [s for s in backup.states if not s.deleted and s.item["ns"] in ("entry", "item")]
    plan = plan_restore(desk, lease, backup, now=T0 + 2000)
    assert plan.held_back == 0 and plan.skipped == 0
    assert plan.new == len(live) and plan.updated == 0 and plan.unchanged == 0
    report = restore(desk, lease, plan, now=T0 + 2000)
    assert report.issues == ()
    assert report.new == len(live) and report.held_back == 0 and report.skipped == 0
    restored = {r["id"]: r for key in ("entries", "items") for r in desk._payload[key]}
    assert set(restored) == {s.item_id for s in live}
    assert restored[NEW_WEB_LOGIN]["label"] == "Créé sur Android"
    assert restored[NEW_PASSKEY]["kind"] == "passkey"
    assert restored["22222222-aaaa-4000-8000-000000000002"]["title"] == "Edited on Android"
    # a second restore changes nothing
    again = plan_restore(desk, lease, backup, now=T0 + 2100)
    assert (again.new, again.updated) == (0, 0)
