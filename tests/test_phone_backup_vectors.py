"""The desktop restores the phone backup the iOS Swift core wrote (tests/vectors/backup/from_ios).

Written by ``LGK_WRITE_FROM_IOS=1 swift test --filter PhoneBackupTests`` (ios/LGKCore) from the fixed inputs of
tests/vectors/backup/README.md with ``platform`` ``ios``.  Production Argon2id costs (128 MiB).
"""

from __future__ import annotations

import base64
import json
from pathlib import Path

import pytest
from test_sync_vault_bridge import FakeLease, _vault

from localvault.phone_backup import PhoneBackupError, inspect_phone_backup, read_phone_backup, write_phone_backup
from localvault.sync.phone_restore import plan_restore, restore

ROOT = Path(__file__).resolve().parents[1]
VEC = ROOT / "tests" / "vectors" / "backup"
BACKUP = VEC / "from_ios" / "backup.lgkm"
EXPECTED = json.loads((VEC / "expected.json").read_text(encoding="utf-8"))
PASSWORD = EXPECTED["password"]
T0 = EXPECTED["created_at"]


@pytest.fixture(scope="module")
def backup():
    return read_phone_backup(BACKUP.read_bytes(), PASSWORD)


def test_header_is_ios():
    header = inspect_phone_backup(BACKUP.read_bytes())
    assert header.platform == "ios"
    assert header.created_at == T0
    assert header.kdf == {"name": "argon2id", "time_cost": 4, "memory_cost_kib": 131072, "parallelism": 4}


def test_swift_bytes_equal_the_reference_writer(backup):
    again = write_phone_backup(backup.states, password=PASSWORD, device_id=EXPECTED["device_id"], platform="ios",
                               app_version=EXPECTED["app_version"], created_at=T0, pro_hint=EXPECTED["pro_hint"],
                               _salt=base64.b64decode(EXPECTED["salt_b64"]),
                               _nonce=base64.b64decode(EXPECTED["nonce_b64"]))
    assert again == BACKUP.read_bytes()


def test_payload_equals_the_fixed_inputs(backup):
    assert backup.device_id == EXPECTED["device_id"]
    assert backup.app_version == EXPECTED["app_version"]
    assert backup.pro_hint is EXPECTED["pro_hint"]
    got = [{"deleted": s.deleted, "deleted_at": s.deleted_at, "id": s.item_id, "item": s.item, "vv": dict(s.vv)}
           for s in backup.states]
    assert got == EXPECTED["states"]


def test_wrong_password_is_refused():
    with pytest.raises(PhoneBackupError) as err:
        read_phone_backup(BACKUP.read_bytes(), "wrong")
    assert err.value.reason == "wrong-password-or-damaged"


def test_restores_ios_vector(tmp_path, backup):
    desk = _vault(tmp_path, "desk")
    desk.item_limit = None  # a Pro vault: no 4-item cap
    desk.pro_features = None
    lease = FakeLease()
    live = [s for s in backup.states if not s.deleted and s.item["ns"] in ("entry", "item")]
    tombstones = [s for s in backup.states if s.deleted]
    assert live and tombstones
    plan = plan_restore(desk, lease, backup, now=T0 + 2000)
    assert plan.held_back == 0
    assert plan.new == len(live) and plan.updated == 0 and plan.unchanged == 0
    report = restore(desk, lease, plan, now=T0 + 2000)
    assert report.issues == ()
    restored = {r["id"]: r for key in ("entries", "items") for r in desk._payload[key]}
    assert set(restored) == {s.item_id for s in live}
    assert not {s.item_id for s in tombstones} & set(restored)
    again = plan_restore(desk, lease, backup, now=T0 + 2100)
    assert (again.new, again.updated) == (0, 0)
