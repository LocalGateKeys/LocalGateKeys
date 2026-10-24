from __future__ import annotations

import time
import uuid
from pathlib import Path

import pytest

from localvault.activity import ActivityService
from localvault.item_schema import ItemSchemaError
from localvault.vault import VaultError, VaultLockedError, create_vault

KDF = {"time_cost": 1, "memory_cost_kib": 8192, "parallelism": 1, "hash_len": 32}
MASTER = "m5 activity test master password"


@pytest.fixture
def session() -> object:
    directory = Path(".m5-test-data") / uuid.uuid4().hex
    directory.mkdir(parents=True, exist_ok=False)
    return create_vault(directory / "vault.json", MASTER, kdf_overrides=KDF)


def test_activity_is_allowlisted_content_free_and_retentive(session) -> None:
    item_id = session.items.create_license("Editor", license_value="LICENSE-SECRET")
    service = ActivityService(session, retention_days=1, max_events=3)
    old = int(time.time()) - 2 * 86400
    service.record("item.update", item_id=item_id, count=1, timestamp=old)
    for _ in range(4):
        service.record("item.update", item_id=item_id)

    events = service.list()
    assert len(events) == 3
    assert all(set(event) == {"id", "event_type", "timestamp", "item_id", "result", "count"}
               for event in events)
    assert all("LICENSE-SECRET" not in repr(event) for event in events)
    assert "item.update" not in session.path.read_text(encoding="utf-8")

    for field, value in {
        "url": "https://example.test/private",
        "username": "alice@example.test",
        "note_body": "private note body",
        "license_value": "LICENSE-SECRET",
        "path": "C:\\Users\\alice\\secret.txt",
        "secret": "opaque-secret",
    }.items():
        with pytest.raises(ItemSchemaError):
            service.record("item.update", **{field: value})
    with pytest.raises(ItemSchemaError):
        service.record("item.secret")

    raw = session._require_typed_catalog()
    raw["events"].append({
        "id": str(uuid.uuid4()),
        "event_type": "item.update",
        "timestamp": int(time.time()),
        "item_id": item_id,
        "result": "ok",
        "count": 0,
        "path": "C:\\Users\\alice\\secret.txt",
    })
    with pytest.raises(VaultError):
        session.save()

    session.lock()
    with pytest.raises(VaultLockedError):
        service.list()
