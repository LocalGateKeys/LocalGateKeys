from __future__ import annotations

import uuid
from pathlib import Path

import pytest

from localvault.item_schema import ItemSchemaError
from localvault.vault import VaultLockedError, create_vault, unlock_vault

KDF = {"time_cost": 1, "memory_cost_kib": 8192, "parallelism": 1, "hash_len": 32}
MASTER = "m5 reminder test master password"


@pytest.fixture
def session() -> object:
    directory = Path(".m5-test-data") / uuid.uuid4().hex
    directory.mkdir(parents=True, exist_ok=False)
    return create_vault(directory / "vault.json", MASTER, kdf_overrides=KDF)


def test_reminder_crud_dates_snooze_complete_and_encrypted_restart(session) -> None:
    item_id = session.items.create_license("Editor", license_value="DO-NOT-LOG")
    other_id = session.items.create_purchase("Renewal")

    with pytest.raises(ItemSchemaError):
        session.reminders.create(str(uuid.uuid4()), "2030-01-10")

    reminder_id = session.reminders.create(item_id, "2030-01-10", lead_days=2)
    overdue_id = session.reminders.create(other_id, "2029-12-01")
    assert {row["id"] for row in session.reminders.due("2030-01-08")} == {reminder_id}
    assert {row["id"] for row in session.reminders.overdue("2030-01-01")} == {overdue_id}
    assert {row["id"] for row in session.reminders.upcoming(1, from_date="2030-01-07")} == {
        reminder_id
    }

    assert session.reminders.update(reminder_id, due_date="2030-01-12", lead_days=0)
    assert session.reminders.get(reminder_id)["due_date"] == "2030-01-12"
    assert session.reminders.snooze(reminder_id, until="2030-01-15")
    assert session.reminders.due("2030-01-12") == []
    assert {row["id"] for row in session.reminders.due("2030-01-15")} == {reminder_id}

    assert session.reminders.complete(reminder_id)
    assert session.reminders.get(reminder_id)["status"] == "dismissed"
    assert session.reminders.due("2030-01-15") == []
    assert session.reminders.delete(overdue_id)
    assert session.reminders.get(overdue_id) is None
    stale_id = session.reminders.create(other_id, "2030-02-01")

    # Item deletion commits through the vault validator, which prunes stale
    # live-item references rather than leaving hidden rows in the catalog.
    assert session.items.delete_item(other_id)
    assert [row["id"] for row in session.reminders.list()] == [reminder_id]
    assert session.reminders.get(stale_id) is None
    session.lock()
    reopened = unlock_vault(session.path, MASTER)
    assert [row["id"] for row in reopened.reminders.list()] == [reminder_id]
    reopened.lock()


def test_reminder_scheduler_is_local_and_cleared_by_lock(session) -> None:
    item_id = session.items.create_warranty("Warranty")
    session.reminders.create(item_id, "2030-01-10")
    scheduler = session.reminder_scheduler
    scheduler.start()
    assert scheduler.active
    assert scheduler.poll("2030-01-10") == [
        {
            "id": session.reminders.list()[0]["id"],
            "item_id": item_id,
            "due_date": "2030-01-10",
        }
    ]

    session.lock()
    assert not scheduler.active
    assert session._reminder_service is None
    assert session._reminder_scheduler is None
    with pytest.raises(VaultLockedError):
        _ = session.reminders
    with pytest.raises(VaultLockedError):
        scheduler.start()
