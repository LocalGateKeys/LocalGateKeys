from __future__ import annotations

import uuid
from pathlib import Path

import pytest

from localvault.import_workflow import (
    ImportCancelled,
    ImportWorkflowError,
    apply_import_plan,
    build_import_plan,
    inspect_source,
)
from localvault.vault import create_vault, unlock_vault

KDF = {"time_cost": 1, "memory_cost_kib": 8192, "parallelism": 1, "hash_len": 32}
MASTER = "next release import reminders master"


@pytest.fixture
def session():
    directory = Path(".n08-test-data") / uuid.uuid4().hex
    directory.mkdir(parents=True, exist_ok=False)
    return create_vault(directory / "vault.json", MASTER, kdf_overrides=KDF)


@pytest.fixture
def source_dir():
    directory = Path(".n08-test-data") / uuid.uuid4().hex
    directory.mkdir(parents=True, exist_ok=False)
    return directory


def test_import_plan_masks_secrets_and_preserves_history(session, source_dir: Path):
    session.upsert_web(origin="https://example.test", username="alice", password="old-password", label="Old")
    source = source_dir / "accounts.csv"
    source.write_text("name,url,username,password,unknown\nNew,https://example.test/path,alice,new-password,formula=1+1\n", encoding="utf-8")
    inspection = inspect_source(source)
    assert inspection.source_format == "chrome-csv"
    assert "unknown" in inspection.unmapped and inspection.row_count == 1
    plan = build_import_plan(session, source)
    assert "new-password" not in repr(plan)
    assert plan.preview[0]["password"] == "********"
    plan.set_decision(2, "merge", fields={"password": "import", "label": "import"})
    plan.review()
    assert apply_import_plan(session, plan) == 1
    entry = session.find_web("https://example.test")[0]
    assert entry["password"] == "new-password"
    assert session.password_history(entry["id"])[0]["password"] == "old-password"


def test_import_plan_rejects_changed_source_and_target(session, source_dir: Path):
    session.upsert_web(origin="https://example.test", username="alice", password="old-password")
    source = source_dir / "accounts.csv"
    source.write_text("url,username,password\nhttps://example.test,alice,new-password\n", encoding="utf-8")
    plan = build_import_plan(session, source)
    plan.set_decision(2, "replace")
    plan.review()
    source.write_text("url,username,password\nhttps://example.test,alice,changed-source\n", encoding="utf-8")
    with pytest.raises(ImportWorkflowError, match="source changed"):
        apply_import_plan(session, plan)


def test_import_cancellation_rolls_back(session, source_dir: Path):
    source = source_dir / "accounts.csv"
    source.write_text("url,username,password\nhttps://one.test,a,password-a\nhttps://two.test,b,password-b\n", encoding="utf-8")
    plan = build_import_plan(session, source)
    plan.review()
    with pytest.raises(ImportCancelled):
        apply_import_plan(session, plan, cancel=lambda: True)
    assert session.find_web("https://one.test") == []
    assert session.find_web("https://two.test") == []


def test_recurring_anchor_clamp_leap_and_ledger(session):
    item = session.items.create_license("Renewal", license_value="masked")
    schedule = session.reminders.create_schedule(item, "2024-01-31", unit="month", interval=1)
    assert session.reminders.next_occurrence(schedule, after="2024-01-31")["due_date"] == "2024-02-29"
    assert session.reminders.next_occurrence(schedule, after="2024-02-29")["due_date"] == "2024-03-31"
    assert session.reminders.process("2024-03-31")
    assert len(session.reminders.occurrence_history(schedule)) == 3
    assert session.reminders.process("2024-03-31") == []

    leap = session.reminders.create_schedule(item, "2024-02-29", unit="year")
    assert session.reminders.next_occurrence(leap, after="2024-02-29")["due_date"] == "2025-02-28"
    assert session.reminders.next_occurrence(leap, after="2025-02-28")["due_date"] == "2026-02-28"


def test_recurring_deadline_event_is_independent_and_cancel_ends_schedule(session):
    item = session.items.create_subscription("Subscription")
    schedule = session.reminders.create_schedule(item, "2030-01-10", unit="month", deadline_days_before=3)
    events = session.reminders.process("2030-01-08")
    assert events and events[0]["kind"] == "deadline"
    deadline = session.reminders.occurrence_history(schedule)[0]
    assert session.reminders.complete_deadline(schedule, deadline["due_date"])
    assert session.reminders.mark_cancelled(schedule)
    assert session.reminders.next_occurrence(schedule, after="2030-02-01") is None


def test_schedule_persists_after_restart(session):
    item = session.items.create_purchase("Purchase")
    sid = session.reminders.create_schedule(item, "2031-02-28", unit="year", max_count=2)
    path = session.path
    session.lock()
    reopened = unlock_vault(path, MASTER)
    assert reopened.reminders.get_schedule(sid)["max_count"] == 2
    reopened.lock()
