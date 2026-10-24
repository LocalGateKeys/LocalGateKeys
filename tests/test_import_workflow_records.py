"""Record-based import workflow: planning, decisions, transactional apply, preview wrapper."""
from __future__ import annotations

import json
import uuid
from pathlib import Path

import pytest

from localvault import import_preview
from localvault.import_workflow import (
    ImportCancelled,
    ImportPlan,
    ImportWorkflowError,
    apply_import_plan,
    build_import_plan,
    inspect_source,
    plan_records,
)
from localvault.importers import ImportedRecord, ImportPasswordRequired
from localvault.importers.kdbx import write_kdbx
from localvault.vault import create_vault

KDF = {"time_cost": 1, "memory_cost_kib": 8192, "parallelism": 1, "hash_len": 32}
MASTER = "record workflow master"
FAST_ARGON = {"memory": 8 * 1024 * 1024, "iterations": 1, "parallelism": 1}


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


def _records() -> list[ImportedRecord]:
    return [
        ImportedRecord(kind="login", title="Example", username="alice", password="pw-alice",
                       urls=["https://example.test/login?x=1"], notes="login note",
                       totp_uri="otpauth://totp/Example:alice?secret=JBSWY3DPEHPK3PXP&issuer=Example",
                       favorite=True, tags=["work"],
                       custom_fields=[{"name": "PIN", "value": "1234", "hidden": True}], source_row=2),
        ImportedRecord(kind="login", title="Dup", username="alice", password="pw-alice", urls=["https://example.test"],
                       source_row=3),
        ImportedRecord(kind="login", title="No site", username="carol", password="pw-carol", source_row=4),
        ImportedRecord(kind="login", title="Bad", username="dave", password="pw", urls=["https://u:p@bad.test"],
                       source_row=5),
        ImportedRecord(kind="login", title="Empty", username="erin", password="", urls=["https://empty.test"],
                       source_row=6),
        ImportedRecord(kind="note", title="Memo", notes="remember the milk", tags=["home"],
                       custom_fields=[{"name": "Where", "value": "fridge", "hidden": False}], source_row=7),
        ImportedRecord(kind="identity", title="Me",
                       identity={"given_name": "Alice", "family_name": "Smith", "email": "a@example.test",
                                 "passport": "X123"}, source_row=8),
        ImportedRecord(kind="card", title="Visa", custom_fields=[{"name": "Number", "value": "card-no-4111", "hidden": True},
                                                                   {"name": "Brand", "value": "Visa", "hidden": False}],
                       source_row=9),
    ]


def test_plan_records_classifies_and_applies_every_kind(session):
    plan = plan_records(session, _records())
    assert isinstance(plan, ImportPlan)
    by_row = {row.row: row for row in plan.rows}
    assert by_row[2].status == "new" and by_row[2].decision == "add" and by_row[2].origin == "https://example.test"
    assert by_row[2].kind == "login" and by_row[7].kind == "note" and by_row[8].kind == "identity"
    assert by_row[3].status == "duplicate" and by_row[3].decision == "skip"  # duplicate inside the import
    assert by_row[4].kind == "note" and by_row[4].status == "new"  # login without a site becomes a secure note
    # Nothing readable is dropped: a URL with embedded credentials and a login
    # without a password are both kept as secure notes.
    assert by_row[5].kind == "note" and by_row[6].kind == "note"
    assert any("Row 5" in issue and "secure note" in issue for issue in plan.issues)
    assert any("Row 6" in issue and "no password" in issue for issue in plan.issues)
    assert any("Row 8" in issue and "passport" in issue for issue in plan.issues)
    assert by_row[8].extra is not None and by_row[9].kind == "note"
    assert plan.preview[0]["password"] == "********"
    assert "pw-alice" not in repr(plan) and "pw-carol" not in repr(plan) and "card-no-4111" not in repr(plan)
    assert plan.summary() == {"total": 8, "add": 7, "replace": 0, "merge": 0, "keep_both": 0, "skip": 1,
                              "limited": 0, "skipped_rows": 1}

    plan.review()
    assert apply_import_plan(session, plan) == 7
    entry = session.find_web("https://example.test")[0]
    assert entry["username"] == "alice" and entry["password"] == "pw-alice" and entry["label"] == "Example"
    assert entry["notes"] == "login note" and entry["favorite"] is True and entry["tags"] == ["work"]
    assert entry["totp"]["secret"] == "JBSWY3DPEHPK3PXP" and entry["custom_fields"][0]["name"] == "PIN"
    items = {item["title"]: item for item in session.items.list_items()}
    assert set(items) == {"No site", "Bad", "Empty", "Memo", "Me", "Me (extra details)", "Visa"}
    assert items["Memo"]["kind"] == "note" and items["Me"]["kind"] == "identity" and items["Visa"]["kind"] == "note"
    memo = session.items.get_item(items["Memo"]["id"], include_protected=True)
    assert memo["payload"]["body"] == "remember the milk" and memo["payload"]["fields"][0]["name"] == "Where"
    me = session.items.get_item(items["Me"]["id"], include_protected=True)
    assert me["payload"]["given_name"] == "Alice" and "passport" not in me["payload"]
    extra = session.items.get_item(items["Me (extra details)"]["id"], include_protected=True)
    assert extra["payload"]["fields"] == [{"name": "Passport", "value": "X123", "hidden": False}]
    bad = session.items.get_item(items["Bad"]["id"], include_protected=True)
    assert {f["name"]: f["hidden"] for f in bad["payload"]["fields"]} == {"Website": False, "Username": False,
                                                                           "Password": True}
    no_site = session.items.get_item(items["No site"]["id"], include_protected=True)
    assert {f["name"]: f["hidden"] for f in no_site["payload"]["fields"]} == {"Username": False, "Password": True}
    # Secrets are wiped once the plan has been applied.
    assert all(record.password == "" for record in plan.records)


def test_merge_decisions_update_details_and_keep_history(session):
    entry_id = session.upsert_web(origin="https://example.test", username="alice", password="old", label="Old")
    session.set_details(entry_id, notes="old note")
    plan = plan_records(session, _records()[:1])
    row = plan.rows[0]
    assert row.status == "conflict" and row.decision == "skip" and row.target_label == "Old"
    assert row.review_view()["fields"]["details"]["selected"] is False
    plan.set_decision(row, "merge", fields={"password": "import", "label": "keep", "details": "import"})
    plan.review()
    assert apply_import_plan(session, plan) == 1
    entry = session.find_web("https://example.test")[0]
    assert entry["label"] == "Old" and entry["password"] == "pw-alice" and entry["notes"] == "login note"
    assert entry["totp"]["secret"] == "JBSWY3DPEHPK3PXP"
    assert session.password_history(entry_id)[0]["password"] == "old"
    with pytest.raises(ImportWorkflowError):
        apply_import_plan(session, plan)


def test_replace_refuses_when_target_changed_and_cancel_rolls_back_items(session):
    entry_id = session.upsert_web(origin="https://example.test", username="alice", password="old")
    plan = plan_records(session, _records())
    plan.set_decision(2, "replace")
    plan.review()
    session.update_entry_fields(entry_id, password="changed-elsewhere")
    with pytest.raises(ImportWorkflowError, match="revision changed"):
        apply_import_plan(session, plan)
    assert session.items.list_items() == []

    plan = plan_records(session, _records())
    plan.review()
    calls = iter([False, False, True])
    with pytest.raises(ImportCancelled):
        apply_import_plan(session, plan, cancel=lambda: next(calls, True))
    assert session.items.list_items() == [] and session.find_web("https://example.test")[0]["password"] == "changed-elsewhere"
    assert plan.cancelled and all(record.password == "" for record in plan.records)


def test_build_import_plan_from_bitwarden_json_and_kdbx(session, source_dir: Path):
    document = {"encrypted": False, "folders": [], "items": [
        {"type": 1, "name": "Example", "favorite": True, "notes": "n",
         "login": {"username": "alice", "password": "pw-alice", "totp": "JBSWY3DPEHPK3PXP",
                   "uris": [{"uri": "https://example.test/login"}]}},
        {"type": 2, "name": "Memo", "notes": "remember", "secureNote": {"type": 0}},
    ]}
    source = source_dir / "bitwarden.json"
    source.write_text(json.dumps(document), encoding="utf-8")
    inspection = inspect_source(source)
    assert inspection.source_format == "bitwarden-json" and inspection.row_count == 2 and not inspection.needs_password
    plan = build_import_plan(session, source)
    assert plan.source_format == "bitwarden-json" and [row.kind for row in plan.rows] == ["login", "note"]
    plan.review()
    assert apply_import_plan(session, plan) == 2
    assert session.find_web("https://example.test")[0]["totp"]["secret"] == "JBSWY3DPEHPK3PXP"

    kdbx = source_dir / "db.kdbx"
    kdbx.write_bytes(write_kdbx(_records()[:1], "kdbx secret", kdf_params=FAST_ARGON))
    inspection = inspect_source(kdbx)
    assert inspection.source_format == "kdbx" and inspection.needs_password and inspection.row_count == 0
    with pytest.raises(ImportPasswordRequired):
        build_import_plan(session, kdbx)
    plan = build_import_plan(session, kdbx, password="kdbx secret")
    assert plan.rows[0].status == "duplicate" and plan.rows[0].target_id
    plan.set_decision(plan.rows[0], "merge", fields={"details": "import"})
    plan.review()
    assert apply_import_plan(session, plan) == 1
    assert session.find_web("https://example.test")[0]["custom_fields"][0]["name"] == "PIN"


def test_source_change_is_detected_even_for_binary_sources(session, source_dir: Path):
    kdbx = source_dir / "db.kdbx"
    kdbx.write_bytes(write_kdbx(_records()[:1], "kdbx secret", kdf_params=FAST_ARGON))
    plan = build_import_plan(session, kdbx, password="kdbx secret")
    plan.review()
    kdbx.write_bytes(write_kdbx(_records()[:1], "kdbx secret", kdf_params=FAST_ARGON))
    with pytest.raises(ImportWorkflowError, match="source changed"):
        apply_import_plan(session, plan)


def test_set_decision_validation(session):
    plan = plan_records(session, _records()[:1])
    with pytest.raises(ImportWorkflowError):
        plan.set_decision(99, "add")
    with pytest.raises(ImportWorkflowError):
        plan.set_decision(2, "explode")
    with pytest.raises(ImportWorkflowError):
        plan.set_decision(2, "replace", fields={"shoes": "import"})
    plan.set_decision(2, "skip")
    plan.review()
    assert apply_import_plan(session, plan) == 0
    with pytest.raises(ImportWorkflowError):
        apply_import_plan(session, plan_records(session, []))  # not reviewed


def test_import_preview_wrapper_keeps_legacy_contract(session, source_dir: Path):
    session.upsert_web(origin="https://example.test", username="alice", password="pw-alice")
    source = source_dir / "logins.csv"
    source.write_text("name,url,username,password\n"
                      "Example,https://example.test/login,alice,different\n"
                      "Example,https://example.test/login,alice,again\n"
                      "Bob,https://example.test/login,bob,pw-bob\n"
                      "Weird,not a url,x,pw\n"
                      "Nothing,https://nothing.test,y,\n", encoding="utf-8")
    rows, issues = import_preview.load_import(source)
    assert [row.username for row in rows] == ["alice", "bob"] and len(issues) == 5
    assert rows[0].row == 2 and rows[1].row == 4 and "different" not in repr(rows[0])
    import_preview.classify(rows, session.all_entries())
    assert [row.status for row in rows] == ["conflict", "new"] and rows[0].selected == "skip" and rows[1].selected == "add"
    assert import_preview.apply_import(session, rows) == 1
    rows[0].selected = "replace"
    rows[1].selected = "skip"
    assert import_preview.apply_import(session, rows) == 1
    assert session.find_web("https://example.test")[0]["password"] == "different"
    with pytest.raises(import_preview.ImportError):
        import_preview.load_import(source_dir / "missing.csv")
    (source_dir / "bad.json").write_text("{not json", encoding="utf-8")
    with pytest.raises(import_preview.ImportError):
        import_preview.load_import(source_dir / "bad.json")
