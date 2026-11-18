"""Regression tests for the 2026-11-15 security scan, Windows findings W-M5, W-L12, W-L13, W-L4, W-L9, A-L1.

See ``docs/reports/2026-11-15-scan-security-new-code.md``.
"""
from __future__ import annotations

import json
import time

import pytest

from localvault import access_policy, duress, item_history
from localvault import vault as vault_module
from localvault.export import item_to_record, render_csv, render_json
from localvault.import_report import (
    ImportUndo,
    UndoStore,
    census,
    landed,
    prepare_undo,
    row_facts,
    undo_import,
)
from localvault.import_workflow import apply_import_plan, plan_records
from localvault.importers import ImportedRecord
from localvault.vault import create_vault

KDF = {"time_cost": 1, "memory_cost_kib": 8192, "parallelism": 1, "hash_len": 32}
MASTER = "scan security master"


@pytest.fixture(autouse=True)
def _throttle_state():
    vault_module._reset_unlock_throttle_state_for_tests()
    yield
    vault_module._reset_unlock_throttle_state_for_tests()


@pytest.fixture
def session(tmp_path):
    vault = create_vault(tmp_path / "profile" / "vault.json", MASTER, kdf_overrides=KDF)
    vault.item_limit = None
    yield vault
    vault.lock()


def _login(session, site: str, user: str = "owner", value: str = "first-password-1") -> str:  # noqa: S107 - test data
    return session.upsert_web(origin=f"https://{site}", username=user, password=value, label=site)


def _history_ids(session) -> set[str]:
    rows = session._require_payload().get(item_history.ENTRY_HISTORY_KEY) or []
    return {row["item_id"] for row in rows}


# ------------------------------------------------------------------ W-M5: purge drops item history
def _edited_login(session, site: str) -> str:
    entry_id = _login(session, site)
    session.update_entry_fields(entry_id, password="second-password-2")
    assert session.entry_history_rows(entry_id), "the edit should have captured a history row"
    return entry_id


def test_delete_forever_drops_the_login_history(session):
    gone = _edited_login(session, "gone.example")
    kept = _edited_login(session, "kept.example")
    session.delete(gone)
    assert gone in _history_ids(session)  # still in the trash: history stays for a restore
    session.purge_deleted(gone)
    assert gone not in _history_ids(session) and kept in _history_ids(session)
    assert session.entry_history_rows(gone) == []
    session.lock()
    reopened = vault_module.unlock_vault(session.path, MASTER)
    try:
        assert gone not in _history_ids(reopened) and kept in _history_ids(reopened)
    finally:
        reopened.lock()


def test_empty_all_drops_the_history_of_every_purged_login(session):
    first, second = _edited_login(session, "one.example"), _edited_login(session, "two.example")
    session.delete(first)
    session.delete(second)
    assert session.purge_deleted_many([first, second]) == 2
    assert _history_ids(session) == set()


def test_trash_auto_purge_drops_the_login_history(session):
    old = _edited_login(session, "old.example")
    session.delete(old)
    payload = session._require_payload()
    record = next(r for r in payload["trash"] if r["entry"]["id"] == old)
    record["deleted_at"] = int(time.time()) - 40 * 86400
    session.trash_auto_purge, session.trash_retention_days = True, 30
    session.save()
    assert not any(r["entry"]["id"] == old for r in payload["trash"])
    assert old not in _history_ids(session)


def test_history_age_limit_applies_on_every_save(session):
    entry_id = _edited_login(session, "aged.example")
    rows = session._require_payload()[item_history.ENTRY_HISTORY_KEY]
    limits = session._entry_history_limits()
    rows[0]["created_at"] = int(time.time()) - (limits["max_age_days"] + 1) * 86400
    session.item_service.create_note("Unrelated", "no login is edited")  # any save
    assert session.entry_history_rows(entry_id) == []


def test_delete_forever_drops_typed_item_history(session):
    note_id = session.items.create_note("Diary", "first body")
    session.items.update_item(note_id, title="Diary", body="second body")
    assert any(row["item_id"] == note_id for row in session._require_payload()["history"])
    session.items.delete_item(note_id)
    session.purge_deleted(note_id)
    assert not any(row["item_id"] == note_id for row in session._require_payload()["history"])


# ------------------------------------------------------------------ W-L12: clock anchor skew cap
def test_newest_payload_time_caps_future_times_at_local_time_plus_skew():
    now = 1_800_000_000
    payload = {"updated_at": now - 10, "entries": [{"updated_at": now + 400 * 86400}],
               "trash": [{"deleted_at": now + 5 * 86400}]}
    assert vault_module._newest_payload_time(payload, now=now) == now + vault_module._CLOCK_FUTURE_SKEW_SECONDS
    assert vault_module._newest_payload_time({"items": [{"updated_at": now - 5}]}, now=now) == now - 5
    assert vault_module._CLOCK_FUTURE_SKEW_SECONDS == 86400


def test_a_synced_far_future_record_does_not_switch_off_the_clock_jump_guard(session, monkeypatch):
    entry_id = _login(session, "future.example")
    entry = next(e for e in session._require_payload()["entries"] if e["id"] == entry_id)
    entry["updated_at"] = int(time.time()) + 3650 * 86400  # a peer whose clock is ten years ahead
    session.save()
    session.lock()
    reopened = vault_module.unlock_vault(session.path, MASTER)
    try:
        real_now = time.time()
        assert reopened._clock_anchor[0] <= real_now + vault_module._CLOCK_FUTURE_SKEW_SECONDS + 5
        monkeypatch.setattr(vault_module.time, "time", lambda: real_now + 30 * 86400)  # clock jumps a month
        trusted = reopened._trusted_now()
        monkeypatch.undo()
        limit = (vault_module._CLOCK_FUTURE_SKEW_SECONDS + vault_module._CLOCK_SLACK_SECONDS + 60)
        assert trusted <= real_now + limit
    finally:
        reopened.lock()


# ------------------------------------------------------------------ W-L13: duress throttle
REAL, DURESS = "correct horse battery", "orange tractor sunset"


def test_real_password_without_its_security_key_is_not_a_failed_attempt(tmp_path, monkeypatch):
    monkeypatch.setattr(duress, "_boot_clock", lambda: ("boot-1", 1000))
    path = tmp_path / "real" / "vault.json"
    path.parent.mkdir()
    real = create_vault(path, REAL, kdf_overrides=KDF)
    duress.setup(real, DURESS, lock_hours=6, master_password=REAL)
    real.lock()

    def needs_key(*args, **kwargs):
        raise vault_module.FactorRequired("security key required")

    monkeypatch.setattr(duress, "unlock_vault", needs_key)
    for _ in range(6):
        with pytest.raises(vault_module.FactorRequired):
            duress.open_vault(path, REAL, now=1000)
    assert vault_module.UnlockThrottle(path).failures == 0
    opened = duress.open_vault(path, DURESS, now=1000)  # the second vault still opens without the key
    assert duress.is_decoy(opened)
    opened.lock()


# ------------------------------------------------------------------ W-L4: import undo
def _import(session, records, decisions):
    plan = plan_records(session, records)
    for row, decision in decisions.items():
        plan.set_decision(row, decision)
    facts = row_facts(plan)
    before, entries, items = prepare_undo(session, facts)
    plan.review()
    apply_import_plan(session, plan)
    return plan, before, entries, items


def test_import_undo_keeps_later_edits_and_items_that_did_not_come_from_the_import(session):
    r1 = _login(session, "r1.example", "r1", "before-1")
    r2 = _login(session, "r2.example", "r2", "before-2")
    records = [
        ImportedRecord(kind="login", title="R1", username="r1", password="imported-1",
                       urls=["https://r1.example"], source_row=2),
        ImportedRecord(kind="login", title="R2", username="r2", password="imported-2",
                       urls=["https://r2.example"], source_row=3),
        ImportedRecord(kind="login", title="C1", username="c1", password="new-1", urls=["https://c1.example"],
                       source_row=4),
        ImportedRecord(kind="login", title="C2", username="c2", password="new-2", urls=["https://c2.example"],
                       source_row=5),
        ImportedRecord(kind="note", title="Imported memo", notes="body", source_row=6),
    ]
    plan, before, entries, items = _import(session, records, {2: "replace", 3: "replace"})
    c1 = session.find_web_login("https://c1.example", "c1")
    c2 = session.find_web_login("https://c2.example", "c2")
    assert plan.created_ids["web"] == {c1, c2} and len(plan.created_ids["note"]) == 1
    assert set(plan.written) == {c1, c2, r1, r2} | plan.created_ids["note"]

    # After the import: a browser save / sync adds a login the census diff would take for an import one,
    # the user edits one created and one replaced login, and a site icon arrives for another.
    synced = _login(session, "synced.example", "s", "synced-pw")
    session.update_entry_fields(c2, label="Changed after import")
    session.update_entry_fields(r2, password="edited-2")
    assert session.set_entry_icon(c1, vault_module.PNG_SIGNATURE + b"icon")

    store = UndoStore()
    record = store.add("p", landed(before, census(session)), entries, items, written=plan.written)
    result = undo_import(session, record)

    live = {s.id for s in session.summaries()}
    assert synced in live and c2 in live and c1 not in live
    assert session.get_entry(synced)["password"] == "synced-pw"
    assert session.get_entry(r1)["password"] == "before-1"
    assert session.get_entry(r2)["password"] == "edited-2"
    assert result["trashed"] == 2 and result["restored"] == 1
    assert sorted(result["missed"]) == ["Changed after import", "r2.example"]


def test_import_undo_without_digests_keeps_the_old_behaviour(session):
    r1 = _login(session, "r1.example", "r1", "before-1")
    records = [ImportedRecord(kind="login", title="R1", username="r1", password="imported-1",
                              urls=["https://r1.example"], source_row=2)]
    _plan, _before, entries, items = _import(session, records, {2: "replace"})
    result = undo_import(session, ImportUndo(token="t", profile="p", created={}, changed_entries=entries,
                                             changed_items=items))
    assert result == {"trashed": 0, "restored": 1, "missed": []}
    assert session.get_entry(r1)["password"] == "before-1"


# ------------------------------------------------------------------ W-L9: CSV leaves out CVV and PIN
def _card_item():
    return {"kind": "card", "title": "Visa", "created_at": 1, "updated_at": 2, "tags": [],
            "payload": {"cardholder": "A Smith", "number": "4111111111111111", "expiry": "12/30",
                        "cvv": "987", "pin": "4321", "notes": ""}}


def test_csv_export_leaves_out_card_security_code_and_pin():
    record = item_to_record(_card_item())
    text = render_csv([record], include_totp=False).decode("utf-8")
    assert "4111111111111111" in text and "A Smith" in text
    assert "987" not in text and "4321" not in text
    assert "Security code" not in text and "PIN" not in text


def test_other_exports_still_carry_card_security_code():
    record = item_to_record(_card_item())
    names = {field["name"]: field["value"] for field in record.custom_fields}
    assert names["Security code"] == "987" and names["PIN"] == "4321"  # what the KDBX export writes
    document = json.loads(render_json([record], include_totp=False))
    assert document["items"][0]["card"]["code"] == "987"


# ------------------------------------------------------------------ A-L1: non-boolean require_master_password
@pytest.mark.parametrize("value", [True, "yes", "false", 1, 0, None, {}, [], ""])
def test_present_non_false_require_master_password_is_strict(value):
    raw = {"require_master_password": value}
    policy = access_policy.normalized_policy(raw)
    assert policy["require_master_password"] is True
    assert access_policy.enforced_policy({"policy": raw, "scope": {}})["require_master_password"] is True
    assert access_policy.effective({"policy": raw}, access_policy.DEVICE_COMPUTER, "2026-11-15")["reauth"] is True
    assert access_policy.has_rule({"policy": raw}, "2026-11-15") is True
    merged = access_policy.stricter_policy(raw, None)
    assert merged["require_master_password"] is True


@pytest.mark.parametrize("raw", [{}, {"require_master_password": False}, None, "not a dict"])
def test_absent_or_false_require_master_password_is_off(raw):
    assert access_policy.normalized_policy(raw)["require_master_password"] is False


def test_stricter_policy_keeps_an_explicit_false_and_tightens_from_the_other_side():
    assert access_policy.stricter_policy({"require_master_password": False}, None) == {"require_master_password": False}
    assert access_policy.stricter_policy({"require_master_password": False},
                                         {"require_master_password": "yes"})["require_master_password"] is True


def test_transfer_writes_a_non_boolean_strict_flag_as_true():
    from localvault.transfer import _sanitize_credential

    entry = {"id": "x", "kind": "web", "label": "L", "username": "u", "password": "p",
             "scope": {"origin": "https://a.example"}, "policy": {"require_master_password": "yes"}}
    assert _sanitize_credential(entry)["policy"]["require_master_password"] is True
    entry["policy"] = {}
    assert _sanitize_credential(entry)["policy"]["require_master_password"] is False


def test_vault_writes_a_non_boolean_strict_flag_back_as_true(session):
    entry_id = _login(session, "strict.example")
    session.set_details(entry_id, favorite=False, tags=[], notes="", totp=None, recovery_codes=[],
                        policy={"require_master_password": "yes"}, custom_fields=[])
    assert session.get_entry(entry_id)["policy"]["require_master_password"] is True
