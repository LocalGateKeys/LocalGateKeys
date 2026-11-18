"""Switch report and whole-import undo (feature idea 1): counts come from the vault, undo is one step."""
from __future__ import annotations

import json

import pytest

from localvault.api.result import ApiError
from localvault.import_report import RowFacts, build_report, landed
from test_app_import_export import _chrome_csv, env  # noqa: F401 - the fixture


def _run(env, path):
    env.dialogs.open_path = path
    handle = env.imports.open()["handle"]
    env.imports.plan(handle, None, None)
    return handle


def _logins(env):
    session = env.controller.session
    return {s.title: str(s.id) for s in session.item_service.all_metadata_summaries() if s.kind == "web"}


def test_report_counts_what_landed_and_names_the_skipped(env):
    handle = _run(env, _chrome_csv(env.tmp, rows=3))
    review = env.imports.review(handle)
    env.imports.decide(handle, [review["rows"][2]["row"]], "skip")
    result = env.imports.apply(handle)
    report = result["report"]
    assert report["total"] == 3 and report["written"] == 2 and report["added"] == 2
    assert report["kinds"] == [{"kind": "web", "label": report["kinds"][0]["label"], "count": 2}]
    assert [row["name"] for row in report["not_carried"]] == ["Site2"]
    assert "2" in report["toast"] and "3" in report["toast"]
    assert report["undo"]
    assert "pw-secret" not in json.dumps(result)


def test_report_never_claims_more_than_arrived():
    facts = [RowFacts(row=i, kind="passkey", name=f"pk{i}", status="new", decision="add", limited=False,
                      target_id=None, custom_fields=2, field_events={"split": 1}, attachments=0) for i in range(3)]
    report = build_report(facts, {"passkey": {"only-one"}}, 1, [])
    assert report["added"] == 1 and report["kinds"][0]["count"] == 1
    assert report["passkeys"] == {"total": 3, "imported": 1, "skipped": 2}
    assert report["fields"]["kept"] == 6 and report["fields"]["split"] == 3


def test_landed_is_after_minus_before():
    assert landed({"web": {"a"}}, {"web": {"a", "b"}, "note": {"c"}}) == {"web": {"b"}, "note": {"c"}}


def test_undo_trashes_added_items_and_restores_replaced_ones(env):
    session = env.controller.session
    session.upsert_web(origin="https://site0.test", username="user0", password="old-password-0")
    before = set(_logins(env).values())
    handle = _run(env, _chrome_csv(env.tmp, rows=2))
    env.imports.decide_all(handle, "replace-conflicts")
    env.imports.decide_all(handle, "add-new")
    report = env.imports.apply(handle)["report"]
    assert report["added"] == 1 and report["updated"] == 1
    replaced = next(e for e in session.find_web("https://site0.test"))
    assert replaced["password"] == "pw-secret-0-12345"
    undone = env.imports.undo(report["undo"])
    assert undone["trashed"] == 1 and undone["restored"] == 1 and undone["missed"] == []
    assert set(_logins(env).values()) == before
    restored = next(e for e in session.find_web("https://site0.test"))
    assert restored["password"] == "old-password-0"
    with pytest.raises(ApiError) as again:
        env.imports.undo(report["undo"])
    assert again.value.code == "expired"


def test_undo_declined_keeps_the_import(env):
    report = env.imports.apply(_run(env, _chrome_csv(env.tmp, rows=1)))["report"]
    env.port.answers = [False]
    with pytest.raises(ApiError):
        env.imports.undo(report["undo"])
    assert "Site0" in _logins(env)


def test_lock_drops_the_undo(env):
    report = env.imports.apply(_run(env, _chrome_csv(env.tmp, rows=1)))["report"]
    env.controller.lock()
    with pytest.raises(ApiError):
        env.imports.undo(report["undo"])


def test_undo_restores_a_changed_typed_item_from_history(tmp_path, monkeypatch):
    from localvault.import_report import ImportUndo, prepare_undo, undo_import
    from localvault.vault import create_vault

    monkeypatch.setenv("LOCALGATEKEYS_DATA_DIR", str(tmp_path / "data"))
    vault = create_vault(tmp_path / "v.json", "typed undo master",
                         kdf_overrides={"time_cost": 1, "memory_cost_kib": 8192, "parallelism": 1, "hash_len": 32})
    note_id = vault.items.create_note("Before", "old body")
    note_id = note_id if isinstance(note_id, str) else note_id["id"]
    fact = RowFacts(row=1, kind="note", name="Before", status="conflict", decision="merge", limited=False,
                    target_id=note_id, custom_fields=0, field_events={}, attachments=0)
    _before, entries, items = prepare_undo(vault, [fact])
    vault.items.update_item(note_id, title="After", body="new body")
    result = undo_import(vault, ImportUndo(token="t", profile="p", created={}, changed_entries=entries,
                                           changed_items=items))
    assert result == {"trashed": 0, "restored": 1, "missed": []}
    assert vault.items.get_item(note_id, include_protected=True)["title"] == "Before"
    vault.lock()
