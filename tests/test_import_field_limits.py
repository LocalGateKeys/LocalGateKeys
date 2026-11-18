"""Import never silently cuts custom fields: long values are split, extra fields move to notes, all reported."""
from __future__ import annotations

import pytest

from localvault.import_workflow import apply_import_plan, normalise_records, plan_records
from localvault.importers import ImportedRecord, add_custom_field
from localvault.vault import create_vault

KDF = {"time_cost": 1, "memory_cost_kib": 8192, "parallelism": 1, "hash_len": 32}


@pytest.fixture(autouse=True)
def _isolated(tmp_path, monkeypatch):
    monkeypatch.setenv("LOCALGATEKEYS_DATA_DIR", str(tmp_path / "data"))


def test_add_custom_field_keeps_long_values_and_many_fields():
    record = ImportedRecord(kind="note", title="n")
    add_custom_field(record, "key", "k" * 9000, hidden=True)
    for index in range(60):
        add_custom_field(record, f"f{index}", "v")
    assert record.custom_fields[0]["value"] == "k" * 9000
    assert len(record.custom_fields) == 61 and record.dropped_fields == 0


def test_long_ssh_key_is_split_not_truncated_and_reported():
    key = "".join(chr(65 + i % 26) for i in range(9000))
    record = ImportedRecord(kind="note", title="ssh")
    add_custom_field(record, "Private key", key, hidden=True)
    rows, issues = normalise_records([record])
    fields = rows[0].record.custom_fields
    assert "".join(f["value"] for f in fields) == key
    assert all(f["hidden"] and len(f["value"]) <= 4096 for f in fields)
    assert any("split" in issue for issue in issues)


def test_fields_past_fifty_move_into_notes_with_an_issue():
    record = ImportedRecord(kind="note", title="many", notes="original")
    for index in range(55):
        add_custom_field(record, f"field{index}", f"value{index}")
    rows, issues = normalise_records([record])
    note = rows[0].record
    assert len(note.custom_fields) == 50
    assert note.notes.startswith("original") and "field54:\nvalue54" in note.notes
    assert any("notes" in issue for issue in issues)


def test_over_long_login_is_kept_as_a_note(tmp_path):
    record = ImportedRecord(kind="login", title="huge", username="me", password="p" * 5000,
                            urls=["https://example.test"])
    rows, issues = normalise_records([record])
    assert len(rows) == 1 and rows[0].kind == "note"
    assert "".join(f["value"] for f in rows[0].record.custom_fields if f["name"].startswith("Password")) == "p" * 5000
    assert any("secure note" in issue for issue in issues)
    session = create_vault(tmp_path / "vault.json", "field-limits master", kdf_overrides=KDF)
    try:
        plan = plan_records(session, [record])
        plan.review()
        assert apply_import_plan(session, plan) == 1
    finally:
        session.lock()


def test_1pux_hidden_hint_matches_whole_words_and_passkeys_are_reported():
    from localvault.importers import onepassword

    assert not onepassword._looks_sensitive("", "Postal code")
    assert not onepassword._looks_sensitive("", "Keyword")
    assert onepassword._looks_sensitive("", "Recovery code")
    document = {"accounts": [{"vaults": [{"attrs": {"name": "V"}, "items": [
        {"categoryUuid": "001", "overview": {"title": "Site", "url": "https://a.test"},
         "details": {"loginFields": [], "passkey": {"credentialId": "x"}}}]}]}]}
    result = onepassword.records_from_export(document)
    assert any("passkey" in line.casefold() for line in result.diagnostics)
