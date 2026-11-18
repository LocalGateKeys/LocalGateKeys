from __future__ import annotations

from pathlib import Path

from localvault import estate_pack
from localvault.item_schema import validate_template
from localvault.templates import BUILTIN_TEMPLATES
from localvault.vault import create_vault

KDF = {"time_cost": 1, "memory_cost_kib": 8192, "parallelism": 1, "hash_len": 32}


def test_estate_template_is_valid_with_the_five_fields() -> None:
    row = next(r for r in BUILTIN_TEMPLATES if r["id"] == "builtin.estate")
    assert row["kind"] in ("note", "document")
    validate_template(row)
    labels = [f["label"] for f in row["fields"]]
    assert labels == ["Where the will is", "Executor", "Accounts to close", "Devices and their unlock",
                      "Shard holders"]
    assert next(f for f in row["fields"] if f["name"] == "devices_unlock")["secret"] is True


def test_body_lists_holders_by_nickname() -> None:
    text = estate_pack.body(["Sam", " ", "Ana"])
    assert "## Shard holders\n- Sam\n- Ana\n" in text
    assert text.count("## ") == 5


def test_create_makes_one_note(tmp_path: Path) -> None:
    session = create_vault(tmp_path / "vault.json", "synthetic estate master 01", kdf_overrides=KDF)
    try:
        item_id = estate_pack.create(session, ["Sam"])
        item = session.item_service.get_item(item_id, include_protected=True)
        assert item["kind"] == "note" and "estate" in item.get("tags", [])
    finally:
        session.lock()
