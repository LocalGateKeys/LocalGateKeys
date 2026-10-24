"""Passkey vault items: the WebAuthn fields and the per-site record lookup."""
from __future__ import annotations

import pytest

from localvault.item_schema import ITEM_SCHEMA_VERSION, ItemSchemaError, validate_payload
from localvault.vault import create_vault

KDF = {"time_cost": 1, "memory_cost_kib": 8192, "parallelism": 1, "hash_len": 32}


def _session(tmp_path):
    return create_vault(tmp_path / "passkeys.json", "passkey items test master", kdf_overrides=KDF)


def test_item_schema_version_is_3() -> None:
    assert ITEM_SCHEMA_VERSION == 3


def test_passkey_payload_accepts_new_fields_and_defaults_discoverable() -> None:
    payload = validate_payload("passkey", {
        "relying_party_id": "example.com", "user_name": "ada", "user_display_name": "Ada L.",
        "rp_name": "Example",
    })
    assert payload["user_name"] == "ada"
    assert payload["user_display_name"] == "Ada L."
    assert payload["rp_name"] == "Example"
    assert payload["discoverable"] is True
    assert validate_payload("passkey", {"discoverable": False})["discoverable"] is False


def test_passkey_payload_rejects_non_bool_discoverable_and_overlong_names() -> None:
    with pytest.raises(ItemSchemaError):
        validate_payload("passkey", {"discoverable": "yes"})
    for field in ("user_name", "user_display_name", "rp_name"):
        with pytest.raises(ItemSchemaError):
            validate_payload("passkey", {field: "x" * 257})


def test_scaffold_record_without_new_fields_still_validates() -> None:
    payload = validate_payload("passkey", {"relying_party_id": "example.com", "algorithm": "ES256"})
    assert payload["user_name"] == ""
    assert payload["rp_name"] == ""
    assert payload["discoverable"] is True


def test_passkey_records_filters_by_rp_and_includes_private_key(tmp_path) -> None:
    session = _session(tmp_path)
    items = session.items
    b = items.create_passkey("Bravo", relying_party_id="example.com", credential_id="QQ",
                             private_key="key-b", algorithm="ES256", user_name="bob")
    a = items.create_passkey("alpha", relying_party_id="example.com", credential_id="Qg",
                             private_key="key-a", algorithm="ES256", user_name="ann")
    items.create_passkey("Other", relying_party_id="other.test", private_key="key-o")
    gone = items.create_passkey("Gone", relying_party_id="example.com", private_key="key-g")
    assert items.delete_item(gone)

    records = items.passkey_records("example.com")
    assert [record["id"] for record in records] == [a, b]
    assert records[0]["title"] == "alpha"
    assert records[0]["private_key"] == "key-a"
    assert records[0]["user_name"] == "ann"
    assert records[1]["credential_id"] == "QQ"
    assert items.passkey_records("missing.test") == []


