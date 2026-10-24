from __future__ import annotations

import uuid
from pathlib import Path

import pytest

from localvault.item_schema import ItemSchemaError
from localvault.app.typed_schema import KIND_CODE_BY_LABEL, KIND_LABELS, SECRET_KIND_FIELDS
from localvault.item_schema import PROTECTED_FIELDS_BY_KIND, SECRET_ITEM_KINDS
from localvault.vault import VaultError, create_vault

KDF = {"time_cost": 1, "memory_cost_kib": 8192, "parallelism": 1, "hash_len": 32}
MASTER = "typed item test master password"


@pytest.fixture
def test_dir() -> Path:
    path = Path(".m4-test-data") / uuid.uuid4().hex
    path.mkdir(parents=True, exist_ok=False)
    return path


@pytest.fixture
def session(test_dir: Path):
    return create_vault(test_dir / "vault.json", MASTER, kdf_overrides=KDF)


def test_m4_crud_has_uuid_revision_timestamps_and_metadata(session) -> None:
    item_id = session.items.create_license(
        "IDE license", serial="SERIAL-123", product="Editor", vendor="Acme"
    )
    item = session.items.get_item(item_id)
    assert item is not None
    assert item["kind"] == "license"
    assert item["revision"] == 1
    assert item["id"] == item_id
    assert item["created_at"] <= item["updated_at"]

    assert session.items.update_license(item_id, product="Editor Pro", expected_revision=1)
    updated = session.items.get_item(item_id)
    assert updated is not None
    assert updated["revision"] == 2
    assert updated["created_at"] == item["created_at"]
    assert updated["updated_at"] >= item["updated_at"]

    purchase_id = session.items.create_purchase("Receipt", vendor="Store", amount_minor=1299, currency="USD")
    warranty_id = session.items.create_warranty("Warranty", provider="Acme", expiration_date="2030-01-01")
    subscription_id = session.items.create_subscription("Subscription", provider="Acme", renewal_date="2030-02-01")
    assert {session.items.get_item(value)["kind"] for value in (purchase_id, warranty_id, subscription_id)} == {
        "purchase", "warranty", "subscription"
    }


def test_m4_schema_rejection_and_revision_conflict(session) -> None:
    with pytest.raises(ItemSchemaError):
        session.items.create_license("Bad date", expiration_date="2030-02-31")
    with pytest.raises(ItemSchemaError):
        session.items.create_purchase("Bad amount", amount_minor=1, currency="US")
    with pytest.raises(ItemSchemaError):
        session.items.create_license("Too long", license_value="x" * 4097)

    item_id = session.items.create_warranty("Warranty")
    with pytest.raises(VaultError, match="revision conflict"):
        session.items.update_warranty(item_id, provider="Acme", expected_revision=9)
    with pytest.raises(ItemSchemaError):
        session.items.update_typed_item(item_id, payload={"unsupported": "value"})


def test_secret_is_redacted_from_reads_search_and_requires_intent(session) -> None:
    secret = "SECRET-LICENSE-KEY"
    item_id = session.items.create_license("Editor", license_value=secret, tags=["software"])
    safe = session.items.get_item(item_id)
    assert safe is not None
    assert secret not in repr(safe)
    assert "license_value" not in safe["payload"]
    assert all(secret not in repr(value) for value in session.items.list_items())
    assert session.items.search_metadata(secret) == []

    with pytest.raises(ItemSchemaError, match="explicit caller intent"):
        session.items.reveal_secret(item_id)
    assert session.items.reveal_secret(item_id, intent="user pressed reveal") == secret
    assert session.items.copy_serial(item_id, intent="user pressed copy") == secret


def test_phase01_list_and_search_redact_note_bookmark_and_identity_payloads(session) -> None:
    note_id = session.items.create_note("Private note", body="note secret", tags=["private"])
    bookmark_id = session.items.create_bookmark(
        "Private bookmark", "https://example.test/private", notes="bookmark secret")
    identity_id = session.items.create_identity(
        "Private identity", {"name": "Ada Example", "email": "ada@example.test"})

    for item_id in (note_id, bookmark_id, identity_id):
        safe = session.items.get_item(item_id)
        assert safe is not None
        assert "secret" not in repr(safe)
        assert "ada@example.test" not in repr(safe)
    assert session.items.search_metadata("note secret") == []
    assert session.items.search_metadata("example.test/private") == []
    assert session.items.search_metadata("ada@example.test") == []
    assert session.items.get_item_for_edit(note_id)["payload"]["body"] == "note secret"
    assert session.items.get_item_for_edit(bookmark_id)["payload"]["url"] == "https://example.test/private"
    assert session.items.get_item_for_edit(identity_id)["payload"]["email"] == "ada@example.test"


def test_document_ids_require_live_catalog_backed_documents_and_delete_is_non_cascading(
    session, test_dir: Path
) -> None:
    source = test_dir / "receipt.txt"
    source.write_text("receipt", encoding="utf-8")
    document_id = session.documents.create(source)

    with pytest.raises(ItemSchemaError, match="missing live document"):
        session.items.create_purchase("Bad reference", document_ids=["00000000-0000-4000-8000-000000000001"])

    purchase_id = session.items.create_purchase("Receipt", document_ids=[document_id])
    assert session.items.delete_item(purchase_id)
    assert session.items.get_item(document_id)["kind"] == "document"

    session.items.create_purchase("Receipt 2", document_ids=[document_id])
    with pytest.raises(VaultError, match="referenced"):
        session.documents.delete(document_id)


def test_document_replace_keeps_one_typed_item_and_retains_history_sidecar(session, test_dir: Path) -> None:
    original = test_dir / "original.txt"
    replacement = test_dir / "replacement.txt"
    original.write_text("before", encoding="utf-8")
    replacement.write_text("after", encoding="utf-8")
    document_id = session.documents.create(original, title="Receipt", description="before description")
    old_attachment = session.documents.attachment_for(document_id)["id"]

    session.documents.replace(document_id, replacement, description="after description")

    assert session.documents.read(document_id) == b"after"
    assert session.documents.attachment_for(document_id)["id"] != old_attachment
    edited = session.items.get_item_for_edit(document_id)
    assert edited["payload"]["description"] == "after description"
    # Typed history is a reachability root so an older document revision can
    # still be inspected or restored after replacement.
    assert old_attachment in {row["id"] for row in session._require_typed_catalog()["attachments"]}


def test_typed_trash_restore_preserves_payload_and_revision(session) -> None:
    secret = "RESTORE-ME"
    item_id = session.items.create_license("Restore", license_value=secret)
    assert session.items.update_license(item_id, notes="updated", expected_revision=1)
    assert session.items.delete_item(item_id)
    assert session.items.get_item(item_id) is None
    deleted = session.items.trash_summaries()
    assert deleted and deleted[0]["id"] == item_id
    assert secret not in repr(deleted)

    assert session.items.restore_item(item_id)
    restored = session.items.get_item(item_id)
    assert restored is not None
    assert restored["revision"] == 2
    assert restored["payload"]["notes"] == "updated"
    assert session.items.reveal_license_value(item_id, intent="restore verification") == secret


def test_builtin_templates_cover_m4_kinds_with_safe_secret_flags(session) -> None:
    templates = session.templates.list()
    by_id = {template["id"]: template for template in templates}
    assert by_id["builtin.license"]["kind"] == "license"
    assert by_id["builtin.purchase"]["kind"] == "purchase"
    assert by_id["builtin.warranty"]["kind"] == "warranty"
    assert by_id["builtin.subscription"]["kind"] == "subscription"
    license_fields = {field["name"]: field for field in by_id["builtin.license"]["fields"]}
    assert license_fields["license_value"]["secret"] is True
    assert all("SECRET-LICENSE-KEY" not in repr(template) for template in templates)


def test_editor_shows_friendly_kinds_but_keeps_schema_kind_keys() -> None:
    assert KIND_CODE_BY_LABEL == {label: kind for kind, label in KIND_LABELS.items()}
    assert set(KIND_CODE_BY_LABEL.values()) == set(KIND_LABELS)


def test_secret_kind_layout_covers_every_schema_kind_and_protected_field() -> None:
    assert SECRET_ITEM_KINDS <= set(KIND_LABELS)
    assert set(SECRET_KIND_FIELDS) == SECRET_ITEM_KINDS
    for kind in SECRET_ITEM_KINDS:
        keys = {key for key, _label, _control in SECRET_KIND_FIELDS[kind]}
        assert set(PROTECTED_FIELDS_BY_KIND[kind]) <= keys, kind
    assert KIND_LABELS["card"] == "Payment card" and KIND_CODE_BY_LABEL["Wi-Fi network"] == "wifi"


