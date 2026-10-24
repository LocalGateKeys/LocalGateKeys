from __future__ import annotations

import hashlib
import json
import uuid
from pathlib import Path

import pytest

from localvault import transfer
from localvault.transfer import (
    TransferConflictError,
    TransferError,
    export_transfer,
    import_transfer,
    inspect_transfer,
)
from localvault.vault import create_vault

KDF = {"time_cost": 1, "memory_cost_kib": 8192, "parallelism": 1, "hash_len": 32}
MASTER = "transfer test master password"
TRANSFER_PASSWORD = "transfer package password"


@pytest.fixture
def vault_dir() -> Path:
    # Some Windows pytest temp roots reject the ACL changes used by the vault
    # writer.  Keep this bounded harness inside the repository instead.
    path = Path(".m7-test-data") / uuid.uuid4().hex
    path.mkdir(parents=True, exist_ok=False)
    return path


def _new_vault(path: Path, name: str = "vault.json"):
    return create_vault(path / name, MASTER, kdf_overrides=KDF)


def test_selective_scope_manifest_and_secrets_are_encrypted(vault_dir: Path) -> None:
    source = _new_vault(vault_dir, "source.json")
    license_id = source.items.create_license("Selected", license_value="LICENSE-SECRET")
    source.items.create_note("Unselected", "UNSELECTED-BODY")
    credential_id = source.upsert_web(origin="https://example.test", username="alice", password="WEB-SECRET")
    source.items.create_identity("Private identity", {"name": "Alice Example"})

    package = vault_dir / "selected.lgt"
    manifest = export_transfer(source, package, TRANSFER_PASSWORD, ids=[license_id, credential_id])
    public = package.read_text(encoding="utf-8")
    assert manifest["item_count"] == 1 and manifest["credential_count"] == 1
    assert "Unselected" not in repr(manifest)
    assert "LICENSE-SECRET" not in public and "WEB-SECRET" not in public
    assert "UNSELECTED-BODY" not in public

    destination = _new_vault(vault_dir, "destination.json")
    import_transfer(package, destination, TRANSFER_PASSWORD)
    assert [item["title"] for item in destination.items.list_items()] == ["Selected"]
    assert destination.all_entries()[0]["password"] == "WEB-SECRET"


def test_document_attachment_and_references_are_remapped(vault_dir: Path) -> None:
    source = _new_vault(vault_dir, "source.json")
    document_path = vault_dir / "receipt.txt"
    document_path.write_text("receipt contents", encoding="utf-8")
    document_id = source.documents.create(document_path, title="Receipt")
    purchase_id = source.items.create_purchase("Purchase", document_ids=[document_id])
    package = vault_dir / "documents.lgt"
    export_transfer(source, package, TRANSFER_PASSWORD, ids=[document_id, purchase_id])

    destination = _new_vault(vault_dir, "destination.json")
    result = import_transfer(package, destination, TRANSFER_PASSWORD)
    assert result["attachment_map"]
    document = next(item for item in destination.items.list_items() if item["kind"] == "document")
    purchase = next(item for item in destination.items.list_items() if item["kind"] == "purchase")
    assert purchase["payload"]["document_ids"] == [document["id"]]
    assert destination.documents.read(document["id"]) == b"receipt contents"


def test_wrong_password_tamper_and_traversal_fail_without_mutation(vault_dir: Path) -> None:
    source = _new_vault(vault_dir, "source.json")
    item_id = source.items.create_license("Selected", license_value="SECRET")
    package = vault_dir / "selected.lgt"
    export_transfer(source, package, TRANSFER_PASSWORD, ids=[item_id])
    destination = _new_vault(vault_dir, "destination.json")
    before = hashlib.sha256(destination.path.read_bytes()).hexdigest()
    with pytest.raises(TransferError):
        import_transfer(package, destination, "wrong transfer password")
    assert hashlib.sha256(destination.path.read_bytes()).hexdigest() == before

    envelope = json.loads(package.read_text(encoding="utf-8"))
    ciphertext = envelope["cipher"]["ciphertext"]
    envelope["cipher"]["ciphertext"] = ("A" if ciphertext[0] != "A" else "B") + ciphertext[1:]
    package.write_text(json.dumps(envelope), encoding="utf-8")
    with pytest.raises(TransferError):
        import_transfer(package, destination, TRANSFER_PASSWORD)
    assert destination.items.list_items() == []


def test_conflicts_are_safe_by_default_and_copy_or_replace_are_explicit(vault_dir: Path) -> None:
    source = _new_vault(vault_dir, "source.json")
    item_id = source.items.create_license("Selected", license_value="SECRET")
    package = vault_dir / "selected.lgt"
    export_transfer(source, package, TRANSFER_PASSWORD, ids=[item_id])
    destination = _new_vault(vault_dir, "destination.json")

    first = import_transfer(package, destination, TRANSFER_PASSWORD)
    assert first["imported_ids"] == [item_id]
    skipped = import_transfer(package, destination, TRANSFER_PASSWORD)
    assert skipped["skipped_ids"] == [item_id]
    assert len(destination.items.list_items()) == 1
    copied = import_transfer(package, destination, TRANSFER_PASSWORD, conflict_policy="copy")
    assert copied["copied_ids"] == [item_id]
    assert len(destination.items.list_items()) == 2
    with pytest.raises(TransferConflictError):
        import_transfer(package, destination, TRANSFER_PASSWORD, conflict_policy="replace")
    replaced = import_transfer(package, destination, TRANSFER_PASSWORD, conflict_policy="replace", replace=True)
    assert replaced["replaced_ids"] == [item_id]


def test_dry_run_and_cancellation_do_not_mutate_catalog(vault_dir: Path) -> None:
    source = _new_vault(vault_dir, "source.json")
    item_id = source.items.create_license("Selected", license_value="SECRET")
    package = vault_dir / "selected.lgt"
    export_transfer(source, package, TRANSFER_PASSWORD, ids=[item_id])
    destination = _new_vault(vault_dir, "destination.json")
    before = destination.path.read_bytes()
    preview = import_transfer(package, destination, TRANSFER_PASSWORD, dry_run=True)
    assert preview["dry_run"] is True and preview["imported_ids"] == [item_id]
    assert destination.path.read_bytes() == before and destination.items.list_items() == []
    with pytest.raises(transfer.TransferCancelled):
        import_transfer(package, destination, TRANSFER_PASSWORD, cancel=lambda: True)
    assert destination.items.list_items() == []


def test_failed_final_save_rolls_back_catalog_and_sidecar(vault_dir: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    source = _new_vault(vault_dir, "source.json")
    source_file = vault_dir / "source.txt"
    source_file.write_text("data", encoding="utf-8")
    document_id = source.documents.create(source_file)
    package = vault_dir / "document.lgt"
    export_transfer(source, package, TRANSFER_PASSWORD, ids=[document_id])
    destination = _new_vault(vault_dir, "destination.json")
    original = destination.path.read_bytes()
    original_blobs = {path.name for path in (vault_dir / "Attachments").glob("*.blob")}

    def fail_save() -> None:
        raise OSError("synthetic commit failure")

    monkeypatch.setattr(destination, "save", fail_save)
    with pytest.raises(OSError):
        import_transfer(package, destination, TRANSFER_PASSWORD)
    assert destination.path.read_bytes() == original
    assert destination.items.list_items() == []
    assert {path.name for path in (vault_dir / "Attachments").glob("*.blob")} == original_blobs


def test_bounds_and_attachment_exclusion_are_rejected(vault_dir: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    source = _new_vault(vault_dir, "source.json")
    source_file = vault_dir / "source.txt"
    source_file.write_text("data", encoding="utf-8")
    document_id = source.documents.create(source_file)
    with pytest.raises(TransferError, match="attachments"):
        export_transfer(source, vault_dir / "excluded.lgt", TRANSFER_PASSWORD, ids=[document_id], include_attachments=False)

    item_id = source.items.create_note("Small", "body")
    package = vault_dir / "small.lgt"
    export_transfer(source, package, TRANSFER_PASSWORD, ids=[item_id])
    monkeypatch.setattr(transfer, "MAX_TRANSFER_PACKAGE_BYTES", 1)
    with pytest.raises(TransferError):
        inspect_transfer(package)


FAST_TRANSFER_KDF = {"time_cost": 1, "memory_cost_kib": 8192, "parallelism": 1}


def test_transfer_kdf_header_uses_vault_defaults_and_accepts_only_bounded_parameters(
        vault_dir: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    source = _new_vault(vault_dir, "source.json")
    item_id = source.items.create_license("Selected", license_value="SECRET")
    default = vault_dir / "default.lgt"
    export_transfer(source, default, TRANSFER_PASSWORD, ids=[item_id])
    header = json.loads(default.read_text(encoding="utf-8"))["kdf"]
    assert {key: header[key] for key in ("name", "time_cost", "memory_cost_kib", "parallelism")} == {
        "name": "argon2id", "time_cost": 3, "memory_cost_kib": 65536, "parallelism": 4}

    fast = vault_dir / "fast.lgt"
    export_transfer(source, fast, TRANSFER_PASSWORD, ids=[item_id], kdf_overrides=FAST_TRANSFER_KDF)
    envelope = json.loads(fast.read_text(encoding="utf-8"))
    assert envelope["kdf"]["memory_cost_kib"] == 8192
    destination = _new_vault(vault_dir, "destination.json")
    import_transfer(fast, destination, TRANSFER_PASSWORD)
    assert len(destination.items.list_items()) == 1
    with pytest.raises(TransferError):
        export_transfer(source, vault_dir / "bad.lgt", TRANSFER_PASSWORD, ids=[item_id],
                        kdf_overrides={**FAST_TRANSFER_KDF, "parallelism": 17})

    def mutated(bad: dict) -> Path:
        path = vault_dir / f"mutated-{uuid.uuid4().hex}.lgt"
        value = json.loads(fast.read_text(encoding="utf-8"))
        value["kdf"] = {**value["kdf"], **bad}
        path.write_text(json.dumps(value), encoding="utf-8")
        return path

    def refuse(*_args, **_kwargs):
        raise AssertionError("KDF must not run for out-of-range parameters")

    monkeypatch.setattr(transfer, "hash_secret_raw", refuse)
    for bad in ({"memory_cost_kib": 4096}, {"memory_cost_kib": 1024 * 1024}, {"time_cost": 0},
                {"time_cost": 11}, {"parallelism": 0}, {"parallelism": 17}, {"hash_len": 16}):
        with pytest.raises(TransferError):
            import_transfer(mutated(bad), destination, TRANSFER_PASSWORD)
    monkeypatch.undo()
    with pytest.raises(TransferError):
        import_transfer(mutated({"memory_cost_kib": 16384}), destination, TRANSFER_PASSWORD)
    assert len(destination.items.list_items()) == 1
