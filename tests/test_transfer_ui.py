from __future__ import annotations

import socket
import uuid
from pathlib import Path

import pytest

from localvault.session_guard import SessionGuard, StaleSession
from localvault.transfer import TransferCancelled, TransferError
from localvault.app.transfer_controller import TransferController, TransferSelection
from localvault.vault import create_vault

KDF = {"time_cost": 1, "memory_cost_kib": 8192, "parallelism": 1, "hash_len": 32}
MASTER = "transfer ui master password"
PACKAGE_PASSWORD = "different transfer password"


@pytest.fixture
def vault_dir() -> Path:
    path = Path(".m7-transfer-ui-data") / uuid.uuid4().hex
    path.mkdir(parents=True, exist_ok=False)
    return path


def _new_vault(path: Path, name: str):
    return create_vault(path / name, MASTER, kdf_overrides=KDF)


def test_export_preview_filters_are_metadata_only_and_do_not_publish(vault_dir: Path) -> None:
    source = _new_vault(vault_dir, "source.json")
    selected = source.items.create_license("Selected", license_value="PROTECTED-SECRET", tags=["work"])
    source.items.create_note("Other", body="PRIVATE-BODY", tags=["home"])
    source.items.set_metadata(selected, favorite=True)

    controller = TransferController(source)
    preview = controller.preview_export(tags=["work"])
    assert preview["item_count"] == 1
    assert preview["kind_counts"] == {"license": 1}
    assert "PROTECTED-SECRET" not in repr(preview)
    assert not list(vault_dir.glob("*.lgt"))

    favorite = controller.preview_export(favorite=True)
    assert favorite["item_count"] == 1
    assert favorite["manifest"]["items"][0]["id"] == selected


def test_import_requires_confirmation_and_commit_revalidates(vault_dir: Path) -> None:
    source = _new_vault(vault_dir, "source.json")
    item_id = source.items.create_note("Selected", body="PRIVATE-BODY")
    package = vault_dir / "selected.lgt"
    TransferController(source).export(package, PACKAGE_PASSWORD, ids=[item_id])

    destination = _new_vault(vault_dir, "destination.json")
    controller = TransferController(destination)
    preview = controller.import_package(package, PACKAGE_PASSWORD)
    assert preview["requires_confirmation"] is True
    assert destination.items.list_items() == []

    result = controller.commit_import(package, PACKAGE_PASSWORD)
    assert result["committed"] is True
    assert [row["id"] for row in destination.items.list_items()] == [item_id]
    assert "PRIVATE-BODY" not in repr(preview)


def test_locked_or_invalidated_session_fails_closed(vault_dir: Path) -> None:
    session = _new_vault(vault_dir, "vault.json")
    session.items.create_note("Selected", body="PRIVATE")
    controller = TransferController(session)
    session.lock()
    with pytest.raises(StaleSession):
        controller.preview_export(kinds=["note"])

    session = _new_vault(vault_dir, "guarded.json")
    guard = SessionGuard("profile-a")
    lease = guard.open(300)
    controller = TransferController(session, guard=guard, lease=lease)
    guard.invalidate("profile-b")
    with pytest.raises(StaleSession):
        controller.preview_export(kinds=["note"])


def test_cancellation_and_non_local_destinations_are_rejected(vault_dir: Path) -> None:
    session = _new_vault(vault_dir, "vault.json")
    session.items.create_note("Selected", body="PRIVATE")
    controller = TransferController(session)
    with pytest.raises(TransferCancelled):
        controller.preview_export(kinds=["note"], cancel=lambda: True)
    with pytest.raises(TransferError, match="local"):
        controller.export(r"\\server\share\selected.lgt", PACKAGE_PASSWORD, kinds=["note"])


def test_transfer_password_must_be_distinct_when_master_is_known(vault_dir: Path) -> None:
    session = _new_vault(vault_dir, "vault.json")
    session.items.create_note("Selected", body="PRIVATE")
    controller = TransferController(session)
    with pytest.raises(TransferError, match="distinct"):
        controller.export(
            vault_dir / "selected.lgt", MASTER, kinds=["note"], master_password=MASTER,
        )


def test_transfer_selection_accepts_explicit_ids_alias(vault_dir: Path) -> None:
    session = _new_vault(vault_dir, "vault.json")
    item_id = session.items.create_note("Selected", body="PRIVATE")
    selection = TransferSelection.from_values(selected_ids=[item_id])
    preview = TransferController(session).preview_export(selection)
    assert preview["item_count"] == 1


def test_transfer_preview_and_export_are_offline_by_default(vault_dir: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    session = _new_vault(vault_dir, "vault.json")
    session.items.create_note("Selected", body="PRIVATE")

    def network_forbidden(*_args, **_kwargs):
        raise AssertionError("selective transfer attempted network access")

    monkeypatch.setattr(socket, "socket", network_forbidden)
    monkeypatch.setattr(socket, "create_connection", network_forbidden, raising=False)
    monkeypatch.setattr(socket, "getaddrinfo", network_forbidden)
    controller = TransferController(session)
    controller.preview_export(kinds=["note"])
    controller.export(vault_dir / "selected.lgt", PACKAGE_PASSWORD, kinds=["note"])
