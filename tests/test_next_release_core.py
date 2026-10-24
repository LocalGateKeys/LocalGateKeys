from __future__ import annotations

import shutil
import uuid
from pathlib import Path

import pytest

from localvault.history import HistoryConflict
from localvault.relationships import RelationshipConflict
from localvault.smart_views import SmartViewError
from localvault.vault import VaultLockedError, create_vault

KDF = {"time_cost": 1, "memory_cost_kib": 8192, "parallelism": 1, "hash_len": 32}
MASTER = "next release synthetic test master"


@pytest.fixture
def session():
    # Keep the focused suite away from pytest's Windows temp directory.  On
    # some developer machines that directory has inherited ACLs which prevent
    # pytest's tmp_path fixture from creating its numbered child.
    root = Path(".next-release-core-data") / uuid.uuid4().hex
    root.mkdir(parents=True)
    value = create_vault(root / "vault.json", MASTER, kdf_overrides=KDF)
    try:
        yield value
    finally:
        value.lock()
        shutil.rmtree(root, ignore_errors=True)


def test_typed_history_is_immutable_masked_and_restores_monotonically(session) -> None:
    item_id = session.items.create_note("Private", "first secret")
    assert session.items.update_item(item_id, body="second secret", expected_revision=1)
    rows = session.history.list(item_id)
    assert len(rows) == 1 and rows[0]["revision"] == 1
    snapshot_id = rows[0]["snapshot_id"]

    diff = session.history.compare(item_id, snapshot_id)
    assert diff["from_revision"] == 1
    assert all("secret" not in repr(value) for value in diff["differences"])
    with pytest.raises(Exception, match="explicit caller intent"):
        session.history.compare(item_id, snapshot_id, reveal=True)
    revealed = session.history.compare(item_id, snapshot_id, reveal=True, intent="review history")
    assert any(value["before"] == "first secret" for value in revealed["differences"])

    assert session.items.update_item(item_id, expected_revision=2) is False
    with pytest.raises(HistoryConflict, match="revision conflict"):
        session.history.restore_as_new_revision(item_id, snapshot_id, expected_revision=1)
    assert session.history.restore_as_new_revision(item_id, snapshot_id, expected_revision=2)
    restored = session.items.get_item_for_edit(item_id)
    assert restored["revision"] == 3 and restored["payload"]["body"] == "first secret"


def test_relationship_edges_backlinks_cycles_and_legacy_migration(session) -> None:
    first = session.items.create_note("First")
    second = session.items.create_note("Second")
    edge_id = session.relationships.add(first, second, "related_to", expected_revision=1)
    assert session.relationships.outgoing(first)[0]["edge_id"] == edge_id
    assert session.relationships.backlinks(second)[0]["source_id"] == first
    session.relationships.add(second, first, "related_to", expected_revision=1)
    walked = session.relationships.traverse(first, depth=5)
    assert set(walked["nodes"]) == {first, second}
    with pytest.raises(RelationshipConflict, match="revision conflict"):
        session.relationships.remove(edge_id, expected_revision=1)
    assert session.relationships.remove(edge_id, expected_revision=2)
    assert session.relationships.outgoing(first) == []
    assert any(row["edge_id"] == edge_id and row["tombstoned"] is True
               for row in session.relationships.list(include_tombstoned=True))

    source = session.path.parent / "receipt.txt"
    source.write_text("receipt", encoding="utf-8")
    document_id = session.documents.create(source)
    purchase = session.items.create_purchase("Receipt", document_ids=[document_id])
    report = session.relationships.migrate_legacy()
    assert report["migrated"] == 1
    migrated = session.relationships.outgoing(purchase)
    assert migrated and migrated[0]["relation_type"] == "supports_document"


def test_smart_views_are_bounded_metadata_only_and_deterministic(session) -> None:
    first = session.items.create_note("Alpha", "private body", tags=["work"])
    second = session.items.create_note("Beta", "other private body", tags=["home"])
    view = session.smart_views.create(
        "Work notes", {"op": "and", "clauses": [
            {"field": "kind", "op": "eq", "value": "note"},
            {"field": "tags", "op": "contains", "value": "work"},
        ]}, sort_keys=[{"field": "title", "direction": "asc"}], pinned=True,
    )
    result = session.smart_views.evaluate(view)
    assert [row["id"] for row in result] == [first]
    assert all("private body" not in repr(row) for row in result)
    assert session.smart_views.rename(view, "Renamed")
    assert session.smart_views.pin(view, False)
    assert session.smart_views.delete(view)
    assert session.smart_views.get(view) is None
    with pytest.raises(SmartViewError):
        session.smart_views.create("Unsafe", {"field": "payload.body", "op": "contains", "value": "x"})


def test_history_relationship_and_view_services_fail_closed_after_lock(session) -> None:
    session.items.create_note("Ephemeral")
    session.lock()
    with pytest.raises(VaultLockedError):
        session.history.list()
    with pytest.raises(VaultLockedError):
        session.relationships.list()
    with pytest.raises(VaultLockedError):
        session.smart_views.list()
