"""Vault bridge between the vault payload and the pure sync merge engine."""
from __future__ import annotations

import base64
import copy
import time
from pathlib import Path

import pytest
import test_licensing

from localvault import licensing
from localvault.item_schema import MAX_TITLE
from localvault.session_guard import StaleSession
from localvault.sync.engine import ItemState, MergeOutcome, bump, merge
from localvault.sync.pairing import DeviceIdentity
from localvault.sync.vault_bridge import (
    CONFLICT_SUFFIX,
    ITEM_WRAPPER_SCHEMA,
    LOCAL_ONLY_ENTRY_FIELDS,
    LOCAL_ONLY_ITEM_FIELDS,
    MAX_SYNC_RECORDS,
    ApplyReport,
    BridgeError,
    SyncGroupState,
    _wrapper,
    apply,
    check_remote_state,
    clear_sync_state,
    load_sync_state,
    local_view,
    prune_tombstones,
    save_sync_state,
    wrapper_digest,
)
from localvault.vault import PNG_SIGNATURE, VaultLockedError, create_vault

TEST_KDF = {"time_cost": 1, "memory_cost_kib": 8192, "parallelism": 1, "hash_len": 32}
MASTER = "synthetic master"
NOW = int(time.time())
A, B = "device-a", "device-b"


class FakeLease:
    def __init__(self) -> None:
        self.valid = True
        self.checks = 0

    def check(self) -> None:
        self.checks += 1
        if not self.valid:
            raise StaleSession("Vault is locked")


@pytest.fixture
def lease() -> FakeLease:
    return FakeLease()


def _vault(tmp_path: Path, name: str):
    return create_vault(tmp_path / f"{name}.json", MASTER, kdf_overrides=TEST_KDF)


def _file(session) -> bytes:
    return Path(session.path).read_bytes()


def _sync(dst, dst_id: str, src, src_id: str, lease: FakeLease) -> ApplyReport:
    """One direction: dst pulls src's view (the runner's local_view -> merge -> apply)."""
    src_view = local_view(src, lease, device_id=src_id, now=NOW)
    dst_view = local_view(dst, lease, device_id=dst_id, now=NOW)
    return apply(dst, lease, merge(dst_view, src_view.values()), device_id=dst_id, now=NOW)


def _entry(session, entry_id: str) -> dict:
    return next(e for e in session._payload["entries"] if e["id"] == entry_id)


def _item(session, item_id: str) -> dict:
    return next(i for i in session._payload["items"] if i["id"] == item_id)


def _trash_ids(session) -> set[str]:
    return {r["entry"]["id"] for r in session._payload.get("trash", [])}


# --- local_view ------------------------------------------------------------------------


def test_local_edit_bumps_own_counter_once(tmp_path: Path, lease: FakeLease) -> None:
    a = _vault(tmp_path, "a")
    entry_id = a.upsert_web(origin="https://example.com", username="me", password="first-pass")
    first = local_view(a, lease, device_id=A, now=NOW)
    assert first[entry_id].vv == {A: 1}
    before = _file(a)
    again = local_view(a, lease, device_id=A, now=NOW)
    assert again == first
    assert _file(a) == before, "an unchanged view must not write the vault"

    a.update_entry_fields(entry_id, password="second-pass")
    edited = local_view(a, lease, device_id=A, now=NOW)
    assert edited[entry_id].vv == {A: 2}
    assert local_view(a, lease, device_id=A, now=NOW)[entry_id].vv == {A: 2}


def test_view_covers_both_namespaces_without_local_only_fields(tmp_path: Path, lease: FakeLease) -> None:
    a = _vault(tmp_path, "a")
    entry_id = a.upsert_web(origin="https://example.com", username="me", password="pw-123456")
    a.set_entry_icon(entry_id, PNG_SIGNATURE + b"icon-bytes")
    collection_id = a.collection_service.create("Home")
    item_id = a.item_service.create_note("Note", "body")
    a.item_service.set_metadata(item_id, collection_ids=[collection_id])
    view = local_view(a, lease, device_id=A, now=NOW)
    assert set(view) == {entry_id, item_id}
    entry_state, item_state = view[entry_id], view[item_id]
    assert entry_state.item["ns"] == "entry" and entry_state.item["record"]["password"] == "pw-123456"
    assert item_state.item["ns"] == "item" and item_state.item["record"]["payload"]["body"] == "body"
    assert set(entry_state.item) == {"ns", "schema", "updated_at", "record"}
    assert entry_state.item["updated_at"] == _entry(a, entry_id)["updated_at"]
    for field in LOCAL_ONLY_ENTRY_FIELDS:
        assert field not in entry_state.item["record"]
    for field in LOCAL_ONLY_ITEM_FIELDS:
        assert field not in item_state.item["record"]
    assert "site_icon" in LOCAL_ONLY_ENTRY_FIELDS
    assert {"revision", "collection_ids"} <= set(LOCAL_ONLY_ITEM_FIELDS)
    meta = a._payload["sync_meta"]["items"]
    assert meta[entry_id]["digest"] == wrapper_digest(entry_state.item)


def test_local_only_field_change_does_not_bump(tmp_path: Path, lease: FakeLease) -> None:
    a = _vault(tmp_path, "a")
    entry_id = a.upsert_web(origin="https://example.com", username="me", password="pw-123456")
    first = local_view(a, lease, device_id=A, now=NOW)
    a.set_entry_icon(entry_id, PNG_SIGNATURE + b"other-icon")
    assert local_view(a, lease, device_id=A, now=NOW)[entry_id].vv == first[entry_id].vv


def test_delete_and_purge_produce_one_tombstone(tmp_path: Path, lease: FakeLease) -> None:
    a = _vault(tmp_path, "a")
    entry_id = a.upsert_web(origin="https://example.com", username="me", password="pw-123456")
    item_id = a.item_service.create_note("Note", "body")
    local_view(a, lease, device_id=A, now=NOW)
    a.delete(entry_id)
    a.item_service.delete_item(item_id)
    view = local_view(a, lease, device_id=A, now=NOW + 5)
    for rid in (entry_id, item_id):
        assert view[rid].deleted and view[rid].item is None
        assert view[rid].vv == {A: 2}
        assert view[rid].deleted_at == NOW + 5
    a.purge_deleted_many([entry_id, item_id])
    again = local_view(a, lease, device_id=A, now=NOW + 9)
    assert again[entry_id] == view[entry_id] and again[item_id] == view[item_id]


def test_local_restore_from_trash_revives_with_bumped_vector(tmp_path: Path, lease: FakeLease) -> None:
    a = _vault(tmp_path, "a")
    item_id = a.item_service.create_note("Note", "body")
    local_view(a, lease, device_id=A, now=NOW)
    a.item_service.delete_item(item_id)
    assert local_view(a, lease, device_id=A, now=NOW)[item_id].deleted
    a.item_service.restore_item(item_id)
    revived = local_view(a, lease, device_id=A, now=NOW)[item_id]
    assert not revived.deleted and revived.vv == {A: 3}


def test_cross_namespace_id_collision_raises(tmp_path: Path, lease: FakeLease) -> None:
    a = _vault(tmp_path, "a")
    entry_id = a.upsert_web(origin="https://example.com", username="me", password="pw-123456")
    item_id = a.item_service.create_note("Note", "body")
    _item(a, item_id)["id"] = entry_id  # in-memory corruption only
    with pytest.raises(BridgeError):
        local_view(a, lease, device_id=A, now=NOW)


def test_meta_bound_is_enforced(tmp_path: Path, lease: FakeLease) -> None:
    a = _vault(tmp_path, "a")
    tomb = {"digest": None, "body": None, "updated_at": None, "vv": {B: 1},
            "deleted": True, "deleted_at": NOW}
    a._payload["sync_meta"] = {"device_id": A,
                               "items": {f"id-{n}": dict(tomb) for n in range(MAX_SYNC_RECORDS + 1)}}
    before = _file(a)
    with pytest.raises(BridgeError):
        local_view(a, lease, device_id=A, now=NOW)
    assert _file(a) == before


def test_malformed_meta_fails_closed(tmp_path: Path, lease: FakeLease) -> None:
    a = _vault(tmp_path, "a")
    bad = {"digest": None, "body": None, "updated_at": None, "vv": {B: -1},
           "deleted": True, "deleted_at": NOW}
    a._payload["sync_meta"] = {"device_id": A, "items": {"x": bad}}
    with pytest.raises(BridgeError):
        local_view(a, lease, device_id=A, now=NOW)


# --- prune -----------------------------------------------------------------------------


def test_prune_tombstones_drops_only_old_tombstones() -> None:
    day = 86400
    meta = {
        "old": {"digest": None, "vv": {A: 2}, "deleted": True, "deleted_at": NOW - 366 * day},
        "recent": {"digest": None, "vv": {A: 2}, "deleted": True, "deleted_at": NOW - 10 * day},
        "live": {"digest": "0" * 64, "vv": {A: 1}, "deleted": False, "deleted_at": None},
    }
    pruned = prune_tombstones(meta, NOW)
    assert set(pruned) == {"recent", "live"}
    assert set(meta) == {"old", "recent", "live"}, "input must not be mutated"
    assert set(prune_tombstones(meta, NOW, max_age_days=5)) == {"live"}


def test_local_view_prunes_expired_tombstones(tmp_path: Path, lease: FakeLease) -> None:
    a = _vault(tmp_path, "a")
    item_id = a.item_service.create_note("Note", "body")
    local_view(a, lease, device_id=A, now=NOW)
    a.item_service.delete_item(item_id)
    assert local_view(a, lease, device_id=A, now=NOW)[item_id].deleted
    later = local_view(a, lease, device_id=A, now=NOW + 400 * 86400)
    assert item_id not in later
    assert item_id not in a._payload["sync_meta"]["items"]


# --- apply -----------------------------------------------------------------------------


def test_entry_password_edit_propagates_without_rebump(tmp_path: Path, lease: FakeLease) -> None:
    a, b = _vault(tmp_path, "a"), _vault(tmp_path, "b")
    entry_id = a.upsert_web(origin="https://example.com", username="me", password="first-pass")
    report = _sync(b, B, a, A, lease)
    assert report.applied == 1
    assert _entry(b, entry_id)["password"] == "first-pass"
    assert local_view(b, lease, device_id=B, now=NOW) == local_view(a, lease, device_id=A, now=NOW)

    a.update_entry_fields(entry_id, password="second-pass")
    _sync(b, B, a, A, lease)
    assert _entry(b, entry_id)["password"] == "second-pass"
    assert b.password_history(entry_id)[0]["password"] == "first-pass"
    view_b = local_view(b, lease, device_id=B, now=NOW)
    assert view_b[entry_id].vv == {A: 2}, "an applied remote edit must not be re-attributed to B"
    assert view_b == local_view(a, lease, device_id=A, now=NOW)


def test_typed_item_edit_propagates(tmp_path: Path, lease: FakeLease) -> None:
    a, b = _vault(tmp_path, "a"), _vault(tmp_path, "b")
    item_id = a.item_service.create_note("Note", "body one")
    _sync(b, B, a, A, lease)
    assert _item(b, item_id)["payload"]["body"] == "body one"
    a.item_service.update_item(item_id, body="body two")
    _sync(b, B, a, A, lease)
    assert _item(b, item_id)["payload"]["body"] == "body two"
    assert local_view(b, lease, device_id=B, now=NOW)[item_id].vv == {A: 2}


def test_apply_delete_moves_to_trash(tmp_path: Path, lease: FakeLease) -> None:
    a, b = _vault(tmp_path, "a"), _vault(tmp_path, "b")
    entry_id = a.upsert_web(origin="https://example.com", username="me", password="pw-123456")
    item_id = a.item_service.create_note("Note", "body")
    _sync(b, B, a, A, lease)
    a.delete(entry_id)
    a.item_service.delete_item(item_id)
    report = _sync(b, B, a, A, lease)
    assert report.deleted == 2
    assert not any(e["id"] == entry_id for e in b._payload["entries"])
    assert not any(i["id"] == item_id for i in b._payload["items"])
    assert {entry_id, item_id} <= _trash_ids(b), "remote deletes must stay recoverable"
    view_b = local_view(b, lease, device_id=B, now=NOW)
    view_a = local_view(a, lease, device_id=A, now=NOW)
    assert view_b == view_a
    b.restore_deleted(entry_id)  # still recoverable by the user
    assert any(e["id"] == entry_id for e in b._payload["entries"])


def test_remote_upsert_restores_from_trash(tmp_path: Path, lease: FakeLease) -> None:
    a, b = _vault(tmp_path, "a"), _vault(tmp_path, "b")
    item_id = a.item_service.create_note("Note", "body")
    entry_id = a.upsert_web(origin="https://example.com", username="me", password="pw-123456")
    _sync(b, B, a, A, lease)
    b.item_service.delete_item(item_id)
    b.delete(entry_id)
    local_view(b, lease, device_id=B, now=NOW)  # B's tombstones: {A:1, B:1}
    a.item_service.update_item(item_id, body="edited on A")  # concurrent edit {A:2}
    a.update_entry_fields(entry_id, password="edited-on-a")
    _sync(b, B, a, A, lease)
    assert _item(b, item_id)["payload"]["body"] == "edited on A"
    assert _entry(b, entry_id)["password"] == "edited-on-a"
    assert not ({item_id, entry_id} & _trash_ids(b))
    view_b = local_view(b, lease, device_id=B, now=NOW)
    assert view_b[item_id].vv == {A: 2, B: 1} and not view_b[item_id].deleted
    _sync(a, A, b, B, lease)
    assert local_view(a, lease, device_id=A, now=NOW) == local_view(b, lease, device_id=B, now=NOW)


def test_local_only_fields_preserved_on_remote_upsert(tmp_path: Path, lease: FakeLease) -> None:
    a, b = _vault(tmp_path, "a"), _vault(tmp_path, "b")
    item_id = a.item_service.create_note("Note", "body")
    entry_id = a.upsert_web(origin="https://example.com", username="me", password="pw-123456")
    _sync(b, B, a, A, lease)
    collection_id = b.collection_service.create("Mine")
    b.item_service.set_metadata(item_id, collection_ids=[collection_id])
    b.set_entry_icon(entry_id, PNG_SIGNATURE + b"b-icon")
    revision_before = _item(b, item_id)["revision"]
    icon_before = _entry(b, entry_id)["site_icon"]
    local_view(b, lease, device_id=B, now=NOW)  # collection/icon changes are local-only: no bump
    a.item_service.update_item(item_id, body="new body")
    a.update_entry_fields(entry_id, password="new-password")
    _sync(b, B, a, A, lease)
    item = _item(b, item_id)
    assert item["payload"]["body"] == "new body"
    assert item["collection_ids"] == [collection_id]
    assert item["revision"] == revision_before + 1
    assert _entry(b, entry_id)["site_icon"] == icon_before
    assert _entry(b, entry_id)["password"] == "new-password"
    assert local_view(b, lease, device_id=B, now=NOW)[item_id].vv == {A: 2}


def test_new_remote_item_gets_default_local_fields(tmp_path: Path, lease: FakeLease) -> None:
    a, b = _vault(tmp_path, "a"), _vault(tmp_path, "b")
    item_id = a.item_service.create_note("Note", "body")
    for _ in range(3):
        a.item_service.update_item(item_id, body=f"body {_}")
    _sync(b, B, a, A, lease)
    assert _item(b, item_id)["revision"] == 1
    assert _item(b, item_id)["collection_ids"] == []


def _concurrent_title_edit(tmp_path: Path, lease: FakeLease, title_a: str, title_b: str):
    a, b = _vault(tmp_path, "a"), _vault(tmp_path, "b")
    item_id = a.item_service.create_note("Shared", "body")
    _sync(b, B, a, A, lease)
    a.item_service.update_item(item_id, title=title_a)
    b.item_service.update_item(item_id, title=title_b)
    return a, b, item_id


def test_conflict_copy_inserted_once_with_suffix(tmp_path: Path, lease: FakeLease) -> None:
    a, b, item_id = _concurrent_title_edit(tmp_path, lease, "Title from A", "Title from B")
    report = _sync(b, B, a, A, lease)
    assert report.conflicts == 1
    titles = sorted(i["title"] for i in b._payload["items"])
    copies = [t for t in titles if t.endswith(CONFLICT_SUFFIX)]
    assert len(copies) == 1 and len(titles) == 2
    assert {t.removesuffix(CONFLICT_SUFFIX) for t in titles} == {"Title from A", "Title from B"}
    # repeating the same pull creates nothing new and does not re-bump
    view_before = local_view(b, lease, device_id=B, now=NOW)
    again = _sync(b, B, a, A, lease)
    assert again.applied == 0
    assert len(b._payload["items"]) == 2
    assert local_view(b, lease, device_id=B, now=NOW) == view_before
    # the other side converges to the same two items and identical states
    _sync(a, A, b, B, lease)
    assert local_view(a, lease, device_id=A, now=NOW) == local_view(b, lease, device_id=B, now=NOW)
    assert sorted(i["title"] for i in a._payload["items"]) == titles


def test_conflict_copy_of_entry_uses_label_suffix(tmp_path: Path, lease: FakeLease) -> None:
    a, b = _vault(tmp_path, "a"), _vault(tmp_path, "b")
    entry_id = a.upsert_web(origin="https://example.com", username="me", password="base-pass")
    _sync(b, B, a, A, lease)
    a.update_entry_fields(entry_id, password="pass-from-a")
    b.update_entry_fields(entry_id, password="pass-from-b")
    _sync(b, B, a, A, lease)
    passwords = sorted(e["password"] for e in b._payload["entries"])
    assert passwords == ["pass-from-a", "pass-from-b"], "neither concurrent password may be lost"
    labels = [e["label"] for e in b._payload["entries"]]
    assert sum(label.endswith(CONFLICT_SUFFIX) for label in labels) == 1
    _sync(a, A, b, B, lease)
    assert local_view(a, lease, device_id=A, now=NOW) == local_view(b, lease, device_id=B, now=NOW)


def test_conflict_copy_title_is_truncated_to_fit(tmp_path: Path, lease: FakeLease) -> None:
    long_a, long_b = "A" * MAX_TITLE, "B" * MAX_TITLE
    a, b, _ = _concurrent_title_edit(tmp_path, lease, long_a, long_b)
    _sync(b, B, a, A, lease)
    copies = [i["title"] for i in b._payload["items"] if i["title"].endswith(CONFLICT_SUFFIX)]
    assert len(copies) == 1 and len(copies[0]) == MAX_TITLE


def test_stale_view_is_rejected_without_writes(tmp_path: Path, lease: FakeLease) -> None:
    a, b = _vault(tmp_path, "a"), _vault(tmp_path, "b")
    entry_id = a.upsert_web(origin="https://example.com", username="me", password="pw-123456")
    _sync(b, B, a, A, lease)
    a.update_entry_fields(entry_id, password="from-a-now")
    view_a = local_view(a, lease, device_id=A, now=NOW)
    outcome = merge(local_view(b, lease, device_id=B, now=NOW), view_a.values())
    b.update_entry_fields(entry_id, password="b-edited-after-view")  # not in B's view
    before = _file(b)
    with pytest.raises(BridgeError):
        apply(b, lease, outcome, device_id=B, now=NOW)
    assert _file(b) == before
    assert _entry(b, entry_id)["password"] == "b-edited-after-view"


def test_invalid_remote_record_rejected_without_partial_writes(tmp_path: Path, lease: FakeLease) -> None:
    a, b = _vault(tmp_path, "a"), _vault(tmp_path, "b")
    a.upsert_web(origin="https://good.example", username="me", password="pw-123456")
    good = list(local_view(a, lease, device_id=A, now=NOW).values())[0]
    bad_item = ItemState("6a1f6c55-8a50-4b8c-9a87-6e0d2f1b9f11", {A: 1}, False, None,
                         {"ns": "item", "schema": 1, "updated_at": 1, "record": {"id": "6a1f6c55-8a50-4b8c-9a87-6e0d2f1b9f11",
                                                   "kind": "note", "title": "", "created_at": 1,
                                                   "updated_at": 1, "payload": {"body": "x"}}})
    bad_entry = ItemState("e-1", {A: 1}, False, None,
                          {"ns": "entry", "schema": 1, "updated_at": 0, "record": {"id": "e-1", "kind": "web", "label": "x",
                                                     "username": "u", "password": "p" * 5000,
                                                     "scope": {"origin": "https://x.example"}}})
    local_view(b, lease, device_id=B, now=NOW)
    for bad in (bad_item, bad_entry):
        before_file, before_payload = _file(b), copy.deepcopy(b._payload)
        with pytest.raises(BridgeError):
            apply(b, lease, MergeOutcome((good, bad), (), ()), device_id=B, now=NOW)
        assert _file(b) == before_file
        assert b._payload == before_payload


def test_malformed_wrapper_rejected(tmp_path: Path, lease: FakeLease) -> None:
    b = _vault(tmp_path, "b")
    local_view(b, lease, device_id=B, now=NOW)
    record = {"id": "e-1", "kind": "web", "label": "x", "username": "u", "password": "p",
              "scope": {"origin": "https://x.example"}}
    cases = [
        {"ns": "nope", "schema": 1, "updated_at": 0, "record": record},
        {"ns": "entry", "schema": 1, "updated_at": 0, "record": record, "extra": 1},
        {"ns": "entry", "schema": 1, "updated_at": 0, "record": {**record, "id": "other"}},
        {"ns": "item", "schema": 1, "updated_at": 0, "record": record},  # a credential in the typed namespace
        {"ns": "entry", "schema": 1, "record": record},  # no rank
        {"ns": "entry", "schema": 1, "updated_at": 99, "record": record},  # rank does not match the record
    ]
    for wrapper in cases:
        state = ItemState("e-1", {A: 1}, False, None, wrapper)
        with pytest.raises(BridgeError):
            apply(b, lease, MergeOutcome((state,), (), ()), device_id=B, now=NOW)
    assert b._payload["entries"] == []


def test_unnormalized_remote_record_is_normalized_as_a_local_edit(tmp_path: Path, lease: FakeLease) -> None:
    b = _vault(tmp_path, "b")
    local_view(b, lease, device_id=B, now=NOW)
    record = {"id": "e-1", "kind": "web", "label": "x", "username": "u", "password": "pw",
              "scope": {"origin": "https://X.example"}, "created_at": 1, "updated_at": 1}
    state = ItemState("e-1", {A: 1}, False, None, {"ns": "entry", "schema": 1, "updated_at": 1, "record": record})
    apply(b, lease, MergeOutcome((state,), (), ()), device_id=B, now=NOW)
    view = local_view(b, lease, device_id=B, now=NOW)
    assert view["e-1"].vv == {A: 1, B: 1}, "B's normalized content must dominate the raw remote state"
    assert view["e-1"].item["record"]["scope"]["origin"] == "https://x.example"
    assert local_view(b, lease, device_id=B, now=NOW) == view


def test_invalid_lease_raises_without_writes(tmp_path: Path, lease: FakeLease) -> None:
    a, b = _vault(tmp_path, "a"), _vault(tmp_path, "b")
    a.upsert_web(origin="https://example.com", username="me", password="pw-123456")
    view_a = local_view(a, lease, device_id=A, now=NOW)
    b.upsert_web(origin="https://b.example", username="me", password="pw-123456")
    outcome = merge({}, view_a.values())
    lease.valid = False
    before = _file(b)
    with pytest.raises(StaleSession):
        local_view(b, lease, device_id=B, now=NOW)
    with pytest.raises(StaleSession):
        apply(b, lease, outcome, device_id=B, now=NOW)
    assert _file(b) == before
    assert "sync_meta" not in b._payload


def test_locked_vault_raises(tmp_path: Path, lease: FakeLease) -> None:
    from localvault.vault import VaultLockedError

    b = _vault(tmp_path, "b")
    b.lock()
    with pytest.raises(VaultLockedError):
        local_view(b, lease, device_id=B, now=NOW)
    with pytest.raises(VaultLockedError):
        apply(b, lease, MergeOutcome((), (), ()), device_id=B, now=NOW)


def test_two_vaults_reach_a_fixed_point(tmp_path: Path, lease: FakeLease) -> None:
    a, b = _vault(tmp_path, "a"), _vault(tmp_path, "b")
    e1 = a.upsert_web(origin="https://one.example", username="u1", password="pw-one")
    e2 = a.upsert_web(origin="https://two.example", username="u2", password="pw-two")
    n1 = a.item_service.create_note("Note one", "body")
    b.upsert_web(origin="https://bee.example", username="ub", password="pw-bee")
    n2 = b.item_service.create_bookmark("Mark", "https://example.org/")
    _sync(b, B, a, A, lease)
    _sync(a, A, b, B, lease)
    # concurrent edits, an edit-vs-delete and a delete on both sides
    a.update_entry_fields(e1, password="pw-one-a")
    b.update_entry_fields(e1, password="pw-one-b")
    a.delete(e2)
    b.update_entry_fields(e2, label="Two (edited on B)")
    b.item_service.update_item(n1, body="b body")
    a.item_service.delete_item(n1)
    a.item_service.update_item(n2, url="https://example.org/a")
    for _ in range(4):
        _sync(b, B, a, A, lease)
        _sync(a, A, b, B, lease)
    view_a = local_view(a, lease, device_id=A, now=NOW)
    view_b = local_view(b, lease, device_id=B, now=NOW)
    assert view_a == view_b
    before_a, before_b = _file(a), _file(b)
    assert _sync(b, B, a, A, lease) == ApplyReport(0, 0, 0)
    assert _sync(a, A, b, B, lease) == ApplyReport(0, 0, 0)
    assert local_view(a, lease, device_id=A, now=NOW) == view_a
    assert _file(a) == before_a and _file(b) == before_b, "a converged sync must not write"
    # nothing user-authored was lost
    passwords = {e["password"] for e in a._payload["entries"]}
    assert {"pw-one-a", "pw-one-b", "pw-bee"} <= passwords
    assert any(e["id"] == e2 and e["label"] == "Two (edited on B)" for e in a._payload["entries"])
    assert any(i["id"] == n1 and i["payload"]["body"] == "b body" for i in a._payload["items"])


def test_bump_semantics_match_engine(tmp_path: Path, lease: FakeLease) -> None:
    a = _vault(tmp_path, "a")
    item_id = a.item_service.create_note("Note", "body")
    first = local_view(a, lease, device_id=A, now=NOW)[item_id].vv
    a.item_service.update_item(item_id, body="x")
    assert local_view(a, lease, device_id=A, now=NOW)[item_id].vv == bump(first, A)


# --- sync_group state ------------------------------------------------------------------


def _state(**changes) -> SyncGroupState:
    identity = DeviceIdentity.generate("device-a")
    values = dict(group_id="group-1", epoch=1, key=b"k" * 32,
                  device_identity=identity.protected_dict(), last_seen={"device-b": 7},
                  folder_path="C:/Sync/LocalGateKeys", lan_peers=({"device_id": "device-b",
                                                                   "host": "192.168.1.5", "port": 5000},),
                  install_id="install-1")
    values.update(changes)
    return SyncGroupState(**values)


def test_sync_group_state_round_trip(tmp_path: Path) -> None:
    a = _vault(tmp_path, "a")
    assert load_sync_state(a) is None
    state = _state()
    save_sync_state(a, state)
    loaded = load_sync_state(a)
    assert loaded == state
    assert loaded.device_id == "device-a"
    assert loaded.identity().fingerprint == DeviceIdentity.from_protected_dict(state.device_identity).fingerprint
    assert a._payload["sync_group"]["key"] == base64.b64encode(b"k" * 32).decode("ascii")
    assert "k" * 32 not in repr(state)
    clear_sync_state(a)
    assert load_sync_state(a) is None


@pytest.mark.parametrize("changes", [
    {"group_id": ""}, {"epoch": 0}, {"epoch": True}, {"key": b"short"},
    {"device_identity": {"device_id": "x"}}, {"last_seen": {"bad|id": 1}},
    {"last_seen": {"device-b": -1}}, {"last_seen": {f"d{n}": 1 for n in range(65)}},
    {"folder_path": ""}, {"lan_peers": tuple({"n": n} for n in range(17))},
    {"lan_peers": ({"x": float("nan")},)}, {"install_id": "a\x00b"},
])
def test_sync_group_state_validation(changes) -> None:
    with pytest.raises(BridgeError):
        _state(**changes)


def test_malformed_stored_sync_group_fails_closed(tmp_path: Path) -> None:
    a = _vault(tmp_path, "a")
    save_sync_state(a, _state())
    a._payload["sync_group"]["epoch"] = "1"
    with pytest.raises(BridgeError):
        load_sync_state(a)


# --- fix round 1: per-device trust, newest-edit rank, strict entries ---------------------


def _desktop(session, label: str = "App") -> str:
    return session.add_desktop(
        label=label, username="me", password="desk-pass", exe_path="C:/Apps/app.exe",
        exe_sha256="a" * 64, window_title="App - Sign in",
        control_fingerprint=[{"control_type": "Edit", "name": "User"}],
        username_selector={"automation_id": "user"}, password_selector={"automation_id": "pw"})


def test_device_trust_does_not_sync(tmp_path: Path, lease: FakeLease) -> None:
    a, b = _vault(tmp_path, "a"), _vault(tmp_path, "b")
    entry_id = _desktop(a)
    view_before = local_view(a, lease, device_id=A, now=NOW)
    a.set_desktop_embedded_fill_approval(entry_id, True)
    a.set_entry_extras(entry_id, policy={"fill": "click", "sign_in": "enabled"})
    # the setters also touch updated_at; undo that to isolate the trust fields
    _entry(a, entry_id)["updated_at"] = view_before[entry_id].item["record"]["updated_at"]
    view_a = local_view(a, lease, device_id=A, now=NOW)
    assert view_a[entry_id].vv == view_before[entry_id].vv, "trust changes are not synced edits"
    record = view_a[entry_id].item["record"]
    assert "embedded_web_fill_approved" not in record["scope"] and "sign_in" not in record["policy"]
    _sync(b, B, a, A, lease)
    stored = _entry(b, entry_id)
    assert stored["scope"]["embedded_web_fill_approved"] is False
    assert stored["policy"]["sign_in"] == "never"
    # B's own approval survives a later remote edit from A
    b.set_desktop_embedded_fill_approval(entry_id, True)
    b.set_entry_extras(entry_id, policy={"fill": "click", "sign_in": "enabled"})
    local_view(b, lease, device_id=B, now=NOW)
    a.update_entry_fields(entry_id, password="new-desk-pass")
    _sync(b, B, a, A, lease)
    stored = _entry(b, entry_id)
    assert stored["password"] == "new-desk-pass"
    assert stored["scope"]["embedded_web_fill_approved"] is True
    assert stored["policy"]["sign_in"] == "enabled"


def test_malicious_remote_trust_is_replaced_with_safe_defaults(tmp_path: Path, lease: FakeLease) -> None:
    b = _vault(tmp_path, "b")
    local_view(b, lease, device_id=B, now=NOW)
    record = {"id": "d-1", "kind": "desktop", "label": "Evil", "username": "u", "password": "p",
              "created_at": 1, "updated_at": 1,
              "policy": {"fill": "click", "sign_in": "enabled", "require_master_password": False,
                         "save_prompts": True},
              "scope": {"exe_path": "C:/x.exe", "exe_sha256": "B" * 64, "window_title": "X",
                        "control_fingerprint": [{"name": "User"}], "username_selector": None,
                        "password_selector": None, "binding_mode": "strict",
                        "embedded_web_fill_approved": True, "pairing_secret": "s",
                        "sign_in_selector": {"name": "Sign in"}}}
    state = ItemState("d-1", {A: 1}, False, None, {"ns": "entry", "schema": 1, "updated_at": 1, "record": record})
    apply(b, lease, MergeOutcome((state,), (), ()), device_id=B, now=NOW)
    stored = _entry(b, "d-1")
    assert stored["scope"]["embedded_web_fill_approved"] is False
    assert stored["policy"]["sign_in"] == "never"
    assert not {"pairing_secret", "sign_in_selector"} & set(stored["scope"])
    view = local_view(b, lease, device_id=B, now=NOW)
    assert view["d-1"].vv == {A: 1, B: 1}, "the sanitized form is recorded as B's edit"


def test_local_only_change_that_touches_updated_at_is_not_an_edit(tmp_path: Path, lease: FakeLease) -> None:
    """Moving an item into a collection bumps its updated_at; that alone must not sync."""
    a = _vault(tmp_path, "a")
    item_id = a.item_service.create_note("Note", "body")
    first = local_view(a, lease, device_id=A, now=NOW)[item_id]
    collection_id = a.collection_service.create("Mine")
    a.item_service.set_metadata(item_id, collection_ids=[collection_id])
    _item(a, item_id)["updated_at"] += 7  # deterministic: the move happened later
    again = local_view(a, lease, device_id=A, now=NOW)[item_id]
    assert again == first, "same vector and same synced content as before the move"
    a.item_service.update_item(item_id, body="real edit")
    edited = local_view(a, lease, device_id=A, now=NOW)[item_id]
    assert edited.vv == {A: 2}
    assert edited.item["updated_at"] == _item(a, item_id)["updated_at"]


def test_newest_edit_keeps_the_original_id(tmp_path: Path, lease: FakeLease) -> None:
    """Probe: B edits at t=1000 and A at t=2000, so the newer A password keeps the original id.

    Six logins, so a content-hash tie-break alone would pick A for all of
    them with probability 1/64 only.
    """
    a, b = _vault(tmp_path, "a"), _vault(tmp_path, "b")
    ids = [a.upsert_web(origin=f"https://site{n}.example", username="me", password="base-pass")
           for n in range(6)]
    for entry_id in ids:
        _entry(a, entry_id)["updated_at"] = 500
    _sync(b, B, a, A, lease)
    for entry_id in ids:
        b.update_entry_fields(entry_id, password="older-b-pass")
        _entry(b, entry_id)["updated_at"] = 1000
        a.update_entry_fields(entry_id, password="newer-a-pass")
        _entry(a, entry_id)["updated_at"] = 2000
    for _ in range(2):
        _sync(b, B, a, A, lease)
        _sync(a, A, b, B, lease)
    for session in (a, b):
        for entry_id in ids:
            assert _entry(session, entry_id)["password"] == "newer-a-pass"
        copies = [e for e in session._payload["entries"] if e["id"] not in ids]
        assert [c["password"] for c in copies] == ["older-b-pass"] * 6
        assert all(c["label"].endswith(CONFLICT_SUFFIX) for c in copies)
    assert local_view(a, lease, device_id=A, now=NOW) == local_view(b, lease, device_id=B, now=NOW)


_GOOD_WEB = {"id": "e-9", "kind": "web", "label": "x", "username": "u", "password": "pw",
             "scope": {"origin": "https://x.example"}, "created_at": 1, "updated_at": 1,
             "policy": {"fill": "click", "require_master_password": False, "save_prompts": True}}
_GOOD_DESKTOP_SCOPE = {"exe_path": "C:/x.exe", "exe_sha256": "B" * 64, "window_title": "X",
                       "control_fingerprint": [{"name": "User"}], "username_selector": None,
                       "password_selector": None, "binding_mode": "strict"}


@pytest.mark.parametrize("changes", [
    {"notes": 12345},
    {"totp": "junk"},
    {"totp": {"secret": "JBSWY3DPEHPK3PXP", "digits": "abc"}},
    {"totp": {"secret": "JBSWY3DPEHPK3PXP", "digits": None}},
    {"totp": {"secret": "JBSWY3DPEHPK3PXP", "digits": True}},
    {"totp": {"secret": "JBSWY3DPEHPK3PXP", "digits": 5}},
    {"totp": {"secret": "JBSWY3DPEHPK3PXP", "period": "30"}},
    {"totp": {"secret": "JBSWY3DPEHPK3PXP", "period": 7}},
    {"totp": {"secret": "JBSWY3DPEHPK3PXP", "algorithm": 1}},
    {"totp": {"secret": 12345}},
    {"totp": {"secret": {"nested": "dict"}}},
    {"totp": {f"k{n}": n for n in range(17)}},
    {"tags": [1, {"x": 1}]},
    {"tags": [f"t{n}" for n in range(21)]},
    {"unknown_blob": "x" * 100_000},
    {"password_history": [{"password": "old", "changed_at": "abc"}]},
    {"password_history": [{"password": "old", "changed_at": 1, "extra": 1}]},
    {"recovery_codes": "code"},
    {"custom_fields": [{"name": "n", "value": "v"}] * 51},
    {"custom_fields": [{"name": "n", "value": [1, 2]}]},
    {"custom_fields": [{"name": "n", "value": "v" * 5000}]},
    {"favorite": "yes"},
    {"updated_at": "soon"},
    {"scope": {"origin": "https://x.example", "urls": "not a list"}},
    {"kind": "desktop", "scope": {k: v for k, v in _GOOD_DESKTOP_SCOPE.items() if k != "exe_sha256"}},
    {"kind": "desktop", "scope": {**_GOOD_DESKTOP_SCOPE, "username_selector": "C:/evil"}},
    {"kind": "desktop", "scope": {**_GOOD_DESKTOP_SCOPE, "binding_mode": "anything"}},
    {"kind": "desktop", "scope": {**_GOOD_DESKTOP_SCOPE, "control_fingerprint": []}},
])
def test_untrusted_entry_content_is_rejected(tmp_path: Path, lease: FakeLease, changes) -> None:
    b = _vault(tmp_path, "b")
    local_view(b, lease, device_id=B, now=NOW)
    record = {**copy.deepcopy(_GOOD_WEB), **changes}
    rank = record["updated_at"] if isinstance(record["updated_at"], int) else 0
    state = ItemState("e-9", {A: 1}, False, None, {"ns": "entry", "schema": 1, "updated_at": rank, "record": record})
    before_file, before_payload = _file(b), copy.deepcopy(b._payload)
    with pytest.raises(BridgeError):
        apply(b, lease, MergeOutcome((state,), (), ()), device_id=B, now=NOW)
    assert _file(b) == before_file and b._payload == before_payload


def test_good_untrusted_entry_is_accepted(tmp_path: Path, lease: FakeLease) -> None:
    b = _vault(tmp_path, "b")
    local_view(b, lease, device_id=B, now=NOW)
    record = {**copy.deepcopy(_GOOD_WEB), "notes": "n", "tags": ["a"], "favorite": True,
              "totp": {"secret": "JBSWY3DPEHPK3PXP", "algorithm": "SHA1", "digits": 6, "period": 30},
              "recovery_codes": ["c1"], "custom_fields": [{"name": "n", "value": "v", "hidden": True}],
              "password_history": [{"password": "old", "changed_at": 5}]}
    state = ItemState("e-9", {A: 1}, False, None, {"ns": "entry", "schema": 1, "updated_at": 1, "record": record})
    apply(b, lease, MergeOutcome((state,), (), ()), device_id=B, now=NOW)
    assert b.password_history("e-9") == [{"password": "old", "changed_at": 5}]


def test_shapes_the_vault_writers_produce_are_accepted(tmp_path: Path, lease: FakeLease) -> None:
    """set_entry_extras stores totp and custom-field dicts as given; scope keeps other keys."""
    a, b = _vault(tmp_path, "a"), _vault(tmp_path, "b")
    entry_id = _desktop(a)
    a.set_entry_extras(entry_id, totp={"secret": "JBSWY3DPEHPK3PXP", "issuer": "Legacy"},
                       custom_fields=[{"name": "PIN", "value": 1234, "type": "number"}])
    _entry(a, entry_id)["scope"]["vendor_hint"] = "kept by the writers"
    _sync(b, B, a, A, lease)
    stored = _entry(b, entry_id)
    assert stored["totp"] == {"secret": "JBSWY3DPEHPK3PXP", "issuer": "Legacy"}
    assert stored["custom_fields"] == [{"name": "PIN", "value": 1234, "type": "number"}]
    assert stored["scope"]["vendor_hint"] == "kept by the writers"
    assert local_view(b, lease, device_id=B, now=NOW) == local_view(a, lease, device_id=A, now=NOW)


def _make_unreadable(session, entry_id: str) -> None:
    # Six history rows: more than the vault's writers keep (a hand-edited vault).
    _entry(session, entry_id)["password_history"] = [{"password": "p", "changed_at": 1}] * 6


def test_unreadable_local_record_is_skipped_not_tombstoned(tmp_path: Path, lease: FakeLease) -> None:
    a, b = _vault(tmp_path, "a"), _vault(tmp_path, "b")
    bad_id = a.upsert_web(origin="https://bad.example", username="me", password="pw-bad")
    _sync(b, B, a, A, lease)
    meta_before = copy.deepcopy(a._payload["sync_meta"]["items"][bad_id])
    _make_unreadable(a, bad_id)
    new_id = a.upsert_web(origin="https://new.example", username="me", password="pw-new")
    view_a = local_view(a, lease, device_id=A, now=NOW)
    assert bad_id not in view_a and new_id in view_a
    assert set(view_a.skipped) == {bad_id} and "history" in view_a.skipped[bad_id].lower()
    assert a._payload["sync_meta"]["items"][bad_id] == meta_before, "meta of a skipped record is untouched"
    _sync(b, B, a, A, lease)
    assert _entry(b, new_id)["password"] == "pw-new", "other records still sync"
    assert _entry(b, bad_id)["password"] == "pw-bad", "the skipped record is not deleted elsewhere"
    assert not local_view(b, lease, device_id=B, now=NOW)[bad_id].deleted


def test_local_record_with_mistyped_totp_is_skipped(tmp_path: Path, lease: FakeLease) -> None:
    a = _vault(tmp_path, "a")
    bad_id = a.upsert_web(origin="https://bad.example", username="me", password="pw-bad")
    good_id = a.upsert_web(origin="https://good.example", username="me", password="pw-good")
    a.set_entry_extras(bad_id, totp={"secret": "JBSWY3DPEHPK3PXP", "digits": "abc"})
    view = local_view(a, lease, device_id=A, now=NOW)
    assert set(view.skipped) == {bad_id} and "digits" in view.skipped[bad_id]
    assert good_id in view and bad_id not in view


def test_bad_origin_in_a_local_record_is_a_bridge_error_so_local_view_skips_it(
        tmp_path: Path, lease: FakeLease) -> None:
    # The vault refuses to save a plain-HTTP login, so the skip path is driven through the
    # bridge's view of a record held in memory: OriginError must become the usual BridgeError.
    a = _vault(tmp_path, "a")
    good_id = a.upsert_web(origin="https://good.example", username="me", password="pw-good")
    bad = copy.deepcopy(_entry(a, good_id))
    bad["scope"] = {"origin": "http://example.com"}
    with pytest.raises(BridgeError, match="malformed"):
        _wrapper("entry", bad)
    assert good_id in local_view(a, lease, device_id=A, now=NOW)


def test_unreadable_local_record_is_not_overwritten(tmp_path: Path, lease: FakeLease) -> None:
    a, b = _vault(tmp_path, "a"), _vault(tmp_path, "b")
    bad_id = a.upsert_web(origin="https://bad.example", username="me", password="pw-bad")
    _sync(b, B, a, A, lease)
    _make_unreadable(a, bad_id)
    b.update_entry_fields(bad_id, password="pw-from-b")
    other_id = b.upsert_web(origin="https://other.example", username="me", password="pw-other")
    report = _sync(a, A, b, B, lease)
    assert [item_id for item_id, _reason in report.skipped] == [bad_id]
    assert _entry(a, bad_id)["password"] == "pw-bad", "a skipped local record is never overwritten"
    assert len(_entry(a, bad_id)["password_history"]) == 6
    assert _entry(a, other_id)["password"] == "pw-other", "the rest of the outcome is applied"
    # a remote delete of the skipped record is dropped as well
    b.delete(bad_id)
    report = _sync(a, A, b, B, lease)
    assert report.skipped and report.skipped[0][0] == bad_id
    assert any(e["id"] == bad_id for e in a._payload["entries"])


def test_only_skipped_ids_in_outcome_do_not_write(tmp_path: Path, lease: FakeLease) -> None:
    a, b = _vault(tmp_path, "a"), _vault(tmp_path, "b")
    bad_id = a.upsert_web(origin="https://bad.example", username="me", password="pw-bad")
    _sync(b, B, a, A, lease)
    _make_unreadable(a, bad_id)
    local_view(a, lease, device_id=A, now=NOW)
    b.update_entry_fields(bad_id, password="pw-from-b")
    before = _file(a)
    report = _sync(a, A, b, B, lease)
    assert report.applied == 0 and len(report.skipped) == 1
    assert _file(a) == before


def test_identical_remote_content_after_local_only_change_is_not_rewritten(
        tmp_path: Path, lease: FakeLease) -> None:
    a, b = _vault(tmp_path, "a"), _vault(tmp_path, "b")
    item_id = a.item_service.create_note("Note", "body")
    _sync(b, B, a, A, lease)
    collection_id = b.collection_service.create("Mine")
    b.item_service.set_metadata(item_id, collection_ids=[collection_id])
    _item(b, item_id)["updated_at"] += 7  # the local-only move happened later
    published = local_view(b, lease, device_id=B, now=NOW)[item_id]
    local_record = copy.deepcopy(_item(b, item_id))
    remote = ItemState(item_id, bump(published.vv, A), False, None, copy.deepcopy(published.item))
    report = apply(b, lease, MergeOutcome((remote,), (), ()), device_id=B, now=NOW)
    assert report.applied == 0
    assert _item(b, item_id) == local_record, "identical synced content must not rewrite the record"
    assert local_view(b, lease, device_id=B, now=NOW)[item_id].vv == remote.vv


def test_legacy_password_history_is_canonical_in_the_view(tmp_path: Path, lease: FakeLease) -> None:
    a = _vault(tmp_path, "a")
    entry_id = a.upsert_web(origin="https://example.com", username="me", password="pw-123456")
    _entry(a, entry_id)["password_history"] = [{"password": "old", "replaced_at": 7}]
    view = local_view(a, lease, device_id=A, now=NOW)
    assert view[entry_id].item["record"]["password_history"] == [{"password": "old", "changed_at": 7}]


def test_collision_with_trashed_record_of_other_kind_raises(tmp_path: Path, lease: FakeLease) -> None:
    b = _vault(tmp_path, "b")
    entry_id = b.upsert_web(origin="https://example.com", username="me", password="pw-123456")
    b.delete(entry_id)
    local_view(b, lease, device_id=B, now=NOW)
    note = {"id": entry_id, "kind": "note", "title": "T", "created_at": 1, "updated_at": 1,
            "favorite": False, "tags": [], "payload": {"body": "", "fields": [], "template_id": None}}
    state = ItemState(entry_id, {A: 1}, False, None, {"ns": "item", "schema": 1, "updated_at": 1, "record": note})
    with pytest.raises(BridgeError):
        apply(b, lease, MergeOutcome((state,), (), ()), device_id=B, now=NOW)
    assert entry_id in _trash_ids(b)


def test_remote_tombstone_time_is_capped_and_stale_ones_ignored(tmp_path: Path, lease: FakeLease) -> None:
    a, b = _vault(tmp_path, "a"), _vault(tmp_path, "b")
    keep_id = a.item_service.create_note("Keep", "body")
    drop_id = a.item_service.create_note("Drop", "body")
    _sync(b, B, a, A, lease)
    view_b = local_view(b, lease, device_id=B, now=NOW)
    future = ItemState(drop_id, {A: 2}, True, NOW + 10**6, None)
    stale = ItemState(keep_id, {A: 2}, True, NOW - 400 * 86400, None)
    report = apply(b, lease, merge(view_b, [future, stale]), device_id=B, now=NOW)
    assert report.deleted == 1
    meta = b._payload["sync_meta"]["items"]
    assert meta[drop_id]["deleted_at"] == NOW
    assert any(i["id"] == keep_id for i in b._payload["items"]), "a stale tombstone must not delete"
    assert meta[keep_id]["deleted"] is False
    before = _file(b)
    view_b = local_view(b, lease, device_id=B, now=NOW)
    assert apply(b, lease, merge(view_b, [stale]), device_id=B, now=NOW) == ApplyReport(0, 0, 0)
    assert _file(b) == before


def test_full_trash_reports_trash_full(tmp_path: Path, lease: FakeLease) -> None:
    from localvault.item_schema import MAX_ITEMS

    a, b = _vault(tmp_path, "a"), _vault(tmp_path, "b")
    item_id = a.item_service.create_note("Note", "body")
    _sync(b, B, a, A, lease)
    a.item_service.delete_item(item_id)
    view_a = local_view(a, lease, device_id=A, now=NOW)
    outcome = merge(local_view(b, lease, device_id=B, now=NOW), view_a.values())
    b._payload["trash"] = [{"entry": {"id": f"t{n}", "kind": "note"}, "deleted_at": NOW}
                           for n in range(MAX_ITEMS)]  # in memory only
    before = _file(b)
    with pytest.raises(BridgeError) as info:
        apply(b, lease, outcome, device_id=B, now=NOW)
    assert info.value.reason == "trash-full" and str(info.value).startswith("trash-full")
    assert _file(b) == before


def test_history_quota_reports_history_quota(tmp_path: Path, lease: FakeLease, monkeypatch) -> None:
    from localvault.history import HistoryQuotaError, HistoryService

    a, b = _vault(tmp_path, "a"), _vault(tmp_path, "b")
    item_id = a.item_service.create_note("Note", "body")
    _sync(b, B, a, A, lease)
    a.item_service.update_item(item_id, body="new")

    def full(*_args, **_kwargs):
        raise HistoryQuotaError("Typed history quota would be exceeded")

    monkeypatch.setattr(HistoryService, "record_before_change", full)
    before = _file(b)
    with pytest.raises(BridgeError) as info:
        _sync(b, B, a, A, lease)
    assert info.value.reason == "history-quota"
    assert _file(b) == before and _item(b, item_id)["payload"]["body"] == "body"


def test_local_record_with_invalid_id_is_skipped(tmp_path: Path, lease: FakeLease) -> None:
    a, b = _vault(tmp_path, "a"), _vault(tmp_path, "b")
    bad_id = a.upsert_web(origin="https://bad.example", username="me", password="pw-bad")
    good_id = a.upsert_web(origin="https://good.example", username="me", password="pw-good")
    local_view(a, lease, device_id=A, now=NOW)
    weird = "café id"
    _entry(a, bad_id)["id"] = weird
    view = local_view(a, lease, device_id=A, now=NOW)
    assert view.skipped == {weird: "invalid-id"}
    assert weird not in view and good_id in view
    _sync(b, B, a, A, lease)
    assert _entry(b, good_id)["password"] == "pw-good"
    assert not any(e["id"] == weird for e in b._payload["entries"])
    report = apply(a, lease, merge(local_view(a, lease, device_id=A, now=NOW), []), device_id=A, now=NOW)
    assert isinstance(report, ApplyReport)


# --- wrapper schema -----------------------------------------------------------------------


def _remote_entry_state(item_id: str, schema, *, extra_record=None, vv=None) -> ItemState:
    record = {"id": item_id, "kind": "web", "label": "x", "username": "u", "password": "p",
              "scope": {"origin": "https://x.example"}, **(extra_record or {})}
    wrapper = {"ns": "entry", "schema": schema, "updated_at": 0, "record": record}
    return ItemState(item_id, vv or {A: 1}, False, None, wrapper)


def test_wrapper_carries_schema(tmp_path: Path, lease: FakeLease) -> None:
    a = _vault(tmp_path, "a")
    entry_id = a.upsert_web(origin="https://good.example", username="me", password="pw-123456")
    state = local_view(a, lease, device_id=A, now=NOW)[entry_id]
    assert ITEM_WRAPPER_SCHEMA == 1
    assert state.item == {"ns": "entry", "schema": 1, "updated_at": state.item["updated_at"],
                          "record": state.item["record"]}


def test_newer_schema_is_update_needed_not_bad_remote(tmp_path: Path, lease: FakeLease) -> None:
    from localvault.sync import runner
    from localvault.sync.group import View

    a, b = _vault(tmp_path, "a"), _vault(tmp_path, "b")
    local_id = a.upsert_web(origin="https://shared.example", username="me", password="pw-old-123")
    _sync(b, B, a, A, lease)
    before = copy.deepcopy(_entry(b, local_id))
    state = local_view(a, lease, device_id=A, now=NOW)[local_id]
    newer = ItemState(local_id, bump(state.vv, A), False, None,
                      {**state.item, "schema": 2,
                       "record": {**state.item["record"], "label": "changed", "future_field": 1}})
    fresh = ItemState("e-new", {A: 1}, False, None, _remote_entry_state("e-new", 1).item)
    header = {"format": 1, "group_id": "g", "device_id": A, "epoch": 1, "counter": 1, "written_at": NOW}
    report = runner.run_merge(b, lease, device_id=B, views=[View(header, (newer, fresh))], now=NOW)
    assert [i.kind for i in report.issues] == ["update-needed"]
    assert report.issues[0].detail == f"{A}:{local_id}"
    assert _entry(b, local_id) == before
    assert _entry(b, "e-new")["label"] == "x"


@pytest.mark.parametrize("schema", [None, 0, -1, "1", True, 1.0])
def test_missing_or_bad_schema_is_bad_remote(tmp_path: Path, lease: FakeLease, schema) -> None:
    from localvault.sync import runner
    from localvault.sync.group import View

    b = _vault(tmp_path, "b")
    state = _remote_entry_state("e-1", schema)
    if schema is None:
        del state.item["schema"]
    header = {"format": 1, "group_id": "g", "device_id": A, "epoch": 1, "counter": 1, "written_at": NOW}
    report = runner.run_merge(b, lease, device_id=B, views=[View(header, (state,))], now=NOW)
    assert [i.kind for i in report.issues] == ["bad-peer-record"]
    assert b._payload["entries"] == []


def test_unknown_field_at_known_schema_is_bad_remote(tmp_path: Path, lease: FakeLease) -> None:
    b = _vault(tmp_path, "b")
    local_view(b, lease, device_id=B, now=NOW)
    state = _remote_entry_state("e-1", 1, extra_record={"future_field": 1})
    with pytest.raises(BridgeError) as info:
        apply(b, lease, MergeOutcome((state,), (), ()), device_id=B, now=NOW)
    assert info.value.reason == "bad-remote"
    assert b._payload["entries"] == []


def test_newer_schema_with_extra_wrapper_key_is_update_needed(tmp_path: Path, lease: FakeLease) -> None:
    """The schema is checked before the wrapper key set: a newer schema may add wrapper fields."""
    b = _vault(tmp_path, "b")
    local_view(b, lease, device_id=B, now=NOW)
    state = _remote_entry_state("e-1", 2)
    state.item["extra"] = 1
    with pytest.raises(BridgeError) as info:
        apply(b, lease, MergeOutcome((state,), (), ()), device_id=B, now=NOW)
    assert info.value.reason == "update-needed"


def test_schema_1_with_extra_wrapper_key_and_bool_schema_stay_bad_remote(tmp_path: Path, lease: FakeLease) -> None:
    b = _vault(tmp_path, "b")
    local_view(b, lease, device_id=B, now=NOW)
    for schema in (1, True):
        state = _remote_entry_state("e-1", schema)
        state.item["extra"] = 1
        with pytest.raises(BridgeError) as info:
            apply(b, lease, MergeOutcome((state,), (), ()), device_id=B, now=NOW)
        assert info.value.reason == "bad-remote"


def test_blame_wraps_unexpected_exceptions(tmp_path: Path, lease: FakeLease, monkeypatch) -> None:
    from localvault.sync import runner, vault_bridge
    from localvault.sync.group import View

    b = _vault(tmp_path, "b")
    good = _remote_entry_state("e-good", 1)
    bad = _remote_entry_state("e-bad", 1)
    real = vault_bridge._Applier.store

    def store(self, ns, record):
        if record["id"] == "e-bad":
            raise TypeError("boom")
        return real(self, ns, record)

    monkeypatch.setattr(vault_bridge._Applier, "store", store)
    header = {"format": 1, "group_id": "g", "device_id": A, "epoch": 1, "counter": 1, "written_at": NOW}
    report = runner.run_merge(b, lease, device_id=B, views=[View(header, (good, bad))], now=NOW)
    assert [(i.kind, i.detail) for i in report.issues] == [("bad-peer-record", f"{A}:e-bad")]
    assert [e["id"] for e in b._payload["entries"]] == ["e-good"]


def test_sync_metadata_save_suppresses_rolling_backup(tmp_path: Path) -> None:
    a = _vault(tmp_path, "a")
    assert a._suppress_rolling_backup is False
    with a.sync_metadata_save():
        assert a._suppress_rolling_backup is True
        with a.sync_metadata_save():
            assert a._suppress_rolling_backup is True
        assert a._suppress_rolling_backup is True
    assert a._suppress_rolling_backup is False
    with pytest.raises(RuntimeError):
        with a.sync_metadata_save():
            raise RuntimeError("x")
    assert a._suppress_rolling_backup is False


@pytest.mark.parametrize("exc_type", ["locked", "stale"])
def test_lock_and_lease_errors_propagate_from_run_merge(tmp_path: Path, lease: FakeLease, monkeypatch,
                                                        exc_type: str) -> None:
    from localvault.sync import runner, vault_bridge
    from localvault.sync.group import View

    b = _vault(tmp_path, "b")
    error = VaultLockedError("Vault is locked") if exc_type == "locked" else StaleSession("Vault is locked")

    def store(self, ns, record):
        raise error

    monkeypatch.setattr(vault_bridge._Applier, "store", store)
    header = {"format": 1, "group_id": "g", "device_id": A, "epoch": 1, "counter": 1, "written_at": NOW}
    with pytest.raises(type(error)):
        runner.run_merge(b, lease, device_id=B, views=[View(header, (_remote_entry_state("e-1", 1),))], now=NOW)


# --- licence states ------------------------------------------------------------------------


#: pytest fixture: a generated test licence key in LICENSE_KEYS (never a production key).
signer = test_licensing.signer
make_bundle = test_licensing.make_bundle


def _license_state(bundle: dict, vv=None, *, item_id: str | None = None) -> ItemState:
    sid = item_id or licensing.sync_state_id(bundle["license"]["license_id"])
    return ItemState(sid, vv or {A: 1}, False, None,
                     {"ns": "license", "schema": 1, "updated_at": 0, "record": copy.deepcopy(bundle)})


def _store_copy(session, bundle: dict) -> None:
    licensing.store_in_vault(session, bundle)


def test_local_view_publishes_valid_vault_license(tmp_path: Path, lease: FakeLease, signer) -> None:
    a = _vault(tmp_path, "a")
    bundle = make_bundle(signer)
    _store_copy(a, bundle)
    view = local_view(a, lease, device_id=A, now=NOW)
    sid = licensing.sync_state_id("lic-0001")
    assert set(view) == {sid}
    state = view[sid]
    assert not state.deleted and state.vv == {A: 1}
    assert state.item == {"ns": "license", "schema": 1, "updated_at": 0, "record": bundle}
    again = local_view(a, lease, device_id=A, now=NOW)
    assert again[sid].vv == {A: 1}, "an unchanged licence must not be re-attributed"


def test_revoked_or_invalid_license_not_published(tmp_path: Path, lease: FakeLease, signer,
                                                  monkeypatch) -> None:
    a = _vault(tmp_path, "a")
    _store_copy(a, make_bundle(signer))
    monkeypatch.setattr(licensing, "_cached_revoked_ids", lambda: frozenset({"lic-0001"}))
    assert dict(local_view(a, lease, device_id=A, now=NOW)) == {}

    monkeypatch.setattr(licensing, "_cached_revoked_ids", lambda: frozenset())
    b = _vault(tmp_path, "b")
    tampered = make_bundle(signer, license_id="lic-0002")
    tampered["license"]["name"] = "Mallory"
    b._payload["license"] = tampered
    b._payload["sync_licenses"] = {licensing.sync_state_id("lic-0002"): tampered}
    assert dict(local_view(b, lease, device_id=B, now=NOW)) == {}


def test_received_license_stored_and_republished(tmp_path: Path, lease: FakeLease, signer) -> None:
    a, b = _vault(tmp_path, "a"), _vault(tmp_path, "b")
    bundle = make_bundle(signer)
    _store_copy(a, bundle)
    report = _sync(b, B, a, A, lease)
    sid = licensing.sync_state_id("lic-0001")
    assert b._payload["sync_licenses"] == {sid: bundle}
    assert report.licenses == (bundle,)
    assert "license" not in b._payload, "receiving is not installing"
    view = local_view(b, lease, device_id=B, now=NOW)
    assert view[sid].vv == {A: 1}
    assert view[sid].item["record"] == bundle
    # A third device learns it from b alone.
    c = _vault(tmp_path, "c")
    _sync(c, "device-c", b, B, lease)
    assert c._payload["sync_licenses"] == {sid: bundle}
    # Nothing left to do: a second pass writes nothing.
    before = _file(b)
    second = _sync(b, B, a, A, lease)
    assert second.licenses == ()
    assert _file(b) == before


def test_license_tombstone_and_edit_ignored(tmp_path: Path, lease: FakeLease, signer) -> None:
    b = _vault(tmp_path, "b")
    bundle = make_bundle(signer)
    sid = licensing.sync_state_id("lic-0001")
    local_view(b, lease, device_id=B, now=NOW)
    apply(b, lease, MergeOutcome((_license_state(bundle),), (), ()), device_id=B, now=NOW)
    assert b._payload["sync_licenses"] == {sid: bundle}

    tomb = ItemState(sid, {A: 5}, True, NOW, None)
    view = local_view(b, lease, device_id=B, now=NOW)
    apply(b, lease, merge(view, [tomb]), device_id=B, now=NOW)
    assert b._payload["sync_licenses"] == {sid: bundle}
    after = local_view(b, lease, device_id=B, now=NOW)[sid]
    assert not after.deleted and after.item["record"] == bundle
    assert after.vv[B] >= 1 and after.vv[A] == 5, "the live licence must dominate the tombstone"

    other = make_bundle(signer, name="Someone Else")
    with pytest.raises(BridgeError) as info:
        apply(b, lease, MergeOutcome((_license_state(other, {A: 9}),), (), ()), device_id=B, now=NOW)
    assert info.value.reason == "bad-remote" and info.value.item_id == sid
    assert b._payload["sync_licenses"] == {sid: bundle}


def test_invalid_license_state_is_bad_remote(tmp_path: Path, lease: FakeLease, signer) -> None:
    from localvault.sync import runner
    from localvault.sync.group import View

    b = _vault(tmp_path, "b")
    bad = make_bundle(signer)
    bad["license"]["name"] = "Mallory"
    wrong_id = make_bundle(signer, license_id="lic-0002")
    header = {"format": 1, "group_id": "g", "device_id": A, "epoch": 1, "counter": 1, "written_at": NOW}
    states = (_license_state(bad), _license_state(wrong_id, item_id=licensing.sync_state_id("lic-9999")),
              _remote_entry_state("e-1", 1))
    report = runner.run_merge(b, lease, device_id=B, views=[View(header, states)], now=NOW)
    assert sorted((i.kind, i.detail) for i in report.issues) == sorted([
        ("bad-peer-record", f"{A}:{licensing.sync_state_id('lic-0001')}"),
        ("bad-peer-record", f"{A}:{licensing.sync_state_id('lic-9999')}"),
    ])
    assert b._payload.get("sync_licenses", {}) == {}
    assert [e["id"] for e in b._payload["entries"]] == ["e-1"]
    assert report.licenses == ()


def test_license_states_do_not_count_as_items(tmp_path: Path, lease: FakeLease, signer) -> None:
    b = _vault(tmp_path, "b")
    for n in range(4):
        b.item_service.create_note(f"Note {n}", "body")
    b.item_limit = 4
    count = b.live_item_count()
    local_view(b, lease, device_id=B, now=NOW)
    apply(b, lease, MergeOutcome((_license_state(make_bundle(signer)),), (), ()), device_id=B, now=NOW)
    assert b.live_item_count() == count == 4
    assert all(not str(i["id"]).startswith("lic:") for i in b._payload["items"] + b._payload["entries"])


def test_revoked_received_license_is_not_stored_and_writes_nothing(tmp_path: Path, lease: FakeLease, signer,
                                                                  monkeypatch) -> None:
    b = _vault(tmp_path, "b")
    monkeypatch.setattr(licensing, "_cached_revoked_ids", lambda: frozenset({"lic-0001"}))
    view = local_view(b, lease, device_id=B, now=NOW)
    before = _file(b)
    report = apply(b, lease, merge(view, [_license_state(make_bundle(signer))]), device_id=B, now=NOW)
    assert report.licenses == ()
    assert "sync_licenses" not in b._payload
    assert _file(b) == before


def test_revoked_received_license_beside_other_records_is_not_stored(tmp_path: Path, lease: FakeLease, signer,
                                                                     monkeypatch) -> None:
    b = _vault(tmp_path, "b")
    monkeypatch.setattr(licensing, "_cached_revoked_ids", lambda: frozenset({"lic-0001"}))
    view = local_view(b, lease, device_id=B, now=NOW)
    states = [_license_state(make_bundle(signer)), _remote_entry_state("e-1", 1)]
    report = apply(b, lease, merge(view, states), device_id=B, now=NOW)
    assert report.licenses == ()
    assert "sync_licenses" not in b._payload
    assert licensing.sync_state_id("lic-0001") not in b._payload["sync_meta"]["items"]
    assert [e["id"] for e in b._payload["entries"]] == ["e-1"]


def test_unknown_key_or_newer_format_license_is_update_needed(tmp_path: Path, lease: FakeLease, signer) -> None:
    from localvault.sync import runner
    from localvault.sync.group import View

    b = _vault(tmp_path, "b")
    unknown = make_bundle(signer, license_id="lic-0002")
    unknown["signature"]["key_id"] = "0" * 16
    newer = make_bundle(signer, license_id="lic-0003", format=2)
    header = {"format": 1, "group_id": "g", "device_id": A, "epoch": 1, "counter": 1, "written_at": NOW}
    states = (_license_state(unknown), _license_state(newer), _remote_entry_state("e-1", 1))
    report = runner.run_merge(b, lease, device_id=B, views=[View(header, states)], now=NOW)
    assert sorted((i.kind, i.detail) for i in report.issues) == sorted([
        ("update-needed", f"{A}:{licensing.sync_state_id('lic-0002')}"),
        ("update-needed", f"{A}:{licensing.sync_state_id('lic-0003')}"),
    ])
    assert "sync_licenses" not in b._payload
    assert [e["id"] for e in b._payload["entries"]] == ["e-1"]


def test_license_conflict_copy_is_dropped_silently(tmp_path: Path, lease: FakeLease, signer) -> None:
    from localvault.sync.engine import conflict_copy_id

    b = _vault(tmp_path, "b")
    view = local_view(b, lease, device_id=B, now=NOW)
    reissue = _license_state(make_bundle(signer, name="Reissued"))
    cid = conflict_copy_id(reissue.item_id, "0" * 64)
    copy_state = ItemState(cid, {A: 1}, False, None, {**reissue.item, "id": cid})
    before = _file(b)
    report = apply(b, lease, MergeOutcome((), (), (), (copy_state,)), device_id=B, now=NOW)
    assert report.licenses == ()
    assert "sync_licenses" not in b._payload
    assert _file(b) == before
    assert dict(view) == {}


def test_no_license_is_published_while_a_removal_is_pending(tmp_path: Path, lease: FakeLease, signer,
                                                           monkeypatch) -> None:
    from localvault.sync.vault_bridge import published_licenses

    a = _vault(tmp_path, "a")
    received = make_bundle(signer, license_id="lic-0002")
    a._payload["sync_licenses"] = {licensing.sync_state_id("lic-0002"): received}
    assert published_licenses(a) == (received,)
    monkeypatch.setattr(licensing, "removal_pending", lambda: True)
    assert published_licenses(a) == ()
    view = local_view(a, lease, device_id=A, now=NOW)
    assert not any(item_id.startswith("lic:") for item_id in view)


def test_vault_copy_wins_over_received_license_at_publish(tmp_path: Path, lease: FakeLease, signer) -> None:
    a = _vault(tmp_path, "a")
    mine = make_bundle(signer)
    other = make_bundle(signer, name="Reissued")
    sid = licensing.sync_state_id("lic-0001")
    a._payload["sync_licenses"] = {sid: other}
    _store_copy(a, mine)
    assert local_view(a, lease, device_id=A, now=NOW)[sid].item["record"] == mine


def test_check_remote_state_predicts_what_apply_refuses(tmp_path: Path, lease: FakeLease, monkeypatch) -> None:
    from localvault.sync.vault_bridge import check_remote_state

    a = _vault(tmp_path, "a")
    note_id = a.item_service.create_note("Note", "body")
    good = local_view(a, lease, device_id=A, now=NOW)[note_id]
    assert check_remote_state(good) is None
    assert check_remote_state(ItemState("gone-1", {A: 1}, True, NOW, None)) is None
    # the engine form of a conflict copy: a top-level id, record.id still the original
    engine_copy = ItemState("copy-1", good.vv, False, None, {**good.item, "id": "copy-1"})
    assert check_remote_state(engine_copy) == "bad-remote"
    newer = ItemState(note_id, good.vv, False, None, {**good.item, "schema": 2})
    assert check_remote_state(newer) == "update-needed"
    broken = copy.deepcopy(good.item)
    broken["record"]["kind"] = "no-such-kind"
    assert check_remote_state(ItemState(note_id, good.vv, False, None, broken)) == "bad-remote"
    # apply refuses exactly those with the same reason
    for state in (engine_copy, newer, ItemState(note_id, good.vv, False, None, broken)):
        b = _vault(tmp_path, f"b-{len(list(tmp_path.iterdir()))}")
        local_view(b, lease, device_id=B, now=NOW)
        with pytest.raises(BridgeError) as err:
            apply(b, lease, MergeOutcome((state,), (), ()), device_id=B, now=NOW)
        assert err.value.reason == check_remote_state(state)
    # a licence state with no licence keys in the build is dropped quietly: nothing to report
    monkeypatch.setattr(licensing, "LICENSE_KEYS", {})
    lic = ItemState("lic:x", {A: 1}, False, None, {"ns": "license", "schema": 1, "updated_at": 0, "record": {}})
    assert check_remote_state(lic) is None


@pytest.mark.parametrize("junk", ["site_icon", "embedded_web_fill_approved"])
def test_remote_entry_with_junk_local_only_field_is_cleaned_not_refused(tmp_path: Path, lease: FakeLease,
                                                                        junk: str) -> None:
    b = _vault(tmp_path, "b")
    local_view(b, lease, device_id=B, now=NOW)
    record = {"id": "d-2", "kind": "desktop", "label": "App", "username": "u", "password": "p",
              "created_at": 1, "updated_at": 1,
              "policy": {"fill": "click", "require_master_password": False, "save_prompts": True},
              "scope": {"exe_path": "C:/x.exe", "exe_sha256": "B" * 64, "window_title": "X",
                        "control_fingerprint": [{"name": "User"}], "username_selector": None,
                        "password_selector": None, "binding_mode": "strict"}}
    if junk == "site_icon":
        record["site_icon"] = 123
    else:
        record["scope"]["embedded_web_fill_approved"] = "yes"
    state = ItemState("d-2", {A: 1}, False, None, {"ns": "entry", "schema": 1, "updated_at": 1, "record": record})
    assert check_remote_state(state) is None
    apply(b, lease, MergeOutcome((state,), (), ()), device_id=B, now=NOW)
    stored = _entry(b, "d-2")
    assert stored["label"] == "App"
    assert stored["scope"]["embedded_web_fill_approved"] is False
    assert "site_icon" not in stored


@pytest.mark.parametrize("junk", ["collection_ids", "revision", "document_ids"])
def test_remote_item_with_junk_local_only_field_is_cleaned_not_refused(tmp_path: Path, lease: FakeLease,
                                                                       junk: str) -> None:
    a = _vault(tmp_path, "a")
    item_id = a.item_service.create_note("Note", "body")
    record = copy.deepcopy(_item(a, item_id))
    if junk == "collection_ids":
        record["collection_ids"] = ["not-a-collection-here"]
    elif junk == "revision":
        record["revision"] = "x"
    else:
        record["payload"]["document_ids"] = "junk"
    b = _vault(tmp_path, "b")
    local_view(b, lease, device_id=B, now=NOW)
    state = ItemState(item_id, {A: 1}, False, None,
                      {"ns": "item", "schema": 1, "updated_at": record["updated_at"], "record": record})
    assert check_remote_state(state) is None
    apply(b, lease, MergeOutcome((state,), (), ()), device_id=B, now=NOW)
    stored = _item(b, item_id)
    assert stored["title"] == "Note"
    assert stored["collection_ids"] == []
