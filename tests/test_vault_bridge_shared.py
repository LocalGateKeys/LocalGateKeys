"""Shared collections in the vault bridge (sub-plan 07 Task 2): the namespace filter.

A share group's view holds only the items tagged with its collection; incoming items land only in
that collection; a read-only member's local changes never leave the device.
"""
from __future__ import annotations

import json
import time

import pytest

from localvault import licensing
from localvault.attachments import AttachmentStore
from localvault.collections import CollectionService
from localvault.item_schema import new_item
from localvault.item_service import ItemService, ReadOnlyCollection
from localvault.sync import removal
from localvault.sync import share_group as sg
from localvault.sync.engine import ItemState, MergeOutcome, merge
from localvault.sync.pairing import DeviceIdentity
from localvault.sync.vault_bridge import CONFLICT_SUFFIX, BridgeError, apply, local_view
from localvault.vault import create_vault

TEST_KDF = {"time_cost": 1, "memory_cost_kib": 8192, "parallelism": 1, "hash_len": 32}
CHEAP = (1024, 1, 1)
MASTER = "synthetic master"
PW = "correct horse battery staple 7!"
PW2 = "another very long passphrase 42?"
NOW = int(time.time())


class FakeLease:
    def check(self) -> None:
        pass


LEASE = FakeLease()


@pytest.fixture(autouse=True)
def pro(monkeypatch):
    monkeypatch.setattr(licensing, "item_limit", lambda st=None: None)


def vault(tmp_path, name):
    return create_vault(tmp_path / f"{name}.json", MASTER, kdf_overrides=TEST_KDF)


class Pair:
    """An owner and a member of one share group, each with its own vault."""

    def __init__(self, tmp_path, mode="edit"):
        self.owner = vault(tmp_path, "owner")
        self.cid = CollectionService(self.owner).create("Family")
        group = sg.create_share_group(self.owner, self.cid, password=PW, device="Owner PC", shared_mode=mode,
                                      _kdf_override=CHEAP)
        self.gid = group.group_id
        self.member = vault(tmp_path, "member")
        sg.join_share_group(self.member, sg.share_keyring(self.owner, self.gid), password=PW, device="Member PC",
                            _kdf_override=CHEAP)
        self.owner_dev = sg.share_state(self.owner, self.gid).device_id
        self.member_dev = sg.share_state(self.member, self.gid).device_id

    def dev(self, session):
        return self.owner_dev if session is self.owner else self.member_dev

    def view(self, session):
        return local_view(session, LEASE, device_id=self.dev(session), now=NOW, collection_id=self.cid)

    def pull(self, dst, src):
        """*dst* merges *src*'s share view (what one transport run does for one peer)."""
        theirs = self.view(src)
        mine = self.view(dst)
        return apply(dst, LEASE, merge(mine, theirs.values()), device_id=self.dev(dst), now=NOW,
                     collection_id=self.cid)


def items(session):
    return {i["id"]: i for i in session._payload.get("items", [])}


def trash_ids(session):
    return {r["entry"]["id"] for r in session._payload.get("trash", [])}


def note(session, title, body="body", collections=()):
    return ItemService(session).create_note(title, body, collection_ids=list(collections))


# --- what leaves the device -----------------------------------------------------------------------------

def test_share_view_holds_only_items_of_the_shared_collection(tmp_path):
    p = Pair(tmp_path)
    owner = p.owner
    other = CollectionService(owner).create("Work")
    shared = note(owner, "Shared", "family wifi", [p.cid, other])
    personal = note(owner, "Personal", "my diary")
    work = note(owner, "Work only", "work secret", [other])
    owner.upsert_web(origin="https://bank.example", username="me", password="bank-password-1")
    trashed = note(owner, "Trashed shared", "old", [p.cid])
    ItemService(owner).delete_item(trashed)
    # A document in the shared collection: its file never leaves through a share.
    aid = AttachmentStore(owner).add_bytes("scan.txt", b"passport scan", mime_type="text/plain")
    doc = ItemService(owner)._append(new_item("document", "Scan", {"attachment_id": aid, "description": ""},
                                              collection_ids=[p.cid]))
    linked = ItemService(owner).create_purchase("Linked", document_ids=[doc], collection_ids=[p.cid])

    view = p.view(owner)
    assert set(view) == {shared, linked}
    rec = view[shared].item["record"]
    assert rec["collection_ids"] == [p.cid], "only the shared collection's id is published"
    assert "revision" not in rec
    assert "document_ids" not in view[linked].item["record"]["payload"]
    blob = json.dumps({k: s.item for k, s in view.items()})
    for secret in ("my diary", "work secret", "bank-password-1", "old", "passport scan", other, personal, work):
        assert secret not in blob
    assert all(not k.startswith("lic:") for k in view)


def test_personal_view_is_unchanged_by_a_share(tmp_path):
    p = Pair(tmp_path)
    shared = note(p.owner, "Shared", collections=[p.cid])
    personal = local_view(p.owner, LEASE, device_id="device-a", now=NOW)
    assert "collection_ids" not in personal[shared].item["record"]
    assert "sync_meta" in p.owner._payload
    # The personal and share bookkeeping are separate.
    p.view(p.owner)
    assert set(p.owner._payload["share_sync_meta"]) == {p.cid}
    assert p.owner._payload["sync_meta"]["device_id"] == "device-a"


def test_view_needs_a_shared_collection(tmp_path):
    p = Pair(tmp_path)
    plain = CollectionService(p.owner).create("Plain")
    with pytest.raises(BridgeError) as err:
        local_view(p.owner, LEASE, device_id=p.owner_dev, now=NOW, collection_id=plain)
    assert err.value.reason == "not-shared"


# --- what arrives ---------------------------------------------------------------------------------------

def test_member_receives_only_the_shared_item_tagged_with_the_collection(tmp_path):
    p = Pair(tmp_path)
    a = note(p.owner, "A", "shared text", [p.cid])
    note(p.owner, "Personal", "my diary")
    personal_member = note(p.member, "Member own", "member diary")
    report = p.pull(p.member, p.owner)
    assert report.applied == 1
    got = items(p.member)
    assert set(got) == {a, personal_member}
    assert got[a]["collection_ids"] == [p.cid] and got[a]["payload"]["body"] == "shared text"
    # Nothing of the member's own vault went the other way.
    p.pull(p.owner, p.member)
    assert personal_member not in items(p.owner)


def test_member_edit_reaches_the_owner_in_edit_mode(tmp_path):
    p = Pair(tmp_path, "edit")
    other = CollectionService(p.owner).create("Home")
    a = note(p.owner, "A", "v1", [p.cid, other])
    p.pull(p.member, p.owner)
    ItemService(p.member).update_item(a, body="v2 by member")
    p.pull(p.owner, p.member)
    rec = items(p.owner)[a]
    assert rec["payload"]["body"] == "v2 by member"
    assert sorted(rec["collection_ids"]) == sorted([p.cid, other]), "the owner keeps its own collections"


def test_both_edit_offline_and_both_versions_survive(tmp_path):
    p = Pair(tmp_path, "edit")
    a = note(p.owner, "A", "v1", [p.cid])
    p.pull(p.member, p.owner)
    ItemService(p.owner).update_item(a, body="owner offline")
    ItemService(p.member).update_item(a, body="member offline")
    p.pull(p.owner, p.member)
    p.pull(p.member, p.owner)
    p.pull(p.owner, p.member)
    for session in (p.owner, p.member):
        live = [i for i in items(session).values() if i["kind"] == "note"]
        bodies = sorted(i["payload"]["body"] for i in live)
        assert bodies == ["member offline", "owner offline"]
        copy_rec = next(i for i in live if i["id"] != a)
        assert copy_rec["title"].endswith(CONFLICT_SUFFIX)
        assert all(p.cid in i["collection_ids"] for i in live), "the conflict copy stays in the share"
    assert {i["payload"]["body"] for i in items(p.owner).values()} == {
        i["payload"]["body"] for i in items(p.member).values()}


def test_owner_untags_an_item_member_loses_it_owner_keeps_it(tmp_path):
    p = Pair(tmp_path)
    a = note(p.owner, "A", "was shared", [p.cid])
    p.pull(p.member, p.owner)
    assert a in items(p.member)
    ItemService(p.owner).set_metadata(a, collection_ids=[])
    report = p.pull(p.member, p.owner)
    assert report.deleted == 1
    assert a not in items(p.member) and a in trash_ids(p.member)
    assert a in items(p.owner) and a not in trash_ids(p.owner)
    # Tagging it again shares it again (restored from the member's trash).
    ItemService(p.owner).set_metadata(a, collection_ids=[p.cid])
    p.pull(p.member, p.owner)
    assert a in items(p.member)


def test_owner_trashing_a_trashed_shared_item_never_exports_its_content(tmp_path):
    p = Pair(tmp_path)
    a = note(p.owner, "A", "text", [p.cid])
    p.pull(p.member, p.owner)
    ItemService(p.owner).delete_item(a)
    view = p.view(p.owner)
    assert view[a].deleted and view[a].item is None
    p.pull(p.member, p.owner)
    assert a in trash_ids(p.member)


# --- an incoming item cannot reach outside the collection -----------------------------------------------

def forged(p, record, *, vv=None, item_id=None):
    item_id = item_id or record["id"]
    wrapper = {"ns": "item", "schema": 1, "updated_at": record.get("updated_at", 0), "record": record}
    return ItemState(item_id, vv or {p.owner_dev: 99}, False, None, wrapper)


def apply_states(p, session, upserts=(), deletes=()):
    return apply(session, LEASE, MergeOutcome(tuple(upserts), tuple(deletes), (), ()), device_id=p.dev(session),
                 now=NOW, collection_id=p.cid)


def shared_record(p, title="X", body="b", cids=None):
    rec = new_item("note", title, {"body": body, "fields": []}, collection_ids=cids if cids is not None else [p.cid])
    rec.pop("revision", None)
    return rec


def test_incoming_item_claiming_another_collection_is_refused(tmp_path):
    p = Pair(tmp_path)
    work = CollectionService(p.member).create("Work")
    for cids in ([work], [p.cid, work], []):
        with pytest.raises(BridgeError) as err:
            apply_states(p, p.member, [forged(p, shared_record(p, cids=cids))])
        assert err.value.reason == "bad-remote"
    assert not items(p.member)


def test_incoming_item_cannot_overwrite_or_delete_a_personal_item(tmp_path):
    p = Pair(tmp_path)
    personal = note(p.member, "Mine", "member diary")
    trashed = note(p.member, "Trashed mine", "old diary")
    ItemService(p.member).delete_item(trashed)
    for target in (personal, trashed):
        rec = shared_record(p, body="overwritten")
        rec["id"] = target
        with pytest.raises(BridgeError) as err:
            apply_states(p, p.member, [forged(p, rec)])
        assert err.value.reason == "bad-remote"
    tomb = ItemState(personal, {p.owner_dev: 99}, True, NOW, None)
    report = apply_states(p, p.member, deletes=[tomb])
    assert report.deleted == 0
    assert items(p.member)[personal]["payload"]["body"] == "member diary"
    assert trashed in trash_ids(p.member)
    # A tombstone for a personal item never turns it into a shared one later either.
    assert p.view(p.member)[personal].deleted


def test_incoming_login_licence_or_document_is_refused(tmp_path):
    p = Pair(tmp_path)
    login = {"id": "11111111-1111-4111-8111-111111111111", "kind": "web", "label": "Bank", "username": "u",
             "password": "p", "scope": {"origin": "https://bank.example"}, "created_at": 1, "updated_at": 1}
    entry = ItemState(login["id"], {p.owner_dev: 1}, False, None,
                      {"ns": "entry", "schema": 1, "updated_at": 1, "record": login})
    doc = new_item("document", "Doc", {"attachment_id": "22222222-2222-4222-8222-222222222222",
                                       "description": ""}, collection_ids=[p.cid])
    doc.pop("revision")
    for state in (entry, forged(p, doc)):
        with pytest.raises(BridgeError) as err:
            apply_states(p, p.member, [state])
        assert err.value.reason == "bad-remote"
    lic = ItemState("lic:" + "0" * 64, {p.owner_dev: 1}, False, None,
                    {"ns": "license", "schema": 1, "updated_at": 0, "record": {"x": 1}})
    with pytest.raises(BridgeError) as err:
        apply_states(p, p.member, [lic])
    assert err.value.reason in ("bad-remote", "update-needed")
    assert not p.member._payload.get("entries") and not items(p.member)
    assert not p.member._payload.get("sync_licenses")


# --- read-only shares -----------------------------------------------------------------------------------

def test_read_only_member_cannot_edit_shared_items(tmp_path):
    p = Pair(tmp_path, "read")
    a = note(p.owner, "A", "owner text", [p.cid])
    p.pull(p.member, p.owner)
    service = ItemService(p.member)
    assert p.member.read_only_collection_ids == frozenset({p.cid})
    assert p.owner.read_only_collection_ids == frozenset()
    with pytest.raises(ReadOnlyCollection):
        service.update_item(a, body="member edit")
    with pytest.raises(ReadOnlyCollection):
        service.set_metadata(a, collection_ids=[])
    with pytest.raises(ReadOnlyCollection):
        service.delete_item(a)
    with pytest.raises(ReadOnlyCollection):
        note(p.member, "New", collections=[p.cid])
    mine = note(p.member, "Mine")
    with pytest.raises(ReadOnlyCollection):
        service.set_metadata(mine, collection_ids=[p.cid])
    assert items(p.member)[a]["payload"]["body"] == "owner text"
    # The member's own items stay editable; the owner edits freely and the edit flows.
    assert service.update_item(mine, body="still mine")
    ItemService(p.owner).update_item(a, body="owner v2")
    p.pull(p.member, p.owner)
    assert items(p.member)[a]["payload"]["body"] == "owner v2"
    ItemService(p.owner).delete_item(a)
    p.pull(p.member, p.owner)
    assert a in trash_ids(p.member)


def test_read_only_member_never_exports_a_local_change_and_the_owner_version_returns(tmp_path):
    p = Pair(tmp_path, "read")
    a = note(p.owner, "A", "owner text", [p.cid])
    b = note(p.owner, "B", "owner b", [p.cid])
    p.pull(p.member, p.owner)
    before = p.view(p.member)
    # Changes that bypass the item service (a bug, a hand-edited vault): edit, delete and untag.
    with p.member.transaction():
        rows = p.member._payload["items"]
        next(i for i in rows if i["id"] == a)["payload"]["body"] = "member tampered"
        next(i for i in rows if i["id"] == b)["collection_ids"] = []
        rows.append(new_item("note", "Sneaky", {"body": "x", "fields": []}, collection_ids=[p.cid]))
    view = p.view(p.member)
    assert set(before) == {a, b} and not view, "a local change of a read-only share is never published"
    assert p.view(p.member) == view
    p.pull(p.owner, p.member)
    assert items(p.owner)[a]["payload"]["body"] == "owner text"
    # The owner's next change wins on the member; until then the owner's version is restored.
    p.pull(p.member, p.owner)
    assert items(p.member)[a]["payload"]["body"] == "owner text"


# --- removal notice (Review Focus 2) and leaving -------------------------------------------------------

def test_removal_notice_trashes_the_shared_items_and_nothing_else(tmp_path):
    p = Pair(tmp_path)
    sg.adopt_keyring(p.owner, p.gid, sg.share_keyring(p.member, p.gid), _kdf_override=CHEAP)
    a = note(p.owner, "A", "shared", [p.cid])
    p.pull(p.member, p.owner)
    personal = note(p.member, "Mine", "diary")
    other = CollectionService(p.member).create("Work")
    work = note(p.member, "Work", "work", [other])
    notice = sg.remove_member(p.owner, p.gid, p.member_dev, new_password=PW2, _kdf_override=CHEAP)
    ring = sg.share_keyring(p.owner, p.gid)
    # The owner's own device never acts on a notice.
    with pytest.raises(removal.RemovalError):
        sg.apply_share_removal(p.owner, p.gid, notice, ring)
    assert a in items(p.owner)
    moved = sg.apply_share_removal(p.member, p.gid, notice, ring)
    assert moved == 1
    assert a in trash_ids(p.member)
    assert set(items(p.member)) == {personal, work}
    assert sg.list_share_groups(p.member) == []
    assert p.cid not in p.member._payload.get("share_sync_meta", {})


def test_removal_notice_signed_by_a_member_is_refused(tmp_path):
    p = Pair(tmp_path)
    a = note(p.owner, "A", "shared", [p.cid])
    p.pull(p.member, p.owner)
    st = sg.share_state(p.member, p.gid)
    other = DeviceIdentity.generate()
    fake = removal.make_notice(other.signing_key, group_id=p.gid, device_id=p.member_dev, epoch=st.epoch + 1,
                               signer=other.device_id, now=NOW)
    with pytest.raises(removal.RemovalError):
        sg.apply_share_removal(p.member, p.gid, fake, sg.share_keyring(p.member, p.gid))
    assert a in items(p.member)


def test_leaving_forgets_the_share_bookkeeping(tmp_path):
    p = Pair(tmp_path)
    a = note(p.owner, "A", "shared", [p.cid])
    p.pull(p.member, p.owner)
    sg.leave_share_group(p.member, p.gid)
    assert p.cid not in p.member._payload.get("share_sync_meta", {})
    assert a in items(p.member)
    assert p.member.read_only_collection_ids == frozenset()


# --- fix round 1 -------------------------------------------------------------------------------------

def test_an_item_tagged_and_untagged_before_any_share_run_never_yields_a_tombstone(tmp_path):
    p = Pair(tmp_path)
    a = note(p.owner, "A", "briefly shared", [p.cid])
    ItemService(p.owner).set_metadata(a, collection_ids=[])
    assert not p.view(p.owner)
    assert a not in p.owner._payload["share_sync_meta"][p.cid]["items"]


def test_tags_and_favourites_stay_personal(tmp_path):
    p = Pair(tmp_path)
    service = ItemService(p.owner)
    a = service.create_note("A", "v1", tags=["owner-private-tag"], collection_ids=[p.cid], favorite=True)
    record = p.view(p.owner)[a].item["record"]
    assert "tags" not in record and "favorite" not in record
    p.pull(p.member, p.owner)
    got = items(p.member)[a]
    assert got["tags"] == [] and got["favorite"] is False
    ItemService(p.member).set_metadata(a, tags=["member-tag"], favorite=True)
    assert not p.pull(p.owner, p.member).applied, "a tag or favourite change is not an edit of the share"
    service.update_item(a, body="v2")
    p.pull(p.member, p.owner)
    got = items(p.member)[a]
    assert got["payload"]["body"] == "v2" and got["tags"] == ["member-tag"] and got["favorite"] is True
    assert items(p.owner)[a]["tags"] == ["owner-private-tag"]


def test_owner_untag_while_a_member_edits_is_skipped_quietly_on_the_owner(tmp_path):
    # Not a bad peer record: the owner skips the member's edit on every run, keeps publishing the
    # tombstone, and the untagged item never returns to the share.
    p = Pair(tmp_path)
    a = note(p.owner, "A", "v1", [p.cid])
    p.pull(p.member, p.owner)
    ItemService(p.owner).set_metadata(a, collection_ids=[])
    p.view(p.owner)
    ItemService(p.member).update_item(a, body="member edit")
    for _ in range(2):
        report = p.pull(p.owner, p.member)
        assert report.applied == 0
        assert items(p.owner)[a]["payload"]["body"] == "v1" and items(p.owner)[a]["collection_ids"] == []
        assert p.view(p.owner)[a].deleted, "the owner keeps publishing the tombstone"


def _removal(p):
    sg.adopt_keyring(p.owner, p.gid, sg.share_keyring(p.member, p.gid), _kdf_override=CHEAP)
    notice = sg.remove_member(p.owner, p.gid, p.member_dev, new_password=PW2, _kdf_override=CHEAP)
    return notice, sg.share_keyring(p.owner, p.gid)


def test_removal_keeps_a_shared_document_that_a_personal_item_links(tmp_path):
    p = Pair(tmp_path)
    m = p.member
    aid = AttachmentStore(m).add_bytes("scan.txt", b"scan", mime_type="text/plain")
    doc = ItemService(m)._append(new_item("document", "Scan", {"attachment_id": aid, "description": ""},
                                          collection_ids=[p.cid]))
    linking_shared = ItemService(m).create_purchase("Shared receipt", document_ids=[doc], collection_ids=[p.cid])
    personal = ItemService(m).create_purchase("My receipt", document_ids=[doc])
    other_doc = ItemService(m)._append(new_item("document", "Other", {"attachment_id": aid, "description": ""},
                                                collection_ids=[p.cid]))
    notice, ring = _removal(p)
    moved = sg.apply_share_removal(m, p.gid, notice, ring)
    assert moved == 2
    assert {linking_shared, other_doc} <= trash_ids(m)
    assert {doc, personal} <= set(items(m))
    assert sg.list_share_groups(m) == []


def test_removal_with_a_full_trash_changes_nothing_and_says_so(tmp_path, monkeypatch):
    import localvault.item_service as item_service_module

    p = Pair(tmp_path)
    a = note(p.owner, "A", "shared", [p.cid])
    p.pull(p.member, p.owner)
    notice, ring = _removal(p)
    with monkeypatch.context() as mp:
        mp.setattr(item_service_module, "MAX_ITEMS", 0)
        with pytest.raises(sg.ShareGroupError) as err:
            sg.apply_share_removal(p.member, p.gid, notice, ring)
    assert err.value.reason == "trash-full"
    assert a in items(p.member) and [g.group_id for g in sg.list_share_groups(p.member)] == [p.gid]
    assert sg.apply_share_removal(p.member, p.gid, notice, ring) == 1


def test_removal_reports_other_item_errors_as_they_are_not_as_a_full_trash(tmp_path, monkeypatch):
    from localvault.item_schema import ItemSchemaError
    from localvault.vault import VaultError

    p = Pair(tmp_path)
    a = note(p.owner, "A", "shared", [p.cid])
    p.pull(p.member, p.owner)
    notice, ring = _removal(p)
    for error in (ItemSchemaError("note body is too long"), VaultError("Document is referenced by a live item")):
        def refuse(self, item_id, _error=error):
            raise _error
        with monkeypatch.context() as mp:
            mp.setattr(ItemService, "delete_item", refuse)
            with pytest.raises(sg.ShareGroupError) as err:
                sg.apply_share_removal(p.member, p.gid, notice, ring)
        assert err.value.reason == "item-error"
        assert a in items(p.member)
    assert sg.apply_share_removal(p.member, p.gid, notice, ring) == 1
