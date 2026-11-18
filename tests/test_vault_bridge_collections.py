"""Personal collections sync between one person's own devices (sub-plan 07 Task 4).

Collections, item membership and share links travel as states of the ``collection`` namespace in
the personal group, only in runs whose peers all read them (``collections=True``).  Item records
stay exactly as v1 peers know them, so an older peer never sees a new field and never loses one.
"""
from __future__ import annotations

import json
import time

import pytest

from localvault import licensing
from localvault.collections import CollectionService, SharedCollection
from localvault.item_service import ItemService, ReadOnlyCollection, sync_writes
from localvault.sync import share_group as sg
from localvault.sync.engine import ItemState
from localvault.sync.group import View
from localvault.sync.runner import run_merge
from localvault.sync.vault_bridge import (
    COLLECTION_NS,
    CONFLICT_SUFFIX,
    LINKS_KEY,
    is_collection_state_id,
    local_view,
)
from localvault.vault import create_vault

TEST_KDF = {"time_cost": 1, "memory_cost_kib": 8192, "parallelism": 1, "hash_len": 32}
CHEAP = (1024, 1, 1)
MASTER = "synthetic master"
PW = "correct horse battery staple 7!"
NOW = int(time.time())


class FakeLease:
    def check(self) -> None:
        pass


LEASE = FakeLease()


@pytest.fixture(autouse=True)
def pro(monkeypatch):
    monkeypatch.setattr(licensing, "item_limit", lambda st=None: None)


class Dev:
    """One device of the person: a vault and its personal-group device id."""

    def __init__(self, tmp_path, name, session=None):
        self.s = session if session is not None else create_vault(tmp_path / f"{name}.json", MASTER,
                                                                   kdf_overrides=TEST_KDF)
        self.id = f"dev-{name}"

    def view(self, collections=True):
        return local_view(self.s, LEASE, device_id=self.id, now=NOW, collections=collections)

    def items(self):
        return {i["id"]: i for i in self.s._payload.get("items", [])}

    def item(self, item_id):
        return self.items()[item_id]

    def collections(self):
        return {r["id"]: r["name"] for r in CollectionService(self.s).list()}

    def membership(self, item_id):
        return sorted(self.item(item_id).get("collection_ids", []))


def pull(dst, src, *, collections=True, src_collections=None):
    """*dst* merges *src*'s personal view (one transport run with one peer)."""
    theirs = src.view(collections if src_collections is None else src_collections)
    states = tuple(theirs[k] for k in sorted(theirs))
    return run_merge(dst.s, LEASE, device_id=dst.id, views=[View({"device_id": src.id}, states)], now=NOW,
                     collections=collections)


def sync(a, b, rounds=2, **kw):
    for _ in range(rounds):
        pull(b, a, **kw)
        pull(a, b, **kw)


def note(dev, title, body="body", collections=()):
    return ItemService(dev.s).create_note(title, body, collection_ids=list(collections))


def copies(dev):
    return [i for i in dev.items().values() if i["title"].endswith(CONFLICT_SUFFIX)]


def col_states(view):
    return {k: s for k, s in view.items() if is_collection_state_id(k)}


# --- between two devices of the new version -------------------------------------------------------------

def test_collections_and_membership_sync_between_new_devices(tmp_path):
    a, b = Dev(tmp_path, "a"), Dev(tmp_path, "b")
    family = CollectionService(a.s).create("Family", description="the house")
    nid = note(a, "Wi-Fi", "hunter2", [family])
    plain = note(a, "Plain")
    report = pull(b, a)
    assert not report.issues
    assert b.collections() == {family: "Family"}
    assert CollectionService(b.s).list()[0]["description"] == "the house"
    assert b.membership(nid) == [family]
    assert b.membership(plain) == []

    # B moves it from Family into a new Work collection; A follows.
    work = CollectionService(b.s).create("Work")
    ItemService(b.s).update_item(nid, collection_ids=[work])
    pull(a, b)
    assert a.collections() == {family: "Family", work: "Work"}
    assert a.membership(nid) == [work]
    # Settled: another round changes nothing on either side.
    before = (dict(a.view()), dict(b.view()))
    sync(a, b)
    assert (dict(a.view()), dict(b.view())) == before


def test_items_without_collections_sync_exactly_as_before(tmp_path):
    a = Dev(tmp_path, "a")
    family = CollectionService(a.s).create("Family")
    tagged = note(a, "Tagged", collections=[family])
    plain = note(a, "Plain")
    old = a.view(collections=False)
    new = a.view(collections=True)
    assert not col_states(old), "no collection state leaves for a peer that does not read them"
    assert {k: s for k, s in new.items() if not is_collection_state_id(k)} == dict(old)
    for item_id in (tagged, plain):
        assert set(old[item_id].item) == {"ns", "schema", "updated_at", "record"}
        assert "collection_ids" not in old[item_id].item["record"], "item records keep the v1 shape"
    assert set(col_states(new)) == {f"col:{family}", f"cm:{tagged}"}
    assert all(s.item["ns"] == COLLECTION_NS for s in col_states(new).values())


def test_two_devices_change_one_membership_at_once_and_both_stay(tmp_path):
    a, b = Dev(tmp_path, "a"), Dev(tmp_path, "b")
    x = CollectionService(a.s).create("X")
    y = CollectionService(a.s).create("Y")
    nid = note(a, "Shared note")
    sync(a, b)
    ItemService(a.s).update_item(nid, collection_ids=[x])
    ItemService(b.s).update_item(nid, collection_ids=[y], title="Renamed on B")
    sync(a, b, rounds=3)
    for dev in (a, b):
        assert dev.membership(nid) == sorted([x, y])
        assert dev.item(nid)["title"] == "Renamed on B"
        assert not copies(dev), "a membership change never makes a conflict copy"


def test_same_name_collections_made_on_two_devices(tmp_path):
    a, b = Dev(tmp_path, "a"), Dev(tmp_path, "b")
    fa = CollectionService(a.s).create("Family")
    fb = CollectionService(b.s).create("family")
    sync(a, b, rounds=3)
    assert a.collections() == b.collections()
    assert set(a.collections()) == {fa, fb}
    low, high = sorted([fa, fb])
    assert a.collections()[high].endswith("(2)")
    before = (dict(a.view()), dict(b.view()))
    sync(a, b)
    assert (dict(a.view()), dict(b.view())) == before


def test_deleting_a_collection_syncs_and_its_items_stay(tmp_path):
    a, b = Dev(tmp_path, "a"), Dev(tmp_path, "b")
    family = CollectionService(a.s).create("Family")
    nid = note(a, "Kept", collections=[family])
    sync(a, b)
    CollectionService(b.s).delete(family)
    sync(a, b)
    for dev in (a, b):
        assert dev.collections() == {}
        assert dev.membership(nid) == []
        assert nid in dev.items()


# --- with an older peer (a v1 view: no collection states, records without collection_ids) -----------------

def test_an_older_peer_edits_an_item_and_the_new_devices_keep_its_collections(tmp_path):
    a, b, old = Dev(tmp_path, "a"), Dev(tmp_path, "b"), Dev(tmp_path, "old")
    family = CollectionService(a.s).create("Family")
    nid = note(a, "Door code", "1234", [family])
    sync(a, b)
    # The older peer only ever runs without collections (its views are v1 views).
    sync(a, old, collections=False)
    assert old.membership(nid) == [], "the older peer gets the item, not the membership"
    ItemService(old.s).update_item(nid, title="Door code (new)")
    report = pull(a, old, collections=True, src_collections=False)  # a v1 view in a collections run
    assert not report.issues and report.conflicts == 0
    assert a.item(nid)["title"] == "Door code (new)"
    assert a.membership(nid) == [family], "the older peer's edit keeps the newer device's collections"
    pull(b, a)
    assert b.item(nid)["title"] == "Door code (new)" and b.membership(nid) == [family]
    # Back to the older peer: it never sees a collection state and keeps the edit.
    pull(old, a, collections=False)
    assert old.item(nid)["title"] == "Door code (new)"
    assert not copies(a) and not copies(old)


def test_collection_states_reaching_a_run_without_collections_are_dropped(tmp_path):
    a, old = Dev(tmp_path, "a"), Dev(tmp_path, "old")
    family = CollectionService(a.s).create("Family")
    nid = note(a, "Tagged", collections=[family])
    report = pull(old, a, collections=False, src_collections=True)
    assert not report.issues
    assert nid in old.items() and old.collections() == {}
    assert not col_states(old.view(collections=False))
    meta = old.s._payload["sync_meta"]["items"]
    assert not any(is_collection_state_id(k) for k in meta)


def test_a_run_without_collections_never_tombstones_them(tmp_path):
    a, b = Dev(tmp_path, "a"), Dev(tmp_path, "b")
    family = CollectionService(a.s).create("Family")
    nid = note(a, "Tagged", collections=[family])
    sync(a, b)
    # An older device joins: A's runs go without collections for a while, then come back.
    assert not col_states(a.view(collections=False))
    pull(b, a, collections=True, src_collections=False)
    assert b.collections() == {family: "Family"} and b.membership(nid) == [family]
    assert all(not s.deleted for s in col_states(a.view()).values())


def test_a_membership_waits_for_its_item_and_collection(tmp_path):
    a, b = Dev(tmp_path, "a"), Dev(tmp_path, "b")
    family = CollectionService(a.s).create("Family")
    nid = note(a, "Tagged", collections=[family])
    theirs = a.view()
    only_membership = tuple(theirs[k] for k in sorted(theirs) if k == f"cm:{nid}")
    report = run_merge(b.s, LEASE, device_id=b.id, views=[View({"device_id": a.id}, only_membership)],
                       now=NOW, collections=True)
    assert not report.issues
    assert f"cm:{nid}" not in b.s._payload.get("sync_meta", {}).get("items", {})
    pull(b, a)
    assert b.membership(nid) == [family]


def test_malformed_collection_states_are_refused_alone(tmp_path):
    a, b = Dev(tmp_path, "a"), Dev(tmp_path, "b")
    family = CollectionService(a.s).create("Family")
    nid = note(a, "Tagged", collections=[family])
    theirs = dict(a.view())
    good = theirs[f"cm:{nid}"]
    bad_record = {**good.item["record"], "collection_ids": [family, "not-a-uuid"]}
    theirs[f"cm:{nid}"] = ItemState(good.item_id, good.vv, False, None, {**good.item, "record": bad_record})
    report = run_merge(b.s, LEASE, device_id=b.id, now=NOW, collections=True,
                       views=[View({"device_id": a.id}, tuple(theirs[k] for k in sorted(theirs)))])
    assert [i.kind for i in report.issues] == ["bad-peer-record"]
    assert nid in b.items() and b.collections() == {family: "Family"}
    assert b.membership(nid) == []


# --- shares across one person's own devices -----------------------------------------------------------------

def _share(tmp_path, mode):
    """An owner (other person) shares Family with *mode*; member device M1 joins; M2 is M1's second device."""
    owner = Dev(tmp_path, "owner")
    cid = CollectionService(owner.s).create("Family")
    nid = note(owner, "Alarm code", "4321", [cid])
    group = sg.create_share_group(owner.s, cid, password=PW, device="Owner PC", shared_mode=mode,
                                  _kdf_override=CHEAP)
    m1, m2 = Dev(tmp_path, "m1"), Dev(tmp_path, "m2")
    sg.join_share_group(m1.s, sg.share_keyring(owner.s, group.group_id), password=PW, device="Member PC",
                        _kdf_override=CHEAP)
    share_owner = sg.share_state(owner.s, group.group_id).device_id
    share_m1 = sg.share_state(m1.s, group.group_id).device_id

    def share_pull(dst, src, dst_dev, src_dev):
        theirs = local_view(src.s, LEASE, device_id=src_dev, now=NOW, collection_id=cid)
        return run_merge(dst.s, LEASE, device_id=dst_dev, now=NOW, collection_id=cid,
                         views=[View({"device_id": src_dev}, tuple(theirs[k] for k in sorted(theirs)))])

    share_pull(m1, owner, share_m1, share_owner)
    assert m1.membership(nid) == [cid]
    return owner, m1, m2, cid, nid, group.group_id, (share_pull, share_owner, share_m1)


def test_share_secrets_never_leave_through_personal_sync(tmp_path):
    owner, m1, m2, cid, nid, gid, _ = _share(tmp_path, "read")
    for dev, role in ((owner, "owner"), (m1, "member")):
        view = dev.view()
        row = CollectionService(dev.s).list()[0]
        assert view[f"col:{cid}"].item["record"] == {"kind": "collection", "collection_id": cid, **{
            k: row[k] for k in ("name", "description", "created_at", "updated_at")}}
        assert view[f"csl:{cid}"].item["record"] == {"kind": "share-link", "collection_id": cid,
                                                     "mode": "read", "role": role}
        blob = json.dumps({k: s.item for k, s in view.items()})
        state = sg.share_state(dev.s, gid)
        for secret in (gid, state.device_id, sg.share_info(dev.s, gid)["owner_key"], "shared_group_id",
                       state.key.hex(), "keyring"):
            assert secret not in blob
    pull(m2, m1)
    assert m2.collections() == {cid: "Family"}
    assert CollectionService(m2.s).shared_group_id(cid) is None, "the second device is not in the share"
    assert sg.list_share_groups(m2.s) == [] and sg.read_only_collection_ids(m2.s) == frozenset()
    assert m2.s._payload[LINKS_KEY] == {cid: {"mode": "read", "role": "member"}}


def test_read_only_share_stays_read_only_on_a_members_second_device(tmp_path):
    owner, m1, m2, cid, nid, gid, (share_pull, share_owner, share_m1) = _share(tmp_path, "read")
    pull(m2, m1)
    assert m2.membership(nid) == [cid]
    # The second device refuses edits, moves and new items there like the member's device does.
    with pytest.raises(ReadOnlyCollection):
        ItemService(m2.s).update_item(nid, title="Changed on M2")
    personal = note(m2, "Personal")
    with pytest.raises(ReadOnlyCollection):
        ItemService(m2.s).update_item(personal, collection_ids=[cid])
    with pytest.raises(sg.ShareGroupError, match="already-shared"):
        sg.create_share_group(m2.s, cid, password=PW, device="M2", shared_mode="edit", _kdf_override=CHEAP)

    # Even a forced change on M2 (an older app, a tampered vault) never edits it on M1.
    with sync_writes():
        ItemService(m2.s).update_item(nid, title="Forced on M2")
        ItemService(m2.s).update_item(personal, collection_ids=[cid])
    pull(m1, m2)
    assert m1.item(nid)["title"] == "Alarm code"
    assert m1.membership(personal) == [], "a personal item is never added to a read-only share"
    member_view = local_view(m1.s, LEASE, device_id=share_m1, now=NOW, collection_id=cid)
    assert set(member_view) == {nid}
    assert member_view[nid].item["record"]["title"] == "Alarm code", "nothing new is exported into the share"
    # M1's copy wins back on M2.
    pull(m2, m1)
    assert m2.item(nid)["title"] == "Alarm code"
    assert cid not in m2.item(personal)["collection_ids"]

    # A delete or a removed collection from M2 is undone the same way.
    with sync_writes():
        ItemService(m2.s).delete_item(nid)
    with pytest.raises(SharedCollection):
        CollectionService(m2.s).delete(cid)
    _force_delete(m2, cid)
    sync(m1, m2)
    assert nid in m1.items() and m1.membership(nid) == [cid]
    assert CollectionService(m1.s).shared_group_id(cid) == gid
    assert m2.collections() == {cid: "Family"} and nid in m2.items()
    assert not copies(m1)

    # The owner's next edit reaches M2 through M1.
    ItemService(owner.s).update_item(nid, title="Alarm code v2")
    share_pull(m1, owner, share_m1, share_owner)
    pull(m2, m1)
    assert m2.item(nid)["title"] == "Alarm code v2"


def _force_delete(dev, cid):
    """What an older app (or a tampered vault) does: the row and every membership go, shared or not."""
    with dev.s.transaction():
        payload = dev.s._require_typed_catalog()
        payload["collections"] = [r for r in payload["collections"] if r["id"] != cid]
        items = payload.get("items", []) + [r["entry"] for r in payload.get("trash", []) if isinstance(r.get("entry"), dict)]
        for item in items:
            if "collection_ids" in item:
                item["collection_ids"] = [c for c in item["collection_ids"] if c != cid]


def _force_rename(dev, cid, name):
    with dev.s.transaction():
        row = next(r for r in dev.s._require_typed_catalog()["collections"] if r["id"] == cid)
        row.update(name=name, description="changed elsewhere", updated_at=row["updated_at"] + 5)


def test_read_only_share_row_is_never_renamed_from_a_second_device(tmp_path):
    owner, m1, m2, cid, nid, gid, _ = _share(tmp_path, "read")
    pull(m2, m1)
    with pytest.raises(SharedCollection):
        CollectionService(m2.s).rename(cid, "Renamed on M2")
    _force_rename(m2, cid, "Renamed on M2")  # an older app on M2
    report = pull(m1, m2)
    assert not report.issues
    assert m1.collections() == {cid: "Family"}
    assert CollectionService(m1.s).list()[0]["description"] == ""
    assert m1.view()[f"col:{cid}"].vv.get(m1.id, 0) == 2, "M1's row is republished above M2's"
    pull(m2, m1)
    assert m2.collections() == {cid: "Family"}
    # The member device itself refuses too, as on the Mac, the iPhone and Android (final review minor 6).
    with pytest.raises(SharedCollection):
        CollectionService(m1.s).rename(cid, "Family (shared)")
    assert m1.collections() == {cid: "Family"}


def test_a_shared_collection_is_never_deleted(tmp_path):
    owner, m1, m2, cid, nid, gid, _ = _share(tmp_path, "read")
    pull(m2, m1)
    o2 = Dev(tmp_path, "o2")
    pull(o2, owner)
    for dev in (owner, m1, m2, o2):  # the owner, the member, and their second devices (links)
        with pytest.raises(SharedCollection):
            CollectionService(dev.s).delete(cid)
        assert cid in dev.collections()
    work = CollectionService(m2.s).create("Work")
    assert CollectionService(m2.s).delete(work)
    # After leaving, the collection is the member's own again.
    sg.leave_share_group(m1.s, gid)
    pull(m2, m1)
    assert CollectionService(m2.s).delete(cid) and CollectionService(m1.s).delete(cid)
    assert nid in m1.items()


def test_edit_share_second_device_edits_reach_the_share_through_the_member(tmp_path):
    owner, m1, m2, cid, nid, gid, (share_pull, share_owner, share_m1) = _share(tmp_path, "edit")
    pull(m2, m1)
    assert m2.s._payload[LINKS_KEY] == {cid: {"mode": "edit", "role": "member"}}
    ItemService(m2.s).update_item(nid, title="Changed on M2")
    pull(m1, m2)
    assert m1.item(nid)["title"] == "Changed on M2"
    share_pull(owner, m1, share_owner, share_m1)
    assert owner.item(nid)["title"] == "Changed on M2"


def test_second_devices_join_rules(tmp_path):
    owner, m1, m2, cid, nid, gid, _ = _share(tmp_path, "read")
    pull(m2, m1)
    # The member's second device may join the same share; it then speaks for it itself.
    sg.join_share_group(m2.s, sg.share_keyring(m1.s, gid), password=PW, device="M2", _kdf_override=CHEAP)
    assert LINKS_KEY not in m2.s._payload
    assert cid in sg.read_only_collection_ids(m2.s)
    # The owner's second device already gets the collection through device sync: joining is refused.
    o2 = Dev(tmp_path, "o2")
    pull(o2, owner)
    assert o2.s._payload[LINKS_KEY] == {cid: {"mode": "read", "role": "owner"}}
    ItemService(o2.s).update_item(nid, title="Owner edits on a second PC")  # the owner's devices may edit
    with pytest.raises(sg.ShareGroupError, match="own-share"):
        sg.join_share_group(o2.s, sg.share_keyring(owner.s, gid), password=PW, device="O2", _kdf_override=CHEAP)


def test_leaving_the_share_clears_the_link_on_the_second_device(tmp_path):
    owner, m1, m2, cid, nid, gid, _ = _share(tmp_path, "read")
    pull(m2, m1)
    sg.leave_share_group(m1.s, gid)
    pull(m2, m1)
    assert LINKS_KEY not in m2.s._payload
    ItemService(m2.s).update_item(nid, title="Mine now")


# --- final fix wave B: finding 4 (a share link whose holder device is gone stays forever) -----------------

def test_forgetting_the_link_of_a_lost_member_device_frees_the_collection_on_every_other_device(tmp_path):
    owner, m1, m2, cid, nid, gid, _ = _share(tmp_path, "read")
    pull(m2, m1)
    m3 = Dev(tmp_path, "m3")
    pull(m3, m2)
    assert m3.s._payload[LINKS_KEY] == {cid: {"mode": "read", "role": "member"}}
    # M1 (the device in the share) is lost: M2 and M3 refuse edits and deletes there for ever.
    with pytest.raises(ReadOnlyCollection):
        ItemService(m2.s).update_item(nid, title="Mine now")
    with pytest.raises(SharedCollection):
        CollectionService(m2.s).delete(cid)
    assert sg.received_share_link(m2.s, cid) == {"mode": "read", "role": "member"}
    sg.forget_share_link(m2.s, cid)
    assert LINKS_KEY not in m2.s._payload and sg.received_share_link(m2.s, cid) is None
    ItemService(m2.s).update_item(nid, title="Mine now")
    assert m2.view()[f"csl:{cid}"].deleted, "M2 publishes the link's tombstone"
    pull(m3, m2)
    assert LINKS_KEY not in m3.s._payload
    assert m3.item(nid)["title"] == "Mine now"
    assert CollectionService(m3.s).delete(cid)


def test_a_device_that_still_holds_the_share_publishes_its_link_again(tmp_path):
    owner, m1, m2, cid, nid, gid, _ = _share(tmp_path, "read")
    pull(m2, m1)
    sg.forget_share_link(m2.s, cid)
    pull(m1, m2)
    assert sg.read_only_collection_ids(m1.s) == frozenset({cid}), "M1 is still in the share"
    pull(m2, m1)
    assert m2.s._payload[LINKS_KEY] == {cid: {"mode": "read", "role": "member"}}
    with pytest.raises(ReadOnlyCollection):
        ItemService(m2.s).update_item(nid, title="Not mine")


def test_forgetting_a_lost_owner_devices_link_lets_the_owner_share_again(tmp_path):
    owner, m1, m2, cid, nid, gid, _ = _share(tmp_path, "read")
    o2 = Dev(tmp_path, "o2")
    pull(o2, owner)
    with pytest.raises(sg.ShareGroupError, match="already-shared"):
        sg.create_share_group(o2.s, cid, password=PW, device="O2", _kdf_override=CHEAP)
    # The owner's PC is lost: the documented recovery is to share again from another device.
    sg.forget_share_link(o2.s, cid)
    again = sg.create_share_group(o2.s, cid, password=PW, device="O2", _kdf_override=CHEAP)
    assert again.group_id != gid and sg.share_info(o2.s, again.group_id)["role"] == "owner"


def test_forget_share_link_refusals(tmp_path):
    owner, m1, m2, cid, nid, gid, _ = _share(tmp_path, "read")
    with pytest.raises(sg.ShareGroupError, match="shared-here"):
        sg.forget_share_link(m1.s, cid)  # leave the share instead
    with pytest.raises(sg.ShareGroupError, match="shared-here"):
        sg.forget_share_link(owner.s, cid)  # stop sharing instead
    assert sg.received_share_link(m1.s, cid) is None
    work = CollectionService(m2.s).create("Work")
    with pytest.raises(sg.ShareGroupError, match="no-link"):
        sg.forget_share_link(m2.s, work)


# --- re-review wave B: B1 (one collection shared from two of this person's devices) ---------------------------

def _link_vvs(*devs, cid):
    return [dict(d.view()[f"csl:{cid}"].vv) for d in devs]


def test_a_collection_shared_from_two_devices_settles_on_one_link_and_both_warn(tmp_path):
    owner, m1, m2, cid, nid, gid, _ = _share(tmp_path, "read")
    o2 = Dev(tmp_path, "o2")
    pull(o2, owner)
    # The owner's PC is wrongly taken for lost: O2 forgets its link and shares Family again, in edit mode.
    sg.forget_share_link(o2.s, cid)
    sg.create_share_group(o2.s, cid, password=PW, device="O2", shared_mode="edit", _kdf_override=CHEAP)
    o3 = Dev(tmp_path, "o3")
    rounds = []
    for _ in range(5):
        pull(owner, o2)
        pull(o2, owner)
        pull(o3, o2)
        rounds.append(_link_vvs(owner, o2, o3, cid=cid))
    assert rounds[-1] == rounds[-2] == rounds[-3], rounds
    # Owner beats member, then the larger canonical record: both are owners here.
    from localvault.sync.vault_bridge import _link_beats, _link_record
    read, edit = _link_record(cid, {"mode": "read", "role": "owner"}), _link_record(cid, {"mode": "edit", "role": "owner"})
    winner = "read" if _link_beats(read, edit) else "edit"
    for dev in (owner, o2, o3):
        assert dev.view()[f"csl:{cid}"].item["record"]["mode"] == winner
    assert sg.shared_twice(owner.s, cid) and sg.shared_twice(o2.s, cid)
    assert not sg.shared_twice(o3.s, cid)
    # Stopping the share on one device ends the warning on the other, and it settles again.
    sg.leave_share_group(o2.s, sg.list_share_groups(o2.s)[0].group_id)
    for _ in range(3):
        pull(owner, o2)
        pull(o2, owner)
    assert not sg.shared_twice(owner.s, cid)
    assert o2.s._payload[LINKS_KEY] == {cid: {"mode": "read", "role": "owner"}}
    settled = _link_vvs(owner, o2, cid=cid)
    pull(owner, o2)
    pull(o2, owner)
    assert _link_vvs(owner, o2, cid=cid) == settled


def test_a_member_link_never_beats_an_owner_link():
    from localvault.sync.vault_bridge import _link_beats, _link_record
    owner = _link_record("c", {"mode": "read", "role": "owner"})
    member = _link_record("c", {"mode": "read", "role": "member"})
    edit_member = _link_record("c", {"mode": "edit", "role": "member"})
    assert _link_beats(owner, member) and not _link_beats(member, owner)
    assert _link_beats(owner, edit_member) and not _link_beats(edit_member, owner)
    assert _link_beats(member, edit_member) != _link_beats(edit_member, member)
