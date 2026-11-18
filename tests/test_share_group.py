"""Share groups (sub-plan 07 Task 1): a collection shared through its own keyring, Pro only."""
from __future__ import annotations

import copy
import dataclasses

import pytest

from localvault import licensing
from localvault.collections import CollectionService
from localvault.sync import keyring as kr
from localvault.sync import removal
from localvault.sync import share_group as sg
from localvault.sync.vault_bridge import SyncGroupState, load_sync_state, save_sync_state
from localvault.vault import ProFeatureRequired, create_vault, unlock_vault

TEST_KDF = {"time_cost": 1, "memory_cost_kib": 8192, "parallelism": 1, "hash_len": 32}
CHEAP = (1024, 1, 1)
MASTER = "synthetic master"
PW = "correct horse battery staple 7!"
PW2 = "another very long passphrase 42?"


@pytest.fixture
def pro(monkeypatch):
    """Pro on this device (``licensing.item_limit() is None``); set ``pro.on = False`` to lapse it."""

    class Switch:
        on = True

    switch = Switch()
    monkeypatch.setattr(licensing, "item_limit", lambda st=None: None if switch.on else licensing.FREE_ITEM_LIMIT)
    return switch


def vault(tmp_path, name):
    return create_vault(tmp_path / f"{name}.json", MASTER, kdf_overrides=TEST_KDF)


def family(session, name="Family"):
    return CollectionService(session).create(name)


def share(session, cid, **kw):
    return sg.create_share_group(session, cid, password=PW, device="Owner PC", _kdf_override=CHEAP, **kw)


def join(session, ring, password=PW, device="Member PC"):
    return sg.join_share_group(session, ring, password=password, device=device, _kdf_override=CHEAP)


def test_create_writes_signed_metadata_and_marks_the_collection(tmp_path, pro):
    owner = vault(tmp_path, "owner")
    cid = family(owner)
    group = share(owner, cid, shared_mode="edit")
    assert isinstance(group, sg.ShareGroup)
    assert (group.collection_id, group.name, group.shared_mode) == (cid, "Family", "edit")
    assert [m.name for m in group.members] == ["Owner PC"]
    ring = kr.parse_keyring(sg.share_keyring(owner, group.group_id))
    kr.verify_keyring_structure(ring, _kdf_override=CHEAP)
    meta = kr.keyring_metadata(ring)
    owner_id = sg.share_state(owner, group.group_id).device_id
    assert (meta["collection_id"], meta["shared_mode"], meta["owner"]) == (cid, "edit", owner_id)
    assert group.owner == owner_id and [m.approved for m in group.members] == [True]
    # The folder never shows the collection name, and tampering with the metadata is refused on join.
    assert b"Family" not in sg.share_keyring(owner, group.group_id)
    tampered = copy.deepcopy(ring)
    tampered["metadata"]["shared_mode"] = "read"
    member = vault(tmp_path, "member")
    with pytest.raises(kr.KeyringError) as err:
        join(member, canonical(tampered))
    assert err.value.reason == "bad-owner-sig"
    assert CollectionService(owner).shared_group_id(cid) == group.group_id
    assert sg.list_share_groups(owner) == [group]
    # The personal sync group is untouched.
    assert load_sync_state(owner) is None


def approve_all(owner, group_id):
    """What the owner's UI does: show the pending members by name, then approve them."""
    pending = sg.pending_members(owner, group_id)
    return sg.approve_members(owner, group_id, [m.device_id for m in pending], _kdf_override=CHEAP)


def canonical(ring):
    from localvault.updates import canonical_json
    return canonical_json(ring)


def test_state_survives_a_save_and_reopen(tmp_path, pro):
    owner = vault(tmp_path, "owner")
    cid = family(owner)
    group = share(owner, cid)
    path = owner.path
    owner.lock()
    again = unlock_vault(path, MASTER)
    assert sg.list_share_groups(again) == [group]
    assert CollectionService(again).shared_group_id(cid) == group.group_id


def test_create_refusals(tmp_path, pro):
    owner = vault(tmp_path, "owner")
    cid = family(owner)
    with pytest.raises(sg.ShareGroupError) as err:
        sg.create_share_group(owner, "0b9a3c7e-2f4d-4c1a-9e5b-1d2c3b4a5f60", password=PW, device="PC",
                              _kdf_override=CHEAP)
    assert err.value.reason == "no-collection"
    with pytest.raises(kr.KeyringError):
        share(owner, cid, shared_mode="write")
    with pytest.raises(kr.WeakSyncPassword):
        sg.create_share_group(owner, cid, password="short", device="PC", _kdf_override=CHEAP)
    share(owner, cid)
    with pytest.raises(sg.ShareGroupError) as err:
        share(owner, cid)
    assert err.value.reason == "already-shared"


def test_join_adds_the_member_and_the_collection(tmp_path, pro):
    owner, member = vault(tmp_path, "owner"), vault(tmp_path, "member")
    group = share(owner, family(owner))
    joined = join(member, sg.share_keyring(owner, group.group_id))
    assert (joined.group_id, joined.collection_id, joined.name, joined.shared_mode) == (
        group.group_id, group.collection_id, "Family", "read")
    assert [m.name for m in joined.members] == ["Owner PC", "Member PC"]
    rows = CollectionService(member).list()
    assert [(r["id"], r["name"], r.get("shared_group_id")) for r in rows] == [
        (group.collection_id, "Family", group.group_id)]
    assert load_sync_state(member) is None  # the member's own device sync is untouched
    with pytest.raises(sg.ShareGroupError) as err:
        join(member, sg.share_keyring(member, group.group_id))
    assert err.value.reason == "already-joined"


def test_join_with_a_name_clash_keeps_both_collections(tmp_path, pro):
    owner, member = vault(tmp_path, "owner"), vault(tmp_path, "member")
    group = share(owner, family(owner))
    mine = family(member)
    joined = join(member, sg.share_keyring(owner, group.group_id))
    rows = {r["id"]: r for r in CollectionService(member).list()}
    assert rows[mine]["name"] == "Family" and "shared_group_id" not in rows[mine]
    assert rows[joined.collection_id]["name"] == "Family (2)"


def test_join_with_wrong_password_fails_and_changes_nothing(tmp_path, pro):
    owner, member = vault(tmp_path, "owner"), vault(tmp_path, "member")
    group = share(owner, family(owner))
    with pytest.raises(kr.KeyringError) as err:
        join(member, sg.share_keyring(owner, group.group_id), password=PW2)
    assert err.value.reason == "password"
    assert sg.list_share_groups(member) == [] and CollectionService(member).list() == []


def test_join_refuses_a_personal_keyring(tmp_path, pro):
    member = vault(tmp_path, "member")
    ring, _ = kr.create_group(PW, kr.DeviceIdentity.generate(), "A", _kdf_override=CHEAP)
    with pytest.raises(sg.ShareGroupError) as err:
        join(member, canonical(ring))
    assert err.value.reason == "not-share"


def test_join_on_a_free_device_raises_pro_required_before_any_work(tmp_path, pro, monkeypatch):
    owner, member = vault(tmp_path, "owner"), vault(tmp_path, "member")
    group = share(owner, family(owner))
    pro.on = False
    monkeypatch.setattr(kr, "_argon2", lambda *a: pytest.fail("the KDF ran on a free device"))
    with pytest.raises(sg.ProRequired) as err:
        join(member, sg.share_keyring(owner, group.group_id))
    assert isinstance(err.value, ProFeatureRequired) and err.value.feature == "sharing"
    assert str(err.value)  # the upgrade sheet shows this text
    with pytest.raises(sg.ProRequired):
        share(member, family(member))
    assert sg.list_share_groups(member) == []


def test_lapsed_pro_stops_syncing_but_keeps_read_access(tmp_path, pro):
    owner, member = vault(tmp_path, "owner"), vault(tmp_path, "member")
    group = share(owner, family(owner), shared_mode="edit")  # a read-only share refuses member items
    joined = join(member, sg.share_keyring(owner, group.group_id))
    item = member.items.create_note("Shared note", "hello", collection_ids=[joined.collection_id])
    assert sg.share_sync_allowed()
    pro.on = False  # refund: the licence lapsed
    assert not sg.share_sync_allowed()
    with pytest.raises(sg.ProRequired):
        sg.require_share_sync()
    # Read access stays: the group, its collection and the items in it are all still there.
    assert sg.list_share_groups(member) == [joined]
    assert CollectionService(member).shared_group_id(joined.collection_id) == joined.group_id
    assert [s.id for s in CollectionService(member).members(joined.collection_id)] == [item]
    # Leaving is always allowed; the collection and its items stay.
    sg.leave_share_group(member, joined.group_id)
    assert sg.list_share_groups(member) == []
    assert CollectionService(member).shared_group_id(joined.collection_id) is None


def test_remove_member_rotates_and_returns_a_notice_for_the_share_group_only(tmp_path, pro):
    owner, member = vault(tmp_path, "owner"), vault(tmp_path, "member")
    group = share(owner, family(owner))
    joined = join(member, sg.share_keyring(owner, group.group_id))
    # The owner adopts the member's join (in the app the folder run does this).
    sg.adopt_keyring(owner, group.group_id, sg.share_keyring(member, joined.group_id), _kdf_override=CHEAP)
    removed = next(m.device_id for m in joined.members if m.name == "Member PC")
    member_state = sg.share_state(member, joined.group_id)
    before = sg.share_state(owner, group.group_id).epoch

    # The member's own device sync group, which the notice must never touch.
    personal = SyncGroupState("personal-group-1", 1, b"\x01" * 32, member_state.device_identity,
                              install_id="install-member")
    save_sync_state(member, personal)

    notice = sg.remove_member(owner, group.group_id, removed, new_password=PW2, _kdf_override=CHEAP)
    after = sg.share_state(owner, group.group_id)
    assert after.epoch == before + 1
    new_ring = sg.share_keyring(owner, group.group_id)
    assert removed not in {m["device_id"] for m in kr.parse_keyring(new_ring)["members"]}
    assert kr.keyring_metadata(kr.parse_keyring(new_ring))["collection_id"] == group.collection_id
    assert [m.name for m in sg.list_share_groups(owner)[0].members] == ["Owner PC"]

    # The removed member's watch for the SHARE group accepts the notice ...
    share_watch = removal.watch_from_state(dataclasses.replace(member_state, install_id="install-member"), tmp_path)
    accepted = removal.verify_notice(notice, share_watch, new_ring)
    assert (accepted.group_id, accepted.device_id, accepted.epoch) == (group.group_id, removed, after.epoch)
    # ... and a watch for the member's own vault (its personal group) refuses it.
    own_watch = removal.Watch("personal-group-1", removed, 1, "install-member", str(tmp_path),
                              dict(share_watch.signers))
    with pytest.raises(removal.RemovalError) as err:
        removal.verify_notice(notice, own_watch, new_ring)
    assert err.value.reason == "not-for-this-device"
    assert load_sync_state(member) == personal


def test_remove_member_refusals(tmp_path, pro):
    owner, member = vault(tmp_path, "owner"), vault(tmp_path, "member")
    group = share(owner, family(owner))
    joined = join(member, sg.share_keyring(owner, group.group_id))
    sg.adopt_keyring(owner, group.group_id, sg.share_keyring(member, joined.group_id), _kdf_override=CHEAP)
    owner_id = sg.share_state(owner, group.group_id).device_id
    member_id = sg.share_state(member, joined.group_id).device_id
    with pytest.raises(sg.ShareGroupError) as err:
        sg.remove_member(member, joined.group_id, owner_id, new_password=PW2, _kdf_override=CHEAP)
    assert err.value.reason == "not-owner"  # a member cannot throw the owner out
    with pytest.raises(kr.KeyringError) as err:
        sg.remove_member(owner, group.group_id, owner_id, new_password=PW2, _kdf_override=CHEAP)
    assert err.value.reason == "cannot-remove-self"
    with pytest.raises(kr.KeyringError) as err:
        sg.remove_member(owner, group.group_id, member_id, new_password=PW, _kdf_override=CHEAP)
    assert err.value.reason == "password-reused"
    with pytest.raises(sg.ShareGroupError) as err:
        sg.remove_member(owner, "no-such-group", member_id, new_password=PW2, _kdf_override=CHEAP)
    assert err.value.reason == "not-joined"
    # Removal is a security action: it still works after the owner's Pro lapsed.
    pro.on = False
    notice = sg.remove_member(owner, group.group_id, member_id, new_password=PW2, _kdf_override=CHEAP)
    assert removal.parse_notice(notice)[0].device_id == member_id


def test_stored_share_state_is_validated(tmp_path, pro):
    owner = vault(tmp_path, "owner")
    share(owner, family(owner))
    payload = owner._require_typed_catalog()
    good = copy.deepcopy(payload[sg.STORE_KEY])
    for bad in ([], {"x": {}}, {k: {**v, "role": "admin"} for k, v in good.items()},
                {k: {**v, "extra": 1} for k, v in good.items()}):
        payload[sg.STORE_KEY] = bad
        with pytest.raises(sg.ShareGroupError) as err:
            sg.list_share_groups(owner)
        assert err.value.reason == "bad-state"
    payload[sg.STORE_KEY] = good


def test_personal_folder_join_refuses_a_share_keyring(tmp_path, pro):
    from localvault.sync import folder_transport as ft

    class Lease:
        def check(self):
            return None

    owner, other = vault(tmp_path, "owner"), vault(tmp_path, "other")
    group = share(owner, family(owner))
    root = tmp_path / "cloud"
    (root / ft.SYNC_DIR_NAME).mkdir(parents=True)
    (root / ft.SYNC_DIR_NAME / "keyring.lgkkeys").write_bytes(sg.share_keyring(owner, group.group_id))
    with pytest.raises(ft.FolderSyncError) as err:
        ft.join_folder_group(root, other, Lease(), PW, "PC", install_id="i", run=False, _kdf_override=CHEAP)
    assert err.value.reason == "share-group"
    assert load_sync_state(other) is None


def test_no_secrets_in_reprs(tmp_path, pro):
    owner = vault(tmp_path, "owner")
    group = share(owner, family(owner))
    state = sg.share_state(owner, group.group_id)
    text = repr(group) + repr(sg.list_share_groups(owner))
    assert PW not in text and state.key.hex() not in text


def test_unacknowledged_members_are_dropped_when_the_owner_removes_someone(tmp_path, pro):
    owner, member, puppet = vault(tmp_path, "owner"), vault(tmp_path, "member"), vault(tmp_path, "puppet")
    group = share(owner, family(owner))
    joined = join(member, sg.share_keyring(owner, group.group_id))
    seen = sg.adopt_keyring(owner, group.group_id, sg.share_keyring(member, joined.group_id), _kdf_override=CHEAP)
    member_id = next(m.device_id for m in seen.members if m.name == "Member PC")
    assert sg.share_state(owner, group.group_id).unacked_members == (member_id,)
    approved = approve_all(owner, group.group_id)
    assert [(m.name, m.approved) for m in approved] == [("Member PC", True)]
    assert sg.share_state(owner, group.group_id).unacked_members == ()
    # Someone else with the password adds a device the owner never confirms ...
    extra = join(puppet, sg.share_keyring(owner, group.group_id), device="Puppet")
    seen = sg.adopt_keyring(owner, group.group_id, sg.share_keyring(puppet, extra.group_id), _kdf_override=CHEAP)
    puppet_id = next(m.device_id for m in seen.members if m.name == "Puppet")
    assert sg.share_state(owner, group.group_id).unacked_members == (puppet_id,)
    # ... removing the member drops it as well, without a notice for it.
    notice = sg.remove_member(owner, group.group_id, member_id, new_password=PW2, _kdf_override=CHEAP)
    assert removal.parse_notice(notice)[0].device_id == member_id
    assert [m.name for m in sg.list_share_groups(owner)[0].members] == ["Owner PC"]


def test_adopt_refuses_a_keyring_of_another_collection_or_group(tmp_path, pro):
    owner = vault(tmp_path, "owner")
    group = share(owner, family(owner))
    other = share(owner, family(owner, "Team"))
    with pytest.raises(kr.KeyringError) as err:
        sg.adopt_keyring(owner, group.group_id, sg.share_keyring(owner, other.group_id), _kdf_override=CHEAP)
    assert err.value.reason == "group-mismatch"


def test_collection_shared_group_id_field_is_optional_and_validated():
    from localvault.item_schema import ItemSchemaError, validate_collections

    base = {"id": "0b9a3c7e-2f4d-4c1a-9e5b-1d2c3b4a5f60", "name": "Family", "description": "",
            "created_at": 1, "updated_at": 1, "revision": 1, "starter": False}
    assert validate_collections([base]) == [base]  # an unshared collection keeps its exact shape
    assert validate_collections([{**base, "shared_group_id": None}]) == [base]
    shared = {**base, "shared_group_id": "8ba6a25d-be57-489b-98fb-53e00e9a0b1c"}
    assert validate_collections([shared]) == [shared]
    for bad in ("", "a/b", "x" * 129, 5, "é"):
        with pytest.raises(ItemSchemaError):
            validate_collections([{**base, "shared_group_id": bad}])


def test_join_never_shares_a_collection_the_vault_already_has(tmp_path, pro):
    member = vault(tmp_path, "member")
    mine = family(member, "Private")
    note = member.items.create_note("Private note", "secret", collection_ids=[mine])
    # A keyring made (by anyone with the share password) for a collection id this vault already uses.
    ring, _ = kr.create_group(PW, kr.DeviceIdentity.generate(), "Owner PC", _kdf_override=CHEAP,
                              metadata={"kind": "share", "collection_id": mine, "name": "Family",
                                        "shared_mode": "edit"})
    with pytest.raises(sg.ShareGroupError) as err:
        join(member, canonical(ring))
    assert err.value.reason == "collection-exists"
    assert CollectionService(member).shared_group_id(mine) is None
    assert [s.id for s in CollectionService(member).members(mine)] == [note]
    assert sg.list_share_groups(member) == []


def test_a_left_collection_is_not_shared_again_by_a_join(tmp_path, pro):
    owner, member = vault(tmp_path, "owner"), vault(tmp_path, "member")
    group = share(owner, family(owner))
    joined = join(member, sg.share_keyring(owner, group.group_id))
    sg.leave_share_group(member, joined.group_id)
    # The left collection is now the member's own: a later join of a keyring naming it is refused.
    with pytest.raises(sg.ShareGroupError) as err:
        join(member, sg.share_keyring(owner, group.group_id))
    assert err.value.reason == "collection-exists"



def _forge(session, group_id, mutate):
    """A member holding G rewrites the keyring (re-MAC under G), as a modified client could."""
    state = sg.share_state(session, group_id)
    ring = kr.parse_keyring(state.keyring)
    mutate(ring)
    gk = kr.GroupKey(state.group_id, state.epoch, state.key)
    return canonical(kr._finish(ring, gk, None, ring["prev_mac"]))


def _two_members(tmp_path):
    owner, alice, bob = vault(tmp_path, "owner"), vault(tmp_path, "alice"), vault(tmp_path, "bob")
    group = share(owner, family(owner))
    a = join(alice, sg.share_keyring(owner, group.group_id), device="Alice PC")
    b = join(bob, sg.share_keyring(alice, a.group_id), device="Bob PC")
    sg.adopt_keyring(owner, group.group_id, sg.share_keyring(bob, b.group_id), _kdf_override=CHEAP)
    approve_all(owner, group.group_id)
    for s in (alice, bob):
        sg.adopt_keyring(s, group.group_id, sg.share_keyring(owner, group.group_id), _kdf_override=CHEAP)
    return owner, alice, bob, group


def test_forged_member_changes_are_refused_and_the_owners_are_accepted(tmp_path, pro):
    owner, alice, bob, group = _two_members(tmp_path)
    gid = group.group_id
    alice_state = sg.share_state(alice, gid)
    owner_id = sg.share_state(owner, gid).device_id
    bob_id = sg.share_state(bob, gid).device_id

    def flip(ring):
        ring["metadata"]["shared_mode"] = "edit"

    def drop_owner(ring):
        ring["members"] = [m for m in ring["members"] if m["device_id"] != owner_id]
        del ring["device_wraps"][owner_id]

    def drop_bob(ring):
        ring["members"] = [m for m in ring["members"] if m["device_id"] != bob_id]
        del ring["device_wraps"][bob_id]

    def usurp(ring):
        ring["metadata"]["owner"] = alice_state.device_id
        ring["metadata"]["owner_key"] = kr._b64e(alice_state.identity().signing_public_key)
        # alice is approved, so she holds the content key (share v2) and can re-sign with it.
        signed = kr._sign_owner(ring, alice_state.identity(),
                                content=kr.open_content_key(ring, alice_state.identity()))
        ring.clear()
        ring.update(signed)

    for mutate, why in ((flip, "bad-owner-sig"), (drop_owner, "bad-owner"), (drop_bob, "bad-owner"),
                        (usurp, "tampered")):
        forged = _forge(alice, gid, mutate)
        with pytest.raises(kr.KeyringError) as err:
            sg.adopt_keyring(bob, gid, forged, _kdf_override=CHEAP)
        assert err.value.reason == why, mutate.__name__
    # A rotation by a member: the keyring layer refuses it, and nobody would accept one.
    with pytest.raises(kr.KeyringError) as err:
        kr.rotate(kr.parse_keyring(alice_state.keyring), kr.GroupKey(gid, alice_state.epoch, alice_state.key),
                  alice_state.identity(), PW2, remove=[bob_id], _kdf_override=CHEAP)
    assert err.value.reason == "not-owner"
    # The member's forged removal notice for bob, signed with alice's own key, is refused by bob.
    forged_notice = removal.make_notice(alice_state.identity().signing_key, group_id=gid, device_id=bob_id,
                                        epoch=alice_state.epoch + 1, signer=alice_state.device_id)
    with pytest.raises(removal.RemovalError) as err:
        sg.verify_share_notice(bob, gid, forged_notice, sg.share_keyring(owner, gid))
    assert err.value.reason == "unknown-signer"
    # The owner's genuine removal is accepted by bob and by alice (rotation).
    notice = sg.remove_member(owner, gid, bob_id, new_password=PW2, _kdf_override=CHEAP)
    ring = sg.share_keyring(owner, gid)
    assert sg.verify_share_notice(bob, gid, notice, ring).device_id == bob_id
    after = sg.adopt_keyring(alice, gid, ring, _kdf_override=CHEAP)
    assert sorted(m.name for m in after.members) == ["Alice PC", "Owner PC"]
    assert after.name == "Family"


def test_the_owner_never_acts_on_a_removal_notice(tmp_path, pro):
    owner, alice, _, group = _two_members(tmp_path)
    gid = group.group_id
    owner_state = sg.share_state(owner, gid)
    alice_state = sg.share_state(alice, gid)
    assert sg.share_watch(owner, gid, tmp_path) is None
    forged = removal.make_notice(alice_state.identity().signing_key, group_id=gid, device_id=owner_state.device_id,
                                 epoch=owner_state.epoch + 1, signer=alice_state.device_id)
    with pytest.raises(removal.RemovalError) as err:
        sg.verify_share_notice(owner, gid, forged, sg.share_keyring(owner, gid))
    assert err.value.reason == "owner"
    watch = sg.share_watch(alice, gid, tmp_path)
    assert watch.signers == {owner_state.device_id: kr._b64e(owner_state.identity().signing_public_key)}


def test_pending_members_are_marked_until_the_owner_approves(tmp_path, pro):
    owner, member = vault(tmp_path, "owner"), vault(tmp_path, "member")
    group = share(owner, family(owner))
    joined = join(member, sg.share_keyring(owner, group.group_id))
    assert {m.name: m.approved for m in joined.members} == {"Owner PC": True, "Member PC": False}
    member_id = sg.share_state(member, joined.group_id).device_id
    with pytest.raises(sg.ShareGroupError) as err:
        sg.approve_members(member, joined.group_id, [member_id], _kdf_override=CHEAP)
    assert err.value.reason == "not-owner"
    sg.adopt_keyring(owner, group.group_id, sg.share_keyring(member, joined.group_id), _kdf_override=CHEAP)
    assert [m.name for m in sg.pending_members(owner, group.group_id)] == ["Member PC"]
    for bad in ([], ["no-such-device"], [sg.share_state(owner, group.group_id).device_id]):
        with pytest.raises(sg.ShareGroupError) as err:
            sg.approve_members(owner, group.group_id, bad, _kdf_override=CHEAP)
        assert err.value.reason == "not-pending"
    approved = approve_all(owner, group.group_id)
    assert [m.device_id for m in approved] == [member_id]
    assert sg.pending_members(owner, group.group_id) == ()
    after = sg.adopt_keyring(member, joined.group_id, sg.share_keyring(owner, group.group_id), _kdf_override=CHEAP)
    assert all(m.approved for m in after.members)
    assert sg.share_state(member, joined.group_id).unacked_members == ()


def test_a_replayed_older_owner_signature_is_refused(tmp_path, pro):
    owner, member = vault(tmp_path, "owner"), vault(tmp_path, "member")
    group = share(owner, family(owner))
    joined = join(member, sg.share_keyring(owner, group.group_id))
    stale = sg.share_keyring(member, joined.group_id)  # owner-signed roster: owner only
    sg.adopt_keyring(owner, group.group_id, stale, _kdf_override=CHEAP)
    approve_all(owner, group.group_id)
    approved_ring = sg.share_keyring(owner, group.group_id)
    with pytest.raises(kr.KeyringError) as err:
        sg.adopt_keyring(owner, group.group_id, stale, _kdf_override=CHEAP)  # replayed
    assert err.value.reason == "tampered"
    assert sg.share_keyring(owner, group.group_id) == approved_ring
    assert sg.pending_members(owner, group.group_id) == ()


def test_replayed_creation_signature_cannot_drop_an_approved_member(tmp_path, pro):
    """The re-review probe: alice replays the epoch-1 creation signature (owner only) and drops bob."""
    owner, alice, bob = vault(tmp_path, "owner"), vault(tmp_path, "alice"), vault(tmp_path, "bob")
    group = share(owner, family(owner))
    gid = group.group_id
    created = kr.parse_keyring(sg.share_keyring(owner, gid))
    old_sig, old_content = created["owner_sig"], created["content"]  # owner-only roster, epoch 1
    join(alice, sg.share_keyring(owner, gid), device="Alice PC")
    join(bob, sg.share_keyring(alice, gid), device="Bob PC")
    sg.adopt_keyring(owner, gid, sg.share_keyring(bob, gid), _kdf_override=CHEAP)
    approve_all(owner, gid)
    for s in (alice, bob):
        sg.adopt_keyring(s, gid, sg.share_keyring(owner, gid), _kdf_override=CHEAP)
    bob_id = sg.share_state(bob, gid).device_id
    before = sg.share_keyring(owner, gid)

    def replay(ring):
        ring["members"] = [m for m in ring["members"] if m["device_id"] != bob_id]
        del ring["device_wraps"][bob_id]
        ring["owner_sig"], ring["content"] = old_sig, old_content

    forged = _forge(alice, gid, replay)
    for victim in (bob, owner, alice):
        with pytest.raises(kr.KeyringError) as err:
            sg.adopt_keyring(victim, gid, forged, _kdf_override=CHEAP)
        assert err.value.reason == "tampered"
    assert sg.share_keyring(owner, gid) == before
    assert {m.name: m.approved for m in sg.list_share_groups(owner)[0].members} == {
        "Owner PC": True, "Alice PC": True, "Bob PC": True}


def test_same_epoch_changes_to_wraps_keys_or_password_are_refused(tmp_path, pro):
    owner, alice, bob, group = _two_members(tmp_path)
    gid = group.group_id
    bob_id = sg.share_state(bob, gid).device_id
    other = kr.parse_keyring(sg.share_keyring(owner, gid))

    def swap_wrap(ring):  # alice replaces bob's wrap (locks bob out)
        ring["device_wraps"][bob_id] = dict(ring["device_wraps"][alice_id])

    def swap_password(ring):  # a password wrap only alice knows the password of
        ring["password_wrap"] = dict(other["password_wrap"], nonce=kr._b64e(b"\x00" * 12))

    def swap_key(ring):
        for m in ring["members"]:
            if m["device_id"] == bob_id:
                m["exchange_public"] = kr._b64e(kr.DeviceIdentity.generate().exchange_public_key)

    alice_id = sg.share_state(alice, gid).device_id
    for mutate in (swap_wrap, swap_password, swap_key):
        forged = _forge(alice, gid, mutate)
        with pytest.raises(kr.KeyringError) as err:
            sg.adopt_keyring(owner, gid, forged, _kdf_override=CHEAP)
        # Share v2: the owner signature covers the approved members' wraps and the password wrap.
        assert err.value.reason in ("tampered", "bad-member-proof", "bad-owner-sig"), mutate.__name__
    # A genuine join still grows the keyring and is accepted.
    carol = vault(tmp_path, "carol")
    join(carol, sg.share_keyring(owner, gid), device="Carol PC")
    grown = sg.adopt_keyring(owner, gid, sg.share_keyring(carol, gid), _kdf_override=CHEAP)
    assert [m.name for m in sg.pending_members(owner, gid)] == ["Carol PC"]
    assert len(grown.members) == 4


# --- Task 3: what the owner's member list shows ---------------------------------------------------------

def test_the_owner_sees_who_was_removed(tmp_path, pro):
    owner, member = vault(tmp_path, "owner"), vault(tmp_path, "member")
    group = share(owner, family(owner))
    join(member, sg.share_keyring(owner, group.group_id))
    sg.adopt_keyring(owner, group.group_id, sg.share_keyring(member, group.group_id), _kdf_override=CHEAP)
    assert sg.removed_members(owner, group.group_id) == ()
    gone = sg.pending_members(owner, group.group_id)[0].device_id
    sg.remove_member(owner, group.group_id, gone, new_password=PW2, now=1_800_000_000, _kdf_override=CHEAP)
    assert sg.removed_members(owner, group.group_id) == (("Member PC", 1_800_000_000),)
    # Kept in the encrypted record, validated like the rest of it.
    payload = owner._require_typed_catalog()
    record = payload[sg.STORE_KEY][group.group_id]
    for bad in ("x", [{"name": "A"}], [{"name": 3, "at": 1}], [{"name": "A", "at": -1, "x": 1}]):
        payload[sg.STORE_KEY][group.group_id] = {**record, "removed": bad}
        with pytest.raises(sg.ShareGroupError):
            sg.list_share_groups(owner)
    payload[sg.STORE_KEY][group.group_id] = record
    # The list is bounded: the oldest names go first.
    for n in range(sg.MAX_REMOVED + 3):
        sg._note_removed(record, [f"Old {n}"], n)
    assert len(record["removed"]) == sg.MAX_REMOVED and record["removed"][-1]["name"] == f"Old {sg.MAX_REMOVED + 2}"
