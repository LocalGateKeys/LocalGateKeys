"""Share v2: item views keyed to the devices the owner approved (spec 2026-11-12-collections-crypto-gating)."""
from __future__ import annotations

import copy
import json
import time

import pytest

from localvault import licensing
from localvault.collections import CollectionService
from localvault.item_service import ItemService
from localvault.sync import keyring as kr
from localvault.sync import share_group as sg
from localvault.sync.folder_transport import FolderSync
from localvault.sync.group import GroupKey, SyncFormatError, decode_view
from localvault.updates import canonical_json
from localvault.vault import create_vault

TEST_KDF = {"time_cost": 1, "memory_cost_kib": 8192, "parallelism": 1, "hash_len": 32}
CHEAP = (1024, 1, 1)
MASTER = "synthetic master"
PW = "correct horse battery staple 7!"
PW2 = "another very long passphrase 42?"


class _Lease:
    def check(self) -> None:
        pass


LEASE = _Lease()


@pytest.fixture
def pro(monkeypatch):
    monkeypatch.setattr(licensing, "item_limit", lambda st=None: None)


def vault(tmp_path, name):
    return create_vault(tmp_path / f"{name}.json", MASTER, kdf_overrides=TEST_KDF)


def items(session):
    return {i["id"]: i for i in session._payload.get("items", [])}


def kinds(report):
    return [i.kind for i in report.issues]


class Folder:
    """An owner and any number of people syncing one shared collection through one folder."""

    def __init__(self, tmp_path, *, version=2, monkeypatch=None):
        self.tmp = tmp_path
        self.folder = tmp_path / "share"
        self.folder.mkdir()
        self.owner = vault(tmp_path, "owner")
        self.cid = CollectionService(self.owner).create("Family")
        if version == 1:
            monkeypatch.setattr(sg, "_NEW_SHARE_FORMAT", 2)
        self.gid = sg.create_share_group(self.owner, self.cid, password=PW, device="Owner PC", shared_mode="edit",
                                         install_id="i-owner", _kdf_override=CHEAP).group_id
        if version == 1:
            monkeypatch.setattr(sg, "_NEW_SHARE_FORMAT", kr.SHARE_FORMAT)
        sg.set_share_folder(self.owner, self.gid, str(self.folder))
        self.installs = {id(self.owner): "i-owner"}
        self.now = int(time.time())
        self.run(self.owner)

    def fs(self, session):
        return FolderSync(self.folder, install_id=self.installs[id(session)], share=self.gid, _kdf_override=CHEAP)

    def run(self, session):
        self.now += 1
        return self.fs(session).run_once(session, LEASE, now=self.now)

    def join(self, name, password=PW):
        session = vault(self.tmp, name)
        self.installs[id(session)] = f"i-{name}"
        raw = self.fs(session).read_keyring_bytes()
        sg.join_share_group(session, raw, password=password, device=f"{name} PC", install_id=f"i-{name}",
                            _kdf_override=CHEAP)
        sg.set_share_folder(session, self.gid, str(self.folder))
        self.run(session)  # writes the grown keyring
        self.run(self.owner)  # adopts it
        return session

    def approve(self, session):
        sg.approve_members(self.owner, self.gid, [sg.share_state(session, self.gid).device_id], _kdf_override=CHEAP)
        self.run(self.owner)

    def own_view(self):
        dev = sg.share_state(self.owner, self.gid).device_id
        return dev, self.fs(self.owner).device_file(dev).read_bytes()


def test_the_share_password_alone_opens_no_item(tmp_path, pro):
    s = Folder(tmp_path)
    secret = ItemService(s.owner).create_note("Wifi", "family wifi secret", collection_ids=[s.cid])
    s.run(s.owner)
    joiner = s.join("eve")
    # Eve knows the share password, so she holds G, but the owner's view does not open with it.
    st = sg.share_state(joiner, s.gid)
    dev, raw = s.own_view()
    with pytest.raises(SyncFormatError):
        decode_view(GroupKey(st.group_id, st.epoch, st.key), raw, expected_device_id=dev)
    ring = kr.parse_keyring(sg.share_keyring(joiner, s.gid))
    assert ring["format"] == kr.SHARE_FORMAT and st.device_id not in ring["content"]["wraps"]
    assert sg.view_key(joiner, s.gid) is None
    assert "awaiting-approval" in kinds(s.run(joiner)) and secret not in items(joiner)
    # The owner lets her in: her content wrap opens the key the owner seals with, and the items flow.
    s.approve(joiner)
    s.run(joiner)
    assert sg.view_key(joiner, s.gid) == sg.view_key(s.owner, s.gid)
    assert items(joiner)[secret]["payload"]["body"] == "family wifi secret"
    assert sg.list_share_groups(joiner)[0].version == 2


def test_removal_draws_a_new_content_key_for_the_others_only(tmp_path, pro):
    s = Folder(tmp_path)
    ItemService(s.owner).create_note("A", "first", collection_ids=[s.cid])
    alice, bob = s.join("alice"), s.join("bob")
    s.approve(alice)
    s.approve(bob)
    for p in (alice, bob):
        s.run(p)
    old = sg.view_key(bob, s.gid)
    notice = sg.remove_member(s.owner, s.gid, sg.share_state(bob, s.gid).device_id, new_password=PW2,
                              _kdf_override=CHEAP)
    assert s.fs(s.owner).publish_share_notice(sg.share_state(bob, s.gid).device_id, notice)
    s.run(s.owner)
    s.run(alice)
    new = sg.view_key(alice, s.gid)
    assert new == sg.view_key(s.owner, s.gid) and new.epoch == old.epoch + 1 and new.key != old.key
    ring = kr.parse_keyring(sg.share_keyring(s.owner, s.gid))
    assert set(ring["content"]["wraps"]) == {sg.share_state(x, s.gid).device_id for x in (s.owner, alice)}
    later = ItemService(s.owner).create_note("B", "after bob left", collection_ids=[s.cid])
    s.run(s.owner)
    dev, raw = s.own_view()
    with pytest.raises(SyncFormatError):  # bob's old content key opens nothing of the new epoch
        decode_view(GroupKey(old.group_id, new.epoch, old.key), raw, expected_device_id=dev)
    s.run(alice)
    assert items(alice)[later]["payload"]["body"] == "after bob left"


def test_a_v1_share_keeps_syncing_until_the_owner_upgrades_it(tmp_path, pro, monkeypatch):
    s = Folder(tmp_path, version=1, monkeypatch=monkeypatch)
    a = ItemService(s.owner).create_note("A", "v1 text", collection_ids=[s.cid])
    member = s.join("member")
    s.approve(member)
    pending = s.join("pending")
    s.run(member)
    assert items(member)[a]["payload"]["body"] == "v1 text"
    assert kr.parse_keyring(sg.share_keyring(s.owner, s.gid))["format"] == 2
    assert sg.needs_upgrade(s.owner, s.gid) and not sg.needs_upgrade(member, s.gid)
    assert sg.list_share_groups(s.owner)[0].version == 1
    with pytest.raises(sg.ShareGroupError) as err:
        sg.upgrade_share(member, s.gid, password=PW, _kdf_override=CHEAP)
    assert err.value.reason == "not-owner"
    with pytest.raises(kr.WeakSyncPassword):
        sg.upgrade_share(s.owner, s.gid, password="short", _kdf_override=CHEAP)
    # The owner opens the share and upgrades it, keeping the share password.
    before = sg.share_state(s.owner, s.gid).epoch
    group = sg.upgrade_share(s.owner, s.gid, password=PW, _kdf_override=CHEAP)
    assert group.version == 2 and not sg.needs_upgrade(s.owner, s.gid)
    assert sg.share_state(s.owner, s.gid).epoch == before + 1
    assert {m.name: m.approved for m in group.members} == {"Owner PC": True, "member PC": True,
                                                            "pending PC": False}
    with pytest.raises(sg.ShareGroupError) as err:
        sg.upgrade_share(s.owner, s.gid, password=PW, _kdf_override=CHEAP)
    assert err.value.reason == "already-upgraded"
    s.run(s.owner)
    s.run(member)  # adopts epoch + 1 with its device wrap and opens its content wrap
    assert sg.view_key(member, s.gid) == sg.view_key(s.owner, s.gid)
    ItemService(member).update_item(a, body="v2 edit")
    s.run(member)
    s.run(s.owner)
    assert items(s.owner)[a]["payload"]["body"] == "v2 edit"
    # The pending member follows the rotation but still opens nothing.
    assert "awaiting-approval" in kinds(s.run(pending)) and sg.view_key(pending, s.gid) is None
    # The same password still lets new people join (pending, as always).
    s.join("late")


def test_removing_from_a_v1_share_upgrades_it(tmp_path, pro, monkeypatch):
    s = Folder(tmp_path, version=1, monkeypatch=monkeypatch)
    alice, bob = s.join("alice"), s.join("bob")
    s.approve(alice)
    s.approve(bob)
    sg.remove_member(s.owner, s.gid, sg.share_state(bob, s.gid).device_id, new_password=PW2, _kdf_override=CHEAP)
    ring = kr.parse_keyring(sg.share_keyring(s.owner, s.gid))
    assert ring["format"] == kr.SHARE_FORMAT
    assert set(ring["content"]["wraps"]) == {sg.share_state(x, s.gid).device_id for x in (s.owner, alice)}
    s.run(s.owner)
    s.run(alice)
    assert sg.view_key(alice, s.gid) == sg.view_key(s.owner, s.gid)


def test_a_newer_keyring_format_asks_for_an_update_and_is_never_overwritten(tmp_path, pro):
    s = Folder(tmp_path)
    member = s.join("member")
    s.approve(member)
    s.run(member)
    path = s.fs(s.owner).keyring_path
    newer = json.loads(path.read_bytes())
    newer["format"] = 4
    raw = canonical_json(newer)
    path.write_bytes(raw)
    with pytest.raises(kr.KeyringError) as err:
        kr.verify_keyring_structure(newer, _kdf_override=CHEAP)
    assert err.value.reason == "newer-format"
    for who in (s.owner, member):
        assert kinds(s.run(who)) == ["update-required"]
        assert path.read_bytes() == raw


def test_content_wraps_cannot_change_within_an_epoch(tmp_path, pro):
    s = Folder(tmp_path)
    alice, bob = s.join("alice"), s.join("bob")
    s.approve(alice)
    s.run(alice)
    stored = kr.parse_keyring(sg.share_keyring(alice, s.gid))
    # Alice (holding G) swaps her own wrap for one of a key she picked: MAC fine, owner signature not.
    st = sg.share_state(alice, s.gid)
    forged = copy.deepcopy(stored)
    fake = kr.GroupKey(st.group_id, st.epoch, bytes(range(32)))
    forged["content"]["wraps"][st.device_id] = kr._wrap_content(fake, st.device_id,
                                                               kr._b64e(st.identity().exchange_public_key))
    forged = kr._finish(forged, GroupKey(st.group_id, st.epoch, st.key), None, forged["prev_mac"])
    with pytest.raises(kr.KeyringError) as err:
        sg.adopt_keyring(bob, s.gid, canonical_json(forged), _kdf_override=CHEAP)
    assert err.value.reason == "bad-owner-sig"
    # A wrong commitment in a keyring the device already trusts is refused when the key is opened.
    bad = copy.deepcopy(stored)
    bad["content"]["commit"] = kr._b64e(bytes(32))
    with pytest.raises(kr.KeyringError) as err:
        kr.open_content_key(bad, st.identity())
    assert err.value.reason == "content-key"


def test_keyring_level_upgrade_and_formats():
    from localvault.sync.pairing import DeviceIdentity

    a, b = DeviceIdentity.generate(), DeviceIdentity.generate()
    spec = {"kind": "share", "collection_id": "0b9a3c7e-2f4d-4c1a-9e5b-1d2c3b4a5f60", "name": "Family",
            "shared_mode": "read"}
    v1, gk = kr.create_group(PW, a, "A", metadata=spec, share_format=2, _kdf_override=CHEAP)
    assert v1["format"] == 2 and kr.share_version(v1) == 1
    joined, _ = kr.join_with_password(v1, PW, b, "B", _kdf_override=CHEAP)
    approved = kr.owner_approve_members(joined, gk, a, _kdf_override=CHEAP)
    with pytest.raises(kr.KeyringError) as err:
        kr.upgrade_share_keyring(approved, gk, b, PW, _kdf_override=CHEAP)
    assert err.value.reason == "not-owner"
    v2, gk2 = kr.upgrade_share_keyring(approved, gk, a, PW, _kdf_override=CHEAP)
    assert v2["format"] == kr.SHARE_FORMAT and kr.share_version(v2) == 2 and gk2.epoch == gk.epoch + 1
    assert kr.accept_keyring(v2, gk, b, _kdf_override=CHEAP) == gk2
    assert kr.open_content_key(v2, a) == kr.open_content_key(v2, b) != gk2
    with pytest.raises(kr.KeyringError) as err:
        kr.upgrade_share_keyring(v2, gk2, a, PW, _kdf_override=CHEAP)
    assert err.value.reason == "already-v2"
    # A plain rotation keeps the version; a personal keyring cannot be upgraded.
    assert kr.rotate(approved, gk, a, PW2, _kdf_override=CHEAP)[0]["format"] == 2
    personal, pgk = kr.create_group(PW, a, "A", _kdf_override=CHEAP)
    with pytest.raises(kr.KeyringError) as err:
        kr.upgrade_share_keyring(personal, pgk, a, PW, _kdf_override=CHEAP)
    assert err.value.reason == "not-share"
    # Format 3 without the share fields, and format 2 with a content block, are malformed.
    with pytest.raises(kr.KeyringError) as err:
        kr.verify_keyring_structure({**personal, "format": 3}, _kdf_override=CHEAP)
    assert err.value.reason == "bad-fields"
    with pytest.raises(kr.KeyringError) as err:
        kr.verify_keyring_structure({**approved, "content": v2["content"]}, _kdf_override=CHEAP)
    assert err.value.reason == "bad-fields"


# --- audit 2026-11-12 F-01: the owner signature binds G (device wraps, password wrap, kdf, prev_mac) ----------

def _people():
    from localvault.sync.pairing import DeviceIdentity

    a, b, c = DeviceIdentity.generate(), DeviceIdentity.generate(), DeviceIdentity.generate()
    spec = {"kind": "share", "collection_id": "0b9a3c7e-2f4d-4c1a-9e5b-1d2c3b4a5f60", "name": "Family",
            "shared_mode": "edit"}
    ring, gk = kr.create_group(PW, a, "A", metadata=spec, _kdf_override=CHEAP)
    ring, _ = kr.join_with_password(ring, PW, b, "B", _kdf_override=CHEAP)
    ring, _ = kr.join_with_password(ring, PW, c, "C", _kdf_override=CHEAP)
    return a, b, c, ring, gk


def _fork(genuine, old_gk):
    """What a removed member holding the old G writes: the owner's signature over wraps of a key it picked."""
    g_star = GroupKey(genuine["group_id"], genuine["epoch"], bytes(range(32)))
    forged = copy.deepcopy(genuine)
    salt = bytes(16)
    forged["kdf"]["salt"] = kr._b64e(salt)
    forged["password_wrap"] = kr._wrap_password(g_star, "attacker chosen password 99!", salt, CHEAP)
    for m in forged["members"]:
        forged["device_wraps"][m["device_id"]] = kr._wrap_device(g_star, m["device_id"],
                                                                 kr._b64d(m["exchange_public"], 32, "x"))
    return kr._finish(forged, g_star, old_gk), g_star


@pytest.mark.parametrize("victim_approved", [True, False])
def test_a_removed_member_cannot_fork_the_next_epoch_with_the_owners_signature(victim_approved):
    a, b, c, ring, gk1 = _people()
    ring = kr.owner_approve_members(ring, gk1, a, approve=[b.device_id] + ([c.device_id] if victim_approved else []),
                                    _kdf_override=CHEAP)
    genuine, gk2 = kr.rotate(ring, gk1, a, PW2, remove=[b.device_id], _kdf_override=CHEAP)
    assert kr.accept_keyring(genuine, gk1, c, _kdf_override=CHEAP) == gk2
    forged, g_star = _fork(genuine, gk1)
    # Every check but the owner signature passes: C's wrap opens B's key, the chain MAC verifies under the old
    # G (B knows it) and the MAC under B's key.  Before the fix C adopted it.
    assert kr._unwrap_device(forged, c) == g_star
    assert kr._chain_ok(forged["prev_mac"], gk1, g_star)
    assert kr._mac_ok(forged["mac"], g_star.key, g_star.group_id, g_star.epoch, forged)
    with pytest.raises(kr.KeyringError) as err:
        kr.accept_keyring(forged, gk1, c, _kdf_override=CHEAP)
    assert err.value.reason == "bad-owner-sig"
    # A fork that keeps the genuine prev_mac (or C's genuine wrap) fails the chain or the MAC instead.
    kept = kr._finish({**forged, "prev_mac": genuine["prev_mac"]}, g_star, None, genuine["prev_mac"])
    with pytest.raises(kr.KeyringError):
        kr.accept_keyring(kept, gk1, c, _kdf_override=CHEAP)


@pytest.mark.parametrize("field", ["kdf", "password_wrap", "approved_device_wrap", "prev_mac"])
def test_each_g_bound_field_is_covered_by_the_owner_signature(field):
    a, b, c, ring, gk1 = _people()
    ring = kr.owner_approve_members(ring, gk1, a, approve=[b.device_id, c.device_id], _kdf_override=CHEAP)
    genuine, gk2 = kr.rotate(ring, gk1, a, PW2, remove=[b.device_id], _kdf_override=CHEAP)
    changed = copy.deepcopy(genuine)
    if field == "kdf":
        changed["kdf"]["salt"] = kr._b64e(bytes(16))
    elif field == "password_wrap":
        changed["password_wrap"]["nonce"] = kr._b64e(bytes(12))
    elif field == "approved_device_wrap":
        changed["device_wraps"][c.device_id] = changed["device_wraps"][a.device_id]
    else:
        changed["prev_mac"] = kr._b64e(bytes(32))
    # Re-MACed with the genuine new key: only the owner signature can catch the change.
    changed = kr._finish(changed, gk2, None, changed["prev_mac"])
    with pytest.raises(kr.KeyringError) as err:
        kr.verify_keyring_structure(changed, _kdf_override=CHEAP)
    assert err.value.reason == "bad-owner-sig"


def test_a_password_join_keeps_the_owner_signature_and_a_v1_relabel_is_refused():
    a, b, c, ring, gk1 = _people()
    ring = kr.owner_approve_members(ring, gk1, a, approve=[b.device_id, c.device_id], _kdf_override=CHEAP)
    genuine, gk2 = kr.rotate(ring, gk1, a, PW2, remove=[b.device_id], _kdf_override=CHEAP)
    from localvault.sync.pairing import DeviceIdentity

    joined, _ = kr.join_with_password(genuine, PW2, DeviceIdentity.generate(), "D", _kdf_override=CHEAP)
    assert joined["owner_sig"] == genuine["owner_sig"]
    kr.verify_keyring_structure(joined, _kdf_override=CHEAP)
    # Downgrade: the fork relabelled as share v1 (whose owner message does not bind G) needs an owner v1
    # signature over epoch 2 that the owner never made.
    forged, g_star = _fork(genuine, gk1)
    as_v1 = kr._finish({**{k: v for k, v in forged.items() if k != "content"}, "format": 2}, g_star, None,
                       forged["prev_mac"])
    with pytest.raises(kr.KeyringError) as err:
        kr.accept_keyring(as_v1, gk1, c, _kdf_override=CHEAP)
    assert err.value.reason == "bad-owner-sig"


def test_an_offline_member_refuses_the_fork_and_follows_the_owners_rotation(tmp_path, pro):
    s = Folder(tmp_path)
    ItemService(s.owner).create_note("A", "before", collection_ids=[s.cid])
    alice, bob = s.join("alice"), s.join("bob")
    s.approve(alice)
    s.approve(bob)
    for p in (alice, bob):
        s.run(p)
    bob_state = sg.share_state(bob, s.gid)
    old = GroupKey(bob_state.group_id, bob_state.epoch, bob_state.key)
    sg.remove_member(s.owner, s.gid, bob_state.device_id, new_password=PW2, _kdf_override=CHEAP)
    s.run(s.owner)
    # Alice was offline.  Bob, removed but still able to write the folder, replaces the new keyring.
    path = s.fs(s.owner).keyring_path
    forged, _ = _fork(kr.parse_keyring(path.read_bytes()), old)
    path.write_bytes(canonical_json(forged))
    s.run(alice)
    assert sg.share_state(alice, s.gid).epoch == old.epoch  # the fork was not adopted
    assert "keyring-restored" in kinds(s.run(s.owner))
    s.run(alice)
    assert sg.view_key(alice, s.gid) == sg.view_key(s.owner, s.gid)
    assert sg.share_state(alice, s.gid).epoch == old.epoch + 1


def test_gating_vectors_are_current(tmp_path):
    """``gating.json`` (read by lgk-core and LGKCore) is exactly what the desktop writes today."""
    import importlib.util
    from pathlib import Path

    root = Path(__file__).resolve().parent.parent
    spec = importlib.util.spec_from_file_location("make_share_gating_vectors",
                                                  root / "scripts/make_share_gating_vectors.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    (written,) = module.generate(tmp_path)
    assert written.read_bytes() == (root / "tests/vectors/share/collections/gating.json").read_bytes()
