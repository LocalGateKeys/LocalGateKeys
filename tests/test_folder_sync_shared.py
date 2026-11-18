"""A share group syncing through its own cloud folder (sub-plan 07 Task 2): ``FolderSync(share=...)``."""
from __future__ import annotations

import time

import pytest

from localvault import licensing
from localvault.collections import CollectionService
from localvault.item_service import ItemService
from localvault.sync import share_group as sg
from localvault.sync.engine import ItemState
from localvault.sync.folder_transport import FolderSync
from localvault.sync.group import GroupKey, decode_view
from localvault.sync.vault_bridge import load_sync_state
from localvault.vault import create_vault

TEST_KDF = {"time_cost": 1, "memory_cost_kib": 8192, "parallelism": 1, "hash_len": 32}
CHEAP = (1024, 1, 1)
MASTER = "synthetic master"
PW = "correct horse battery staple 7!"
PW2 = "another very long passphrase 42?"


class FakeLease:
    def check(self) -> None:
        pass


LEASE = FakeLease()


@pytest.fixture
def pro(monkeypatch):
    class Switch:
        on = True

    switch = Switch()
    monkeypatch.setattr(licensing, "item_limit", lambda st=None: None if switch.on else licensing.FREE_ITEM_LIMIT)
    return switch


def vault(tmp_path, name):
    return create_vault(tmp_path / f"{name}.json", MASTER, kdf_overrides=TEST_KDF)


def items(session):
    return {i["id"]: i for i in session._payload.get("items", [])}


def trash_ids(session):
    return {r["entry"]["id"] for r in session._payload.get("trash", [])}


class Share:
    """Owner and member, each with its own vault, syncing one share group through *folder*."""

    def __init__(self, tmp_path, mode="edit"):
        self.folder = tmp_path / "Family share"
        self.folder.mkdir()
        self.owner = vault(tmp_path, "owner")
        self.cid = CollectionService(self.owner).create("Family")
        self.gid = sg.create_share_group(self.owner, self.cid, password=PW, device="Owner PC", shared_mode=mode,
                                         install_id="install-owner", _kdf_override=CHEAP).group_id
        sg.set_share_folder(self.owner, self.gid, str(self.folder))
        self.member = vault(tmp_path, "member")
        self.now = int(time.time())

    def fs(self, session):
        install = "install-owner" if session is self.owner else "install-member"
        return FolderSync(self.folder, install_id=install, share=self.gid, _kdf_override=CHEAP)

    def run(self, session):
        self.now += 1
        return self.fs(session).run_once(session, LEASE, now=self.now)

    def join(self):
        self.run(self.owner)  # writes the keyring into the folder
        raw = self.fs(self.member).read_keyring_bytes()
        sg.join_share_group(self.member, raw, password=PW, device="Member PC", install_id="install-member",
                            _kdf_override=CHEAP)
        sg.set_share_folder(self.member, self.gid, str(self.folder))
        self.run(self.member)  # writes the grown keyring
        self.run(self.owner)  # adopts it
        sg.approve_members(self.owner, self.gid, [m.device_id for m in sg.pending_members(self.owner, self.gid)],
                           _kdf_override=CHEAP)
        self.run(self.owner)  # writes the approved keyring
        self.run(self.member)  # adopts it

    @property
    def owner_dev(self):
        return sg.share_state(self.owner, self.gid).device_id

    @property
    def member_dev(self):
        return sg.share_state(self.member, self.gid).device_id


def kinds(report):
    return [i.kind for i in report.issues]


def test_items_of_the_shared_collection_flow_both_ways_through_the_folder(tmp_path, pro):
    s = Share(tmp_path)
    a = ItemService(s.owner).create_note("A", "family wifi", collection_ids=[s.cid])
    private = ItemService(s.owner).create_note("Private", "my diary")
    s.owner.upsert_web(origin="https://bank.example", username="me", password="bank-password-1")
    s.join()
    report = s.run(s.member)
    assert "not-joined" not in kinds(report)
    assert items(s.member)[a]["payload"]["body"] == "family wifi"
    assert private not in items(s.member) and not s.member._payload.get("entries")
    # The owner's file in the folder holds exactly the shared item.
    gk = sg.view_key(s.owner, s.gid)
    raw = s.fs(s.owner).device_file(s.owner_dev).read_bytes()
    view = decode_view(gk, raw, expected_device_id=s.owner_dev)
    assert [st.item_id for st in view.states] == [a]
    assert b"my diary" not in raw and b"bank-password-1" not in raw

    ItemService(s.member).update_item(a, body="new wifi password")
    s.run(s.member)
    s.run(s.owner)
    assert items(s.owner)[a]["payload"]["body"] == "new wifi password"
    # The personal device-sync group was never created or touched.
    assert load_sync_state(s.owner) is None and load_sync_state(s.member) is None


@pytest.mark.parametrize("mode", ["read", "edit"])
def test_read_only_share_ignores_a_members_forged_view(tmp_path, pro, mode):
    s = Share(tmp_path, mode)
    a = ItemService(s.owner).create_note("A", "owner text", collection_ids=[s.cid])
    s.join()
    s.run(s.member)
    assert items(s.member)[a]["payload"]["body"] == "owner text"
    # The member (holding the content key and its own signing key) publishes an edit anyway.
    st = sg.share_state(s.member, s.gid)
    gk = sg.view_key(s.member, s.gid)
    record = dict(items(s.member)[a])
    record.pop("revision")
    record["payload"] = {**record["payload"], "body": "member tampered"}
    record["collection_ids"] = [s.cid]
    forged = ItemState(a, {st.device_id: 50, s.owner_dev: 50}, False, None,
                       {"ns": "item", "schema": 1, "updated_at": record["updated_at"] + 10,
                        "record": {**record, "updated_at": record["updated_at"] + 10}})
    s.fs(s.member).write_own(gk, st.device_id, [forged], st.own_counter + 5, now=s.now + 1,
                             signing_key=st.identity().signing_key)
    s.run(s.owner)
    # Read-only: the owner never merges a member's view.  (Edit: the same view is a member's edit.)
    assert items(s.owner)[a]["payload"]["body"] == ("owner text" if mode == "read" else "member tampered")


def test_owner_removes_a_member_who_loses_the_shared_items_only(tmp_path, pro):
    s = Share(tmp_path)
    a = ItemService(s.owner).create_note("A", "shared", collection_ids=[s.cid])
    s.join()
    s.run(s.member)
    assert a in items(s.member)
    personal = ItemService(s.member).create_note("Mine", "member diary")
    member_dev = s.member_dev
    notice = sg.remove_member(s.owner, s.gid, member_dev, new_password=PW2, _kdf_override=CHEAP)
    assert s.fs(s.owner).publish_share_notice(member_dev, notice)
    s.run(s.owner)  # writes the rotated keyring
    report = s.run(s.member)
    assert kinds(report) == ["share-removed"]
    assert a in trash_ids(s.member) and a not in items(s.member)
    assert set(items(s.member)) == {personal}
    assert sg.list_share_groups(s.member) == []
    assert a in items(s.owner)


def test_rotation_without_a_notice_only_stops_the_member(tmp_path, pro):
    s = Share(tmp_path)
    a = ItemService(s.owner).create_note("A", "shared", collection_ids=[s.cid])
    s.join()
    s.run(s.member)
    sg.remove_member(s.owner, s.gid, s.member_dev, new_password=PW2, _kdf_override=CHEAP)
    s.run(s.owner)
    report = s.run(s.member)
    assert kinds(report) == ["rejoin-required"]
    assert a in items(s.member)


def test_share_run_needs_pro_and_writes_no_view_without_it(tmp_path, pro):
    s = Share(tmp_path)
    pro.on = False
    report = s.run(s.owner)
    assert kinds(report) == ["pro-required"]
    # Only the keyring step runs without Pro (final review A2): the keyring is written, no view.
    fs = s.fs(s.owner)
    assert [p for p in s.folder.rglob("*") if p.is_file()] == [fs.keyring_path]
    assert not fs.device_file(s.owner_dev).exists() and report.own_states is None and not report.wrote
    assert s.fs(s.owner).licence_round(s.owner, LEASE, now=s.now).licenses == ()


def test_a_member_never_writes_over_another_groups_keyring_and_the_owner_restores_its_own(tmp_path, pro):
    # Final review finding 1: anyone who can write to the folder could put another group's keyring
    # there and stop everyone.  The owner's device writes its trusted keyring back; a member's
    # never writes over another group's keyring and waits for the owner.
    s = Share(tmp_path)
    a = ItemService(s.owner).create_note("A", "shared", collection_ids=[s.cid])
    s.join()
    other = vault(tmp_path, "other")
    ocid = CollectionService(other).create("Other")
    ogid = sg.create_share_group(other, ocid, password=PW, device="Other PC", _kdf_override=CHEAP).group_id
    foreign = sg.share_keyring(other, ogid)
    fs = s.fs(s.owner)
    fs.keyring_path.write_bytes(foreign)
    assert kinds(s.run(s.member)) == ["folder-has-other-group"]
    assert fs.keyring_path.read_bytes() == foreign
    # Said apart from a plain repair (final review A1), so two owners in one folder show up.
    assert "other-group-replaced" in kinds(s.run(s.owner))
    assert fs.keyring_path.read_bytes() == sg.share_keyring(s.owner, s.gid)
    assert kinds(s.run(s.member)) == []
    assert items(s.member)[a]["payload"]["body"] == "shared"


def test_share_folder_refuses_a_malformed_group_id(tmp_path):
    with pytest.raises(ValueError):
        FolderSync(tmp_path, install_id="install", share="../x")


def test_the_sync_service_runs_share_groups_beside_device_sync(tmp_path, pro):
    from localvault.sync import service as svc

    s = Share(tmp_path)
    a = ItemService(s.owner).create_note("A", "shared", collection_ids=[s.cid])
    s.join()

    class Clock:
        def __call__(self):
            return float(s.now + 10)

    class Worker:
        def submit(self, fn):
            fn()

    service = svc.SyncService(s.member, LEASE, install_id="install-member", transports=[], clock=Clock(),
                              scheduler=None, worker=Worker())
    service._run_once()
    assert items(s.member)[a]["payload"]["body"] == "shared"
    shares = service.status().shares
    assert [t.name for t in shares] == [s.gid] and shares[0].last_sync is not None
    assert not service.status().issues, "share issues stay out of the device-sync status"
    # A device without Pro never runs a share (the owner's newer edit stays in the folder).
    ItemService(s.owner).update_item(a, body="v2")
    s.run(s.owner)
    pro.on = False
    service._run_once()
    assert items(s.member)[a]["payload"]["body"] == "shared"


# --- fix round 1 -------------------------------------------------------------------------------------

def _fs(s, session, install):
    return FolderSync(s.folder, install_id=install, share=s.gid, _kdf_override=CHEAP)


def _join(s, session, name, install):
    raw = _fs(s, session, install).read_keyring_bytes()
    sg.join_share_group(session, raw, password=PW, device=name, install_id=install, _kdf_override=CHEAP)
    sg.set_share_folder(session, s.gid, str(s.folder))


def _run(s, session, install):
    s.now += 1
    return _fs(s, session, install).run_once(session, LEASE, now=s.now)


def test_a_join_racing_the_owners_approval_is_merged_not_frozen(tmp_path, pro):
    s = Share(tmp_path)
    a = ItemService(s.owner).create_note("A", "shared", collection_ids=[s.cid])
    j1, j2 = s.member, vault(tmp_path, "second")
    s.run(s.owner)
    _join(s, j1, "J1", "install-member")
    _run(s, j1, "install-member")
    s.run(s.owner)  # adopts J1's join
    _join(s, j2, "J2", "install-j2")  # J2 joins from the folder before the owner's approval is written
    _run(s, j2, "install-j2")
    sg.approve_members(s.owner, s.gid, [sg.share_state(j1, s.gid).device_id], _kdf_override=CHEAP)
    report = s.run(s.owner)
    assert "keyring-merged" in kinds(report) and "tampered" not in kinds(report)
    pending = [m.name for m in sg.pending_members(s.owner, s.gid)]
    assert pending == ["J2"], "the new joiner stays pending"
    for session, install in ((j1, "install-member"), (j2, "install-j2")):
        assert "tampered" not in kinds(_run(s, session, install))
    assert "tampered" not in kinds(s.run(s.owner))
    assert items(j1)[a]["payload"]["body"] == "shared"
    # J2 receives the share once the owner approves it too.
    sg.approve_members(s.owner, s.gid, [sg.share_state(j2, s.gid).device_id], _kdf_override=CHEAP)
    s.run(s.owner)
    _run(s, j2, "install-j2")
    assert items(j2)[a]["payload"]["body"] == "shared"


def test_two_people_joining_at_once_tells_the_superseded_joiner_to_join_again(tmp_path, pro):
    # The owner and the winner go on; the joiner whose join was lost is told "superseded" (join
    # again), not the attack-like "tampered", and joining again with the password lets it in.
    s = Share(tmp_path)
    a = ItemService(s.owner).create_note("A", "shared", collection_ids=[s.cid])
    j1, j2 = s.member, vault(tmp_path, "second")
    s.run(s.owner)
    _join(s, j1, "J1", "install-member")
    _join(s, j2, "J2", "install-j2")  # both read the same keyring
    _run(s, j1, "install-member")
    report = _run(s, j2, "install-j2")
    assert "superseded" in kinds(report) and "tampered" not in kinds(report)
    assert "tampered" not in kinds(s.run(s.owner))
    assert [m.name for m in sg.pending_members(s.owner, s.gid)] == ["J1"]
    # Join again: the same group and collection, a new place in the folder keyring.
    _join(s, j2, "J2", "install-j2")
    assert [g.group_id for g in sg.list_share_groups(j2)] == [s.gid]
    assert not {"superseded", "tampered"} & set(kinds(_run(s, j2, "install-j2")))
    s.run(s.owner)
    assert sorted(m.name for m in sg.pending_members(s.owner, s.gid)) == ["J1", "J2"]
    sg.approve_members(s.owner, s.gid, [m.device_id for m in sg.pending_members(s.owner, s.gid)],
                       _kdf_override=CHEAP)
    s.run(s.owner)
    _run(s, j2, "install-j2")
    assert items(j2)[a]["payload"]["body"] == "shared"


def test_a_keyring_that_drops_another_member_is_not_called_superseded(tmp_path, pro):
    # Only a lost join of this very device is "superseded"; a folder keyring that also drops an
    # earlier joiner (J1) is still refused as tampered, and joining again is refused too.
    s = Share(tmp_path)
    j1, j2, j3 = s.member, vault(tmp_path, "second"), vault(tmp_path, "third")
    s.run(s.owner)
    base = _fs(s, s.owner, "install-owner").read_keyring_bytes()
    _join(s, j1, "J1", "install-member")
    _run(s, j1, "install-member")  # the folder holds owner + J1
    _join(s, j2, "J2", "install-j2")  # J2 joins from owner + J1
    sg.join_share_group(j3, base, password=PW, device="J3", install_id="install-j3", _kdf_override=CHEAP)
    _fs(s, j3, "install-j3").keyring_path.write_bytes(sg.share_keyring(j3, s.gid))  # owner + J3: J1 gone
    report = _run(s, j2, "install-j2")
    assert "superseded" not in kinds(report) and "tampered" in kinds(report)
    assert sg.superseded_join(j2, s.gid, sg.share_keyring(j3, s.gid)) is False
    assert sg.superseded_join(s.owner, s.gid, sg.share_keyring(j3, s.gid)) is False  # never on the owner


def test_share_keyring_io_runs_with_the_ui_released(tmp_path, pro):
    from localvault.sync import service as svc

    class Gate:
        released: list = []

        def ui_released(self):
            import contextlib

            @contextlib.contextmanager
            def cm():
                Gate.released.append(True)
                yield
            return cm()

    s = Share(tmp_path)
    fs = s.fs(s.owner)
    svc._release_folder_io(fs, Gate(), LEASE, svc.SHARE_FOLDER_IO_STEPS)
    fs.run_once(s.owner, LEASE, now=s.now + 1)
    assert fs.keyring_path.exists() and len(Gate.released) >= 3
    for name in ("read_keyring_bytes", "write_keyring", "_read_share_notice"):
        assert name in svc.SHARE_FOLDER_IO_STEPS and getattr(fs, name).__name__ == "call"


# --- final fix wave A: finding 1 (anyone with folder access froze the share) ------------------------------

def _flip_password_wrap(path):
    """No group key needed: change one byte of ``password_wrap.ct`` (the MAC then fails)."""
    import base64
    import json

    from localvault.updates import canonical_json

    ring = json.loads(path.read_bytes())
    ct = bytearray(base64.b64decode(ring["password_wrap"]["ct"]))
    ct[0] ^= 1
    ring["password_wrap"]["ct"] = base64.b64encode(bytes(ct)).decode()
    path.write_bytes(canonical_json(ring))


def _owner_edits_and_member_receives(s, a, body):
    ItemService(s.owner).update_item(a, body=body)
    s.run(s.owner)
    s.run(s.member)
    return items(s.member)[a]["payload"]["body"] == body


def test_a_flipped_byte_in_the_password_wrap_is_restored_by_the_owner_then_the_share_syncs(tmp_path, pro):
    s = Share(tmp_path)
    a = ItemService(s.owner).create_note("A", "v1", collection_ids=[s.cid])
    s.join()
    trusted = sg.share_keyring(s.owner, s.gid)
    _flip_password_wrap(s.fs(s.owner).keyring_path)
    report = s.run(s.owner)
    assert "keyring-restored" in kinds(report) and "tampered" not in kinds(report)
    assert s.fs(s.owner).keyring_path.read_bytes() == trusted
    assert kinds(s.run(s.member)) == []
    assert _owner_edits_and_member_receives(s, a, "v2")


def test_a_member_restores_a_keyring_of_its_epoch_that_does_not_authenticate(tmp_path, pro):
    s = Share(tmp_path)
    a = ItemService(s.owner).create_note("A", "v1", collection_ids=[s.cid])
    s.join()
    _flip_password_wrap(s.fs(s.member).keyring_path)
    report = s.run(s.member)  # the member runs first
    assert "keyring-restored" in kinds(report) and "tampered" not in kinds(report)
    assert s.fs(s.member).keyring_path.read_bytes() == sg.share_keyring(s.owner, s.gid)
    assert "tampered" not in kinds(s.run(s.owner))
    assert _owner_edits_and_member_receives(s, a, "v2")


def test_the_owner_restores_over_bytes_that_do_not_parse_or_a_forged_later_epoch(tmp_path, pro):
    import json

    from localvault.updates import canonical_json

    s = Share(tmp_path)
    a = ItemService(s.owner).create_note("A", "v1", collection_ids=[s.cid])
    s.join()
    path = s.fs(s.owner).keyring_path
    trusted = sg.share_keyring(s.owner, s.gid)
    for garbage in (b"{}", b"not json", canonical_json({"group_id": "x"})):
        path.write_bytes(garbage)
        # A member cannot tell what the folder should hold: it stops and writes nothing.
        assert kinds(s.run(s.member)) in (["keyring-corrupt"], ["folder-has-other-group"])
        assert path.read_bytes() == garbage
        # A keyring naming another group is said apart (final review A1).
        expected = "other-group-replaced" if garbage.startswith(b'{"group_id"') else "keyring-restored"
        assert expected in kinds(s.run(s.owner))
        assert path.read_bytes() == trusted
    # A later epoch nobody but the owner could sign (the owner signature covers the epoch).
    ring = json.loads(trusted)
    ring["epoch"] += 5
    path.write_bytes(canonical_json(ring))
    report = s.run(s.owner)
    assert "keyring-restored" in kinds(report) and "rejoin-required" not in kinds(report)
    assert path.read_bytes() == trusted
    assert _owner_edits_and_member_receives(s, a, "v2")


def test_a_members_rewrite_of_the_password_wrap_is_restored_by_any_device(tmp_path, pro):
    # A member holds G and can re-MAC a keyring that swaps the password wrap.  In share v2 the owner
    # signature covers the password wrap (audit 2026-11-12 F-01), so that keyring does not authenticate:
    # a member's run puts its trusted keyring back, and so does the owner's.
    import base64
    import json

    from localvault.sync import keyring as kr
    from localvault.updates import canonical_json

    s = Share(tmp_path)
    a = ItemService(s.owner).create_note("A", "v1", collection_ids=[s.cid])
    s.join()
    st = sg.share_state(s.member, s.gid)
    path = s.fs(s.member).keyring_path
    ring = json.loads(path.read_bytes())
    gk = GroupKey(st.group_id, st.epoch, st.key)
    salt = base64.b64decode(ring["kdf"]["salt"])
    params = (ring["kdf"]["memory_kib"], ring["kdf"]["iterations"], ring["kdf"]["parallelism"])
    ring["password_wrap"] = kr._wrap_password(gk, "attacker chosen password 99!", salt, params)
    forged = canonical_json(kr._finish(ring, gk, None, ring["prev_mac"]))
    path.write_bytes(forged)
    with pytest.raises(kr.KeyringError) as err:
        kr.verify_keyring_structure(json.loads(forged), _kdf_override=CHEAP)
    assert err.value.reason == "bad-owner-sig"
    assert "keyring-restored" in kinds(s.run(s.member))
    assert path.read_bytes() == sg.share_keyring(s.member, s.gid)
    path.write_bytes(forged)
    assert "keyring-restored" in kinds(s.run(s.owner))
    assert path.read_bytes() == sg.share_keyring(s.owner, s.gid)
    assert _owner_edits_and_member_receives(s, a, "v2")


# --- final fix wave A: finding 2 (a pending member got every item before approval) -------------------------

@pytest.mark.parametrize("mode", ["read", "edit"])
def test_a_pending_member_adopts_the_keyring_but_merges_and_writes_nothing_until_approved(tmp_path, pro, mode):
    s = Share(tmp_path, mode=mode)
    a = ItemService(s.owner).create_note("A", "family wifi", collection_ids=[s.cid])
    s.run(s.owner)
    raw = s.fs(s.member).read_keyring_bytes()
    sg.join_share_group(s.member, raw, password=PW, device="Member PC", install_id="install-member",
                        _kdf_override=CHEAP)
    sg.set_share_folder(s.member, s.gid, str(s.folder))
    mine = ItemService(s.member).create_note("M", "member text", collection_ids=[s.cid]) if mode == "edit" else None
    report = s.run(s.member)
    assert "awaiting-approval" in kinds(report) and report.own_states is None and not report.wrote
    assert a not in items(s.member), "nothing of the owner's arrives before approval"
    assert not s.fs(s.member).device_file(s.member_dev).exists(), "no own view before approval"
    s.run(s.owner)  # adopts the join (pending)
    assert [m.name for m in sg.pending_members(s.owner, s.gid)] == ["Member PC"]
    assert mine not in items(s.owner)
    # The keyring is still adopted while pending (here: the owner's approval of someone else would be).
    assert sg.share_state(s.member, s.gid).keyring == sg.share_keyring(s.owner, s.gid)
    sg.approve_members(s.owner, s.gid, [s.member_dev], _kdf_override=CHEAP)
    s.run(s.owner)
    report = s.run(s.member)
    assert "awaiting-approval" not in kinds(report)
    assert items(s.member)[a]["payload"]["body"] == "family wifi"
    if mode == "edit":
        s.run(s.owner)
        assert items(s.owner)[mine]["payload"]["body"] == "member text"


# --- final fix wave B: A2 (a lapsed owner still repairs), minor 5 (desktop writes only over an older state) --

def test_a_lapsed_owner_still_puts_a_damaged_keyring_back(tmp_path, pro):
    s = Share(tmp_path)
    a = ItemService(s.owner).create_note("A", "v1", collection_ids=[s.cid])
    s.join()
    path = s.fs(s.owner).keyring_path
    trusted = path.read_bytes()
    path.write_bytes(b"{}")
    pro.on = False
    report = s.run(s.owner)
    assert kinds(report) == ["keyring-restored", "pro-required"]
    assert path.read_bytes() == trusted
    assert report.own_states is None and not report.wrote
    pro.on = True
    assert _owner_edits_and_member_receives(s, a, "v2")


def test_desktop_approve_never_overwrites_a_join_that_arrived_meanwhile(tmp_path, pro):
    from localvault.app.collection_share import CollectionShareService

    s = Share(tmp_path)
    s.run(s.owner)
    raw = s.fs(s.member).read_keyring_bytes()
    sg.join_share_group(s.member, raw, password=PW, device="Member PC", install_id="install-member",
                        _kdf_override=CHEAP)
    sg.set_share_folder(s.member, s.gid, str(s.folder))
    s.run(s.member)
    s.run(s.owner)  # the member waits for approval
    late = vault(tmp_path, "late")
    sg.join_share_group(late, s.fs(s.member).read_keyring_bytes(), password=PW, device="Late PC",
                        install_id="install-late", _kdf_override=CHEAP)
    sg.set_share_folder(late, s.gid, str(s.folder))
    s.now += 1
    FolderSync(s.folder, install_id="install-late", share=s.gid, _kdf_override=CHEAP).run_once(late, LEASE, now=s.now)
    with_late = s.fs(s.owner).read_keyring_bytes()
    sg.approve_members(s.owner, s.gid, [s.member_dev], _kdf_override=CHEAP)
    service = object.__new__(CollectionShareService)
    service._install_id = lambda: "install-owner"
    service._kdf = CHEAP
    assert service._write_keyring(s.owner, s.gid, str(s.folder)) is False
    assert s.fs(s.owner).read_keyring_bytes() == with_late, "the late join stays in the folder"
    # The run reconciles: the approval re-signed over the grown roster, the late joiner pending.
    assert "keyring-merged" in kinds(s.run(s.owner))
    assert [m.name for m in sg.pending_members(s.owner, s.gid)] == ["Late PC"]
    # A rotation (a later epoch) is still written at once.
    sg.remove_member(s.owner, s.gid, s.member_dev, new_password=PW2, _kdf_override=CHEAP)
    assert service._write_keyring(s.owner, s.gid, str(s.folder)) is True
    assert s.fs(s.owner).read_keyring_bytes() == sg.share_keyring(s.owner, s.gid)
