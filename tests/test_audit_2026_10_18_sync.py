"""Audit 2026-10-18 sync fixes: M9 (removed Wi-Fi device and a later cloud folder), M10 (member additions
at the same epoch, keep-list rotations), the LAN listener slots and the enrollment pre-check (loopback only)."""
from __future__ import annotations

import socket
import threading
import time
from dataclasses import dataclass
from pathlib import Path

import pytest

from localvault.app import sync_view as ui
from localvault.session_guard import StaleSession
from localvault.sync import folder_transport as ft
from localvault.sync import keyring as kr
from localvault.sync import lan_sync as lan
from localvault.sync import pairing
from localvault.sync import service as svc
from localvault.sync import transport as tr
from localvault.sync.group import GroupKey, SyncFormatError, decode_view
from localvault.sync.pairing import DeviceIdentity
from localvault.sync.state import SyncState
from localvault.sync.transport import LANEndpoint, SyncTransport
from localvault.sync.vault_bridge import (
    BridgeError,
    SyncGroupState,
    load_sync_state,
    save_sync_state,
)
from localvault.vault import create_vault

TEST_KDF = {"time_cost": 1, "memory_cost_kib": 8192, "parallelism": 1, "hash_len": 32}
MASTER = "synthetic master"
NOW = int(time.time())
CHEAP = (1024, 1, 1)
PW = "correct horse battery staple 7!"
PW2 = "another very long passphrase 42?"


class FakeLease:
    def __init__(self) -> None:
        self.valid = True

    def check(self) -> None:
        if not self.valid:
            raise StaleSession("Vault is locked")


def _free_endpoint() -> tuple[LANEndpoint, socket.socket]:
    probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    if hasattr(socket, "SO_EXCLUSIVEADDRUSE"):
        probe.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
    probe.bind(("127.0.0.1", 0))
    return LANEndpoint("127.0.0.1", int(probe.getsockname()[1])), probe


@dataclass
class Dev:
    name: str
    session: object
    lease: FakeLease
    install: str
    endpoint: LANEndpoint
    transport: SyncTransport | None = None
    responder: lan.LanResponder | None = None
    port_hold: socket.socket | None = None

    @property
    def state(self) -> SyncGroupState:
        return load_sync_state(self.session)

    @property
    def device_id(self) -> str:
        return self.state.device_id

    def relisten(self) -> None:
        if self.transport is not None:
            self.transport.stop()
        self.responder = lan.LanResponder(self.session, self.lease, install_id=self.install, clock=lambda: NOW,
                                          on_pending=lambda pending: pending.decide(True))
        self.transport = SyncTransport(lan.transport_state(self.state, self.session, self.lease))
        self.transport.set_peer_request_handler(self.responder)
        if self.port_hold is not None:
            self.port_hold.close()
            self.port_hold = None
        self.transport.start(self.endpoint)

    def sync_with(self, other: Dev) -> lan.RunReport:
        return lan.sync_with(self.transport, other.device_id, self.session, self.lease, install_id=self.install,
                             now=NOW)

    def folder(self, root: Path) -> ft.FolderSync:
        return ft.FolderSync(root, install_id=self.install, _kdf_override=CHEAP)

    def run(self, root: Path) -> lan.RunReport:
        return self.folder(root).run_once(self.session, self.lease, now=NOW)

    def labels(self) -> list[str]:
        return sorted(e["label"] for e in self.session._payload["entries"])

    def stop(self) -> None:
        if self.transport is not None:
            self.transport.stop()
        if self.port_hold is not None:
            self.port_hold.close()


def kinds(report) -> list[str]:
    return [i.kind for i in report.issues]


def _web(dev: Dev, label: str) -> str:
    return dev.session.upsert_web(origin=f"https://{label}.example.com", username="me", password="pw-123456",
                                  label=label)


@pytest.fixture
def devs(tmp_path: Path):
    made: list[Dev] = []

    def make(name: str, *, group: bool = False) -> Dev:
        session = create_vault(tmp_path / f"{name}.json", MASTER, kdf_overrides=TEST_KDF)
        endpoint, hold = _free_endpoint()
        d = Dev(name, session, FakeLease(), f"install-{name}", endpoint, port_hold=hold)
        made.append(d)
        if group:
            lan.create_lan_group(d.session, d.lease, install_id=d.install)
            d.relisten()
        return d

    yield make
    for d in made:
        d.stop()


@pytest.fixture
def root(tmp_path: Path) -> Path:
    path = tmp_path / "Cloud"
    path.mkdir()
    return path


def _pair(inviter: Dev, invitee: Dev) -> None:
    offer = lan.begin_pairing(inviter.session, inviter.lease, inviter.endpoint.host, inviter.endpoint.port,
                              install_id=inviter.install, now=NOW)
    inviter.responder.start_enrollment(offer, inviter.transport)
    lan.enroll_from_qr(pairing.offer_qr_payload(offer), invitee.session, invitee.lease, install_id=invitee.install,
                       endpoint=invitee.endpoint, now=NOW)
    invitee.relisten()


# --- M9: a removed Wi-Fi device and a cloud folder added later --------------------------------------


def test_lan_removed_flag_is_persisted_and_backward_compatible(devs) -> None:
    a, b = devs("a", group=True), devs("b")
    _pair(a, b)
    raw = a.state.to_dict()
    assert "lan_removed" not in raw and "unacked_members" not in raw  # older versions still read it
    assert SyncGroupState.from_dict(raw).lan_removed is False
    assert lan.remove_lan_peer(a.session, a.lease, b.device_id, install_id=a.install, transport=a.transport)
    assert a.state.lan_removed is True
    assert a.state.to_dict()["lan_removed"] is True
    assert SyncGroupState.from_dict(a.state.to_dict()).lan_removed is True
    # removing an id that is not listed does not set it
    c = devs("c", group=True)
    assert not lan.remove_lan_peer(c.session, c.lease, "not-listed", install_id=c.install)
    assert c.state.lan_removed is False
    with pytest.raises(BridgeError):
        SyncGroupState.from_dict({**raw, "lan_removed": "yes"})


def test_adding_a_folder_after_a_wifi_removal_needs_a_fresh_key(devs, root: Path) -> None:
    a, b, c = devs("a", group=True), devs("b"), devs("c")
    _pair(a, b)
    _pair(a, c)
    old = a.state
    lan.remove_lan_peer(a.session, a.lease, c.device_id, install_id=a.install, transport=a.transport)

    with pytest.raises(ft.FolderSyncError) as refused:
        ft.add_folder_to_group(root, a.session, a.lease, PW, "PC A", install_id=a.install, now=NOW,
                               _kdf_override=CHEAP, run=False)
    assert refused.value.reason == "lan-peer-removed"
    assert not (root / ft.SYNC_DIR_NAME / ft.KEYRING_NAME).exists()  # nothing written
    assert a.state == old.__class__(**{**old.__dict__, "lan_peers": a.state.lan_peers, "lan_removed": True})
    assert "Wi-Fi device was removed" in ui.error_text(refused.value)

    ft.add_folder_to_group(root, a.session, a.lease, PW, "PC A", install_id=a.install, now=NOW,
                           _kdf_override=CHEAP, fresh_key=True)
    new = a.state
    assert new.group_id == old.group_id and new.epoch == old.epoch + 1 and new.key != old.key
    assert new.lan_removed is False and new.folder_path == str(root)
    assert [p["device_id"] for p in new.lan_peers] == [b.device_id]  # B keeps its pairing entry

    # C (removed, still holding the old key) can open neither the keyring nor A's file.
    ring = kr.parse_keyring((root / ft.SYNC_DIR_NAME / ft.KEYRING_NAME).read_bytes())
    assert ring["epoch"] == new.epoch and ring["prev_mac"] is None
    c_state = c.state
    with pytest.raises(kr.KeyringError):
        kr.accept_keyring(ring, GroupKey(c_state.group_id, c_state.epoch, c_state.key), c_state.identity(),
                          _kdf_override=CHEAP)
    own_file = root / ft.SYNC_DIR_NAME / ft.DEVICES_DIR_NAME / f"{a.device_id}.lgksync"
    with pytest.raises(SyncFormatError):
        decode_view(GroupKey(c_state.group_id, c_state.epoch, c_state.key), own_file.read_bytes())
    with pytest.raises(SyncFormatError):  # and the old key at the new epoch is just as useless
        decode_view(GroupKey(c_state.group_id, new.epoch, c_state.key), own_file.read_bytes())

    # B (remaining) is told it has an older key and exchanges nothing; A says B must pair again.
    _web(a, "after-folder")
    report = b.sync_with(a)
    assert kinds(report) == ["epoch-behind"]
    assert "after-folder" not in b.labels()
    assert "older sync key" in ui.issue_text(report.issues[0])

    # B pairs again (leave, scan a new code): it gets the new key and syncs over Wi-Fi and through the folder.
    ft.leave_folder_group(b.session, b.lease, install_id=b.install)
    _pair(a, b)
    assert b.state.epoch == new.epoch and b.state.key == new.key
    assert kinds(b.sync_with(a)) == [] and "after-folder" in b.labels()
    ft.attach_folder(root, b.session, b.lease, PW, "PC B", install_id=b.install, now=NOW, _kdf_override=CHEAP)
    _web(b, "from-b")
    b.run(root)
    assert "member-added" in kinds(a.run(root))  # B added itself to the keyring (M10)
    assert "from-b" in a.labels()


def test_the_removal_flag_clears_on_a_key_change_and_survives_a_same_key_attach(devs, root: Path) -> None:
    a, b, c = devs("a", group=True), devs("b"), devs("c")
    _pair(a, b)
    _pair(a, c)
    # B adds the folder (B removed nobody), A removed C meanwhile and then attaches with the old key.
    ft.add_folder_to_group(root, b.session, b.lease, PW, "PC B", install_id=b.install, now=NOW,
                           _kdf_override=CHEAP)
    lan.remove_lan_peer(a.session, a.lease, c.device_id, install_id=a.install, transport=a.transport)
    ft.add_folder_to_group(root, a.session, a.lease, PW, "PC A", install_id=a.install, now=NOW,
                           _kdf_override=CHEAP, run=False)  # existing folder: attach, key unchanged
    assert a.state.lan_removed is True
    report = a.run(root)
    assert "old-key-known" in kinds(report)
    assert "change the sync password" in ui.issue_text(report.issues[kinds(report).index("old-key-known")]).lower()
    ft.rotate_folder_group(root, a.session, a.lease, PW2, keep=[b.device_id], install_id=a.install, now=NOW,
                           _kdf_override=CHEAP)
    assert a.state.lan_removed is False and "old-key-known" not in kinds(a.run(root))


def test_adopting_another_devices_rotation_clears_the_flag(tmp_path: Path, root: Path) -> None:
    sa = create_vault(tmp_path / "a.json", MASTER, kdf_overrides=TEST_KDF)
    sb = create_vault(tmp_path / "b.json", MASTER, kdf_overrides=TEST_KDF)
    la, lb = FakeLease(), FakeLease()
    ft.create_folder_group(root, sa, la, PW, "PC A", install_id="ia", now=NOW, _kdf_override=CHEAP)
    ft.join_folder_group(root, sb, lb, PW, "PC B", install_id="ib", now=NOW, _kdf_override=CHEAP)
    state = load_sync_state(sb)
    save_sync_state(sb, SyncGroupState(**{**state.__dict__, "lan_removed": True}))
    ft.FolderSync(root, install_id="ia", _kdf_override=CHEAP).run_once(sa, la, now=NOW)
    ft.rotate_folder_group(root, sa, la, PW2, keep=[state.device_id], install_id="ia", now=NOW,
                           _kdf_override=CHEAP)
    ft.FolderSync(root, install_id="ib", _kdf_override=CHEAP).run_once(sb, lb, now=NOW)
    assert load_sync_state(sb).epoch == 2 and load_sync_state(sb).lan_removed is False


def test_add_folder_confirmation_copy_names_the_devices_to_pair_again() -> None:
    group = ui.GroupSnapshot("me", None, 1, True, (), (ui.PeerSnapshot("phone-1", None),), lan_removed=True)
    text = ui.lan_removed_folder_text(group)
    assert "NEW key" in text and "Device phone-1" in text and "pair" in text and text.endswith("Continue?")


# --- M10: member additions at the same epoch, keep-list rotations ------------------------------------


def _folder_group(tmp_path: Path, root: Path, names: str = "abc") -> list[Dev]:
    out = []
    for name in names:
        session = create_vault(tmp_path / f"f{name}.json", MASTER, kdf_overrides=TEST_KDF)
        out.append(Dev(name, session, FakeLease(), f"install-{name}", LANEndpoint("127.0.0.1", 1)))
    first = out[0]
    ft.create_folder_group(root, first.session, first.lease, PW, "PC A", install_id=first.install, now=NOW,
                           _kdf_override=CHEAP)
    for d in out[1:]:
        ft.join_folder_group(root, d.session, d.lease, PW, f"PC {d.name.upper()}", install_id=d.install, now=NOW,
                             _kdf_override=CHEAP)
    for d in out:
        d.run(root)
    return out


def _ring(root: Path) -> dict:
    return kr.parse_keyring((root / ft.SYNC_DIR_NAME / ft.KEYRING_NAME).read_bytes())


def _add_puppet(root: Path) -> str:
    """A member who knows the sync password adds a device at the same epoch (no rotation)."""
    path = root / ft.SYNC_DIR_NAME / ft.KEYRING_NAME
    puppet = DeviceIdentity.generate()
    ring, _gk = kr.join_with_password(_ring(root), PW, puppet, "Puppet", _kdf_override=CHEAP)
    path.write_bytes(ft.canonical_json(ring))
    return puppet.device_id


def test_same_epoch_additions_are_reported_until_acknowledged(tmp_path: Path, root: Path) -> None:
    a, b, c = _folder_group(tmp_path, root)
    # Every device saw B and C join (A both, B saw C): reported, persisted, and named on the screen.
    assert set(a.state.unacked_members) == {b.device_id, c.device_id}
    assert a.state.unacked_members == load_sync_state(a.session).unacked_members
    assert b.state.unacked_members == (c.device_id,) and c.state.unacked_members == ()
    report = a.run(root)
    added = [i.detail for i in report.issues if i.kind == "member-added"]
    assert sorted(added) == sorted([b.device_id, c.device_id])
    text = ui.issue_text(report.issues[0], names={b.device_id: "PC B"})
    assert "added to this sync group by another device" in text
    # Acknowledge only what was shown: a device that appears afterwards stays reported.
    puppet = _add_puppet(root)
    assert ft.acknowledge_members(a.session, a.lease, [b.device_id, c.device_id], install_id=a.install) == 2
    assert [i.detail for i in a.run(root).issues if i.kind == "member-added"] == [puppet]
    assert ft.acknowledge_members(a.session, a.lease, ["unknown"], install_id=a.install) == 0
    assert a.state.unacked_members == (puppet,)
    with pytest.raises(ft.FolderSyncError):
        ft.acknowledge_members(a.session, a.lease, [puppet], install_id="other-install")


def test_a_legacy_state_without_a_member_list_reports_nothing(tmp_path: Path, root: Path) -> None:
    a, b = _folder_group(tmp_path, root, "ab")
    state = a.state
    save_sync_state(a.session, SyncGroupState(**{**state.__dict__, "members_epoch": None, "members": (),
                                                  "unacked_members": ()}))
    assert "member-added" not in kinds(a.run(root))
    assert set(a.state.members) == {a.device_id, b.device_id}


def test_rotation_never_wraps_the_new_key_for_an_unconfirmed_sock_puppet(tmp_path: Path, root: Path) -> None:
    a, b, c = _folder_group(tmp_path, root)
    ft.acknowledge_members(a.session, a.lease, a.state.unacked_members, install_id=a.install)
    puppet = _add_puppet(root)  # C, about to be removed, adds a sock puppet at the same epoch
    a.run(root)
    assert puppet in a.state.unacked_members
    # The screen's plan lists who gets the key and leaves the puppet out.
    snap = ui.GroupSnapshot(a.device_id, str(root), a.state.epoch, True,
                            tuple(ui.MemberSnapshot(d, d, d == a.device_id) for d in a.state.members),
                            unacked=a.state.unacked_members)
    plan = ui.rotation_plan(snap, removing=(c.device_id,))
    assert plan.keep == (b.device_id,)
    assert "goes only to" in plan.text and "lose access" in plan.text and puppet[:8] in plan.text
    ft.rotate_folder_group(root, a.session, a.lease, PW2, [c.device_id], keep=plan.keep, install_id=a.install,
                           now=NOW, _kdf_override=CHEAP)
    ring = _ring(root)
    assert {m["device_id"] for m in ring["members"]} == {a.device_id, b.device_id}
    assert set(ring["device_wraps"]) == {a.device_id, b.device_id}
    assert a.state.unacked_members == ()
    b.run(root)
    assert b.state.epoch == 2


def test_rotation_with_the_default_keep_drops_unknown_and_unacknowledged_members(tmp_path: Path, root: Path) -> None:
    a, b = _folder_group(tmp_path, root, "ab")
    ft.acknowledge_members(a.session, a.lease, a.state.unacked_members, install_id=a.install)
    puppet = _add_puppet(root)  # A has not even run since: not in its member list at all
    ft.rotate_folder_group(root, a.session, a.lease, PW2, install_id=a.install, now=NOW, _kdf_override=CHEAP)
    assert {m["device_id"] for m in _ring(root)["members"]} == {a.device_id, b.device_id}
    assert puppet not in a.state.members


def test_an_explicit_keep_list_is_honoured_and_late_members_are_dropped(tmp_path: Path, root: Path) -> None:
    a, b, c = _folder_group(tmp_path, root)
    puppet = _add_puppet(root)
    a.run(root)
    # The user explicitly confirmed the puppet in the list (keep), but not C (it joined "after they looked").
    ft.rotate_folder_group(root, a.session, a.lease, PW2, keep=[b.device_id, puppet], install_id=a.install, now=NOW,
                           _kdf_override=CHEAP)
    assert {m["device_id"] for m in _ring(root)["members"]} == {a.device_id, b.device_id, puppet}
    assert not (root / ft.SYNC_DIR_NAME / ft.DEVICES_DIR_NAME / f"{c.device_id}.lgksync").exists()
    with pytest.raises(ft.FolderSyncError):
        ft.rotate_folder_group(root, a.session, a.lease, "yet another long passphrase 9!", keep=["bad id!"],
                               install_id=a.install, now=NOW, _kdf_override=CHEAP)


def test_an_unknown_member_in_another_devices_rotation_is_reported(tmp_path: Path, root: Path) -> None:
    a, b = _folder_group(tmp_path, root, "ab")
    for d in (a, b):
        ft.acknowledge_members(d.session, d.lease, d.state.unacked_members, install_id=d.install)
    puppet = _add_puppet(root)
    # B rotates and explicitly keeps the puppet; A adopts epoch 2 and reports the member it never saw.
    ft.rotate_folder_group(root, b.session, b.lease, PW2, keep=[a.device_id, puppet], install_id=b.install, now=NOW,
                           _kdf_override=CHEAP)
    report = a.run(root)
    assert a.state.epoch == 2
    assert [i.detail for i in report.issues if i.kind == "member-added"] == [puppet]


def test_view_marks_unconfirmed_members_and_offers_confirmation() -> None:
    group = ui.GroupSnapshot("me", "C:/Cloud", 1, True,
                             (ui.MemberSnapshot("me", "This PC", True), ui.MemberSnapshot("new-1", "Phone")),
                             unacked=("new-1",))
    view = ui.sync_view(None, group, lan_endpoint="", now=NOW)
    member = next(m for m in view.folder.members if m.device_id == "new-1")
    assert member.detail == "Added by another device, not confirmed"
    assert "ack-members" in view.folder.actions and ui._ACTION_LABELS["ack-members"] == "These are my devices"
    assert ui.issue_severity("member-added") == "warning"
    intro = ui.rotation_intro(group)
    assert "goes only to: this PC" in intro and "Phone" in intro and "lose access" in intro
    calm = ui.GroupSnapshot("me", "C:/Cloud", 1, True, group.members)
    assert "ack-members" not in ui.sync_view(None, calm, lan_endpoint="", now=NOW).folder.actions
    assert ui.rotation_plan(None) == ui.RotationPlan(None, "")


# --- Low: listener slots ------------------------------------------------------------------------------


def _idle(endpoint: LANEndpoint, source: str | None = None) -> socket.socket:
    """An idle connection to *endpoint*, from the loopback address *source* (another host of the same /24)."""
    sock = socket.create_connection((endpoint.host, endpoint.port), timeout=5,
                                    source_address=None if source is None else (source, 0))
    sock.settimeout(5)
    return sock


def _closed_by_peer(sock: socket.socket, within: float) -> bool:
    sock.settimeout(within)
    try:
        return sock.recv(1) == b""
    except TimeoutError:
        return False
    except OSError:
        return True  # reset


def test_an_idle_unauthenticated_connection_no_longer_blocks_sync(devs) -> None:
    a, b = devs("a", group=True), devs("b")
    _pair(a, b)
    idle = _idle(a.endpoint, "127.0.0.2")  # another host of B's /24 (B connects from 127.0.0.1)
    try:
        time.sleep(0.1)
        _web(b, "through")
        started = time.monotonic()
        assert kinds(b.sync_with(a)) == []  # inbound to A while A holds an idle connection
        assert time.monotonic() - started < 2.0
        assert kinds(a.sync_with(b)) == []  # and A's own outbound sync is not blocked by its inbound
    finally:
        idle.close()
    assert "through" in sorted(e["label"] for e in a.session._payload["entries"])


def test_first_frame_deadline_and_per_address_cap(devs, monkeypatch) -> None:
    monkeypatch.setattr(tr, "FIRST_FRAME_SECONDS", 0.4)
    a = devs("a", group=True)
    first = _idle(a.endpoint)
    try:
        time.sleep(0.1)
        second = _idle(a.endpoint)  # same source address: over MAX_PRE_AUTH_PER_ADDRESS (1)
        assert _closed_by_peer(second, 1.0)
        second.close()
        assert _closed_by_peer(first, 2.0)  # first frame never came
    finally:
        first.close()
    assert tr.MAX_PRE_AUTH_PER_ADDRESS == 1 and tr.FIRST_FRAME_SECONDS == 0.4


def test_a_peer_on_the_same_network_connects_while_another_host_holds_its_allowance(devs, monkeypatch) -> None:
    """R-1: per-address 1, per-/24 3, total 4 with one slot for recently verified addresses."""
    monkeypatch.setattr(tr, "FIRST_FRAME_SECONDS", 30.0)  # the idle connections stay for the whole test
    a, b = devs("a", group=True), devs("b")
    _pair(a, b)
    # One attacker address holds its whole allowance (a second connection is refused at once) ...
    held = [_idle(a.endpoint, "127.0.0.2")]
    try:
        time.sleep(0.1)
        refused = _idle(a.endpoint, "127.0.0.2")
        assert _closed_by_peer(refused, 1.0)
        refused.close()
        # ... and B, on the same /24 and never verified at A before, still syncs.
        _web(b, "same-net")
        assert kinds(b.sync_with(a)) == []
        # Now the attacker uses two more addresses: the /24 allowance (3) is full ...
        held += [_idle(a.endpoint, "127.0.0.3"), _idle(a.endpoint, "127.0.0.4")]
        time.sleep(0.1)
        fourth = _idle(a.endpoint, "127.0.0.5")
        assert _closed_by_peer(fourth, 1.0)
        fourth.close()
        # ... but B completed a verified hello at A a moment ago, so it takes the reserved slot.
        _web(b, "reserved")
        assert kinds(b.sync_with(a)) == []
    finally:
        for sock in held:
            sock.close()
    assert {"same-net", "reserved"} <= {e["label"] for e in a.session._payload["entries"]}


def test_total_inbound_cap(devs, monkeypatch) -> None:
    monkeypatch.setattr(tr, "MAX_INBOUND_PER_ADDRESS", 10)
    monkeypatch.setattr(tr, "MAX_PRE_AUTH_PER_ADDRESS", 10)  # every test connection comes from 127.0.0.1
    monkeypatch.setattr(tr, "MAX_PRE_AUTH_PER_PREFIX", 10)
    a = devs("a", group=True)
    held = [_idle(a.endpoint) for _ in range(tr.MAX_INBOUND_CONNECTIONS)]
    try:
        time.sleep(0.2)
        extra = _idle(a.endpoint)
        assert _closed_by_peer(extra, 1.0)
        extra.close()
    finally:
        for sock in held:
            sock.close()


def test_an_oversized_first_frame_is_dropped(devs) -> None:
    a = devs("a", group=True)
    sock = _idle(a.endpoint)
    try:
        sock.sendall(tr.FRAME_HEADER.pack(tr.MAX_FIRST_FRAME_BYTES + 1))
        assert _closed_by_peer(sock, 2.0)
    finally:
        sock.close()


def test_stop_closes_every_inbound_connection(devs) -> None:
    a = devs("a", group=True)
    sock = _idle(a.endpoint)
    try:
        time.sleep(0.1)
        a.transport.stop()
        assert _closed_by_peer(sock, 2.0)
        assert a.transport._inbound == {} and a.transport._active_socket is None
    finally:
        sock.close()


# --- Low: enrollment frames are pre-checked outside the gate -----------------------------------------


class _Inner:
    state = None

    def __init__(self) -> None:
        self.handler = None

    def set_enrollment_handler(self, handler) -> None:
        self.handler = handler


def _armed(devs):
    a = devs("a", group=True)
    gate = svc.SyncGate()
    inner = _Inner()
    responder = lan.LanResponder(a.session, a.lease, install_id=a.install, clock=lambda: NOW,
                                 on_pending=lambda pending: pending.decide(True))
    offer = lan.begin_pairing(a.session, a.lease, a.endpoint.host, a.endpoint.port, install_id=a.install, now=NOW)
    responder.start_enrollment(offer, svc._GatedEnrollment(inner, gate))
    return a, gate, inner, responder, offer


def _call_while_gate_is_held(gate: svc.SyncGate, fn, raw: bytes) -> tuple[bool, object]:
    """Run fn(raw) on a thread while another thread holds the gate; (finished before release, result)."""
    held, release = threading.Event(), threading.Event()

    def holder() -> None:
        with gate.hold():
            held.set()
            release.wait(5)

    out: dict = {}
    keeper = threading.Thread(target=holder, daemon=True)
    keeper.start()
    held.wait(5)
    worker = threading.Thread(target=lambda: out.setdefault("r", fn(raw)), daemon=True)
    worker.start()
    worker.join(0.5)
    early = not worker.is_alive()
    release.set()
    worker.join(5)
    keeper.join(5)
    return early, out.get("r")


def test_stray_enrollment_frames_are_refused_without_the_gate(devs) -> None:
    a, gate, inner, responder, offer = _armed(devs)
    other = pairing.create_pairing_offer(DeviceIdentity.generate(), offer.group_id, "192.168.1.2", 47821, now=NOW)
    stray = pairing.build_enrollment_request(other, DeviceIdentity.generate(), now=NOW)
    early, reply = _call_while_gate_is_held(gate, inner.handler, stray)
    assert early and reply == pairing.enrollment_refusal()
    early, reply = _call_while_gate_is_held(gate, inner.handler, pairing.ENROLL_REQUEST_MAGIC + b"{not json")
    assert early and reply == pairing.enrollment_refusal()
    # The real request still goes through the gate (it waits for it) and pairs.
    joiner = DeviceIdentity.generate()
    genuine = pairing.build_enrollment_request(offer, joiner, now=NOW)
    early, reply = _call_while_gate_is_held(gate, inner.handler, genuine)
    assert not early and reply.startswith(pairing.ENROLL_REPLY_MAGIC)
    assert responder.enrolled.device_id == joiner.device_id
    # Used up: refused at once, again without the gate.
    early, reply = _call_while_gate_is_held(gate, inner.handler, genuine)
    assert early and reply == pairing.enrollment_refusal("used-or-expired")


def test_expired_or_disarmed_offers_are_refused_without_the_gate(devs) -> None:
    a, gate, inner, responder, offer = _armed(devs)
    request = pairing.build_enrollment_request(offer, DeviceIdentity.generate(), now=NOW)
    handler = inner.handler
    responder._deadline = responder.monotonic() - 1  # the offer's time is up
    early, reply = _call_while_gate_is_held(gate, handler, request)
    assert early and reply == pairing.enrollment_refusal("used-or-expired")
    responder.pairing = None  # disarmed, still within the grace period
    early, reply = _call_while_gate_is_held(gate, handler, request)
    assert early and reply == pairing.enrollment_refusal("used-or-expired")
    responder._refuse_until = responder.monotonic() - 1  # after the grace period: close without a reply
    assert responder.enroll_prefilter(request) == (True, None)


def test_the_enrolled_peer_is_exposed_for_the_undo_notice(devs) -> None:
    a, b = devs("a", group=True), devs("b")
    _pair(a, b)
    peer = a.responder.enrolled
    assert peer.device_id == b.device_id
    assert peer.fingerprint == b.state.identity().fingerprint
    assert isinstance(a.transport.state, SyncState) and b.device_id in a.transport.state.trusted_peers
