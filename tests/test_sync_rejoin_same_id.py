"""Keep the device id when a device leaves and rejoins the same sync group (2026-11-17).

Spec: ``docs/superpowers/specs/2026-11-17-keep-device-id-on-rejoin-design.md``.  Leave keeps the
identity (rule 1); Reset, erase, a removal and a successful rejoin drop it (rule 2); a join of the same
group reuses it and continues its counters (rule 3); a host accepts a known id only with the same keys
(rule 4); a released host's plain refusal drops it with the rule-5 message (rule 5); a folder join
rewrites the member entry in place (rule 6).
"""
from __future__ import annotations

import base64
import dataclasses
import json
from pathlib import Path

import pytest
import test_sync_folder_transport as ftt
import test_sync_lan as lt
from test_sync_folder_transport import CHEAP, NOW, PW, PW2, _group, _web, kinds

from localvault.app.sync_view import error_text
from localvault.backup import (
    DEVICE_ONLY_PAYLOAD_KEYS,
    export_encrypted_backup,
    restore_verified_backup,
    without_share_records,
)
from localvault.i18n import t
from localvault.sync import folder_transport as ft
from localvault.sync import keyring as kr
from localvault.sync import lan_sync as lan
from localvault.sync import pairing, removal
from localvault.sync.service import reset_sync
from localvault.sync.vault_bridge import (
    KEPT_IDENTITY_KEY,
    KeptIdentity,
    load_kept_identity,
    load_sync_state,
    save_sync_state,
)
from localvault.vault import create_vault, unlock_vault

root = ftt.root  # the fixture
devs = lt.devs  # the fixture
FAST_BACKUP_KDF = {"time_cost": 1, "memory_cost_kib": 8192, "parallelism": 1}
BACKUP_PASSWORD = "synthetic independent backup password"


def _ring(root: Path) -> dict:
    return kr.parse_keyring((root / ft.SYNC_DIR_NAME / ft.KEYRING_NAME).read_bytes())


def _entries(root: Path, device_id: str) -> list[dict]:
    return [m for m in _ring(root)["members"] if m["device_id"] == device_id]


def _join(dev, password: str = PW, name: str = "PC again") -> None:
    ft.join_folder_group(dev.root, dev.session, dev.lease, password, name, install_id=dev.install, now=NOW,
                         run=False, _kdf_override=CHEAP)


def _leave(dev) -> None:
    assert ft.leave_folder_group(dev.session, dev.lease, install_id=dev.install) is True


# --- rule 1: Leave keeps it ------------------------------------------------------------------------------


def test_leave_keeps_the_identity_and_its_counters(tmp_path: Path, root: Path) -> None:
    a, b = _group(tmp_path, root, 2)
    _web(b, "on-b")
    b.sync()
    before = b.state
    assert before.own_counter > 0
    _leave(b)
    assert load_sync_state(b.session) is None
    kept = load_kept_identity(b.session)
    assert kept is not None
    assert kept.device_identity == dict(before.device_identity) and kept.group_id == before.group_id
    assert (kept.own_counter, kept.hello_counter, kept.install_id) == (
        before.own_counter, before.hello_counter, b.install)
    # Only on this device: no group key, no peers, nothing but the identity and its counters.
    assert set(b.session._payload[KEPT_IDENTITY_KEY]) == {
        "version", "group_id", "device_identity", "install_id", "own_counter", "hello_counter"}


def test_a_later_leave_replaces_the_kept_identity(tmp_path: Path, root: Path) -> None:
    a, b = _group(tmp_path, root, 2)
    _leave(b)
    first = load_kept_identity(b.session)
    other = tmp_path / "Dropbox"
    other.mkdir()
    ft.create_folder_group(other, b.session, b.lease, PW2, "B", install_id=b.install, now=NOW, run=False,
                           _kdf_override=CHEAP)
    second_id = b.device_id
    assert second_id != first.device_id
    assert load_kept_identity(b.session) == first  # another group leaves the kept one alone (rule 3)
    _leave(b)
    assert load_kept_identity(b.session).device_id == second_id  # at most one per vault


def test_leave_on_another_installation_or_in_the_duress_vault_keeps_nothing(tmp_path: Path, root: Path) -> None:
    a, b, c = _group(tmp_path, root, 3)
    ft.leave_folder_group(b.session, b.lease, install_id="another-pc")  # a copied vault
    assert load_kept_identity(b.session) is None
    c.session.decoy = True
    try:
        _leave(c)
    finally:
        c.session.decoy = False
    assert load_kept_identity(c.session) is None


# --- rules 3 and 6: rejoin the same folder ---------------------------------------------------------------


def test_folder_rejoin_reuses_the_id_with_one_member_entry_and_items_sync_both_ways(
        tmp_path: Path, root: Path) -> None:
    a, b, c = _group(tmp_path, root, 3)
    _web(b, "before-leave")
    ftt._round([a, b, c])
    b_id, counter = b.device_id, b.state.own_counter
    old_entry = _entries(root, b_id)[0]
    members = len(_ring(root)["members"])
    _leave(b)
    ftt._round([a, c])
    _join(b)
    assert b.device_id == b_id
    assert load_kept_identity(b.session) is None  # live again (rule 2)
    assert len(_ring(root)["members"]) == members
    (entry,) = _entries(root, b_id)
    assert (entry["exchange_public"], entry["signing_public"]) == (
        old_entry["exchange_public"], old_entry["signing_public"])
    assert b.state.own_counter >= counter
    report = b.sync()
    assert kinds(report) == [], report.issues  # no counter-resynced, no own-file-rewritten
    on_b = _web(b, "after-rejoin")
    assert kinds(b.sync()) == []
    for d in (a, c):
        report = d.sync()
        assert kinds(report) == [], report.issues  # no rollback, suspicious-rewrite or member-added
        assert d.entry(on_b)["label"] == "after-rejoin"
        assert d.state.members == tuple(sorted(d.state.members)) and b_id in d.state.members
        assert d.state.unacked_members == ()
    on_a = _web(a, "from-a")
    a.sync()
    assert kinds(b.sync()) == []
    assert b.entry(on_a)["label"] == "from-a"


def test_rejoin_continues_the_view_counter_when_its_old_file_is_gone(tmp_path: Path, root: Path) -> None:
    """The hazard: the others remember the last counter of this id; a restart at 1 would be a rollback."""
    a, b = _group(tmp_path, root, 2)
    for i in range(3):
        _web(b, f"edit-{i}")
        b.sync()
        a.sync()
    seen_by_a = a.state.last_seen[b.device_id]
    assert seen_by_a == b.state.own_counter
    _leave(b)
    # The cloud provider lost the own file meanwhile: only the kept counter can continue it.
    kept_id = load_kept_identity(b.session).device_id
    sync_dir = root / ft.SYNC_DIR_NAME
    (sync_dir / "devices" / f"{kept_id}.lgksync").unlink()
    (sync_dir / "signatures" / f"{kept_id}.lgksig").unlink()
    _join(b)
    on_b = _web(b, "after-rejoin")
    assert kinds(b.sync()) == []
    assert b.state.own_counter > seen_by_a
    report = a.sync()
    assert kinds(report) == [], report.issues
    assert a.entry(on_b)["label"] == "after-rejoin"


def test_rejoin_after_a_password_change_that_kept_the_device(tmp_path: Path, root: Path) -> None:
    a, b = _group(tmp_path, root, 2)
    b_id = b.device_id
    _leave(b)
    ft.rotate_folder_group(root, a.session, a.lease, PW2, install_id=a.install, now=NOW, _kdf_override=CHEAP)
    assert len(_entries(root, b_id)) == 1  # still listed, wrapped to the new key
    _join(b, PW2)
    assert b.device_id == b_id and b.state.epoch == 2
    on_b = _web(b, "after")
    assert kinds(b.sync()) == []
    assert kinds(a.sync()) == [] and a.entry(on_b)["label"] == "after"


def test_a_removed_device_gets_a_new_id(tmp_path: Path, root: Path) -> None:
    a, b, c = _group(tmp_path, root, 3)
    b_id = b.device_id
    _leave(b)
    ft.rotate_folder_group(root, a.session, a.lease, PW2, remove=[b_id], install_id=a.install, now=NOW,
                           _kdf_override=CHEAP)
    assert (root / ft.SYNC_DIR_NAME / removal.REMOVED_DIR_NAME / removal.notice_name(b_id)).exists()
    _join(b, PW2)
    assert b.device_id != b_id and _entries(root, b_id) == []
    assert load_kept_identity(b.session) is None


def test_a_removal_notice_alone_drops_the_kept_identity(tmp_path: Path, root: Path) -> None:
    a, b = _group(tmp_path, root, 2)
    b_id = b.device_id
    _leave(b)
    folder = ft.FolderSync(root, install_id=a.install, _kdf_override=CHEAP)
    assert folder.write_removal_notice(a.state.identity(), a.state.group_id, b_id, a.state.epoch + 1, now=NOW)
    _join(b)
    assert b.device_id != b_id and load_kept_identity(b.session) is None


def test_a_listed_id_with_other_keys_is_not_taken_over(tmp_path: Path, root: Path) -> None:
    a, b = _group(tmp_path, root, 2)
    b_id = b.device_id
    _leave(b)
    forged = KeptIdentity(a.state.group_id, pairing.DeviceIdentity.generate(b_id).protected_dict(), b.install)
    b.session._payload[KEPT_IDENTITY_KEY] = forged.to_dict()
    old = _entries(root, b_id)
    _join(b)
    assert b.device_id != b_id
    assert _entries(root, b_id) == old  # the listed device's entry is untouched
    assert load_kept_identity(b.session) is None


def test_joining_another_group_leaves_the_kept_identity_alone(tmp_path: Path, root: Path) -> None:
    a, b = _group(tmp_path, root, 2)
    _leave(b)
    kept = load_kept_identity(b.session)
    other = tmp_path / "Dropbox"
    other.mkdir()
    z = ftt._device(tmp_path, "z", other)
    ft.create_folder_group(other, z.session, z.lease, PW2, "Z", install_id=z.install, now=NOW, run=False,
                           _kdf_override=CHEAP)
    ft.join_folder_group(other, b.session, b.lease, PW2, "B", install_id=b.install, now=NOW, run=False,
                         _kdf_override=CHEAP)
    assert b.device_id != kept.device_id
    assert load_kept_identity(b.session) == kept


def test_a_kept_identity_of_another_installation_is_not_reused(tmp_path: Path, root: Path) -> None:
    a, b = _group(tmp_path, root, 2)
    b_id = b.device_id
    _leave(b)
    b.install = "install-restored-elsewhere"
    _join(b)
    assert b.device_id != b_id


# --- rule 2: Reset and erase drop it ---------------------------------------------------------------------


def test_reset_drops_the_kept_identity_and_the_next_join_has_a_new_id(tmp_path: Path, root: Path) -> None:
    a, b = _group(tmp_path, root, 2)
    b_id = b.device_id
    _leave(b)
    assert reset_sync(b.session, b.lease) is True
    assert load_kept_identity(b.session) is None and KEPT_IDENTITY_KEY not in b.session._payload
    _join(b)
    assert b.device_id != b_id


def test_reset_with_only_a_kept_identity_still_reports_cleared(tmp_path: Path, root: Path) -> None:
    a, b = _group(tmp_path, root, 2)
    _leave(b)
    b.session._payload.pop("sync_meta", None)
    assert reset_sync(b.session, b.lease) is True
    assert reset_sync(b.session, b.lease) is False


def test_erasing_the_vault_leaves_no_kept_identity_anywhere(tmp_path: Path, root: Path) -> None:
    from localvault import device_erase
    from localvault.profiles import ProfileManager

    manager = ProfileManager(tmp_path / "data")
    record = manager.create_profile("Erased")
    vault_path = manager.vault_path(record.id)
    a, b = _group(tmp_path, root, 2)
    session = create_vault(vault_path, ftt.MASTER, kdf_overrides=ftt.TEST_KDF)
    dev = ftt.Dev("e", session, ftt.FakeLease(), "install-e", root)
    _join(dev)
    e_id = dev.device_id
    _leave(dev)
    assert load_kept_identity(session).device_id == e_id
    session.lock()
    assert device_erase.erase_profile(manager, record.id, delete_hello_key=lambda _id: None) == []
    for path in (tmp_path / "data").rglob("*"):
        if path.is_file():
            assert e_id.encode() not in path.read_bytes()


# --- backups ---------------------------------------------------------------------------------------------


def test_a_backup_made_after_leave_does_not_carry_the_kept_identity(tmp_path: Path, root: Path) -> None:
    assert DEVICE_ONLY_PAYLOAD_KEYS == (KEPT_IDENTITY_KEY,)
    a, b = _group(tmp_path, root, 2)
    b_id = b.device_id
    _leave(b)
    secrets = load_kept_identity(b.session).device_identity
    vault_file = Path(b.session.path)
    for name, vault_filter in (("filtered", without_share_records(b.session)), ("unfiltered", None)):
        backup = tmp_path / f"{name}.lgk"
        export_encrypted_backup(backup, vault_file=vault_file, settings_file=None, profile_name="B",
                                backup_password=BACKUP_PASSWORD, kdf_overrides=FAST_BACKUP_KDF,
                                vault_filter=vault_filter)
        restored = tmp_path / name / "vault.json"
        restored.parent.mkdir()
        restore_verified_backup(backup, vault_file=restored, settings_file=None, backup_password=BACKUP_PASSWORD,
                                vault_password=ftt.MASTER)
        session = unlock_vault(restored, ftt.MASTER)
        try:
            # An older backup (no filter) still carries it inside; the restore strips it.
            assert KEPT_IDENTITY_KEY not in session._payload and load_kept_identity(session) is None
            text = json.dumps(session._payload)
            # The id itself may appear in item version vectors (public); the kept private keys never do.
            assert secrets["signing_private"] not in text and secrets["exchange_private"] not in text
        finally:
            session.lock()
    # The live vault keeps it.
    assert load_kept_identity(b.session).device_id == b_id


def test_the_filtered_backup_file_itself_holds_no_kept_identity(tmp_path: Path, root: Path) -> None:
    a, b = _group(tmp_path, root, 2)
    _leave(b)
    vault_json = json.loads(Path(b.session.path).read_text(encoding="utf-8"))
    filtered = without_share_records(b.session)(vault_json)
    probe = tmp_path / "probe" / "vault.json"
    probe.parent.mkdir()
    probe.write_text(json.dumps(filtered), encoding="utf-8")
    session = unlock_vault(probe, ftt.MASTER)
    try:
        assert KEPT_IDENTITY_KEY not in session._payload
    finally:
        session.lock()


# --- keyring: the in-place rewrite -------------------------------------------------------------------


def test_rejoin_with_password_rewrites_only_the_own_entry(tmp_path: Path, root: Path) -> None:
    a, b = _group(tmp_path, root, 2)
    ring = _ring(root)
    ident = b.state.identity()
    new_ring, gk = kr.rejoin_with_password(ring, PW, ident, "B again", _kdf_override=CHEAP)
    kr.verify_keyring_structure(new_ring, _kdf_override=CHEAP)
    assert [m["device_id"] for m in new_ring["members"]] == [m["device_id"] for m in ring["members"]]
    others = [m for m in ring["members"] if m["device_id"] != ident.device_id]
    assert [m for m in new_ring["members"] if m["device_id"] != ident.device_id] == others
    assert kr.accept_keyring(new_ring, gk, a.state.identity(), _kdf_override=CHEAP) == gk  # same epoch, same key
    assert kr.member_names(new_ring, gk)[ident.device_id] == "B again"
    assert kr.open_with_device_wrap(new_ring, ident, _kdf_override=CHEAP) == gk
    with pytest.raises(kr.KeyringError) as info:
        kr.rejoin_with_password(ring, PW, pairing.DeviceIdentity.generate(ident.device_id), "X",
                                _kdf_override=CHEAP)
    assert info.value.reason == "key-mismatch"
    with pytest.raises(kr.KeyringError) as info:
        kr.rejoin_with_password(ring, PW, pairing.DeviceIdentity.generate(), "X", _kdf_override=CHEAP)
    assert info.value.reason == "not-member"
    with pytest.raises(kr.KeyringError) as info:
        kr.rejoin_with_password(ring, PW2, ident, "X", _kdf_override=CHEAP)
    assert info.value.reason == "password"


# --- Wi-Fi: rules 3, 4 and 5 -----------------------------------------------------------------------------


def _wifi_leave(dev) -> None:
    assert ft.leave_folder_group(dev.session, dev.lease, install_id=dev.install) is True
    dev.stop()


def _repair(inviter, invitee) -> None:
    lt._pair(inviter, invitee)


def test_wifi_rejoin_keeps_one_entry_with_the_same_id_and_syncs_both_ways(devs) -> None:
    a, b = lt._group_ab(devs)
    on_a = lt._web(a, "from-a")
    assert lt.kinds(b.sync_with(a)) == []
    b_id = b.device_id
    _wifi_leave(b)
    b.endpoint, b.port_hold = lt._free_endpoint()
    _repair(a, b)
    assert b.device_id == b_id and load_kept_identity(b.session) is None
    assert [p["device_id"] for p in a.state.lan_peers] == [b_id]
    assert a.responder.enrolled.device_id == b_id
    assert lan.peer_endpoint(a.state, b_id) == b.endpoint  # the address was replaced
    assert lt.kinds(b.sync_with(a)) == []
    on_b = lt._web(b, "from-b")
    assert lt.kinds(a.sync_with(b)) == []
    assert a.entry(on_b)["label"] == "from-b" and b.entry(on_a)["label"] == "from-a"


def test_wifi_rejoin_continues_the_hello_counter(devs) -> None:
    """The hazard: the host keeps the last hello counter of this id; a restart below it is a replay."""
    a, b = lt._group_ab(devs)
    far = 10**15
    b.relisten(hello_clock=lambda: far)
    assert lt.kinds(b.sync_with(a)) == []
    high = a.transport.state.inbound_counters[b.device_id]
    assert high >= far
    _wifi_leave(b)
    assert load_kept_identity(b.session).hello_counter >= high
    b.endpoint, b.port_hold = lt._free_endpoint()
    _repair(a, b)
    assert a.transport.state.inbound_counters[b.device_id] == high  # the host forgot nothing
    b.relisten(hello_clock=lambda: 5)  # the clock is far behind the counter the host holds
    assert lt.kinds(b.sync_with(a)) == []
    assert a.transport.state.inbound_counters[b.device_id] > high


def test_a_known_id_is_refused_with_other_keys_when_revoked_and_when_only_a_folder_member(devs) -> None:
    a, b = lt._group_ab(devs)
    st = a.state
    save_sync_state(a.session, dataclasses.replace(st, members_epoch=st.epoch, members=("folder-member-1",)))
    offer, _text = lt._offer_for(a)
    sender = lt.SyncTransport()
    refused = pairing.enrollment_refusal()
    # The same id with other keys, the host's own id, and a folder member the host cannot compare.
    assert sender.enroll(a.endpoint, pairing.build_enrollment_request(
        offer, pairing.DeviceIdentity.generate(b.device_id), now=NOW)) == refused
    assert sender.enroll(a.endpoint, lt._custom_request(
        offer, lt._body(offer, pairing.DeviceIdentity.generate(a.device_id)))) == refused
    assert sender.enroll(a.endpoint, pairing.build_enrollment_request(
        offer, pairing.DeviceIdentity.generate("folder-member-1"), now=NOW)) == refused
    ident_b = b.state.identity()
    # A revoked entry (same keys) and a peer revoked on the running listener (same keys).
    entry = dict(lan.peer_entry(a.state, b.device_id), revoked=True)
    save_sync_state(a.session, dataclasses.replace(a.state, lan_peers=(entry,)))
    assert sender.enroll(a.endpoint, pairing.build_enrollment_request(offer, ident_b, now=NOW)) == refused
    entry["revoked"] = False
    save_sync_state(a.session, dataclasses.replace(a.state, lan_peers=(entry,)))
    a.transport.state.revoke_peer(b.device_id)
    assert sender.enroll(a.endpoint, pairing.build_enrollment_request(offer, ident_b, now=NOW)) == refused
    assert a.responder.pairing.attempts == 5 and a.responder.pairing.exhausted
    assert [p["device_id"] for p in a.state.lan_peers] == [b.device_id]


def test_a_known_device_pairs_again_on_a_full_list_and_others_still_get_full(devs) -> None:
    a, b = lt._group_ab(devs)
    fakes = [dict(p) for p in a.state.lan_peers]
    for i in range(lan.MAX_LAN_PEERS - 1):
        ident = pairing.DeviceIdentity.generate(f"fake-{i}")
        fakes.append(lan.peer_to_entry(pairing.PairedDevice(
            ident.device_id, a.state.group_id, ident.signing_public_key, ident.exchange_public_key,
            ident.fingerprint, NOW, ident.sign(b"x"))))
    save_sync_state(a.session, dataclasses.replace(a.state, lan_peers=tuple(fakes)))
    _offer, text = lt._offer_for(a)
    c = devs("c")
    with pytest.raises(lan.LanSyncError) as err:
        lan.enroll_from_qr(text, c.session, c.lease, install_id=c.install, now=NOW)
    assert err.value.reason == "too-many-peers"
    assert a.responder.pairing.attempts == 0 and not a.responder.pairing.exhausted
    b_id = b.device_id
    _wifi_leave(b)
    lan.enroll_from_qr(text, b.session, b.lease, install_id=b.install, now=NOW)  # same offer
    assert b.device_id == b_id
    assert len(a.state.lan_peers) == lan.MAX_LAN_PEERS
    assert [p["device_id"] for p in a.state.lan_peers].count(b_id) == 1


def test_a_released_host_refusal_drops_the_kept_identity_with_the_rule_5_message(devs, monkeypatch) -> None:
    a, b = lt._group_ab(devs)
    b_id = b.device_id
    _wifi_leave(b)
    # A host on a released build refuses every id it knows with the plain refusal.
    monkeypatch.setattr(lan.LanResponder, "_known_keys", lambda self, state: {})
    _offer, text = lt._offer_for(a)
    with pytest.raises(lan.LanSyncError) as err:
        lan.enroll_from_qr(text, b.session, b.lease, install_id=b.install, now=NOW)
    assert err.value.reason == "pair-again"
    assert str(err.value).endswith(lan.PAIR_AGAIN_MESSAGE) or lan.PAIR_AGAIN_MESSAGE in str(err.value)
    assert error_text(err.value) == t("sync.theOtherDeviceCouldNotPair")
    assert t("sync.theOtherDeviceCouldNotPair") == lan.PAIR_AGAIN_MESSAGE
    assert load_kept_identity(b.session) is None and load_sync_state(b.session) is None
    # The next pairing uses a new identity, as before (one more row on the released host).
    _offer, text = lt._offer_for(a)
    lan.enroll_from_qr(text, b.session, b.lease, install_id=b.install, now=NOW)
    assert b.device_id != b_id


def test_declined_full_or_expired_keeps_the_kept_identity(devs) -> None:
    a, b = lt._group_ab(devs)
    b_id = b.device_id
    _wifi_leave(b)
    a.accept = False
    _offer, text = lt._offer_for(a)
    with pytest.raises(lan.LanSyncError) as err:
        lan.enroll_from_qr(text, b.session, b.lease, install_id=b.install, now=NOW)
    assert err.value.reason == "declined"
    assert load_kept_identity(b.session).device_id == b_id
    a.accept = True
    _offer, text = lt._offer_for(a)
    lan.enroll_from_qr(text, b.session, b.lease, install_id=b.install, now=NOW)
    assert b.device_id == b_id


def test_pairing_into_another_group_leaves_the_kept_identity_alone(devs) -> None:
    a, b = lt._group_ab(devs)
    _wifi_leave(b)
    kept = load_kept_identity(b.session)
    z = devs("z", group=True)
    _offer, text = lt._offer_for(z)
    lan.enroll_from_qr(text, b.session, b.lease, install_id=b.install, now=NOW)
    assert b.device_id != kept.device_id and load_kept_identity(b.session) == kept


def test_a_peer_that_never_left_is_unaffected_by_a_pairing_under_a_new_id(devs) -> None:
    """Compatibility: a device without a kept identity pairs exactly as before (a new id, a new entry)."""
    a, b = lt._group_ab(devs)
    c = devs("c")
    lt._pair(a, c)
    assert c.device_id not in (a.device_id, b.device_id)
    assert {p["device_id"] for p in a.state.lan_peers} == {b.device_id, c.device_id}
    assert base64.b64decode(lan.peer_entry(a.state, c.device_id)["signing_public"]) == \
        c.state.identity().signing_public_key


# --- a removed (revoked) Wi-Fi peer never comes back under its kept id --------------------------------------


def _remove(host, peer_id: str) -> None:
    assert lan.remove_lan_peer(host.session, host.lease, peer_id, install_id=host.install, transport=host.transport)


def test_a_removed_wifi_peer_stays_revoked_and_its_kept_id_is_refused_after_a_restart(devs) -> None:
    a, b = lt._group_ab(devs)
    assert lt.kinds(b.sync_with(a)) == []
    b_id, ident_b = b.device_id, b.state.identity()
    _remove(a, b_id)
    entry = lan.peer_entry(a.state, b_id)
    assert entry["revoked"] is True and a.state.lan_removed is True
    assert base64.b64decode(entry["signing_public"]) == ident_b.signing_public_key  # keys stay pinned
    assert not lan.remove_lan_peer(a.session, a.lease, b_id, install_id=a.install)  # already revoked: no change
    refused = pairing.enrollment_refusal()
    # While running: the removed id with its own pinned keys is refused like any reserved id.
    offer, _text = lt._offer_for(a)
    assert lt.SyncTransport().enroll(a.endpoint, pairing.build_enrollment_request(offer, ident_b, now=NOW)) == refused
    # After a restart (everything read back from the vault): its hello and its kept id are still refused.
    a.relisten()
    assert lt.kinds(b.sync_with(a)) == ["not-accepted"]
    offer, _text = lt._offer_for(a)
    assert lt.SyncTransport().enroll(a.endpoint, pairing.build_enrollment_request(offer, ident_b, now=NOW)) == refused
    _wifi_leave(b)
    assert load_kept_identity(b.session).device_id == b_id
    b.endpoint, b.port_hold = lt._free_endpoint()
    _offer, text = lt._offer_for(a)
    with pytest.raises(lan.LanSyncError) as err:
        lan.enroll_from_qr(text, b.session, b.lease, install_id=b.install, now=NOW)
    assert err.value.reason == "pair-again" and load_kept_identity(b.session) is None
    # The same device pairs again under a new id; the revoked entry stays as it is.
    _repair(a, b)
    assert b.device_id != b_id
    assert {p["device_id"]: p["revoked"] for p in a.state.lan_peers} == {b_id: True, b.device_id: False}
    on_b = lt._web(b, "from-new-b")
    assert lt.kinds(a.sync_with(b)) == [] and lt.kinds(b.sync_with(a)) == []
    assert a.entry(on_b)["label"] == "from-new-b"


def test_a_revoked_entry_is_not_a_device_on_the_sync_page_and_is_no_heir(devs) -> None:
    import contextlib
    from types import SimpleNamespace

    from localvault.app.sync_view import lan_removed_folder_text, snapshot_job

    a, b = lt._group_ab(devs)
    c = devs("c")
    lt._pair(a, c)
    assert lan.set_heir_peer(a.session, a.lease, b.device_id, True)
    _remove(a, b.device_id)
    assert b.device_id not in a.state.heir_peers
    # A later heir answer is not recorded for it: the pruning on add drops it again.
    assert lan.set_heir_peer(a.session, a.lease, c.device_id, True)
    assert lan.set_heir_peer(a.session, a.lease, b.device_id, True)
    assert lan.set_heir_peer(a.session, a.lease, "another", True)
    assert b.device_id not in a.state.heir_peers and c.device_id in a.state.heir_peers
    snap, corrupt = snapshot_job(a.install)(a.session, a.lease, SimpleNamespace(ui_released=contextlib.nullcontext))
    assert not corrupt and [p.device_id for p in snap.lan_peers] == [c.device_id] and snap.lan_removed
    assert b.device_id[:8] not in lan_removed_folder_text(snap)


def test_a_revoked_entry_counts_against_the_peer_limit(devs) -> None:
    """As on the iPhone, Mac and Android (``LanPeers.maxPeers``: revoked entries count)."""
    a, b = lt._group_ab(devs)
    fakes = [dict(p) for p in a.state.lan_peers]
    for i in range(lan.MAX_LAN_PEERS - 1):
        ident = pairing.DeviceIdentity.generate(f"fake-{i}")
        fakes.append(lan.peer_to_entry(pairing.PairedDevice(
            ident.device_id, a.state.group_id, ident.signing_public_key, ident.exchange_public_key,
            ident.fingerprint, NOW, ident.sign(b"x"))))
    save_sync_state(a.session, dataclasses.replace(a.state, lan_peers=tuple(fakes)))
    _remove(a, b.device_id)
    assert len(a.state.lan_peers) == lan.MAX_LAN_PEERS
    _offer, text = lt._offer_for(a)
    c = devs("c")
    with pytest.raises(lan.LanSyncError) as err:
        lan.enroll_from_qr(text, c.session, c.lease, install_id=c.install, now=NOW)
    assert err.value.reason == "too-many-peers"


def test_a_host_with_a_revoked_entry_rotates_leaves_and_resets(devs, root: Path) -> None:
    a, b = lt._group_ab(devs)
    c = devs("c")
    lt._pair(a, c)
    _remove(a, b.device_id)
    ft.add_folder_to_group(root, a.session, a.lease, PW, "PC A", install_id=a.install, now=NOW,
                           _kdf_override=CHEAP, fresh_key=True)
    ft.rotate_folder_group(root, a.session, a.lease, PW2, keep=[], install_id=a.install, now=NOW,
                           _kdf_override=CHEAP)
    st = a.state
    assert st.lan_removed is False
    assert {p["device_id"]: p["revoked"] for p in st.lan_peers} == {b.device_id: True, c.device_id: False}
    assert ft.leave_folder_group(a.session, a.lease, install_id=a.install) is True
    assert load_kept_identity(a.session).device_id == st.device_id
    assert reset_sync(a.session, a.lease) is True and load_sync_state(a.session) is None


def test_an_older_vault_whose_removed_peer_was_deleted_needs_nothing(devs) -> None:
    """An older build deleted the entry: there is nothing to migrate, and nothing is listed again."""
    a, b = lt._group_ab(devs)
    save_sync_state(a.session, dataclasses.replace(a.state, lan_peers=(), lan_removed=True))
    assert not lan.remove_lan_peer(a.session, a.lease, b.device_id, install_id=a.install)
    assert a.state.lan_peers == () and a.state.lan_removed is True
    a.relisten()
    assert lt.kinds(b.sync_with(a)) == ["not-accepted"]
