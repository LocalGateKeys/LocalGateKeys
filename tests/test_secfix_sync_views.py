"""Audit 2026-10-24 M-7: a member must not be able to forge or freeze another device's sync file."""
from __future__ import annotations

import base64
import dataclasses
import json
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric import ed25519
from test_sync_folder_transport import CHEAP, NOW, PW2, _group, _older_app_members, _ring_path, _web, kinds

from localvault.sync import folder_transport as ft
from localvault.sync.engine import ItemState
from localvault.sync.group import (
    SyncFormatError,
    decode_view,
    encode_view,
    sign_view,
    verify_view_signature,
)
from localvault.sync.vault_bridge import SyncGroupState, save_sync_state
from localvault.updates import canonical_json

MAX = 2**53 - 1
VECTORS = Path(__file__).parent / "vectors" / "sync"


@pytest.fixture
def root(tmp_path: Path) -> Path:
    path = tmp_path / "OneDrive"
    path.mkdir()
    return path


def _sig_file(root: Path, dev) -> Path:
    return root / ft.SYNC_DIR_NAME / ft.SIGNATURES_DIR_NAME / f"{dev.device_id}{ft.SIGNATURE_SUFFIX}"


def _forge(m, victim, eid: str, counter: int, value: str = "attacker-chosen") -> None:
    """m (holding G) writes the victim's file with chosen content and counter (the audit PoC)."""
    gk = m.gk()
    view = decode_view(gk, victim.own_file.read_bytes(), expected_device_id=victim.device_id)
    states = []
    for s in view.states:
        if s.item_id == eid:
            item = dict(s.item)
            item["record"] = {**item["record"], "password": value}
            vv = {**s.vv, victim.device_id: s.vv.get(victim.device_id, 0) + 1}
            s = ItemState(s.item_id, vv, False, None, item)
        states.append(s)
    victim.own_file.write_bytes(encode_view(gk, victim.device_id, counter, states, NOW + 1))


def b64key(dev) -> str:
    return base64.b64encode(dev.state.identity().signing_public_key).decode()


def _unpin(*devs) -> None:
    for d in devs:
        st = d.state
        save_sync_state(d.session, dataclasses.replace(
            st, view_signers={k: v for k, v in st.view_signers.items() if k == st.device_id}))


# --- format --------------------------------------------------------------------------------


def test_sign_and_verify_view(root: Path, tmp_path: Path) -> None:
    a, _b = _group(tmp_path, root, 2)
    raw = a.own_file.read_bytes()
    header = decode_view(a.gk(), raw).header
    sig = _sig_file(root, a).read_bytes()
    assert verify_view_signature(sig, raw, header) == a.state.identity().signing_public_key
    doc = json.loads(sig)
    assert set(doc) == {"format", "group_id", "device_id", "epoch", "counter", "view_sha256", "signing_public", "sig"}
    assert sign_view(raw, a.state.identity().signing_key) == sig  # Ed25519 is deterministic

    with pytest.raises(SyncFormatError) as err:
        verify_view_signature(sig, raw + b"x", header)
    assert err.value.reason == "sig-mismatch"
    with pytest.raises(SyncFormatError) as err:
        verify_view_signature(sig, raw, {**header, "counter": header["counter"] + 1})
    assert err.value.reason == "sig-stale"
    other = ed25519.Ed25519PrivateKey.generate()
    body = {k: v for k, v in doc.items() if k != "sig"}
    forged = canonical_json({**body, "sig": base64.b64encode(other.sign(b"lgk-sync-view-sig-v1|"
                                                                        + canonical_json(body))).decode()})
    with pytest.raises(SyncFormatError) as err:
        verify_view_signature(forged, raw, header)
    assert err.value.reason == "sig-mismatch"
    for bad in (b"{", sig + b" ", canonical_json({**doc, "extra": 1}), b"x" * 5000,
                canonical_json({**doc, "format": 2})):
        with pytest.raises(SyncFormatError) as err:
            verify_view_signature(bad, raw, header)
        assert err.value.reason == "sig-malformed"


def test_shared_signature_vector() -> None:
    ids = json.loads((VECTORS / "identities.json").read_text(encoding="utf-8"))
    raw = (VECTORS / "devices" / "A.lgksync").read_bytes()
    sig = (VECTORS / "signatures" / "A.lgksig").read_bytes()
    from localvault.sync.group import _read_header

    header = _read_header(raw)[0]
    assert base64.b64encode(verify_view_signature(sig, raw, header)).decode() == ids["devices"]["A"]["signing_public_b64"]
    cases = json.loads((VECTORS / "hardening_cases.json").read_text(encoding="utf-8"))["signatures"]
    assert cases
    for case in cases:
        try:
            verify_view_signature(case["signature"].encode("utf-8"), raw, header)
            got = "valid"
        except SyncFormatError as exc:
            got = exc.reason
        assert got == case["expected"], case["name"]


# --- the audit PoC -------------------------------------------------------------------------


def test_forged_victim_file_is_refused_and_reported(root: Path, tmp_path: Path) -> None:
    a, b, m = _group(tmp_path, root, 3)
    eid = _web(a, "bank")
    for d in (a, b, m):
        d.sync(NOW)
    _forge(m, b, eid, MAX)

    report = a.sync(NOW + 2)
    assert kinds(report) == ["view-unsigned"]
    assert a.entry(eid)["password"] == "pw-123456"
    assert a.state.last_seen[b.device_id] < 100

    report = b.sync(NOW + 3)  # the victim notices and takes its file back
    assert kinds(report) == ["own-file-rewritten"]
    assert b.state.own_counter < 100
    b.session.update_entry_fields(eid, password="b-real-edit")
    assert kinds(b.sync(NOW + 5)) == []
    assert kinds(a.sync(NOW + 6)) == []
    assert a.entry(eid)["password"] == "b-real-edit"


def test_unpinned_forgery_with_huge_counter_cannot_freeze_the_victim(root: Path, tmp_path: Path) -> None:
    a, b, m = _group(tmp_path, root, 3)
    eid = _web(a, "bank")
    for d in (a, b, m):
        d.sync(NOW)
    _older_app_members(root, a, b)
    _unpin(a)  # a has only ever seen unsigned views (b on an older app)
    _sig_file(root, b).unlink()
    _forge(m, b, eid, MAX)

    report = a.sync(NOW + 2)
    assert kinds(report) == ["implausible-counter"]
    assert a.entry(eid)["password"] == "pw-123456"

    report = b.sync(NOW + 3)  # never raises, never overflows
    assert kinds(report) == ["own-file-rewritten"] and report.wrote
    b.session.update_entry_fields(eid, password="b-real-edit")
    b.sync(NOW + 4)
    assert kinds(a.sync(NOW + 5)) == []
    assert a.entry(eid)["password"] == "b-real-edit"


def test_unpinned_small_forgery_is_followed_by_the_victim(root: Path, tmp_path: Path) -> None:
    a, b, m = _group(tmp_path, root, 3)
    eid = _web(a, "bank")
    for d in (a, b, m):
        d.sync(NOW)
    _older_app_members(root, a, b)
    _unpin(a)
    _sig_file(root, b).unlink()
    forged = b.state.own_counter + 3
    _forge(m, b, eid, forged)
    a.sync(NOW + 2)
    assert a.entry(eid)["password"] == "attacker-chosen"  # unsigned, unpinned: still accepted (older peers)

    report = b.sync(NOW + 3)
    assert kinds(report) == ["own-file-rewritten"]
    assert b.state.own_counter == forged + 1  # moved past it, so a does not report a rollback
    assert "rollback" not in kinds(a.sync(NOW + 4))


def test_own_counter_overflow_is_reported_not_raised(root: Path, tmp_path: Path) -> None:
    a, _b = _group(tmp_path, root, 2)
    st = a.state
    save_sync_state(a.session, dataclasses.replace(st, own_counter=MAX))
    _web(a, "new")
    report = a.sync(NOW + 1)
    assert "counter-exhausted" in kinds(report) and not report.wrote


def test_rotation_resets_peer_counters(root: Path, tmp_path: Path) -> None:
    a, b, m = _group(tmp_path, root, 3)
    eid = _web(a, "bank")
    for d in (a, b, m):
        d.sync(NOW)
    st = a.state
    # a forged counter accepted before this fix: a's last-seen for b is far ahead of b
    save_sync_state(a.session, dataclasses.replace(st, last_seen={**st.last_seen, b.device_id: 2**40}))
    assert "rollback" in kinds(a.sync(NOW + 1))
    ft.rotate_folder_group(root, a.session, a.lease, PW2, remove=[m.device_id], keep=[b.device_id],
                           install_id=a.install, now=NOW + 2, _kdf_override=CHEAP)
    assert a.state.last_seen == {} and a.state.peer_digests == {}
    # pins of the old epoch are gone; only the new keyring's members are pinned again, from the keyring
    assert set(a.state.view_signers) <= {a.device_id, b.device_id}
    assert a.state.view_signers.get(b.device_id, b64key(b)) == b64key(b)
    b.sync(NOW + 3)
    assert b.state.last_seen.get(m.device_id) is None
    b.session.update_entry_fields(eid, password="after-rotation")
    b.sync(NOW + 4)
    assert kinds(a.sync(NOW + 5)) == []
    assert a.entry(eid)["password"] == "after-rotation"


def test_counter_jump_is_refused(root: Path, tmp_path: Path) -> None:
    a, b = _group(tmp_path, root, 2)
    _older_app_members(root, a, b)
    _unpin(a)
    _sig_file(root, b).unlink()
    gk = b.gk()
    view = decode_view(gk, b.own_file.read_bytes(), expected_device_id=b.device_id)
    last = a.state.last_seen[b.device_id]
    b.own_file.write_bytes(encode_view(gk, b.device_id, last + ft.MAX_COUNTER_JUMP + 1, view.states, NOW + 1))
    assert kinds(a.sync(NOW + 2)) == ["implausible-counter"]
    b.own_file.write_bytes(encode_view(gk, b.device_id, last + ft.MAX_COUNTER_JUMP, view.states, NOW + 1))
    assert kinds(a.sync(NOW + 3)) == []


# --- compatibility --------------------------------------------------------------------------


def test_unsigned_views_of_older_peers_still_sync(root: Path, tmp_path: Path) -> None:
    a, b = _group(tmp_path, root, 2)
    _older_app_members(root, a, b)  # b joined with an app from before keyring format 2
    _unpin(a)
    eid = _web(b, "legacy")
    original = ft.FolderSync.write_own

    def legacy_write(self, *args, **kwargs):  # an app from before signatures
        kwargs.pop("signing_key", None)
        return original(self, *args, **kwargs)

    ft.FolderSync.write_own = legacy_write
    try:
        _sig_file(root, b).unlink()
        b.sync(NOW + 1)
    finally:
        ft.FolderSync.write_own = original
    assert not _sig_file(root, b).exists()
    assert kinds(a.sync(NOW + 2)) == []
    assert a.entry(eid)["label"] == "legacy"
    assert b.device_id not in a.state.view_signers


def test_signed_peer_is_pinned_and_another_key_is_refused(root: Path, tmp_path: Path) -> None:
    a, b = _group(tmp_path, root, 2)
    pinned = a.state.view_signers[b.device_id]
    assert pinned == base64.b64encode(b.state.identity().signing_public_key).decode()
    # someone re-signs b's file with another key
    raw = b.own_file.read_bytes()
    _sig_file(root, b).write_bytes(sign_view(raw, ed25519.Ed25519PrivateKey.generate()))
    _web(b, "x")  # make a's read happen on a fresh file, not one already accepted
    b.sync(NOW + 1)
    _sig_file(root, b).write_bytes(sign_view(b.own_file.read_bytes(), ed25519.Ed25519PrivateKey.generate()))
    assert kinds(a.sync(NOW + 2)) == ["view-forged"]


def test_lan_paired_key_is_the_only_accepted_signer(root: Path, tmp_path: Path) -> None:
    """For a member whose keyring entry has no key (older app), the LAN-paired key wins over the pin."""
    a, b = _group(tmp_path, root, 2)
    _older_app_members(root, a, b)
    st = a.state
    other = base64.b64encode(ed25519.Ed25519PrivateKey.generate().public_key().public_bytes_raw()).decode()
    entry = {"device_id": b.device_id, "group_id": st.group_id, "signing_public": other,
             "exchange_public": other, "fingerprint": "0" * 64, "endpoint": None}
    save_sync_state(a.session, dataclasses.replace(st, lan_peers=(entry,), view_signers={}))
    _web(b, "y")
    b.sync(NOW + 1)
    assert kinds(a.sync(NOW + 2)) == ["view-forged"]


def test_state_round_trips_view_signers() -> None:
    from localvault.sync.pairing import DeviceIdentity

    ident = DeviceIdentity.generate()
    key = base64.b64encode(ident.signing_public_key).decode()
    st = SyncGroupState("g", 1, b"\x01" * 32, ident.protected_dict(), view_signers={"peer-1": key})
    again = SyncGroupState.from_dict(st.to_dict())
    assert again.view_signers == {"peer-1": key}
    assert "view_signers" not in dataclasses.replace(st, view_signers={}).to_dict()
    from localvault.sync.vault_bridge import BridgeError

    with pytest.raises(BridgeError):
        SyncGroupState("g", 1, b"\x01" * 32, ident.protected_dict(), view_signers={"peer-1": "nope"})


@pytest.mark.parametrize("kind", ["implausible-vv", "implausible-counter", "view-unsigned", "view-forged",
                                  "own-file-rewritten", "counter-exhausted"])
def test_new_issue_kinds_have_user_copy(kind: str) -> None:
    from localvault.app import sync_view as ui
    from localvault.sync.runner import SyncIssue

    assert kind in ui.ISSUE_COPY
    detail = "dev-b:item-1" if kind == "implausible-vv" else "dev-b.lgksync: x"
    text = ui.issue_text(SyncIssue(kind, detail), names={"dev-b": "Laptop"})
    assert text and kind not in text and "{subject}" not in text
    assert ui.issue_severity(kind) == ("error" if kind == "counter-exhausted" else "warning")
    if kind == "implausible-vv":
        assert "Laptop" in text


# --- R-4: the keyring anchors each member's signing key -------------------------------------------


def test_keyring_key_is_pinned_at_once_and_wins_over_a_paired_key(root: Path, tmp_path: Path) -> None:
    a, b = _group(tmp_path, root, 2)
    assert a.state.view_signers[b.device_id] == b64key(b)
    st = a.state
    other = base64.b64encode(ed25519.Ed25519PrivateKey.generate().public_key().public_bytes_raw()).decode()
    entry = {"device_id": b.device_id, "group_id": st.group_id, "signing_public": other,
             "exchange_public": other, "fingerprint": "0" * 64, "endpoint": None}
    save_sync_state(a.session, dataclasses.replace(st, lan_peers=(entry,), view_signers={}))
    eid = _web(b, "anchored")
    b.sync(NOW + 1)
    assert kinds(a.sync(NOW + 2)) == []  # the keyring's key (b's real one) wins over the paired one
    assert a.entry(eid)["label"] == "anchored" and a.state.view_signers[b.device_id] == b64key(b)


def test_a_member_that_never_wrote_cannot_be_pinned_to_a_forger(root: Path, tmp_path: Path) -> None:
    """Before R-4 the first signed view pinned its key: someone with G could sign first for a new member."""
    a, b = _group(tmp_path, root, 2)
    _unpin(a)  # a never saw b's view yet
    _sig_file(root, b).write_bytes(sign_view(b.own_file.read_bytes(), ed25519.Ed25519PrivateKey.generate()))
    _web(b, "z")
    b.sync(NOW + 1)
    _sig_file(root, b).write_bytes(sign_view(b.own_file.read_bytes(), ed25519.Ed25519PrivateKey.generate()))
    assert kinds(a.sync(NOW + 2)) == ["view-forged"]
    assert a.state.view_signers[b.device_id] == b64key(b)  # pinned from the keyring, not from the forgery
    # an unsigned file is refused too: a keyring key means "must be signed"
    _sig_file(root, b).unlink()
    assert kinds(a.sync(NOW + 3)) == ["view-unsigned"]


def test_a_changed_keyring_key_replaces_the_pin_and_is_reported(root: Path, tmp_path: Path) -> None:
    from localvault.sync import keyring as kr

    a, b = _group(tmp_path, root, 2)
    old_pin = a.state.view_signers[b.device_id]
    # someone holding G lists a new key (with a valid proof by that key) for b
    new = ed25519.Ed25519PrivateKey.generate()
    new_b64 = base64.b64encode(new.public_key().public_bytes_raw()).decode()
    path = _ring_path(root)
    ring = kr.parse_keyring(path.read_bytes())
    for m in ring["members"]:
        if m["device_id"] == b.device_id:
            m["signing_public"] = new_b64
            m["signing_proof"] = base64.b64encode(new.sign(kr._proof_message(
                ring["group_id"], m["device_id"], m["exchange_public"], new_b64))).decode()
    path.write_bytes(kr.canonical_json(kr._finish(ring, a.gk(), None, ring["prev_mac"])))
    report = a.sync(NOW + 1)
    assert "signer-changed" in kinds(report) and old_pin != new_b64
    assert a.state.view_signers[b.device_id] == new_b64
