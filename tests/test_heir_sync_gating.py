"""Sub-plan 08 review round 2: the emergency access plan (``heir:plan``) reaches only peers that read it.

Older desktop builds and the phone apps refuse the ``heir`` namespace, so it is published over the sync folder
only when every other member wrote a signed heir capability file, and over Wi-Fi only to peers that answered
``heir-hello``.  Also: a synced plan that re-keys the stored one is refused, and request floods are read.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest
import test_sync_folder_transport as folder_tests
import test_sync_lan as lan_tests
from cryptography.hazmat.primitives.asymmetric import ed25519
from test_sync_folder_transport import kinds
from test_sync_lan import _group_ab
from test_sync_lan import kinds as lan_kinds

from localvault import envelope, heir, heir_flow
from localvault.sync import attachment_sync as asy
from localvault.sync import folder_transport as ft
from localvault.sync import lan_sync as lan
from localvault.sync.engine import ItemState, MergeOutcome, bump
from localvault.sync.group import decode_view
from localvault.sync.vault_bridge import (
    HEIR_STATE_ID,
    BridgeError,
    apply,
    local_view,
    publishable,
)
from localvault.vault import create_vault

MASTER = folder_tests.MASTER
NOW = folder_tests.NOW


def _make_plan(session, folder=None):
    phrase = session.create_recovery_phrase(MASTER)
    plan, packages = heir.create_plan(session, k=2, n=2, holders=("Anna", "Ben"), wait_days=3, folder=folder,
                                      phrase=phrase, reauthenticate=lambda: True)
    return plan, packages, phrase


def _has_plan(view_states) -> bool:
    return any(s.item_id == HEIR_STATE_ID for s in view_states)


class _Lease:
    def check(self) -> None:
        return None


# ------------------------------------------------------------------------------------------- publishable
def test_publishable_leaves_the_plan_out_unless_the_peer_reads_it(tmp_path):
    session = create_vault(tmp_path / "v.json", MASTER, kdf_overrides=folder_tests.TEST_KDF)
    _make_plan(session)
    view = local_view(session, _Lease(), device_id="device-a", now=NOW)
    assert _has_plan(view.values())
    assert not _has_plan(publishable(view.values(), documents=True))
    assert _has_plan(publishable(view.values(), documents=True, heir=True))


# ------------------------------------------------------------------------------------------------ folder
@pytest.fixture
def root(tmp_path: Path) -> Path:
    path = tmp_path / "OneDrive"
    path.mkdir()
    return path


def _caps(root: Path, device_id: str) -> list[Path]:
    return list((root / ft.SYNC_DIR_NAME / asy.BLOBS_DIR_NAME).glob(f"{device_id}.lgkheircap*"))


def _folder_view_has_plan(dev, viewer) -> bool:
    view = decode_view(viewer.gk(), dev.own_file.read_bytes(), expected_device_id=dev.device_id)
    return _has_plan(view.states)


def test_folder_member_without_the_heir_feature_never_sees_the_plan(tmp_path, root, monkeypatch):
    a, b = folder_tests._group(tmp_path, root, n=2)
    older = b.device_id
    real = ft.write_capability
    monkeypatch.setattr(ft, "write_capability",
                        lambda sync_dir, gk, device_id, *args, feature="documents", **kw:
                        False if (device_id == older and feature == "heir")
                        else real(sync_dir, gk, device_id, *args, feature=feature, **kw))
    for path in _caps(root, older):  # written while the group was set up
        path.unlink()
    _make_plan(a.session)
    for _ in range(2):
        for dev in (a, b):
            report = dev.sync()
            assert kinds(report) == []  # the older member sees no sync issue
    assert not _folder_view_has_plan(a, b) and heir.load_plan(b.session) is None
    assert _caps(root, a.device_id)  # A advertises the feature itself
    monkeypatch.setattr(ft, "write_capability", real)  # B updated
    for _ in range(2):
        for dev in (b, a):
            assert kinds(dev.sync()) == []
    assert _folder_view_has_plan(a, b) and heir.load_plan(b.session).home is False


# ------------------------------------------------------------------------------------------------- Wi-Fi
@pytest.fixture
def devs(tmp_path: Path):
    made = []

    def make(name: str, *, group: bool = False):
        (tmp_path / name).mkdir()
        session = create_vault(tmp_path / name / f"{name}.json", lan_tests.MASTER, kdf_overrides=lan_tests.TEST_KDF)
        endpoint, hold = lan_tests._free_endpoint()
        d = lan_tests.Dev(name, session, lan_tests.FakeLease(), f"install-{name}", endpoint, port_hold=hold)
        made.append(d)
        if group:
            lan.create_lan_group(d.session, d.lease, install_id=d.install)
            d.relisten()
        return d

    yield make
    for d in made:
        d.stop()


class _PhoneResponder:
    """A responder that does not know ``heir-hello`` (an older desktop or a phone app): it answers bad-message."""

    def __init__(self, dev) -> None:
        self.inner, self.types = dev.responder, []
        dev.transport.set_peer_request_handler(self)

    def __call__(self, peer, request: bytes) -> bytes:
        msg = json.loads(request)
        self.types.append(msg.get("type"))
        if msg.get("type") == "heir-hello":
            return lan.encode_message({"type": "error", "reason": "bad-message"})
        return self.inner(peer, request)


def test_wifi_peers_learn_the_feature_and_then_get_the_plan(devs):
    a, b = _group_ab(devs)
    _make_plan(a.session)
    assert lan_kinds(b.sync_with(a)) == []  # first exchange: the feature is learned both ways
    assert a.device_id in b.state.heir_peers and b.device_id in a.state.heir_peers
    assert lan_kinds(b.sync_with(a)) == []
    assert heir.load_plan(b.session) is not None and heir.load_plan(b.session).home is False


def test_wifi_peer_without_the_feature_never_gets_the_plan_and_sees_no_issue(devs):
    a, b = _group_ab(devs)
    phone = _PhoneResponder(b)
    _make_plan(a.session)
    for _ in range(3):
        assert lan_kinds(a.sync_with(b)) == []
    assert "heir-hello" in phone.types
    assert b.device_id not in a.state.heir_peers and heir.load_plan(b.session) is None


# ------------------------------------------------------------------------ a synced plan cannot re-key it
def test_a_remote_that_re_keys_the_same_plan_is_refused(tmp_path):
    a = create_vault(tmp_path / "a.json", MASTER, kdf_overrides=folder_tests.TEST_KDF)
    b = create_vault(tmp_path / "b.json", MASTER, kdf_overrides=folder_tests.TEST_KDF)
    plan, _packages, _phrase = _make_plan(a)
    view_a = local_view(a, _Lease(), device_id="device-a", now=NOW)
    view_b = local_view(b, _Lease(), device_id="device-b", now=NOW)
    from localvault.sync.engine import merge

    apply(b, _Lease(), merge(view_b, view_a.values()), device_id="device-b", now=NOW)
    assert heir.load_plan(b).signer == plan.signer
    state = view_a[HEIR_STATE_ID]
    other = ed25519.Ed25519PrivateKey.generate()
    record = dict(state.item["record"], signing_key=envelope.b64e(other.private_bytes_raw()),
                  signer=envelope.b64e(other.public_key().public_bytes_raw()))
    with pytest.raises(heir.HeirError) as raised:
        heir.merge_synced(b.heir_plan_record(), record)
    assert raised.value.reason == "conflict"
    forged = ItemState(HEIR_STATE_ID, bump(bump(state.vv, "device-a"), "device-a"), False, None,
                       {**state.item, "record": record})
    local_view(b, _Lease(), device_id="device-b", now=NOW)
    with pytest.raises(BridgeError) as refused:
        apply(b, _Lease(), MergeOutcome(upserts=(forged,), deletes=(), conflicts=()), device_id="device-b", now=NOW)
    assert refused.value.reason == "bad-remote"
    assert heir.load_plan(b).signer == plan.signer  # B keeps the plan key the shards name
    # Same plan, only a new refused id: that merges.
    request_id = "0b5f0c43-7f6a-4c2a-9a55-7d3f9f2f9c11"
    merged = heir.merge_synced(b.heir_plan_record(), dict(state.item["record"], denied=[request_id]))
    assert merged["denied"] == [request_id]


# --------------------------------------------------------------------------- well-named request floods
def test_well_named_junk_requests_hide_no_real_request(tmp_path, monkeypatch):
    shared = tmp_path / "shared"
    shared.mkdir()
    session = create_vault(tmp_path / "owner.json", MASTER, kdf_overrides=folder_tests.TEST_KDF)
    plan, packages, _phrase = _make_plan(session, folder=shared)
    folder = heir_flow.plan_dir(shared, plan.plan_id)
    folder.mkdir(parents=True)
    for n in range(heir_flow.MAX_SCAN + 100):  # names that sort before any random request id
        (folder / f"request-00000000-0000-4000-8000-{n:012x}.lgkheirreq").write_bytes(b"{}")
    heir_flow.request_access(shared, packages[0], heir_flow.RequesterIdentity.generate())
    pending = heir_flow.pending_requests(session)
    assert [r.holder for r in pending] == ["Anna"] and not pending.flooded
    monkeypatch.setattr(heir_flow, "MAX_REQUEST_SCAN", 100)
    assert heir_flow.pending_requests(session).flooded  # past the hard cap the owner is warned


def test_a_copied_documents_capability_does_not_pass_as_the_heir_one(tmp_path):
    """Review M1: the heir capability names its feature (its own view counter); a copy of another signed file of
    the same device, made by anyone with write access to the folder, is not read as one."""
    import base64
    import shutil

    from localvault.sync import attachment_flow as af
    from localvault.sync.group import GroupKey

    gk = GroupKey("group-1", 1, bytes(range(32)))
    key = ed25519.Ed25519PrivateKey.generate()
    signer = base64.b64encode(key.public_key().public_bytes_raw()).decode("ascii")
    assert af.write_capability(tmp_path, gk, "device-b", key, signer, now=NOW)
    assert af.folder_capable(tmp_path, gk, "device-b", signer)
    assert not af.folder_capable(tmp_path, gk, "device-b", signer, feature="heir")
    cap, sig = af._cap_paths(tmp_path, "device-b")
    heir_cap, heir_sig = af._cap_paths(tmp_path, "device-b", "heir")
    shutil.copyfile(cap, heir_cap)
    shutil.copyfile(sig, heir_sig)
    assert not af.folder_capable(tmp_path, gk, "device-b", signer, feature="heir")
    assert af.write_capability(tmp_path, gk, "device-b", key, signer, now=NOW, feature="heir")
    assert af.folder_capable(tmp_path, gk, "device-b", signer, feature="heir")
    assert not af.write_capability(tmp_path, gk, "device-b", key, signer, now=NOW, feature="heir")


def test_a_failed_heir_hello_does_not_drop_the_wifi_run(monkeypatch):
    """Review M2: the probe's failure is ignored; the next run asks again."""
    calls = []

    def call(msg):
        calls.append(msg)
        raise lan.LanSyncError("bad-message", "gone")

    monkeypatch.setattr(lan, "load_sync_state", lambda session: type("S", (), {"heir_peers": ()})())
    lan._probe_heir(call, object(), _Lease(), "peer-1")
    assert calls == [{"type": "heir-hello"}]


def test_heir_peers_drop_devices_no_longer_paired(devs):
    """Review M3: an unpaired device leaves ``heir_peers``, and each add drops ids that are no longer known."""
    import dataclasses

    from localvault.sync.vault_bridge import load_sync_state, save_sync_state

    a, b = _group_ab(devs)
    _make_plan(a.session)
    assert lan_kinds(b.sync_with(a)) == []
    assert b.device_id in a.state.heir_peers
    state = load_sync_state(a.session)
    save_sync_state(a.session, dataclasses.replace(state, heir_peers=(*state.heir_peers, "gone-device")))
    assert lan.set_heir_peer(a.session, a.lease, "new-device", True)
    assert set(a.state.heir_peers) == {b.device_id, "new-device"}
    assert lan.remove_lan_peer(a.session, a.lease, b.device_id, install_id=a.install)
    assert b.device_id not in a.state.heir_peers
