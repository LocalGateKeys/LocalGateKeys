"""Signed removal notices (WP-A): only a notice a trusted member signed proves a removal."""
from __future__ import annotations

import base64
import json
from pathlib import Path

import pytest
import test_sync_folder_transport as ftt
from cryptography.hazmat.primitives.asymmetric import ed25519
from test_sync_folder_transport import CHEAP, NOW, PW2, _group, _ring_path, kinds

from localvault.sync import folder_transport as ft
from localvault.sync import keyring as kr
from localvault.sync import removal
from localvault.updates import canonical_json

root = ftt.root  # the fixture


def _notice_path(root: Path, device_id: str) -> Path:
    return root / ft.SYNC_DIR_NAME / removal.REMOVED_DIR_NAME / f"{device_id}{removal.NOTICE_SUFFIX}"


def _remove(a, c, root: Path) -> None:
    ft.rotate_folder_group(root, a.session, a.lease, PW2, remove=[c.device_id], install_id=a.install, now=NOW,
                           _kdf_override=CHEAP)


def _watch(dev) -> removal.Watch:
    return removal.load_watch(removal.watch_path(dev.session.path))


def test_rotation_writes_a_notice_signed_by_the_remover(tmp_path: Path, root: Path) -> None:
    a, b, c = _group(tmp_path, root)
    c_id = c.device_id
    _remove(a, c, root)
    raw = _notice_path(root, c_id).read_bytes()
    notice, message, sig = removal.parse_notice(raw)
    assert (notice.group_id, notice.device_id, notice.epoch, notice.signer) == (a.state.group_id, c_id, 2,
                                                                                 a.device_id)
    a.state.identity().signing_key.public_key().verify(sig, message)
    assert message.startswith(removal.NOTICE_LABEL)
    # Kept members get no notice.
    assert not _notice_path(root, b.device_id).exists()


def test_removed_device_reports_the_verified_notice(tmp_path: Path, root: Path) -> None:
    a, b, c = _group(tmp_path, root)
    watch = _watch(c)
    assert watch is not None and watch.device_id == c.device_id and a.device_id in watch.signers
    _remove(a, c, root)
    report = c.sync()
    assert kinds(report) == ["rejoin-required", "removal-notice"]
    assert report.issues[-1].detail == a.device_id
    # The app's locked check reads the watch file and finds the same notice.
    notice = removal.check_file(removal.watch_path(c.session.path), install_id=c.install)
    assert notice is not None and notice.device_id == c.device_id
    assert removal.check_file(removal.watch_path(c.session.path), install_id="another-pc") is None


def test_kept_member_never_sees_a_notice(tmp_path: Path, root: Path) -> None:
    a, b, c = _group(tmp_path, root)
    _remove(a, c, root)
    assert "removal-notice" not in kinds(b.sync())
    assert removal.check_file(removal.watch_path(b.session.path), install_id=b.install) is None


def test_unconfirmed_members_lose_the_key_but_get_no_notice(tmp_path: Path, root: Path) -> None:
    a, b, c = _group(tmp_path, root)
    ft.rotate_folder_group(root, a.session, a.lease, PW2, keep=[b.device_id], install_id=a.install, now=NOW,
                           _kdf_override=CHEAP)
    assert c.device_id not in {m["device_id"] for m in kr.parse_keyring(_ring_path(root).read_bytes())["members"]}
    assert not _notice_path(root, c.device_id).exists()
    assert "removal-notice" not in kinds(c.sync())


def test_existing_issue_kinds_alone_never_report_a_notice(tmp_path: Path, root: Path) -> None:
    a, b, c = _group(tmp_path, root)
    _remove(a, c, root)
    _notice_path(root, c.device_id).unlink()
    assert kinds(c.sync()) == ["rejoin-required"]


def _forge(root: Path, c, key: ed25519.Ed25519PrivateKey, signer: str, **changes) -> None:
    body = {"group_id": c.state.group_id, "device_id": c.device_id, "epoch": c.state.epoch + 1,
            "signer": signer, "now": NOW, **changes}
    path = _notice_path(root, c.device_id)
    path.parent.mkdir(exist_ok=True)
    path.write_bytes(removal.make_notice(key, **body))


def test_notice_signed_by_an_unknown_key_is_ignored(tmp_path: Path, root: Path) -> None:
    a, b, c = _group(tmp_path, root)
    _remove(a, c, root)
    _forge(root, c, ed25519.Ed25519PrivateKey.generate(), a.device_id)  # right signer id, wrong key
    assert kinds(c.sync()) == ["rejoin-required"]
    _forge(root, c, ed25519.Ed25519PrivateKey.generate(), "stranger")
    assert kinds(c.sync()) == ["rejoin-required"]


def test_notice_without_a_keyring_that_drops_the_device_is_ignored(tmp_path: Path, root: Path) -> None:
    """A member's genuine signature is not enough while the folder keyring still lists the device."""
    a, b, c = _group(tmp_path, root)
    _forge(root, c, a.state.identity().signing_key, a.device_id)
    report = c.sync()
    assert "removal-notice" not in kinds(report)
    assert removal.check_file(removal.watch_path(c.session.path), install_id=c.install) is None


def test_notice_bound_to_device_group_and_epoch(tmp_path: Path, root: Path) -> None:
    a, b, c = _group(tmp_path, root)
    key = a.state.identity().signing_key
    _remove(a, c, root)
    ring = _ring_path(root).read_bytes()
    watch = removal.load_watch(removal.watch_path(c.session.path))
    good = removal.make_notice(key, group_id=watch.group_id, device_id=watch.device_id, epoch=2,
                               signer=a.device_id, now=NOW)
    assert removal.verify_notice(good, watch, ring).signer == a.device_id
    for change, reason in (({"device_id": b.device_id}, "not-for-this-device"),
                           ({"group_id": "other-group"}, "not-for-this-device"),
                           ({"epoch": watch.epoch}, "stale"),
                           ({"epoch": 3}, "keyring")):
        body = {"group_id": watch.group_id, "device_id": watch.device_id, "epoch": 2, "signer": a.device_id,
                "now": NOW, **change}
        with pytest.raises(removal.RemovalError) as info:
            removal.verify_notice(removal.make_notice(key, **body), watch, ring)
        assert info.value.reason == reason
    # Tampering with any signed field breaks the signature.
    doc = json.loads(good)
    doc["issued_at"] += 1
    with pytest.raises(removal.RemovalError) as info:
        removal.verify_notice(canonical_json(doc), watch, ring)
    assert info.value.reason == "bad-signature"


@pytest.mark.parametrize("raw", [
    b"", b"[]", b"{}", b"not json", b"{\"format\":1}" , b"x" * (removal.MAX_NOTICE_BYTES + 1),
])
def test_malformed_notices_are_refused(raw: bytes) -> None:
    with pytest.raises(removal.RemovalError):
        removal.parse_notice(raw)


def test_notice_with_extra_field_or_bad_signature_encoding_is_refused() -> None:
    key = ed25519.Ed25519PrivateKey.generate()
    good = json.loads(removal.make_notice(key, group_id="g", device_id="d", epoch=2, signer="s", now=1))
    for doc in ({**good, "extra": 1}, {**good, "sig": good["sig"] + "="}, {**good, "format": True},
                {**good, "epoch": 2.0}):
        with pytest.raises(removal.RemovalError):
            removal.parse_notice(json.dumps(doc).encode())
    with pytest.raises(removal.RemovalError):
        removal.make_notice(key, group_id="g", device_id="d", epoch=2, signer="d", now=1)  # self-removal


def test_leave_and_reset_forget_the_watch_file(tmp_path: Path, root: Path) -> None:
    a, b, c = _group(tmp_path, root)
    path_c, path_b = removal.watch_path(c.session.path), removal.watch_path(b.session.path)
    assert path_c.is_file() and path_b.is_file()
    c_id = c.device_id
    ft.leave_folder_group(c.session, c.lease, install_id=c.install)
    assert not path_c.exists()
    ft.rotate_folder_group(root, a.session, a.lease, PW2, remove=[c_id], install_id=a.install, now=NOW,
                           _kdf_override=CHEAP)
    assert _notice_path(root, c_id).is_file()  # removed after it left: never erased
    assert removal.check_file(path_c, install_id=c.install) is None
    from localvault.sync.service import reset_sync

    reset_sync(b.session, b.lease)
    assert not path_b.exists()


def test_watch_file_round_trip_and_rejects_garbage(tmp_path: Path) -> None:
    watch = removal.Watch("g", "d", 3, "install", str(tmp_path), {"s": base64.b64encode(b"k" * 32).decode()})
    path = tmp_path / "vault.sync-watch.json"
    assert removal.save_watch(path, watch) is True
    assert removal.save_watch(path, watch) is False  # unchanged: not rewritten
    assert removal.load_watch(path) == watch
    path.write_text('{"version":1}', encoding="utf-8")
    assert removal.load_watch(path) is None
    assert removal.check(watch, install_id="install") is None  # no folder, no notice


def test_unconfirmed_members_cannot_sign_and_keys_stay_pinned(tmp_path: Path, root: Path) -> None:
    import dataclasses

    a, b, c = _group(tmp_path, root)
    state = c.state
    fresh = removal.watch_from_state(state, root)
    assert set(fresh.signers) == {a.device_id, b.device_id}
    unconfirmed = removal.watch_from_state(dataclasses.replace(state, unacked_members=(b.device_id,)), root)
    assert set(unconfirmed.signers) == {a.device_id}
    # Someone holding the group key swaps A's signing key in the keyring: the stored pin wins.
    stored = _watch(c)
    other = base64.b64encode(ed25519.Ed25519PrivateKey.generate().public_key().public_bytes_raw()).decode()
    swapped = dataclasses.replace(fresh, signers={**fresh.signers, a.device_id: other})
    assert removal.pinned(swapped, stored).signers[a.device_id] == stored.signers[a.device_id]
    # A member gone from the trusted keyring signs nothing any more.
    dropped = dataclasses.replace(fresh, signers={b.device_id: fresh.signers[b.device_id]})
    assert set(removal.pinned(dropped, stored).signers) == {b.device_id}
