"""Cloud-folder transport and the shared sync runner (three simulated devices, no Tk)."""
from __future__ import annotations

import base64
import dataclasses
import hashlib
import os
import time
from dataclasses import dataclass
from pathlib import Path

import pytest

from localvault.session_guard import StaleSession
from localvault.sync import folder_transport as ft
from localvault.sync import keyring as kr
from localvault.sync import runner
from localvault.sync.engine import ItemState
from localvault.sync.group import GroupKey, View, decode_view, encode_view
from localvault.sync.pairing import DeviceIdentity
from localvault.sync.vault_bridge import (
    BridgeError,
    SyncGroupState,
    load_sync_state,
    local_view,
    save_sync_state,
)
from localvault.vault import create_vault

TEST_KDF = {"time_cost": 1, "memory_cost_kib": 8192, "parallelism": 1, "hash_len": 32}
CHEAP = (1024, 1, 1)
MASTER = "synthetic master"
PW = "correct horse battery staple 7!"
PW2 = "another very long passphrase 42?"
NOW = int(time.time())
DAY = 86400


class FakeLease:
    def __init__(self) -> None:
        self.valid = True

    def check(self) -> None:
        if not self.valid:
            raise StaleSession("Vault is locked")


@dataclass
class Dev:
    name: str
    session: object
    lease: FakeLease
    install: str
    root: Path

    @property
    def state(self) -> SyncGroupState:
        return load_sync_state(self.session)

    @property
    def device_id(self) -> str:
        return self.state.device_id

    @property
    def own_file(self) -> Path:
        return self.root / ft.SYNC_DIR_NAME / "devices" / f"{self.device_id}.lgksync"

    def gk(self) -> GroupKey:
        st = self.state
        return GroupKey(st.group_id, st.epoch, st.key)

    def sync(self, now: int = NOW, install: str | None = None) -> runner.RunReport:
        fs = ft.FolderSync(self.root, install_id=install or self.install, _kdf_override=CHEAP)
        return fs.run_once(self.session, self.lease, now=now)

    def labels(self) -> list[str]:
        return sorted(e["label"] for e in self.session._payload["entries"])

    def entry(self, entry_id: str) -> dict:
        return next(e for e in self.session._payload["entries"] if e["id"] == entry_id)

    def vault_bytes(self) -> bytes:
        return Path(self.session.path).read_bytes()


def _device(tmp_path: Path, name: str, root: Path) -> Dev:
    session = create_vault(tmp_path / f"{name}.json", MASTER, kdf_overrides=TEST_KDF)
    return Dev(name, session, FakeLease(), f"install-{name}", root)


def kinds(report: runner.RunReport) -> list[str]:
    return [i.kind for i in report.issues]


@pytest.fixture
def root(tmp_path: Path) -> Path:
    path = tmp_path / "OneDrive"
    path.mkdir()
    return path


def _group(tmp_path: Path, root: Path, n: int = 3) -> list[Dev]:
    devs = [_device(tmp_path, name, root) for name in "abc"[:n]]
    a = devs[0]
    ft.create_folder_group(root, a.session, a.lease, PW, "PC A", install_id=a.install, now=NOW,
                           _kdf_override=CHEAP)
    for d in devs[1:]:
        ft.join_folder_group(root, d.session, d.lease, PW, f"PC {d.name.upper()}", install_id=d.install,
                             now=NOW, _kdf_override=CHEAP)
    for d in devs:  # every device has now accepted the final keyring
        d.sync()
    for d in devs:  # the user confirmed the devices that joined (audit M10 "member-added")
        ft.acknowledge_members(d.session, d.lease, d.state.unacked_members, install_id=d.install)
    return devs


def _round(devs: list[Dev], now: int = NOW) -> list[runner.RunReport]:
    return [d.sync(now) for d in devs]


def _web(dev: Dev, label: str) -> str:
    return dev.session.upsert_web(origin=f"https://{label}.example.com", username="me", password="pw-123456",
                                  label=label)


# --- happy paths ---------------------------------------------------------------------------


def test_layout_and_create_join(tmp_path: Path, root: Path) -> None:
    a, b, c = _group(tmp_path, root)
    sync_dir = root / ft.SYNC_DIR_NAME
    assert ft.SYNC_DIR_NAME == "LocalGateKeys Sync"
    assert (sync_dir / "keyring.lgkkeys").is_file()
    files = sorted(p.name for p in (sync_dir / "devices").iterdir())
    assert files == sorted(f"{d.device_id}.lgksync" for d in (a, b, c))
    ring = kr.parse_keyring((sync_dir / "keyring.lgkkeys").read_bytes())
    assert {m["device_id"] for m in ring["members"]} == {a.device_id, b.device_id, c.device_id}
    for d in (a, b, c):
        assert d.state.install_id == d.install and d.state.group_id == ring["group_id"]


def test_edit_propagates_a_to_b_to_c(tmp_path: Path, root: Path) -> None:
    a, b, c = _group(tmp_path, root)
    entry_id = _web(a, "mail")
    assert a.sync().wrote
    b.sync()
    assert b.entry(entry_id)["password"] == "pw-123456"
    b.session.update_entry_fields(entry_id, password="changed-on-b")
    b.sync()
    c.sync()
    assert c.entry(entry_id)["password"] == "changed-on-b"
    a.sync()
    assert a.entry(entry_id)["password"] == "changed-on-b"


def test_unchanged_run_does_not_rewrite(tmp_path: Path, root: Path) -> None:
    a, b = _group(tmp_path, root, 2)
    _web(a, "mail")
    a.sync()
    before = a.own_file.read_bytes()
    report = a.sync()
    assert not report.wrote and a.own_file.read_bytes() == before
    a.own_file.unlink()
    assert a.sync().wrote and a.own_file.is_file()


def test_concurrent_edits_converge_with_one_conflict_copy(tmp_path: Path, root: Path) -> None:
    devs = _group(tmp_path, root)
    a, b, c = devs
    entry_id = _web(a, "bank")
    _round(devs)
    _round(devs)
    a.session.update_entry_fields(entry_id, password="edit-on-a")
    b.session.update_entry_fields(entry_id, password="edit-on-b")
    _round(devs)
    _round(devs)
    _round(devs)
    views = [sorted((e["label"], e["password"]) for e in d.session._payload["entries"]) for d in devs]
    assert views[0] == views[1] == views[2]
    assert len(views[0]) == 2
    assert sum(label.endswith(" (sync conflict)") for label, _ in views[0]) == 1
    assert {pw for _, pw in views[0]} == {"edit-on-a", "edit-on-b"}


def test_delete_propagates(tmp_path: Path, root: Path) -> None:
    devs = _group(tmp_path, root)
    a, b, c = devs
    entry_id = _web(a, "old")
    _round(devs)
    assert entry_id in {e["id"] for e in c.session._payload["entries"]}
    b.session.delete(entry_id)
    _round(devs)
    _round(devs)  # A ran before B in the first round
    for d in devs:
        assert entry_id not in {e["id"] for e in d.session._payload["entries"]}
        assert entry_id in {r["entry"]["id"] for r in d.session._payload["trash"]}


# --- hostile or broken folder content --------------------------------------------------------


def test_provider_duplicates_and_unknown_files_ignored(tmp_path: Path, root: Path) -> None:
    a, b, c = _group(tmp_path, root)
    _web(b, "shared")
    b.sync()
    devices = b.own_file.parent
    raw = b.own_file.read_bytes()
    names = [f"{b.device_id} (1).lgksync", f"{b.device_id}-DESKTOP-ABC.lgksync", "notes.txt", "x.lgksync.bak"]
    for name in names:
        (devices / name).write_bytes(raw)
    report = a.sync()
    assert kinds(report) == ["ignored-file"]
    detail = report.issues[0].detail
    assert detail.startswith("4 files: ")
    for name in names:
        assert name in detail
    assert a.labels() == ["shared"]
    for n in range(30):
        (devices / f"junk-{n:02d}.txt").write_bytes(b"x")
    (detail,) = [i.detail for i in a.sync().issues]
    assert detail.startswith("34 files: ") and detail.endswith(", +14 more")


def test_own_stale_temp_files_are_swept(tmp_path: Path, root: Path) -> None:
    a, b = _group(tmp_path, root, 2)
    devices = a.own_file.parent
    mine = devices / f".{a.own_file.name}.abc123.tmp"
    theirs = devices / f".{b.own_file.name}.abc123.tmp"
    mine.write_bytes(b"partial")
    theirs.write_bytes(b"partial")
    assert kinds(a.sync()) == []
    assert not mine.exists() and theirs.exists()


def test_truncated_and_corrupt_files_skip_only_that_peer(tmp_path: Path, root: Path) -> None:
    a, b, c = _group(tmp_path, root)
    _web(c, "from-c")
    c.sync()
    _web(b, "from-b")
    b.sync()  # C has not seen from-b, so only B's file carries it
    raw = b.own_file.read_bytes()
    b.own_file.write_bytes(raw[: len(raw) // 2])
    before = a.vault_bytes()
    report = a.sync()
    assert [(i.kind, i.detail.split(":")[0]) for i in report.issues] == [("corrupt", f"{b.device_id}.lgksync")]
    assert a.labels() == ["from-c"]
    assert before != a.vault_bytes()
    b.own_file.write_bytes(b"\x00garbage" * 50)
    assert kinds(a.sync()) == ["corrupt"]
    flipped = bytearray(raw)
    flipped[-5] ^= 1
    b.own_file.write_bytes(bytes(flipped))
    assert kinds(a.sync()) == ["corrupt"]
    b.own_file.unlink()
    b.sync()  # B notices its file is missing and rewrites it
    assert kinds(a.sync()) == []
    assert a.labels() == ["from-b", "from-c"]


def test_rollback_and_suspicious_rewrite(tmp_path: Path, root: Path) -> None:
    a, b = _group(tmp_path, root, 2)
    entry_id = _web(b, "acct")
    b.sync()
    old = b.own_file.read_bytes()
    b.session.update_entry_fields(entry_id, password="newer-password")
    b.sync()
    a.sync()
    assert a.entry(entry_id)["password"] == "newer-password"
    current = b.own_file.read_bytes()
    b.own_file.write_bytes(old)  # cloud restores an older version
    report = a.sync()
    assert kinds(report) == ["rollback"]
    assert a.entry(entry_id)["password"] == "newer-password"
    # Same counter, different bytes (re-encrypted with the group key): suspicious.
    view = decode_view(b.gk(), current, expected_device_id=b.device_id)
    rewrite = encode_view(b.gk(), b.device_id, view.header["counter"], view.states, view.header["written_at"])
    assert rewrite != current
    b.own_file.write_bytes(rewrite)
    assert kinds(a.sync()) == ["suspicious-rewrite"]
    b.own_file.write_bytes(current)
    assert kinds(a.sync()) == []


def test_file_swapped_for_another_device_is_device_mismatch(tmp_path: Path, root: Path) -> None:
    a, b, c = _group(tmp_path, root)
    _web(c, "from-c")
    c.sync()
    b.own_file.write_bytes(c.own_file.read_bytes())
    report = a.sync()
    assert kinds(report) == ["device-mismatch"]
    assert f"{b.device_id}.lgksync" in report.issues[0].detail
    assert a.labels() == ["from-c"]


def test_stale_device_file_is_skipped(tmp_path: Path, root: Path) -> None:
    a, b = _group(tmp_path, root, 2)
    _web(b, "ancient")
    b.sync(now=NOW - 400 * DAY)
    report = a.sync()
    assert kinds(report) == ["stale-device"]
    assert a.labels() == []


def test_missing_folder_reports_and_leaves_vault_alone(tmp_path: Path, root: Path) -> None:
    a, b = _group(tmp_path, root, 2)
    _web(a, "local")
    before = a.vault_bytes()
    (root / ft.SYNC_DIR_NAME).rename(root / "moved")
    report = a.sync()
    assert kinds(report) == ["folder-missing"]
    assert a.vault_bytes() == before
    assert not report.wrote


def test_install_id_mismatch_refuses_and_never_writes(tmp_path: Path, root: Path) -> None:
    a, b = _group(tmp_path, root, 2)
    _web(a, "local")
    before_vault, before_file = a.vault_bytes(), a.own_file.read_bytes()
    report = a.sync(install="another-pc")
    assert kinds(report) == ["rejoin-required"]
    assert a.vault_bytes() == before_vault and a.own_file.read_bytes() == before_file


def test_counter_strictly_increases_across_crashes(tmp_path: Path, root: Path, monkeypatch) -> None:
    a, b = _group(tmp_path, root, 2)
    first = decode_view(a.gk(), a.own_file.read_bytes()).header["counter"]
    _web(a, "x1")

    def crash(path: Path, data: bytes) -> None:
        raise OSError("disk went away")

    monkeypatch.setattr(ft, "_atomic_write", crash)
    report = a.sync()
    assert kinds(report) == ["write-failed"] and not report.wrote
    assert a.state.own_counter == first + 1
    monkeypatch.undo()
    assert a.sync().wrote
    second = decode_view(a.gk(), a.own_file.read_bytes()).header["counter"]
    assert second == first + 2
    # A vault restored from an older backup must still never reuse a counter.
    stale = a.state
    _web(a, "x2")
    a.sync()
    third = decode_view(a.gk(), a.own_file.read_bytes()).header["counter"]
    save_sync_state(a.session, dataclasses.replace(a.state, own_counter=stale.own_counter))
    _web(a, "x3")
    a.sync()
    assert decode_view(a.gk(), a.own_file.read_bytes()).header["counter"] > third
    b.sync()
    assert b.labels() == ["x1", "x2", "x3"]


def test_no_temp_files_left_and_other_files_untouched(tmp_path: Path, root: Path) -> None:
    a, b = _group(tmp_path, root, 2)
    b_before = b.own_file.read_bytes()
    _web(a, "x")
    a.sync()
    assert b.own_file.read_bytes() == b_before
    names = sorted(p.name for p in a.own_file.parent.iterdir())
    assert names == sorted([a.own_file.name, b.own_file.name])


# --- keyring trust ---------------------------------------------------------------------------


def _ring_path(root: Path) -> Path:
    return root / ft.SYNC_DIR_NAME / "keyring.lgkkeys"


def test_removed_device_cannot_read_after_rotation(tmp_path: Path, root: Path) -> None:
    devs = _group(tmp_path, root)
    a, b, c = devs
    c_id, c_gk = c.device_id, c.gk()
    ft.rotate_folder_group(root, a.session, a.lease, PW2, remove=[c_id], install_id=a.install, now=NOW,
                           _kdf_override=CHEAP)
    assert not c.own_file.exists()
    assert a.state.epoch == 2
    _web(a, "after-rotation")
    a.sync()
    report = c.sync()
    assert kinds(report) == ["rejoin-required"]
    assert c.labels() == []
    with pytest.raises(Exception) as info:
        decode_view(c_gk, a.own_file.read_bytes())
    assert getattr(info.value, "reason", "") == "epoch-mismatch"
    with pytest.raises(ft.FolderSyncError) as info:
        ft.join_folder_group(root, c.session, c.lease, PW, "C again", install_id=c.install, now=NOW,
                             _kdf_override=CHEAP)
    assert info.value.reason == "password" and isinstance(info.value.__cause__, kr.KeyringError)
    with pytest.raises(kr.KeyringError):
        kr.join_with_password(kr.parse_keyring(_ring_path(root).read_bytes()), PW, c.state.identity(), "C",
                              _kdf_override=CHEAP)


def test_lagging_device_adopts_rotation(tmp_path: Path, root: Path) -> None:
    devs = _group(tmp_path, root)
    a, b, c = devs
    entry_id = _web(b, "from-b")
    b.sync()
    a.sync()
    ft.rotate_folder_group(root, a.session, a.lease, PW2, install_id=a.install, now=NOW, _kdf_override=CHEAP)
    a.session.update_entry_fields(entry_id, password="post-rotation")
    report = a.sync()
    assert "epoch-mismatch" in kinds(report), report.issues  # B and C still write epoch 1
    report = b.sync()
    assert kinds(report) == ["epoch-mismatch"], report.issues  # C has not adopted epoch 2 yet
    assert b.state.epoch == 2
    assert b.entry(entry_id)["password"] == "post-rotation"
    assert decode_view(b.gk(), b.own_file.read_bytes()).header["epoch"] == 2
    report = c.sync()
    assert kinds(report) == [], report.issues
    report = a.sync()
    assert kinds(report) == [], report.issues


def test_tampered_keyring_stops_sync(tmp_path: Path, root: Path) -> None:
    a, b = _group(tmp_path, root, 2)
    _web(b, "from-b")
    b.sync()
    path = _ring_path(root)
    ring = kr.parse_keyring(path.read_bytes())
    ring["members"][0]["added_at"] += 1
    path.write_bytes(kr.canonical_json(ring))
    report = a.sync()
    assert kinds(report) == ["keyring-restored"]
    assert report.issues[0].detail.startswith("tampered") and "tampered: tampered" not in report.issues[0].detail
    assert path.read_bytes() == a.state.keyring
    assert a.labels() == ["from-b"]
    assert kinds(b.sync()) == []


def test_rolled_back_keyring_stops_sync(tmp_path: Path, root: Path) -> None:
    a, b = _group(tmp_path, root, 2)
    old = _ring_path(root).read_bytes()
    ft.rotate_folder_group(root, a.session, a.lease, PW2, install_id=a.install, now=NOW, _kdf_override=CHEAP)
    _ring_path(root).write_bytes(old)  # attacker (or provider history) replays an older keyring
    report = a.sync()
    assert kinds(report)[0] == "keyring-restored" and report.issues[0].detail.startswith("rollback")
    assert set(kinds(report)[1:]) <= {"epoch-mismatch"}  # B has not adopted epoch 2 yet
    restored = _ring_path(root).read_bytes()
    assert restored == a.state.keyring and kr.parse_keyring(restored)["epoch"] == 2
    assert kinds(b.sync()) == []
    assert b.state.epoch == 2


def test_foreign_keyring_stops_without_writing(tmp_path: Path, root: Path) -> None:
    a, b = _group(tmp_path, root, 2)
    _web(a, "local-edit")
    ring, _gk = kr.create_group(PW, kr.DeviceIdentity.generate(), "M", _kdf_override=CHEAP)
    foreign = kr.canonical_json(ring)
    _ring_path(root).write_bytes(foreign)
    before = a.vault_bytes(), a.own_file.read_bytes()
    report = a.sync()
    assert kinds(report) == ["folder-has-other-group"] and not report.wrote
    assert _ring_path(root).read_bytes() == foreign
    assert (a.vault_bytes(), a.own_file.read_bytes()) == before


def test_two_groups_in_one_folder_do_not_ping_pong(tmp_path: Path, root: Path) -> None:
    """An old member was offline while the folder was emptied and a new group created there."""
    a, b = _group(tmp_path, root, 2)
    sync_dir = root / ft.SYNC_DIR_NAME
    for path in sorted(sync_dir.rglob("*"), reverse=True):
        path.rmdir() if path.is_dir() else path.unlink()
    sync_dir.rmdir()
    z = _device(tmp_path, "z", root)
    ft.create_folder_group(root, z.session, z.lease, PW2, "PC Z", install_id=z.install, now=NOW,
                           _kdf_override=CHEAP)
    z_ring = _ring_path(root).read_bytes()
    for _ in range(3):
        assert kinds(a.sync()) == ["folder-has-other-group"]
        assert kinds(z.sync()) == []
        assert _ring_path(root).read_bytes() == z_ring
    assert not (sync_dir / "devices" / f"{a.device_id}.lgksync").exists()


def test_without_stored_keyring_a_bad_keyring_stops_sync(tmp_path: Path, root: Path) -> None:
    a, b = _group(tmp_path, root, 2)
    save_sync_state(a.session, dataclasses.replace(a.state, keyring=None))
    ring, _gk = kr.create_group(PW, kr.DeviceIdentity.generate(), "M", _kdf_override=CHEAP)
    _ring_path(root).write_bytes(kr.canonical_json(ring))
    before = a.vault_bytes()
    assert kinds(a.sync()) == ["folder-has-other-group"]
    assert a.vault_bytes() == before
    # A same-group tamper without a stored copy stops with "tampered".
    ring = kr.parse_keyring(a.state.keyring or b.state.keyring)
    ring["members"][0]["added_at"] += 1
    _ring_path(root).write_bytes(kr.canonical_json(ring))
    assert kinds(a.sync()) == ["tampered"]
    assert a.vault_bytes() == before


def test_missed_rotations_require_rejoin(tmp_path: Path, root: Path) -> None:
    a, b = _group(tmp_path, root, 2)
    ft.rotate_folder_group(root, a.session, a.lease, PW2, install_id=a.install, now=NOW, _kdf_override=CHEAP)
    ft.rotate_folder_group(root, a.session, a.lease, "third long sync phrase 99#", install_id=a.install,
                           now=NOW, _kdf_override=CHEAP)
    before = b.vault_bytes()
    assert kinds(b.sync()) == ["rejoin-required"]
    assert b.vault_bytes() == before


def test_member_dropped_at_same_epoch_is_reported(tmp_path: Path, root: Path) -> None:
    a, b, c = _group(tmp_path, root)
    a.sync()
    path = _ring_path(root)
    ring = kr.parse_keyring(path.read_bytes())
    gk = a.gk()
    ring["members"] = [m for m in ring["members"] if m["device_id"] != c.device_id]
    ring["device_wraps"].pop(c.device_id)
    path.write_bytes(kr.canonical_json(kr._finish(ring, gk, None, ring["prev_mac"])))
    report = a.sync()
    assert ("member-dropped", c.device_id) in [(i.kind, i.detail) for i in report.issues]
    assert "member-dropped" in kinds(a.sync())  # keeps warning until a rotation


def test_join_refuses_folder_of_another_group(tmp_path: Path, root: Path) -> None:
    (a,) = _group(tmp_path, root, 1)
    other = tmp_path / "Dropbox"
    other.mkdir()
    z = _device(tmp_path, "z", other)
    ft.create_folder_group(other, z.session, z.lease, PW, "PC Z", install_id=z.install, now=NOW,
                           _kdf_override=CHEAP)
    with pytest.raises(ft.FolderSyncError) as info:
        ft.join_folder_group(other, a.session, a.lease, PW, "PC A", install_id=a.install, now=NOW,
                             _kdf_override=CHEAP)
    assert info.value.reason == "different-group"
    with pytest.raises(ft.FolderSyncError) as info:
        ft.create_folder_group(other, _device(tmp_path, "y", other).session, FakeLease(), PW, "Y",
                               install_id="i", now=NOW, _kdf_override=CHEAP)
    assert info.value.reason == "folder-in-use"


def test_leave_keeps_own_file_and_clears_state(tmp_path: Path, root: Path) -> None:
    a, b = _group(tmp_path, root, 2)
    entry_id = _web(b, "kept")
    _round([a, b])
    b_file = b.own_file
    b_before = b_file.read_bytes()
    a_before = a.own_file.read_bytes()
    assert ft.leave_folder_group(b.session, b.lease, install_id=b.install) is True
    assert b_file.read_bytes() == b_before and a.own_file.read_bytes() == a_before
    assert load_sync_state(b.session) is None
    assert b.entry(entry_id)["label"] == "kept"
    assert ft.leave_folder_group(b.session, b.lease, install_id=b.install) is False


def test_edits_synced_just_before_leaving_still_reach_the_group(tmp_path: Path, root: Path) -> None:
    """I2: B edits, syncs and leaves before A and C ran; A and C still receive the edit."""
    a, b, c = _group(tmp_path, root, 3)
    shared = _web(a, "shared")
    _round([a, b, c])
    new_on_b = _web(b, "made-on-b")
    b.session.update_entry_fields(shared, password="edited-on-b")
    assert kinds(b.sync()) == []
    b_id, b_file = b.device_id, b.own_file
    ft.leave_folder_group(b.session, b.lease, install_id=b.install)
    for d in (a, c):
        assert kinds(d.sync()) == []
        assert d.entry(new_on_b)["label"] == "made-on-b"
        assert d.entry(shared)["password"] == "edited-on-b"
    # Removing B (rotation) is what deletes its file.
    ft.rotate_folder_group(root, a.session, a.lease, PW2, [b_id], install_id=a.install, now=NOW,
                           _kdf_override=CHEAP)
    assert not b_file.exists()


def test_leave_with_cloned_install_keeps_files(tmp_path: Path, root: Path) -> None:
    a, b = _group(tmp_path, root, 2)
    b_file = b.own_file
    ft.leave_folder_group(b.session, b.lease, install_id="another-pc")
    assert b_file.exists()
    assert load_sync_state(b.session) is None


# --- shared runner ---------------------------------------------------------------------------


def _view_of(dev: Dev) -> View:
    return decode_view(dev.gk(), dev.own_file.read_bytes(), expected_device_id=dev.device_id)


def test_same_view_via_two_routes(tmp_path: Path, root: Path) -> None:
    a, b = _group(tmp_path, root, 2)
    entry_id = _web(a, "twice")
    a.sync()
    lan = runner.run_merge(b.session, b.lease, device_id=b.device_id, views=[_view_of(a), _view_of(a)], now=NOW)
    assert lan.applied == 1 and lan.conflicts == 0 and lan.issues == ()
    report = b.sync()
    assert report.applied == 0 and report.conflicts == 0
    assert b.labels() == ["twice"]
    a.sync()
    assert a.labels() == ["twice"] and b.entry(entry_id)["password"] == "pw-123456"


def test_run_merge_returns_post_apply_view(tmp_path: Path, root: Path) -> None:
    a, b = _group(tmp_path, root, 2)
    _web(a, "x")
    a.sync()
    report = runner.run_merge(b.session, b.lease, device_id=b.device_id, views=[_view_of(a)], now=NOW)
    fresh = local_view(b.session, b.lease, device_id=b.device_id, now=NOW)
    assert {s.item_id: s for s in report.own_states} == dict(fresh)


def _bad_view(dev: Dev, device_id: str) -> View:
    bogus = ItemState("bogus-1", {device_id: 1}, False, None,
                      {"ns": "entry", "schema": 1, "updated_at": 0, "record": {"id": "bogus-1", "kind": "web"}})
    header = {"format": 1, "group_id": dev.state.group_id, "device_id": device_id, "epoch": dev.state.epoch,
              "counter": 1, "written_at": NOW}
    return View(header, (bogus,))


def test_bad_peer_data_view_does_not_abort_run(tmp_path: Path, root: Path) -> None:
    a, b = _group(tmp_path, root, 2)
    _web(a, "good")
    a.sync()
    report = runner.run_merge(b.session, b.lease, device_id=b.device_id,
                              views=[_bad_view(b, "0-evil"), _view_of(a)], now=NOW)
    # Per-record quarantine (I4): only the bad record is skipped and reported.
    assert [(i.kind, i.detail) for i in report.issues] == [("bad-peer-record", "0-evil:bogus-1")]
    assert b.labels() == ["good"]


def test_busy_vault_retries_once_then_reports(tmp_path: Path, root: Path, monkeypatch) -> None:
    a, b = _group(tmp_path, root, 2)
    _web(a, "good")
    a.sync()
    real = runner.apply
    calls = []

    def flaky(*args, **kwargs):
        calls.append(1)
        if len(calls) == 1:
            raise BridgeError("vault changed", reason="vault-changed")
        return real(*args, **kwargs)

    monkeypatch.setattr(runner, "apply", flaky)
    report = runner.run_merge(b.session, b.lease, device_id=b.device_id, views=[_view_of(a)], now=NOW)
    assert report.issues == () and b.labels() == ["good"] and len(calls) == 2

    def always(*args, **kwargs):
        raise BridgeError("vault changed", reason="vault-changed")

    monkeypatch.setattr(runner, "apply", always)
    _web(a, "second")
    a.sync()
    report = runner.run_merge(b.session, b.lease, device_id=b.device_id, views=[_view_of(a)], now=NOW)
    assert kinds(report) == ["busy"] and report.applied == 0


@pytest.mark.parametrize("reason", ["trash-full", "history-quota"])
def test_user_fixable_bridge_errors_become_issues(tmp_path: Path, root: Path, monkeypatch, reason) -> None:
    a, b = _group(tmp_path, root, 2)
    _web(a, "good")
    a.sync()

    def full(*args, **kwargs):
        raise BridgeError("full", reason=reason)

    monkeypatch.setattr(runner, "apply", full)
    report = runner.run_merge(b.session, b.lease, device_id=b.device_id, views=[_view_of(a)], now=NOW)
    assert kinds(report) == [reason] and report.own_states is not None


def test_real_concurrent_edit_refusal_has_reason(tmp_path: Path, root: Path) -> None:
    from localvault.sync.engine import merge
    from localvault.sync.vault_bridge import apply

    a, b = _group(tmp_path, root, 2)
    entry_id = _web(b, "mine")
    b.sync()
    _web(a, "theirs")
    a.sync()
    view = local_view(b.session, b.lease, device_id=b.device_id, now=NOW)
    b.session.update_entry_fields(entry_id, password="edited-meanwhile")
    outcome = merge(view, _view_of(a).states)
    edited = ItemState(entry_id, {**view[entry_id].vv, a.device_id: 9}, False, None, view[entry_id].item)
    outcome = type(outcome)((*outcome.upserts, edited), outcome.deletes, outcome.conflicts, outcome.copies)
    with pytest.raises(BridgeError) as info:
        apply(b.session, b.lease, outcome, device_id=b.device_id, now=NOW)
    assert info.value.reason == "vault-changed"


def test_locked_vault_aborts_without_writing(tmp_path: Path, root: Path) -> None:
    a, b = _group(tmp_path, root, 2)
    _web(a, "x")
    before = a.own_file.read_bytes()
    a.lease.valid = False
    with pytest.raises(StaleSession):
        a.sync()
    assert a.own_file.read_bytes() == before


def test_peer_digest_tracked_in_state(tmp_path: Path, root: Path) -> None:
    a, b = _group(tmp_path, root, 2)
    a.sync()
    raw = b.own_file.read_bytes()
    st = a.state
    assert st.last_seen[b.device_id] == decode_view(b.gk(), raw).header["counter"]
    assert st.peer_digests[b.device_id] == hashlib.sha256(raw).hexdigest()
    assert set(st.members) == {a.device_id, b.device_id} and st.members_epoch == 1


def _renamed(view: View, device_id: str) -> View:
    return View({**view.header, "device_id": device_id}, view.states)


def test_copy_from_earlier_view_does_not_conflict_with_stored_copy(tmp_path: Path, root: Path) -> None:
    """B merges A's raw edit first, then C's view that already stores the resulting copy."""
    a, b, c = _group(tmp_path, root)
    entry_id = _web(a, "bank")
    _round([a, b, c])
    _round([a, b, c])
    a.session.update_entry_fields(entry_id, password="edit-on-a")
    b.session.update_entry_fields(entry_id, password="edit-on-b")
    a.sync()
    view_a = _view_of(a)
    b_states = tuple(local_view(b.session, b.lease, device_id=b.device_id, now=NOW).values())
    view_b = View({**view_a.header, "device_id": b.device_id}, b_states)
    runner.run_merge(c.session, c.lease, device_id=c.device_id, views=[view_a, view_b], now=NOW)
    c.sync()
    assert len(c.labels()) == 2
    # Force the order: A's raw edit first, C's merged view (with the stored copy) second.
    report = runner.run_merge(b.session, b.lease, device_id=b.device_id,
                              views=[_renamed(_view_of(c), "z-last"), _renamed(view_a, "0-first")], now=NOW)
    assert report.issues == ()
    assert sorted((e["label"], e["password"]) for e in b.session._payload["entries"]) == sorted(
        (e["label"], e["password"]) for e in c.session._payload["entries"])


# --- fix round 1 -----------------------------------------------------------------------------


def test_join_racing_rotation_is_undone_by_restore(tmp_path: Path, root: Path, monkeypatch) -> None:
    """J read the keyring before A rotated (removing C) and wrote its join after: A restores."""
    a, b, c = _group(tmp_path, root)
    j = _device(tmp_path, "j", root)
    real_write = ft._atomic_write
    fired = []

    def racing_write(path: Path, data: bytes) -> None:
        if path.name == ft.KEYRING_NAME and not fired:
            fired.append(1)  # A's rotation lands between J's re-read and J's replace
            ft.rotate_folder_group(root, a.session, a.lease, PW2, remove=[c.device_id], install_id=a.install,
                                   now=NOW, _kdf_override=CHEAP)
        real_write(path, data)

    monkeypatch.setattr(ft, "_atomic_write", racing_write)
    ft.join_folder_group(root, j.session, j.lease, PW, "PC J", install_id=j.install, now=NOW,
                         _kdf_override=CHEAP)
    monkeypatch.undo()
    assert kr.parse_keyring(_ring_path(root).read_bytes())["epoch"] == 1  # J's stale write won
    report = a.sync()
    assert kinds(report)[0] == "keyring-restored" and "rollback" in report.issues[0].detail
    ring = kr.parse_keyring(_ring_path(root).read_bytes())
    assert ring["epoch"] == 2 and c.device_id not in {m["device_id"] for m in ring["members"]}
    _web(a, "after")
    a.sync()
    assert kinds(j.sync()) == ["rejoin-required"]
    assert kinds(c.sync()) == ["rejoin-required"]
    b.sync()
    assert b.state.epoch == 2 and b.labels() == ["after"]


@pytest.mark.parametrize("op", ["join", "rotate"])
def test_keyring_changed_since_read_aborts(tmp_path: Path, root: Path, monkeypatch, op) -> None:
    a, b = _group(tmp_path, root, 2)
    j = _device(tmp_path, "j", root)
    path = _ring_path(root)
    ring = kr.parse_keyring(path.read_bytes())
    ring["members"] = list(reversed(ring["members"]))
    meddled = kr.canonical_json(kr._finish(ring, a.gk(), None, ring["prev_mac"]))
    assert meddled != path.read_bytes()
    name = "join_with_password" if op == "join" else "rotate"
    real = getattr(ft, name)

    def meddle(*args, **kwargs):
        out = real(*args, **kwargs)
        path.write_bytes(meddled)  # someone else wrote the keyring meanwhile
        return out

    monkeypatch.setattr(ft, name, meddle)
    with pytest.raises(ft.FolderSyncError) as info:
        if op == "join":
            ft.join_folder_group(root, j.session, j.lease, PW, "PC J", install_id=j.install, now=NOW,
                                 _kdf_override=CHEAP)
        else:
            ft.rotate_folder_group(root, a.session, a.lease, PW2, install_id=a.install, now=NOW,
                                   _kdf_override=CHEAP)
    assert info.value.reason == "keyring-changed"
    assert path.read_bytes() == meddled
    assert a.state.epoch == 1
    assert load_sync_state(j.session) is None


@pytest.mark.parametrize("probe", ["D:evil", "C:{victim}", "CON", "nul.txt", "Lpt9", "com1.x.y", "COM0", "lpt0.a", "trailing."])
def test_unsafe_device_ids_never_become_paths(tmp_path: Path, root: Path, probe: str) -> None:
    a, b = _group(tmp_path, root, 2)
    fs = ft.FolderSync(root, install_id=a.install, _kdf_override=CHEAP)
    with pytest.raises(ValueError):
        fs.device_file(probe.format(victim=b.device_id))
    assert fs.device_file(b.device_id) == b.own_file


def test_unsafe_members_are_skipped_and_removed_without_unlink(tmp_path: Path, root: Path, monkeypatch) -> None:
    a, b = _group(tmp_path, root, 2)
    path = _ring_path(root)
    probes = ["D:evil", "C:" + b.device_id]
    for probe in probes:
        ring = kr.parse_keyring(path.read_bytes())
        joined, _gk = kr.join_with_password(ring, PW, kr.DeviceIdentity.generate(probe), "probe",
                                            _kdf_override=CHEAP)
        path.write_bytes(kr.canonical_json(joined))
    monkeypatch.chdir(b.own_file.parent)  # "C:<victim>.lgksync" would resolve to B's file here
    report = a.sync()
    assert sorted(i.detail for i in report.issues if i.kind == "unsafe-member") == sorted(probes)
    ft.rotate_folder_group(root, a.session, a.lease, PW2, remove=probes, install_id=a.install, now=NOW,
                           _kdf_override=CHEAP)
    assert b.own_file.is_file()
    ring = kr.parse_keyring(path.read_bytes())
    assert {m["device_id"] for m in ring["members"]} == {a.device_id, b.device_id}


@pytest.mark.parametrize("bad", [None, "", "x" * 129, 7, "a\x00b"])
def test_install_id_must_be_a_bounded_string(tmp_path: Path, root: Path, bad) -> None:
    a, b = _group(tmp_path, root, 2)
    with pytest.raises(ft.FolderSyncError) as info:
        ft.FolderSync(root, install_id=bad)
    assert info.value.reason == "bad-install-id"
    for call in (
        lambda: ft.create_folder_group(root, a.session, a.lease, PW, "A", install_id=bad, _kdf_override=CHEAP),
        lambda: ft.join_folder_group(root, a.session, a.lease, PW, "A", install_id=bad, _kdf_override=CHEAP),
        lambda: ft.rotate_folder_group(root, a.session, a.lease, PW2, install_id=bad, _kdf_override=CHEAP),
        lambda: ft.leave_folder_group(a.session, a.lease, install_id=bad),
    ):
        with pytest.raises(ft.FolderSyncError) as info:
            call()
        assert info.value.reason == "bad-install-id"
    assert a.state.epoch == 1


def test_stale_self_is_a_warning_and_publishes(tmp_path: Path, root: Path) -> None:
    a, b = _group(tmp_path, root, 2)
    _web(a, "old")
    a.sync(now=NOW - 400 * DAY)
    _web(a, "new")
    report = a.sync()
    assert kinds(report) == ["stale-self"] and report.wrote
    assert decode_view(a.gk(), a.own_file.read_bytes()).header["written_at"] == NOW
    assert kinds(a.sync()) == []
    b.sync()
    assert b.labels() == ["new", "old"]


def test_all_stale_group_recovers_on_next_run(tmp_path: Path, root: Path) -> None:
    a, b = _group(tmp_path, root, 2)
    _web(a, "from-a")
    _web(b, "from-b")
    a.sync(now=NOW - 400 * DAY)
    b.sync(now=NOW - 400 * DAY)
    assert sorted(kinds(a.sync())) == ["stale-device", "stale-self"]
    assert kinds(b.sync()) == ["stale-self"]  # A's file is fresh again
    assert kinds(a.sync()) == []
    assert a.labels() == b.labels() == ["from-a", "from-b"]


def test_quiet_device_refreshes_its_file_before_going_stale(tmp_path: Path, root: Path) -> None:
    a, b = _group(tmp_path, root, 2)
    a.sync(now=NOW)
    assert not a.sync(now=NOW + 10 * DAY).wrote
    report = a.sync(now=NOW + 40 * DAY)
    assert report.wrote
    assert decode_view(a.gk(), a.own_file.read_bytes()).header["written_at"] == NOW + 40 * DAY


def test_replace_retries_on_permission_error(tmp_path: Path, monkeypatch) -> None:
    target = tmp_path / "f.bin"
    real = ft.os.replace
    failures = [PermissionError("locked by sync client"), PermissionError("still locked")]

    def flaky(src, dst):
        if failures:
            raise failures.pop(0)
        return real(src, dst)

    monkeypatch.setattr(ft.os, "replace", flaky)
    monkeypatch.setattr(ft, "_REPLACE_BACKOFF", (0.0, 0.0, 0.0))
    ft._atomic_write(target, b"data")
    assert target.read_bytes() == b"data" and not failures
    failures.extend([PermissionError("x")] * 5)
    with pytest.raises(PermissionError):
        ft._atomic_write(target, b"other")
    assert target.read_bytes() == b"data"
    assert [p.name for p in tmp_path.iterdir()] == ["f.bin"]


# --- fix round 3 -----------------------------------------------------------------------------

PW3 = "third long sync phrase 99#"


def test_competing_rotations_stop_with_rotation_conflict(tmp_path: Path, root: Path) -> None:
    devs = _group(tmp_path, root)
    a, b, c = devs
    path = _ring_path(root)
    epoch1 = path.read_bytes()
    ft.rotate_folder_group(root, a.session, a.lease, PW2, install_id=a.install, now=NOW, _kdf_override=CHEAP)
    ring_a = path.read_bytes()
    path.write_bytes(epoch1)  # B works from a stale copy of epoch 1 and rotates too
    ft.rotate_folder_group(root, b.session, b.lease, PW3, install_id=b.install, now=NOW, _kdf_override=CHEAP)
    ring_b = path.read_bytes()
    assert kr.parse_keyring(ring_a)["epoch"] == kr.parse_keyring(ring_b)["epoch"] == 2

    files = {d.name: d.own_file.read_bytes() for d in (a, b)}
    report = a.sync()
    assert kinds(report) == ["rotation-conflict"] and not report.wrote
    assert path.read_bytes() == ring_b
    path.write_bytes(ring_a)
    report = b.sync()
    assert kinds(report) == ["rotation-conflict"] and not report.wrote
    assert path.read_bytes() == ring_a
    for _ in range(2):
        a.sync()
        b.sync()
    assert path.read_bytes() == ring_a  # nobody rewrites the keyring
    assert {d.name: d.own_file.read_bytes() for d in (a, b)} == files

    # Resolve: A's rotation is in the folder; B re-joins with the newest password.
    ft.join_folder_group(root, b.session, b.lease, PW2, "PC B", install_id=b.install, now=NOW,
                         _kdf_override=CHEAP)
    assert b.state.epoch == 2
    _web(b, "after")
    b.sync()
    c.sync()  # C (epoch 1) adopts A's rotation
    assert c.state.epoch == 2 and c.labels() == ["after"]
    report = a.sync()  # B re-joined under a new device id: reported until confirmed
    assert kinds(report) == ["member-added"] and report.issues[0].detail == b.device_id
    assert a.labels() == ["after"]


def test_bad_mac_with_genuine_wrap_is_still_restored(tmp_path: Path, root: Path) -> None:
    a, b = _group(tmp_path, root, 2)
    path = _ring_path(root)
    ring = kr.parse_keyring(path.read_bytes())
    ring["mac"] = base64.b64encode(bytes(32)).decode("ascii")  # our wrap still opens; the MAC fails
    path.write_bytes(kr.canonical_json(ring))
    report = a.sync()
    assert kinds(report)[0] == "keyring-restored"


def test_old_keyring_temp_files_are_swept(tmp_path: Path, root: Path) -> None:
    a, b = _group(tmp_path, root, 2)
    sync_dir = root / ft.SYNC_DIR_NAME
    old = sync_dir / ".keyring.lgkkeys.aaaa.tmp"
    fresh = sync_dir / ".keyring.lgkkeys.bbbb.tmp"
    old.write_bytes(b"x")
    fresh.write_bytes(b"x")
    os.utime(old, (time.time() - 7200, time.time() - 7200))
    a.sync()
    assert not old.exists() and fresh.exists()


# --- fix round 4 -----------------------------------------------------------------------------


def test_device_removed_in_overlapping_rotation_does_not_restore_itself(tmp_path: Path, root: Path) -> None:
    a, b, c = _group(tmp_path, root)
    path = _ring_path(root)
    epoch1 = path.read_bytes()
    ft.rotate_folder_group(root, a.session, a.lease, PW2, install_id=a.install, now=NOW, _kdf_override=CHEAP)
    c.sync()
    assert c.state.epoch == 2  # C adopts A's keyring (C still a member)
    path.write_bytes(epoch1)  # B works from a stale copy of epoch 1 and removes C
    ft.rotate_folder_group(root, b.session, b.lease, PW3, remove=[c.device_id], install_id=b.install, now=NOW,
                           _kdf_override=CHEAP)
    ring_b = path.read_bytes()
    assert c.device_id not in {m["device_id"] for m in kr.parse_keyring(ring_b)["members"]}

    c_file = c.own_file.read_bytes() if c.own_file.exists() else None
    report = c.sync()
    assert kinds(report) == ["removed-or-conflict"] and not report.wrote
    assert report.issues[0].detail == "This device may have been removed from sync. Re-join if that isn't expected."
    assert path.read_bytes() == ring_b  # nothing restored
    assert (c.own_file.read_bytes() if c.own_file.exists() else None) == c_file
    report = a.sync()
    assert kinds(report) == ["rotation-conflict"] and not report.wrote
    assert path.read_bytes() == ring_b


# --- fix round 5 -----------------------------------------------------------------------------


def test_winner_rotating_again_after_conflict_does_not_ping_pong(tmp_path: Path, root: Path) -> None:
    a, b, c = _group(tmp_path, root)
    path = _ring_path(root)
    epoch1 = path.read_bytes()
    ft.rotate_folder_group(root, a.session, a.lease, PW2, install_id=a.install, now=NOW, _kdf_override=CHEAP)
    path.write_bytes(epoch1)  # B rotates from a stale epoch-1 copy
    ft.rotate_folder_group(root, b.session, b.lease, PW3, install_id=b.install, now=NOW, _kdf_override=CHEAP)
    assert kinds(a.sync()) == ["rotation-conflict"]
    ft.rotate_folder_group(root, b.session, b.lease, PW2, install_id=b.install, now=NOW, _kdf_override=CHEAP)
    ring_b3 = path.read_bytes()
    assert kr.parse_keyring(ring_b3)["epoch"] == 3 and a.state.epoch == 2

    a_file = a.own_file.read_bytes()
    for _ in range(3):
        report = a.sync()
        assert kinds(report) == ["rotation-conflict"] and not report.wrote
        assert path.read_bytes() == ring_b3  # never restored over the newer epoch
        assert "keyring-restored" not in kinds(b.sync())
        assert path.read_bytes() == ring_b3
    assert a.own_file.read_bytes() == a_file and a.state.epoch == 2


def test_next_epoch_key_mismatch_stops_without_restore(tmp_path: Path, root: Path) -> None:
    a, b, c = _group(tmp_path, root)
    ft.rotate_folder_group(root, a.session, a.lease, PW2, install_id=a.install, now=NOW, _kdf_override=CHEAP)
    path = _ring_path(root)
    ring = kr.parse_keyring(path.read_bytes())
    pubs = {m["device_id"]: m["exchange_public"] for m in ring["members"]}
    for m in ring["members"]:
        if m["device_id"] == b.device_id:
            m["exchange_public"] = pubs[c.device_id]  # B is listed, but with another device's key
    forged = kr.canonical_json(ring)
    path.write_bytes(forged)
    b_file = b.own_file.read_bytes()
    for _ in range(2):
        report = b.sync()
        assert kinds(report) == ["rotation-conflict"] and not report.wrote
        assert path.read_bytes() == forged
    assert b.own_file.read_bytes() == b_file and b.state.epoch == 1


# --- I4: one record a peer's newer build wrote does not block that peer's other records ----------------


def test_one_unreadable_record_is_quarantined_and_the_peer_s_other_records_merge(tmp_path: Path, root: Path,
                                                                                 monkeypatch) -> None:
    from localvault.sync import vault_bridge as vb

    a, b = _group(tmp_path, root, 2)
    known = _web(b, "known-to-both")
    _round([b, a])
    before_on_a = dict(a.entry(known))
    good = [_web(b, f"b-good-{i}") for i in range(4)]
    new_bad = _web(b, "b-new-with-passkey")

    # B is a newer build that knows one more credential field and uses it on two records.
    newer_fields = vb.ENTRY_FIELDS | {"passkey"}
    monkeypatch.setattr(vb, "ENTRY_FIELDS", newer_fields)
    with b.session.transaction():
        for entry_id in (known, new_bad):
            next(e for e in b.session._payload["entries"] if e["id"] == entry_id)["passkey"] = {"rp": "x"}
            next(e for e in b.session._payload["entries"] if e["id"] == entry_id)["updated_at"] += 1
    assert kinds(b.sync()) == []
    monkeypatch.setattr(vb, "ENTRY_FIELDS", newer_fields - {"passkey"})  # A runs the older build

    report = a.sync()
    bad_issues = [i for i in report.issues if i.kind == "bad-peer-record"]
    assert sorted(i.detail for i in bad_issues) == sorted(f"{b.device_id}:{x}" for x in (known, new_bad))
    assert len(bad_issues) == len(set((i.kind, i.detail) for i in bad_issues))  # each reported once
    assert "bad-peer-data" not in kinds(report)
    assert all(a.entry(g)["label"].startswith("b-good-") for g in good)  # B's 4 valid items arrived
    assert new_bad not in {e["id"] for e in a.session._payload["entries"]}
    assert a.entry(known) == before_on_a  # A's copy of the quarantined id is untouched
    assert kinds(a.sync()).count("bad-peer-record") == 2  # still quarantined, still not applied
    assert a.entry(known) == before_on_a

    # Nothing A publishes deletes or overwrites the records on B (the newer build).
    monkeypatch.setattr(vb, "ENTRY_FIELDS", newer_fields)
    assert kinds(b.sync()) == []
    assert b.entry(known)["passkey"] == {"rp": "x"} and b.entry(new_bad)["passkey"] == {"rp": "x"}


def test_undecryptable_name_is_reported_not_fatal(tmp_path: Path, root: Path) -> None:
    from localvault.app import sync_view as ui

    a, b, c = _group(tmp_path, root)
    path = _ring_path(root)
    ring = kr.parse_keyring(path.read_bytes())
    assert kr.member_names(ring, a.gk()) == {a.device_id: "PC A", b.device_id: "PC B", c.device_id: "PC C"}
    # Someone holding G writes a name sealed for another device: the MAC is valid, the name is not.
    idx = next(i for i, m in enumerate(ring["members"]) if m["device_id"] == c.device_id)
    other = next(m for m in ring["members"] if m["device_id"] == b.device_id)
    ring["members"][idx]["name_ct"] = other["name_ct"]
    path.write_bytes(kr.canonical_json(kr._finish(ring, a.gk(), None, ring["prev_mac"])))
    label = _web(a, "after-bad-name")
    report = a.sync()
    assert ("bad-name", c.device_id) in [(i.kind, i.detail) for i in report.issues]
    assert report.wrote and a.state.keyring == path.read_bytes()
    b.sync()
    assert label in [e["id"] for e in b.session._payload["entries"]]

    class _Gate:
        import contextlib

        @staticmethod
        @contextlib.contextmanager
        def ui_released():
            yield

    snap, corrupt = ui.snapshot_job(a.install)(a.session, a.lease, _Gate())
    assert not corrupt
    names = {m.device_id: m.name for m in snap.members}
    assert names == {a.device_id: "PC A", b.device_id: "PC B", c.device_id: "Unnamed device"}
    assert ui.issue_severity("bad-name") == "warning"


# --- adding a cloud folder to a Wi-Fi-only group ------------------------------------------------


def _wifi_pair(tmp_path: Path, root: Path) -> tuple[Dev, Dev]:
    """A Wi-Fi-only group of A and B (B's state as QR enrollment stores it, without the network)."""
    from localvault.sync import lan_sync as lan

    a, b = _device(tmp_path, "a", root), _device(tmp_path, "b", root)
    st = lan.create_lan_group(a.session, a.lease, install_id=a.install)
    identity = DeviceIdentity.generate().protected_dict()
    save_sync_state(b.session, SyncGroupState(st.group_id, st.epoch, st.key, identity, install_id=b.install))
    return a, b


def _add(dev: Dev, root: Path, pw: str = PW, **kw) -> runner.RunReport:
    return ft.add_folder_to_group(root, dev.session, dev.lease, pw, f"PC {dev.name.upper()}", install_id=dev.install,
                                  now=NOW, _kdf_override=CHEAP, **kw)


def _attach(dev: Dev, root: Path, pw: str = PW, **kw) -> runner.RunReport:
    return ft.attach_folder(root, dev.session, dev.lease, pw, f"PC {dev.name.upper()}", install_id=dev.install,
                            now=NOW, _kdf_override=CHEAP, **kw)


def _reason(fn, *args, **kw) -> str:
    with pytest.raises(ft.FolderSyncError) as info:
        fn(*args, **kw)
    return info.value.reason


def test_add_folder_then_attach_syncs_through_the_folder(tmp_path: Path, root: Path) -> None:
    a, b = _wifi_pair(tmp_path, root)
    ids, gk = (a.device_id, b.device_id), a.gk()
    _add(a, root)
    ring = kr.parse_keyring(_ring_path(root).read_bytes())
    assert ring["group_id"] == gk.group_id and ring["epoch"] == gk.epoch and ring["prev_mac"] is None
    assert a.state.folder_path == str(root) and a.state.members == (a.device_id,)
    assert a.state.keyring == _ring_path(root).read_bytes() and a.own_file.is_file()
    _attach(b, root)
    assert (a.device_id, b.device_id) == ids and a.gk() == gk and b.gk() == gk
    assert b.state.folder_path == str(root) and b.state.members == tuple(sorted(ids))
    entry = _web(a, "alpha")
    a.sync()
    b.sync()
    assert b.entry(entry)["label"] == "alpha"
    report = a.sync()  # B added itself to A's keyring: A reports it until the user confirms
    assert kinds(report) == ["member-added"] and report.issues[0].detail == b.device_id
    assert ft.acknowledge_members(a.session, a.lease, [b.device_id], install_id=a.install) == 1
    assert kinds(a.sync()) == [] and kinds(b.sync()) == []


def test_add_folder_on_folder_with_same_group_switches_to_attach(tmp_path: Path, root: Path) -> None:
    a, b = _wifi_pair(tmp_path, root)
    b_id = b.device_id
    _add(a, root)
    _add(b, root)  # the folder already holds this group: attach with the given password
    ring = kr.parse_keyring(_ring_path(root).read_bytes())
    assert {m["device_id"] for m in ring["members"]} == {a.device_id, b_id} and b.device_id == b_id
    assert b.state.folder_path == str(root)
    c = _device(tmp_path, "c", root)
    save_sync_state(c.session, dataclasses.replace(load_sync_state(b.session), folder_path=None, keyring=None,
                                                   members=(), members_epoch=None, install_id=c.install,
                                                   device_identity=DeviceIdentity.generate().protected_dict()))
    assert _reason(_add, c, root, PW2) == "password"  # attach needs the folder's password


def test_add_folder_refuses_other_group(tmp_path: Path, root: Path) -> None:
    a, b = _wifi_pair(tmp_path, root)
    c = _device(tmp_path, "c", root)
    ft.create_folder_group(root, c.session, c.lease, PW, "PC C", install_id=c.install, now=NOW, _kdf_override=CHEAP)
    before = _ring_path(root).read_bytes()
    state = a.state
    assert _reason(_add, a, root) == "folder-has-other-group"
    assert _reason(_attach, a, root) == "folder-has-other-group"
    assert _ring_path(root).read_bytes() == before and a.state == state


def test_attach_refuses_different_group_key(tmp_path: Path, root: Path) -> None:
    a, b = _wifi_pair(tmp_path, root)
    gk = a.gk()
    # someone builds a keyring for the same group id with another key
    forged = kr.create_for_existing_group(GroupKey(gk.group_id, gk.epoch, os.urandom(32)), PW,
                                          DeviceIdentity.generate(), "X", _kdf_override=CHEAP)
    fs = ft.FolderSync(root, install_id=a.install, _kdf_override=CHEAP)
    fs.devices_dir.mkdir(parents=True)
    written = fs.write_keyring(forged, expected=None)
    state = b.state
    assert _reason(_attach, b, root) == "different-group-key"
    assert _reason(_add, b, root) == "different-group-key"
    assert _ring_path(root).read_bytes() == written and b.state == state


def test_add_and_attach_refusals(tmp_path: Path, root: Path) -> None:
    lone = _device(tmp_path, "z", root)
    assert _reason(_add, lone, root) == "not-joined"
    assert _reason(_attach, lone, root) == "not-joined"
    a, b = _wifi_pair(tmp_path, root)
    assert _reason(_attach, b, root) == "no-group"
    assert _reason(_add, a, root / "missing") == "folder-missing"
    for fn in (ft.add_folder_to_group, ft.attach_folder):
        assert _reason(fn, root, a.session, a.lease, PW, "PC A", install_id="install-other",
                       _kdf_override=CHEAP) == "rejoin-required"
    _add(a, root)
    assert _reason(_add, a, root) == "already-has-folder"
    assert _reason(_attach, a, root) == "already-has-folder"


def test_add_folder_needs_a_strong_password(tmp_path: Path, root: Path) -> None:
    a, _b = _wifi_pair(tmp_path, root)
    state = a.state
    assert _reason(_add, a, root, "short") == "weak-password"
    assert not _ring_path(root).exists() and a.state == state


@pytest.mark.parametrize("op", ["add", "attach"])
def test_add_or_attach_aborts_when_keyring_changed(tmp_path: Path, root: Path, monkeypatch, op) -> None:
    a, b = _wifi_pair(tmp_path, root)
    path = _ring_path(root)
    if op == "attach":
        _add(a, root)
        name = "attach_with_password"
    else:
        name = "create_for_existing_group"
    real = getattr(ft, name)
    meddled = b"{}"

    def meddle(*args, **kwargs):
        out = real(*args, **kwargs)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(meddled)  # another device wrote the keyring meanwhile
        return out

    monkeypatch.setattr(ft, name, meddle)
    dev = b if op == "attach" else a
    state = dev.state
    assert _reason(_add if op == "add" else _attach, dev, root) == "keyring-changed"
    assert path.read_bytes() == meddled and dev.state == state


class _SaveFails(Exception):
    pass


@pytest.mark.parametrize("failure", ["save", "lease"])
def test_attach_that_cannot_save_puts_the_keyring_back_and_retries(tmp_path: Path, root: Path, monkeypatch,
                                                                    failure) -> None:
    a, b = _wifi_pair(tmp_path, root)
    _add(a, root)
    before = _ring_path(root).read_bytes()
    state = b.state
    if failure == "save":
        def fail(*_a, **_k):
            raise _SaveFails("disk full")

        monkeypatch.setattr(ft, "save_sync_state", fail)
        with pytest.raises(_SaveFails):
            _attach(b, root)
    else:
        real = ft.attach_with_password

        def lock_meanwhile(*args, **kwargs):
            out = real(*args, **kwargs)
            b.lease.valid = False  # the vault locked during the slow password check
            return out

        monkeypatch.setattr(ft, "attach_with_password", lock_meanwhile)
        with pytest.raises(StaleSession):
            _attach(b, root)
        b.lease.valid = True
    assert _ring_path(root).read_bytes() == before and b.state == state
    monkeypatch.undo()
    b_id = b.device_id
    _attach(b, root)
    assert b.device_id == b_id and b.state.folder_path == str(root)


def test_attach_retry_after_a_failed_rollback_succeeds_without_rewrite(tmp_path: Path, root: Path,
                                                                       monkeypatch) -> None:
    a, b = _wifi_pair(tmp_path, root)
    _add(a, root)

    def fail(*_a, **_k):
        raise _SaveFails("disk full")

    monkeypatch.setattr(ft, "save_sync_state", fail)
    monkeypatch.setattr(ft, "_undo_keyring_write", lambda *_a: None)  # the folder could not be written back
    with pytest.raises(_SaveFails):
        _attach(b, root)
    monkeypatch.undo()
    stuck = _ring_path(root).read_bytes()
    assert b.device_id in {m["device_id"] for m in kr.parse_keyring(stuck)["members"]}
    assert b.state.folder_path is None
    _attach(b, root, run=False)  # not already-member: same device, same key
    assert _ring_path(root).read_bytes() == stuck and b.state.keyring == stuck
    assert b.state.folder_path == str(root) and b.state.members == tuple(sorted((a.device_id, b.device_id)))
    assert kinds(b.sync()) == []


def test_add_that_cannot_save_removes_its_keyring_and_retries(tmp_path: Path, root: Path, monkeypatch) -> None:
    a, _b = _wifi_pair(tmp_path, root)
    state = a.state

    def fail(*_a, **_k):
        raise _SaveFails("disk full")

    monkeypatch.setattr(ft, "save_sync_state", fail)
    with pytest.raises(_SaveFails):
        _add(a, root)
    assert not _ring_path(root).exists() and a.state == state
    monkeypatch.undo()
    _add(a, root)
    assert a.state.folder_path == str(root)


def test_add_cleanup_leaves_a_keyring_another_device_wrote(tmp_path: Path, root: Path, monkeypatch) -> None:
    a, _b = _wifi_pair(tmp_path, root)
    other = b"another device wrote this"

    def fail(*_a, **_k):
        _ring_path(root).write_bytes(other)
        raise _SaveFails("disk full")

    monkeypatch.setattr(ft, "save_sync_state", fail)
    with pytest.raises(_SaveFails):
        _add(a, root)
    assert _ring_path(root).read_bytes() == other


def test_add_retry_after_a_failed_cleanup_attaches_itself(tmp_path: Path, root: Path, monkeypatch) -> None:
    a, _b = _wifi_pair(tmp_path, root)

    def fail(*_a, **_k):
        raise _SaveFails("disk full")

    monkeypatch.setattr(ft, "save_sync_state", fail)
    monkeypatch.setattr(ft, "_undo_keyring_write", lambda *_a: None)
    with pytest.raises(_SaveFails):
        _add(a, root)
    monkeypatch.undo()
    stuck = _ring_path(root).read_bytes()
    _add(a, root)  # the folder holds this group with this device: attach succeeds unchanged
    assert _ring_path(root).read_bytes() == stuck and a.state.folder_path == str(root)
