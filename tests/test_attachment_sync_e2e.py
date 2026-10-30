"""Documents and their files between two Python devices, over the sync folder and over Wi-Fi."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from localvault.attachments import AttachmentStore
from localvault.item_schema import new_item
from localvault.item_service import ItemService
from localvault.sync import attachment_sync as asy
from localvault.sync import folder_transport as ft
from localvault.sync import lan_sync as lan
from localvault.sync.group import decode_view

import test_sync_folder_transport as folder_tests
import test_sync_lan as lan_tests
from test_sync_folder_transport import kinds
from test_sync_lan import _group_ab
from test_sync_lan import kinds as lan_kinds
from localvault.vault import create_vault

DATA = b"synthetic passport scan\n" * 400


@pytest.fixture
def root(tmp_path: Path) -> Path:
    path = tmp_path / "OneDrive"
    path.mkdir()
    return path


@pytest.fixture(autouse=True)
def _own_folders(tmp_path: Path, monkeypatch) -> None:
    """Each vault in its own folder: attachments live next to the vault file."""
    def device(tmp: Path, name: str, root: Path):
        (tmp / name).mkdir()
        session = create_vault(tmp / name / f"{name}.json", folder_tests.MASTER, kdf_overrides=folder_tests.TEST_KDF)
        return folder_tests.Dev(name, session, folder_tests.FakeLease(), f"install-{name}", root)

    monkeypatch.setattr(folder_tests, "_device", device)


def _group(tmp_path: Path, root: Path, n: int = 2):
    return folder_tests._group(tmp_path, root, n=n)


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


def _add_document(dev, data: bytes = DATA, title: str = "Passport") -> str:
    store = AttachmentStore(dev.session)
    attachment_id = store.add_bytes("passport.pdf", data, mime_type="application/pdf")
    return ItemService(dev.session)._append(new_item("document", title, {"attachment_id": attachment_id,
                                                                         "description": ""}))


def _documents(dev) -> dict[str, dict]:
    return {i["id"]: i for i in dev.session._payload.get("items", []) if i.get("kind") == "document"}


def _trash_ids(dev) -> set[str]:
    return {r["entry"]["id"] for r in dev.session._payload.get("trash", [])}


def _file(dev, item_id: str) -> bytes:
    item = _documents(dev)[item_id]
    return AttachmentStore(dev.session).read_bytes(item["payload"]["attachment_id"])


def _blob_dir(root: Path) -> Path:
    return root / ft.SYNC_DIR_NAME / asy.BLOBS_DIR_NAME


def _view_has_documents(dev, viewer) -> bool:
    raw = dev.own_file.read_bytes()
    view = decode_view(viewer.gk(), raw, expected_device_id=dev.device_id)
    return any(isinstance(s.item, dict) and s.item.get("record", {}).get("kind") == "document" for s in view.states)


# --- folder -----------------------------------------------------------------------------------


def test_folder_document_appears_unchanged_file_not_resent_and_delete_propagates(tmp_path, root) -> None:
    a, b = _group(tmp_path, root, n=2)
    for d in (a, b):  # both write their capability file
        d.sync()
    item_id = _add_document(a)
    for _ in range(2):
        for d in (a, b):
            assert "attachment-refused" not in kinds(d.sync())
    assert item_id in _documents(b) and _file(b, item_id) == DATA
    blobs = sorted(p.name for p in _blob_dir(root).glob("*.lgkblob"))
    assert len(blobs) == 1
    assert b"passport" not in (_blob_dir(root) / blobs[0]).read_bytes()
    mtime = (_blob_dir(root) / blobs[0]).stat().st_mtime_ns
    for d in (a, b):
        d.sync()
    assert (_blob_dir(root) / blobs[0]).stat().st_mtime_ns == mtime  # never rewritten
    ItemService(b.session).delete_item(item_id)
    for _ in range(2):
        for d in (a, b):
            d.sync()
    assert item_id not in _documents(a) and item_id in _trash_ids(a)


def test_folder_tampered_blob_is_refused_and_nothing_applied(tmp_path, root) -> None:
    a, b = _group(tmp_path, root, n=2)
    for d in (a, b):
        d.sync()
    item_id = _add_document(a)
    a.sync()
    (path,) = _blob_dir(root).glob("*.lgkblob")
    raw = bytearray(path.read_bytes())
    raw[-1] ^= 1
    path.write_bytes(bytes(raw))
    report = b.sync()
    assert "attachment-missing" in kinds(report)  # the damaged file does not match its name: not used
    assert item_id not in _documents(b)
    assert AttachmentStore(b.session)._payload().get("attachments", []) == []


def test_folder_older_member_gets_no_documents(tmp_path, root, monkeypatch) -> None:
    a, b = _group(tmp_path, root, n=2)
    real = ft.write_capability
    older = b.device_id
    monkeypatch.setattr(ft, "write_capability",
                        lambda sync_dir, gk, device_id, *args, **kw:
                        False if device_id == older else real(sync_dir, gk, device_id, *args, **kw))
    for path in _blob_dir(root).glob(f"{older}.lgkcap*"):  # written while _group set up the folder
        path.unlink()
    item_id = _add_document(a)
    for _ in range(2):
        for d in (a, b):
            d.sync()
    assert not _view_has_documents(a, b) and item_id not in _documents(b)
    assert not list(_blob_dir(root).glob("*.lgkblob"))
    monkeypatch.setattr(ft, "write_capability", real)  # B updated
    for _ in range(2):
        for d in (b, a):
            d.sync()
    assert _view_has_documents(a, b) and _file(b, item_id) == DATA


def test_forged_capability_file_does_not_count(tmp_path, root, monkeypatch) -> None:
    a, b = _group(tmp_path, root, n=2)
    real = ft.write_capability
    monkeypatch.setattr(ft, "write_capability",
                        lambda sync_dir, gk, device_id, *args, **kw:
                        False if device_id == b.device_id else real(sync_dir, gk, device_id, *args, **kw))
    a.sync()
    folder = _blob_dir(root)
    # A capability for B signed by A's key: B's trusted key does not match, so B counts as older.
    (folder / f"{b.device_id}.lgkcap").write_bytes((folder / f"{a.device_id}.lgkcap").read_bytes())
    (folder / f"{b.device_id}.lgkcap.lgksig").write_bytes((folder / f"{a.device_id}.lgkcap.lgksig").read_bytes())
    b.sync()
    _add_document(a)
    a.sync()
    assert not _view_has_documents(a, b)


# --- Wi-Fi ------------------------------------------------------------------------------------


def test_lan_document_appears_delete_propagates_and_old_peer_gating(devs) -> None:
    a, b = _group_ab(devs)
    item_id = _add_document(a)
    assert lan_kinds(b.sync_with(a)) == []  # first exchange: support learned, no documents yet
    assert b.device_id in a.state.attachment_peers and a.device_id in b.state.attachment_peers
    assert item_id not in _documents(b)
    report = b.sync_with(a)  # B fetches the file from A, then applies the document
    assert lan_kinds(report) == [] and _file(b, item_id) == DATA
    ItemService(a.session).delete_item(item_id)
    a.sync_with(b)
    assert item_id in _trash_ids(b)


def test_lan_responder_waits_for_file_then_initiator_run_fetches(devs) -> None:
    a, b = _group_ab(devs)
    b.sync_with(a)  # learn support both ways
    item_id = _add_document(a)
    report = a.sync_with(b)  # B is the responder: it cannot fetch, so the document waits
    assert item_id not in _documents(b)
    b.sync_with(a)
    assert _file(b, item_id) == DATA


class _OlderResponder:
    def __init__(self, dev) -> None:
        self.inner, self.types = dev.responder, []
        dev.transport.set_peer_request_handler(self)

    def __call__(self, peer, request: bytes) -> bytes:
        msg = json.loads(request)
        self.types.append(msg.get("type"))
        if msg.get("type") in ("blob-get", "witness"):
            return lan.encode_message({"type": "error", "reason": "bad-message"})
        return self.inner(peer, request)


def test_lan_older_peer_never_gets_documents(devs) -> None:
    a, b = _group_ab(devs)
    _OlderResponder(a)
    _add_document(b)
    for _ in range(3):
        b.sync_with(a)
    assert a.device_id not in b.state.attachment_peers
    assert _documents(a) == {}


def test_lan_tampered_chunk_is_refused(devs, monkeypatch) -> None:
    a, b = _group_ab(devs)
    b.sync_with(a)
    item_id = _add_document(a)
    real = asy.blob_chunk

    def damaged(blob: bytes, seq: int) -> dict:
        out = bytearray(blob)
        out[-1] ^= 1
        return real(bytes(out), seq)

    monkeypatch.setattr(asy, "blob_chunk", damaged)
    report = b.sync_with(a)
    assert item_id not in _documents(b)
    assert "attachment-missing" in lan_kinds(report)


def test_only_a_chunk_or_no_blob_shows_support_and_other_errors_say_nothing() -> None:
    from localvault.sync.lan_sync import _note_support
    answered: list[bool] = []
    for reply in ({"type": "error", "reason": "revoked"}, {"type": "error", "reason": "unknown-peer"},
                  {"type": "error", "reason": "busy"}):
        _note_support(answered, reply)
    assert answered == []
    _note_support(answered, {"type": "error", "reason": "no-blob"})
    _note_support(answered, {"type": "blob"})
    _note_support(answered, {"type": "error", "reason": "bad-message"})
    assert answered == [True, True, False]


def test_lan_responder_builds_its_document_list_once_per_store_revision(devs, monkeypatch) -> None:
    a, b = _group_ab(devs)
    b.sync_with(a)  # learn support both ways
    first = _add_document(a, b"one" * 100, "One")
    second = _add_document(a, b"two" * 100, "Two")
    builds = []
    real = lan.document_refs

    def counting(states):
        builds.append(1)
        return real(states)

    monkeypatch.setattr(lan, "document_refs", counting)
    b.sync_with(a)  # B fetches both files: two blob-get seq 0 on an unchanged store, one build
    assert _file(b, first) == b"one" * 100 and _file(b, second) == b"two" * 100
    assert len(builds) == 1
    third = _add_document(a, b"three" * 100, "Three")  # a save: the next request rebuilds
    b.sync_with(a)
    assert _file(b, third) == b"three" * 100
    assert len(builds) == 2
