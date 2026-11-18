# ruff: noqa: F811 - pytest fixtures imported from test_attachment_sync_e2e are used as parameters
"""Personal collections between two Python devices over the sync folder and over Wi-Fi (sub-plan 07 Task 4).

Collection states go only to peers that read them: a folder member that wrote its signed ``.lgkcol``
file, a Wi-Fi peer that answered ``features``.  An older peer keeps getting v1 views.
"""
from __future__ import annotations

import json
from pathlib import Path

import test_sync_folder_transport as folder_tests
from test_attachment_sync_e2e import _own_folders, devs, root  # noqa: F401 - fixtures
from test_sync_folder_transport import kinds
from test_sync_lan import _group_ab
from test_sync_lan import kinds as lan_kinds

from localvault.collections import CollectionService
from localvault.item_service import ItemService
from localvault.sync import attachment_sync as asy
from localvault.sync import folder_transport as ft
from localvault.sync import lan_sync as lan
from localvault.sync.group import decode_view
from localvault.sync.vault_bridge import is_collection_state_id


def _collections(dev) -> dict[str, str]:
    return {r["id"]: r["name"] for r in CollectionService(dev.session).list()}


def _membership(dev, item_id: str) -> list[str]:
    item = next(i for i in dev.session._payload.get("items", []) if i["id"] == item_id)
    return sorted(item.get("collection_ids", []))


def _tagged_note(dev, name: str = "Family") -> tuple[str, str]:
    cid = CollectionService(dev.session).create(name)
    return cid, ItemService(dev.session).create_note("Wi-Fi", "hunter2", collection_ids=[cid])


def _view_has_collections(dev, viewer) -> bool:
    view = decode_view(viewer.gk(), dev.own_file.read_bytes(), expected_device_id=dev.device_id)
    return any(is_collection_state_id(s.item_id) for s in view.states)


def _cap_files(root: Path, dev) -> list[Path]:
    return list((root / ft.SYNC_DIR_NAME / asy.BLOBS_DIR_NAME).glob(f"{dev.device_id}.lgkcol*"))


# --- folder -----------------------------------------------------------------------------------


def test_folder_collections_sync_between_new_members(tmp_path, root) -> None:
    a, b = folder_tests._group(tmp_path, root, n=2)
    for d in (a, b):  # both write their capability files
        d.sync()
    assert len(_cap_files(root, a)) == 2 and len(_cap_files(root, b)) == 2
    cid, nid = _tagged_note(a)
    for _ in range(2):
        for d in (a, b):
            assert kinds(d.sync()) == []
    assert _collections(b) == {cid: "Family"} and _membership(b, nid) == [cid]
    assert _view_has_collections(a, b)
    work = CollectionService(b.session).create("Work")
    ItemService(b.session).update_item(nid, collection_ids=[work])
    for _ in range(2):
        for d in (b, a):
            d.sync()
    assert _membership(a, nid) == [work]


def test_folder_older_member_gets_v1_views_until_it_updates(tmp_path, root, monkeypatch) -> None:
    a, b = folder_tests._group(tmp_path, root, n=2)
    real = ft.write_collections_capability
    older = b.device_id
    monkeypatch.setattr(ft, "write_collections_capability",
                        lambda sync_dir, gk, device_id, *args, **kw:
                        False if device_id == older else real(sync_dir, gk, device_id, *args, **kw))
    for path in _cap_files(root, b):  # written while _group set up the folder
        path.unlink()
    cid, nid = _tagged_note(a)
    for _ in range(2):
        for d in (a, b):
            assert kinds(d.sync()) == []
    assert not _view_has_collections(a, b), "an older member never reads a collection state"
    assert _membership(b, nid) == [] and _collections(b) == {}
    ItemService(b.session).update_item(nid, title="Wi-Fi (new)")  # the older member edits it
    for _ in range(2):
        for d in (b, a):
            d.sync()
    assert _membership(a, nid) == [cid], "the newer member keeps its collections"
    monkeypatch.setattr(ft, "write_collections_capability", real)  # B updated
    for _ in range(2):
        for d in (b, a):
            d.sync()
    assert _view_has_collections(a, b)
    assert _collections(b) == {cid: "Family"} and _membership(b, nid) == [cid]


def test_folder_document_capability_does_not_count_for_collections(tmp_path, root) -> None:
    a, b = folder_tests._group(tmp_path, root, n=2)
    for d in (a, b):
        d.sync()
    blobs = root / ft.SYNC_DIR_NAME / asy.BLOBS_DIR_NAME
    for suffix in (".lgkcol", ".lgkcol.lgksig"):
        (blobs / f"{b.device_id}{suffix}").unlink()
    # Someone with folder access copies B's document capability under the collections name.
    (blobs / f"{b.device_id}.lgkcol").write_bytes((blobs / f"{b.device_id}.lgkcap").read_bytes())
    (blobs / f"{b.device_id}.lgkcol.lgksig").write_bytes((blobs / f"{b.device_id}.lgkcap.lgksig").read_bytes())
    signer = a.state.view_signers.get(b.device_id)
    assert ft.folder_capable(blobs.parent, a.gk(), b.device_id, signer), "the copied files verify as such"
    assert not ft.collections_capable(blobs.parent, a.gk(), b.device_id, signer)
    _tagged_note(a)
    a.sync()
    assert not _view_has_collections(a, b), "B counts as older until it writes its own collections file"
    b.sync()  # B (this version) replaces the copy with a real one
    a.sync()
    assert _view_has_collections(a, b)


# --- Wi-Fi ------------------------------------------------------------------------------------


def test_lan_collections_sync_after_features_are_learned(devs) -> None:  # noqa: F811
    a, b = _group_ab(devs)
    cid, nid = _tagged_note(a)
    assert lan_kinds(b.sync_with(a)) == []  # first exchange: features learned both ways
    assert a.device_id in b.state.collection_peers and b.device_id in a.state.collection_peers
    b.sync_with(a)
    assert _collections(b) == {cid: "Family"} and _membership(b, nid) == [cid]
    ItemService(b.session).update_item(nid, collection_ids=[])
    a.sync_with(b)
    assert _membership(a, nid) == []


class _OlderResponder:
    def __init__(self, dev) -> None:
        self.inner, self.types = dev.responder, []
        dev.transport.set_peer_request_handler(self)

    def __call__(self, peer, request: bytes) -> bytes:
        msg = json.loads(request)
        self.types.append(msg.get("type"))
        if msg.get("type") in ("features", "witness", "blob-get"):
            return lan.encode_message({"type": "error", "reason": "bad-message"})
        return self.inner(peer, request)


def test_lan_older_peer_never_gets_collection_states(devs, monkeypatch) -> None:  # noqa: F811
    a, b = _group_ab(devs)
    older = _OlderResponder(a)
    seen: list[bool] = []
    real = lan.local_view

    def spy(*args, **kw):
        seen.append(kw.get("collections", False))
        return real(*args, **kw)

    monkeypatch.setattr(lan, "local_view", spy)
    cid, nid = _tagged_note(b)
    for _ in range(3):
        assert lan_kinds(b.sync_with(a)) == []
    assert "features" in older.types
    assert a.device_id not in b.state.collection_peers
    assert seen and not any(seen), "no view with collection states goes to the older peer"
    assert _collections(a) == {} and _membership(a, nid) == []
