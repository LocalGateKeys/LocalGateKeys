"""The shared-collection vectors (tests/vectors/share/collections) are what the desktop code writes today.

Regenerates them with scripts/make_share_collection_vectors.py into a temporary folder and compares the bytes,
so a change of the share keyring, share view, collection states, .lgkcol file or features message cannot slip
past the phones' copies of these files.

Then the cross-platform folder check (sub-plan 07 Task 5n, ``folder.json``): the desktop's own device B joins
device A's personal folder (``folder/a``) and must end with ``expected_b``; the desktop's device A then reads B's
files back to the same state.  The same A runs over the files the Kotlin core wrote as B
(``folder/from_android``, ``CollectionInteropTest``) and the Swift core (``folder/from_ios``,
``CollectionInteropTests``, written on a Mac with ``LGK_WRITE_FROM_IOS=1``; skipped until it is there).
"""
from __future__ import annotations

import base64
import copy
import importlib.util
import json
import shutil
from pathlib import Path

import pytest

from localvault.collections import CollectionService
from localvault.sync import attachment_flow
from localvault.sync import folder_transport as ft
from localvault.sync import keyring as kr
from localvault.sync import share_group as sg
from localvault.sync.engine import ItemState
from localvault.sync.group import GroupKey, decode_view, verify_view_signature
from localvault.sync.pairing import DeviceIdentity
from localvault.sync.vault_bridge import (
    LINKS_KEY,
    SyncGroupState,
    load_sync_state,
    local_view,
    save_sync_state,
)
from localvault.updates import canonical_json
from localvault.vault import create_vault

ROOT = Path(__file__).resolve().parent.parent
VECTORS = ROOT / "tests/vectors/share/collections"
FOLDER = VECTORS / "folder"
TEST_KDF = {"time_cost": 1, "memory_cost_kib": 8192, "parallelism": 1, "hash_len": 32}
MASTER = "synthetic master"
#: Run issues that are expected here: A learns that B joined (the user confirms new members).
EXPECTED_ISSUES = {"member-added"}


def _generator():
    spec = importlib.util.spec_from_file_location("make_share_collection_vectors",
                                                  ROOT / "scripts/make_share_collection_vectors.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_share_collection_vectors_are_current(tmp_path: Path) -> None:
    written = _generator().generate(tmp_path)
    rel = sorted(p.relative_to(tmp_path).as_posix() for p in written)
    # gating.json has its own generator (make_share_gating_vectors.py) and freshness test (test_share_gating.py).
    committed = sorted([p.name for p in VECTORS.glob("*.json") if p.name != "gating.json"]
                       + [p.relative_to(VECTORS).as_posix() for p in (FOLDER / "a").rglob("*") if p.is_file()])
    assert rel == committed
    for path in written:
        name = path.relative_to(tmp_path).as_posix()
        assert path.read_bytes() == (VECTORS / name).read_bytes(), f"{name} is stale: rerun the script"


# --- the cross-platform folder check (folder.json) ---------------------------------------------------------


class _Lease:
    def check(self) -> None:
        pass


LEASE = _Lease()


def _doc() -> dict:
    return json.loads((VECTORS / "folder.json").read_text(encoding="utf-8"))


def _identity(who: str) -> DeviceIdentity:
    devices = json.loads((ROOT / "tests/vectors/sync/identities.json").read_text(encoding="utf-8"))["devices"]
    return DeviceIdentity.from_protected_dict(devices[who]["private"])


def _b64(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def _gk(doc: dict) -> GroupKey:
    return GroupKey(doc["group_id"], doc["epoch"], bytes.fromhex(doc["group_key_hex"]))


def _states(rows: list[dict]) -> list[ItemState]:
    return [ItemState(r["id"], r["vv"], r["deleted"], r["deleted_at"], r["item"]) for r in rows]


def _folder(tmp_path: Path, *overlays: Path) -> Path:
    """A cloud folder holding A's files plus each overlay (a phone's B files), as a sync client leaves it."""
    root = tmp_path / "OneDrive"
    for src in (FOLDER / "a", *overlays):
        shutil.copytree(src, root / ft.SYNC_DIR_NAME, dirs_exist_ok=True)
    return root


def _catalog(session) -> dict:
    return {r["id"]: {"name": r["name"], "description": r["description"]} for r in CollectionService(session).list()}


def _memberships(session) -> dict:
    return {i["id"]: sorted(i["collection_ids"]) for i in session._payload.get("items", []) if i.get("collection_ids")}


def _device_a(tmp_path: Path, root: Path, doc: dict):
    """The desktop's device A: its vault holds ``a_vault``, it owns the Family share (keyring.json ``create``) and
    it is the personal group's only member with its first view (counter 1) published."""
    session = create_vault(tmp_path / "a.json", MASTER, kdf_overrides=TEST_KDF)
    a = _identity("A")
    share = json.loads((VECTORS / "keyring.json").read_text(encoding="utf-8"))["create"]
    ring = share["keyring"]
    assert ring["group_id"] == doc["a_share_group_id"]
    share_state = SyncGroupState(ring["group_id"], 1, bytes.fromhex(share["group_key_hex"]), a.protected_dict(),
                                 members_epoch=1, members=(a.device_id,), keyring=canonical_json(ring))
    vault = copy.deepcopy(doc["a_vault"])
    for row in vault["collections"]:
        if row["id"] in vault["links"]:
            row["shared_group_id"] = ring["group_id"]
    with session.transaction():
        payload = session._require_typed_catalog()
        payload["collections"] = vault["collections"]
        payload["items"] = vault["items"]
        sg._store(session, ring["group_id"], sg._new_record(ring["metadata"], "owner", share_state))
    assert sg.share_links(session) == doc["a_vault"]["links"]
    save_sync_state(session, SyncGroupState(
        doc["group_id"], doc["epoch"], bytes.fromhex(doc["group_key_hex"]), a.protected_dict(),
        folder_path=str(root), install_id="install-a", own_counter=1, members_epoch=doc["epoch"],
        members=(a.device_id,), keyring=(FOLDER / "a/keyring.lgkkeys").read_bytes(),
        view_signers={a.device_id: _b64(a.signing_public_key)}))
    return session


def _assert_publishes_a_states(root: Path, doc: dict, device_id: str) -> None:
    """*device_id*'s files: a signed view (key from the keyring) that republishes A's states unchanged, and a
    signed .lgkcol (it reads collection states)."""
    sync = root / ft.SYNC_DIR_NAME
    gk = _gk(doc)
    ring = kr.parse_keyring((sync / "keyring.lgkkeys").read_bytes())
    assert kr.accept_keyring(ring, gk, _identity("A")) == gk
    key = kr.member_signing_keys(ring)[device_id]
    raw = (sync / "devices" / f"{device_id}.lgksync").read_bytes()
    view = decode_view(gk, raw, expected_device_id=device_id)
    sig = (sync / "signatures" / f"{device_id}.lgksig").read_bytes()
    assert _b64(verify_view_signature(sig, raw, view.header)) == key
    assert list(view.states) == _states(doc["a_states"])
    assert attachment_flow.collections_capable(sync, gk, device_id, key)


def _assert_a_reads_back(tmp_path: Path, root: Path, doc: dict, b_id: str) -> None:
    session = _device_a(tmp_path, root, doc)
    a_id = doc["device_a"]
    # The generator wrote exactly A's own first view.
    mine = local_view(session, LEASE, device_id=a_id, now=doc["written_at"], collections=True)
    assert [mine[k] for k in sorted(mine)] == _states(doc["a_states"])
    report = ft.FolderSync(root, install_id="install-a").run_once(session, LEASE, now=doc["b_run"]["run_at"] + 60)
    assert {i.kind for i in report.issues} <= EXPECTED_ISSUES, report.issues
    assert [i.detail for i in report.issues] == [b_id]
    b_view = decode_view(_gk(doc), (root / ft.SYNC_DIR_NAME / "devices" / f"{b_id}.lgksync").read_bytes(),
                         expected_device_id=b_id)
    assert load_sync_state(session).last_seen.get(b_id) == b_view.header["counter"], "A accepted B's view"
    assert _catalog(session) == doc["expected_b"]["catalog"]
    assert _memberships(session) == doc["expected_b"]["memberships"]
    assert sg.share_links(session) == doc["a_vault"]["links"]
    sync = root / ft.SYNC_DIR_NAME
    own = decode_view(_gk(doc), (sync / "devices" / f"{a_id}.lgksync").read_bytes(), expected_device_id=a_id)
    assert list(own.states) == _states(doc["a_states"]), "A's state is unchanged after reading B"
    again = ft.FolderSync(root, install_id="install-a").run_once(session, LEASE, now=doc["b_run"]["run_at"] + 120)
    assert {i.kind for i in again.issues} <= EXPECTED_ISSUES and not again.wrote, "settled"


def _b_device_id(root: Path, doc: dict) -> str:
    ids = sorted(p.name.removesuffix(".lgksync") for p in (root / ft.SYNC_DIR_NAME / "devices").iterdir())
    others = [d for d in ids if d != doc["device_a"]]
    assert len(others) == 1, ids
    return others[0]


def test_desktop_b_joins_a_folder_and_a_reads_it_back(tmp_path: Path) -> None:
    doc = _doc()
    root = _folder(tmp_path)
    session = create_vault(tmp_path / "b.json", MASTER, kdf_overrides=TEST_KDF)
    run = doc["b_run"]
    joined = ft.join_folder_group(root, session, LEASE, doc["password"], run["device_name"], install_id="install-b",
                                  now=run["join_at"])
    assert joined.issues == ()
    again = ft.FolderSync(root, install_id="install-b").run_once(session, LEASE, now=run["run_at"])
    assert again.issues == ()
    expected = doc["expected_b"]
    assert _catalog(session) == expected["catalog"]
    assert _memberships(session) == expected["memberships"]
    assert session._payload.get(LINKS_KEY) == expected["links"]
    assert sorted(i["id"] for i in session._payload["items"]) == expected["items"]
    b_id = _b_device_id(root, doc)
    _assert_publishes_a_states(root, doc, b_id)
    _assert_a_reads_back(tmp_path, root, doc, b_id)


@pytest.mark.parametrize("phone", ["from_android", "from_ios"])
def test_desktop_a_reads_back_a_phone_b(tmp_path: Path, phone: str) -> None:
    files = FOLDER / phone
    if not files.is_dir():
        pytest.skip(f"{phone} not written yet (docs/PENDING.md: run the Swift CollectionInteropTests on a Mac)")
    doc = _doc()
    root = _folder(tmp_path, files)
    b_id = _b_device_id(root, doc)
    _assert_publishes_a_states(root, doc, b_id)
    _assert_a_reads_back(tmp_path, root, doc, b_id)
