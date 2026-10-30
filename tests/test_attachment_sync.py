from __future__ import annotations

import base64
import hashlib
import json
import os
import shutil
import uuid
from pathlib import Path

import pytest

from localvault.attachments import AttachmentError, AttachmentStore
from localvault.sync import attachment_sync as a
from localvault.vault import create_vault

MASTER = "synthetic attachment master password"
TEST_KDF = {"time_cost": 1, "memory_cost_kib": 8192, "parallelism": 1, "hash_len": 32}
KEY = bytes(range(32))
AID = "6f1c2d3e-4b5a-4c6d-8e7f-90a1b2c3d4e5"


@pytest.fixture
def case_dir(request: pytest.FixtureRequest) -> Path:
    root = Path(__file__).parents[1] / ".m3-focused" / f"attsync-{request.node.name}-{uuid.uuid4().hex}"
    root.mkdir(parents=True)
    try:
        yield root
    finally:
        shutil.rmtree(root, ignore_errors=True)


def _ref(data: bytes, blob: bytes, **over) -> a.AttachmentRef:
    record = {"id": AID, "name": "scan.pdf", "mime_type": "application/pdf", "size": len(data),
              "sha256": hashlib.sha256(data).hexdigest(), "key": base64.b64encode(KEY).decode()}
    record.update(over)
    return a.AttachmentRef.for_blob(record, blob)


def test_blob_is_deterministic_padded_and_hides_plaintext() -> None:
    data = b"synthetic passport scan " * 100
    blob = a.seal_blob(KEY, AID, data)
    assert blob == a.seal_blob(KEY, AID, data)
    assert blob.startswith(a.BLOB_MAGIC)
    assert len(blob) == 8 + 12 + a.PAD_BLOCK + 16
    assert data[:24] not in blob
    assert a.blob_id(blob) != hashlib.sha256(data).hexdigest()
    assert a.open_blob(blob, _ref(data, blob)) == data
    # Two sizes in one 64 KiB bucket give blobs of equal length.
    assert len(a.seal_blob(KEY, AID, b"x")) == len(a.seal_blob(KEY, AID, b"y" * 60000))


def test_empty_and_maximum_sizes() -> None:
    assert a.open_blob(a.seal_blob(KEY, AID, b""), _ref(b"", a.seal_blob(KEY, AID, b""))) == b""
    assert a.padded_length(a.MAX_FILE_BYTES) + 36 == a.MAX_BLOB_BYTES
    with pytest.raises(a.AttachmentSyncError):
        a.seal_blob(KEY, AID, b"x" * (a.MAX_FILE_BYTES + 1))


@pytest.mark.parametrize("where", [0, 8, 20, -1, -17])
def test_tampered_blob_is_refused(where: int) -> None:
    data = b"synthetic"
    blob = bytearray(a.seal_blob(KEY, AID, data))
    ref = _ref(data, bytes(blob))
    blob[where] ^= 1
    with pytest.raises(a.AttachmentSyncError):
        a.open_blob(bytes(blob), ref)


def test_blob_under_other_id_or_key_or_digest_is_refused() -> None:
    data = b"synthetic"
    other_id = str(uuid.UUID(int=1))
    blob = a.seal_blob(KEY, other_id, data)
    with pytest.raises(a.AttachmentSyncError):
        a.open_blob(blob, _ref(data, blob))  # ref says AID
    blob = a.seal_blob(KEY, AID, data)
    with pytest.raises(a.AttachmentSyncError):
        a.open_blob(blob, _ref(data, blob, key=base64.b64encode(bytes(32)).decode()))
    with pytest.raises(a.AttachmentSyncError):
        a.open_blob(blob, _ref(data, blob, sha256="0" * 64))
    # A valid older blob under the same id (replay) does not match a newer reference.
    newer = a.seal_blob(KEY, AID, b"synthetic v2")
    with pytest.raises(a.AttachmentSyncError, match="tampered"):
        a.open_blob(blob, _ref(b"synthetic v2", newer))


def test_reference_round_trip_and_strict_shape() -> None:
    data = b"synthetic"
    blob = a.seal_blob(KEY, AID, data)
    ref = _ref(data, blob)
    raw = ref.to_dict()
    assert set(raw) == a.REF_FIELDS
    assert a.AttachmentRef.from_value(raw) == ref
    assert "key" not in repr(ref) and base64.b64encode(KEY).decode() not in repr(ref)
    for bad in ({**raw, "extra": 1}, {k: v for k, v in raw.items() if k != "key"},
                {**raw, "id": AID.upper()}, {**raw, "name": "../x"}, {**raw, "name": "a\nb"},
                {**raw, "blob_size": raw["blob_size"] + 1}, {**raw, "size": True},
                {**raw, "key": raw["key"].rstrip("=")}, {**raw, "blob": "G" * 64}):
        with pytest.raises(a.AttachmentSyncError):
            a.AttachmentRef.from_value(bad)


def test_caps_and_wanted() -> None:
    blob = a.seal_blob(KEY, AID, b"x")
    ref = _ref(b"x", blob)
    assert a.wanted([ref, ref], present=[]) == [ref]
    assert a.wanted([ref], present=[AID]) == []
    many = []
    for n in range(a.MAX_ATTACHMENTS + 1):
        aid = str(uuid.UUID(int=n + 10))
        b = a.seal_blob(KEY, aid, b"x")
        many.append(a.AttachmentRef(aid, a.blob_id(b), len(b), "f", "text/plain", 1,
                                    hashlib.sha256(b"x").hexdigest(), KEY))
    with pytest.raises(a.AttachmentSyncError, match="too-many"):
        a.check_refs(many)
    other = a.seal_blob(KEY, AID, b"y")
    with pytest.raises(a.AttachmentSyncError, match="conflict"):
        a.check_refs([ref, _ref(b"y", other)])


def test_blob_folder_write_read_names_and_sweep(case_dir: Path) -> None:
    folder = a.BlobFolder(case_dir)
    blob = a.seal_blob(KEY, AID, b"synthetic")
    name = folder.write(blob)
    assert folder.write(blob) == name  # content addressed: never rewritten
    assert folder.read(name) == blob and folder.ids() == {name}
    for bad in ("../" + name, name.upper(), name[:-1], "..", name + "/x"):
        with pytest.raises(a.AttachmentSyncError):
            folder.path(bad)
    # A file whose bytes do not match its name is ignored, as are foreign files.
    (folder.dir / ("0" * 64 + a.BLOB_SUFFIX)).write_bytes(blob)
    (folder.dir / "notes.txt").write_text("x")
    assert folder.read("0" * 64) is None
    assert "notes.txt" not in folder.ids()
    old = os.stat(folder.path(name)).st_mtime
    assert folder.sweep([], now=old + 60) == []  # too young
    assert set(folder.sweep([name], now=old + a.SWEEP_MIN_AGE_SECONDS + 1)) == {"0" * 64}
    assert folder.sweep([], now=old + a.SWEEP_MIN_AGE_SECONDS + 1) == [name]


def test_keep_refreshes_an_old_blob_so_a_concurrent_sweep_leaves_it(case_dir: Path) -> None:
    folder = a.BlobFolder(case_dir)
    blob = a.seal_blob(KEY, AID, b"synthetic")
    name = folder.write(blob)
    old = os.stat(folder.path(name)).st_mtime
    later = old + a.SWEEP_MIN_AGE_SECONDS + 1
    assert folder.keep(name, len(blob), now=later)  # a writer is about to reference it again
    assert folder.sweep([], now=later + 60) == []
    assert not folder.keep(name, len(blob) + a.PAD_BLOCK, now=later)  # wrong length: rewrite it


def test_truncated_folder_blob_is_rewritten_by_its_owner(case_dir: Path) -> None:
    from localvault.sync import attachment_flow as flow

    folder = a.BlobFolder(case_dir)
    blob = a.seal_blob(KEY, AID, b"synthetic")
    name = folder.write(blob)
    folder.path(name).write_bytes(blob[:100])  # a half-synced cloud copy
    ref = _ref(b"synthetic", blob)

    class _State:
        deleted = False
        item = {"ns": "item", "record": {"kind": "document"}, "attachment": ref.to_dict()}

    original = flow.own_blob
    flow.own_blob = lambda session, r: blob if r == ref else None
    try:
        assert flow.publish_folder_blobs(None, folder, [_State()], now=1.0) == []
    finally:
        flow.own_blob = original
    assert folder.read(name) == blob


def test_blob_id_cache_holds_no_attachment_key() -> None:
    from localvault.sync import vault_bridge

    row = {"id": AID, "sha256": "0" * 64, "key": base64.b64encode(KEY).decode()}
    vault_bridge.remember_blob(row, "1" * 64, 100)
    try:
        assert all(row["key"] not in repr(k) for k in vault_bridge._BLOB_IDS)
        assert vault_bridge._BLOB_IDS[vault_bridge._blob_cache_key(row)] == ("1" * 64, 100)
    finally:
        vault_bridge._BLOB_IDS.clear()


def test_lan_chunks_round_trip_and_refusals() -> None:
    data = os.urandom(1_200_000)
    blob = a.seal_blob(KEY, AID, data)
    ref = _ref(data, blob)
    get = a.parse_message(json.loads(a.encode_message(a.blob_get(ref.blob))))
    assert get == {"type": "blob-get", "blob": ref.blob, "seq": 0}
    download = a.BlobDownload(ref)
    total = a.blob_chunk(blob, 0)["total"]
    assert total == 3
    result = None
    for seq in range(total):
        message = json.loads(a.encode_message(a.blob_chunk(blob, seq)))
        assert len(a.encode_message(message)) < 1024 * 1024 - 256
        result = download.add(message)
    assert result == blob and a.open_blob(result, ref) == data
    # Out of order, wrong blob, extra field.
    with pytest.raises(a.AttachmentSyncError):
        a.BlobDownload(ref).add(a.blob_chunk(blob, 1))
    with pytest.raises(a.AttachmentSyncError):
        a.parse_message({**a.blob_chunk(blob, 0), "x": 1})
    with pytest.raises(a.AttachmentSyncError):
        a.parse_message({**a.blob_chunk(blob, 0), "size": a.MAX_BLOB_BYTES + 1})


def _store(case_dir: Path, name: str) -> AttachmentStore:
    (case_dir / name).mkdir()
    return AttachmentStore(create_vault(case_dir / name / "vault.json", MASTER, kdf_overrides=TEST_KDF))


def test_store_export_import_between_vaults(case_dir: Path) -> None:
    source = _store(case_dir, "a")
    target = _store(case_dir, "b")
    data = b"synthetic insurance card\n" * 50
    attachment_id = source.add_bytes("card.png", data, mime_type="image/png")
    ref, blob = source.export_sync_blob(attachment_id)
    assert source.export_sync_blob(attachment_id) == (ref, blob)
    assert target.import_sync_blob(ref, blob) is True
    assert target.read_bytes(attachment_id) == data
    assert target.import_sync_blob(ref, blob) is False  # unchanged: nothing stored again
    assert target.export_sync_blob(attachment_id) == (ref, blob)  # same blob id on every device


def test_store_refuses_tampered_or_conflicting_blob(case_dir: Path) -> None:
    source = _store(case_dir, "a")
    target = _store(case_dir, "b")
    attachment_id = source.add_bytes("card.png", b"synthetic", mime_type="image/png")
    ref, blob = source.export_sync_blob(attachment_id)
    bad = bytearray(blob)
    bad[-1] ^= 1
    with pytest.raises(AttachmentError, match="refused"):
        target.import_sync_blob(ref, bytes(bad))
    assert target._payload().get("attachments", []) == []
    assert not list(target.root.glob("*.blob"))
    target.import_sync_blob(ref, blob)
    with pytest.raises(AttachmentError, match="conflicts"):
        target.import_sync_blob({**ref, "name": "other.png"}, blob)
