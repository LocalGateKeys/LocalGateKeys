"""Writes tests/vectors/sync/attachments/vectors.json: synced attachment blobs (format 1).

The format is defined in ``src/localvault/sync/attachment_sync.py`` and
``docs/superpowers/plans/2026-10-29-attachment-sync.md``.  Every value is
deterministic (fixed keys, ids and plaintexts; the nonce is derived), so
LGKCore (Swift) and lgk-core (Kotlin) must reproduce each blob byte for byte.
Run ``python scripts/make_attachment_sync_vectors.py`` to rewrite, ``--check``
to compare.
"""
from __future__ import annotations

import base64
import hashlib
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from localvault.sync import attachment_sync as a  # noqa: E402

OUT = ROOT / "tests" / "vectors" / "sync" / "attachments" / "vectors.json"


def b64(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


CASES = [
    ("empty", "00000000-0000-4000-8000-000000000001", bytes(range(32)), b"", "empty.txt", "text/plain"),
    ("small", "6f1c2d3e-4b5a-4c6d-8e7f-90a1b2c3d4e5", bytes(range(32)),
     b"synthetic passport scan\n", "passport.pdf", "application/pdf"),
    ("bucket-edge", "00000000-0000-4000-8000-000000000003", bytes([7]) * 32,
     bytes(i % 251 for i in range(a.PAD_BLOCK - 8)), "edge.bin", "application/octet-stream"),
    ("two-buckets", "00000000-0000-4000-8000-000000000004", bytes([7]) * 32,
     bytes(i % 251 for i in range(a.PAD_BLOCK - 7)), "next.bin", "application/octet-stream"),
    ("unicode-name", "00000000-0000-4000-8000-000000000005", bytes(range(32, 64)),
     "Ünïcødé ✓".encode("utf-8"), "Rechnung März ✓.txt", "text/plain"),
]


def _flip(raw: bytes, index: int) -> str:
    out = bytearray(raw)
    out[index] ^= 1
    return b64(bytes(out))


def build() -> dict:
    blobs = []
    for name, aid, key, data, filename, mime in CASES:
        blob = a.seal_blob(key, aid, data)
        record = {"id": aid, "name": filename, "mime_type": mime, "size": len(data),
                  "sha256": hashlib.sha256(data).hexdigest(), "key": b64(key)}
        ref = a.AttachmentRef.for_blob(record, blob)
        blobs.append({
            "name": name, "attachment_id": aid, "key": b64(key), "plaintext": b64(data),
            "plaintext_sha256": hashlib.sha256(data).hexdigest(),
            "nonce": a.blob_nonce(key, aid, data).hex(), "padded_length": a.padded_length(len(data)),
            "blob": b64(blob), "blob_id": a.blob_id(blob), "blob_size": len(blob),
            "ref": ref.to_dict(),
            "ref_canonical": json.dumps(ref.to_dict(), ensure_ascii=False, sort_keys=True, separators=(",", ":")),
        })
    small = blobs[1]
    small_blob = base64.b64decode(small["blob"])
    two = base64.b64decode(blobs[3]["blob"])
    refused = [
        {"name": "magic", "blob": _flip(small_blob, 0), "ref": small["ref"], "reason": "bad-blob"},
        {"name": "nonce-bit", "blob": _flip(small_blob, 10), "ref": small["ref"], "reason": "tampered"},
        {"name": "tag-bit", "blob": _flip(small_blob, -1), "ref": small["ref"], "reason": "tampered"},
        {"name": "truncated", "blob": b64(small_blob[:-1]), "ref": small["ref"], "reason": "bad-blob"},
        {"name": "other-blob-for-ref", "blob": blobs[0]["blob"], "ref": small["ref"], "reason": "tampered"},
        {"name": "wrong-key", "blob": small["blob"], "reason": "tampered",
         "ref": {**small["ref"], "key": b64(bytes(32))}},
        {"name": "wrong-digest", "blob": small["blob"], "reason": "tampered",
         "ref": {**small["ref"], "sha256": "0" * 64}},
    ]
    bad_refs = [
        {**small["ref"], "extra": 1},
        {k: v for k, v in small["ref"].items() if k != "name"},
        {**small["ref"], "id": small["ref"]["id"].upper()},
        {**small["ref"], "name": "../escape"},
        {**small["ref"], "name": "a/b"},
        {**small["ref"], "blob_size": small["ref"]["blob_size"] + 1},
        {**small["ref"], "size": a.MAX_FILE_BYTES + 1},
        {**small["ref"], "key": small["ref"]["key"].rstrip("=")},
        {**small["ref"], "blob": small["ref"]["blob"].upper()},
    ]
    lan = {
        "blob_get": a.encode_message(a.blob_get(blobs[3]["blob_id"])).decode("ascii"),
        "chunks": [a.encode_message(a.blob_chunk(two, seq)).decode("ascii")
                   for seq in range(a.blob_chunk(two, 0)["total"])],
    }
    return {
        "format": a.FORMAT,
        "constants": {
            "blob_magic": a.BLOB_MAGIC.decode("ascii"), "blob_aad": a.BLOB_AAD.decode("ascii"),
            "nonce_label": a.NONCE_LABEL.decode("ascii"), "pad_block": a.PAD_BLOCK,
            "max_file_bytes": a.MAX_FILE_BYTES, "max_blob_bytes": a.MAX_BLOB_BYTES,
            "max_attachments": a.MAX_ATTACHMENTS, "chunk_bytes": a.CHUNK_BYTES,
            "folder": f"{a.BLOBS_DIR_NAME}/<blob_id>{a.BLOB_SUFFIX}",
            "sweep_min_age_seconds": a.SWEEP_MIN_AGE_SECONDS,
        },
        "blobs": blobs, "refused_blobs": refused, "refused_refs": bad_refs, "lan": lan,
    }


def render() -> bytes:
    return (json.dumps(build(), ensure_ascii=False, indent=1, sort_keys=True) + "\n").encode("utf-8")


if __name__ == "__main__":
    data = render()
    if "--check" in sys.argv:
        sys.exit(0 if OUT.read_bytes() == data else 1)
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_bytes(data)
    print(f"wrote {OUT.relative_to(ROOT)} ({len(data)} bytes)")
