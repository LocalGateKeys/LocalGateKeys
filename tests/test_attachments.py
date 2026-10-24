from __future__ import annotations

import shutil
import uuid
from pathlib import Path
from threading import Event

import pytest

from localvault.attachments import (
    MAX_ATTACHMENT_SIZE,
    AttachmentCancelled,
    AttachmentError,
    AttachmentStore,
    DocumentPreviewService,
)
from localvault.vault import create_vault

MASTER = "synthetic attachment master password"
TEST_KDF = {"time_cost": 1, "memory_cost_kib": 8192, "parallelism": 1, "hash_len": 32}


@pytest.fixture
def case_dir(request: pytest.FixtureRequest) -> Path:
    root = Path(__file__).parents[1] / ".m3-focused" / f"attachments-{request.node.name}-{uuid.uuid4().hex}"
    root.mkdir(parents=True)
    try:
        yield root
    finally:
        shutil.rmtree(root, ignore_errors=True)


def _session(case_dir: Path):
    return create_vault(case_dir / "vault.json", MASTER, kdf_overrides=TEST_KDF)


def test_encrypted_sidecar_round_trip_and_tamper_rejection(case_dir: Path) -> None:
    session = _session(case_dir)
    store = AttachmentStore(session)
    plaintext = b"synthetic confidential attachment\n"
    attachment_id = store.add_bytes("notes.txt", plaintext, mime_type="text/plain")

    sidecar = store.root / f"{attachment_id}.blob"
    assert sidecar.exists()
    assert plaintext not in sidecar.read_bytes()
    assert store.read_bytes(attachment_id) == plaintext

    original = sidecar.read_bytes()
    sidecar.write_bytes(original[:-1] + bytes([original[-1] ^ 1]))
    with pytest.raises(AttachmentError):
        store.read_bytes(attachment_id)


def test_attachment_bounds_traversal_quota_and_cancellation(case_dir: Path) -> None:
    session = _session(case_dir)
    store = AttachmentStore(session, quota_bytes=16 * 1024)

    for name in ("../escape.txt", "nested/name.txt", "nested\\name.txt", ""):
        with pytest.raises(AttachmentError):
            store.add_bytes(name, b"synthetic")
    with pytest.raises(AttachmentError):
        store.add_bytes("oversized.bin", b"x" * (MAX_ATTACHMENT_SIZE + 1))

    attachment_id = store.add_bytes("small.bin", b"x" * 64)
    assert store.read_bytes(attachment_id) == b"x" * 64
    before = store.quota_status()
    with pytest.raises(AttachmentError, match="quota"):
        store.add_bytes("quota.bin", b"q" * 10 * 1024)
    assert store.quota_status() == before

    cancelled = Event()
    cancelled.set()
    before_records = list(session._payload["attachments"])
    with pytest.raises(AttachmentCancelled):
        store.add_bytes("cancelled.bin", b"synthetic", cancel=cancelled)
    assert session._payload["attachments"] == before_records
    assert not list(store.root.glob(".lgk-attachment-*.tmp"))


def test_previews_are_bounded_and_active_formats_are_unsafe(case_dir: Path) -> None:
    session = _session(case_dir)
    store = AttachmentStore(session)
    previews = DocumentPreviewService(session)

    text_id = store.add_bytes("readme.txt", b"synthetic safe text", mime_type="text/plain")
    text_preview = previews.preview_attachment(text_id)
    assert text_preview["kind"] == "text"
    assert text_preview["safe"] is True
    assert text_preview["content"] == "synthetic safe text"

    html_id = store.add_bytes("page.html", b"<script>synthetic()</script>", mime_type="text/html")
    html_preview = previews.preview_attachment(html_id)
    assert html_preview["kind"] == "metadata"
    assert html_preview["safe"] is False

    svg_id = store.add_bytes("image.svg", b"<svg><script>synthetic()</script></svg>", mime_type="image/svg+xml")
    svg_preview = previews.preview_attachment(svg_id)
    assert svg_preview["safe"] is False

    pdf_id = store.add_bytes("document.pdf", b"%PDF-1.7\n/JavaScript synthetic", mime_type="application/pdf")
    pdf_preview = previews.preview_attachment(pdf_id)
    assert pdf_preview["kind"] == "metadata"
    assert pdf_preview["safe"] is False

    binary_id = store.add_bytes("payload.bin", b"\x00\x01synthetic", mime_type="application/octet-stream")
    binary_preview = previews.preview_attachment(binary_id)
    assert binary_preview["kind"] == "metadata"
    assert binary_preview["safe"] is True


def _sidecar_header(raw: bytes) -> tuple[dict, bytes, bytes]:
    import json

    from localvault.attachments import ATTACHMENT_MAGIC

    assert raw.startswith(ATTACHMENT_MAGIC)
    offset = len(ATTACHMENT_MAGIC)
    length = int.from_bytes(raw[offset:offset + 4], "big")
    header_bytes = raw[offset + 4:offset + 4 + length]
    rest = raw[offset + 4 + length:]
    return json.loads(header_bytes), rest[:12], rest[12:]


def test_v2_sidecar_header_omits_plaintext_metadata_and_verifies_catalog_digest(case_dir: Path) -> None:
    from localvault.attachments import ATTACHMENT_VERSION

    session = _session(case_dir)
    store = AttachmentStore(session)
    plaintext = b"synthetic confidential attachment body"
    attachment_id = store.add_bytes("notes.txt", plaintext, mime_type="text/plain")
    header, _nonce, ciphertext = _sidecar_header((store.root / f"{attachment_id}.blob").read_bytes())
    assert ATTACHMENT_VERSION == 2
    assert header == {"format": "localgatekeys-attachment", "version": 2, "id": attachment_id,
                      "store_id": session._payload["attachment_store_id"]}
    assert "size" not in header and "sha256" not in header
    assert len(ciphertext) == len(plaintext) + 16
    assert store.read_bytes(attachment_id) == plaintext

    record = next(row for row in session._payload["attachments"] if row["id"] == attachment_id)
    original = record["sha256"]
    record["sha256"] = "0" * 64
    with pytest.raises(AttachmentError):
        store.read_bytes(attachment_id)
    record["sha256"] = original
    record["size"] = len(plaintext) + 1
    with pytest.raises(AttachmentError):
        store.read_bytes(attachment_id)


def test_legacy_v1_sidecars_remain_readable_and_header_tampering_is_rejected(case_dir: Path) -> None:
    import base64
    import json
    import secrets

    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    from localvault.attachments import ATTACHMENT_MAGIC

    session = _session(case_dir)
    store = AttachmentStore(session)
    plaintext = b"legacy sidecar body"
    attachment_id = store.add_bytes("legacy.txt", plaintext, mime_type="text/plain")
    record = next(row for row in session._payload["attachments"] if row["id"] == attachment_id)

    def write_v1(size: int, digest: str) -> None:
        header = {"format": "localgatekeys-attachment", "version": 1, "id": attachment_id,
                  "store_id": session._payload["attachment_store_id"], "size": size, "sha256": digest}
        header_bytes = json.dumps(header, separators=(",", ":"), sort_keys=True).encode("utf-8")
        nonce = secrets.token_bytes(12)
        ciphertext = AESGCM(base64.b64decode(record["key"])).encrypt(nonce, plaintext, header_bytes)
        (store.root / f"{attachment_id}.blob").write_bytes(
            ATTACHMENT_MAGIC + len(header_bytes).to_bytes(4, "big") + header_bytes + nonce + ciphertext)

    write_v1(len(plaintext), record["sha256"])
    assert store.read_bytes(attachment_id) == plaintext
    write_v1(len(plaintext), "0" * 64)
    with pytest.raises(AttachmentError):
        store.read_bytes(attachment_id)
