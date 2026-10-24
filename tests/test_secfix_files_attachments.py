"""Regression tests for the 2026-10-24 extended audit: attachments, file output and untrusted images.

Covers L-20/L-25 (Save a copy: Mark-of-the-Web, owner-only ACL, bidi names),
L-21 (no Mark-of-the-Web: macro-capable types refused), L-22 (key and
plaintext buffers zeroed), I-15 (favicon address checks), I-16 (image
formats and ICO entry sizes, QR paste header checks), I-17 (reserved device
names) and I-18 (crash leftovers swept).
"""
from __future__ import annotations

import io
import ipaddress
import os
import shutil
import struct
import subprocess
import time
import tracemalloc
import uuid
from pathlib import Path
from typing import Any

import pytest

from localvault import attachments as attachments_module
from localvault import export as export_module
from localvault.attachments import (
    AttachmentError,
    AttachmentStore,
    _open_copy_name,
    can_open_externally,
    strip_format_controls,
)
from localvault.transfer import export_transfer, import_transfer
from localvault.vault import create_vault
from localvault.winpaths import system32

MASTER = "synthetic file secfix master password"
TEST_KDF = {"time_cost": 1, "memory_cost_kib": 8192, "parallelism": 1, "hash_len": 32}
TRANSFER_PASSWORD = "synthetic transfer package password"
RLO = "‮"
MiB = 1024 * 1024


@pytest.fixture
def case_dir(request: pytest.FixtureRequest) -> Path:
    root = Path(__file__).parents[1] / ".m3-focused" / f"secfix-files-{request.node.name[:40]}-{uuid.uuid4().hex}"
    root.mkdir(parents=True)
    try:
        yield root
    finally:
        shutil.rmtree(root, ignore_errors=True)


def _session(case_dir: Path, name: str = "vault.json") -> Any:
    return create_vault(case_dir / name, MASTER, kdf_overrides=TEST_KDF)


# --------------------------------------------------------------------------- L-20: bidi names
def test_bidi_and_format_controls_are_stripped_from_new_attachment_names(case_dir: Path) -> None:
    store = AttachmentStore(_session(case_dir))
    attachment_id = store.add_bytes(f"Invoice{RLO}fdp.exe", b"MZ synthetic")
    record = store._record_for_id(attachment_id)
    assert record["name"] == "Invoicefdp.exe"
    assert not can_open_externally(record["name"])
    zero_width = store.add_bytes("re​port⁦.pdf⁩", b"%PDF-1.4")
    assert store._record_for_id(zero_width)["name"] == "report.pdf"
    with pytest.raises(AttachmentError, match="malformed"):
        store.add_bytes("​‮﻿", b"x")


def test_stored_bidi_names_are_cleaned_for_opened_copies() -> None:
    assert _open_copy_name(f"Invoice{RLO}fdp.exe") == "Invoicefdp.exe"
    assert not can_open_externally(f"Invoice{RLO}fdp.exe")
    assert strip_format_controls(f"a{RLO}b‍⁧c") == "abc"
    assert strip_format_controls("Résumé 東京.pdf") == "Résumé 東京.pdf"


def test_transfer_import_strips_bidi_controls_from_attachment_names(case_dir: Path) -> None:
    source = _session(case_dir, "source.json")
    document_path = case_dir / "receipt.txt"
    document_path.write_text("receipt contents", encoding="utf-8")
    document_id = source.documents.create(document_path, title="Receipt")
    for record in source._payload["attachments"]:
        record["name"] = f"receipt{RLO}txt.exe"
    package = case_dir / "bidi.lgt"
    export_transfer(source, package, TRANSFER_PASSWORD, ids=[document_id])
    destination = _session(case_dir, "destination.json")
    import_transfer(package, destination, TRANSFER_PASSWORD)
    names = [record["name"] for record in destination._payload["attachments"]]
    assert names == ["receipttxt.exe"]


# --------------------------------------------------------------------------- L-20 / L-25 / I-18: Save a copy
def _zone_identifier(path: Path) -> str | None:
    try:
        with open(str(path) + ":Zone.Identifier", encoding="ascii") as stream:
            return stream.read()
    except OSError:
        return None


@pytest.mark.skipif(os.name != "nt", reason="Mark-of-the-Web and ACLs are Windows features")
def test_save_a_copy_has_mark_of_the_web_and_an_owner_only_acl(case_dir: Path) -> None:
    store = AttachmentStore(_session(case_dir))
    attachment_id = store.add_bytes("statement.pdf", b"%PDF-1.4 synthetic statement")
    out_dir = case_dir / "out"
    out_dir.mkdir()
    destination = store.export(attachment_id, out_dir / "statement.pdf")
    assert destination.read_bytes() == b"%PDF-1.4 synthetic statement"
    assert "ZoneId=3" in (_zone_identifier(destination) or "")
    acl = subprocess.run([system32("icacls.exe"), str(destination)], capture_output=True, text=True,
                         check=True).stdout
    assert "(I)" not in acl, acl  # nothing inherited from the folder
    assert "APPLICATION PACKAGES" not in acl.upper()
    assert sorted(path.name for path in out_dir.iterdir()) == ["statement.pdf"]
    with pytest.raises(AttachmentError, match="already exists"):
        store.export(attachment_id, destination)
    assert store.export(attachment_id, destination, overwrite=True) == destination


def test_save_a_copy_goes_through_the_restricted_export_writer(case_dir: Path,
                                                               monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[tuple[Path, bool]] = []
    original = export_module.atomic_write

    def spy(path: Any, data: Any, **kwargs: Any) -> bool:
        calls.append((Path(path), kwargs.get("restrict", True)))
        assert kwargs.get("prepare") is attachments_module.mark_of_the_web
        return original(path, data, **kwargs)

    monkeypatch.setattr(export_module, "atomic_write", spy)
    store = AttachmentStore(_session(case_dir))
    attachment_id = store.add_bytes("a.txt", b"synthetic")
    store.export(attachment_id, case_dir / "a-copy.txt")
    assert calls == [(case_dir / "a-copy.txt", True)]


def test_stale_export_leftovers_are_swept_on_the_next_export(case_dir: Path) -> None:
    folder = case_dir / "exports"
    folder.mkdir()
    old = time.time() - 2 * export_module.STALE_TEMP_SECONDS
    stale_dir = folder / ".lgk-export-crashed"
    stale_dir.mkdir()
    (stale_dir / ".lgk-export-abc.tmp").write_bytes(b"plaintext left by a crash")
    stale_file = folder / ".lgk-export-def.tmp"
    stale_file.write_bytes(b"plaintext left by a crash")
    foreign_dir = folder / ".lgk-export-foreign"
    foreign_dir.mkdir()
    (foreign_dir / "keep.txt").write_bytes(b"not ours")
    fresh = folder / ".lgk-export-inprogress.tmp"
    fresh.write_bytes(b"another export still writing")
    unrelated = folder / "notes.tmp"
    unrelated.write_bytes(b"user file")
    for path in (stale_dir / ".lgk-export-abc.tmp", stale_dir, stale_file, foreign_dir, unrelated):
        os.utime(path, (old, old))
    export_module.atomic_write(folder / "export.csv", b"a,b\n", restrict=False)
    remaining = sorted(path.name for path in folder.iterdir())
    assert remaining == [".lgk-export-foreign", ".lgk-export-inprogress.tmp", "export.csv", "notes.tmp"]


# --------------------------------------------------------------------------- L-21: no mark, no macros
def test_macro_capable_copies_are_refused_without_mark_of_the_web(case_dir: Path,
                                                                  monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(attachments_module, "mark_of_the_web", lambda path: False)
    store = AttachmentStore(_session(case_dir))
    for name in ("budget.xls", "letter.DOC", "deck.ppt"):
        attachment_id = store.add_bytes(name, b"\xd0\xcf\x11\xe0 synthetic")
        with pytest.raises(AttachmentError, match="Protected View"):
            store.write_open_copy(attachment_id)
    root = attachments_module.open_copies_dir(store.root.parent)
    assert not root.exists() or not any(path.is_file() for path in root.rglob("*"))
    pdf = store.add_bytes("receipt.pdf", b"%PDF-1.4")
    assert store.write_open_copy(pdf).read_bytes() == b"%PDF-1.4"


# --------------------------------------------------------------------------- L-22: zeroed buffers
def test_attachment_key_and_plaintext_buffers_are_zeroed(case_dir: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    store = AttachmentStore(_session(case_dir))
    attachment_id = store.add_bytes("secret.txt", b"synthetic secret document")
    keys: list[bytearray] = []
    buffers: list[bytearray] = []
    real = attachments_module.AESGCM

    class SpyAESGCM:
        def __init__(self, key: Any) -> None:
            self._key = key
            self._inner = real(bytes(key))

        def encrypt(self, *args: Any) -> bytes:
            return self._inner.encrypt(*args)

        def decrypt_into(self, nonce: bytes, data: Any, aad: bytes, buffer: bytearray) -> int:
            # Only attachment decryptions: the vault's own save also builds an AESGCM (with the live data key).
            if isinstance(self._key, bytearray):
                keys.append(self._key)
            buffers.append(buffer)
            return self._inner.decrypt_into(nonce, data, aad, buffer)

    monkeypatch.setattr(attachments_module, "AESGCM", SpyAESGCM)
    # Reads decrypt through the vault helper (R-7: it falls back when decrypt_into is missing).
    from localvault import vault as vault_module

    monkeypatch.setattr(vault_module, "AESGCM", SpyAESGCM)
    assert store.read_bytes(attachment_id) == b"synthetic secret document"
    store.export(attachment_id, case_dir / "copy.txt")
    assert len(keys) == 2 and len(buffers) == 2
    assert all(not any(key) for key in keys)
    assert all(not any(buffer) for buffer in buffers)


# --------------------------------------------------------------------------- I-17: device names
@pytest.mark.parametrize("name", ["NUL .pdf", "nul.tar.gz", "COM¹.pdf", "lpt³.txt", "CONIN$.txt",
                                  "conout$.pdf", "COM0.pdf", "AUX  .docx", "PRN.pdf"])
def test_reserved_device_names_get_a_prefix(name: str) -> None:
    cleaned = _open_copy_name(name)
    assert cleaned.startswith("_"), cleaned


@pytest.mark.parametrize("name", ["NULL.pdf", "COM10.pdf", "console.txt", "report.pdf"])
def test_ordinary_names_are_unchanged(name: str) -> None:
    assert _open_copy_name(name) == name


# --------------------------------------------------------------------------- I-15: favicon addresses
@pytest.mark.parametrize("address", [
    "::ffff:127.0.0.1", "::127.0.0.1", "::10.0.0.1", "64:ff9b::7f00:1", "64:ff9b::c0a8:101", "64:ff9b:1::a00:1",
    "2002:7f00:1::1", "224.0.0.1", "ff0e::1", "fec0::1", "::1", "10.1.2.3", "169.254.1.1",
])
def test_favicon_check_refuses_embedded_private_site_local_and_multicast(address: str) -> None:
    from localvault.item_icons import _public_address

    assert not _public_address(ipaddress.ip_address(address))


@pytest.mark.parametrize("address", ["8.8.8.8", "2606:4700::1111", "64:ff9b::808:808"])
def test_favicon_check_keeps_public_addresses(address: str) -> None:
    from localvault.item_icons import _public_address

    assert _public_address(ipaddress.ip_address(address))


# --------------------------------------------------------------------------- I-16: website images
def _png(width: int, height: int, mode: str = "1") -> bytes:
    from PIL import Image

    buffer = io.BytesIO()
    Image.new(mode, (width, height)).save(buffer, "PNG", optimize=True)
    return buffer.getvalue()


def _ico_with_png(png: bytes, claimed: int = 16) -> bytes:
    header = struct.pack("<HHH", 0, 1, 1) + struct.pack("<BBBBHHII", claimed, claimed, 0, 0, 1, 32, len(png), 22)
    return header + png


def test_ico_entry_larger_than_its_directory_claims_is_refused_before_decoding() -> None:
    pytest.importorskip("PIL")
    from localvault.item_icons import IconDecodeError, _decode_image

    bomb = _ico_with_png(_png(4000, 4000))  # a few KiB that decode to 16,000,000 pixels
    tracemalloc.start()
    started = time.perf_counter()
    with pytest.raises(IconDecodeError, match="dimensions"):
        _decode_image(bomb)
    elapsed = time.perf_counter() - started
    peak = tracemalloc.get_traced_memory()[1]
    tracemalloc.stop()
    assert elapsed < 2 and peak < 4 * MiB
    assert _decode_image(_ico_with_png(_png(32, 32, "RGBA"), claimed=32)).size == (32, 32)


def test_website_bytes_only_reach_the_png_jpeg_and_ico_decoders() -> None:
    pil = pytest.importorskip("PIL.Image")
    from localvault.item_icons import IconDecodeError, _decode_image

    buffer = io.BytesIO()
    pil.new("RGB", (8, 8)).save(buffer, "GIF")
    with pytest.raises(IconDecodeError):
        _decode_image(buffer.getvalue())
    assert _decode_image(_png(16, 16, "RGBA")).size == (16, 16)


def test_qr_paste_checks_magic_bytes_and_dimensions() -> None:
    pil = pytest.importorskip("PIL.Image")
    from localvault.api.result import ApiError
    from localvault.app.qr_import import check_image, image_size

    for fmt in ("PNG", "JPEG", "BMP"):
        buffer = io.BytesIO()
        pil.new("RGB", (120, 80)).save(buffer, fmt)
        assert image_size(buffer.getvalue()) == (120, 80)
        check_image(buffer.getvalue())
    huge = bytearray(_png(8, 8))
    huge[16:24] = struct.pack(">II", 20_000, 20_000)
    with pytest.raises(ApiError):
        check_image(bytes(huge))
    for other in (b"GIF89a" + bytes(32), b"RIFF\x00\x00\x00\x00WEBPVP8 ", b"II*\x00" + bytes(16), b""):
        with pytest.raises(ApiError):
            check_image(other)
