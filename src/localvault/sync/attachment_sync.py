"""Synced file attachments: encrypted content-addressed blobs (format 1, 2026-10-29).

The design, the byte formats and the security review are in
``docs/SYNC.md`` ("Documents and files"); the shared vectors are
``tests/vectors/sync/attachments/`` (``scripts/make_attachment_sync_vectors.py``).
Every rule below is part of the format that LGKCore (Swift) and lgk-core
(Kotlin) implement byte for byte.

Blob (one per attachment, immutable)
------------------------------------
* ``k`` is the attachment's own random 32-byte key (the catalog record's
  ``key``).  A key encrypts exactly one attachment id; content never changes
  under an id (a new file is a new id and a new key).
* ``P = u64_be(len(data)) || data || zero bytes`` up to the next multiple of
  ``PAD_BLOCK`` (64 KiB), so a blob reveals the size only to 64 KiB.
* ``nonce = HMAC-SHA256(k, NONCE_LABEL + id + "|" + sha256(data))[:12]``
  (deterministic, so every device that seals the same attachment gets the same
  bytes and the same blob id; a different plaintext under a reused key still
  gets a different nonce).
* ``aad = BLOB_AAD + id`` (ASCII), ``blob = BLOB_MAGIC || nonce || AESGCM(k, P, aad)``.
* ``blob_id = hex(sha256(blob))`` (lowercase).  It is the hash of ciphertext,
  never of plaintext.  A blob is at most ``MAX_BLOB_BYTES``.

Reference (carried inside the encrypted, signed sync view)
-----------------------------------------------------------
``{"id","blob","blob_size","name","mime_type","size","sha256","key"}``,
exactly these keys: ``id`` the attachment UUID (lowercase, canonical form),
``blob``/``blob_size`` the blob id and length, then the catalog record fields
(``key`` standard base64 with padding of 32 bytes).  It lives only inside the
sealed view, so the folder and the network see no name, type or key.

Folder: ``LocalGateKeys Sync/attachments/<blob_id>.lgkblob``.  Wi-Fi: the
``blob-get`` / ``blob`` messages below, chunked at ``CHUNK_BYTES`` inside the
existing 1 MiB frames.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import math
import os
import secrets
import uuid
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

FORMAT = 1
BLOB_MAGIC = b"LGKABLB1"
BLOB_AAD = b"lgk-sync-attachment-v1|"
NONCE_LABEL = b"lgk-sync-attachment-nonce-v1|"
PAD_BLOCK = 64 * 1024
MAX_FILE_BYTES = 25 * 1024 * 1024
MAX_ATTACHMENTS = 500
_KEY_LEN = 32
_NONCE_LEN = 12
_TAG_LEN = 16
_LEN_PREFIX = 8
MAX_PLAINTEXT_FRAME = math.ceil((_LEN_PREFIX + MAX_FILE_BYTES) / PAD_BLOCK) * PAD_BLOCK
MAX_BLOB_BYTES = len(BLOB_MAGIC) + _NONCE_LEN + MAX_PLAINTEXT_FRAME + _TAG_LEN
MIN_BLOB_BYTES = len(BLOB_MAGIC) + _NONCE_LEN + PAD_BLOCK + _TAG_LEN
MAX_NAME = 255
MAX_MIME = 255
BLOBS_DIR_NAME = "attachments"
BLOB_SUFFIX = ".lgkblob"
CHUNK_BYTES = 512 * 1024
MAX_CHUNKS = math.ceil(MAX_BLOB_BYTES / CHUNK_BYTES)
#: An unreferenced blob in the shared folder is removed only after this long.
SWEEP_MIN_AGE_SECONDS = 7 * 86400
REF_FIELDS = frozenset({"id", "blob", "blob_size", "name", "mime_type", "size", "sha256", "key"})
_HEX = frozenset("0123456789abcdef")
_MSG_FIELDS = {
    "blob-get": frozenset({"type", "blob", "seq"}),
    "blob": frozenset({"type", "blob", "seq", "total", "size", "data"}),
}


class AttachmentSyncError(ValueError):
    """A blob, reference or message was refused; ``reason`` is a stable code."""

    def __init__(self, reason: str, detail: str = "") -> None:
        super().__init__(f"{reason}: {detail}" if detail else reason)
        self.reason = reason


# --- small checks ---------------------------------------------------------------------------


def is_blob_id(value: object) -> bool:
    return isinstance(value, str) and len(value) == 64 and set(value) <= _HEX


def _check_blob_id(value: object) -> str:
    if not is_blob_id(value):
        raise AttachmentSyncError("bad-blob-id")
    return value  # type: ignore[return-value]


def _check_attachment_id(value: object) -> str:
    if not isinstance(value, str) or len(value) != 36:
        raise AttachmentSyncError("bad-ref", "attachment id")
    try:
        canonical = str(uuid.UUID(value))
    except ValueError:
        raise AttachmentSyncError("bad-ref", "attachment id") from None
    if canonical != value:
        raise AttachmentSyncError("bad-ref", "attachment id is not canonical")
    return value


def _check_key(key: object) -> bytes:
    if not isinstance(key, (bytes, bytearray)) or len(key) != _KEY_LEN:
        raise AttachmentSyncError("bad-key")
    return bytes(key)


def _b64d_strict(value: object, what: str) -> bytes:
    if not isinstance(value, str):
        raise AttachmentSyncError("bad-ref", what)
    try:
        raw = base64.b64decode(value.encode("ascii"), validate=True)
    except (binascii.Error, UnicodeEncodeError, ValueError):
        raise AttachmentSyncError("bad-ref", what) from None
    if base64.b64encode(raw).decode("ascii") != value:
        raise AttachmentSyncError("bad-ref", what)
    return raw


def _text(value: object, what: str, limit: int) -> str:
    if (not isinstance(value, str) or not value or len(value) > limit
            or any(ord(c) < 32 or ord(c) == 127 for c in value)):
        raise AttachmentSyncError("bad-ref", what)
    return value


# --- blob -----------------------------------------------------------------------------------


def padded_length(size: int) -> int:
    """Length of the framed plaintext ``P`` for a file of *size* bytes."""
    return math.ceil((_LEN_PREFIX + size) / PAD_BLOCK) * PAD_BLOCK


def blob_nonce(key: bytes, attachment_id: str, data: bytes) -> bytes:
    message = NONCE_LABEL + attachment_id.encode("ascii") + b"|" + hashlib.sha256(data).digest()
    return hmac.new(_check_key(key), message, hashlib.sha256).digest()[:_NONCE_LEN]


def seal_blob(key: bytes, attachment_id: str, data: bytes) -> bytes:
    key = _check_key(key)
    attachment_id = _check_attachment_id(attachment_id)
    if not isinstance(data, (bytes, bytearray)) or len(data) > MAX_FILE_BYTES:
        raise AttachmentSyncError("too-large")
    data = bytes(data)
    frame = bytearray(len(data).to_bytes(_LEN_PREFIX, "big"))
    frame += data
    frame += bytes(padded_length(len(data)) - len(frame))
    nonce = blob_nonce(key, attachment_id, data)
    sealed = AESGCM(key).encrypt(nonce, bytes(frame), BLOB_AAD + attachment_id.encode("ascii"))
    return BLOB_MAGIC + nonce + sealed


def blob_id(blob: bytes) -> str:
    return hashlib.sha256(blob).hexdigest()


def check_blob_shape(blob: object, expected_id: str | None = None) -> bytes:
    """Size, magic and (when given) content address; no key needed."""
    if not isinstance(blob, (bytes, bytearray)):
        raise AttachmentSyncError("bad-blob")
    blob = bytes(blob)
    if not MIN_BLOB_BYTES <= len(blob) <= MAX_BLOB_BYTES:
        raise AttachmentSyncError("bad-blob", "size")
    if (len(blob) - len(BLOB_MAGIC) - _NONCE_LEN - _TAG_LEN) % PAD_BLOCK:
        raise AttachmentSyncError("bad-blob", "size")
    if blob[:len(BLOB_MAGIC)] != BLOB_MAGIC:
        raise AttachmentSyncError("bad-blob", "magic")
    if expected_id is not None and not hmac.compare_digest(blob_id(blob), _check_blob_id(expected_id)):
        raise AttachmentSyncError("tampered", "content address")
    return blob


def open_blob(blob: bytes, ref: AttachmentRef) -> bytes:
    """Verify *blob* against its reference and return the file bytes."""
    blob = check_blob_shape(blob, ref.blob)
    if len(blob) != ref.blob_size or len(blob) != len(BLOB_MAGIC) + _NONCE_LEN + padded_length(ref.size) + _TAG_LEN:
        raise AttachmentSyncError("tampered", "length")
    start = len(BLOB_MAGIC)
    nonce = blob[start:start + _NONCE_LEN]
    try:
        frame = AESGCM(ref.key).decrypt(nonce, blob[start + _NONCE_LEN:], BLOB_AAD + ref.attachment_id.encode("ascii"))
    except (InvalidTag, ValueError):
        raise AttachmentSyncError("tampered", "authentication") from None
    size = int.from_bytes(frame[:_LEN_PREFIX], "big")
    if size != ref.size or any(frame[_LEN_PREFIX + size:]):
        raise AttachmentSyncError("tampered", "frame")
    data = frame[_LEN_PREFIX:_LEN_PREFIX + size]
    if not hmac.compare_digest(hashlib.sha256(data).hexdigest(), ref.sha256):
        raise AttachmentSyncError("tampered", "digest")
    if not hmac.compare_digest(nonce, blob_nonce(ref.key, ref.attachment_id, data)):
        raise AttachmentSyncError("tampered", "nonce")
    return data


# --- reference ------------------------------------------------------------------------------


@dataclass(frozen=True)
class AttachmentRef:
    attachment_id: str
    blob: str
    blob_size: int
    name: str
    mime_type: str
    size: int
    sha256: str
    key: bytes

    def __post_init__(self) -> None:
        _check_attachment_id(self.attachment_id)
        _check_blob_id(self.blob)
        _text(self.name, "name", MAX_NAME)
        if self.name in {".", ".."} or "/" in self.name or "\\" in self.name:
            raise AttachmentSyncError("bad-ref", "name")
        _text(self.mime_type, "mime type", MAX_MIME)
        if type(self.size) is not int or not 0 <= self.size <= MAX_FILE_BYTES:
            raise AttachmentSyncError("bad-ref", "size")
        if (type(self.blob_size) is not int
                or self.blob_size != len(BLOB_MAGIC) + _NONCE_LEN + padded_length(self.size) + _TAG_LEN):
            raise AttachmentSyncError("bad-ref", "blob size")
        if not is_blob_id(self.sha256):
            raise AttachmentSyncError("bad-ref", "sha256")
        _check_key(self.key)

    def __repr__(self) -> str:  # never print the key
        return f"AttachmentRef(id={self.attachment_id!r}, blob={self.blob!r}, size={self.size})"

    def to_dict(self) -> dict[str, Any]:
        return {"id": self.attachment_id, "blob": self.blob, "blob_size": self.blob_size, "name": self.name,
                "mime_type": self.mime_type, "size": self.size, "sha256": self.sha256,
                "key": base64.b64encode(self.key).decode("ascii")}

    @classmethod
    def from_value(cls, value: object) -> AttachmentRef:
        if not isinstance(value, Mapping) or set(value) != REF_FIELDS:
            raise AttachmentSyncError("bad-ref", "fields")
        key = _b64d_strict(value["key"], "key")
        if len(key) != _KEY_LEN:
            raise AttachmentSyncError("bad-ref", "key")
        return cls(value["id"], value["blob"], value["blob_size"], value["name"], value["mime_type"],
                   value["size"], value["sha256"], key)

    @classmethod
    def for_blob(cls, record: Mapping[str, Any], blob: bytes) -> AttachmentRef:
        """Reference for a catalog record (``attachments.py`` shape) and its sealed blob."""
        key = _b64d_strict(record.get("key"), "key")
        return cls(record.get("id"), blob_id(blob), len(blob), record.get("name"),
                   record.get("mime_type") or "application/octet-stream", record.get("size"),
                   record.get("sha256"), key)

    def catalog_record(self) -> dict[str, Any]:
        """The ``payload["attachments"]`` row this reference stands for."""
        return {"id": self.attachment_id, "name": self.name, "mime_type": self.mime_type, "size": self.size,
                "sha256": self.sha256, "key": base64.b64encode(self.key).decode("ascii")}


def check_refs(refs: Iterable[AttachmentRef]) -> dict[str, AttachmentRef]:
    """Index references by attachment id: at most ``MAX_ATTACHMENTS``, one blob per id."""
    out: dict[str, AttachmentRef] = {}
    for ref in refs:
        if len(out) >= MAX_ATTACHMENTS and ref.attachment_id not in out:
            raise AttachmentSyncError("too-many")
        previous = out.get(ref.attachment_id)
        if previous is not None and previous != ref:
            raise AttachmentSyncError("conflict", ref.attachment_id)
        out[ref.attachment_id] = ref
    return out


def wanted(refs: Iterable[AttachmentRef], present: Iterable[str]) -> list[AttachmentRef]:
    """References whose blob this device still lacks, sorted by blob id (nothing present is fetched)."""
    have = set(present)
    return sorted((ref for ref in check_refs(refs).values() if ref.attachment_id not in have),
                  key=lambda ref: ref.blob)


# --- sync folder ----------------------------------------------------------------------------


class BlobFolder:
    """``<sync dir>/attachments/<blob_id>.lgkblob``; older builds never look in this folder."""

    def __init__(self, sync_dir: Path | str) -> None:
        self.dir = Path(sync_dir) / BLOBS_DIR_NAME

    def path(self, blob: str) -> Path:
        path = self.dir / f"{_check_blob_id(blob)}{BLOB_SUFFIX}"
        if path.parent != self.dir:
            raise AttachmentSyncError("bad-blob-id")
        return path

    def ids(self) -> set[str]:
        try:
            entries = list(os.scandir(self.dir))
        except OSError:
            return set()
        out = set()
        for entry in entries:
            name = entry.name
            if not name.endswith(BLOB_SUFFIX) or entry.is_symlink():
                continue
            stem = name[:-len(BLOB_SUFFIX)]
            if is_blob_id(stem) and entry.is_file(follow_symlinks=False):
                out.add(stem)
        return out

    def has(self, blob: str) -> bool:
        path = self.path(blob)
        return path.is_file() and not path.is_symlink()

    def keep(self, blob: str, size: int, *, now: float) -> bool:
        """Whether a stored blob has the expected length; refreshes its time when half the sweep age old.

        A writer about to reference an existing blob calls this so another device's sweep (which
        waits ``SWEEP_MIN_AGE_SECONDS`` after the last write) does not remove it in between.
        """
        path = self.path(blob)
        try:
            if path.is_symlink() or not path.is_file():
                return False
            info = path.stat()
            if info.st_size != size:
                return False
            if now - info.st_mtime >= SWEEP_MIN_AGE_SECONDS / 2:
                os.utime(path, (now, now))
        except OSError:
            return False
        return True

    def write(self, blob_bytes: bytes, *, replace: bool = False) -> str:
        """Store a blob once; an existing file with that name is kept (content addressed) unless *replace*."""
        blob_bytes = check_blob_shape(blob_bytes)
        name = blob_id(blob_bytes)
        target = self.path(name)
        if target.is_file() and not target.is_symlink() and not replace:
            return name
        self.dir.mkdir(parents=True, exist_ok=True)
        temporary = self.dir / f".{name}.{secrets.token_hex(6)}.tmp"
        try:
            with temporary.open("xb") as handle:
                handle.write(blob_bytes)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary, target)
        finally:
            temporary.unlink(missing_ok=True)
        return name

    def read(self, blob: str) -> bytes | None:
        """The verified blob bytes, or None when missing, too large or not matching its name."""
        path = self.path(blob)
        try:
            if path.is_symlink() or not path.is_file() or path.stat().st_size > MAX_BLOB_BYTES:
                return None
            with path.open("rb") as handle:
                raw = handle.read(MAX_BLOB_BYTES + 1)
        except OSError:
            return None
        try:
            return check_blob_shape(raw, blob)
        except AttachmentSyncError:
            return None

    def sweep(self, referenced: Iterable[str], *, now: float,
              min_age: float = SWEEP_MIN_AGE_SECONDS) -> list[str]:
        """Remove blobs no view references, only once older than *min_age* (a writer may be mid-publish)."""
        keep = set(referenced)
        removed = []
        for name in sorted(self.ids() - keep):
            path = self.path(name)
            try:
                if now - path.stat().st_mtime < min_age:
                    continue
                path.unlink()
                removed.append(name)
            except OSError:
                continue
        return removed


# --- Wi-Fi messages -------------------------------------------------------------------------


def _is_int(value: object, low: int, high: int) -> bool:
    return type(value) is int and low <= value <= high


def encode_message(message: Mapping[str, Any]) -> bytes:
    return json.dumps(message, ensure_ascii=True, separators=(",", ":"), sort_keys=True,
                      allow_nan=False).encode("ascii")


def blob_get(blob: str, seq: int = 0) -> dict[str, Any]:
    return {"type": "blob-get", "blob": _check_blob_id(blob), "seq": seq}


def blob_chunk(blob_bytes: bytes, seq: int) -> dict[str, Any]:
    blob_bytes = check_blob_shape(blob_bytes)
    total = math.ceil(len(blob_bytes) / CHUNK_BYTES)
    if not 0 <= seq < total:
        raise AttachmentSyncError("bad-chunk")
    part = blob_bytes[seq * CHUNK_BYTES:(seq + 1) * CHUNK_BYTES]
    return {"type": "blob", "blob": blob_id(blob_bytes), "seq": seq, "total": total, "size": len(blob_bytes),
            "data": base64.b64encode(part).decode("ascii")}


def parse_message(message: Mapping[str, Any]) -> dict[str, Any]:
    """Shape-check a parsed ``blob-get`` / ``blob`` message (``lan_sync.parse_message`` style)."""
    kind = message.get("type") if isinstance(message, Mapping) else None
    if kind not in _MSG_FIELDS or set(message) != _MSG_FIELDS[kind]:
        raise AttachmentSyncError("bad-message")
    if not is_blob_id(message["blob"]) or not _is_int(message["seq"], 0, MAX_CHUNKS - 1):
        raise AttachmentSyncError("bad-message")
    if kind == "blob":
        if not _is_int(message["size"], MIN_BLOB_BYTES, MAX_BLOB_BYTES):
            raise AttachmentSyncError("too-large")
        if message["total"] != math.ceil(message["size"] / CHUNK_BYTES) or message["seq"] >= message["total"]:
            raise AttachmentSyncError("bad-message")
        if not isinstance(message["data"], str) or len(message["data"]) > 4 * math.ceil(CHUNK_BYTES / 3):
            raise AttachmentSyncError("too-large")
    return dict(message)


class BlobDownload:
    """Collects the chunks of one blob in order and verifies the content address at the end."""

    def __init__(self, ref: AttachmentRef) -> None:
        self.ref = ref
        self._parts = bytearray()
        self.next_seq = 0
        self.total: int | None = None

    def add(self, message: Mapping[str, Any]) -> bytes | None:
        msg = parse_message(message)
        if msg["type"] != "blob" or msg["blob"] != self.ref.blob or msg["size"] != self.ref.blob_size:
            raise AttachmentSyncError("bad-chunk")
        if msg["seq"] != self.next_seq or (self.total is not None and msg["total"] != self.total):
            raise AttachmentSyncError("bad-chunk")
        part = _b64d_strict(msg["data"], "chunk")
        expected = min(CHUNK_BYTES, msg["size"] - msg["seq"] * CHUNK_BYTES)
        if len(part) != expected:
            raise AttachmentSyncError("bad-chunk")
        self.total = msg["total"]
        self._parts += part
        self.next_seq += 1
        if self.next_seq < self.total:
            return None
        return check_blob_shape(bytes(self._parts), self.ref.blob)


__all__ = [
    "AttachmentRef", "AttachmentSyncError", "BlobDownload", "BlobFolder", "BLOB_AAD", "BLOB_MAGIC",
    "BLOBS_DIR_NAME", "CHUNK_BYTES", "MAX_ATTACHMENTS", "MAX_BLOB_BYTES", "MAX_FILE_BYTES", "NONCE_LABEL",
    "PAD_BLOCK", "blob_chunk", "blob_get", "blob_id", "blob_nonce", "check_blob_shape", "check_refs",
    "encode_message", "is_blob_id", "open_blob", "padded_length", "parse_message", "seal_blob", "wanted",
]
