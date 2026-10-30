"""Encrypted immutable attachment sidecars and document catalog services.

The catalog remains the source of truth for attachment metadata and keys.  A
sidecar is opaque ciphertext identified only by a random UUID filename.  A
failed catalog commit may leave an orphan, but a catalog can never point at a
partially written sidecar because the sidecar is fsync'd and atomically
renamed before the reference is committed.
"""
from __future__ import annotations

import base64
import copy
import hashlib
import json
import mimetypes
import os
import re
import secrets
import threading
import time
import unicodedata
import uuid
from collections.abc import Callable
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .item_schema import MAX_ATTACHMENT_NAME, ItemSchemaError, new_item, validate_attachment_records
from .vault import VaultError, VaultLockedError, _aesgcm_decrypt, require_pro_feature
from .i18n import t

MAX_ATTACHMENT_SIZE = 25 * 1024 * 1024
MAX_ATTACHMENT_QUOTA = 1024 * 1024 * 1024
MAX_BATCH_SIZE = 250 * 1024 * 1024
ATTACHMENT_MAGIC = b"LGKATT1\x00"
# v2 sidecar headers carry only identity (format/version/id/store_id).  The
# plaintext size and SHA-256 digest live in the encrypted catalog record next
# to the per-attachment key and are verified after decryption.  v1 sidecars,
# whose header also carried size/sha256, remain readable.
ATTACHMENT_VERSION = 2
SUPPORTED_ATTACHMENT_VERSIONS = frozenset({1, 2})
_V2_HEADER_FIELDS = frozenset({"format", "version", "id", "store_id"})
_HEADER_LIMIT = 8 * 1024
_CHUNK_SIZE = 1024 * 1024
MAX_PREVIEW_TEXT_BYTES = 1 * 1024 * 1024
MAX_PREVIEW_TEXT_CHARS = 200_000
MAX_PREVIEW_BINARY_BYTES = 10 * 1024 * 1024
MAX_PREVIEW_PDF_PAGES = 100
PREVIEW_TIMEOUT_SECONDS = 2.0
_SAFE_TEXT_MIME_TYPES = frozenset({
    "text/plain", "text/csv", "text/markdown", "text/tab-separated-values",
    "application/json", "application/xml", "text/xml", "application/yaml",
    "text/yaml", "text/x-yaml", "text/x-log", "text/rtf",
})
_SAFE_TEXT_SUFFIXES = frozenset({
    ".txt", ".text", ".csv", ".tsv", ".md", ".markdown", ".json", ".xml",
    ".yaml", ".yml", ".log", ".ini", ".toml", ".rtf",
})
# PDF names that start or carry active content. Names are compared after
# decoding ``#xx`` escapes (``/J#61vaScript`` is ``/JavaScript``) so the check
# cannot be dodged by spelling. /URI is deliberately absent: plain hyperlinks
# are in most ordinary PDFs and are not executed by opening the file. Names
# inside compressed object streams are not visible to this check; the flag is
# advisory and no PDF is ever rendered or opened by the app.
_PDF_ACTIVE_NAMES = frozenset({
    b"JavaScript", b"JS", b"OpenAction", b"AA", b"Launch", b"EmbeddedFile", b"EmbeddedFiles",
    b"RichMedia", b"SubmitForm", b"GoToR", b"GoToE", b"ImportData",
})
_PDF_NAME = re.compile(rb"/([^\x00\t\n\x0c\r ()<>\[\]{}/%]*)")
_PDF_NAME_ESCAPE = re.compile(rb"#([0-9A-Fa-f]{2})")


def _pdf_has_active_content(data: bytes) -> bool:
    for match in _PDF_NAME.finditer(data):
        name = match.group(1)
        if b"#" in name:
            name = _PDF_NAME_ESCAPE.sub(lambda escape: bytes((int(escape.group(1), 16),)), name)
        if name in _PDF_ACTIVE_NAMES:
            return True
    return False


_ACTIVE_SUFFIXES = frozenset({
    ".html", ".htm", ".xhtml", ".svg", ".js", ".mjs", ".cjs", ".css",
    ".bat", ".cmd", ".com", ".exe", ".msi", ".ps1", ".psm1", ".vbs",
    ".wsf", ".sh", ".bash", ".py", ".pyw", ".jar", ".class", ".scr",
    ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".odt", ".ods", ".odp",
})


class AttachmentError(VaultError):
    """A bounded attachment operation failed."""


class AttachmentCancelled(AttachmentError):
    pass


def _b64e(value: bytes) -> str:
    return base64.b64encode(value).decode("ascii")


def _b64d(value: str) -> bytes:
    try:
        return base64.b64decode(value.encode("ascii"), validate=True)
    except Exception as exc:  # noqa: BLE001
        raise AttachmentError("Attachment contains malformed encoded data") from exc


def _zero(buffer: bytearray) -> None:
    """Overwrite a secret buffer in place (best effort; Python may hold other copies)."""
    buffer[:] = bytes(len(buffer))


def _canonical(value: Any) -> bytes:
    return json.dumps(value, separators=(",", ":"), sort_keys=True).encode("utf-8")


def _uuid(value: str, field: str = "attachment id") -> str:
    try:
        parsed = uuid.UUID(value)
    except (ValueError, AttributeError, TypeError):
        raise AttachmentError(f"{field} is malformed") from None
    return str(parsed)


def _check_cancel(cancel: Callable[[], bool] | threading.Event | None) -> None:
    if cancel is None:
        return
    try:
        cancelled = cancel.is_set() if hasattr(cancel, "is_set") else bool(cancel())
    except Exception as exc:  # noqa: BLE001
        raise AttachmentCancelled("Attachment operation was cancelled") from exc
    if cancelled:
        raise AttachmentCancelled("Attachment operation was cancelled")


def _atomic_replace(source: Path, destination: Path) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    os.replace(source, destination)
    try:
        with destination.open("rb") as handle:
            os.fsync(handle.fileno())
    except OSError:
        # Windows can reject fsync on a just-renamed handle; the rename is
        # still atomic and the caller treats write errors conservatively.
        pass


def _is_regular_file(path: Path) -> bool:
    try:
        return not path.is_symlink() and path.is_file()
    except OSError:
        return False


OPEN_COPIES_DIR_NAME = "Opened documents"
# "Open file" hands a decrypted copy to its Windows default app, so it is limited
# to an allow-list of document, image and media types that default apps show
# rather than run. Anything else (programs, scripts, shortcuts, disk images,
# remote-desktop files, macro-enabled Office files, archives, ...) goes through
# "Save a copy…", a deliberate export the user opens themselves.
# Legacy Office files (.doc/.xls/.ppt) can carry macros, but every opened copy
# gets Mark-of-the-Web (ZoneId=3, below), so Office opens them in Protected View
# and blocks Internet macros; where the mark cannot be written (FAT/exFAT, some
# network shares) they are refused. HTML/SVG and other script-capable handlers,
# .eml and archives stay excluded.
OPENABLE_SUFFIXES = frozenset({
    ".pdf",
    ".png", ".jpg", ".jpeg", ".gif", ".webp", ".bmp", ".tif", ".tiff", ".heic", ".heif",
    ".txt", ".md", ".csv", ".json", ".xml", ".log",
    ".docx", ".xlsx", ".pptx", ".odt", ".ods", ".odp", ".rtf", ".epub",
    ".doc", ".xls", ".ppt",
    ".mp3", ".m4a", ".wav", ".flac", ".ogg", ".aac",
    ".mp4", ".mov", ".webm", ".mkv", ".avi", ".m4v",
})
OPEN_NOT_ALLOWED_TEXT = (
    "attachments.localgatekeysOnlyOpensDocumentsImages"
)
# Mark-of-the-Web: the opened copy counts as from the Internet zone, so Office
# Protected View, SmartScreen and similar checks treat it as untrusted.
_ZONE_IDENTIFIER = "[ZoneTransfer]\r\nZoneId=3\r\n"
# Types that may carry macros: opened only when the copy carries the mark.
MOTW_REQUIRED_SUFFIXES = frozenset({".doc", ".xls", ".ppt"})
MOTW_MISSING_TEXT = (
    "attachments.windowsCouldNotMarkThis"
)
# Device names Windows reserves in any folder, with any extension and with
# trailing spaces before the extension ("NUL .pdf"); the superscript-digit
# ports (COM¹, LPT³) count as well.
_WINDOWS_RESERVED_NAMES = frozenset(
    {"CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$"}
    | {f"{port}{digit}" for port in ("COM", "LPT") for digit in (*"0123456789", "\u00b9", "\u00b2", "\u00b3")})


def strip_format_controls(name: str) -> str:
    """Drop invisible Unicode format characters (category Cf) from a file name.

    Bidi overrides and isolates (U+202A-U+202E, U+2066-U+2069), zero-width
    characters and the BOM let ``Invoice\u202efdp.exe`` display as
    "Invoiceexe.pdf"; no legitimate file name needs them.
    """
    return "".join(char for char in str(name) if unicodedata.category(char) != "Cf")


def is_reserved_device_name(name: str) -> bool:
    """True when Windows would treat ``name`` as a device (``NUL .pdf``, ``com¹.txt``)."""
    stem = str(name).split(".", 1)[0].rstrip(" ")
    return stem.upper() in _WINDOWS_RESERVED_NAMES


def open_copies_dir(profile_dir: Path) -> Path:
    """Per-profile folder that holds decrypted copies opened in other apps."""
    return Path(profile_dir) / OPEN_COPIES_DIR_NAME


def can_open_externally(name: str) -> bool:
    """True when handing a file of this name to its Windows default app is allowed (allow-list)."""
    suffix = Path(_open_copy_name(name)).suffix.lower()  # judged by the name the copy gets
    return suffix in OPENABLE_SUFFIXES


def mark_of_the_web(path: Path) -> bool:
    """Tag ``path`` as downloaded from the Internet (``Zone.Identifier`` stream); False when not possible.

    Only NTFS (and ReFS) volumes keep alternate data streams; elsewhere the copy is
    opened without the mark.
    """
    if os.name != "nt":
        return False
    try:
        with open(str(path) + ":Zone.Identifier", "w", encoding="ascii", newline="") as stream:
            stream.write(_ZONE_IDENTIFIER)
        return True
    except OSError:
        return False


def _open_copy_name(name: str) -> str:
    """A Windows-safe file name that keeps the extension Windows opens by."""
    cleaned = "".join("_" if char in '<>:"/\\|?*' or ord(char) < 32 else char
                      for char in strip_format_controls(name))
    cleaned = cleaned.strip().rstrip(". ")
    if not cleaned:
        return "document"
    if is_reserved_device_name(cleaned):
        cleaned = "_" + cleaned
    return cleaned


def cleanup_open_copies(profile_dir: Path) -> list[Path]:
    """Delete decrypted copies opened from this profile; return the ones still in use.

    Each copy lives in its own random subfolder.  A file another app still
    holds open cannot be deleted on Windows; it is reported and retried later.
    """
    from .open_copy_watch import is_plain_dir

    root = open_copies_dir(profile_dir)
    if not root.exists() or not is_plain_dir(root):
        return []
    remaining: list[Path] = []
    for folder in root.iterdir():
        if not is_plain_dir(folder):  # a symlink or junction is never followed
            try:
                folder.unlink()
            except OSError:
                remaining.append(folder)
            continue
        for path in folder.iterdir():
            try:
                if path.is_dir() and not path.is_symlink():
                    # Only files are ever written here; never recurse into anything else.
                    remaining.append(path)
                    continue
                path.unlink()
            except OSError:
                remaining.append(path)
        try:
            folder.rmdir()
        except OSError:
            pass
    try:
        root.rmdir()
    except OSError:
        pass
    return remaining


class AttachmentStore:
    """Attachment store bound to one unlocked vault session."""

    def __init__(self, session: Any, *, quota_bytes: int = MAX_ATTACHMENT_QUOTA) -> None:
        self.session = session
        self.quota_bytes = max(1, min(int(quota_bytes), MAX_ATTACHMENT_QUOTA))
        self.root = Path(session.path).parent / "Attachments"
        self.root.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self.cleanup_temporary()

    def _payload(self) -> dict[str, Any]:
        if not getattr(self.session, "is_unlocked", False):
            raise VaultLockedError("Vault is locked")
        return self.session._require_typed_catalog()

    def _store_id(self, payload: dict[str, Any]) -> str:
        store_id = payload.get("attachment_store_id")
        if store_id is None:
            store_id = str(uuid.uuid4())
            payload["attachment_store_id"] = store_id
        return _uuid(str(store_id), "attachment store id")

    def _records(self, payload: dict[str, Any]) -> list[dict[str, Any]]:
        try:
            records = validate_attachment_records(payload.setdefault("attachments", []))
        except ItemSchemaError as exc:
            raise AttachmentError(str(exc)) from exc
        payload["attachments"] = records
        return records

    def _path(self, attachment_id: str) -> Path:
        attachment_id = _uuid(attachment_id)
        path = self.root / f"{attachment_id}.blob"
        if path.parent != self.root or path.name != f"{attachment_id}.blob" or path.is_symlink():
            raise AttachmentError("Attachment path is invalid")
        return path

    def usage_bytes(self) -> int:
        if not self.root.exists():
            return 0
        total = 0
        for path in self.root.glob("*.blob"):
            if not _is_regular_file(path):
                continue
            try:
                size = path.stat().st_size
            except OSError:
                continue
            total += size
        return total

    def quota_status(self) -> dict[str, int]:
        used = self.usage_bytes()
        return {"used": used, "quota": self.quota_bytes, "available": max(0, self.quota_bytes - used)}

    def cleanup_temporary(self) -> None:
        if not self.root.exists():
            return
        for path in self.root.glob(".lgk-attachment-*.tmp"):
            try:
                path.unlink()
            except OSError:
                pass

    @staticmethod
    def cleanup_profile_temporary(profile_dir: Path) -> None:
        """Remove bounded attachment temp files and opened decrypted copies for a profile."""
        cleanup_open_copies(profile_dir)
        root = Path(profile_dir) / "Attachments"
        if not root.exists():
            return
        for path in root.glob(".lgk-attachment-*.tmp"):
            try:
                path.unlink()
            except OSError:
                pass

    def _read_source(self, source: Path, *, cancel: Callable[[], bool] | threading.Event | None) -> bytes:
        source = Path(source)
        if source.is_symlink() or not source.is_file():
            raise AttachmentError("Attachment source must be a regular non-symlink file")
        try:
            initial = source.stat()
            if initial.st_size > MAX_ATTACHMENT_SIZE:
                raise AttachmentError(t("attachments.attachmentExceedsThe25Mib"))
            chunks: list[bytes] = []
            total = 0
            with source.open("rb") as handle:
                while True:
                    _check_cancel(cancel)
                    chunk = handle.read(_CHUNK_SIZE)
                    if not chunk:
                        break
                    total += len(chunk)
                    if total > MAX_ATTACHMENT_SIZE:
                        raise AttachmentError(t("attachments.attachmentExceedsThe25Mib"))
                    chunks.append(chunk)
            final = source.stat()
            if final.st_size != initial.st_size or final.st_mtime_ns != initial.st_mtime_ns:
                raise AttachmentError("Attachment changed while it was being read")
            return b"".join(chunks)
        except OSError as exc:
            raise AttachmentError("Could not read attachment") from exc

    def _write_blob(self, attachment_id: str, plaintext: bytes, *, store_id: str, key: bytes,
                    cancel: Callable[[], bool] | threading.Event | None) -> None:
        header = {
            "format": "localgatekeys-attachment",
            "version": ATTACHMENT_VERSION,
            "id": attachment_id,
            "store_id": store_id,
        }
        header_bytes = _canonical(header)
        if len(header_bytes) > _HEADER_LIMIT:
            raise AttachmentError("Attachment header is too large")
        nonce = secrets.token_bytes(12)
        ciphertext = AESGCM(key).encrypt(nonce, plaintext, header_bytes)
        temporary = self.root / f".lgk-attachment-{secrets.token_hex(12)}.tmp"
        try:
            with temporary.open("xb") as handle:
                handle.write(ATTACHMENT_MAGIC)
                handle.write(len(header_bytes).to_bytes(4, "big"))
                handle.write(header_bytes)
                handle.write(nonce)
                for offset in range(0, len(ciphertext), _CHUNK_SIZE):
                    _check_cancel(cancel)
                    handle.write(ciphertext[offset:offset + _CHUNK_SIZE])
                handle.flush()
                os.fsync(handle.fileno())
            _check_cancel(cancel)
            destination = self._path(attachment_id)
            if destination.exists() or destination.is_symlink():
                raise AttachmentError("Attachment already exists")
            _atomic_replace(temporary, destination)
        except AttachmentError:
            temporary.unlink(missing_ok=True)
            raise
        except OSError as exc:
            temporary.unlink(missing_ok=True)
            raise AttachmentError("Could not commit encrypted attachment") from exc

    def add_bytes(self, name: str, data: bytes, *, mime_type: str | None = None,
                  cancel: Callable[[], bool] | threading.Event | None = None) -> str:
        if not isinstance(data, bytes):
            raise AttachmentError("Attachment data must be bytes")
        if len(data) > MAX_ATTACHMENT_SIZE:
            raise AttachmentError("Attachment exceeds the 25 MiB limit")
        name = strip_format_controls(name)
        if (not name or len(name) > MAX_ATTACHMENT_NAME or "\x00" in name
                or name in {".", ".."} or "/" in name or "\\" in name
                or any(ord(char) < 32 for char in name)):
            raise AttachmentError("Attachment name is malformed")
        with self._lock:
            payload = self._payload()
            projected = self.usage_bytes() + len(data) + 8 * 1024
            if projected > self.quota_bytes:
                raise AttachmentError("Attachment quota exceeded")
            store_id = self._store_id(payload)
            attachment_id = str(uuid.uuid4())
            key = secrets.token_bytes(32)
            digest = hashlib.sha256(data).hexdigest()
            self._write_blob(attachment_id, data, store_id=store_id, key=key, cancel=cancel)
            record = {"id": attachment_id, "name": name,
                      "mime_type": mime_type or mimetypes.guess_type(name)[0] or "application/octet-stream",
                      "size": len(data), "sha256": digest, "key": _b64e(key)}
            payload.setdefault("attachments", []).append(record)
            payload["updated_at"] = __import__("time").time_ns() // 1_000_000_000
            try:
                self.session.save()
            except BaseException:
                payload["attachments"] = [row for row in payload.get("attachments", [])
                                           if row.get("id") != attachment_id]
                raise
            self._record("attachment.add", item_id=None, count=1)
            return attachment_id

    def add_file(self, source: Path, *, name: str | None = None, mime_type: str | None = None,
                 cancel: Callable[[], bool] | threading.Event | None = None) -> str:
        source = Path(source)
        return self.add_bytes(name or source.name, self._read_source(source, cancel=cancel),
                              mime_type=mime_type, cancel=cancel)

    def _record(self, event_type: str, *, item_id: str | None, count: int = 0) -> None:
        try:
            self.session.activity.record(event_type, item_id=item_id, count=count)
        except (AttributeError, VaultError, ItemSchemaError):
            # Activity is convenience history and must not make a committed
            # attachment unusable if an older catalog lacks the event seam.
            pass

    def _record_for_id(self, attachment_id: str) -> dict[str, Any]:
        payload = self._payload()
        record = next((row for row in self._records(payload) if row["id"] == _uuid(attachment_id)), None)
        if record is None:
            raise AttachmentError("Attachment reference is missing")
        return copy.deepcopy(record)

    def read_bytes(self, attachment_id: str, *, cancel: Callable[[], bool] | threading.Event | None = None) -> bytes:
        buffer = self._read_buffer(attachment_id, cancel=cancel)
        try:
            return bytes(buffer)
        finally:
            _zero(buffer)

    def _read_buffer(self, attachment_id: str, *,
                     cancel: Callable[[], bool] | threading.Event | None = None) -> bytearray:
        """Decrypt into a fresh ``bytearray`` the caller zeroes once done.

        The per-attachment key is held in a ``bytearray`` that is zeroed as
        soon as decryption ends, so neither the key nor the plaintext of an
        exported or opened document lingers in freed memory after a lock.
        """
        record = self._record_for_id(attachment_id)
        path = self._path(record["id"])
        try:
            if not _is_regular_file(path):
                raise AttachmentError("Attachment sidecar is unavailable")
            if path.stat().st_size > MAX_ATTACHMENT_SIZE + 64 * 1024:
                raise AttachmentError("Attachment sidecar is too large")
            with path.open("rb") as handle:
                if handle.read(len(ATTACHMENT_MAGIC)) != ATTACHMENT_MAGIC:
                    raise AttachmentError("Attachment sidecar has an invalid header")
                header_length = int.from_bytes(handle.read(4), "big")
                if not 1 <= header_length <= _HEADER_LIMIT:
                    raise AttachmentError("Attachment sidecar header is malformed")
                header_bytes = handle.read(header_length)
                if len(header_bytes) != header_length:
                    raise AttachmentError("Attachment sidecar header is truncated")
                header = json.loads(header_bytes)
                nonce = handle.read(12)
                if len(nonce) != 12:
                    raise AttachmentError("Attachment sidecar nonce is malformed")
                ciphertext = bytearray()
                while True:
                    _check_cancel(cancel)
                    chunk = handle.read(_CHUNK_SIZE)
                    if not chunk:
                        break
                    ciphertext.extend(chunk)
                    if len(ciphertext) > MAX_ATTACHMENT_SIZE + 16:
                        raise AttachmentError("Attachment sidecar exceeds the size bound")
        except (OSError, ValueError, TypeError, json.JSONDecodeError):
            raise AttachmentError("Attachment sidecar is malformed or unavailable") from None
        version = header.get("version") if isinstance(header, dict) else None
        if (not isinstance(header, dict) or header.get("format") != "localgatekeys-attachment"
                or version not in SUPPORTED_ATTACHMENT_VERSIONS or header.get("id") != record["id"]
                or header.get("store_id") != self._store_id(self._payload())):
            raise AttachmentError("Attachment identity metadata does not match")
        if version == 1 and (header.get("size") != record["size"] or header.get("sha256") != record["sha256"]):
            raise AttachmentError("Attachment identity or integrity metadata does not match")
        if version == 2 and set(header) != _V2_HEADER_FIELDS:
            raise AttachmentError("Attachment sidecar header is malformed")
        if len(ciphertext) != record["size"] + 16:
            raise AttachmentError("Attachment sidecar length does not match its catalog record")
        key = bytearray(_b64d(record["key"]))
        plaintext = bytearray()
        try:
            # The vault helper falls back when this cryptography build has no decrypt_into (R-7).
            plaintext = _aesgcm_decrypt(key, nonce, ciphertext, header_bytes)
            if hashlib.sha256(plaintext).hexdigest() != record["sha256"]:
                raise AttachmentError("Attachment integrity check failed")
        except (InvalidTag, ValueError):
            _zero(plaintext)
            raise AttachmentError("Attachment authentication failed") from None
        except BaseException:
            _zero(plaintext)
            raise
        finally:
            _zero(key)
            record["key"] = ""
        return plaintext

    def export(self, attachment_id: str, destination: Path, *, overwrite: bool = False,
               cancel: Callable[[], bool] | threading.Event | None = None) -> Path:
        """Save a decrypted copy ("Save a copy…") like an export.

        The copy is written through :func:`localvault.export.atomic_write`, so
        it is owner-only before any byte lands and crash leftovers are swept
        on the next save, and it carries Mark-of-the-Web (ZoneId=3) before it
        becomes visible, so SmartScreen and Office Protected View treat it as
        downloaded.
        """
        from .export import ExportError, atomic_write

        destination = Path(destination)
        if destination.exists() and not overwrite:
            raise AttachmentError(t("attachments.destinationAlreadyExists"))
        plaintext = self._read_buffer(attachment_id, cancel=cancel)
        try:
            _check_cancel(cancel)
            atomic_write(destination, plaintext, overwrite=overwrite, restrict=True, prepare=mark_of_the_web)
        except ExportError as exc:
            message = t("attachments.destinationAlreadyExists") if "already exists" in str(exc) else t("attachments.couldNotExportAttachment")
            raise AttachmentError(message) from exc
        finally:
            _zero(plaintext)
        self._record("attachment.export", item_id=None, count=1)
        return destination

    def write_open_copy(self, attachment_id: str, *,
                        cancel: Callable[[], bool] | threading.Event | None = None) -> Path:
        """Decrypt one attachment into the profile's opened-copies folder.

        The copy keeps its file name (Windows picks the app by extension) inside
        a fresh random subfolder; it is deleted when its app closes it (and at the latest when the vault locks).
        """
        record = self._record_for_id(attachment_id)
        name = _open_copy_name(record["name"])
        if not can_open_externally(name):
            raise AttachmentError(t(OPEN_NOT_ALLOWED_TEXT))
        plaintext = self._read_buffer(record["id"], cancel=cancel)
        folder = open_copies_dir(self.root.parent) / secrets.token_hex(8)
        destination = folder / name
        try:
            _check_cancel(cancel)
            folder.mkdir(parents=True)
            with destination.open("xb") as handle:
                handle.write(plaintext)
                handle.flush()
                os.fsync(handle.fileno())
            marked = mark_of_the_web(destination)
            if not marked and Path(name).suffix.lower() in MOTW_REQUIRED_SUFFIXES:
                raise AttachmentError(t(MOTW_MISSING_TEXT))
        except (AttachmentError, OSError) as exc:
            destination.unlink(missing_ok=True)
            try:
                folder.rmdir()
            except OSError:
                pass
            if isinstance(exc, AttachmentError):
                raise
            raise AttachmentError(t("attachments.couldNotPrepareTheDocument")) from exc
        finally:
            _zero(plaintext)
        self._record("attachment.open", item_id=None, count=1)
        return destination

    def export_sync_blob(self, attachment_id: str) -> tuple[dict[str, Any], bytes]:
        """The sync reference and sealed blob for one attachment (``sync/attachment_sync.py``).

        The blob is deterministic for an attachment, so every export (and every
        device holding it) gives the same blob id and nothing unchanged is resent.
        """
        from .sync.attachment_sync import AttachmentRef, seal_blob

        record = self._record_for_id(attachment_id)
        plaintext = self._read_buffer(record["id"])
        key = bytearray(_b64d(record["key"]))
        try:
            blob = seal_blob(bytes(key), record["id"], bytes(plaintext))
        finally:
            _zero(plaintext)
            _zero(key)
        return AttachmentRef.for_blob(record, blob).to_dict(), blob

    def import_sync_blob(self, ref: Any, blob: bytes) -> bool:
        """Verify a synced blob against its reference and store it; False when already present.

        A tampered blob (wrong content address, failed authentication, wrong
        size or digest) raises ``AttachmentError`` and stores nothing.  An id
        already present with other metadata is refused (ids are immutable).
        """
        from .sync.attachment_sync import AttachmentRef, AttachmentSyncError, open_blob

        try:
            ref = ref if isinstance(ref, AttachmentRef) else AttachmentRef.from_value(ref)
            data = open_blob(blob, ref)
        except AttachmentSyncError as exc:
            raise AttachmentError(f"Synced attachment refused ({exc.reason})") from None
        record = ref.catalog_record()
        with self._lock:
            payload = self._payload()
            existing = next((row for row in self._records(payload) if row["id"] == ref.attachment_id), None)
            if existing is not None:
                if existing != record:
                    raise AttachmentError("Synced attachment conflicts with a local one")
                if _is_regular_file(self._path(ref.attachment_id)):
                    return False
            if self.usage_bytes() + len(data) + 8 * 1024 > self.quota_bytes:
                raise AttachmentError("Attachment quota exceeded")
            store_id = self._store_id(payload)
            path = self._path(ref.attachment_id)
            if not _is_regular_file(path):
                self._write_blob(ref.attachment_id, data, store_id=store_id, key=ref.key, cancel=None)
            if existing is None:
                payload.setdefault("attachments", []).append(record)
                try:
                    self._records(payload)
                    self.session.save()
                except BaseException:
                    payload["attachments"] = [row for row in payload.get("attachments", [])
                                               if row.get("id") != ref.attachment_id]
                    raise
            self._record("attachment.sync", item_id=None, count=1)
            return True

    def referenced_ids(self, payload: dict[str, Any] | None = None) -> set[str]:
        payload = payload or self._payload()
        result: set[str] = set()
        for collection_name in ("items", "trash"):
            rows = payload.get(collection_name, [])
            if collection_name == "trash":
                rows = [row.get("entry") for row in rows if isinstance(row, dict)]
            for item in rows:
                if not isinstance(item, dict):
                    continue
                typed = item.get("payload", {})
                if isinstance(typed, dict):
                    attachment_id = typed.get("attachment_id")
                    if isinstance(attachment_id, str):
                        try:
                            result.add(_uuid(attachment_id))
                        except AttachmentError:
                            pass
        # Retained typed history is a reachability root.  A document may have
        # been replaced or moved to trash while an older snapshot still needs
        # its sidecar for compare/restore.  Include explicit in-flight pins as
        # well; operation owners remove them after publication or rollback.
        for snapshot in payload.get("history", []):
            if not isinstance(snapshot, dict):
                continue
            for attachment_id in snapshot.get("attachment_ids", []):
                if isinstance(attachment_id, str):
                    try:
                        result.add(_uuid(attachment_id))
                    except AttachmentError:
                        pass
        for attachment_id in payload.get("attachment_pins", []):
            if isinstance(attachment_id, str):
                try:
                    result.add(_uuid(attachment_id))
                except AttachmentError:
                    pass
        return result

    def garbage_collect(self) -> list[str]:
        payload = self._payload()
        referenced = self.referenced_ids(payload)
        removed: list[str] = []
        for path in self.root.glob("*.blob"):
            try:
                attachment_id = _uuid(path.stem)
            except AttachmentError:
                continue
            if attachment_id in referenced:
                continue
            try:
                path.unlink()
                removed.append(attachment_id)
            except OSError:
                continue
        if removed:
            payload["attachments"] = [row for row in self._records(payload) if row["id"] in referenced]
            self.session.save()
            self._record("attachment.gc", item_id=None, count=len(removed))
        return removed


class DocumentService:
    """Typed document items backed by immutable encrypted sidecars."""

    def __init__(self, session: Any) -> None:
        self.session = session
        self.store = AttachmentStore(session)

    def create(self, source: Path, *, title: str | None = None, description: str = "",
               mime_type: str | None = None, name: str | None = None,
               cancel: Callable[[], bool] | threading.Event | None = None) -> str:
        source = Path(source)
        from .item_service import ItemService
        # Check Pro and the item limit before the sidecar is written so a
        # blocked create leaves nothing behind; _append checks again at commit.
        require_pro_feature(self.session, "attachments")
        ItemService(self.session)._check_can_create()
        attachment_id = self.store.add_file(source, name=name, mime_type=mime_type, cancel=cancel)
        item = new_item("document", title or source.name,
                        {"attachment_id": attachment_id, "description": description})
        try:
            item_id = ItemService(self.session)._append(item)
        except BaseException:
            # The orphan is intentionally recoverable and can be removed by GC;
            # no incomplete catalog reference is ever committed.
            raise
        try:
            self.session.activity.record("document.create", item_id=item_id)
        except (AttributeError, VaultError, ItemSchemaError):
            pass
        return item_id

    add = create

    def replace(self, item_id: str, source: Path, *, description: str | None = None,
                mime_type: str | None = None, name: str | None = None,
                cancel: Callable[[], bool] | threading.Event | None = None) -> str:
        """Replace one document's encrypted sidecar through the item service.

        The new sidecar is committed before the catalog reference changes. If
        the optimistic revision update fails, garbage collection removes the
        unreferenced new sidecar while the old document remains intact.
        """
        require_pro_feature(self.session, "attachments")
        item = self.session.item_service.get_item_for_edit(item_id)
        if not item or item.get("kind") != "document":
            raise AttachmentError("Document was not found")
        payload = item.get("payload")
        if not isinstance(payload, dict) or not isinstance(payload.get("attachment_id"), str):
            raise AttachmentError("Document attachment reference is malformed")
        old_record = self.store._record_for_id(payload["attachment_id"])
        attachment_id = self.store.add_file(
            Path(source),
            name=name or old_record["name"],
            mime_type=mime_type or old_record["mime_type"],
            cancel=cancel,
        )
        changes: dict[str, Any] = {"attachment_id": attachment_id}
        if description is not None:
            changes["description"] = description
        try:
            updated = self.session.item_service.update_typed_item(
                item_id,
                payload=changes,
                expected_revision=item.get("revision"),
            )
            if not updated:
                raise AttachmentError("Document was not found")
        except BaseException:
            try:
                self.store.garbage_collect()
            except (AttachmentError, OSError, VaultError, ItemSchemaError):
                pass
            raise
        try:
            self.store.garbage_collect()
        except (AttachmentError, OSError, VaultError, ItemSchemaError):
            # The item reference is already committed; an old sidecar is
            # harmless and remains recoverable for a later GC pass.
            pass
        try:
            self.session.activity.record("document.replace", item_id=item_id, count=1)
        except (AttributeError, VaultError, ItemSchemaError):
            pass
        return attachment_id

    def attachment_for(self, item_id: str) -> dict[str, Any]:
        item = self.session.item_service.get_item(item_id)
        if not item or item.get("kind") != "document":
            raise AttachmentError("Document was not found")
        try:
            attachment_id = item["payload"]["attachment_id"]
        except (KeyError, TypeError):
            raise AttachmentError("Document attachment reference is malformed") from None
        return self.store._record_for_id(attachment_id)

    def read(self, item_id: str, *, cancel: Callable[[], bool] | threading.Event | None = None) -> bytes:
        record = self.attachment_for(item_id)
        return self.store.read_bytes(record["id"], cancel=cancel)

    def export(self, item_id: str, destination: Path, *, overwrite: bool = False,
               cancel: Callable[[], bool] | threading.Event | None = None) -> Path:
        record = self.attachment_for(item_id)
        result = self.store.export(record["id"], destination, overwrite=overwrite, cancel=cancel)
        try:
            self.session.activity.record("document.export", item_id=item_id, count=1)
        except (AttributeError, VaultError, ItemSchemaError):
            pass
        return result

    def open_copy(self, item_id: str, *,
                  cancel: Callable[[], bool] | threading.Event | None = None) -> Path:
        """Write a temporary decrypted copy to hand to the file's default app."""
        record = self.attachment_for(item_id)
        result = self.store.write_open_copy(record["id"], cancel=cancel)
        try:
            self.session.activity.record("document.open", item_id=item_id, count=1)
        except (AttributeError, VaultError, ItemSchemaError):
            pass
        return result

    def open_externally(self, item_id: str, *, launcher: Callable[[str], Any] | None = None) -> Path:
        """Open a temporary decrypted copy in the default app for its file type."""
        if launcher is None:
            if os.name != "nt":
                raise AttachmentError(t("attachments.openingDocumentsInOtherApps"))
            from . import open_copy_watch

            # Opens the default app and deletes the copy as soon as that app is done with it.
            launcher = open_copy_watch.open_and_watch
        path = self.open_copy(item_id)
        try:
            launcher(str(path))
        except OSError as exc:
            path.unlink(missing_ok=True)
            try:
                path.parent.rmdir()
            except OSError:
                pass
            raise AttachmentError(
                t("attachments.windowsCouldNotOpenThis")) from exc
        return path

    def delete(self, item_id: str) -> bool:
        result = self.session.item_service.delete_item(item_id)
        if result:
            try:
                self.session.activity.record("document.delete", item_id=item_id)
            except (AttributeError, VaultError, ItemSchemaError):
                pass
        return result

    def preview(self, item_id: str, *, cancel: Callable[[], bool] | threading.Event | None = None) -> dict[str, Any]:
        return DocumentPreviewService(self.session).preview(item_id, cancel=cancel)


def _preview_metadata(record: dict[str, Any]) -> dict[str, Any]:
    return {
        "name": record["name"],
        "mime_type": record["mime_type"],
        "size": record["size"],
        "sha256": record["sha256"],
    }


def _png_dimensions(data: bytes) -> tuple[int, int] | None:
    if len(data) < 24 or data[:8] != b"\x89PNG\r\n\x1a\n" or data[12:16] != b"IHDR":
        return None
    width = int.from_bytes(data[16:20], "big")
    height = int.from_bytes(data[20:24], "big")
    return (width, height) if width > 0 and height > 0 else None


def _jpeg_dimensions(data: bytes) -> tuple[int, int] | None:
    if len(data) < 4 or data[:2] != b"\xff\xd8":
        return None
    offset = 2
    while offset + 4 <= len(data) and offset < MAX_PREVIEW_BINARY_BYTES:
        if data[offset] != 0xFF:
            offset += 1
            continue
        marker = data[offset + 1]
        offset += 2
        if marker in {0xD8, 0xD9} or 0xD0 <= marker <= 0xD7:
            continue
        length = int.from_bytes(data[offset:offset + 2], "big")
        if length < 2 or offset + length > len(data):
            return None
        if marker in ({0xC0, 0xC1, 0xC2, 0xC3, 0xC5, 0xC6, 0xC7,
                       0xC9, 0xCA, 0xCB, 0xCD, 0xCE, 0xCF}):
            if length < 7:
                return None
            height = int.from_bytes(data[offset + 3:offset + 5], "big")
            width = int.from_bytes(data[offset + 5:offset + 7], "big")
            return (width, height) if width > 0 and height > 0 else None
        offset += length
    return None


class DocumentPreviewService:
    """Authenticated, non-executing previews for document attachments.

    Text is returned as plain text only.  PNG/JPEG and PDF parsing is limited
    to bounded metadata; no renderer is bundled here, so image/PDF previews
    deliberately fall back to metadata-only results rather than invoking an
    external document engine.
    """

    def __init__(self, session: Any) -> None:
        self.session = session
        self.store = AttachmentStore(session)

    def _metadata_only(self, record: dict[str, Any], reason: str, *, safe: bool = True,
                       **extra: Any) -> dict[str, Any]:
        result = {"kind": "metadata", "safe": safe, "reason": reason,
                  "metadata": _preview_metadata(record)}
        result.update(extra)
        return result

    def preview(self, item_id: str, *, cancel: Callable[[], bool] | threading.Event | None = None) -> dict[str, Any]:
        item = self.session.item_service.get_item(item_id)
        if not item or item.get("kind") != "document":
            raise AttachmentError("Document was not found")
        try:
            attachment_id = item["payload"]["attachment_id"]
        except (KeyError, TypeError):
            raise AttachmentError("Document attachment reference is malformed") from None
        return self.preview_attachment(attachment_id, cancel=cancel)

    def preview_attachment(self, attachment_id: str, *,
                           cancel: Callable[[], bool] | threading.Event | None = None) -> dict[str, Any]:
        record = self.store._record_for_id(attachment_id)
        # Authentication happens before MIME/name metadata is used to choose a
        # parser.  This prevents a stale/tampered sidecar from influencing the
        # preview path even though catalog metadata is itself encrypted.
        started = time.monotonic()
        data = self.store.read_bytes(record["id"], cancel=cancel)
        _check_cancel(cancel)
        if time.monotonic() - started > PREVIEW_TIMEOUT_SECONDS:
            return self._metadata_only(record, "preview time limit exceeded")

        mime = str(record["mime_type"]).split(";", 1)[0].strip().casefold()
        suffix = Path(record["name"]).suffix.casefold()
        if suffix in _ACTIVE_SUFFIXES or mime in {
            "text/html", "application/xhtml+xml", "image/svg+xml", "application/javascript",
            "text/javascript", "application/x-shockwave-flash",
        }:
            return self._metadata_only(record, "active content is not previewed", safe=False)

        if mime in _SAFE_TEXT_MIME_TYPES or suffix in _SAFE_TEXT_SUFFIXES:
            if len(data) > MAX_PREVIEW_TEXT_BYTES or b"\x00" in data:
                return self._metadata_only(record, "text preview exceeds safe bounds")
            try:
                text = data.decode("utf-8")
            except UnicodeDecodeError:
                return self._metadata_only(record, "text is not valid UTF-8")
            return {
                "kind": "text", "safe": True, "metadata": _preview_metadata(record),
                "content": text[:MAX_PREVIEW_TEXT_CHARS],
                "truncated": len(text) > MAX_PREVIEW_TEXT_CHARS,
            }

        is_png = mime == "image/png" or suffix == ".png"
        is_jpeg = mime in {"image/jpeg", "image/jpg"} or suffix in {".jpg", ".jpeg"}
        if is_png or is_jpeg:
            dimensions = _png_dimensions(data) if is_png else _jpeg_dimensions(data)
            if dimensions is None:
                return self._metadata_only(record, "image header is invalid")
            width, height = dimensions
            if width * height > 20_000_000:
                return self._metadata_only(record, "image decoded dimensions exceed safe bounds")
            return self._metadata_only(record, "image renderer unavailable", format="png" if is_png else "jpeg",
                                       width=width, height=height)

        if mime == "application/pdf" or suffix == ".pdf":
            if len(data) > MAX_PREVIEW_BINARY_BYTES or not data.startswith(b"%PDF-"):
                return self._metadata_only(record, t("attachments.pdfHeaderOrSizeIs"))
            if _pdf_has_active_content(data):
                return self._metadata_only(record, t("attachments.pdfContainsActiveContent"), safe=False)
            pages = data.count(b"/Type /Page") + data.count(b"/Type/Page")
            if pages > MAX_PREVIEW_PDF_PAGES:
                return self._metadata_only(record, t("attachments.pdfPageCountExceedsSafe"), pages=pages)
            return self._metadata_only(record, "PDF renderer unavailable", pages=pages)

        return self._metadata_only(record, "file type is not safely previewable")


# Short names are useful to callers while keeping the document-specific class
# discoverable for UI integrations in later milestones.
PreviewService = DocumentPreviewService


def attachment_dir_for(vault_file: Path) -> Path:
    """Return the profile-local sidecar directory without creating it."""
    return Path(vault_file).parent / "Attachments"
