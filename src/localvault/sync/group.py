"""Group keys and sealed views for LocalGateKeys device sync.

This is the encrypted on-disk/on-wire format stored in a cloud folder.  The iOS
app implements it byte-for-byte, so every rule below is part of the format.

Format rules (version 1)
------------------------
* Canonical JSON is ``localvault.updates.canonical_json`` (sorted keys, compact
  separators, ``ensure_ascii=False``, UTF-8, no NaN).  Key order and float formatting are pinned in
  the "Canonical JSON" block of ``keyring.py``.
* Base64 is standard alphabet WITH padding (``base64.b64encode``); decoding is
  strict (non-alphabet characters and non-canonical padding are rejected).
* A group key ``G`` is 32 bytes.  Keys are derived with
  ``HKDF(SHA256, length=32, salt=group_id.encode("utf-8"), info=label +
  str(epoch).encode("ascii"))`` where ``label`` is
  ``b"localgatekeys|sync|folder-record|v1|"`` (record key) or
  ``b"localgatekeys|sync|folder-file|v1|"`` (file key).
* Nonces are 12 random bytes; AES-256-GCM, 16-byte tag appended to the
  ciphertext.
* Sealed item: ``{"id","vv","deleted","deleted_at","ct"}`` (exactly these
  fields).  ``ct`` = base64(nonce(12) || AESGCM(record_key, plaintext, aad)) for every
  state.  The plaintext is ``canonical_json(item)`` for live items and the
  empty byte string for tombstones, so tombstones are authenticated too (a
  tombstone with an empty ``ct`` is rejected).  ``aad`` =
  ``canonical_json({"label":"lgk-sync-item-v1","id","vv","deleted",
  "deleted_at","epoch"})`` with ``deleted_at`` null for live items.
* Identifiers (group_id, device_id, item id, vv keys) are ASCII
  ``[A-Za-z0-9._:-]``, 1..128 chars, so canonical JSON is byte-identical on
  every platform.  Decoding rejects duplicate JSON object keys everywhere.
* If a live item has a top-level ``id`` it must equal the sealed id (engine
  conflict copies); otherwise, if its ``record`` dict carries an ``id`` that
  must equal the sealed id.  Both checks apply only when present; the item is
  otherwise opaque here.
* View file: ``MAGIC`` (``b"LGKSYNC1\\n"``), the header as one canonical JSON
  line ``{"format":1,"group_id","device_id","epoch","counter","written_at"}``,
  ``b"\\n"``, then nonce(12) || AESGCM(file_key, canonical_json([sealed...]),
  aad = the header line bytes without the trailing newline).  Sealed records are
  sorted by ``id`` (Unicode code point order == UTF-8 byte order).
* Nonce consumption order when encoding (matters for known-answer vectors):
  one nonce per item (live and tombstone) in sorted id order, then the file
  nonce.  All nonces within one ``encode_view`` call must be distinct.
* Header integers are ints in 0..2**53-1 (bool rejected).
* ``expected_device_id`` (decode) binds a file to the device that must have
  written it; a file under another device's name is rejected.

View signature (sidecar, added 2026-10-24, audit M-7)
-----------------------------------------------------
The view file itself is unchanged (older apps read it as before).  Its writer also
stores a signature next to it (``signatures/<device_id>.lgksig`` in the sync
folder, written right after the view): canonical JSON of exactly
``{"format":1,"group_id","device_id","epoch","counter","view_sha256",
"signing_public","sig"}``, at most ``MAX_SIG_BYTES`` bytes.  ``group_id``,
``device_id``, ``epoch`` and ``counter`` repeat the view header; ``view_sha256`` is
the lowercase hex SHA-256 of the WHOLE view file; ``signing_public`` is the
writer's raw 32-byte Ed25519 key and ``sig`` its 64-byte signature (both base64
with padding) over ``SIG_LABEL + canonical_json(the object without "sig")``.
``verify_view_signature`` raises ``SyncFormatError`` with reason
``sig-malformed`` (not this structure, not canonical), ``sig-stale`` (the
signature names another group, device, epoch or counter than the view: a write
in flight, or a view someone else wrote) or ``sig-mismatch`` (same counter but
another file hash, or a signature that does not verify).  Which keys a reader
trusts is the transport's policy (``folder_transport``).
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import os
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, field

from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from localvault.sync.engine import EngineError, ItemState, is_valid_id
from localvault.updates import canonical_json

MAGIC = b"LGKSYNC1\n"
FORMAT = 1
ITEM_LABEL = "lgk-sync-item-v1"
RECORD_INFO = b"localgatekeys|sync|folder-record|v1|"
FILE_INFO = b"localgatekeys|sync|folder-file|v1|"

MAX_BYTES = 64 * 1024 * 1024
MAX_RECORDS = 20000

_MAX_INT = 2**53 - 1
_NONCE_LEN = 12
_TAG_LEN = 16
_ITEM_FIELDS = frozenset({"id", "vv", "deleted", "deleted_at", "ct"})
_HEADER_FIELDS = frozenset({"format", "group_id", "device_id", "epoch", "counter", "written_at"})
SIG_LABEL = b"lgk-sync-view-sig-v1|"
SIG_FORMAT = 1
MAX_SIG_BYTES = 4096
_SIG_FIELDS = frozenset({"format", "group_id", "device_id", "epoch", "counter", "view_sha256", "signing_public", "sig"})
_HEX = frozenset("0123456789abcdef")

NonceSource = Callable[[int], bytes]


class SyncFormatError(ValueError):
    """A sealed item or view is malformed or fails authentication."""

    def __init__(self, reason: str, detail: str = "") -> None:
        super().__init__(f"{reason}: {detail}" if detail else reason)
        self.reason = reason


def _is_id(value: object) -> bool:
    return is_valid_id(value)


def _no_dup_pairs(pairs: list[tuple[str, object]]) -> dict:
    out: dict = {}
    for k, v in pairs:
        if k in out:
            raise ValueError(f"duplicate JSON key: {k!r}")
        out[k] = v
    return out


def _loads(data: bytes) -> object:
    return json.loads(data.decode("utf-8"), object_pairs_hook=_no_dup_pairs)


def _is_int(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and 0 <= value <= _MAX_INT


@dataclass(frozen=True)
class GroupKey:
    group_id: str
    epoch: int
    key: bytes = field(repr=False)

    def __post_init__(self) -> None:
        if not _is_id(self.group_id):
            raise SyncFormatError("bad-group-key", "group_id")
        if isinstance(self.epoch, bool) or not isinstance(self.epoch, int) or not 1 <= self.epoch <= _MAX_INT:
            raise SyncFormatError("bad-group-key", "epoch")
        if not isinstance(self.key, bytes) or len(self.key) != 32:
            raise SyncFormatError("bad-group-key", "key must be 32 bytes")

    def _derive(self, label: bytes) -> bytes:
        return HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=self.group_id.encode("utf-8"),
            info=label + str(self.epoch).encode("ascii"),
        ).derive(self.key)

    def record_key(self) -> bytes:
        return self._derive(RECORD_INFO)

    def file_key(self) -> bytes:
        return self._derive(FILE_INFO)


@dataclass(frozen=True)
class View:
    header: dict
    states: tuple[ItemState, ...]


def _nonce(source: NonceSource | None) -> bytes:
    n = (source or os.urandom)(_NONCE_LEN)
    if not isinstance(n, bytes) or len(n) != _NONCE_LEN:
        raise SyncFormatError("bad-nonce", f"nonce source must return exactly {_NONCE_LEN} bytes")
    return n


def _item_aad(item_id: object, vv: object, deleted: object, deleted_at: object, epoch: int) -> bytes:
    return canonical_json(
        {
            "label": ITEM_LABEL,
            "id": item_id,
            "vv": vv,
            "deleted": deleted,
            "deleted_at": deleted_at,
            "epoch": epoch,
        }
    )


def seal_item(gk: GroupKey, state: ItemState, *, nonce_source: NonceSource | None = None) -> dict:
    """Encrypt one item state into its sealed record (see module docstring)."""
    nonce = _nonce(nonce_source)
    aad = _item_aad(state.item_id, state.vv, state.deleted, state.deleted_at, gk.epoch)
    plain = b"" if state.deleted else canonical_json(state.item)
    body = AESGCM(gk.record_key()).encrypt(nonce, plain, aad)
    ct = base64.b64encode(nonce + body).decode("ascii")
    return {
        "id": state.item_id,
        "vv": dict(state.vv),
        "deleted": state.deleted,
        "deleted_at": state.deleted_at,
        "ct": ct,
    }


def open_item(gk: GroupKey, sealed: object) -> ItemState:
    """Validate and decrypt a sealed record; any problem raises SyncFormatError."""
    if not isinstance(sealed, Mapping) or set(sealed) != _ITEM_FIELDS:
        raise SyncFormatError("bad-fields", "sealed item must have exactly id, vv, deleted, deleted_at, ct")
    item_id, vv = sealed["id"], sealed["vv"]
    deleted, deleted_at, ct = sealed["deleted"], sealed["deleted_at"], sealed["ct"]
    if not isinstance(item_id, str) or not isinstance(vv, dict) or not isinstance(deleted, bool):
        raise SyncFormatError("bad-fields", "id/vv/deleted types")
    if deleted_at is not None and not _is_int(deleted_at):
        raise SyncFormatError("bad-fields", "deleted_at")
    if not isinstance(ct, str):
        raise SyncFormatError("bad-fields", "ct must be a string")
    try:
        ItemState(item_id, vv, True, deleted_at, None)  # validates id, vv, deleted_at
    except EngineError as exc:
        raise SyncFormatError("invalid-state", str(exc)) from exc
    if not ct:
        raise SyncFormatError("empty-ct", "every state needs authenticated ciphertext")
    if not deleted and deleted_at is not None:
        raise SyncFormatError("invalid-state", "live item must not carry deleted_at")
    try:
        raw = base64.b64decode(ct, validate=True)
        if base64.b64encode(raw).decode("ascii") != ct:
            raise ValueError("non-canonical base64")
    except (binascii.Error, ValueError) as exc:
        raise SyncFormatError("bad-ct", "ciphertext is not canonical base64") from exc
    if len(raw) < _NONCE_LEN + _TAG_LEN:
        raise SyncFormatError("bad-ct", "ciphertext too short")
    aad = _item_aad(item_id, vv, deleted, deleted_at, gk.epoch)
    try:
        plain = AESGCM(gk.record_key()).decrypt(raw[:_NONCE_LEN], raw[_NONCE_LEN:], aad)
    except InvalidTag as exc:
        raise SyncFormatError("auth-failed", "item authentication failed") from exc
    if deleted:
        if plain:
            raise SyncFormatError("bad-item", "tombstone plaintext must be empty")
        return ItemState(item_id, vv, True, deleted_at, None)
    try:
        item = _loads(plain)
    except (ValueError, RecursionError) as exc:
        raise SyncFormatError("bad-item", "item plaintext is not valid JSON") from exc
    if not isinstance(item, dict):
        raise SyncFormatError("bad-item", "item plaintext must be an object")
    if "id" in item:
        if item["id"] != item_id:
            raise SyncFormatError("id-mismatch", "item id differs from sealed id")
    else:
        record = item.get("record")
        if isinstance(record, dict) and "id" in record and record["id"] != item_id:
            raise SyncFormatError("id-mismatch", "record id differs from sealed id")
    try:
        return ItemState(item_id, vv, False, None, item)
    except EngineError as exc:
        raise SyncFormatError("invalid-state", str(exc)) from exc


def _check_header_values(device_id: object, epoch: object, counter: object, written_at: object) -> None:
    if not _is_id(device_id) or not _is_int(counter) or not _is_int(written_at):
        raise SyncFormatError("bad-header", "invalid device_id/counter/written_at")
    if not _is_int(epoch):
        raise SyncFormatError("bad-header", "invalid epoch")


def encode_view(
    gk: GroupKey,
    device_id: str,
    counter: int,
    states: Iterable[ItemState],
    written_at: int,
    *,
    nonce_source: NonceSource | None = None,
    max_records: int = MAX_RECORDS,
) -> bytes:
    """Serialise *states* into one device view file (see module docstring)."""
    _check_header_values(device_id, gk.epoch, counter, written_at)
    ordered = sorted(states, key=lambda s: s.item_id)
    if len(ordered) > max_records:
        raise SyncFormatError("too-many-records", f"{len(ordered)} > {max_records}")
    for a, b in zip(ordered, ordered[1:], strict=False):
        if a.item_id == b.item_id:
            raise SyncFormatError("duplicate-id", a.item_id)
    used: set[bytes] = set()

    def unique_nonces(n: int) -> bytes:
        nonce = _nonce(nonce_source)
        if nonce in used:
            raise SyncFormatError("nonce-reuse", "nonce source repeated a nonce")
        used.add(nonce)
        return nonce

    sealed = [seal_item(gk, s, nonce_source=unique_nonces) for s in ordered]
    header = canonical_json(
        {
            "format": FORMAT,
            "group_id": gk.group_id,
            "device_id": device_id,
            "epoch": gk.epoch,
            "counter": counter,
            "written_at": written_at,
        }
    )
    nonce = unique_nonces(_NONCE_LEN)
    body = AESGCM(gk.file_key()).encrypt(nonce, canonical_json(sealed), header)
    return MAGIC + header + b"\n" + nonce + body


def _read_header(raw: bytes) -> tuple[dict, bytes, int]:
    """(header, header line bytes, index of its newline) of a view file; structure checks only."""
    if not raw.startswith(MAGIC):
        raise SyncFormatError("bad-magic", "not a LocalGateKeys sync view")
    end = raw.find(b"\n", len(MAGIC))
    if end < 0:
        raise SyncFormatError("bad-header", "missing header line")
    header_bytes = raw[len(MAGIC) : end]
    try:
        header = _loads(header_bytes)
    except (ValueError, RecursionError) as exc:
        raise SyncFormatError("bad-header", "header is not JSON") from exc
    if not isinstance(header, dict) or set(header) != _HEADER_FIELDS:
        raise SyncFormatError("bad-header", "header fields")
    fmt = header["format"]
    if isinstance(fmt, bool) or fmt != FORMAT or not isinstance(fmt, int):
        raise SyncFormatError("bad-header", "unsupported format")
    if not _is_id(header["group_id"]):
        raise SyncFormatError("bad-header", "group_id")
    _check_header_values(header["device_id"], header["epoch"], header["counter"], header["written_at"])
    try:
        canonical = canonical_json(header)
    except (ValueError, TypeError) as exc:
        raise SyncFormatError("bad-header", "header is not canonical-JSON safe") from exc
    if canonical != header_bytes:
        raise SyncFormatError("header-noncanonical", "header line is not canonical JSON")
    return header, header_bytes, end


def decode_view(
    gk: GroupKey,
    raw: bytes,
    *,
    expected_device_id: str | None = None,
    max_bytes: int = MAX_BYTES,
    max_records: int = MAX_RECORDS,
) -> View:
    """Parse, authenticate and open a device view file."""
    if len(raw) > max_bytes:
        raise SyncFormatError("too-large", f"{len(raw)} > {max_bytes}")
    header, header_bytes, end = _read_header(raw)
    if header["group_id"] != gk.group_id:
        raise SyncFormatError("group-mismatch", "view belongs to another group")
    if header["epoch"] != gk.epoch:
        raise SyncFormatError("epoch-mismatch", "view was written under another epoch")
    if expected_device_id is not None and header["device_id"] != expected_device_id:
        raise SyncFormatError("device-mismatch", "view was written by another device")
    blob = raw[end + 1 :]
    if len(blob) < _NONCE_LEN + _TAG_LEN:
        raise SyncFormatError("bad-payload", "payload too short")
    try:
        plain = AESGCM(gk.file_key()).decrypt(blob[:_NONCE_LEN], blob[_NONCE_LEN:], header_bytes)
    except InvalidTag as exc:
        raise SyncFormatError("auth-failed", "view authentication failed") from exc
    try:
        records = _loads(plain)
    except (ValueError, RecursionError) as exc:
        raise SyncFormatError("bad-payload", "payload is not JSON") from exc
    if not isinstance(records, list):
        raise SyncFormatError("bad-payload", "payload must be a list")
    if len(records) > max_records:
        raise SyncFormatError("too-many-records", f"{len(records)} > {max_records}")
    states: list[ItemState] = []
    seen: set[str] = set()
    for rec in records:
        if not isinstance(rec, dict):
            raise SyncFormatError("bad-payload", "record must be an object")
        rid = rec.get("id")
        if isinstance(rid, str):
            if rid in seen:
                raise SyncFormatError("duplicate-id", rid)
            seen.add(rid)
        states.append(open_item(gk, rec))
    return View(header, tuple(states))


def _signed_body(header: Mapping, raw: bytes, signing_public: bytes) -> dict:
    return {
        "format": SIG_FORMAT,
        "group_id": header["group_id"],
        "device_id": header["device_id"],
        "epoch": header["epoch"],
        "counter": header["counter"],
        "view_sha256": hashlib.sha256(raw).hexdigest(),
        "signing_public": base64.b64encode(signing_public).decode("ascii"),
    }


def sign_view(raw: bytes, signing_key: ed25519.Ed25519PrivateKey) -> bytes:
    """The signature file for the view file *raw*, signed with the writer's Ed25519 key."""
    header, _header_bytes, _end = _read_header(raw)
    public = signing_key.public_key().public_bytes_raw()
    body = _signed_body(header, raw, public)
    sig = signing_key.sign(SIG_LABEL + canonical_json(body))
    return canonical_json({**body, "sig": base64.b64encode(sig).decode("ascii")})


def _b64_exact(value: object, length: int) -> bytes:
    if not isinstance(value, str):
        raise SyncFormatError("sig-malformed", "base64 field")
    try:
        out = base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise SyncFormatError("sig-malformed", "base64 field") from exc
    if len(out) != length or base64.b64encode(out).decode("ascii") != value:
        raise SyncFormatError("sig-malformed", "base64 field")
    return out


def verify_view_signature(sig_raw: bytes, raw: bytes, header: Mapping) -> bytes:
    """The raw Ed25519 key that validly signed the view file *raw* (decoded header *header*).

    Raises ``SyncFormatError`` (``sig-malformed``, ``sig-stale``, ``sig-mismatch``); see the
    module docstring.  It does NOT decide whether that key is the right one for the device.
    """
    if not isinstance(sig_raw, bytes) or len(sig_raw) > MAX_SIG_BYTES:
        raise SyncFormatError("sig-malformed", "signature file too large")
    try:
        doc = _loads(sig_raw)
    except (ValueError, RecursionError) as exc:
        raise SyncFormatError("sig-malformed", "signature file is not JSON") from exc
    if not isinstance(doc, dict) or set(doc) != _SIG_FIELDS:
        raise SyncFormatError("sig-malformed", "signature fields")
    fmt = doc["format"]
    if isinstance(fmt, bool) or not isinstance(fmt, int) or fmt != SIG_FORMAT:
        raise SyncFormatError("sig-malformed", "unsupported signature format")
    if (not _is_id(doc["group_id"]) or not _is_id(doc["device_id"]) or not _is_int(doc["epoch"])
            or not _is_int(doc["counter"])):
        raise SyncFormatError("sig-malformed", "signature header fields")
    digest = doc["view_sha256"]
    if not isinstance(digest, str) or len(digest) != 64 or not set(digest) <= _HEX:
        raise SyncFormatError("sig-malformed", "view_sha256")
    public = _b64_exact(doc["signing_public"], 32)
    sig = _b64_exact(doc["sig"], 64)
    try:
        canonical = canonical_json(doc)
    except (ValueError, TypeError) as exc:
        raise SyncFormatError("sig-malformed", "signature file is not canonical-JSON safe") from exc
    if canonical != sig_raw:
        raise SyncFormatError("sig-malformed", "signature file is not canonical JSON")
    for name in ("group_id", "device_id", "epoch", "counter"):
        if doc[name] != header.get(name):
            raise SyncFormatError("sig-stale", "the signature belongs to another write")
    if digest != hashlib.sha256(raw).hexdigest():
        raise SyncFormatError("sig-mismatch", "the view differs from the signed one")
    body = {k: v for k, v in doc.items() if k != "sig"}
    try:
        ed25519.Ed25519PublicKey.from_public_bytes(public).verify(sig, SIG_LABEL + canonical_json(body))
    except (InvalidSignature, ValueError) as exc:
        raise SyncFormatError("sig-mismatch", "the signature does not verify") from exc
    return public
