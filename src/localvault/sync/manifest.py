"""Bounded opaque catalog manifests and idempotent sync deltas.

Only already-encrypted catalog records and already-encrypted attachment
sidecars belong in this protocol.  The manifest layer never decrypts either
kind of payload and rejects mapping-shaped/plaintext record inputs.
"""
from __future__ import annotations

import base64
import hashlib
import json
import secrets
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from typing import Any

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

MANIFEST_VERSION = 1
MAX_RECORDS = 500
MAX_ATTACHMENTS = 500
MAX_RECORD_CIPHERTEXT = 4 * 1024 * 1024
MAX_ATTACHMENT_CIPHERTEXT = 25 * 1024 * 1024 + 64 * 1024
MAX_MANIFEST_BYTES = 4 * 1024 * 1024
MAX_DELTA_BYTES = 8 * 1024 * 1024
MAX_BATCH_BYTES = 250 * 1024 * 1024
MAX_ID_LENGTH = 128
MAX_ANCESTRY = 128
MAX_ACKS = 500
CATALOG_AAD = b"localgatekeys|sync|catalog-record|v1|"


class ManifestError(ValueError):
    """Malformed, unsupported, or over-limit sync data."""


class ManifestReplayError(ManifestError):
    pass


def _b64e(value: bytes) -> str:
    return base64.b64encode(value).decode("ascii")


def _b64d(value: Any, *, field: str, max_bytes: int) -> bytes:
    if not isinstance(value, str):
        raise ManifestError(f"{field} is malformed")
    try:
        result = base64.b64decode(value.encode("ascii"), validate=True)
    except Exception as exc:  # noqa: BLE001 - stable parser boundary
        raise ManifestError(f"{field} is malformed") from exc
    if len(result) > max_bytes:
        raise ManifestError(f"{field} exceeds the size bound")
    return result


def _canonical(value: Any, *, limit: int = MAX_DELTA_BYTES) -> bytes:
    try:
        result = json.dumps(value, ensure_ascii=True, separators=(",", ":"), sort_keys=True).encode()
    except (TypeError, ValueError) as exc:
        raise ManifestError("Sync data is not serializable") from exc
    if len(result) > limit:
        raise ManifestError("Sync data exceeds the size bound")
    return result


def _id(value: Any, field: str = "id") -> str:
    if not isinstance(value, str) or not value or len(value) > MAX_ID_LENGTH or "\x00" in value:
        raise ManifestError(f"{field} is malformed")
    if "/" in value or "\\" in value or value in {".", ".."}:
        raise ManifestError(f"{field} cannot be a path")
    return value


def _counter(value: Any, field: str = "counter") -> int:
    if type(value) is not int or not 0 <= value <= 2**63 - 1:
        raise ManifestError(f"{field} is malformed")
    return value


@dataclass(frozen=True, order=True)
class Revision:
    """Per-device monotonic revision with explicit parent ancestry."""

    device_id: str
    counter: int
    parents: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        _id(self.device_id, "revision device id")
        _counter(self.counter)
        if len(self.parents) > MAX_ANCESTRY:
            raise ManifestError("Revision ancestry is too large")
        for parent in self.parents:
            _id(parent, "revision parent")

    @property
    def key(self) -> str:
        return f"{self.device_id}:{self.counter}"

    def to_dict(self) -> dict[str, Any]:
        return {"device_id": self.device_id, "counter": self.counter,
                "parents": list(self.parents)}

    @classmethod
    def from_value(cls, value: Any, *, device_id: str | None = None,
                   counter: int | None = None) -> Revision:
        if isinstance(value, Revision):
            return value
        if isinstance(value, Mapping):
            parents = value.get("parents", ())
            if not isinstance(parents, (list, tuple)):
                raise ManifestError("Revision parents are malformed")
            return cls(_id(value.get("device_id"), "revision device id"),
                       _counter(value.get("counter")), tuple(_id(p, "revision parent")
                                                              for p in parents))
        if device_id is None or counter is None:
            raise ManifestError("Revision is missing device and counter")
        return cls(_id(device_id, "revision device id"), _counter(counter))

    def dominates(self, other: Revision) -> bool:
        """A revision dominates when it explicitly names the other revision."""

        return self.key == other.key or other.key in self.parents


def _revision_relation(local: Revision, remote: Revision) -> str:
    if local.key == remote.key:
        return "equal"
    if local.dominates(remote):
        return "local"
    if remote.dominates(local):
        return "remote"
    return "concurrent"


@dataclass(frozen=True)
class SyncRecord:
    """Opaque encrypted catalog record or an encrypted tombstone."""

    record_id: str
    ciphertext: bytes
    revision: Revision
    deleted: bool = False
    digest: str = ""
    original_id: str | None = None

    def __post_init__(self) -> None:
        _id(self.record_id, "record id")
        if not isinstance(self.ciphertext, bytes):
            raise ManifestError("Record ciphertext must be bytes")
        if len(self.ciphertext) > MAX_RECORD_CIPHERTEXT:
            raise ManifestError("Record ciphertext exceeds the size bound")
        if self.deleted and self.ciphertext:
            raise ManifestError("Tombstones must not carry record ciphertext")
        calculated = hashlib.sha256(self.ciphertext).hexdigest()
        if self.digest and self.digest != calculated:
            raise ManifestError("Record digest does not match ciphertext")
        object.__setattr__(self, "digest", calculated)
        if self.original_id is not None:
            _id(self.original_id, "original record id")

    @property
    def content_digest(self) -> str:
        return self.digest

    def to_dict(self) -> dict[str, Any]:
        result: dict[str, Any] = {
            "id": self.record_id, "ciphertext": _b64e(self.ciphertext),
            "revision": self.revision.to_dict(), "deleted": self.deleted,
            "digest": self.digest,
        }
        if self.original_id is not None:
            result["original_id"] = self.original_id
        return result

    @classmethod
    def from_value(cls, value: Any, *, default_device_id: str | None = None,
                   default_counter: int | None = None) -> SyncRecord:
        if isinstance(value, SyncRecord):
            return value
        if not isinstance(value, Mapping):
            raise ManifestError("Sync record must be an opaque object")
        # An allowlist is important: accepting a generic record would make it
        # too easy to accidentally put plaintext passwords, activity, or
        # browser tokens on the wire.
        allowed = {"id", "ciphertext", "revision", "deleted", "digest", "original_id",
                   "device_id", "counter", "parents"}
        if set(value) - allowed:
            raise ManifestError("Sync record contains unsupported or plaintext fields")
        if "ciphertext" not in value:
            raise ManifestError("Sync record must contain ciphertext")
        raw = value.get("ciphertext")
        if isinstance(raw, str):
            raw = _b64d(raw, field="record ciphertext", max_bytes=MAX_RECORD_CIPHERTEXT)
        if not isinstance(raw, bytes):
            raise ManifestError("Record ciphertext must be bytes or base64")
        revision = Revision.from_value(value.get("revision"),
                                       device_id=value.get("device_id", default_device_id),
                                       counter=value.get("counter", default_counter))
        parents = value.get("parents")
        if parents is not None and not isinstance(value.get("revision"), Mapping):
            revision = Revision(revision.device_id, revision.counter,
                                tuple(_id(parent, "revision parent") for parent in parents))
        return cls(_id(value.get("id"), "record id"), raw, revision,
                   deleted=value.get("deleted") is True, digest=value.get("digest", ""),
                   original_id=value.get("original_id"))


@dataclass(frozen=True)
class AttachmentMeta:
    """Manifest-only attachment metadata; it contains no catalog key."""

    attachment_id: str
    size: int
    sha256: str
    revision: Revision

    def __post_init__(self) -> None:
        _id(self.attachment_id, "attachment id")
        if type(self.size) is not int or not 0 <= self.size <= MAX_ATTACHMENT_CIPHERTEXT:
            raise ManifestError("Attachment size is outside the accepted bound")
        if (not isinstance(self.sha256, str) or len(self.sha256) != 64
                or any(char not in "0123456789abcdef" for char in self.sha256)):
            raise ManifestError("Attachment digest is malformed")

    def to_dict(self) -> dict[str, Any]:
        return {"id": self.attachment_id, "size": self.size, "sha256": self.sha256,
                "revision": self.revision.to_dict()}


@dataclass(frozen=True)
class AttachmentDelta:
    """Opaque encrypted attachment sidecar for a delta transfer."""

    attachment_id: str
    ciphertext: bytes
    sha256: str
    revision: Revision

    def __post_init__(self) -> None:
        _id(self.attachment_id, "attachment id")
        if not isinstance(self.ciphertext, bytes) or len(self.ciphertext) > MAX_ATTACHMENT_CIPHERTEXT:
            raise ManifestError("Attachment ciphertext is outside the accepted bound")
        digest = hashlib.sha256(self.ciphertext).hexdigest()
        if self.sha256 != digest:
            raise ManifestError("Attachment digest does not match ciphertext")

    @property
    def size(self) -> int:
        return len(self.ciphertext)

    def to_dict(self) -> dict[str, Any]:
        return {"id": self.attachment_id, "ciphertext": _b64e(self.ciphertext),
                "sha256": self.sha256, "revision": self.revision.to_dict()}

    @classmethod
    def from_value(cls, value: Any) -> AttachmentDelta:
        if isinstance(value, AttachmentDelta):
            return value
        if not isinstance(value, Mapping):
            raise ManifestError("Attachment delta is malformed")
        raw = _b64d(value.get("ciphertext"), field="attachment ciphertext",
                     max_bytes=MAX_ATTACHMENT_CIPHERTEXT)
        return cls(_id(value.get("id"), "attachment id"), raw,
                   value.get("sha256", ""), Revision.from_value(value.get("revision")))


@dataclass(frozen=True)
class Acknowledgement:
    peer_device_id: str
    highest_counter: int
    manifest_digest: str

    def __post_init__(self) -> None:
        _id(self.peer_device_id, "acknowledgement peer")
        _counter(self.highest_counter, "acknowledgement counter")
        if len(self.manifest_digest) != 64 or any(c not in "0123456789abcdef"
                                                 for c in self.manifest_digest):
            raise ManifestError("Acknowledgement digest is malformed")

    def to_dict(self) -> dict[str, Any]:
        return {"peer": self.peer_device_id, "counter": self.highest_counter,
                "digest": self.manifest_digest}


@dataclass(frozen=True)
class Manifest:
    group_id: str
    device_id: str
    counter: int
    ancestry: dict[str, int] = field(default_factory=dict)
    records: tuple[SyncRecord, ...] = ()
    attachments: tuple[AttachmentMeta, ...] = ()
    acknowledgements: tuple[Acknowledgement, ...] = ()
    version: int = MANIFEST_VERSION

    def __post_init__(self) -> None:
        _id(self.group_id, "group id")
        _id(self.device_id, "device id")
        _counter(self.counter)
        if len(self.records) > MAX_RECORDS or len(self.attachments) > MAX_ATTACHMENTS:
            raise ManifestError("Manifest exceeds the item or attachment bound")
        if len(self.ancestry) > MAX_ANCESTRY or len(self.acknowledgements) > MAX_ACKS:
            raise ManifestError("Manifest ancestry or acknowledgement set is too large")
        for key, value in self.ancestry.items():
            _id(key, "ancestry device id")
            _counter(value, "ancestry counter")
        if len({row.record_id for row in self.records}) != len(self.records):
            raise ManifestError("Manifest contains duplicate record IDs")
        if len({row.attachment_id for row in self.attachments}) != len(self.attachments):
            raise ManifestError("Manifest contains duplicate attachment IDs")
        if len({row.peer_device_id for row in self.acknowledgements}) != len(self.acknowledgements):
            raise ManifestError("Manifest contains duplicate acknowledgements")

    @property
    def digest(self) -> str:
        return hashlib.sha256(self.to_bytes()).hexdigest()

    def to_dict(self) -> dict[str, Any]:
        return {
            "version": self.version, "group_id": self.group_id, "device_id": self.device_id,
            "counter": self.counter, "ancestry": dict(sorted(self.ancestry.items())),
            "records": [row.to_dict() for row in self.records],
            "attachments": [row.to_dict() for row in self.attachments],
            "acknowledgements": [row.to_dict() for row in self.acknowledgements],
        }

    def to_bytes(self) -> bytes:
        return _canonical(self.to_dict(), limit=MAX_MANIFEST_BYTES)

    @classmethod
    def from_bytes(cls, value: bytes) -> Manifest:
        if not isinstance(value, bytes) or len(value) > MAX_MANIFEST_BYTES:
            raise ManifestError("Manifest is outside the size bound")
        try:
            raw = json.loads(value)
        except (ValueError, TypeError):
            raise ManifestError("Manifest is not valid JSON") from None
        if not isinstance(raw, Mapping) or raw.get("version") != MANIFEST_VERSION:
            raise ManifestError("Unsupported manifest version")
        records = raw.get("records", [])
        attachments = raw.get("attachments", [])
        ancestry = raw.get("ancestry", {})
        acks = raw.get("acknowledgements", [])
        if not isinstance(records, list) or not isinstance(attachments, list):
            raise ManifestError("Manifest collections are malformed")
        if not isinstance(ancestry, Mapping) or not isinstance(acks, list):
            raise ManifestError("Manifest ancestry is malformed")
        return cls(
            group_id=_id(raw.get("group_id"), "group id"),
            device_id=_id(raw.get("device_id"), "device id"),
            counter=_counter(raw.get("counter")),
            ancestry={_id(k, "ancestry device id"): _counter(v, "ancestry counter")
                      for k, v in ancestry.items()},
            records=tuple(SyncRecord.from_value(row) for row in records),
            attachments=tuple(AttachmentMeta(
                _id(row.get("id"), "attachment id"), row.get("size"), row.get("sha256"),
                Revision.from_value(row.get("revision"))) for row in attachments
                if isinstance(row, Mapping)),
            acknowledgements=tuple(Acknowledgement(
                _id(row.get("peer"), "acknowledgement peer"), row.get("counter"),
                row.get("digest")) for row in acks if isinstance(row, Mapping)),
        )

    def delta_since(self, remote: Manifest) -> SyncDelta:
        if not isinstance(remote, Manifest) or remote.group_id != self.group_id:
            raise ManifestError("Cannot delta manifests from different sync groups")
        remote_records = {row.record_id: row for row in remote.records}
        records = tuple(row for row in self.records
                        if row.record_id not in remote_records
                        or row.digest != remote_records[row.record_id].digest
                        or row.revision != remote_records[row.record_id].revision
                        or row.deleted != remote_records[row.record_id].deleted)
        remote_attachments = {row.attachment_id: row for row in remote.attachments}
        attachments = tuple(row for row in self.attachments
                            if row.attachment_id not in remote_attachments
                            or row.sha256 != remote_attachments[row.attachment_id].sha256
                            or row.revision != remote_attachments[row.attachment_id].revision)
        return SyncDelta(
            group_id=self.group_id, source_device_id=self.device_id,
            base_manifest_digest=remote.digest, target_manifest_digest=self.digest,
            counter=self.counter, ancestry=self.ancestry.copy(), records=records,
            attachments=attachments, acknowledgements=self.acknowledgements,
        )


@dataclass(frozen=True)
class SyncDelta:
    group_id: str
    source_device_id: str
    base_manifest_digest: str
    target_manifest_digest: str
    counter: int
    ancestry: dict[str, int] = field(default_factory=dict)
    records: tuple[SyncRecord, ...] = ()
    attachments: tuple[AttachmentDelta, ...] = ()
    acknowledgements: tuple[Acknowledgement, ...] = ()
    version: int = MANIFEST_VERSION

    def to_dict(self) -> dict[str, Any]:
        return {
            "version": self.version, "group_id": self.group_id,
            "source_device_id": self.source_device_id,
            "base_manifest_digest": self.base_manifest_digest,
            "target_manifest_digest": self.target_manifest_digest,
            "counter": self.counter, "ancestry": dict(sorted(self.ancestry.items())),
            "records": [row.to_dict() for row in self.records],
            "attachments": [row.to_dict() for row in self.attachments],
            "acknowledgements": [row.to_dict() for row in self.acknowledgements],
        }

    def to_bytes(self) -> bytes:
        result = _canonical(self.to_dict(), limit=MAX_DELTA_BYTES)
        if len(result) > MAX_BATCH_BYTES:
            raise ManifestError("Sync delta exceeds the batch bound")
        return result

    @classmethod
    def from_bytes(cls, value: bytes) -> SyncDelta:
        if not isinstance(value, bytes) or len(value) > MAX_DELTA_BYTES:
            raise ManifestError("Sync delta is outside the size bound")
        try:
            raw = json.loads(value)
        except (ValueError, TypeError):
            raise ManifestError("Sync delta is not valid JSON") from None
        if not isinstance(raw, Mapping) or raw.get("version") != MANIFEST_VERSION:
            raise ManifestError("Unsupported sync delta version")
        records = raw.get("records", [])
        attachments = raw.get("attachments", [])
        acks = raw.get("acknowledgements", [])
        if not all(isinstance(value, list) for value in (records, attachments, acks)):
            raise ManifestError("Sync delta collections are malformed")
        return cls(
            group_id=_id(raw.get("group_id"), "group id"),
            source_device_id=_id(raw.get("source_device_id"), "source device id"),
            base_manifest_digest=raw.get("base_manifest_digest", ""),
            target_manifest_digest=raw.get("target_manifest_digest", ""),
            counter=_counter(raw.get("counter")),
            ancestry={_id(k, "ancestry device id"): _counter(v, "ancestry counter")
                      for k, v in (raw.get("ancestry") or {}).items()},
            records=tuple(SyncRecord.from_value(row) for row in records),
            attachments=tuple(AttachmentDelta.from_value(row) for row in attachments),
            acknowledgements=tuple(Acknowledgement(
                _id(row.get("peer"), "acknowledgement peer"), row.get("counter"),
                row.get("digest")) for row in acks if isinstance(row, Mapping)),
        )


def build_manifest(group_id: str, device_id: str, counter: int,
                   records: Iterable[SyncRecord | Mapping[str, Any]], *,
                   attachments: Iterable[AttachmentMeta | Mapping[str, Any]] = (),
                   ancestry: Mapping[str, int] | None = None,
                   acknowledgements: Iterable[Acknowledgement] = ()) -> Manifest:
    normalized_records = tuple(SyncRecord.from_value(row, default_device_id=device_id,
                                                     default_counter=counter)
                               for row in records)
    normalized_attachments = []
    for row in attachments:
        if isinstance(row, AttachmentMeta):
            normalized_attachments.append(row)
            continue
        if not isinstance(row, Mapping):
            raise ManifestError("Attachment metadata is malformed")
        normalized_attachments.append(AttachmentMeta(
            _id(row.get("id"), "attachment id"), row.get("size"), row.get("sha256"),
            Revision.from_value(row.get("revision"), device_id=device_id, counter=counter)))
    return Manifest(group_id=_id(group_id, "group id"), device_id=_id(device_id, "device id"),
                    counter=_counter(counter), ancestry=dict(ancestry or {}),
                    records=normalized_records, attachments=tuple(normalized_attachments),
                    acknowledgements=tuple(acknowledgements))


def make_attachment_delta(attachment_id: str, ciphertext: bytes, revision: Revision) -> AttachmentDelta:
    if not isinstance(ciphertext, bytes):
        raise ManifestError("Attachment sidecar must already be encrypted bytes")
    return AttachmentDelta(_id(attachment_id, "attachment id"), ciphertext,
                           hashlib.sha256(ciphertext).hexdigest(), revision)


def apply_delta(base: Manifest, delta: SyncDelta, *, allow_rebase: bool = False) -> Manifest:
    """Apply a validated delta without partially mutating the base manifest."""

    if not isinstance(base, Manifest) or not isinstance(delta, SyncDelta):
        raise ManifestError("Manifest and delta are required")
    if base.group_id != delta.group_id:
        raise ManifestError("Sync group mismatch")
    if not allow_rebase and base.digest != delta.base_manifest_digest:
        raise ManifestReplayError("Delta base does not match the current manifest")
    records = {row.record_id: row for row in base.records}
    for row in delta.records:
        previous = records.get(row.record_id)
        if previous is not None and previous.revision == row.revision and previous.digest != row.digest:
            raise ManifestError("Revision reused for different record ciphertext")
        records[row.record_id] = row
    attachments = {row.attachment_id: row for row in base.attachments}
    for row in delta.attachments:
        attachments[row.attachment_id] = AttachmentMeta(
            row.attachment_id, row.size, row.sha256, row.revision)
    result = Manifest(
        group_id=base.group_id, device_id=delta.source_device_id, counter=delta.counter,
        ancestry={**base.ancestry, **delta.ancestry}, records=tuple(sorted(records.values(),
        key=lambda row: row.record_id)), attachments=tuple(sorted(attachments.values(),
        key=lambda row: row.attachment_id)), acknowledgements=delta.acknowledgements,
    )
    if result.digest != delta.target_manifest_digest and not allow_rebase:
        raise ManifestError("Delta target digest does not match the resulting manifest")
    return result


def encrypt_catalog_record(plaintext: bytes, key: bytes, *, record_id: str,
                           aad: bytes = b"") -> bytes:
    """Local-session helper; transport accepts only the returned opaque bytes."""

    if not isinstance(plaintext, bytes) or len(plaintext) > MAX_RECORD_CIPHERTEXT - 28:
        raise ManifestError("Catalog record plaintext is outside the bound")
    if not isinstance(key, bytes) or len(key) != 32:
        raise ManifestError("Catalog record key must be 32 bytes")
    record_id = _id(record_id, "record id")
    header = CATALOG_AAD + record_id.encode("utf-8") + bytes(aad)
    if len(header) > 4096:
        raise ManifestError("Catalog record associated data is too large")
    nonce = secrets.token_bytes(12)
    return b"LGKSYNC1" + nonce + AESGCM(key).encrypt(nonce, plaintext, header)


def decrypt_catalog_record(ciphertext: bytes, key: bytes, *, record_id: str,
                           aad: bytes = b"") -> bytes:
    if not isinstance(ciphertext, bytes) or len(ciphertext) < 8 + 12 + 16:
        raise ManifestError("Catalog record ciphertext is malformed")
    if not isinstance(key, bytes) or len(key) != 32:
        raise ManifestError("Catalog record key must be 32 bytes")
    if ciphertext[:8] != b"LGKSYNC1":
        raise ManifestError("Catalog record ciphertext has an invalid envelope")
    record_id = _id(record_id, "record id")
    header = CATALOG_AAD + record_id.encode("utf-8") + bytes(aad)
    try:
        return AESGCM(key).decrypt(ciphertext[8:20], ciphertext[20:], header)
    except (InvalidTag, ValueError):
        raise ManifestError("Catalog record authentication failed") from None


__all__ = [
    "Revision", "SyncRecord", "AttachmentMeta", "AttachmentDelta", "Acknowledgement",
    "Manifest", "SyncDelta", "ManifestError", "ManifestReplayError", "build_manifest",
    "make_attachment_delta", "apply_delta", "encrypt_catalog_record", "decrypt_catalog_record",
    "MAX_RECORDS", "MAX_ATTACHMENTS", "MAX_MANIFEST_BYTES", "MAX_DELTA_BYTES",
    "MAX_ATTACHMENT_CIPHERTEXT", "MAX_BATCH_BYTES",
]
