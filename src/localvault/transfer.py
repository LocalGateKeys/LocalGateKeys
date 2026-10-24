"""Bounded, password-protected selective transfer packages.

Transfer packages are deliberately separate from full profile backups.  The
public envelope contains only a reviewable metadata manifest.  Catalog records
and attachment bytes are authenticated by a second, user-selected password
and are never written as plaintext staging files.
"""
from __future__ import annotations

import base64
import copy
import hashlib
import json
import os
import secrets
import tempfile
import time
import uuid
from collections.abc import Callable, Iterable, Mapping
from contextlib import contextmanager
from pathlib import Path
from typing import Any

from argon2.low_level import Type, hash_secret_raw
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .vault import DEFAULT_KDF, MAX_KDF_MEMORY_KIB, MIN_KDF_MEMORY_KIB, free_item_slots

TRANSFER_FORMAT = "localgatekeys-selective-transfer"
TRANSFER_VERSION = 1
TRANSFER_AAD = b"localgatekeys|selective-transfer|v1"
# New packages use the vault's default Argon2id profile.  Readers accept any
# header inside the vault's bounded range (the header is part of the AAD).
TRANSFER_KDF = {
    "name": "argon2id",
    "time_cost": int(DEFAULT_KDF["time_cost"]),
    "memory_cost_kib": int(DEFAULT_KDF["memory_cost_kib"]),
    "parallelism": int(DEFAULT_KDF["parallelism"]),
    "hash_len": 32,
}
MIN_TRANSFER_KDF_TIME_COST, MAX_TRANSFER_KDF_TIME_COST = 1, 10
MIN_TRANSFER_KDF_PARALLELISM, MAX_TRANSFER_KDF_PARALLELISM = 1, 16
_TRANSFER_KDF_FIELDS = ("time_cost", "memory_cost_kib", "parallelism")

# The limits intentionally match the implementation plan's one-batch bound.
MAX_TRANSFER_BYTES = 250 * 1024 * 1024
MAX_TRANSFER_FILES = 500
MAX_TRANSFER_ITEMS = 20_000
MAX_TRANSFER_MANIFEST_BYTES = 4 * 1024 * 1024
MAX_TRANSFER_PACKAGE_BYTES = 512 * 1024 * 1024
MAX_TRANSFER_PLAINTEXT_BYTES = MAX_TRANSFER_BYTES * 2
MAX_TRANSFER_PASSWORD_LENGTH = 4096
MIN_TRANSFER_PASSWORD_LENGTH = 12


class TransferError(Exception):
    """A transfer package or transfer operation is invalid."""


class TransferCancelled(TransferError):
    """The caller cancelled a transfer before it was published/committed."""


class TransferConflictError(TransferError):
    """An import conflict or stale revision prevented a safe commit."""


def _canonical(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode("utf-8")


def _b64e(value: bytes) -> str:
    return base64.b64encode(value).decode("ascii")


def _b64d(value: Any, label: str) -> bytes:
    if not isinstance(value, str):
        raise TransferError(f"{label} is malformed")
    try:
        return base64.b64decode(value.encode("ascii"), validate=True)
    except Exception as exc:
        raise TransferError(f"{label} is malformed") from exc


def _check_cancel(cancel: Callable[[], bool] | Any | None) -> None:
    if cancel is None:
        return
    try:
        value = cancel.is_set() if hasattr(cancel, "is_set") else (cancel() if callable(cancel) else bool(cancel))
    except Exception as exc:
        raise TransferCancelled("Transfer operation was cancelled") from exc
    if value:
        raise TransferCancelled("Transfer operation was cancelled")


def _kdf_parameters(kdf: Any) -> dict[str, int | str]:
    """Bound Argon2id parameters before any derivation runs (fail closed)."""
    if not isinstance(kdf, dict) or kdf.get("name") != "argon2id" or kdf.get("hash_len") != 32:
        raise TransferError("Unsupported transfer KDF parameters")
    values: dict[str, int | str] = {"name": "argon2id", "hash_len": 32}
    for field in _TRANSFER_KDF_FIELDS:
        value = kdf.get(field)
        if type(value) is not int:
            raise TransferError("Unsupported transfer KDF parameters")
        values[field] = value
    if not (MIN_TRANSFER_KDF_TIME_COST <= int(values["time_cost"]) <= MAX_TRANSFER_KDF_TIME_COST
            and MIN_KDF_MEMORY_KIB <= int(values["memory_cost_kib"]) <= MAX_KDF_MEMORY_KIB
            and MIN_TRANSFER_KDF_PARALLELISM <= int(values["parallelism"]) <= MAX_TRANSFER_KDF_PARALLELISM):
        raise TransferError("Unsupported transfer KDF parameters")
    return values


def _new_kdf(kdf_overrides: Mapping[str, int] | None) -> dict[str, int | str]:
    kdf: dict[str, Any] = dict(TRANSFER_KDF)
    if kdf_overrides:
        for field in _TRANSFER_KDF_FIELDS:
            if field in kdf_overrides:
                kdf[field] = kdf_overrides[field]
    return _kdf_parameters(kdf)


def _derive_key(password: str, salt: bytes, kdf: Mapping[str, Any]) -> bytes:
    if not isinstance(password, str) or not MIN_TRANSFER_PASSWORD_LENGTH <= len(password) <= MAX_TRANSFER_PASSWORD_LENGTH:
        raise TransferError(f"Transfer password must contain at least {MIN_TRANSFER_PASSWORD_LENGTH} characters")
    if len(salt) != 16:
        raise TransferError("Transfer KDF salt is malformed")
    parameters = _kdf_parameters(kdf)
    return hash_secret_raw(
        secret=password.encode("utf-8"),
        salt=salt,
        time_cost=int(parameters["time_cost"]),
        memory_cost=int(parameters["memory_cost_kib"]),
        parallelism=int(parameters["parallelism"]),
        hash_len=32,
        type=Type.ID,
    )


def _header_aad(envelope: Mapping[str, Any]) -> bytes:
    return TRANSFER_AAD + _canonical({
        "format": envelope["format"],
        "version": envelope["version"],
        "manifest": envelope["manifest"],
        "kdf": envelope["kdf"],
        "cipher": {"name": envelope["cipher"]["name"], "nonce": envelope["cipher"]["nonce"]},
    })


def _uuid(value: Any, label: str) -> str:
    try:
        return str(uuid.UUID(str(value)))
    except (ValueError, TypeError, AttributeError):
        raise TransferError(f"{label} is malformed") from None


def _selection_values(values: Iterable[str] | str | None, label: str) -> list[str] | None:
    if values is None:
        return None
    if isinstance(values, str):
        values = [values]
    try:
        result = [str(value) for value in values]
    except TypeError as exc:
        raise TransferError(f"{label} must be a sequence") from exc
    if len(result) != len(set(result)):
        raise TransferError(f"{label} contains duplicate IDs")
    return result


def _regular_read(path: Path, *, limit: int, label: str, cancel: Any = None) -> bytes:
    path = Path(path)
    if path.is_symlink() or not path.is_file():
        raise TransferError(f"{label} must be a regular file")
    try:
        initial = path.stat()
        if initial.st_size > limit:
            raise TransferError(f"{label} exceeds the transfer bound")
        chunks: list[bytes] = []
        total = 0
        with path.open("rb") as handle:
            while True:
                _check_cancel(cancel)
                chunk = handle.read(1024 * 1024)
                if not chunk:
                    break
                total += len(chunk)
                if total > limit:
                    raise TransferError(f"{label} exceeds the transfer bound")
                chunks.append(chunk)
        final = path.stat()
        if final.st_size != initial.st_size or final.st_mtime_ns != initial.st_mtime_ns:
            raise TransferError(f"{label} changed while it was being read")
        return b"".join(chunks)
    except TransferError:
        raise
    except OSError as exc:
        raise TransferError(f"Could not read {label}") from exc


def _read_package(source: Path) -> dict[str, Any]:
    raw = _regular_read(Path(source), limit=MAX_TRANSFER_PACKAGE_BYTES, label="transfer package")
    try:
        # Strict UTF-8 first: json.loads(bytes) would accept lone surrogates
        # that _canonical() later cannot re-encode.
        envelope = json.loads(raw.decode("utf-8"))
    except (TypeError, ValueError, json.JSONDecodeError, RecursionError) as exc:
        raise TransferError("Transfer package is not valid JSON") from exc
    if not isinstance(envelope, dict):
        raise TransferError("Transfer package header must be an object")
    if envelope.get("format") != TRANSFER_FORMAT or envelope.get("version") != TRANSFER_VERSION:
        raise TransferError("Unsupported transfer package format")
    manifest = envelope.get("manifest")
    if not isinstance(manifest, dict) or len(_canonical(manifest)) > MAX_TRANSFER_MANIFEST_BYTES:
        raise TransferError("Transfer manifest is malformed or too large")
    kdf = envelope.get("kdf")
    cipher = envelope.get("cipher")
    if not isinstance(kdf, dict) or not isinstance(cipher, dict):
        raise TransferError("Transfer encryption header is malformed")
    _kdf_parameters(kdf)
    salt = _b64d(kdf.get("salt"), "Transfer KDF salt")
    nonce = _b64d(cipher.get("nonce"), "Transfer nonce")
    if len(salt) != 16 or len(nonce) != 12 or cipher.get("name") != "aes-256-gcm":
        raise TransferError("Malformed transfer encryption header")
    ciphertext = _b64d(cipher.get("ciphertext"), "Transfer ciphertext")
    if not ciphertext or len(ciphertext) > MAX_TRANSFER_PLAINTEXT_BYTES + 16:
        raise TransferError("Transfer ciphertext exceeds the bound")
    return envelope


def inspect_transfer(source: Path) -> dict[str, Any]:
    """Return the unauthenticated-but-safe public manifest for review.

    The manifest contains no usernames, URLs, credential values, typed payloads,
    attachment keys, or attachment bytes.  Password verification happens when
    :func:`import_transfer` or :func:`preview_transfer` decrypts the package.
    """
    envelope = _read_package(source)
    return copy.deepcopy(envelope["manifest"])


read_transfer_manifest = inspect_transfer


def _payload_for(session: Any) -> dict[str, Any]:
    try:
        payload = session._require_typed_catalog()
    except AttributeError:
        payload = session._require_payload()
    except Exception as exc:
        raise TransferError("A versioned typed vault is required for transfer") from exc
    if not isinstance(payload, dict):
        raise TransferError("Vault catalog is malformed")
    return payload


def _entries_for(session: Any, payload: Mapping[str, Any]) -> list[dict[str, Any]]:
    getter = getattr(session, "all_entries", None)
    if callable(getter):
        entries = getter()
    else:
        entries = payload.get("entries", [])
    if not isinstance(entries, list):
        raise TransferError("Vault credentials are malformed")
    return [copy.deepcopy(value) for value in entries]


def _attachment_records(payload: Mapping[str, Any]) -> list[dict[str, Any]]:
    from .item_schema import validate_attachment_records

    try:
        return validate_attachment_records(payload.get("attachments", []))
    except Exception as exc:
        raise TransferError("Vault attachment catalog is malformed") from exc


# Desktop scope keys that record trust granted on one PC (fill/sign-in
# approvals, pairing state).  They never leave the device: transfer drops them
# and device sync keeps each device's own values.
LOCAL_TRUST_SCOPE_KEYS = (
    "sign_in_selector", "embedded_web_fill_approved", "browser_approval",
    "browser_approvals", "sync_pairing", "pairing_secret", "pairing_state",
)


def _sanitize_credential(entry: Mapping[str, Any]) -> dict[str, Any]:
    """Keep a selected credential, but never transfer local trust approvals."""
    result = copy.deepcopy(dict(entry))
    kind = result.get("kind")
    if kind not in {"web", "desktop"}:
        raise TransferError("Only web and desktop credentials can be transferred")
    policy = result.get("policy")
    if not isinstance(policy, dict):
        policy = {}
    # Imported credentials may fill only after the recipient's local review.
    policy = {"fill": policy.get("fill", "click"),
              "sign_in": "never",
              "require_master_password": policy.get("require_master_password", False),
              "save_prompts": policy.get("save_prompts", True)}
    result["policy"] = policy
    if kind == "desktop":
        scope = result.get("scope")
        if not isinstance(scope, dict):
            raise TransferError("Desktop credential scope is malformed")
        for key in LOCAL_TRUST_SCOPE_KEYS:
            scope.pop(key, None)
    return result


def _validate_credential(entry: Mapping[str, Any]) -> dict[str, Any]:
    from .vault import _validate_legacy_payload

    candidate = copy.deepcopy(dict(entry))
    try:
        checked = _validate_legacy_payload({"version": 1, "entries": [candidate], "trash": []},
                                           strict_origins=True)
    except Exception as exc:
        raise TransferError("Transfer credential is malformed") from exc
    return copy.deepcopy(checked["entries"][0])


def _attachment_id_from_item(item: Mapping[str, Any]) -> set[str]:
    typed = item.get("payload")
    if not isinstance(typed, dict):
        return set()
    result: set[str] = set()
    if item.get("kind") == "document" and typed.get("attachment_id") is not None:
        result.add(_uuid(typed["attachment_id"], "attachment reference"))
    return result


def _document_refs(item: Mapping[str, Any]) -> set[str]:
    typed = item.get("payload")
    if not isinstance(typed, dict):
        return set()
    refs = typed.get("document_ids", [])
    if refs is None:
        return set()
    if not isinstance(refs, list):
        raise TransferError("Document references are malformed")
    return {_uuid(value, "document reference") for value in refs}


def _source_attachment_bytes(session: Any, attachment_id: str, cancel: Any) -> bytes:
    store = getattr(session, "attachments", None)
    if store is None:
        store = getattr(session, "attachment_store", None)
    if store is None:
        from .attachments import AttachmentStore
        store = AttachmentStore(session)
    reader = getattr(store, "read_bytes", None)
    if not callable(reader):
        raise TransferError("The vault has no attachment reader")
    try:
        try:
            return reader(attachment_id, cancel=cancel)
        except TypeError:
            return reader(attachment_id)
    except Exception as exc:
        _check_cancel(cancel)
        raise TransferError("Referenced attachment could not be authenticated") from exc


def _select_records(
    session: Any,
    *,
    ids: Iterable[str] | str | None,
    item_ids: Iterable[str] | str | None,
    credential_ids: Iterable[str] | str | None,
    kinds: Iterable[str] | str | None,
    tags: Iterable[str] | str | None,
    collection_ids: Iterable[str] | str | None,
    favorite: bool | None,
    exclude_ids: Iterable[str] | str | None,
    include_attachments: bool,
    attachment_ids: Iterable[str] | str | None,
    cancel: Any,
) -> tuple[dict[str, Any], dict[str, Any]]:
    _check_cancel(cancel)
    payload = _payload_for(session)
    raw_items = payload.get("items", [])
    if not isinstance(raw_items, list):
        raise TransferError("Vault items are malformed")
    from .item_schema import validate_collections, validate_item

    try:
        collections = validate_collections(payload.get("collections", []))
        typed_items = [validate_item(copy.deepcopy(item), known_collection_ids={row["id"] for row in collections})
                       for item in raw_items]
    except Exception as exc:
        raise TransferError("Vault typed catalog is malformed") from exc
    entries = [_validate_credential(value) for value in _entries_for(session, payload)]
    all_by_id: dict[str, tuple[str, dict[str, Any]]] = {}
    for item in typed_items:
        item_id = item["id"]
        if item_id in all_by_id:
            raise TransferError("Vault contains duplicate stable IDs")
        all_by_id[item_id] = ("item", item)
    for entry in entries:
        entry_id = str(entry.get("id", ""))
        if not entry_id or entry_id in all_by_id:
            raise TransferError("Vault contains duplicate stable IDs")
        all_by_id[entry_id] = ("credential", entry)

    requested = []
    for values in (ids, item_ids, credential_ids):
        selected = _selection_values(values, "selected IDs")
        if selected:
            requested.extend(selected)
    requested_set = set(requested)
    excluded = set(_selection_values(exclude_ids, "excluded IDs") or [])
    wanted_kinds = set(_selection_values(kinds, "type selection") or [])
    wanted_tags = {value.strip().casefold() for value in (_selection_values(tags, "tag selection") or [])}
    if "" in wanted_tags:
        raise TransferError("Tag selection contains an empty tag")
    wanted_collections = set(_selection_values(collection_ids, "collection selection") or [])
    if favorite is not None and type(favorite) is not bool:
        raise TransferError("Favorite selection must be a boolean")
    explicit = bool(requested_set or wanted_kinds or wanted_tags or wanted_collections or favorite is not None)
    if not explicit:
        raise TransferError("An explicit item, credential, type, or collection selection is required")
    unknown = requested_set - set(all_by_id)
    if unknown:
        raise TransferError("Selection contains an unknown stable ID")
    if wanted_kinds and any(kind not in {"web", "desktop", "note", "bookmark", "document", "license", "purchase", "warranty", "subscription"} for kind in wanted_kinds):
        if "identity" in wanted_kinds:
            raise TransferError("Identity items are not transferable")
        raise TransferError("Selection contains an unsupported item type")
    for values, expected_kind in ((item_ids, "item"), (credential_ids, "credential")):
        for selected_id in _selection_values(values, "selected IDs") or []:
            if all_by_id[selected_id][0] != expected_kind:
                raise TransferError("Selection ID does not match its selector")

    selected_items: list[dict[str, Any]] = []
    selected_entries: list[dict[str, Any]] = []
    for record_id, (record_kind, record) in all_by_id.items():
        matches = record_id in requested_set
        if wanted_kinds and record.get("kind") in wanted_kinds:
            matches = True
        record_tags = record.get("tags", [])
        if wanted_tags and isinstance(record_tags, list):
            normalized_tags = {str(value).strip().casefold() for value in record_tags}
            if wanted_tags.issubset(normalized_tags):
                matches = True
            elif record_id not in requested_set and not (wanted_kinds and record.get("kind") in wanted_kinds):
                matches = False
        if wanted_collections and record_kind == "item" and wanted_collections.intersection(record.get("collection_ids", [])):
            matches = True
        if favorite is not None:
            if bool(record.get("favorite", False)) != favorite:
                matches = False
            elif not (record_id in requested_set or wanted_kinds or wanted_tags or wanted_collections):
                matches = True
        if matches and record_id not in excluded:
            if record_kind == "item":
                if record.get("kind") == "identity":
                    raise TransferError("Identity items are not transferable")
                selected_items.append(copy.deepcopy(record))
            else:
                selected_entries.append(_sanitize_credential(record))
    if not selected_items and not selected_entries:
        raise TransferError("Selection contains no transferable records")

    selected_item_ids = {item["id"] for item in selected_items}
    for item in selected_items:
        missing = _document_refs(item) - selected_item_ids
        if missing:
            raise TransferError("Select every referenced document before transferring an item")

    records_by_id = {row["id"]: row for row in _attachment_records(payload)}
    needed_attachment_ids: set[str] = set()
    for item in selected_items:
        needed_attachment_ids.update(_attachment_id_from_item(item))
    requested_attachment_ids = set(_selection_values(attachment_ids, "attachment selection") or [])
    for value in requested_attachment_ids:
        _uuid(value, "attachment selection")
    if not include_attachments and needed_attachment_ids:
        raise TransferError("Selected records reference attachments; enable include_attachments")
    if requested_attachment_ids and not needed_attachment_ids.issubset(requested_attachment_ids):
        raise TransferError("Attachment selection omits a referenced attachment")
    if not needed_attachment_ids.issubset(records_by_id):
        raise TransferError("A selected document references an unknown attachment")
    if len(needed_attachment_ids) > MAX_TRANSFER_FILES:
        raise TransferError("The transfer attachment count exceeds the bound")

    attachments: list[dict[str, Any]] = []
    raw_total = 0
    for attachment_id in sorted(needed_attachment_ids):
        _check_cancel(cancel)
        record = copy.deepcopy(records_by_id[attachment_id])
        data = _source_attachment_bytes(session, attachment_id, cancel)
        if len(data) != record["size"] or hashlib.sha256(data).hexdigest() != record["sha256"]:
            raise TransferError("Referenced attachment integrity metadata does not match")
        raw_total += len(data)
        if raw_total > MAX_TRANSFER_BYTES:
            raise TransferError("Transfer attachment bytes exceed the bound")
        attachments.append({
            "record": {key: record[key] for key in ("id", "name", "mime_type", "size", "sha256")},
            "data": _b64e(data),
        })

    referenced_collections = {value for item in selected_items for value in item.get("collection_ids", [])}
    collection_by_id = {row["id"]: row for row in collections}
    if not referenced_collections.issubset(collection_by_id):
        raise TransferError("A selected item references an unknown collection")
    selected_collections = [copy.deepcopy(collection_by_id[value]) for value in sorted(referenced_collections)]
    manifest_items = [
        {"id": item["id"], "kind": item["kind"], "title": item["title"],
         "revision": item["revision"], "collection_ids": list(item.get("collection_ids", []))}
        for item in selected_items
    ]
    manifest_credentials = [
        {"id": entry["id"], "kind": entry["kind"], "label": entry["label"],
         "updated_at": int(entry.get("updated_at", 0))}
        for entry in selected_entries
    ]
    manifest_attachments = [
        {"id": row["record"]["id"], "name": row["record"]["name"],
         "mime_type": row["record"]["mime_type"], "size": row["record"]["size"],
         "sha256": row["record"]["sha256"]}
        for row in attachments
    ]
    manifest = {
        "manifest_version": TRANSFER_VERSION,
        "created_at": int(time.time()),
        "item_count": len(manifest_items),
        "credential_count": len(manifest_credentials),
        "attachment_count": len(manifest_attachments),
        "attachment_bytes": raw_total,
        "items": manifest_items,
        "credentials": manifest_credentials,
        "collections": [
            {"id": row["id"], "name": row["name"], "revision": row["revision"]}
            for row in selected_collections
        ],
        "attachments": manifest_attachments,
    }
    if len(_canonical(manifest)) > MAX_TRANSFER_MANIFEST_BYTES:
        raise TransferError("Transfer manifest is too large")
    payload_out = {
        "version": TRANSFER_VERSION,
        "items": selected_items,
        "credentials": selected_entries,
        "collections": selected_collections,
        "attachments": attachments,
    }
    if len(_canonical(payload_out)) > MAX_TRANSFER_PLAINTEXT_BYTES:
        raise TransferError("Transfer plaintext exceeds the bound")
    return manifest, payload_out


def _build_envelope(manifest: dict[str, Any], payload: dict[str, Any], password: str,
                    kdf_overrides: Mapping[str, int] | None = None) -> dict[str, Any]:
    salt = os.urandom(16)
    nonce = os.urandom(12)
    kdf = _new_kdf(kdf_overrides)
    envelope: dict[str, Any] = {
        "format": TRANSFER_FORMAT,
        "version": TRANSFER_VERSION,
        "manifest": manifest,
        "kdf": {**kdf, "salt": _b64e(salt)},
        "cipher": {"name": "aes-256-gcm", "nonce": _b64e(nonce)},
    }
    encrypted = AESGCM(_derive_key(password, salt, kdf)).encrypt(nonce, _canonical(payload), _header_aad(envelope))
    envelope["cipher"]["ciphertext"] = _b64e(encrypted)
    if len(_canonical(envelope)) > MAX_TRANSFER_PACKAGE_BYTES:
        raise TransferError("Transfer package exceeds the encoded size bound")
    return envelope


def _atomic_package_write(destination: Path, envelope: dict[str, Any], *, overwrite: bool) -> None:
    destination = Path(destination)
    if destination.exists() and not overwrite:
        raise TransferError("Transfer destination already exists")
    destination.parent.mkdir(parents=True, exist_ok=True)
    # The only temporary file is the encrypted JSON envelope, never a
    # decrypted catalog or plaintext attachment.
    fd, name = tempfile.mkstemp(prefix=".lgk-transfer-", suffix=".tmp", dir=destination.parent)
    temporary = Path(name)
    try:
        encoded = _canonical(envelope)
        with os.fdopen(fd, "wb") as handle:
            handle.write(encoded)
            handle.flush()
            os.fsync(handle.fileno())
        if destination.exists() and not overwrite:
            raise TransferError("Transfer destination already exists")
        os.replace(temporary, destination)
    except TransferError:
        temporary.unlink(missing_ok=True)
        raise
    except OSError as exc:
        temporary.unlink(missing_ok=True)
        raise TransferError("Could not publish transfer package") from exc


def export_selective_transfer(
    session: Any = None,
    destination: Path | None = None,
    transfer_password: str | None = None,
    *,
    password: str | None = None,
    ids: Iterable[str] | str | None = None,
    item_ids: Iterable[str] | str | None = None,
    credential_ids: Iterable[str] | str | None = None,
    kinds: Iterable[str] | str | None = None,
    types: Iterable[str] | str | None = None,
    tags: Iterable[str] | str | None = None,
    tag: str | None = None,
    collection_ids: Iterable[str] | str | None = None,
    favorite: bool | None = None,
    favorite_only: bool | None = None,
    exclude_ids: Iterable[str] | str | None = None,
    attachment_ids: Iterable[str] | str | None = None,
    include_attachments: bool = True,
    cancel: Any = None,
    overwrite: bool = False,
    kdf_overrides: Mapping[str, int] | None = None,
) -> dict[str, Any]:
    """Create a selective transfer package and return its safe manifest.

    ``session`` and ``destination`` may be supplied in either order for
    compatibility with callers that use the backup module's destination-first
    convention.
    """
    if isinstance(session, (str, Path)) and not isinstance(destination, (str, Path)):
        session, destination = destination, Path(session)
    if destination is None or session is None:
        raise TransferError("A destination and unlocked vault session are required")
    transfer_password = transfer_password or password
    if transfer_password is None:
        raise TransferError("A transfer password is required")
    if types is not None:
        if kinds is not None:
            raise TransferError("Specify only one type selector")
        kinds = types
    if tag is not None:
        if tags is not None:
            raise TransferError("Specify only one tag selector")
        tags = tag
    if favorite_only is not None:
        if favorite is not None and favorite != favorite_only:
            raise TransferError("Specify only one favorite selector")
        favorite = favorite_only
    manifest, payload = _select_records(
        session, ids=ids, item_ids=item_ids, credential_ids=credential_ids,
        kinds=kinds, tags=tags, collection_ids=collection_ids, favorite=favorite,
        exclude_ids=exclude_ids,
        include_attachments=include_attachments, attachment_ids=attachment_ids,
        cancel=cancel,
    )
    _check_cancel(cancel)
    envelope = _build_envelope(manifest, payload, transfer_password, kdf_overrides)
    _check_cancel(cancel)
    _atomic_package_write(Path(destination), envelope, overwrite=overwrite)
    return copy.deepcopy(manifest)


export_transfer = export_selective_transfer


def preview_selective_transfer(
    session: Any = None,
    *,
    ids: Iterable[str] | str | None = None,
    item_ids: Iterable[str] | str | None = None,
    credential_ids: Iterable[str] | str | None = None,
    kinds: Iterable[str] | str | None = None,
    types: Iterable[str] | str | None = None,
    tags: Iterable[str] | str | None = None,
    tag: str | None = None,
    collection_ids: Iterable[str] | str | None = None,
    favorite: bool | None = None,
    favorite_only: bool | None = None,
    exclude_ids: Iterable[str] | str | None = None,
    attachment_ids: Iterable[str] | str | None = None,
    include_attachments: bool = True,
    cancel: Any = None,
) -> dict[str, Any]:
    """Build the safe export manifest without writing a package.

    This is the UI dry-run seam.  It deliberately performs the same selection,
    validation, attachment authentication, and bounds checks as export, but it
    never derives a transfer key or creates a destination file.
    """
    if session is None:
        raise TransferError("An unlocked vault session is required")
    if types is not None:
        if kinds is not None:
            raise TransferError("Specify only one type selector")
        kinds = types
    if tag is not None:
        if tags is not None:
            raise TransferError("Specify only one tag selector")
        tags = tag
    if favorite_only is not None:
        if favorite is not None and favorite != favorite_only:
            raise TransferError("Specify only one favorite selector")
        favorite = favorite_only
    manifest, _payload = _select_records(
        session, ids=ids, item_ids=item_ids, credential_ids=credential_ids,
        kinds=kinds, tags=tags, collection_ids=collection_ids, favorite=favorite,
        exclude_ids=exclude_ids, include_attachments=include_attachments,
        attachment_ids=attachment_ids, cancel=cancel,
    )
    return copy.deepcopy(manifest)


preview_transfer_export = preview_selective_transfer


def _decrypt_payload(envelope: dict[str, Any], password: str) -> dict[str, Any]:
    salt = _b64d(envelope["kdf"]["salt"], "Transfer KDF salt")
    nonce = _b64d(envelope["cipher"]["nonce"], "Transfer nonce")
    ciphertext = _b64d(envelope["cipher"]["ciphertext"], "Transfer ciphertext")
    try:
        raw = AESGCM(_derive_key(password, salt, envelope["kdf"])).decrypt(nonce, ciphertext, _header_aad(envelope))
    except (InvalidTag, TransferError):
        raise TransferError("Wrong transfer password or modified transfer package") from None
    if len(raw) > MAX_TRANSFER_PLAINTEXT_BYTES:
        raise TransferError("Transfer plaintext exceeds the bound")
    try:
        payload = json.loads(raw.decode("utf-8"))
    except (TypeError, ValueError, json.JSONDecodeError, RecursionError):
        raise TransferError("Transfer payload is malformed") from None
    if not isinstance(payload, dict) or payload.get("version") != TRANSFER_VERSION:
        raise TransferError("Unsupported transfer payload version")
    return payload


def _validate_package_payload(envelope: dict[str, Any], payload: dict[str, Any]) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]], dict[str, dict[str, Any]]]:
    manifest = envelope["manifest"]
    raw_items = payload.get("items")
    raw_credentials = payload.get("credentials")
    raw_collections = payload.get("collections")
    raw_attachments = payload.get("attachments")
    if not all(isinstance(value, list) for value in (raw_items, raw_credentials, raw_collections, raw_attachments)):
        raise TransferError("Transfer payload collections are malformed")
    if len(raw_items) + len(raw_credentials) > MAX_TRANSFER_ITEMS or len(raw_attachments) > MAX_TRANSFER_FILES:
        raise TransferError("Transfer record count exceeds the bound")
    from .item_schema import validate_collections, validate_item

    try:
        collections = validate_collections(copy.deepcopy(raw_collections))
    except Exception as exc:
        raise TransferError("Transfer collections are malformed") from exc
    collection_ids = {row["id"] for row in collections}
    items: list[dict[str, Any]] = []
    ids: set[str] = set()
    for raw in raw_items:
        try:
            item = validate_item(copy.deepcopy(raw), known_collection_ids=collection_ids)
        except Exception as exc:
            raise TransferError("Transfer typed item is malformed") from exc
        if item["kind"] == "identity":
            raise TransferError("Identity items are not transferable")
        if item["id"] in ids:
            raise TransferError("Transfer contains duplicate stable IDs")
        ids.add(item["id"])
        items.append(item)
    credentials: list[dict[str, Any]] = []
    for raw in raw_credentials:
        entry = _sanitize_credential(raw)
        entry = _validate_credential(entry)
        if entry["id"] in ids:
            raise TransferError("Transfer contains duplicate stable IDs")
        ids.add(entry["id"])
        credentials.append(entry)
    attachments: dict[str, dict[str, Any]] = {}
    attachment_records: dict[str, dict[str, Any]] = {}
    manifest_attachment_ids = {row.get("id") for row in manifest.get("attachments", []) if isinstance(row, dict)}
    for row in raw_attachments:
        if not isinstance(row, dict) or set(row) != {"record", "data"} or not isinstance(row["record"], dict):
            raise TransferError("Transfer attachment is malformed")
        record = row["record"]
        allowed = {"id", "name", "mime_type", "size", "sha256"}
        if set(record) != allowed:
            raise TransferError("Transfer attachment metadata is malformed")
        attachment_id = _uuid(record.get("id"), "attachment ID")
        if attachment_id in attachments:
            raise TransferError("Transfer contains duplicate attachment IDs")
        name = record.get("name")
        if isinstance(name, str):
            from .attachments import strip_format_controls

            name = strip_format_controls(name)  # bidi overrides would disguise the file type
        mime_type = record.get("mime_type")
        size = record.get("size")
        digest = record.get("sha256")
        if not isinstance(name, str) or not name or len(name) > 512 or name in {".", ".."} or "/" in name or "\\" in name or "\x00" in name or any(ord(c) < 32 for c in name):
            raise TransferError("Transfer attachment name is unsafe")
        if not isinstance(mime_type, str) or not mime_type or len(mime_type) > 255:
            raise TransferError("Transfer attachment MIME type is malformed")
        if type(size) is not int or not 0 <= size <= 25 * 1024 * 1024:
            raise TransferError("Transfer attachment size is outside the accepted bound")
        if not isinstance(digest, str) or len(digest) != 64 or any(c not in "0123456789abcdefABCDEF" for c in digest):
            raise TransferError("Transfer attachment digest is malformed")
        data = _b64d(row["data"], "Transfer attachment data")
        if len(data) != size or hashlib.sha256(data).hexdigest() != digest.lower():
            raise TransferError("Transfer attachment integrity check failed")
        attachment_records[attachment_id] = {
            "id": attachment_id, "name": name, "mime_type": mime_type,
            "size": size, "sha256": digest.lower(),
        }
        attachments[attachment_id] = {"record": attachment_records[attachment_id], "data": data}
    if not set(attachments).issubset(manifest_attachment_ids):
        raise TransferError("Transfer attachment manifest is inconsistent")
    if len(attachments) != manifest.get("attachment_count") or sum(len(row["data"]) for row in attachments.values()) != manifest.get("attachment_bytes"):
        raise TransferError("Transfer attachment bounds are inconsistent")
    for item in items:
        for attachment_id in _attachment_id_from_item(item):
            if attachment_id not in attachments:
                raise TransferError("Transfer item references a missing attachment")
        for document_id in _document_refs(item):
            if document_id not in {candidate["id"] for candidate in items}:
                raise TransferError("Transfer item references an unknown document")
    if manifest.get("item_count") != len(items) or manifest.get("credential_count") != len(credentials):
        raise TransferError("Transfer manifest counts are inconsistent")
    return items, credentials, collections, attachments


def _target_state(session: Any) -> tuple[dict[str, Any], list[dict[str, Any]], list[dict[str, Any]]]:
    payload = _payload_for(session)
    items = payload.get("items", [])
    entries = _entries_for(session, payload)
    if not isinstance(items, list) or not isinstance(entries, list):
        raise TransferError("Destination catalog is malformed")
    return payload, items, entries


def _new_uuid(existing: set[str]) -> str:
    value = str(uuid.uuid4())
    while value in existing:
        value = str(uuid.uuid4())
    return value


# Plan actions that write nothing.  "limit" marks a new record left out because
# the free plan has no slot for it (an update to an existing record never is).
_NOT_WRITTEN = frozenset({"skip", "limit"})
_NEW_RECORD = frozenset({"import", "copy"})


def _takes_slot(record_id: str, action: str | None, revived: frozenset[str] | set[str]) -> bool:
    return action in _NEW_RECORD or (action == "replace" and record_id in revived)


def _trash_by_id(payload: Mapping[str, Any]) -> dict[str, dict[str, Any]]:
    """Deleted records by id. Their ids stay reserved: restore and purge find rows by id."""
    rows = payload.get("trash", [])
    out: dict[str, dict[str, Any]] = {}
    if not isinstance(rows, list):
        return out
    for row in rows:
        entry = row.get("entry") if isinstance(row, dict) else None
        if isinstance(entry, dict) and entry.get("id") is not None:
            out[str(entry["id"])] = entry
    return out


def _apply_item_limit(
    session: Any,
    incoming: list[tuple[str, dict[str, Any]]],
    actions: dict[str, str],
    id_map: dict[str, str | None],
    revived: frozenset[str] | set[str] = frozenset(),
) -> int | None:
    """Turn new records beyond the free slots left into "limit", in plan order.

    A new item counts together with the new documents it references, so a
    purchase is never written pointing at a document that was left out.
    A "replace" of a record in the trash (``revived``) brings it back as a
    live record, so it takes a slot like a new one.
    Returns the free slots before this import (``None`` when unlimited).
    """
    slots = free_item_slots(session)
    if slots is None:
        return None
    remaining = slots
    admitted: set[str] = set()
    for kind, record in incoming:
        record_id = record["id"]
        action = actions[record_id]
        if action in _NOT_WRITTEN or record_id in admitted:
            continue
        refs = _document_refs(record) if kind == "item" else set()
        if any(actions.get(ref) == "limit" for ref in refs):
            needed = None
        else:
            needed = [record_id] if _takes_slot(record_id, action, revived) else []
            needed += sorted(
                ref for ref in refs
                if _takes_slot(ref, actions.get(ref), revived) and ref not in admitted and ref != record_id
            )
        if needed is not None and len(needed) <= remaining:
            admitted.update(needed)
            remaining -= len(needed)
            continue
        actions[record_id] = "limit"
        id_map[record_id] = None
    return slots


def _feature_allowed(session: Any, feature: str) -> bool:
    allowed = getattr(session, "pro_features", None)
    return allowed is None or feature in allowed


def _apply_feature_limits(session: Any, items: list[dict[str, Any]], actions: dict[str, str],
                          id_map: dict[str, str | None]) -> None:
    """On the free plan, leave new or replaced documents out as "limit".

    Attachments are Pro-only; an item that references a left-out document is
    left out too, so nothing is written pointing at a missing file.
    """
    if _feature_allowed(session, "attachments"):
        return
    blocked: set[str] = set()
    for item in items:
        if item.get("kind") == "document" and actions[item["id"]] not in _NOT_WRITTEN:
            actions[item["id"]] = "limit"
            id_map[item["id"]] = None
            blocked.add(item["id"])
    for item in items:
        if actions[item["id"]] not in _NOT_WRITTEN and _document_refs(item) & blocked:
            actions[item["id"]] = "limit"
            id_map[item["id"]] = None


def _keep_totp_as_field(entry: dict[str, Any], original: Mapping[str, Any] | None) -> None:
    """On the free plan, keep an incoming new two-factor key as a hidden field.

    The key is never lost: it moves into a custom field the user can paste
    into the two-factor field after upgrading.  An unchanged key stays.
    """
    totp = entry.get("totp")
    if not isinstance(totp, dict) or (original is not None and original.get("totp") == totp):
        return
    from .importers import totp_uri_from_secret

    uri = totp_uri_from_secret(str(totp.get("secret", "")), label=str(entry.get("username") or ""),
                               digits=int(totp.get("digits", 6)), period=int(totp.get("period", 30)),
                               algorithm=str(totp.get("algorithm", "SHA1")))
    entry["totp"] = original.get("totp") if original is not None else None
    fields = entry.get("custom_fields")
    fields = list(fields) if isinstance(fields, list) else []
    if uri and len(fields) < 50:
        fields.append({"name": "Two-factor key (needs Pro)", "value": uri, "hidden": True})
    entry["custom_fields"] = fields


def _normalise_policy(conflict_policy: str | None, conflict: str | None) -> str:
    value = conflict_policy if conflict_policy is not None else conflict or "skip"
    value = str(value).casefold().replace("-", "_")
    if value == "create_copy":
        value = "copy"
    if value not in {"skip", "replace", "copy"}:
        raise TransferError("Conflict policy must be skip, replace, or copy")
    return value


def _preview_import(
    session: Any,
    items: list[dict[str, Any]],
    credentials: list[dict[str, Any]],
    collections: list[dict[str, Any]],
    attachments: dict[str, dict[str, Any]],
    *,
    conflict_policy: str,
    allow_replace: bool,
    expected_revisions: Mapping[str, int] | None,
) -> dict[str, Any]:
    payload, target_items, target_entries = _target_state(session)
    trash_by_id = _trash_by_id(payload)
    target_ids = {str(row.get("id")) for row in target_items + target_entries} | set(trash_by_id)
    target_item_by_id = {str(row.get("id")): row for row in target_items}
    target_entry_by_id = {str(row.get("id")): row for row in target_entries}
    # A deleted record keeps its id: an incoming record with that id is a
    # conflict, never a second record with the same id.
    for trash_id, entry in trash_by_id.items():
        if trash_id in target_item_by_id or trash_id in target_entry_by_id:
            continue
        if entry.get("kind") in ("web", "desktop"):
            target_entry_by_id[trash_id] = entry
        else:
            target_item_by_id[trash_id] = entry
    trash_replaced: set[str] = set()
    incoming = [("item", item) for item in items] + [("credential", entry) for entry in credentials]
    id_map: dict[str, str | None] = {}
    actions: dict[str, str] = {}
    existing_ids = set(target_ids) | {item["id"] for item in items} | {entry["id"] for entry in credentials}
    for kind, record in incoming:
        record_id = record["id"]
        target = target_item_by_id.get(record_id) if kind == "item" else target_entry_by_id.get(record_id)
        if target is None and record_id not in target_ids:
            id_map[record_id] = record_id
            actions[record_id] = "import"
            continue
        if target is None:
            raise TransferConflictError(f"Stable ID {record_id} already belongs to another record type")
        if conflict_policy == "skip":
            id_map[record_id] = None
            actions[record_id] = "skip"
        elif conflict_policy == "copy":
            mapped = _new_uuid(existing_ids)
            existing_ids.add(mapped)
            id_map[record_id] = mapped
            actions[record_id] = "copy"
        else:
            if not allow_replace:
                raise TransferConflictError("Replace requires an explicit allow_replace/replace flag")
            expected = expected_revisions.get(record_id) if expected_revisions else None
            if expected is not None:
                actual = target.get("revision", target.get("updated_at"))
                if actual != expected:
                    raise TransferConflictError(f"Revision conflict for {record_id}")
            elif kind == "item" and int(target.get("revision", 1)) > int(record.get("revision", 1)):
                raise TransferConflictError(f"Destination item {record_id} is newer than the transfer")
            elif kind == "credential" and int(target.get("updated_at", 0)) > int(record.get("updated_at", 0)):
                raise TransferConflictError(f"Destination credential {record_id} is newer than the transfer")
            id_map[record_id] = record_id
            actions[record_id] = "replace"
            if record_id in trash_by_id:
                trash_replaced.add(record_id)

    # A skipped document cannot satisfy an incoming selected item's reference.
    changed = True
    while changed:
        changed = False
        for item in items:
            if actions[item["id"]] == "skip":
                continue
            if any(id_map.get(ref) is None for ref in _document_refs(item)):
                if conflict_policy == "skip":
                    id_map[item["id"]] = None
                    actions[item["id"]] = "skip"
                    changed = True
                else:
                    raise TransferConflictError("A selected item references a skipped document")
    _apply_feature_limits(session, items, actions, id_map)
    free_slots = _apply_item_limit(session, incoming, actions, id_map, trash_replaced)
    target_collections = {row["id"]: row for row in payload.get("collections", []) if isinstance(row, dict)}
    collection_map: dict[str, str] = {}
    existing_collection_ids = set(target_collections)
    for collection in collections:
        collection_id = collection["id"]
        target = target_collections.get(collection_id)
        if target is None:
            collection_map[collection_id] = collection_id
            existing_collection_ids.add(collection_id)
        elif target == collection:
            collection_map[collection_id] = collection_id
        else:
            mapped = _new_uuid(existing_collection_ids)
            existing_collection_ids.add(mapped)
            collection_map[collection_id] = mapped

    attachment_map: dict[str, str] = {}
    needed = set()
    for item in items:
        if actions[item["id"]] not in _NOT_WRITTEN:
            needed.update(_attachment_id_from_item(item))
    for attachment_id in sorted(needed):
        attachment_map[attachment_id] = _new_uuid(set(attachment_map.values()) | {row.get("id") for row in payload.get("attachments", []) if isinstance(row, dict)})
    needed_collection_ids = {
        collection_id
        for item in items
        if actions[item["id"]] not in _NOT_WRITTEN
        for collection_id in item.get("collection_ids", [])
    }
    collections = [row for row in collections if row["id"] in needed_collection_ids]
    collection_map = {key: value for key, value in collection_map.items() if key in needed_collection_ids}
    return {
        "payload": payload, "target_items": target_items, "target_entries": target_entries,
        "id_map": id_map, "actions": actions, "collection_map": collection_map,
        "attachment_map": attachment_map, "attachments": attachments,
        "items": items, "credentials": credentials, "collections": collections,
        "free_slots": free_slots, "item_limit": getattr(session, "item_limit", None) if free_slots is not None else None,
        "trash_replaced": {key for key in trash_replaced if actions.get(key) == "replace"},
    }


def _plan_outcomes(plan: dict[str, Any]) -> dict[str, Any]:
    """Per-action id lists plus the free plan figures shown in previews and results."""
    actions = plan["actions"]

    def ids(action: str) -> list[str]:
        return [key for key, value in actions.items() if value == action]

    return {
        "imported_ids": ids("import"),
        "skipped_ids": ids("skip"),
        "copied_ids": ids("copy"),
        "replaced_ids": ids("replace"),
        "limit_skipped_ids": ids("limit"),
        "item_limit": plan["item_limit"],
        "free_slots": plan["free_slots"],
    }


def _mapped_item(item: dict[str, Any], plan: dict[str, Any]) -> dict[str, Any]:
    result = copy.deepcopy(item)
    result["id"] = plan["id_map"][item["id"]]
    result["collection_ids"] = [plan["collection_map"].get(value, value) for value in result.get("collection_ids", [])]
    typed = result.get("payload")
    if isinstance(typed, dict):
        if result.get("kind") == "document":
            typed["attachment_id"] = plan["attachment_map"][typed["attachment_id"]]
        if "document_ids" in typed:
            typed["document_ids"] = [plan["id_map"].get(value, value) for value in typed.get("document_ids", [])]
    return result


@contextmanager
def _fallback_transaction(session: Any):
    """Keep synthetic/fake sessions atomic when they lack VaultSession.transaction."""
    payload = _payload_for(session)
    original = copy.deepcopy(payload)
    try:
        yield session
        saver = getattr(session, "save", None)
        if callable(saver):
            saver()
    except BaseException:
        payload.clear()
        payload.update(original)
        raise


def _attachment_store(session: Any) -> Any:
    store = getattr(session, "attachments", None)
    if store is None:
        store = getattr(session, "attachment_store", None)
    if store is None:
        from .attachments import AttachmentStore
        store = AttachmentStore(session)
    return store


def _stage_attachment(session: Any, payload: dict[str, Any], attachment_id: str, record: dict[str, Any], data: bytes, cancel: Any) -> Path | None:
    store = _attachment_store(session)
    # Use the shared sidecar writer when available so imported references are
    # authenticated under the destination attachment-store identity.
    writer = getattr(store, "_write_blob", None)
    path_for = getattr(store, "_path", None)
    if callable(writer) and callable(path_for):
        store_id = store._store_id(payload)
        key = secrets.token_bytes(32)
        digest = hashlib.sha256(data).hexdigest()
        if digest != record["sha256"] or len(data) != record["size"]:
            raise TransferError("Staged attachment integrity check failed")
        projected = int(store.usage_bytes()) + len(data) + 8 * 1024
        if projected > int(getattr(store, "quota_bytes", MAX_TRANSFER_BYTES)):
            raise TransferError("Destination attachment quota exceeded")
        _check_cancel(cancel)
        try:
            writer(attachment_id, data, store_id=store_id, key=key, cancel=cancel)
        except Exception:
            _check_cancel(cancel)
            raise
        payload.setdefault("attachments", []).append({
            "id": attachment_id, "name": record["name"], "mime_type": record["mime_type"],
            "size": record["size"], "sha256": digest, "key": base64.b64encode(key).decode("ascii"),
        })
        return Path(path_for(attachment_id))
    add_bytes = getattr(store, "add_bytes", None)
    if not callable(add_bytes):
        raise TransferError("The destination has no attachment writer")
    try:
        try:
            new_id = add_bytes(record["name"], data, mime_type=record["mime_type"], cancel=cancel)
        except TypeError:
            new_id = add_bytes(record["name"], data, mime_type=record["mime_type"])
    except Exception:
        _check_cancel(cancel)
        raise
    if new_id != attachment_id:
        raise TransferError("Destination attachment writer cannot preserve a staged reference")
    return None


def _commit_plan(session: Any, plan: dict[str, Any], cancel: Any) -> None:
    payload = plan["payload"]
    original_payload = copy.deepcopy(payload)
    cleanup_paths: list[Path] = []
    try:
        transaction = getattr(session, "transaction", None)
        context = transaction() if callable(transaction) else _fallback_transaction(session)
        with context:
            _check_cancel(cancel)
            # The plan already capped new records at the free slots; re-check
            # in case the vault gained items between planning and commit.
            revived = plan.get("trash_replaced", set())
            new_records = sum(1 for key, value in plan["actions"].items() if _takes_slot(key, value, revived))
            check_can_create = getattr(session, "_check_can_create", None)
            if new_records and callable(check_can_create):
                check_can_create(new_records)
            # Collections are reference metadata; conflicting IDs are copied,
            # never silently replaced.
            existing_collections = {row["id"] for row in payload.setdefault("collections", [])}
            for collection in plan["collections"]:
                mapped_id = plan["collection_map"][collection["id"]]
                if mapped_id in existing_collections:
                    continue
                copied = copy.deepcopy(collection)
                copied["id"] = mapped_id
                payload["collections"].append(copied)
                existing_collections.add(mapped_id)

            # Replacing a deleted record drops its trash row so one id names
            # one record; the incoming copy is written as a live record below.
            if revived:
                payload["trash"] = [
                    row for row in payload.get("trash", [])
                    if not (isinstance(row, dict) and isinstance(row.get("entry"), dict)
                            and str(row["entry"].get("id")) in revived)
                ]

            for source_id, mapped_id in plan["attachment_map"].items():
                _check_cancel(cancel)
                attachment = plan["attachments"][source_id]
                data = attachment["data"]
                record = attachment["record"]
                store = _attachment_store(session)
                path_for = getattr(store, "_path", None)
                staged_path = Path(path_for(mapped_id)) if callable(path_for) else None
                if staged_path is not None:
                    cleanup_paths.append(staged_path)
                path = _stage_attachment(session, payload, mapped_id, record, data, cancel)
                if path is not None and path not in cleanup_paths:
                    cleanup_paths.append(path)

            target_items = payload.setdefault("items", [])
            target_entries = payload.setdefault("entries", [])
            mapped_items: list[dict[str, Any]] = []
            for item in plan["items"]:
                if plan["actions"][item["id"]] in _NOT_WRITTEN:
                    continue
                mapped = _mapped_item(item, plan)
                from .item_schema import validate_item
                try:
                    mapped = validate_item(mapped, known_collection_ids={row["id"] for row in payload["collections"]})
                except Exception as exc:
                    raise TransferError("Imported item reference validation failed") from exc
                mapped_items.append(mapped)
            known_document_ids = {
                row.get("id") for row in target_items if row.get("kind") == "document"
            } | {
                row.get("id") for row in mapped_items if row.get("kind") == "document"
            }
            for mapped in mapped_items:
                if not _document_refs(mapped).issubset(known_document_ids):
                    raise TransferError("Imported document reference is unknown")
            for mapped in mapped_items:
                original = next((row for row in target_items if row.get("id") == mapped["id"]), None)
                if original is None:
                    target_items.append(mapped)
                else:
                    original.clear()
                    original.update(mapped)

            for entry in plan["credentials"]:
                if plan["actions"][entry["id"]] in _NOT_WRITTEN:
                    continue
                mapped = _sanitize_credential(entry)
                mapped["id"] = plan["id_map"][entry["id"]]
                mapped = _validate_credential(mapped)
                original = next((row for row in target_entries if row.get("id") == mapped["id"]), None)
                if not _feature_allowed(session, "totp"):
                    _keep_totp_as_field(mapped, original)
                if original is None:
                    target_entries.append(mapped)
                else:
                    original.clear()
                    original.update(mapped)
            payload["updated_at"] = int(time.time())
    except BaseException:
        payload.clear()
        payload.update(original_payload)
        for path in cleanup_paths:
            try:
                path.unlink(missing_ok=True)
            except OSError:
                pass
        raise


def preview_transfer(
    source: Path,
    session: Any | None = None,
    transfer_password: str | None = None,
    *,
    password: str | None = None,
    conflict_policy: str = "skip",
    conflict: str | None = None,
    allow_replace: bool = False,
    replace: bool = False,
    expected_revisions: Mapping[str, int] | None = None,
) -> dict[str, Any]:
    """Preview a transfer without changing a destination.

    With no password/session this returns the safe public manifest.  Supplying
    both decrypts and computes the exact conflict/remap plan without staging or
    committing anything.
    """
    envelope = _read_package(source)
    if session is None and transfer_password is None and password is None:
        return copy.deepcopy(envelope["manifest"])
    if session is None:
        raise TransferError("A destination session is required for decrypted preview")
    transfer_password = transfer_password or password
    if transfer_password is None:
        raise TransferError("A transfer password is required")
    payload = _decrypt_payload(envelope, transfer_password)
    items, credentials, collections, attachment_values = _validate_package_payload(envelope, payload)
    policy = _normalise_policy(conflict_policy, conflict)
    plan = _preview_import(session, items, credentials, collections, attachment_values, conflict_policy=policy, allow_replace=allow_replace or replace, expected_revisions=expected_revisions)
    return {
        "manifest": copy.deepcopy(envelope["manifest"]),
        "conflict_policy": policy,
        "dry_run": True,
        **_plan_outcomes(plan),
        "id_map": copy.deepcopy(plan["id_map"]),
        "attachment_map": copy.deepcopy(plan["attachment_map"]),
    }


preview_import = preview_transfer


def import_transfer(
    source: Path,
    session: Any | None = None,
    transfer_password: str | None = None,
    *,
    password: str | None = None,
    destination_session: Any | None = None,
    conflict_policy: str = "skip",
    conflict: str | None = None,
    allow_replace: bool = False,
    replace: bool = False,
    dry_run: bool = False,
    preview: bool = False,
    expected_revisions: Mapping[str, int] | None = None,
    cancel: Any = None,
) -> dict[str, Any]:
    """Decrypt, fully validate, preview or atomically import a transfer."""
    if session is None:
        session = destination_session
    if session is None:
        raise TransferError("A destination session is required")
    transfer_password = transfer_password or password
    if transfer_password is None:
        raise TransferError("A transfer password is required")
    _check_cancel(cancel)
    envelope = _read_package(source)
    payload = _decrypt_payload(envelope, transfer_password)
    items, credentials, collections, attachment_values = _validate_package_payload(envelope, payload)
    policy = _normalise_policy(conflict_policy, conflict)
    plan = _preview_import(session, items, credentials, collections, attachment_values, conflict_policy=policy, allow_replace=allow_replace or replace, expected_revisions=expected_revisions)
    result = {
        "manifest": copy.deepcopy(envelope["manifest"]), "conflict_policy": policy,
        "dry_run": bool(dry_run or preview),
        **_plan_outcomes(plan),
        "id_map": copy.deepcopy(plan["id_map"]),
        "attachment_map": copy.deepcopy(plan["attachment_map"]),
    }
    if dry_run or preview:
        return result
    # Keep attachment data separate from record metadata until staging.  This
    # map is never persisted outside the authenticated payload.
    _check_cancel(cancel)
    _commit_plan(session, plan, cancel)
    result["dry_run"] = False
    result["committed"] = True
    return result


import_selective_transfer = import_transfer


__all__ = [
    "MAX_TRANSFER_BYTES",
    "MAX_TRANSFER_FILES",
    "MAX_TRANSFER_ITEMS",
    "TRANSFER_FORMAT",
    "TRANSFER_VERSION",
    "TransferCancelled",
    "TransferConflictError",
    "TransferError",
    "export_selective_transfer",
    "export_transfer",
    "import_selective_transfer",
    "import_transfer",
    "inspect_transfer",
    "preview_import",
    "preview_selective_transfer",
    "preview_transfer",
    "preview_transfer_export",
    "read_transfer_manifest",
]
