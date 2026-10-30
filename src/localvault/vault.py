from __future__ import annotations

import base64
import copy
import ctypes
import functools
import gc
import hashlib
import hmac
import json
import logging
import os
import secrets
import shutil
import sys
import tempfile
import threading
import time
import unicodedata
import uuid
from collections.abc import Iterable, Mapping
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from . import secret_text
from .i18n import t
from .secret_text import SecretText, as_secret
from .access_policy import normalized_policy
from .config import atomic_write_json, read_json, replace_with_retry
from .item_schema import (
    CATALOG_FORMAT,
    CATALOG_VERSION,
    ItemSchemaError,
    ItemSummary,
    summary_from_item,
    validate_attachment_records,
    validate_attachment_references,
    validate_collections,
    validate_events,
    validate_item,
    validate_reminders,
    validate_templates,
)
from .origin import OriginError, canonicalize_origin, origin_of
from .totp import generate_totp, normalize_secret

LEGACY_FORMAT_VERSION = 1
CATALOG_ENVELOPE_VERSION = 2  # format v2: Argon2id output used directly as the catalog key
FORMAT_VERSION = 3  # format v3: random data key wrapped by an Argon2id-derived KEK
SUPPORTED_FORMAT_VERSIONS = (LEGACY_FORMAT_VERSION, CATALOG_ENVELOPE_VERSION, FORMAT_VERSION)
FORMAT_V2_IDENTIFIER = "localgatekeys-vault-v2"
FORMAT_V3_IDENTIFIER = "localgatekeys-vault-v3"
LEGACY_CATALOG_IDENTIFIER = "localgatekeys-credentials-v1"
AAD_PREFIX = b"localvault-prototype|vault|v1|"
AAD_PREFIX_V2 = b"localgatekeys|vault|v2|"
AAD_PREFIX_V3 = b"localgatekeys|vault|v3|"
WRAPPER_AAD_PREFIX = b"localgatekeys|vault-key-wrapper|v3|"
UNLOCK_CONTEXT_PREFIX = b"localgatekeys|unlock-context|v3|"
ROLLBACK_ANCHOR_INFO = b"localgatekeys|rollback-anchor|v1"
RECOVERY_KEY_INFO = b"localgatekeys|recovery-key|v1"
ROLLBACK_ANCHOR_SCHEME = "hkdf-hmac-sha256-v1"
# Recorded inside the encrypted payload of v3 vaults: an anchor must exist.
ANCHOR_REQUIRED_KEY = "rollback_anchor_required"
RECOVERY_WRAPPER_KIND = "bip39-english-24"
BIP39_ENGLISH_SHA256 = "2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda"
DEFAULT_KDF = {
    "name": "argon2id",
    "time_cost": 3,
    "memory_cost_kib": 65536,
    "parallelism": 4,
    "hash_len": 32,
}

MIN_KDF_MEMORY_KIB = 8 * 1024
MAX_KDF_MEMORY_KIB = 512 * 1024
MAX_MASTER_PASSWORD_LENGTH = 4096
MAX_VAULT_BYTES = 24 * 1024 * 1024
MAX_WRAPPER_FIELD_CHARS = 512
MAX_WRAPPERS = 4
VAULT_MIGRATION_JOURNAL_VERSION = 2
MIGRATION_OPERATIONS = ("catalog-v1-to-v2", "envelope-v2-to-v3")

# Master-password throttling: the first five attempts are free; afterwards the
# wait doubles from two seconds up to one minute until a success resets it.
THROTTLE_FREE_ATTEMPTS = 5
THROTTLE_BASE_SECONDS = 2.0
THROTTLE_MAX_SECONDS = 60.0
THROTTLE_FAIL_CLOSED_FAILURES = 10
# v3 header field (authenticated through the catalog AAD) naming the unlock-throttle key in use at
# this vault's location, so a deleted, replaced or downgraded throttle key fails closed (R-8).
THROTTLE_BINDING_FIELD = "throttle_binding"

_LOG = logging.getLogger("localvault.vault")
_monotonic = time.monotonic  # patched by tests with a fake clock


class VaultError(Exception):
    pass


class VaultLockedError(VaultError):
    pass


class InvalidMasterPassword(VaultError):
    pass


class RecoveryPhraseError(VaultError):
    """The recovery phrase is malformed, has a bad checksum, or does not fit this vault."""


class UnlockThrottled(VaultError):
    """Too many wrong master passwords; ``retry_after`` seconds must pass first."""

    def __init__(self, retry_after: float):
        self.retry_after = max(0.0, float(retry_after))
        super().__init__(t("vault.tooManyIncorrectAttempts", seconds=int(self.retry_after + 0.999)))


class RollbackRequiresConfirmation(VaultError):
    """Restoring this copy would move the vault to an older generation."""

    def __init__(self, *, current_generation: int, restored_generation: int):
        self.current_generation = int(current_generation)
        self.restored_generation = int(restored_generation)
        super().__init__(t("vault.backupOlderThanVault", restored=self.restored_generation,
                           current=self.current_generation))


class LoginChangedError(VaultError):
    """The login was changed (or removed) since its edit token was issued."""

    def __init__(self, message: str | None = None):
        super().__init__(message or t("vault.loginChangedElsewhere"))


class DuplicateLoginError(VaultError):
    """A website login for the same canonical origin and username already exists."""

    def __init__(self, existing_id: str, message: str | None = None):
        super().__init__(message or t("vault.loginAlreadyExists"))
        self.existing_id = str(existing_id)


class ItemLimitReached(VaultError):
    """Creating a new live item would exceed the free plan's item limit."""

    def __init__(self, limit: int, count: int):
        super().__init__(t("vault.freePlanHoldsItems", limit=limit))
        self.limit = int(limit)
        self.count = int(count)


class ProFeatureRequired(VaultError):
    """Adding or changing data of a Pro-only feature on the free plan.

    Existing data is never locked: only the write that would add or change
    it is refused, the same way ``ItemLimitReached`` only refuses new items.
    """

    MESSAGES = {
        "totp": "vault.proNeededTotp",
        "attachments": "vault.proNeededAttachments",
        "sync": "vault.proNeededSync",
    }

    def __init__(self, feature: str):
        super().__init__(t(self.MESSAGES.get(feature, "vault.proNeededDefault")))
        self.feature = str(feature)


def require_pro_feature(session: Any, feature: str) -> None:
    """Raise ``ProFeatureRequired`` unless ``session`` allows ``feature``.

    ``session.pro_features`` is ``None`` (no restriction) unless the app set
    it from licensing after unlock, like ``item_limit``.
    """
    allowed = getattr(session, "pro_features", None)
    if allowed is not None and feature not in allowed:
        raise ProFeatureRequired(feature)


def _same_totp(new: dict[str, Any], old: Any) -> bool:
    """Whether normalised ``new`` is the code already saved as ``old``."""
    if not isinstance(old, dict):
        return False
    try:
        saved = {"secret": normalize_secret(str(old.get("secret", ""))),
                 "algorithm": str(old.get("algorithm", "SHA1")).upper(),
                 "digits": int(old.get("digits", 6)), "period": int(old.get("period", 30))}
    except (TypeError, ValueError):
        return False
    return saved == new


# Upper bound for the licence copy stored in the vault catalog.
MAX_STORED_LICENSE_BYTES = 16 * 1024


def free_item_slots(session: Any) -> int | None:
    """New live items the session may still create; ``None`` means unlimited.

    Works on any session-like object: without ``item_limit`` (or a way to count
    live items) there is no limit to apply.  Over the limit reports 0.
    """
    limit = getattr(session, "item_limit", None)
    counter = getattr(session, "live_item_count", None)
    if limit is None or not callable(counter):
        return None
    return max(0, int(limit) - int(counter()))


# Entry keys that never invalidate a login edit token.  ``site_icon`` is the
# only entry field written in the background (browser capture and the icon
# fetcher via ``set_entry_icon``); it is display metadata, not login data.
# URL rows live in ``scope.urls`` and therefore stay covered by the token.
_EDIT_TOKEN_IGNORED_KEYS = frozenset({"site_icon"})


def _same_revision(expected: Any, current: int) -> bool:
    """Equality for credential revisions in constant time; non-int (or bool) expectations never match."""
    return type(expected) is int and hmac.compare_digest(str(expected).encode("ascii"), str(current).encode("ascii"))


def _b64e(value: bytes) -> str:
    return base64.b64encode(value).decode("ascii")


def _b64d(value: str) -> bytes:
    try:
        return base64.b64decode(value.encode("ascii"), validate=True)
    except Exception as exc:  # noqa: BLE001 - convert parser details to a stable error
        raise VaultError("Vault contains invalid base64 data") from exc


def _canonical_json(value: Any) -> bytes:
    return json.dumps(value, separators=(",", ":"), sort_keys=True).encode("utf-8")


def _canonical_json_chunks(value: Any, *, ensure_ascii: bool = True) -> Iterable[str]:
    """Small chunks of the ``_canonical_json`` text, never one string holding the whole document.

    ``_one_shot=False`` selects the pure-Python encoder, which yields pieces;
    the C encoder returns the complete document as a single string.
    """
    encoder = json.JSONEncoder(separators=(",", ":"), sort_keys=True, ensure_ascii=ensure_ascii)
    return encoder.iterencode(value, _one_shot=False)


def _canonical_json_buffer(value: Any) -> bytearray:
    """``_canonical_json`` built straight into one zeroable buffer (the caller zeroes it).

    Only short fragments, comparable to the payload's own field strings, are
    ever held as immutable objects; no immutable copy of the whole catalog is.
    """
    chunks = [chunk.encode("utf-8") for chunk in _canonical_json_chunks(value)]
    buffer = bytearray(sum(len(chunk) for chunk in chunks))
    position = 0
    for chunk in chunks:
        buffer[position:position + len(chunk)] = chunk
        position += len(chunk)
    chunks.clear()
    return buffer


def _scrub_str(text: str) -> None:
    """Best effort: overwrite a private, freshly decoded ASCII ``str`` before it is freed.

    CPython stores a compact ASCII string's characters right after its object
    header.  Only a string this module created and still owns alone is passed
    here; anything else (other interpreters, non-ASCII text) is left as is.
    """
    if sys.implementation.name != "cpython" or len(text) < 2 or not text.isascii():
        return
    try:
        offset = sys.getsizeof(text) - len(text) - 1
        ctypes.memset(id(text) + offset, 0x20, len(text))
    except Exception:  # noqa: BLE001, S110 - scrubbing is defence in depth only
        pass


def _json_from_buffer(buffer: bytearray) -> Any:
    """``json.loads`` from a decrypted buffer; the transient full-text copy is scrubbed."""
    try:
        text = buffer.decode("ascii")
    except UnicodeDecodeError:
        # Non-ASCII catalogs (written elsewhere) are parsed directly; the
        # interpreter's internal decode cannot be scrubbed.
        return json.loads(buffer)
    try:
        return json.loads(text)
    finally:
        _scrub_str(text)
        del text


def _header_version(header: dict[str, Any]) -> int:
    try:
        return int(header.get("version", LEGACY_FORMAT_VERSION))
    except (TypeError, ValueError) as exc:
        raise VaultError("Vault format version is malformed") from exc


def _v3_identity(header: dict[str, Any]) -> dict[str, Any]:
    """Public, stable identity fields shared by every v3 authenticated encoding."""
    return {
        "version": FORMAT_VERSION,
        "format": header.get("format", FORMAT_V3_IDENTIFIER),
        "catalog": header.get("catalog", CATALOG_FORMAT),
        "catalog_version": header.get("catalog_version", CATALOG_VERSION),
        "vault_id": header.get("vault_id", ""),
        "key_generation": header.get("key_generation", 1),
    }


def _aad(header: dict[str, Any]) -> bytes:
    """Associated data for the encrypted catalog.

    v1/v2 bind the KDF because the Argon2 output *is* the catalog key.  v3
    binds the vault identity, catalog version, key generation and the write
    generation instead; wrapper metadata is authenticated by the wrappers.
    """
    version = _header_version(header)
    if version == FORMAT_VERSION:
        authenticated_header = _v3_identity(header)
        authenticated_header["generation"] = header.get("generation", 0)
        authenticated_header["cipher"] = {"name": header["cipher"]["name"]}
        if THROTTLE_BINDING_FIELD in header:
            # R-8: deleting or swapping the throttle key would change this and fail the unlock.
            authenticated_header[THROTTLE_BINDING_FIELD] = header[THROTTLE_BINDING_FIELD]
        return AAD_PREFIX_V3 + _canonical_json(authenticated_header)
    authenticated_header = {
        "version": header["version"],
        "kdf": header["kdf"],
        "cipher": {"name": header["cipher"]["name"]},
    }
    prefix = AAD_PREFIX_V2 if version == CATALOG_ENVELOPE_VERSION else AAD_PREFIX
    if version == CATALOG_ENVELOPE_VERSION:
        authenticated_header["format"] = header.get("format", FORMAT_V2_IDENTIFIER)
        authenticated_header["catalog"] = header.get("catalog", CATALOG_FORMAT)
    return prefix + _canonical_json(authenticated_header)


def _wrapper_aad(header: dict[str, Any], name: str, metadata: dict[str, Any]) -> bytes:
    """Every wrapper authenticates the vault identity plus its own public metadata."""
    body = _v3_identity(header)
    body["wrapper"] = name
    body["metadata"] = metadata
    return WRAPPER_AAD_PREFIX + _canonical_json(body)


def unlock_context_for_header(header: dict[str, Any]) -> str:
    """Hex digest that local unlock sidecars (Hello/camera) bind to.

    It is stable across ordinary saves, and changes when the master password,
    the key generation or the vault format changes, so a stale sidecar is
    refused before any native prompt is shown.
    """
    if _header_version(header) == FORMAT_VERSION:
        body = _v3_identity(header)
        body["kdf"] = header.get("kdf", {})
        body["cipher"] = {"name": header["cipher"]["name"]}
        return hashlib.sha256(UNLOCK_CONTEXT_PREFIX + _canonical_json(body)).hexdigest()
    return hashlib.sha256(_aad(header)).hexdigest()


def _hkdf(key_material: bytes | bytearray, info: bytes, *, salt: bytes = b"", length: int = 32) -> bytearray:
    # The buffer is passed as is: no immutable copy of the key material is made here.
    return bytearray(HKDF(algorithm=hashes.SHA256(), length=length, salt=salt or None, info=info).derive(key_material))


def _aesgcm_decrypt(key: bytes | bytearray, nonce: bytes, ciphertext: bytes, aad: bytes) -> bytearray:
    """AES-GCM decrypt straight into a zeroable buffer (the caller zeroes it)."""
    if len(ciphertext) < 16:
        raise InvalidTag()
    cipher = AESGCM(key)
    decrypt_into = getattr(cipher, "decrypt_into", None)
    if decrypt_into is None:  # cryptography < 44: one transient immutable copy
        return bytearray(cipher.decrypt(nonce, ciphertext, aad))
    plaintext = bytearray(len(ciphertext) - 16)
    try:
        decrypt_into(nonce, ciphertext, aad, plaintext)
    except BaseException:
        _zero(plaintext)
        raise
    return plaintext


def _wrap_key(wrapping_key: bytes | bytearray, key: bytes | bytearray, aad: bytes) -> tuple[bytes, bytes]:
    if len(wrapping_key) != 32 or len(key) != 32:
        raise VaultError("Invalid key-wrapping parameters")
    nonce = os.urandom(12)
    return nonce, AESGCM(wrapping_key).encrypt(nonce, key, aad)


def _unwrap_key(wrapping_key: bytes | bytearray, nonce: bytes, ciphertext: bytes, aad: bytes) -> bytearray:
    """Return the unwrapped key or raise InvalidTag; never partially trusts the input."""
    if len(wrapping_key) != 32 or len(nonce) != 12 or len(ciphertext) != 48:
        raise InvalidTag()
    return _aesgcm_decrypt(wrapping_key, nonce, ciphertext, aad)


def _zero(buffer: bytearray | None) -> None:
    if buffer is not None:
        buffer[:] = b"\0" * len(buffer)


def _validated_wrapper_field(wrapper: Any, name: str, size: int) -> bytes:
    if not isinstance(wrapper, dict):
        raise VaultError("Vault key wrapper is malformed")
    value = wrapper.get(name)
    if not isinstance(value, str) or len(value) > MAX_WRAPPER_FIELD_CHARS:
        raise VaultError("Vault key wrapper is malformed")
    decoded = _b64d(value)
    if len(decoded) != size:
        raise VaultError("Vault key wrapper is malformed")
    return decoded


def _master_secret(value: Any, message: str) -> tuple[SecretText, bool]:
    """Public-entry conversion of a master password: ``(secret, owned)``; owned means the caller wipes it."""
    if not isinstance(value, (str, SecretText)):
        raise VaultError(message)
    try:
        return as_secret(value)
    except ValueError:
        raise VaultError(t("vault.err.passwordTextInvalid")) from None


def _derive_key(password: str | SecretText, kdf: dict[str, Any]) -> bytearray:
    if not isinstance(password, (str, SecretText)):
        raise InvalidMasterPassword(t("vault.err.passwordEmpty"))
    try:
        secret, owned = as_secret(password)
    except ValueError:
        raise VaultError(t("vault.err.passwordTextInvalid")) from None
    try:
        if secret.char_count == 0:
            raise InvalidMasterPassword(t("vault.err.passwordEmpty"))
        if secret.char_count > MAX_MASTER_PASSWORD_LENGTH:
            raise InvalidMasterPassword(t("vault.err.passwordTooLong"))
        if kdf.get("name") != "argon2id":
            raise VaultError("Unsupported KDF")

        salt = _b64d(str(kdf.get("salt", "")))
        if len(salt) < 16:
            raise VaultError("Vault KDF salt is too short")

        try:
            time_cost = int(kdf["time_cost"])
            memory_cost = int(kdf["memory_cost_kib"])
            parallelism = int(kdf["parallelism"])
            hash_len = int(kdf["hash_len"])
            if not (1 <= time_cost <= 10):
                raise ValueError("time_cost is outside the accepted range")
            if not (MIN_KDF_MEMORY_KIB <= memory_cost <= MAX_KDF_MEMORY_KIB):
                raise ValueError("memory_cost_kib is outside the accepted range")
            if not (1 <= parallelism <= 16):
                raise ValueError("parallelism is outside the accepted range")
            if hash_len != 32:
                raise ValueError("hash_len must be 32 bytes")
            return secret_text.argon2id_raw(
                secret.buffer,
                salt,
                time_cost=time_cost,
                memory_cost=memory_cost,
                parallelism=parallelism,
                hash_len=hash_len,
            )
        except (KeyError, TypeError, ValueError, OverflowError) as exc:
            # OverflowError: int() of an out-of-range float such as 1e400 (parsed as inf).
            raise VaultError("Invalid KDF parameters") from exc
        except RuntimeError:
            raise VaultError("Key derivation failed") from None
    finally:
        if owned:
            secret.wipe()


def _empty_payload() -> dict[str, Any]:
    now = int(time.time())
    return {
        "version": CATALOG_VERSION,
        "catalog": CATALOG_FORMAT,
        "created_at": now,
        "updated_at": now,
        "generation": 1,
        "entries": [],
        "items": [],
        "collections": [],
        "templates": [],
        "events": [],
        "attachments": [],
        "reminders": [],
        # Next-release state stays inside the authenticated catalog.  These
        # collections are intentionally data-only; their services enforce the
        # tighter per-record limits before publication.
        "history": [],
        "relationships": [],
        "smart_views": [],
        "ocr_derivatives": [],
        "sync_protocol_state": {"next_counter": 1, "item_revisions": {}},
        "sync_receipts": [],
    }


def _validate_next_release_state(payload: dict[str, Any], *, known_item_ids: set[str]) -> None:
    """Fail closed on persisted next-release metadata before any save.

    The feature services perform semantic validation while mutating.  Vault
    loading also needs a cheap structural gate so a hand-edited or truncated
    encrypted catalog cannot make a later UI operation walk unbounded data.
    """
    history = payload.get("history", [])
    if not isinstance(history, list) or len(history) > 20_000:
        raise VaultError("Typed history is malformed")
    for row in history:
        if not isinstance(row, dict) or not isinstance(row.get("snapshot_id"), str) \
                or not isinstance(row.get("item_id"), str) or row["item_id"] not in known_item_ids \
                or type(row.get("revision")) is not int or row["revision"] < 1 \
                or type(row.get("created_at")) is not int or row["created_at"] < 0 \
                or not isinstance(row.get("item"), dict):
            raise VaultError("Typed history snapshot is malformed")
        if len(row["snapshot_id"]) > 128:
            raise VaultError("Typed history snapshot ID is malformed")
        if not isinstance(row.get("attachment_ids", []), list) or len(row["attachment_ids"]) > 20:
            raise VaultError("Typed history attachment references are malformed")
        if not isinstance(row.get("relations", []), list) or len(row["relations"]) > 100:
            raise VaultError("Typed history relation references are malformed")

    relationships = payload.get("relationships", [])
    if not isinstance(relationships, list) or len(relationships) > 100_000:
        raise VaultError("Relationship edge table is malformed")
    allowed_edge = {"edge_id", "profile_id", "source_id", "target_id", "relation_type", "created_at", "tombstoned"}
    for row in relationships:
        if not isinstance(row, dict) or set(row) - allowed_edge:
            raise VaultError("Relationship edge is malformed")
        if (not isinstance(row.get("edge_id"), str) or len(row["edge_id"]) > 128
                or not isinstance(row.get("profile_id"), str) or len(row["profile_id"]) > 128
                or not isinstance(row.get("source_id"), str) or not isinstance(row.get("target_id"), str)
                or row["source_id"] == row["target_id"]
                or not isinstance(row.get("relation_type"), str) or len(row["relation_type"]) > 64
                or type(row.get("created_at")) is not int or row["created_at"] < 0
                or type(row.get("tombstoned", False)) is not bool):
            raise VaultError("Relationship edge is malformed")

    smart_views = payload.get("smart_views", [])
    if not isinstance(smart_views, list) or len(smart_views) > 100:
        raise VaultError("Smart view collection is malformed")
    if smart_views:
        from .smart_views import validate_predicate, validate_sort_keys
        for row in smart_views:
            if not isinstance(row, dict) or not isinstance(row.get("id"), str) \
                    or not isinstance(row.get("name"), str) or len(row["name"]) > 100 \
                    or type(row.get("created_at")) is not int or type(row.get("updated_at")) is not int:
                raise VaultError("Smart view definition is malformed")
            try:
                validate_predicate(row.get("predicate"))
                validate_sort_keys(row.get("sort_keys"))
            except Exception as exc:  # normalize implementation details at the vault boundary
                raise VaultError("Smart view definition is malformed") from exc

    sync_state = payload.get("sync_protocol_state", {"next_counter": 1, "item_revisions": {}})
    if not isinstance(sync_state, dict) or type(sync_state.get("next_counter", 1)) is not int \
            or not 1 <= sync_state.get("next_counter", 1) <= 2**63 - 1 \
            or not isinstance(sync_state.get("item_revisions", {}), dict) \
            or len(sync_state.get("item_revisions", {})) > 20_000:
        raise VaultError("Sync protocol state is malformed")
    for key, counter in sync_state.get("item_revisions", {}).items():
        if not isinstance(key, str) or len(key) > 200 or type(counter) is not int or not 1 <= counter <= 2**63 - 1:
            raise VaultError("Sync protocol state is malformed")
    receipts = payload.get("sync_receipts", [])
    if not isinstance(receipts, list) or len(receipts) > 500:
        raise VaultError("Sync receipt ledger is malformed")
    for row in receipts:
        if not isinstance(row, dict) or not isinstance(row.get("operation_id"), str) \
                or len(row["operation_id"]) > 128 or type(row.get("applied", 0)) is not int \
                or type(row.get("conflicts", 0)) is not int or type(row.get("created_at", 0)) is not int:
            raise VaultError("Sync receipt ledger is malformed")

    derivatives = payload.get("ocr_derivatives", [])
    if not isinstance(derivatives, list) or len(derivatives) > 20_000:
        raise VaultError("OCR derivative manifest is malformed")
    for row in derivatives:
        if not isinstance(row, dict) or not isinstance(row.get("id"), str) \
                or not isinstance(row.get("item_id"), str) or len(row["item_id"]) > 128 \
                or not isinstance(row.get("attachment_id"), str) or type(row.get("source_revision")) is not int \
                or type(row.get("size", 0)) is not int or row.get("size", 0) < 0:
            raise VaultError("OCR derivative manifest is malformed")


def _stored_origin(value: Any, *, strict: bool = False) -> str:
    """Canonical form of a stored website origin, or the stored text when it is no longer accepted.

    ``canonicalize_origin`` has become stricter over time (2026-10-24:
    backslashes, ``%``, zone ids, mapped IPv6, repeated trailing dots...).
    A login saved before that (only possible through an old crafted import)
    must not make the whole vault fail to open.  Its text is kept unchanged
    so the user can see, fix or delete it; it is never offered for fill,
    because every lookup compares stored origins with a *canonical* request
    origin, which can never equal a refused value.

    ``strict`` (records arriving from outside: imports, transfers, sync) keeps
    the refusal: only a record already stored in this vault is tolerated.
    """
    try:
        return canonicalize_origin(value)
    except OriginError:
        if not strict and isinstance(value, str) and 0 < len(value) <= 2048:
            _LOG.warning("A stored login has a website address that is no longer accepted; it will not be filled.")
            return value
        raise


def _validate_legacy_payload(payload: Any, *, strict_origins: bool = False) -> dict[str, Any]:
    if not isinstance(payload, dict) or payload.get("version") != LEGACY_FORMAT_VERSION:
        raise VaultError("Unsupported decrypted vault payload")
    entries = payload.get("entries")
    trash = payload.get("trash", [])
    generation = payload.get("generation", 0)
    if type(generation) is not int or not 0 <= generation <= 2**63 - 1:
        raise VaultError("Vault generation is malformed")
    payload["generation"] = generation
    if not isinstance(entries, list) or len(entries) > 20000 or not isinstance(trash, list):
        raise VaultError("Vault entries are malformed")
    deleted = []
    for record in trash:
        if not isinstance(record, dict) or not isinstance(record.get("deleted_at"), int):
            raise VaultError("Deleted entries are malformed")
        deleted.append(record.get("entry"))
    ids = set()
    for entry in entries + deleted:
        if not isinstance(entry, dict) or entry.get("kind") not in ("web", "desktop"):
            raise VaultError("Unsupported credential type")
        for field, limit in (("id",128),("label",512),("username",512),("password",4096)):
            _validated_text(entry.get(field), field, limit, allow_empty=field in ("username", "password"))
        if entry["id"] in ids: raise VaultError("Duplicate entry IDs")
        ids.add(entry["id"])
        scope = entry.get("scope")
        if not isinstance(scope, dict): raise VaultError("Credential scope is missing")
        if entry["kind"] == "web":
            scope["origin"] = _stored_origin(scope.get("origin", ""), strict=strict_origins)
        if not isinstance(entry.get("tags", []), list): raise VaultError("Invalid tags")
        entry["policy"] = normalized_policy(entry.get("policy"))
    return payload


def _validate_catalog_payload(payload: Any) -> dict[str, Any]:
    """Validate v2 while retaining the exact v1 credential record shape."""
    if not isinstance(payload, dict) or payload.get("version") != CATALOG_VERSION:
        raise VaultError("Unsupported decrypted vault payload")
    if payload.get("catalog") not in (None, CATALOG_FORMAT):
        raise VaultError("Unsupported encrypted catalog format")
    entries = payload.get("entries", [])
    if not isinstance(entries, list):
        raise VaultError("Vault entries are malformed")
    # Reuse the battle-tested credential validator without rewriting legacy
    # fields or silently accepting a typed record in the credential list.
    legacy_view = {"version": LEGACY_FORMAT_VERSION, "entries": entries, "trash": []}
    _validate_legacy_payload(legacy_view)
    typed_items = payload.get("items", [])
    if not isinstance(typed_items, list) or len(typed_items) > 20_000:
        raise VaultError("Typed catalog items are malformed")
    try:
        collections = validate_collections(payload.get("collections", []))
    except ItemSchemaError as exc:
        raise VaultError(str(exc)) from exc
    collection_ids = {row["id"] for row in collections}
    normalized_items = []
    ids = {str(row["id"]) for row in entries}
    for item in typed_items:
        try:
            normalized = validate_item(item, known_collection_ids=collection_ids)
        except ItemSchemaError as exc:
            raise VaultError(str(exc)) from exc
        if normalized["id"] in ids:
            raise VaultError("Duplicate catalog item IDs")
        ids.add(normalized["id"])
        normalized_items.append(normalized)
    normalized_trash = []
    raw_trash = payload.get("trash", [])
    if not isinstance(raw_trash, list) or len(raw_trash) > 20_000:
        raise VaultError("Deleted entries are malformed")
    for record in raw_trash:
        if not isinstance(record, dict) or not isinstance(record.get("deleted_at"), int):
            raise VaultError("Deleted entries are malformed")
        deleted = record.get("entry")
        if isinstance(deleted, dict) and deleted.get("kind") in ("web", "desktop"):
            # Credential trash is validated by the legacy validator below.
            normalized_trash.append(copy.deepcopy(record))
            continue
        try:
            deleted = validate_item(deleted, known_collection_ids=collection_ids)
        except ItemSchemaError as exc:
            raise VaultError(str(exc)) from exc
        if deleted["id"] in ids:
            raise VaultError("Duplicate deleted catalog item IDs")
        ids.add(deleted["id"])
        normalized_trash.append({"entry": deleted, "deleted_at": record["deleted_at"]})
    credential_trash = [record for record in raw_trash
                        if isinstance(record, dict) and isinstance(record.get("entry"), dict)
                        and record["entry"].get("kind") in ("web", "desktop")]
    legacy_view["trash"] = credential_trash
    _validate_legacy_payload(legacy_view)
    # The legacy validator intentionally normalizes credential records in its
    # private view; retain the original records and canonicalize only typed
    # records, while keeping deletion ordering and timestamps intact.
    payload["trash"] = normalized_trash
    try:
        events = validate_events(payload.get("events", []))
        # The generic schema only bounds event fields. Apply the M5 service's
        # strict domain/action and result allowlists before accepting data
        # loaded from or committed to the encrypted catalog.
        from .activity import ActivityService
        for event in events:
            ActivityService._safe_event_type(event["event_type"])
            ActivityService._safe_result(event["result"])
            ActivityService._safe_item_id(event.get("item_id"))
    except ItemSchemaError as exc:
        raise VaultError(str(exc)) from exc
    payload["catalog"] = CATALOG_FORMAT
    payload["items"] = normalized_items
    payload["collections"] = collections
    payload["events"] = events
    known_next_release_ids = {item["id"] for item in normalized_items}
    known_next_release_ids.update(
        record["entry"]["id"] for record in normalized_trash
        if isinstance(record.get("entry"), dict)
        and record["entry"].get("kind") not in {"web", "desktop"}
    )
    # Purging an item from the trash makes its snapshots unreachable.  Drop
    # them here so every purge path (and vaults older builds left with orphans)
    # stays loadable; the structural checks below still fail closed.
    if isinstance(payload.get("history"), list):
        payload["history"] = [row for row in payload["history"]
                              if not (isinstance(row, dict) and isinstance(row.get("item_id"), str)
                                      and row["item_id"] not in known_next_release_ids)]
    _validate_next_release_state(payload, known_item_ids=known_next_release_ids)
    # Custom templates are validated by TemplateService on write.  Keep a
    # bounded object-only gate here so malformed/newer data fails closed.
    try:
        payload["templates"] = validate_templates(payload.get("templates", []))
    except ItemSchemaError as exc:
        raise VaultError(str(exc)) from exc
    try:
        payload["attachments"] = validate_attachment_records(payload.get("attachments", []))
        reminders = validate_reminders(payload.get("reminders", []))
        live_item_ids = {item["id"] for item in normalized_items}
        # Deleting a typed item moves it to trash before save(). Reminder
        # references are live-item references, so prune stale rows at the
        # authenticated commit boundary, including older vaults.
        payload["reminders"] = [row for row in reminders if row["item_id"] in live_item_ids]
        validate_attachment_references(payload["items"], payload.get("trash", []), payload["attachments"])
    except ItemSchemaError as exc:
        raise VaultError(str(exc)) from exc
    store_id = payload.get("attachment_store_id")
    if store_id is not None:
        try:
            import uuid as _uuid
            store_id = str(_uuid.UUID(str(store_id)))
        except (ValueError, TypeError, AttributeError):
            raise VaultError("Attachment store identity is malformed") from None
        payload["attachment_store_id"] = store_id
    elif payload["attachments"]:
        raise VaultError("Attachment store identity is missing")
    if type(payload.get("generation", 0)) is not int or not 0 <= payload["generation"] <= 2**63 - 1:
        raise VaultError("Vault generation is malformed")
    if "license" in payload and not stored_license_ok(payload["license"]):
        # The copy only restores a licence file; a bad one must never stop the
        # vault from opening or saving.  Drop it and keep going.
        payload.pop("license")
        _LOG.warning("Dropped a malformed licence copy from the vault catalog")
    return payload


def stored_license_ok(value: Any) -> bool:
    """Shape and size check for the licence copy kept inside the vault."""
    if not isinstance(value, dict):
        return False
    try:
        size = len(json.dumps(value, separators=(",", ":"), sort_keys=True))
    except (TypeError, ValueError):
        return False
    return size <= MAX_STORED_LICENSE_BYTES


def _validate_payload(payload: Any, version: int = FORMAT_VERSION) -> dict[str, Any]:
    if version == LEGACY_FORMAT_VERSION:
        return _validate_legacy_payload(payload)
    if version == CATALOG_VERSION:
        return _validate_catalog_payload(payload)
    raise VaultError("Unsupported decrypted vault payload")


def _generation_anchor_path(path: Path) -> Path:
    return path.with_name(path.stem + ".generation.json")


def _rollback_anchor_key(data_key: bytes | bytearray) -> bytearray:
    """HKDF(DK, "rollback-anchor"): only a holder of the data key can mint anchors."""
    return _hkdf(data_key, ROLLBACK_ANCHOR_INFO)


def _anchor_mac(anchor_key: bytes | bytearray, generation: int, vault_id: str) -> bytes:
    body = _canonical_json({"generation": int(generation), "vault_id": vault_id})
    return hmac.new(anchor_key, body, hashlib.sha256).digest()


def _dpapi() -> Any:
    """Return win32crypt when the current-user DPAPI is importable, else None."""
    if os.name != "nt":
        return None
    try:
        import win32crypt  # type: ignore
    except Exception:  # noqa: BLE001 - optional dependency / non-Windows image
        return None
    return win32crypt


_DPAPI_WARNED = False


def _warn_dpapi_unavailable() -> None:
    global _DPAPI_WARNED
    if not _DPAPI_WARNED:
        _DPAPI_WARNED = True
        _LOG.warning("Windows data protection is unavailable; the rollback anchor is HMAC-protected only.")


def _dpapi_protect(blob: bytes, description: str, entropy: bytes) -> str | None:
    api = _dpapi()
    if api is None:
        _warn_dpapi_unavailable()
        return None
    try:
        flags = int(getattr(api, "CRYPTPROTECT_UI_FORBIDDEN", 0x1))
        return _b64e(bytes(api.CryptProtectData(blob, description, entropy, None, None, flags)))
    except Exception:  # noqa: BLE001 - a DPAPI failure must not block the vault
        _warn_dpapi_unavailable()
        return None


def _dpapi_unprotect(value: str, entropy: bytes) -> bytes | None:
    """Return the protected bytes, None when DPAPI is unavailable, or raise ValueError."""
    api = _dpapi()
    if api is None:
        return None
    try:
        flags = int(getattr(api, "CRYPTPROTECT_UI_FORBIDDEN", 0x1))
        result = api.CryptUnprotectData(_b64d(value), entropy, None, None, flags)
    except Exception as exc:  # noqa: BLE001 - normalize the pywin32 error surface
        raise ValueError("DPAPI unprotect failed") from exc
    return bytes(result[1] if isinstance(result, tuple) else result)


def _anchor_protection_matches(protection: Any, anchor_key: bytes | bytearray, generation: int,
                               vault_id: str, *, check_dpapi: bool = True) -> bool:
    """Return whether one anchor protection record authenticates under ``anchor_key``."""
    try:
        if not isinstance(protection, dict) or protection.get("scheme") != ROLLBACK_ANCHOR_SCHEME:
            return False
        expected = _anchor_mac(anchor_key, generation, str(protection.get("vault_id", "")))
        if not hmac.compare_digest(_b64d(str(protection.get("mac", ""))), expected):
            return False
        if vault_id and str(protection.get("vault_id", "")) not in ("", vault_id):
            return False
        sealed = protection.get("dpapi") if check_dpapi else None
        if isinstance(sealed, str) and sealed:
            opened = _dpapi_unprotect(sealed, expected)
            if opened is not None and not hmac.compare_digest(opened, expected):
                return False
    except (ValueError, TypeError, AttributeError):
        return False
    return True


def _read_generation_anchor(path: Path, anchor_key: bytes | bytearray | None = None,
                            vault_id: str = "", *, require_mac: bool = False) -> tuple[int, bool]:
    """Return (generation, needs_upgrade).

    An anchor with a MAC must authenticate under this vault's data key.  The
    legacy plaintext form is accepted once and rewritten with a MAC by the
    caller, but only where it can be legitimate: ``require_mac`` (set for v3
    envelopes, which have always had MAC anchors) refuses it, so an attacker
    cannot downgrade the anchor without unlocking.  A ``previous`` MAC is the
    second half of an in-flight data-key rotation and is accepted once.  Any
    other failure raises instead of being treated as generation 0.
    """
    anchor_path = _generation_anchor_path(path)
    if not anchor_path.exists():
        return 0, False
    try:
        if anchor_path.stat().st_size > 64 * 1024:
            raise ValueError
        raw = read_json(anchor_path)
        generation = raw.get("generation") if isinstance(raw, dict) else None
        if type(generation) is not int or not 0 <= generation <= 2**63 - 1:
            raise ValueError
        protection = raw.get("anchor")
        previous = raw.get("previous")
    except (OSError, ValueError, TypeError, AttributeError) as exc:
        raise VaultError("Vault rollback-protection metadata is malformed") from exc
    if protection is None:
        if require_mac:
            raise VaultError("Vault rollback-protection metadata was downgraded to an unauthenticated form")
        return generation, True
    if anchor_key is None:
        # The caller cannot authenticate (no data key yet); report the value only.
        return generation, False
    if _anchor_protection_matches(protection, anchor_key, generation, vault_id):
        return generation, previous is not None
    if previous is not None and _anchor_protection_matches(previous, anchor_key, generation, vault_id,
                                                           check_dpapi=False):
        return generation, True
    raise VaultError("Vault rollback-protection metadata failed authentication")


def _anchor_protection(anchor_key: bytes | bytearray, generation: int, vault_id: str, *,
                       seal: bool = True) -> dict[str, Any]:
    mac = _anchor_mac(anchor_key, generation, vault_id)
    return {
        "scheme": ROLLBACK_ANCHOR_SCHEME,
        "vault_id": vault_id,
        "mac": _b64e(mac),
        "dpapi": _dpapi_protect(mac, "LocalGateKeys rollback anchor", mac) if seal else None,
    }


def _write_generation_anchor(path: Path, generation: int, anchor_key: bytes | bytearray,
                             vault_id: str = "", *, previous_key: bytes | bytearray | None = None,
                             previous_vault_id: str = "") -> None:
    """Write the anchor; ``previous_key`` also authenticates it during a data-key rotation.

    A rotation publishes the anchor before the re-encrypted vault, so a crash
    between the two must leave an anchor that opens whichever vault is on disk.
    """
    record: dict[str, Any] = {
        "version": 1,
        "generation": int(generation),
        "anchor": _anchor_protection(anchor_key, generation, vault_id),
    }
    if previous_key is not None:
        record["previous"] = _anchor_protection(previous_key, generation, previous_vault_id, seal=False)
    atomic_write_json(_generation_anchor_path(path), record)


def _check_generation_anchor(path: Path, payload: dict[str, Any], anchor_key: bytes | bytearray,
                             vault_id: str = "", *, require_mac: bool = False) -> bool:
    """Enforce the anchor; return True when a required anchor was missing (and was re-minted).

    ``rollback_anchor_required`` lives inside the authenticated payload, so a
    deleted anchor is reported instead of silently looking like a new vault.
    It is a warning rather than a refusal because copying a vault without its
    anchor (backup verification, restore into a new profile) is legitimate.
    """
    generation = int(payload.get("generation", 0))
    missing = (payload.get(ANCHOR_REQUIRED_KEY) is True
               and not _generation_anchor_path(path).exists())
    anchor, needs_upgrade = _read_generation_anchor(path, anchor_key, vault_id, require_mac=require_mac)
    if generation < anchor:
        raise VaultError(t("vault.err.rollbackOlder"))
    if generation > anchor or needs_upgrade:
        try:
            _write_generation_anchor(path, generation, anchor_key, vault_id)
        except OSError as exc:
            raise VaultError("Could not update vault rollback-protection metadata") from exc
    if missing:
        _LOG.warning("Vault rollback-protection anchor was missing; a new one was written.")
    return missing


def vault_migration_journal_path(path: Path) -> Path:
    """Return the journal used while promoting a vault to a newer format."""
    path = Path(path)
    return path.with_name(path.name + ".migration.json")


def _restore_bytes_atomically(path: Path, source: bytes) -> None:
    """Restore a known-good encrypted snapshot without test fault hooks."""
    path = Path(path)
    fd, name = tempfile.mkstemp(prefix=f".{path.name}.recover-", suffix=".tmp", dir=path.parent)
    temporary = Path(name)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(source)
            handle.flush()
            os.fsync(handle.fileno())
        replace_with_retry(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def _keep_before_restore_copy(path: Path, current: bytes) -> Path:
    """Copy the encrypted vault about to be replaced to ``Backups/before-restore-*.json``.

    Same name as the copy a backup restore keeps, so the key-rotation report
    finds it. If the copy cannot be written, nothing is restored.
    """
    directory = Path(path).parent / "Backups"
    try:
        directory.mkdir(parents=True, exist_ok=True)
        target = directory / f"before-restore-{time.time_ns()}.json"
        fd, name = tempfile.mkstemp(prefix=".lgk-", suffix=".tmp", dir=directory)
        temporary = Path(name)
        try:
            with os.fdopen(fd, "wb") as handle:
                handle.write(current)
                handle.flush()
                os.fsync(handle.fileno())
            replace_with_retry(temporary, target)
        finally:
            temporary.unlink(missing_ok=True)
    except OSError as exc:
        raise VaultError("Could not keep a copy of the vault before rolling back a migration") from exc
    return target


def _read_vault_migration_journal(path: Path) -> dict[str, Any] | None:
    journal_path = vault_migration_journal_path(path)
    try:
        raw = json.loads(journal_path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return None
    except (OSError, ValueError, RecursionError) as exc:
        raise VaultError("Vault migration journal is damaged; recovery is required") from exc
    if not isinstance(raw, dict):
        raise VaultError("Vault migration journal is malformed; recovery is required")
    try:
        version = int(raw.get("version", 0))
    except (TypeError, ValueError) as exc:
        raise VaultError("Vault migration journal version is malformed") from exc
    if version > VAULT_MIGRATION_JOURNAL_VERSION:
        raise VaultError("Vault migration journal was written by a newer version")
    if version < 1 or raw.get("operation") not in MIGRATION_OPERATIONS:
        raise VaultError("Unsupported vault migration journal")
    if version == 1 and raw.get("operation") != "catalog-v1-to-v2":
        raise VaultError("Unsupported vault migration journal")
    if raw.get("status") not in {"prepared", "publishing"}:
        raise VaultError("Vault migration journal status is unsupported")
    try:
        expected_path = Path(str(raw["vault_path"])).resolve()
        if expected_path != Path(path).resolve():
            raise ValueError
        backup = Path(str(raw["backup_path"])).resolve()
        backup.relative_to(Path(path).resolve().parent)
        if backup.is_symlink() or not backup.is_file():
            raise FileNotFoundError
        if len(str(raw["source_sha256"])) != 64 or len(str(raw["backup_sha256"])) != 64:
            raise ValueError
        source_generation = raw["source_generation"]
        if type(source_generation) is not int or not 0 <= source_generation <= 2**63 - 1:
            raise ValueError
        source_anchor = raw.get("source_anchor")
        if source_anchor is not None and (not isinstance(source_anchor, str) or len(source_anchor) > 128 * 1024):
            raise ValueError
    except (KeyError, TypeError, ValueError, OSError) as exc:
        raise VaultError("Vault migration journal is unsafe or incomplete") from exc
    return raw


def _recover_vault_migration(path: Path, *, in_process: bool = False) -> str | None:
    """Roll back an incomplete format promotion before opening the vault.

    The journal is unauthenticated (it is read before any key exists), so a
    journal found on disk may never lower the rollback anchor: the anchor on
    disk is kept, and a journal whose source generation is below it is
    discarded without restoring anything.  The anchor is only written after
    the promoted vault is published, so in that case the promotion completed.
    ``in_process`` is the failure path of a promotion this session just
    journaled; it restores the exact pre-migration anchor bytes as well.
    """
    path = Path(path)
    journal = _read_vault_migration_journal(path)
    if journal is None:
        return None
    if not in_process:
        anchor_generation, _upgrade = _read_generation_anchor(path)
        if anchor_generation > int(journal["source_generation"]):
            _LOG.warning("Discarded a vault migration journal older than the rollback anchor.")
            vault_migration_journal_path(path).unlink(missing_ok=True)
            return "discarded"
    backup = Path(str(journal["backup_path"])).resolve()
    backup_bytes = backup.read_bytes()
    if hashlib.sha256(backup_bytes).hexdigest() != str(journal["backup_sha256"]):
        raise VaultError("Vault migration backup failed authentication")
    current = path.read_bytes() if path.exists() else b""
    source_digest = str(journal["source_sha256"])
    if hashlib.sha256(current).hexdigest() != source_digest:
        if current and not in_process:
            # The journal is unauthenticated: keep the vault it would replace.
            _keep_before_restore_copy(path, current)
        _restore_bytes_atomically(path, backup_bytes)
        # A journal found on disk keeps the current anchor, so the restored
        # copy must still satisfy it at the next unlock.
        if in_process:
            anchor = _generation_anchor_path(path)
            source_anchor = journal.get("source_anchor")
            if isinstance(source_anchor, str):
                # Restore the exact pre-migration anchor bytes (MAC included).
                _restore_bytes_atomically(anchor, _b64d(source_anchor))
            else:
                anchor.unlink(missing_ok=True)
    vault_migration_journal_path(path).unlink(missing_ok=True)
    return "rolled_back"


# --------------------------------------------------------------------------
# Master-password attempt throttling
# --------------------------------------------------------------------------

_THROTTLE_LOCK = threading.Lock()
_THROTTLE_STATE: dict[str, dict[str, float]] = {}
# Per vault path: the binding this process last derived from a readable, current throttle key.
_THROTTLE_BINDINGS: dict[str, dict[str, str]] = {}


def _unlock_throttle_path(path: Path) -> Path:
    path = Path(path)
    return path.with_name(path.stem + ".unlock-throttle.json")


def _unlock_throttle_key_path(path: Path) -> Path:
    path = Path(path)
    return path.with_name(path.stem + ".unlock-throttle.key")


def _throttle_delay(failures: int) -> float:
    if failures < THROTTLE_FREE_ATTEMPTS:
        return 0.0
    return float(min(THROTTLE_MAX_SECONDS, THROTTLE_BASE_SECONDS * (2 ** (failures - THROTTLE_FREE_ATTEMPTS))))


def _reset_unlock_throttle_state_for_tests() -> None:
    with _THROTTLE_LOCK:
        _THROTTLE_STATE.clear()
        _THROTTLE_BINDINGS.clear()


def _throttle_location(path: Path) -> str:
    """Hash of the vault's absolute path: a copy elsewhere (a restore, a verified backup) is not bound."""
    text = os.path.normcase(str(Path(path).absolute()))
    return hashlib.sha256(b"localgatekeys|unlock-throttle-location|v1|" + text.encode("utf-8")).hexdigest()[:32]


def _throttle_key_id(key: bytes) -> str:
    return hmac.new(key, b"localgatekeys|unlock-throttle-key-id|v1", hashlib.sha256).hexdigest()[:32]


def _valid_throttle_binding(value: Any) -> bool:
    return (isinstance(value, dict) and set(value) == {"key_id", "location"}
            and all(isinstance(value[name], str) and len(value[name]) == 32
                    and all(c in "0123456789abcdef" for c in value[name]) for name in ("key_id", "location")))


class UnlockThrottle:
    """Persisted per-profile wrong-password counter with exponential backoff.

    The counter file is HMAC-protected with a per-profile random key (DPAPI
    sealed on Windows when available).  Timing uses a monotonic clock inside
    the process; after a restart the persisted counter re-arms a full wait so
    restarting the application never shortens the delay.

    Once a key exists the counter file is never removed: a reset writes a
    MAC'd zero record, and a missing counter next to a current (version 2)
    key fails closed, so deleting the counter file does not clear failures.
    Version 1 keys come from releases that deleted the counter on reset;
    they are upgraded at the next reset.

    Every save of a v3 vault records the current key's id and the vault's
    location in the authenticated header (``THROTTLE_BINDING_FIELD``).  At
    that location a missing, replaced or version-1 key then fails closed
    (the maximum delay, never a permanent lock-out), so deleting both files
    no longer clears the failures.  A vault without the field (older
    release, not saved since) keeps the behaviour above until its next save.
    """

    def __init__(self, path: Path):
        self.path = Path(path)
        self._id = str(self.path.absolute())

    # -- key handling -----------------------------------------------------
    def _key_record(self) -> dict[str, Any] | None:
        key_path = _unlock_throttle_key_path(self.path)
        try:
            raw = json.loads(key_path.read_text(encoding="utf-8")) if key_path.exists() else None
        except (OSError, ValueError, RecursionError):
            raw = None
        return raw if isinstance(raw, dict) else None

    def _key_version(self) -> int:
        record = self._key_record()
        version = record.get("version") if record is not None else None
        return version if type(version) is int else 0

    def _key(self, *, create: bool) -> bytes | None:
        raw = self._key_record()
        if isinstance(raw, dict):
            try:
                if isinstance(raw.get("dpapi"), str):
                    opened = _dpapi_unprotect(raw["dpapi"], ROLLBACK_ANCHOR_INFO)
                    if opened is not None and len(opened) == 32:
                        return opened
                elif isinstance(raw.get("key"), str):
                    key = _b64d(raw["key"])
                    if len(key) == 32:
                        return key
            except (ValueError, VaultError):
                pass
        if not create:
            return None
        key = os.urandom(32)
        return key if self._write_key_record(key) else None

    def _write_key_record(self, key: bytes) -> bool:
        key_path = _unlock_throttle_key_path(self.path)
        _THROTTLE_BINDINGS.pop(self._id, None)
        record: dict[str, Any] = {"version": 2}
        sealed = _dpapi_protect(key, "LocalGateKeys unlock throttle", ROLLBACK_ANCHOR_INFO)
        if sealed is not None:
            record["dpapi"] = sealed
        else:
            record["key"] = _b64e(key)
        try:
            atomic_write_json(key_path, record)
        except OSError:
            return False
        return True

    def _mac(self, key: bytes, failures: int, updated_at: int) -> str:
        body = _canonical_json({"failures": int(failures), "updated_at": int(updated_at), "profile": self.path.name})
        return _b64e(hmac.new(key, body, hashlib.sha256).digest())

    # -- persisted counter --------------------------------------------------
    def _header_binding(self) -> dict[str, str] | None:
        """The binding recorded in this vault's header at this location, if any (read before any key)."""
        try:
            if not self.path.is_file() or self.path.stat().st_size > MAX_VAULT_BYTES:
                return None
            header = json.loads(self.path.read_bytes())
        except (OSError, ValueError, RecursionError):  # deep nesting: _read_vault_header refuses it
            return None
        if not isinstance(header, dict) or header.get("version") != FORMAT_VERSION:
            return None
        binding = header.get(THROTTLE_BINDING_FIELD)
        if not _valid_throttle_binding(binding) or binding["location"] != _throttle_location(self.path):
            return None
        return binding

    def _binding_broken(self) -> bool:
        binding = self._header_binding()
        if binding is None:
            return False
        key = self._key(create=False)
        return (key is None or self._key_version() < 2
                or not hmac.compare_digest(_throttle_key_id(key), binding["key_id"]))

    def binding(self) -> dict[str, str] | None:
        """The header binding for the next save; creates (or upgrades) the key and its counter when needed."""
        with _THROTTLE_LOCK:
            cached = _THROTTLE_BINDINGS.get(self._id)
            if cached is not None:
                return dict(cached)
            state = self._state()
            key = self._key(create=False)
            fresh = key is None
            if key is None:
                key = self._key(create=True)
                if key is None:
                    return None
            elif self._key_version() < 2 and not self._write_key_record(key):
                return None
            if fresh or not _unlock_throttle_path(self.path).exists():
                self._store_failures(int(state["failures"]), key=key)
                if not _unlock_throttle_path(self.path).exists():
                    return None
            binding = {"key_id": _throttle_key_id(key), "location": _throttle_location(self.path)}
            _THROTTLE_BINDINGS[self._id] = binding
            return dict(binding)

    def _load_failures(self) -> int:
        state_path = _unlock_throttle_path(self.path)
        if self._binding_broken():
            _LOG.warning("Unlock attempt key for %s is missing or replaced; failing closed.", self.path.name)
            return THROTTLE_FAIL_CLOSED_FAILURES
        if not state_path.exists():
            if self._key_version() >= 2:
                # A current key always has a counter beside it: a missing
                # counter was deleted, which must not clear the failures.
                _LOG.warning("Unlock attempt counter for %s is missing; failing closed.", self.path.name)
                return THROTTLE_FAIL_CLOSED_FAILURES
            return 0
        try:
            if state_path.stat().st_size > 4096:
                raise ValueError
            raw = read_json(state_path)
            failures, updated_at, mac = raw.get("failures"), raw.get("updated_at"), raw.get("mac")
            if type(failures) is not int or type(updated_at) is not int or not isinstance(mac, str):
                raise ValueError
            key = self._key(create=False)
            if key is None or not hmac.compare_digest(mac, self._mac(key, failures, updated_at)):
                raise ValueError
            return max(0, failures)
        except (OSError, ValueError, TypeError, AttributeError):
            _LOG.warning("Unlock attempt counter for %s is unreadable or forged; failing closed.", self.path.name)
            return THROTTLE_FAIL_CLOSED_FAILURES

    def _store_failures(self, failures: int, *, key: bytes | None = None) -> None:
        state_path = _unlock_throttle_path(self.path)
        failures = max(0, int(failures))
        try:
            if key is not None:
                pass  # binding(): the key was just created or checked
            elif failures == 0:
                if self._key_record() is None:
                    # No failure was ever persisted: nothing to keep.
                    state_path.unlink(missing_ok=True)
                    return
                # An unreadable key (profile copied to another Windows
                # account) is replaced so the zero record can be authenticated.
                key = self._key(create=False)
                if key is None:
                    key = self._key(create=True)
                elif self._key_version() < 2:
                    # Upgrade a key from a release that deleted the counter on reset.
                    self._write_key_record(key)
                if key is None:
                    return
            else:
                key = self._key(create=True)
                if key is None:
                    return
            updated_at = int(time.time())
            atomic_write_json(state_path, {"version": 1, "failures": failures, "updated_at": updated_at,
                                           "mac": self._mac(key, failures, updated_at)})
        except OSError:
            # Persistence is best effort; the in-process state still applies.
            pass

    def _state(self) -> dict[str, float]:
        state = _THROTTLE_STATE.get(self._id)
        if state is None:
            failures = self._load_failures()
            state = {"failures": float(failures), "not_before": _monotonic() + _throttle_delay(failures)}
            _THROTTLE_STATE[self._id] = state
        return state

    # -- public surface -----------------------------------------------------
    @property
    def failures(self) -> int:
        with _THROTTLE_LOCK:
            return int(self._state()["failures"])

    def remaining_backoff_seconds(self) -> float:
        with _THROTTLE_LOCK:
            return max(0.0, self._state()["not_before"] - _monotonic())

    def check(self) -> None:
        remaining = self.remaining_backoff_seconds()
        if remaining > 0:
            raise UnlockThrottled(remaining)

    def record_failure(self) -> None:
        with _THROTTLE_LOCK:
            state = self._state()
            failures = int(state["failures"]) + 1
            state["failures"] = float(failures)
            state["not_before"] = _monotonic() + _throttle_delay(failures)
            self._store_failures(failures)

    def reset(self) -> None:
        with _THROTTLE_LOCK:
            _THROTTLE_STATE[self._id] = {"failures": 0.0, "not_before": _monotonic()}
            self._store_failures(0)


def unlock_throttle(path: Path) -> UnlockThrottle:
    return UnlockThrottle(path)


def remaining_backoff_seconds(path: Path) -> float:
    """Seconds until the next master-password attempt for this vault is accepted."""
    return UnlockThrottle(path).remaining_backoff_seconds()


# --------------------------------------------------------------------------

# Password history (UX plan workstream 8). Up to 10 rows are read; rows older than 365 days are
# dropped when the next password change is written. This
# release still writes at most 5: Windows 0.4.9 and the iPhone refuse synced records with more than
# 5 rows, so the write limit is raised in a later release, once every reader accepts 10.
PASSWORD_HISTORY_WRITE_LIMIT = 5
PASSWORD_HISTORY_READ_LIMIT = 10
PASSWORD_HISTORY_MAX_AGE = 365 * 24 * 3600


def push_password_history(history: Any, previous: str, now: int) -> list[dict[str, Any]]:
    """The history after ``previous`` was replaced at ``now``: newest first, capped and aged out."""
    rows = [row for row in (history if isinstance(history, list) else []) if isinstance(row, dict)]
    rows.insert(0, {"password": previous, "changed_at": now})
    cutoff = now - PASSWORD_HISTORY_MAX_AGE
    kept = [row for row in rows if not isinstance(row.get("changed_at"), int) or row["changed_at"] >= cutoff]
    return kept[:PASSWORD_HISTORY_WRITE_LIMIT]


# Recovery phrase (BIP39 English, 24 words = 256 bits of entropy + checksum)
# --------------------------------------------------------------------------

_BIP39_WORDS: list[str] | None = None


def bip39_words() -> list[str]:
    """Load and verify the bundled BIP39 English list exactly once."""
    global _BIP39_WORDS
    if _BIP39_WORDS is None:
        source = Path(__file__).with_name("assets") / "bip39_english.txt"
        try:
            words = source.read_text(encoding="utf-8").split()
        except OSError as exc:
            raise VaultError("The recovery word list is missing from this installation") from exc
        digest = hashlib.sha256(("\n".join(words) + "\n").encode("utf-8")).hexdigest()
        if len(words) != 2048 or digest != BIP39_ENGLISH_SHA256:
            raise VaultError("The recovery word list is damaged; recovery phrases are unavailable")
        _BIP39_WORDS = words
    return _BIP39_WORDS


def phrase_from_entropy(entropy: bytes) -> str:
    if len(entropy) != 32:
        raise RecoveryPhraseError("Recovery entropy must be 256 bits")
    words = bip39_words()
    checksum = hashlib.sha256(entropy).digest()[0]  # first 8 bits for 256-bit entropy
    bits = int.from_bytes(entropy, "big") << 8 | checksum
    indices = [(bits >> (11 * (23 - position))) & 0x7FF for position in range(24)]
    return " ".join(words[index] for index in indices)


def normalize_recovery_phrase(text: str) -> list[str]:
    if not isinstance(text, str) or len(text) > 2048:
        raise RecoveryPhraseError(t("vault.err.recoveryMalformed"))
    tokens = unicodedata.normalize("NFKD", text).casefold().split()
    if len(tokens) != 24:
        raise RecoveryPhraseError(t("vault.err.recovery24Words"))
    return tokens


def entropy_from_phrase(text: str) -> bytes:
    words = bip39_words()
    lookup = {word: index for index, word in enumerate(words)}
    tokens = normalize_recovery_phrase(text)
    bits = 0
    for token in tokens:
        index = lookup.get(token)
        if index is None:
            raise RecoveryPhraseError(t("vault.err.recoveryUnknownWord"))
        bits = (bits << 11) | index
    checksum = bits & 0xFF
    entropy = (bits >> 8).to_bytes(32, "big")
    if hashlib.sha256(entropy).digest()[0] != checksum:
        raise RecoveryPhraseError(t("vault.err.recoveryChecksum"))
    return entropy


def _recovery_key(entropy: bytes, salt: bytes) -> bytearray:
    return _hkdf(entropy, RECOVERY_KEY_INFO, salt=salt)


def recovery_phrase_enrolled(path: Path) -> bool:
    """Report whether a recovery-phrase wrapper exists without decrypting anything."""
    try:
        header, _source = _read_vault_header(Path(path))
    except (VaultError, OSError):
        return False
    wrappers = header.get("wrappers") if _header_version(header) == FORMAT_VERSION else None
    return isinstance(wrappers, dict) and isinstance(wrappers.get("recovery"), dict)


@dataclass(frozen=True)
class EntrySummary:
    id: str
    kind: str
    label: str
    username: str
    scope: dict[str, Any]
    created_at: int
    updated_at: int
    favorite: bool = False
    tags: tuple[str, ...] = ()



MAX_SITE_ICON_BYTES = 32 * 1024
PNG_SIGNATURE = bytes.fromhex("89504e470d0a1a0a")


def _decode_site_icon(value: Any) -> bytes | None:
    if not isinstance(value, str) or not value or len(value) > MAX_SITE_ICON_BYTES * 2:
        return None
    try:
        data = base64.b64decode(value, validate=True)
    except (ValueError, TypeError):
        return None
    return data if data.startswith(PNG_SIGNATURE) else None


_LOGIN_SUBDOMAINS = ("www.", "app.", "login.", "accounts.", "account.", "auth.", "signin.", "secure.", "my.", "id.")


def friendly_origin_label(origin: str) -> str:
    """Short default name for a website login: ``https://app.example.com:8443``
    becomes ``example.com``. Falls back to the origin when it has no host."""
    host = origin.split("://", 1)[-1].split("/", 1)[0].rsplit(":", 1)[0] if "://" in origin else origin
    if host.startswith("["):
        return origin
    for prefix in _LOGIN_SUBDOMAINS:
        if host.startswith(prefix) and host.count(".") >= 2:
            host = host[len(prefix):]
            break
    return host or origin


def _under_session_lock(method: Any) -> Any:
    """Run a VaultSession method that writes with the data key under the session lock.

    lock() takes the same lock, so it waits for the write instead of zeroing
    the key half way through it (a vault encrypted under a zeroed key).
    """
    @functools.wraps(method)
    def wrapper(self: VaultSession, *args: Any, **kwargs: Any) -> Any:
        with self._state_lock:
            return method(self, *args, **kwargs)
    return wrapper


class VaultSession:
    """Unlocked in-memory view of the encrypted vault.

    Python cannot guarantee that every immutable string copy is scrubbed from
    process memory. lock() clears owned mutable key bytes and drops the payload;
    production hardening should move key handling into a native, locked-memory
    component.
    """

    def __init__(
        self,
        path: Path,
        header: dict[str, Any],
        key: bytearray,
        payload: dict[str, Any],
        *,
        backup_dir: Path | None = None,
        backup_count: int = 0,
    ):
        self.path = path
        # Serializes lock() with saves, transactions and other writes that use
        # the data key.  Re-entrant: transaction bodies call save() and other
        # session methods on the same thread.  Session code never takes the
        # controller's vault_lock, so the controller -> session order holds.
        self._state_lock = threading.RLock()
        self._header = copy.deepcopy(header)
        self._catalog_version = _catalog_version_of(header)
        # Data key (DK).  For v1/v2 envelopes this is still the Argon2 output;
        # the first save promotes the envelope to v3 and keeps DK as-is.
        self._key: bytearray | None = key
        # Per-unlock HMAC key for login edit tokens; never persisted and
        # scrubbed by lock(), so tokens never survive a lock/unlock cycle.
        self._edit_token_key: bytearray | None = bytearray(secrets.token_bytes(32))
        self._payload: dict[str, Any] | None = payload
        self._last_envelope_upgrade_result: dict[str, Any] | None = None
        self._pending_v3_header: dict[str, Any] | None = None
        self.reenroll_required: tuple[str, ...] = ()
        self.recovery_unlocked = False
        # Entropy of the recovery phrase that opened a ``recovery_unlocked``
        # session, kept only until the new master password is set so the same
        # phrase can be re-wrapped under the rotated data key; lock() zeroes it.
        self._recovery_entropy: bytearray | None = None
        # Public, non-secret unlock-generation identity for controllers that
        # must reject in-flight work after lock/profile replacement.  It is
        # deliberately independent of catalog contents and survives the
        # locked state long enough for a bound controller to fail closed.
        self._workspace_session_generation = uuid.uuid4().hex
        self._committed_payload = copy.deepcopy(payload)
        self._last_catalog_migration_result: dict[str, Any] | None = None
        self._disk_digest = hashlib.sha256(path.read_bytes()).digest() if path.exists() else None
        self._reminder_service = None
        self._reminder_scheduler = None
        self.backup_warning = False
        # True when the encrypted payload says a rollback anchor must exist but
        # none was found at unlock (deleted, or the vault was copied without
        # it).  A new anchor has been written; callers should tell the user.
        self.rollback_anchor_missing = False
        self._suppress_rolling_backup = False
        self.trash_retention_days = 30
        # Non-secret result of the last recovery-phrase create / replace / remove.
        self.last_recovery_phrase_change: dict[str, Any] | None = None
        self.trash_auto_purge = True
        self._batch_depth = 0
        self.backup_dir = backup_dir
        self.backup_count = max(0, min(int(backup_count), 20))
        # Free plan limit on live items; None means unlimited (Pro).  Set by
        # the app from licensing after unlock.  Sync apply never checks it.
        self.item_limit: int | None = None
        # Pro-only features this session may add or change (licensing.Feature
        # values); None means unrestricted.  Set by the app with item_limit.
        self.pro_features: frozenset[str] | None = None
        # Lowest generation the next save may write (raise_generation_floor).
        self._generation_floor = 0

    @property
    def is_unlocked(self) -> bool:
        return self._key is not None and self._payload is not None

    @property
    def workspace_session_generation(self) -> str:
        """Return the opaque identity of this unlock/session generation."""
        return self._workspace_session_generation

    def _require_payload(self) -> dict[str, Any]:
        if self._payload is None or self._key is None:
            raise VaultLockedError(t("vault.err.locked"))
        return self._payload

    @property
    def catalog_version(self) -> int:
        return self._catalog_version

    @property
    def generation(self) -> int:
        """The committed vault generation (``payload["generation"]``); it grows with every save.

        Sync publishes it so peers can tell when this vault went back to an older copy.
        """
        if self._committed_payload is None:
            raise VaultLockedError(t("vault.err.locked"))
        return int(self._committed_payload.get("generation", 0))

    def raise_generation_floor(self, minimum: int) -> None:
        """Make the next save write a generation of at least *minimum* (never lowers it)."""
        if type(minimum) is not int or not 0 <= minimum <= 2**63 - 1:
            raise VaultError("Generation floor is malformed")
        self._generation_floor = max(self._generation_floor, minimum)

    @property
    def last_catalog_migration_result(self) -> dict[str, Any] | None:
        """Return the committed result of the most recent catalog migration."""
        return copy.deepcopy(self._last_catalog_migration_result)

    # Explicit method alias for callers that avoid property access in UI code.
    def catalog_migration_result(self) -> dict[str, Any] | None:
        return self.last_catalog_migration_result

    def _require_typed_catalog(self) -> dict[str, Any]:
        payload = self._require_payload()
        if self._catalog_version != CATALOG_VERSION or payload.get("version") != CATALOG_VERSION:
            raise VaultError(t("vault.err.legacyCatalog"))
        return payload

    @property
    def item_service(self):
        """Return the typed-item service bound to this session.

        Imports stay lazy to keep the vault's credential parser independent of
        the domain service modules and to avoid a module import cycle.
        """
        from .item_service import ItemService
        return ItemService(self)

    @property
    def history(self):
        """Return typed immutable revision history for this unlock generation."""
        self._require_typed_catalog()
        from .history import HistoryService
        return HistoryService(self)

    @property
    def relationship_service(self):
        """Return the canonical encrypted relationship edge service."""
        self._require_typed_catalog()
        from .relationships import RelationshipService
        return RelationshipService(self)

    @property
    def relationships(self):
        return self.relationship_service

    @property
    def smart_view_service(self):
        """Return profile-local metadata-only saved views."""
        self._require_typed_catalog()
        from .smart_views import SmartViewService
        return SmartViewService(self)

    @property
    def smart_views(self):
        return self.smart_view_service

    # Short aliases make the aggregate boundary explicit for callers while
    # retaining the longer names for code that prefers service terminology.
    @property
    def items(self):
        return self.item_service

    @property
    def collection_service(self):
        from .collections import CollectionService
        return CollectionService(self)

    @property
    def collections(self):
        return self.collection_service

    @property
    def template_service(self):
        from .templates import TemplateService
        return TemplateService(self)

    @property
    def templates(self):
        return self.template_service

    @property
    def activity_service(self):
        from .activity import ActivityService
        return ActivityService(self)

    @property
    def activity(self):
        return self.activity_service

    @property
    def reminder_service(self):
        """Return the reminder service only for an unlocked v2 catalog."""
        self._require_typed_catalog()
        if self._reminder_service is None:
            from .reminders import ReminderService
            self._reminder_service = ReminderService(self)
        return self._reminder_service

    @property
    def reminders(self):
        return self.reminder_service

    @property
    def reminder_scheduler(self):
        """Return the in-memory scheduler bound to this unlocked session."""
        self._require_typed_catalog()
        if self._reminder_scheduler is None:
            from .reminders import ReminderScheduler
            self._reminder_scheduler = ReminderScheduler(self.reminder_service)
        return self._reminder_scheduler

    @property
    def attachment_store(self):
        from .attachments import AttachmentStore
        return AttachmentStore(self)

    @property
    def attachments(self):
        return self.attachment_store

    @property
    def document_service(self):
        from .attachments import DocumentService
        return DocumentService(self)

    @property
    def documents(self):
        return self.document_service

    def _verified_pre_migration_backup(self) -> Path:
        """Create and authenticate an encrypted v1 snapshot before promotion."""
        if self._key is None or not self.path.exists():
            raise VaultLockedError(t("vault.err.keyUnavailable"))
        source_bytes = self.path.read_bytes()
        if self._disk_digest is not None and hashlib.sha256(source_bytes).digest() != self._disk_digest:
            raise VaultError(t("vault.err.changedOnDiskMigrate"))
        directory = self.backup_dir or (self.path.parent / "Backups")
        directory.mkdir(parents=True, exist_ok=True)
        destination = directory / f"migration-v{_header_version(self._header)}-{time.time_ns()}.json"
        # Keep the exact encrypted bytes so restart recovery can restore the
        # pre-migration envelope, including its authenticated header encoding.
        fd, name = tempfile.mkstemp(prefix=".lgk-migration-", suffix=".tmp", dir=directory)
        temporary = Path(name)
        try:
            with os.fdopen(fd, "wb") as handle:
                handle.write(source_bytes)
                handle.flush()
                os.fsync(handle.fileno())
            replace_with_retry(temporary, destination)
        finally:
            temporary.unlink(missing_ok=True)
        try:
            backup_header, backup_bytes = _read_vault_header(destination)
            probe = _decrypt_vault(
                destination,
                backup_header,
                backup_bytes,
                bytearray(self._key),
                backup_dir=None,
                backup_count=0,
                check_anchor=False,
            )
            probe.lock()
        except BaseException:
            destination.unlink(missing_ok=True)
            raise VaultError("Could not verify the encrypted pre-migration backup") from None
        return destination

    @property
    def last_envelope_upgrade_result(self) -> dict[str, Any] | None:
        """Result of the v2-to-v3 envelope promotion performed by this unlock, if any."""
        return copy.deepcopy(self._last_envelope_upgrade_result)

    def _promoted_header(self, *, catalog_version: int, password: SecretText | None = None) -> dict[str, Any]:
        """Return a v3 header carrying the current data key.

        A v3 header (or one prepared at unlock time) is copied.  Otherwise the
        master password is required to create the password wrapper, because
        the KEK must get a fresh salt so an upgraded vault never wraps its data
        key with itself.
        """
        if self._key is None:
            raise VaultLockedError(t("vault.err.keyUnavailable"))
        catalog = CATALOG_FORMAT if catalog_version == CATALOG_VERSION else LEGACY_CATALOG_IDENTIFIER
        source = self._header if _header_version(self._header) == FORMAT_VERSION else self._pending_v3_header
        if source is not None:
            header = copy.deepcopy(source)
            header["catalog_version"] = int(catalog_version)
            header["catalog"] = catalog
            return header
        if password is None:
            raise VaultError(t("vault.err.upgradeNeedsPassword"))
        current_kdf = self._header.get("kdf", {})
        base = {name: current_kdf[name] for name in ("time_cost", "memory_cost_kib", "parallelism", "hash_len")
                if name in current_kdf}
        header: dict[str, Any] = {
            "version": FORMAT_VERSION,
            "format": FORMAT_V3_IDENTIFIER,
            "catalog": catalog,
            "catalog_version": int(catalog_version),
            "vault_id": uuid.uuid4().hex,
            "generation": int((self._payload or {}).get("generation", 0)),
            "key_generation": 1,
            "kdf": {},
            "wrappers": {},
            "cipher": {"name": "aes-256-gcm", "nonce": "", "ciphertext": ""},
        }
        header["wrappers"]["password"] = self._password_wrapper(
            header, password, {**DEFAULT_KDF, **base, "salt": _b64e(os.urandom(16))})
        return header

    def _prepare_promotion(self, password: SecretText) -> None:
        """Remember a v3 header for a v1/v2 session so its first save publishes v3."""
        if _header_version(self._header) == FORMAT_VERSION or self._pending_v3_header is not None:
            return
        self._pending_v3_header = self._promoted_header(catalog_version=self._catalog_version, password=password)

    @_under_session_lock
    def _journaled_promotion(self, operation: str, header: dict[str, Any], payload: dict[str, Any],
                             catalog_version: int, *, before_save: Any = None) -> Path:
        """Publish a new header/payload under a crash-safe journal; returns the backup path."""
        _recover_vault_migration(self.path)
        old_header = copy.deepcopy(self._header)
        old_payload = copy.deepcopy(self._require_payload())
        old_committed = copy.deepcopy(self._committed_payload)
        old_catalog_version = self._catalog_version
        source_bytes = self.path.read_bytes()
        anchor_path = _generation_anchor_path(self.path)
        source_anchor = _b64e(anchor_path.read_bytes()) if anchor_path.exists() else None
        pre_migration_backup = self._verified_pre_migration_backup()
        journal_path = vault_migration_journal_path(self.path)
        journal = {
            "version": VAULT_MIGRATION_JOURNAL_VERSION,
            "operation": operation,
            "status": "prepared",
            "vault_path": str(self.path.resolve()),
            "backup_path": str(pre_migration_backup.resolve()),
            "source_sha256": hashlib.sha256(source_bytes).hexdigest(),
            "backup_sha256": hashlib.sha256(pre_migration_backup.read_bytes()).hexdigest(),
            "source_generation": int(old_payload.get("generation", 0)),
            "source_anchor": source_anchor,
        }
        atomic_write_json(journal_path, journal)
        self._catalog_version = int(catalog_version)
        self._header = header
        self._payload = payload
        try:
            atomic_write_json(journal_path, {**journal, "status": "publishing"})
            if before_save is not None:
                before_save()
            self.save()
            journal_path.unlink(missing_ok=True)
        except BaseException:
            if journal_path.exists():
                _recover_vault_migration(self.path, in_process=True)
            self._catalog_version = old_catalog_version
            self._header = old_header
            self._payload = old_payload
            self._committed_payload = old_committed
            self._disk_digest = hashlib.sha256(self.path.read_bytes()).digest() if self.path.exists() else None
            raise
        return pre_migration_backup

    def migrate_to_v2(self) -> bool:
        """Promote a v1 credential vault to catalog v2 without losing records.

        The old encrypted file remains untouched until a verified encrypted
        snapshot exists and the normal exclusive, authenticated save succeeds.
        The published envelope is format v3.  Calling this on a v2 catalog is
        an idempotent no-op.
        """
        self._last_catalog_migration_result = None
        _recover_vault_migration(self.path)
        payload = self._require_payload()
        if self._catalog_version == CATALOG_VERSION and payload.get("version") == CATALOG_VERSION:
            return False
        if self._catalog_version != LEGACY_FORMAT_VERSION or payload.get("version") != LEGACY_FORMAT_VERSION:
            raise VaultError("Unsupported vault version for migration")

        migrated = copy.deepcopy(payload)
        migrated.update(
            {
                "version": CATALOG_VERSION,
                "catalog": CATALOG_FORMAT,
                "items": [],
                "collections": [],
                "templates": [],
                "events": [],
            }
        )
        header = self._promoted_header(catalog_version=CATALOG_VERSION)
        pre_migration_backup = self._journaled_promotion("catalog-v1-to-v2", header, migrated, CATALOG_VERSION)
        self._last_catalog_migration_result = {
            "success": True,
            "outcome": "migrated",
            "backup_path": str(pre_migration_backup.resolve()),
        }
        return True

    def _upgrade_envelope_on_unlock(self) -> None:
        """Promote a v2 envelope to v3 right after a master-password unlock.

        The data key is inherited, so the Windows Hello / camera sidecars only
        need their vault context rewritten.  Sidecars that cannot be converted
        are revoked inside the authenticated payload and reported through
        ``reenroll_required``.  A failed publication is recovered from the
        journal and reported; the session stays usable as a v2 session.
        """
        payload = self._require_payload()
        if _header_version(self._header) != CATALOG_ENVELOPE_VERSION:
            return
        from_version = _header_version(self._header)
        old_context = unlock_context_for_header(self._header)
        header = self._promoted_header(catalog_version=self._catalog_version)
        new_context = unlock_context_for_header(header)
        converted: list[str] = []
        reenroll: list[str] = []
        prefs = payload.get("preferences", {})
        prefs = prefs if isinstance(prefs, dict) else {}
        from .face_unlock import upgrade_envelope_context as upgrade_face
        from .hello_unlock import upgrade_envelope_context as upgrade_hello
        upgraded_payload = copy.deepcopy(payload)
        upgraded_prefs = upgraded_payload.setdefault("preferences", {})
        for name, binding_key, convert in (("face", "face_binding", upgrade_face),
                                           ("hello", "hello_binding", upgrade_hello)):
            if not prefs.get(binding_key):
                continue
            if convert(self.path, old_context, new_context):
                converted.append(name)
            else:
                reenroll.append(name)
                if isinstance(upgraded_prefs, dict):
                    upgraded_prefs.pop(binding_key, None)
        try:
            backup = self._journaled_promotion("envelope-v2-to-v3", header, upgraded_payload, self._catalog_version)
        except VaultError as exc:
            self.reenroll_required = ()
            self._last_envelope_upgrade_result = {
                "outcome": "failed", "from_version": from_version, "to_version": FORMAT_VERSION,
                "error": str(exc),
            }
            _LOG.warning("Vault envelope upgrade deferred: %s", exc)
            return
        self.reenroll_required = tuple(sorted(reenroll))
        self._last_envelope_upgrade_result = {
            "outcome": "upgraded", "from_version": from_version, "to_version": FORMAT_VERSION,
            "backup_path": str(backup.resolve()), "data_key": "inherited",
            "converted": sorted(converted), "reenroll_required": sorted(reenroll),
        }

    # Compatibility spelling for migration callers from the implementation
    # plan and for profile lifecycle code that treats it as a command.
    migrate = migrate_to_v2

    def summaries(self) -> list[EntrySummary]:
        entries = self._require_payload()["entries"]
        return [
            EntrySummary(
                id=str(item["id"]),
                kind=str(item["kind"]),
                label=str(item["label"]),
                username=str(item["username"]),
                scope=copy.deepcopy(item["scope"]),
                created_at=int(item.get("created_at", 0)),
                updated_at=int(item.get("updated_at", 0)),
                favorite=bool(item.get("favorite", False)),
                tags=tuple(item.get("tags", [])),
            )
            for item in entries
        ]

    def item_summaries(self) -> list[ItemSummary]:
        """Return typed-item metadata only; no note/bookmark payload is read."""
        payload = self._require_typed_catalog()
        return [summary_from_item(item) for item in payload.get("items", [])]

    # Explicit alias for callers that want to make the non-secret boundary
    # visible in their code.
    metadata_summaries = item_summaries

    def get_entry(self, entry_id: str) -> dict[str, Any] | None:
        for item in self._require_payload()["entries"]:
            if secrets.compare_digest(str(item.get("id", "")).encode("utf-8"), str(entry_id).encode("utf-8")):
                return copy.deepcopy(item)
        return None

    def credential_detail(self, entry_id: str) -> dict[str, Any] | None:
        """Return credential details without password or password history.

        ``revision`` is this credential's conflict token (``entry_revision``):
        it changes only when this credential changes, so sync bookkeeping and
        saves of other items do not invalidate an open window.  Callers present
        it again before asking for the password or saving.
        """
        payload = self._require_payload()
        for item in payload["entries"]:
            if not secrets.compare_digest(str(item.get("id", "")).encode("utf-8"), str(entry_id).encode("utf-8")):
                continue
            detail = copy.deepcopy(item)
            detail.pop("password", None)
            detail.pop("password_history", None)
            detail["revision"] = self._entry_revision(item)
            return detail
        return None

    get_credential_detail = credential_detail

    def credential_secret(self, entry_id: str, *, expected_revision: int | None = None) -> str:
        """Return only the requested current password after a per-credential revision check."""
        payload = self._require_payload()
        for item in payload["entries"]:
            if secrets.compare_digest(str(item.get("id", "")).encode("utf-8"), str(entry_id).encode("utf-8")):
                if expected_revision is not None and not _same_revision(expected_revision, self._entry_revision(item)):
                    raise VaultError(t("vault.err.changedBeforeReveal"))
                return str(item.get("password", ""))
        raise VaultError(t("vault.err.credentialGone"))

    def entry_revision(self, entry_id: str) -> int:
        """This credential's conflict token (see ``credential_detail``); VaultError if it is gone."""
        item = next((e for e in self._require_payload()["entries"] if e.get("id") == entry_id), None)
        if item is None:
            raise VaultError(t("vault.err.credentialGone"))
        return self._entry_revision(item)

    def _entry_revision(self, item: Mapping[str, Any]) -> int:
        """Per-credential token: the first 60 bits of ``_entry_token`` as an int (fits JSON and int checks)."""
        return int(self._entry_token(item)[:15], 16)

    get_credential_secret = credential_secret

    def find_web(self, origin: str) -> list[dict[str, Any]]:
        wanted = canonicalize_origin(origin)
        matches = []
        for item in self._require_payload()["entries"]:
            if item.get("kind") != "web":
                continue
            stored = item.get("scope", {}).get("origin")
            if isinstance(stored, str) and secrets.compare_digest(stored, wanted):
                matches.append(copy.deepcopy(item))
        return sorted(matches, key=lambda entry: int(entry.get("updated_at", 0)), reverse=True)

    def find_desktop(self, exe_path: str) -> list[dict[str, Any]]:
        normalized = os.path.normcase(os.path.abspath(exe_path))
        from .uia import _is_discord_executable

        is_discord = _is_discord_executable(exe_path)
        matches = []
        for item in self._require_payload()["entries"]:
            if item.get("kind") != "desktop":
                continue
            stored = item.get("scope", {}).get("exe_path")
            if not isinstance(stored, str):
                continue
            stored_normalized = os.path.normcase(os.path.abspath(stored))
            same_path = secrets.compare_digest(
                stored_normalized.encode("utf-8"), normalized.encode("utf-8")
            )
            # Discord installs each update below a new app-* directory. Its
            # desktop login is intentionally stable across those directories;
            # all other applications remain exact-path scoped.
            same_discord_app = (
                is_discord
                and str(item.get("scope", {}).get("binding_mode", "")).casefold() == "discord_stable"
                and _is_discord_executable(stored)
            )
            if same_path or same_discord_app:
                matches.append(copy.deepcopy(item))
        return sorted(matches, key=lambda entry: int(entry.get("updated_at", 0)), reverse=True)

    def _validated_web_login(self, origin: str, username: str, password: str,
                             label: str | None) -> tuple[str, str, str, str, str | None]:
        """Validate website-login input exactly as ``upsert_web`` always has."""
        canonical = canonicalize_origin(origin)
        username = _validated_text(username, "username", 512, allow_empty=True)
        password = _validated_text(password, "password", 4096, allow_empty=False)
        explicit_label = label
        label = _validated_text(label or friendly_origin_label(canonical), "label", 512, allow_empty=False)
        return canonical, username, password, label, explicit_label

    def _web_login_match(self, canonical: str, username: str, *,
                         exclude_id: str | None = None) -> dict[str, Any] | None:
        """Return the live website login with this canonical origin and username.

        This is the one duplicate rule for website logins: same kind, same
        canonical ``scope.origin`` and the exact same username.
        """
        for item in self._require_payload()["entries"]:
            if (
                item.get("kind") == "web"
                and item.get("scope", {}).get("origin") == canonical
                and item.get("username") == username
                and (exclude_id is None or item.get("id") != exclude_id)
            ):
                return item
        return None

    def _append_web_entry(self, canonical: str, username: str, password: str, label: str, now: int) -> str:
        """Append a new website login to the in-memory payload without saving."""
        entry_id = str(uuid.uuid4())
        self._require_payload()["entries"].append(
            {
                "id": entry_id,
                "kind": "web",
                "label": label,
                "username": username,
                "password": password,
                "scope": {"origin": canonical},
                "created_at": now,
                "updated_at": now,
            }
        )
        self._require_payload()["updated_at"] = now
        return entry_id

    def upsert_web(
        self,
        *,
        origin: str,
        username: str,
        password: str,
        label: str | None = None,
    ) -> str:
        canonical, username, password, label, explicit_label = self._validated_web_login(
            origin, username, password, label)
        now = int(time.time())
        item = self._web_login_match(canonical, username)
        if item is not None:
            if item.get("password") != password:
                item["password_history"] = push_password_history(
                    item.get("password_history"), item.get("password", ""), now)
            item.update({"password": password, "updated_at": now})
            # Keep a name the user chose; only an explicit label renames it.
            if explicit_label:
                item["label"] = label
            self._require_payload()["updated_at"] = now
            self.save()
            return str(item["id"])

        self._check_can_create()
        entry_id = self._append_web_entry(canonical, username, password, label, now)
        self.save()
        return entry_id

    def find_web_login(self, origin: str, username: str) -> str | None:
        """Return the id of the website login ``upsert_web`` would update, if any.

        ``origin`` may also be a full URL; it is reduced to its origin first.
        """
        canonical = canonicalize_origin(origin_of(origin))
        username = _validated_text(username, "username", 512, allow_empty=True)
        item = self._web_login_match(canonical, username)
        return str(item["id"]) if item is not None else None

    def create_web_login(
        self,
        *,
        urls: list[dict[str, Any]],
        username: str,
        password: str,
        label: str | None = None,
        favorite: bool = False,
        tags: list[str] = (),
        notes: str = "",
        totp: dict[str, Any] | None = None,
        recovery_codes: list[str] = (),
        custom_fields: list[dict[str, Any]] = (),
        policy: dict[str, Any] | None = None,
    ) -> str:
        """Create a new website login with its details and URL rows in one commit.

        Unlike ``upsert_web`` this never updates an existing login: a login
        with the same site and username raises ``DuplicateLoginError``.
        """
        from .item_schema import migrate_web_scope

        if not isinstance(urls, list) or not urls or not isinstance(urls[0], dict):
            raise VaultError(t("vault.err.loginNeedsUrl"))
        try:
            existing = self.find_web_login(urls[0].get("url", ""), username)
        except OriginError as exc:
            raise VaultError(f"url is malformed: {exc}") from None
        if existing is not None:
            raise DuplicateLoginError(existing)
        self._check_can_create()
        # The stored origin is derived from the URL rows exactly as set_web_urls
        # will store it, so the new entry starts on the right site.
        try:
            origin = migrate_web_scope({"urls": urls})["origin"]
        except ItemSchemaError as exc:
            raise VaultError(str(exc)) from exc
        canonical, username, password, label, _explicit = self._validated_web_login(
            origin, username, password, label)
        with self.transaction():
            entry_id = self._append_web_entry(canonical, username, password, label, int(time.time()))
            self.set_details(entry_id, favorite=favorite, tags=list(tags), notes=notes, totp=totp,
                             recovery_codes=list(recovery_codes), policy=policy,
                             custom_fields=list(custom_fields))
            self.item_service.set_web_urls(entry_id, list(urls))
        return entry_id

    def add_desktop(
        self,
        *,
        label: str,
        username: str,
        password: str,
        exe_path: str,
        exe_sha256: str,
        window_title: str,
        control_fingerprint: list[dict[str, Any]],
        username_selector: dict[str, Any] | None,
        password_selector: dict[str, Any] | None,
        signer: dict[str, Any] | None = None,
        binding_mode: str = "strict",
    ) -> str:
        label = _validated_text(label, "label", 512, allow_empty=False)
        username = _validated_text(username, "username", 512, allow_empty=True)
        password = _validated_text(password, "password", 4096, allow_empty=False)
        exe_path = os.path.abspath(_validated_text(exe_path, "exe_path", 32768, allow_empty=False))
        exe_sha256 = _validated_sha256(exe_sha256)
        window_title = _validated_text(window_title, "window_title", 1024, allow_empty=False)
        if not isinstance(control_fingerprint, list) or not control_fingerprint:
            raise VaultError("control_fingerprint must contain at least one control")
        if not all(isinstance(item, dict) for item in control_fingerprint):
            raise VaultError("control_fingerprint is malformed")
        binding_mode = str(binding_mode).casefold()
        if binding_mode not in {"strict", "embedded_web_volatile", "dynamic_layout", "discord_stable"}:
            raise VaultError("Unsupported desktop binding mode")
        self._check_can_create()
        now = int(time.time())
        entry_id = str(uuid.uuid4())
        scope: dict[str, Any] = {
            "exe_path": exe_path,
            "exe_sha256": exe_sha256,
            "window_title": window_title,
            "control_fingerprint": copy.deepcopy(control_fingerprint),
            "username_selector": username_selector,
            "password_selector": password_selector,
            "binding_mode": binding_mode,
        }
        if signer:
            scope["signer"] = copy.deepcopy(signer)
        self._require_payload()["entries"].append(
            {
                "id": entry_id,
                "kind": "desktop",
                "label": label,
                "username": username,
                "password": password,
                "scope": scope,
                "created_at": now,
                "updated_at": now,
            }
        )
        self._require_payload()["updated_at"] = now
        self.save()
        return entry_id


    def update_entry_fields(
        self,
        entry_id: str,
        *,
        label: str | None = None,
        username: str | None = None,
        password: str | None = None,
        expected_revision: int | None = None,
    ) -> bool:
        if label is not None: label = _validated_text(label, "label", 512, allow_empty=False)
        if username is not None: username = _validated_text(username, "username", 512, allow_empty=True)
        if password is not None: password = _validated_text(password, "password", 4096, allow_empty=False)
        payload = self._require_payload()
        if expected_revision is not None:
            # Per-credential check: sync metadata saves and edits of other items do not count.
            item = next((e for e in payload["entries"] if e.get("id") == entry_id), None)
            if item is not None and not _same_revision(expected_revision, self._entry_revision(item)):
                raise VaultError(t("vault.err.changedBeforeSave"))
        if self._apply_entry_fields(entry_id, label=label, username=username, password=password):
            self.save()
            return True
        return False

    def _apply_entry_fields(self, entry_id: str, *, label: str | None, username: str | None,
                            password: str | None) -> bool:
        """Apply label/username/password to one credential in memory, without saving.

        Shared by ``update_entry_fields`` and ``save_login``; a changed password
        is pushed onto the password history (``push_password_history``).
        """
        payload = self._require_payload()
        for item in payload["entries"]:
            if item.get("id") != entry_id:
                continue
            if username is not None and username != item.get("username") and item.get("kind") == "web":
                if any(other.get("id") != entry_id and other.get("kind") == "web" and
                       other.get("scope", {}).get("origin") == item.get("scope", {}).get("origin") and
                       other.get("username") == username for other in payload["entries"]):
                    raise VaultError(t("vault.err.usernameExists"))
            if label is not None:
                item["label"] = _validated_text(label, "label", 512, allow_empty=False)
            if username is not None:
                item["username"] = _validated_text(username, "username", 512, allow_empty=True)
            if password is not None:
                validated_password = _validated_text(password, "password", 4096, allow_empty=False)
                previous = str(item.get("password", ""))
                if previous and not secrets.compare_digest(previous.encode("utf-8"), validated_password.encode("utf-8")):
                    item["password_history"] = push_password_history(
                        item.get("password_history"), previous, int(time.time()))
                item["password"] = validated_password
            now = int(time.time())
            item["updated_at"] = now
            payload["updated_at"] = now
            return True
        return False

    def login_edit_token(self, entry_id: str) -> str:
        """Return an opaque token for the current content of one login.

        The token is an HMAC-SHA256 under a per-unlock key over the entry's
        canonical JSON, minus ``_EDIT_TOKEN_IGNORED_KEYS``.  It changes only
        when this login (fields, details, password or URL rows) changes, so
        saves of other items and background icon updates do not invalidate an
        open editor.  Tokens never survive lock().
        """
        payload = self._require_payload()
        if self._edit_token_key is None:
            raise VaultLockedError(t("vault.err.locked"))
        item = next((e for e in payload["entries"] if e.get("id") == entry_id), None)
        if item is None:
            raise VaultError(t("vault.err.credentialNotFound"))
        return self._entry_token(item)

    def _entry_token(self, item: Mapping[str, Any]) -> str:
        """HMAC-SHA256 (per-unlock key) over one credential's canonical JSON minus ignored keys."""
        key = self._edit_token_key
        if key is None:
            raise VaultLockedError(t("vault.err.locked"))
        content = {name: value for name, value in item.items() if name not in _EDIT_TOKEN_IGNORED_KEYS}
        # Fed in small pieces: no immutable copy of the whole login (password
        # included) is built just to compute the token.
        mac = hmac.new(key, digestmod=hashlib.sha256)
        for chunk in _canonical_json_chunks(content, ensure_ascii=False):
            mac.update(chunk.encode("utf-8", "surrogatepass"))
        return mac.hexdigest()

    def save_login(
        self,
        entry_id: str,
        *,
        expected_token: str,
        label: str,
        username: str,
        password: str | None,
        favorite: bool,
        tags: list[str],
        notes: str,
        totp: dict[str, Any] | None,
        recovery_codes: list[str],
        custom_fields: list[dict[str, Any]],
        policy: dict[str, Any],
        urls: list[dict[str, Any]] | None,
    ) -> str:
        """Save every editable field of one login in a single commit.

        Raises ``LoginChangedError`` when the login no longer matches
        ``expected_token`` and ``DuplicateLoginError`` when the result would
        collide with another login for the same site and username.
        ``password=None`` keeps the password; ``urls=None`` keeps the URL rows
        (desktop logins).  Returns the login's new edit token.
        """
        from .item_schema import migrate_web_scope

        try:
            current = self.login_edit_token(entry_id)
        except VaultLockedError:
            raise
        except VaultError:
            raise LoginChangedError() from None
        if not isinstance(expected_token, str) or not hmac.compare_digest(
                current.encode("ascii"), expected_token.encode("utf-8", "surrogatepass")):
            raise LoginChangedError()
        item = next(e for e in self._require_payload()["entries"] if e.get("id") == entry_id)
        if item.get("kind") == "web":
            origin = item.get("scope", {}).get("origin")
            if urls is not None:
                try:
                    origin = migrate_web_scope({"urls": urls})["origin"]
                except ItemSchemaError as exc:
                    raise VaultError(str(exc)) from exc
            final_username = _validated_text(username, "username", 512, allow_empty=True)
            duplicate = self._web_login_match(origin, final_username, exclude_id=entry_id)
            if duplicate is not None:
                raise DuplicateLoginError(str(duplicate["id"]))
        with self.transaction():
            # URL rows first, so the username duplicate check below runs
            # against the login's final site.
            if urls is not None:
                self.item_service.set_web_urls(entry_id, list(urls))
            self._apply_entry_fields(entry_id, label=label, username=username, password=password)
            self.set_details(entry_id, favorite=favorite, tags=list(tags), notes=notes, totp=totp,
                             recovery_codes=list(recovery_codes), policy=policy,
                             custom_fields=list(custom_fields))
        return self.login_edit_token(entry_id)

    def update_desktop_binding(
        self,
        entry_id: str,
        *,
        exe_path: str,
        exe_sha256: str,
        window_title: str,
        control_fingerprint: list[dict[str, Any]],
        username_selector: dict[str, Any] | None,
        password_selector: dict[str, Any] | None,
        signer: dict[str, Any] | None = None,
        binding_mode: str = "strict",
    ) -> bool:
        binding_mode = str(binding_mode).casefold()
        if binding_mode not in {"strict", "embedded_web_volatile", "dynamic_layout", "discord_stable"}:
            raise VaultError("Unsupported desktop binding mode")
        payload = self._require_payload()
        for item in payload["entries"]:
            if item.get("id") != entry_id or item.get("kind") != "desktop":
                continue
            if not control_fingerprint or not all(isinstance(value, dict) for value in control_fingerprint):
                raise VaultError("control_fingerprint is malformed")
            scope: dict[str, Any] = {
                "exe_path": os.path.abspath(_validated_text(exe_path, "exe_path", 32768, allow_empty=False)),
                "exe_sha256": _validated_sha256(exe_sha256),
                "window_title": _validated_text(window_title, "window_title", 1024, allow_empty=False),
                "control_fingerprint": copy.deepcopy(control_fingerprint),
                "username_selector": copy.deepcopy(username_selector),
                "password_selector": copy.deepcopy(password_selector),
                "binding_mode": binding_mode,
            }
            if signer:
                scope["signer"] = copy.deepcopy(signer)
            # Rebinding changes the target identity, so remembered embedded-web
            # approval must be granted again for the new binding.
            item["scope"] = scope
            policy = normalized_policy(item.get("policy"))
            policy["sign_in"] = "never"
            item["policy"] = policy
            now = int(time.time())
            item["updated_at"] = now
            payload["updated_at"] = now
            self.save()
            return True
        return False

    def accept_desktop_update(
        self,
        entry_id: str,
        *,
        exe_sha256: str,
        window_title: str,
        control_fingerprint: list[dict[str, Any]],
    ) -> bool:
        """Record an updated binary for an existing binding, keeping its selectors and policy."""
        payload = self._require_payload()
        for item in payload["entries"]:
            if item.get("id") != entry_id or item.get("kind") != "desktop":
                continue
            if not control_fingerprint or not all(isinstance(value, dict) for value in control_fingerprint):
                raise VaultError("control_fingerprint is malformed")
            scope = item.setdefault("scope", {})
            scope["exe_sha256"] = _validated_sha256(exe_sha256)
            scope["window_title"] = _validated_text(window_title, "window_title", 1024, allow_empty=False)
            scope["control_fingerprint"] = copy.deepcopy(control_fingerprint)
            now = int(time.time())
            item["updated_at"] = now
            payload["updated_at"] = now
            self.save()
            return True
        return False

    def set_desktop_embedded_fill_approval(self, entry_id: str, approved: bool) -> bool:
        """Persist whether a desktop binding may fill embedded web content without re-prompting.

        The flag lives inside the encrypted entry scope. It does not relax any executable,
        signer, window-title, control-layout, or selector verification performed during fill.
        """
        payload = self._require_payload()
        for item in payload["entries"]:
            if item.get("id") != entry_id or item.get("kind") != "desktop":
                continue
            scope = item.get("scope")
            if not isinstance(scope, dict):
                raise VaultError("Desktop entry scope is malformed")
            scope["embedded_web_fill_approved"] = bool(approved)
            now = int(time.time())
            item["updated_at"] = now
            payload["updated_at"] = now
            self.save()
            return True
        return False

    def set_entry_extras(
        self,
        entry_id: str,
        *,
        totp: dict[str, Any] | None = None,
        custom_fields: list[dict[str, Any]] | None = None,
        policy: dict[str, Any] | None = None,
        notes: str | None = None,
    ) -> bool:
        """Update optional encrypted metadata on one credential."""
        payload = self._require_payload()
        for item in payload["entries"]:
            if item.get("id") != entry_id:
                continue
            if totp is not None:
                item["totp"] = copy.deepcopy(totp)
            if custom_fields is not None:
                if not isinstance(custom_fields, list) or not all(isinstance(value, dict) for value in custom_fields):
                    raise VaultError("custom_fields is malformed")
                item["custom_fields"] = copy.deepcopy(custom_fields[:50])
            if policy is not None:
                if not isinstance(policy, dict):
                    raise VaultError("policy is malformed")
                item["policy"] = normalized_policy(policy)
            if notes is not None:
                item["notes"] = _validated_text(notes, "notes", 20000, allow_empty=True)
            now = int(time.time())
            item["updated_at"] = now
            payload["updated_at"] = now
            self.save()
            return True
        return False

    def all_entries(self) -> list[dict[str, Any]]:
        return copy.deepcopy(self._require_payload()["entries"])

    def live_item_count(self) -> int:
        """Live logins plus live typed items; trash never counts."""
        payload = self._require_payload()
        entries = payload.get("entries")
        items = payload.get("items")
        return (len(entries) if isinstance(entries, list) else 0) + (len(items) if isinstance(items, list) else 0)

    def _check_can_create(self, n: int = 1) -> None:
        """Raise ``ItemLimitReached`` before any mutation if ``n`` new items exceed the limit."""
        limit = self.item_limit
        if limit is None:
            return
        count = self.live_item_count()
        if count + n > limit:
            raise ItemLimitReached(limit, count)

    def password_history(self, entry_id: str) -> list[dict[str, Any]]:
        entry = self.get_entry(entry_id)
        if not entry:
            return []
        history = entry.get("password_history")
        result = []
        if isinstance(history, list):
            for item in history:
                if isinstance(item, dict) and isinstance(item.get("password"), str):
                    changed_at = int(item.get("changed_at", item.get("replaced_at", 0)))
                    result.append({"password": item["password"], "changed_at": changed_at})
                    if len(result) == PASSWORD_HISTORY_READ_LIMIT:
                        break
        entry.clear()
        return result

    @contextmanager
    def transaction(self):
        """One atomic disk commit for a group of changes (including CSV imports).

        The session lock is held for the whole block and its commit, so a lock
        from another thread waits for it.  A lock from inside the block (same
        thread) leaves the session locked: no rollback, and the commit raises.
        """
        with self._state_lock:
            original = copy.deepcopy(self._require_payload())
            self._batch_depth += 1
            try:
                yield self
            except BaseException:
                if self._key is not None:
                    self._payload = original
                raise
            finally:
                self._batch_depth -= 1
            if self._batch_depth == 0:
                self.save()

    @contextmanager
    def sync_metadata_save(self):
        """Saves that commit inside the block skip the rolling backup.

        For changes that touch only sync metadata, so routine sync bookkeeping
        cannot rotate the user's last rolling backups away.  A save that commits
        later (an outer transaction) keeps its backup.
        """
        previous = self._suppress_rolling_backup
        self._suppress_rolling_backup = True
        try:
            yield
        finally:
            self._suppress_rolling_backup = previous

    def _matches_key(self, candidate: bytes | bytearray) -> bool:
        """Constant-time compare with the data key; a lock during the KDF reports locked."""
        with self._state_lock:
            if self._key is None:
                raise VaultLockedError(t("vault.err.locked"))
            return hmac.compare_digest(candidate, self._key)

    def _password_wrapper_matches(self, password: SecretText) -> bool:
        """Derive the KEK and compare the unwrapped data key; no file is written."""
        if self._key is None:
            raise VaultLockedError(t("vault.err.locked"))
        header = self._header
        kek = _derive_key(password, header["kdf"])
        try:
            if _header_version(header) != FORMAT_VERSION:
                return self._matches_key(kek)
            wrapper = header["wrappers"]["password"]
            try:
                unwrapped = _unwrap_key(kek, _validated_wrapper_field(wrapper, "nonce", 12),
                                        _validated_wrapper_field(wrapper, "ciphertext", 48),
                                        _wrapper_aad(header, "password", {"kdf": header["kdf"]}))
            except InvalidTag:
                return False
            try:
                return self._matches_key(unwrapped)
            finally:
                _zero(unwrapped)
        finally:
            _zero(kek)

    def verify_master_password(self, password: str | SecretText) -> bool:
        """Throttled, in-memory check of the master password for sensitive actions."""
        self._require_payload()
        throttle = UnlockThrottle(self.path)
        throttle.check()
        secret, owned = _master_secret(password, t("vault.err.wrongPassword"))
        try:
            try:
                if not self._password_wrapper_matches(secret):
                    throttle.record_failure()
                    raise InvalidMasterPassword(t("vault.err.wrongPassword"))
            except InvalidMasterPassword:
                raise
            except VaultError as exc:
                # Malformed wrappers must not count as a password failure nor pass.
                raise VaultError(t("vault.err.passwordNotVerified", detail=exc)) from exc
        finally:
            if owned:
                secret.wipe()
        throttle.reset()
        return True

    def _password_wrapper(self, header: dict[str, Any], password: SecretText, kdf: dict[str, Any]) -> dict[str, Any]:
        if not isinstance(password, SecretText) or not 12 <= password.char_count <= MAX_MASTER_PASSWORD_LENGTH:
            raise VaultError(t("vault.err.passwordLength"))
        kek = _derive_key(password, kdf)
        try:
            header["kdf"] = kdf
            nonce, ciphertext = _wrap_key(kek, self._key or b"", _wrapper_aad(header, "password", {"kdf": kdf}))
        finally:
            _zero(kek)
        # No created_at: it sat outside the wrapper AAD and nothing read it (old vaults may still carry it).
        return {"nonce": _b64e(nonce), "ciphertext": _b64e(ciphertext)}

    def _commit_header_change(self, header: dict[str, Any], *, before_save: Any = None) -> None:
        """Save with a replacement header; restore the previous header on failure."""
        old_header, old_catalog = self._header, self._catalog_version
        self._header = header
        try:
            if before_save is not None:
                before_save()
            self.save()
        except BaseException:
            self._header, self._catalog_version = old_header, old_catalog
            raise

    def change_master_password(self, current_password: str | SecretText, new_password: str | SecretText, *,
                               recovery_phrase: str | None = None) -> dict[str, Any]:
        """Set a new master password and rotate the data key with it.

        Re-wrapping the old data key would let a leaked old password plus any
        older copy of the vault (rolling backups, exports, synced copies) open
        the current vault.  The catalog is therefore re-encrypted under a fresh
        data key, rolling backups from the previous key are purged, and the
        rollback anchor is re-minted (see ``rotate_data_key`` for the wrapper
        consequences).  The recovery phrase keeps working only when it is
        supplied; otherwise it is invalidated and reported.  Windows Hello and
        camera verification always need to be set up again; the caller removes
        their sidecars and OS keys with ``cleanup_after_password_change``.
        """
        new_secret, new_owned = _master_secret(new_password, t("vault.err.passwordLength"))
        current_secret = None
        current_owned = False
        try:
            if not 12 <= new_secret.char_count <= 4096:
                raise VaultError(t("vault.err.passwordLength"))
            current_secret, current_owned = _master_secret(current_password, t("vault.err.wrongPassword"))
            self.verify_master_password(current_secret)
            return self._rotate_data_key(current_secret, new_secret, recovery_phrase=recovery_phrase,
                                         remove_unlock_envelopes=False)
        finally:
            if new_owned:
                new_secret.wipe()
            if current_owned and current_secret is not None:
                current_secret.wipe()

    @_under_session_lock
    def set_master_password_after_recovery(self, new_password: str | SecretText) -> dict[str, Any]:
        """Set a new master password for a session opened with the recovery phrase.

        This is a password change, so it rotates the data key exactly like
        ``change_master_password``: the catalog is re-encrypted under a fresh
        key, rolling backups under the old key are purged and the rollback
        anchor is switched crash-safely.  The recovery phrase that opened the
        session is re-wrapped under the new key and keeps working.  Windows
        Hello and camera bindings are revoked; the caller removes their
        sidecars and OS keys with ``cleanup_after_password_change`` (they only
        wrap the retired data key).  Returns the ``_rotate_data_key`` result.
        """
        if not self.recovery_unlocked:
            raise VaultError(t("vault.err.newPasswordNeedsRecovery"))
        new_secret, new_owned = _master_secret(new_password, t("vault.err.passwordLength"))
        try:
            if not 12 <= new_secret.char_count <= 4096:
                raise VaultError(t("vault.err.passwordLength"))
            if _header_version(self._header) != FORMAT_VERSION:
                raise VaultError(t("vault.err.recoveryNeedsFormat3"))
            entropy = self._recovery_entropy
            result = self._rotate_data_key(None, new_secret, recovery_phrase=None, recovery_entropy=entropy,
                                           remove_unlock_envelopes=False)
        finally:
            if new_owned:
                new_secret.wipe()
        self.recovery_unlocked = False
        _zero(self._recovery_entropy)
        self._recovery_entropy = None
        UnlockThrottle(self.path).reset()
        return result

    # -- recovery phrase ------------------------------------------------------
    def has_recovery_phrase(self) -> bool:
        self._require_payload()
        wrappers = self._header.get("wrappers") if _header_version(self._header) == FORMAT_VERSION else None
        return isinstance(wrappers, dict) and isinstance(wrappers.get("recovery"), dict)

    def _recovery_wrapper_outlives_removal(self) -> bool:
        """Whether a local older copy still carries a recovery wrapper of the current data key.

        Releases before 2026-10-24 replaced or removed a phrase without
        rotating the data key, so such a copy (rolling backup, pre-restore
        copy) would still open the current vault with the old phrase.
        """
        directories = {directory for directory in (self.backup_dir, self.path.parent / "Backups") if directory}
        generation = self._header.get("key_generation")
        for directory in directories:
            try:
                candidates = [*directory.glob("vault-*.json"), *directory.glob("before-restore-*.json")]
            except OSError:
                continue
            for candidate in candidates:
                try:
                    if candidate.is_symlink() or not candidate.is_file() or candidate.stat().st_size > MAX_VAULT_BYTES:
                        continue
                    header = json.loads(candidate.read_bytes())
                except (OSError, ValueError, RecursionError):
                    continue
                if (isinstance(header, dict) and isinstance(header.get("wrappers"), dict)
                        and isinstance(header["wrappers"].get("recovery"), dict)
                        and header.get("vault_id") == self._header.get("vault_id")
                        and header.get("key_generation") == generation):
                    return True
        return False

    @_under_session_lock
    def create_recovery_phrase(self, current_password: str | SecretText) -> str:
        """Create (or replace) the 24-word recovery phrase; the old phrase stops working.

        The phrase is returned exactly once and is never written anywhere.

        Replacing an existing phrase rotates the data key (``_rotate_data_key``):
        re-wrapping the same key would leave every older copy of the vault
        (rolling backups, pre-restore copies, exports, synced or shadow
        copies) wrapping the *current* data key under the old phrase.  The
        rotation purges rolling backups, revokes Windows Hello / camera
        bindings (their sidecars wrap the retired key) and is reported in
        ``last_recovery_phrase_change``.  A first phrase, with no older
        wrapper anywhere, is only an added wrapper.
        """
        secret, owned = _master_secret(current_password, t("vault.err.wrongPassword"))
        try:
            self.verify_master_password(secret)
            words = bip39_words()  # fail early if the word list is damaged
            assert len(words) == 2048
            entropy = os.urandom(32)
            salt = os.urandom(16)
            if self.has_recovery_phrase() or self._recovery_wrapper_outlives_removal():
                result = self._rotate_data_key(secret, secret, recovery_phrase=None,
                                               new_recovery_entropy=entropy)
                self.last_recovery_phrase_change = {"operation": "replace", **result}
                return phrase_from_entropy(entropy)
            header = self._promoted_header(catalog_version=self._catalog_version, password=secret)
        finally:
            if owned:
                secret.wipe()
        metadata = {"kind": RECOVERY_WRAPPER_KIND, "salt": _b64e(salt)}
        recovery_key = _recovery_key(entropy, salt)
        try:
            nonce, ciphertext = _wrap_key(recovery_key, self._key or b"", _wrapper_aad(header, "recovery", metadata))
        finally:
            _zero(recovery_key)
        header["wrappers"]["recovery"] = {**metadata, "nonce": _b64e(nonce), "ciphertext": _b64e(ciphertext)}
        self._commit_header_change(header)
        self.last_recovery_phrase_change = {"operation": "create", "key_generation": header.get("key_generation"),
                                            "recovery_phrase_invalidated": False, "reenroll_required": [],
                                            "purged_backups": 0, "retained_old_copies": 0}
        return phrase_from_entropy(entropy)

    @_under_session_lock
    def remove_recovery_phrase(self, current_password: str | SecretText) -> dict[str, Any] | None:
        """Remove the recovery phrase by rotating the data key (see ``create_recovery_phrase``).

        Returns the rotation result, or ``None`` when no phrase was enrolled.
        """
        secret, owned = _master_secret(current_password, t("vault.err.wrongPassword"))
        try:
            self.verify_master_password(secret)
            if not self.has_recovery_phrase():
                return None
            result = self._rotate_data_key(secret, secret, recovery_phrase=None)
        finally:
            if owned:
                secret.wipe()
        self.last_recovery_phrase_change = {"operation": "remove", **result}
        return result

    # -- data-key rotation ----------------------------------------------------
    def rotate_data_key(self, current_password: str | SecretText, *,
                        recovery_phrase: str | None = None) -> dict[str, Any]:
        """Replace the data key, re-encrypt the catalog and re-wrap every wrapper that can be.

        Wrappers whose secret is unavailable (recovery phrase not supplied,
        Windows Hello / camera keys held by the OS) are invalidated and
        reported.  Rolling backups written under the previous key are purged.
        Attachment sidecars keep their per-file keys, which live inside the
        re-encrypted catalog, so they stay readable without being rewritten.
        """
        secret, owned = _master_secret(current_password, t("vault.err.wrongPassword"))
        try:
            self.verify_master_password(secret)
            return self._rotate_data_key(secret, secret, recovery_phrase=recovery_phrase)
        finally:
            if owned:
                secret.wipe()

    @_under_session_lock
    def _rotate_data_key(self, current_password: SecretText | None, new_password: SecretText, *, recovery_phrase: str | None,
                         remove_unlock_envelopes: bool = True,
                         recovery_entropy: bytes | bytearray | None = None,
                         new_recovery_entropy: bytes | bytearray | None = None) -> dict[str, Any]:
        """Rotate the data key and wrap it under ``new_password``; the caller verified the password.

        ``current_password`` is ``None`` only for a recovery-phrase session,
        whose header is already format 3 (no promotion needs the password).
        The recovery phrase is identified by ``recovery_phrase`` or, from a
        recovery unlock, by its ``recovery_entropy``.  ``new_recovery_entropy``
        instead wraps the new key under a newly created phrase, replacing any
        existing one.

        ``retained_old_copies`` counts local pre-restore / pre-migration
        copies that are kept (they are the user's safety copies) but still
        open with the retired key's password or phrase; they cannot open the
        re-encrypted vault.

        The Hello / camera bindings inside the payload are always revoked.  With
        ``remove_unlock_envelopes=False`` the stale sidecar files are left for
        the caller's ``cleanup_after_password_change``, which also deletes the
        OS-held key; they only wrap the retired data key.
        """
        payload = self._require_payload()
        old_key = self._key
        if old_key is None:
            raise VaultLockedError(t("vault.err.keyUnavailable"))
        if recovery_phrase is not None:
            recovery_entropy = entropy_from_phrase(recovery_phrase)
        if new_recovery_entropy is not None:
            if len(new_recovery_entropy) != 32:
                raise VaultError("Invalid recovery phrase entropy")
            recovery_entropy = None
        if recovery_entropy is not None:
            # Raises if it is not this vault's phrase.
            _zero(self._unwrap_recovery(recovery_entropy))
        header = self._promoted_header(catalog_version=self._catalog_version, password=current_password)
        header["key_generation"] = int(header.get("key_generation", 1)) + 1
        header["wrappers"] = {}
        new_key = bytearray(os.urandom(32))
        self._key = new_key
        result: dict[str, Any] = {"key_generation": header["key_generation"], "recovery_phrase_invalidated": False,
                                  "reenroll_required": [], "purged_backups": 0, "retained_old_copies": 0}
        try:
            header["wrappers"]["password"] = self._password_wrapper(header, new_password,
                                                                    {**DEFAULT_KDF, "salt": _b64e(os.urandom(16))})
            had_recovery = isinstance(self._header.get("wrappers", {}).get("recovery"), dict)
            wrap_entropy = new_recovery_entropy if new_recovery_entropy is not None else (
                recovery_entropy if had_recovery else None)
            if wrap_entropy is not None:
                salt = os.urandom(16)
                metadata = {"kind": RECOVERY_WRAPPER_KIND, "salt": _b64e(salt)}
                recovery_key = _recovery_key(wrap_entropy, salt)
                try:
                    nonce, ciphertext = _wrap_key(recovery_key, new_key, _wrapper_aad(header, "recovery", metadata))
                finally:
                    _zero(recovery_key)
                header["wrappers"]["recovery"] = {**metadata, "nonce": _b64e(nonce), "ciphertext": _b64e(ciphertext)}
            if had_recovery and recovery_entropy is None:
                # Not re-wrapped (removed, or replaced by a new phrase).
                result["recovery_phrase_invalidated"] = True
            prefs = payload.get("preferences", {})
            snapshot = copy.deepcopy(prefs) if isinstance(prefs, dict) else None

            def drop_bindings() -> None:
                if isinstance(prefs, dict):
                    for name, binding in (("hello", "hello_binding"), ("face", "face_binding")):
                        if prefs.pop(binding, None):
                            result["reenroll_required"].append(name)

            # The rollback anchor is keyed from the data key: before the commit
            # it is re-minted so it authenticates under BOTH keys (a crash
            # leaves an anchor that opens whichever vault is on disk); the
            # commit then rewrites it under the new key alone.  It is restored
            # under the old key if the commit fails.  The rolling backup the
            # commit would take is skipped: it would be wrapped under the old
            # password and open the old data key.
            generation = int(payload.get("generation", 0))
            vault_id = str(header.get("vault_id", ""))
            old_vault_id = str(self._header.get("vault_id", ""))
            new_anchor_key, old_anchor_key = _rollback_anchor_key(new_key), _rollback_anchor_key(old_key)
            try:
                if _generation_anchor_path(self.path).exists():
                    try:
                        _write_generation_anchor(self.path, generation, new_anchor_key, vault_id,
                                                 previous_key=old_anchor_key, previous_vault_id=old_vault_id)
                    except OSError as exc:
                        raise VaultError("Could not update vault rollback-protection metadata") from exc
                self._suppress_rolling_backup = True
                try:
                    self._commit_header_change(header, before_save=drop_bindings)
                except BaseException:
                    if snapshot is not None and isinstance(prefs, dict):
                        prefs.clear()
                        prefs.update(snapshot)
                    try:
                        _write_generation_anchor(self.path, generation, old_anchor_key, old_vault_id)
                    except OSError:
                        pass
                    raise
            finally:
                self._suppress_rolling_backup = False
                _zero(new_anchor_key)
                _zero(old_anchor_key)
        except BaseException:
            self._key = old_key
            _zero(new_key)
            raise
        _zero(old_key)
        for name in result["reenroll_required"] if remove_unlock_envelopes else ():
            try:
                if name == "hello":
                    from .hello_unlock import envelope_path as hello_envelope
                    hello_envelope(self.path).unlink(missing_ok=True)
                else:
                    from .face_unlock import envelope_path as face_envelope
                    face_envelope(self.path).unlink(missing_ok=True)
            except OSError:
                self.backup_warning = True
        result["purged_backups"] = self.purge_rolling_backups_older_than(int(payload.get("generation", 0)))
        result["retained_old_copies"] = len(self.old_key_copies())
        # Keep one rolling backup available, written under the new key.
        self._rolling_backup()
        return result

    def old_key_copies(self) -> list[Path]:
        """Local pre-restore / pre-migration copies not encrypted under the current data key.

        They are deliberately kept (restore safety copies), but each still
        opens with the password or recovery phrase that was valid when it
        was written.  The UI reports them after a key rotation.
        """
        found: list[Path] = []
        generation = self._header.get("key_generation")
        directories = {directory for directory in (self.backup_dir, self.path.parent / "Backups") if directory}
        for directory in directories:
            try:
                candidates = [*directory.glob("before-restore-*"), *directory.glob("migration-v*-*.json")]
            except OSError:
                continue
            for candidate in candidates:
                try:
                    if candidate.is_symlink() or not candidate.is_file():
                        continue
                    if candidate.suffix == ".json" and candidate.stat().st_size <= MAX_VAULT_BYTES:
                        header = json.loads(candidate.read_bytes())
                        if (isinstance(header, dict) and _header_version(header) == FORMAT_VERSION
                                and header.get("vault_id") == self._header.get("vault_id")
                                and header.get("key_generation") == generation):
                            continue
                except (OSError, ValueError, RecursionError, VaultError):
                    pass
                found.append(candidate)
        return sorted(found)

    def _unwrap_recovery(self, entropy: bytes) -> bytearray:
        header = self._header
        wrapper = header.get("wrappers", {}).get("recovery") if _header_version(header) == FORMAT_VERSION else None
        if not isinstance(wrapper, dict):
            raise RecoveryPhraseError(t("vault.err.noRecoveryPhrase"))
        return _unwrap_recovery_wrapper(header, wrapper, entropy)

    def purge_rolling_backups_older_than(self, generation: int) -> int:
        """Delete rolling backups whose header generation is below ``generation``.

        Legacy (v1/v2) rolling backups carry no public generation and were
        written under a different key hierarchy, so they are always purged.
        """
        if self.backup_dir is None or not self.backup_dir.exists():
            return 0
        removed = 0
        for backup in self.backup_dir.glob("vault-*.json"):
            try:
                if backup.is_symlink() or not backup.is_file():
                    continue
                keep = False
                if backup.stat().st_size <= MAX_VAULT_BYTES:
                    header = json.loads(backup.read_bytes())
                    if isinstance(header, dict) and _header_version(header) == FORMAT_VERSION \
                            and type(header.get("generation")) is int \
                            and header["generation"] >= int(generation) \
                            and header.get("key_generation") == self._header.get("key_generation"):
                        keep = True
                if not keep:
                    backup.unlink()
                    removed += 1
            except (OSError, ValueError, RecursionError, VaultError):
                continue
        return removed

    def hello_binding(self) -> str:
        """Authorization is stored inside the authenticated, encrypted payload."""
        prefs = self._require_payload().get("preferences", {})
        value = prefs.get("hello_binding", "") if isinstance(prefs, dict) else ""
        if (isinstance(value, str) and len(value) == 32
                and all(c in "0123456789abcdef" for c in value)):
            return value
        return ""

    def set_hello_binding(self, record_id: str | None) -> None:
        if record_id is not None and (not isinstance(record_id, str) or len(record_id) != 32
                                     or any(c not in "0123456789abcdef" for c in record_id)):
            raise VaultError("Invalid Windows Hello binding")
        payload = self._require_payload()
        prefs = payload.setdefault("preferences", {})
        if not isinstance(prefs, dict):
            raise VaultError("Vault preferences are malformed")
        if record_id is None:
            prefs.pop("hello_binding", None)
        else:
            prefs["hello_binding"] = record_id
        self.save()

    def face_binding(self) -> str:
        """Authorization for ordinary-webcam verification lives inside the vault."""
        prefs = self._require_payload().get("preferences", {})
        value = prefs.get("face_binding", "") if isinstance(prefs, dict) else ""
        if (isinstance(value, str) and len(value) == 32
                and all(c in "0123456789abcdef" for c in value)):
            return value
        return ""

    def set_face_binding(self, record_id: str | None) -> None:
        if record_id is not None and (not isinstance(record_id, str) or len(record_id) != 32
                                     or any(c not in "0123456789abcdef" for c in record_id)):
            raise VaultError("Invalid camera-verification binding")
        payload = self._require_payload()
        prefs = payload.setdefault("preferences", {})
        if not isinstance(prefs, dict):
            raise VaultError("Vault preferences are malformed")
        if record_id is None:
            prefs.pop("face_binding", None)
        else:
            prefs["face_binding"] = record_id
        self.save()

    def scheduled_backup_password(self) -> str:
        """Backup password for scheduled .lgk backups, kept only in the encrypted payload.

        It is never written to plaintext settings and disappears from this
        session with the rest of the payload when the vault locks.
        """
        prefs = self._require_payload().get("preferences", {})
        value = prefs.get("scheduled_backup_password", "") if isinstance(prefs, dict) else ""
        return value if isinstance(value, str) and len(value) >= 12 else ""

    def has_scheduled_backup_password(self) -> bool:
        return bool(self.scheduled_backup_password())

    def set_scheduled_backup_password(self, password: str | None) -> None:
        if password is not None and (not isinstance(password, str) or len(password) < 12
                                     or len(password) > 1024 or "\x00" in password):
            raise VaultError(t("vault.err.backupPasswordShort"))
        payload = self._require_payload()
        prefs = payload.setdefault("preferences", {})
        if not isinstance(prefs, dict):
            raise VaultError("Vault preferences are malformed")
        previous = prefs.get("scheduled_backup_password")
        if password is None:
            prefs.pop("scheduled_backup_password", None)
        else:
            prefs["scheduled_backup_password"] = password
        try:
            self.save()
        except BaseException:
            if previous is None:
                prefs.pop("scheduled_backup_password", None)
            else:
                prefs["scheduled_backup_password"] = previous
            raise

    def unlock_context(self) -> str:
        self._require_payload()
        return unlock_context_for_header(self._header)

    @_under_session_lock
    def wrap_unlock_key(self, wrapping_key: bytearray, context: bytes) -> tuple[bytes, bytes]:
        """Return ciphertext only; never export the master password or bare key."""
        self._require_payload()
        if len(wrapping_key) != 32 or not isinstance(context, bytes):
            raise VaultError("Invalid local key protection parameters")
        return _wrap_key(wrapping_key, self._key or b"", context)

    @_under_session_lock
    def write_rollback_anchor(self, path: Path | None = None) -> None:
        """Write an authenticated rollback anchor for this session's committed generation."""
        payload = self._require_payload()
        anchor_key = _rollback_anchor_key(self._key or b"")
        try:
            _write_generation_anchor(Path(path or self.path), int(payload.get("generation", 0)), anchor_key,
                                     str(self._header.get("vault_id", "")))
        finally:
            _zero(anchor_key)

    @_under_session_lock
    def rollback_anchor_generation(self, path: Path | None = None) -> int | None:
        """Return the anchor generation stored next to ``path`` if it authenticates under this data key.

        ``None`` means there is no anchor; a VaultError means the anchor exists
        but was minted for a different data key or has been tampered with.
        """
        self._require_payload()
        target = Path(path or self.path)
        if not _generation_anchor_path(target).exists():
            return None
        anchor_key = _rollback_anchor_key(self._key or b"")
        try:
            generation, _upgrade = _read_generation_anchor(target, anchor_key, "")
        finally:
            _zero(anchor_key)
        return generation

    def fill_and_sign_in_enabled(self) -> bool:
        prefs = self._require_payload().get("preferences", {})
        return isinstance(prefs, dict) and prefs.get("fill_and_sign_in") is True

    def set_fill_and_sign_in_enabled(self, enabled: bool) -> None:
        if not isinstance(enabled, bool):
            raise VaultError("Fill & sign in must be an explicit boolean preference")
        payload = self._require_payload()
        prefs = payload.setdefault("preferences", {})
        if not isinstance(prefs, dict):
            raise VaultError("Vault preferences are malformed")
        prefs["fill_and_sign_in"] = enabled
        self.save()

    def set_favorite(self, entry_id: str, favorite: bool) -> None:
        payload = self._require_payload()
        item = next((e for e in payload["entries"] if e["id"] == entry_id), None)
        if item is None: raise VaultError(t("vault.err.credentialNotFound"))
        previous = (item.get("favorite", False), item.get("updated_at"))
        item.update(favorite=bool(favorite), updated_at=int(time.time()))
        try:
            self.save()
        except BaseException:
            item["favorite"], item["updated_at"] = previous
            raise

    def set_details(self, entry_id: str, *, favorite: bool = False, tags: list[str] | None = None,
                    notes: str = "", totp: dict[str, Any] | None = None,
                    recovery_codes: list[str] | None = None, policy: dict[str, Any] | None = None,
                    custom_fields: list[dict[str, Any]] | None = None) -> None:
        payload = self._require_payload()
        item = next((e for e in payload["entries"] if e["id"] == entry_id), None)
        if item is None: raise VaultError(t("vault.err.credentialNotFound"))
        tags = list(dict.fromkeys(_validated_text(t.strip(), "tag", 40, allow_empty=False) for t in (tags or []) if t.strip()))
        if len(tags) > 20: raise VaultError(t("vault.err.tooManyTags"))
        codes = [_validated_text(c, "recovery code", 512, allow_empty=False) for c in (recovery_codes or [])]
        if len(codes) > 100: raise VaultError(t("vault.err.tooManyRecoveryCodes"))
        if custom_fields is not None and (not isinstance(custom_fields, list) or not all(isinstance(f, dict) for f in custom_fields)):
            raise VaultError(t("vault.err.customFieldsList"))
        fields = []
        for field in (custom_fields or []):
            fields.append({"name": _validated_text(field.get("name", ""), "field name", 100, allow_empty=False),
                           "value": _validated_text(field.get("value", ""), "field value", 4096, allow_empty=True),
                           "hidden": field.get("hidden", True) is True})
        if len(fields) > 50: raise VaultError(t("vault.err.tooManyCustomFields"))
        if totp:
            totp = {"secret": normalize_secret(str(totp.get("secret", ""))),
                    "algorithm": str(totp.get("algorithm", "SHA1")).upper(),
                    "digits": int(totp.get("digits", 6)), "period": int(totp.get("period", 30))}
            generate_totp(**totp)
            if not _same_totp(totp, item.get("totp")):
                # Removing a code or keeping the saved one is always allowed.
                require_pro_feature(self, "totp")
        item.update(favorite=bool(favorite), tags=tags,
                    notes=_validated_text(notes, "notes", 20000, allow_empty=True),
                    totp=copy.deepcopy(totp) if totp else None, recovery_codes=codes,
                    custom_fields=fields, policy=normalized_policy(policy), updated_at=int(time.time()))
        self.save()

    def set_entry_icon(self, entry_id: str, png: bytes) -> bool:
        """Store a small, already-validated PNG icon with a website login.

        Returns False (and writes nothing) when the icon is unchanged.
        """
        if not isinstance(png, (bytes, bytearray)) or not png.startswith(PNG_SIGNATURE) or len(png) > MAX_SITE_ICON_BYTES:
            raise VaultError(t("vault.err.iconMustBePng"))
        item = next((e for e in self._require_payload()["entries"] if e["id"] == entry_id), None)
        if item is None or item.get("kind") != "web":
            raise VaultError(t("vault.err.credentialNotFound"))
        encoded = base64.b64encode(bytes(png)).decode("ascii")
        if item.get("site_icon") == encoded:
            return False
        item["site_icon"] = encoded
        self.save()
        return True

    def entry_icon(self, entry_id: str) -> bytes | None:
        item = next((e for e in self._require_payload()["entries"] if e["id"] == entry_id), None)
        return _decode_site_icon(item.get("site_icon") if item else None)

    def has_entry_icon(self, entry_id: str) -> bool:
        item = next((e for e in self._require_payload()["entries"] if e["id"] == entry_id), None)
        return bool(item and item.get("site_icon"))

    def captured_site_icons(self) -> dict[str, bytes]:
        """Icons captured from the browser, keyed by exact origin."""
        icons: dict[str, bytes] = {}
        for item in self._require_payload()["entries"]:
            if item.get("kind") != "web":
                continue
            data = _decode_site_icon(item.get("site_icon"))
            if data:
                icons.setdefault(item["scope"]["origin"], data)
        return icons

    def consume_recovery_code(self, entry_id: str, index: int) -> str:
        entry = next((e for e in self._require_payload()["entries"] if e["id"] == entry_id), None)
        if entry is None: raise VaultError(t("vault.err.credentialNotFound"))
        codes = entry.get("recovery_codes", [])
        if not 0 <= index < len(codes): raise VaultError(t("vault.err.recoveryCodeGone"))
        code = codes.pop(index)
        self.save()
        return code

    def bind_sign_in(self, entry_id: str, selector: dict[str, Any]) -> None:
        entry = next((e for e in self._require_payload()["entries"] if e["id"] == entry_id), None)
        if entry is None or entry.get("kind") != "desktop":
            raise VaultError("Select a desktop credential")

        from .access_policy import is_sign_in_label

        explicit = bool(selector.get("explicit_user_mapping"))
        name = str(selector.get("name", "")).strip()
        if not explicit and not is_sign_in_label(name):
            raise VaultError("Only an explicitly mapped login action can be bound")
        if not name:
            raise VaultError("The selected login action has no accessible name")

        identity_mode = str(selector.get("identity_mode", "exact_metadata")).casefold()

        if identity_mode == "exact_metadata":
            if not (selector.get("automation_id") or selector.get("class_name")):
                raise VaultError("The selected login button does not expose a stable identity")
        elif identity_mode == "unique_name":
            if not explicit:
                raise VaultError("Name-only login actions must be explicitly mapped by the user")
        else:
            raise VaultError("Unsupported login-button identity mode")

        saved = copy.deepcopy(selector)
        saved["name"] = name
        saved["identity_mode"] = identity_mode
        entry["scope"]["sign_in_selector"] = saved
        self.save()

    def trash_summaries(self) -> list[dict[str, Any]]:
        # No passwords in the management list. Deleted typed items share the
        # trash list; item_service.trash_summaries() reports those.
        return [{"id": x["entry"]["id"], "label": x["entry"]["label"],
                 "username": x["entry"]["username"], "deleted_at": x["deleted_at"]}
                for x in self._require_payload().get("trash", [])
                if x["entry"].get("kind") in ("web", "desktop")]

    def restore_deleted(self, entry_id: str) -> None:
        payload = self._require_payload()
        record = next((x for x in payload.get("trash", []) if x["entry"]["id"] == entry_id), None)
        if not record: raise VaultError(t("vault.err.deletedNotFound"))
        restored = record["entry"]
        if any(e["id"] == entry_id or (restored["kind"] == "web" and e["kind"] == "web" and
                    e["username"] == restored["username"] and e["scope"] == restored["scope"])
               for e in payload["entries"]):
            raise VaultError(t("vault.err.liveExists"))
        self._check_can_create()
        policy = normalized_policy(restored.get("policy"))
        policy["sign_in"] = "never"
        restored["policy"] = policy
        if restored["kind"] == "desktop": restored["scope"]["embedded_web_fill_approved"] = False
        payload["entries"].append(restored)
        payload["trash"].remove(record)
        self.save()

    def purge_deleted(self, entry_id: str) -> None:
        self.purge_deleted_many([entry_id])

    def purge_deleted_many(self, entry_ids: Iterable[str]) -> int:
        """Permanently remove trash records (logins and typed items) in one save."""
        payload = self._require_payload()
        wanted = {str(value) for value in entry_ids}
        before = payload.get("trash", [])
        kept = [x for x in before if x["entry"]["id"] not in wanted]
        removed = len(before) - len(kept)
        if removed:
            payload["trash"] = kept
            try:
                self.save()
            except BaseException:
                payload["trash"] = before
                raise
        return removed

    def _rolling_backup(self) -> None:
        if (self.backup_count <= 0 or self.backup_dir is None or not self.path.exists()
                or self._suppress_rolling_backup):
            return
        try:
            self.backup_dir.mkdir(parents=True, exist_ok=True)
            stamp = f"{int(time.time() * 1000)}-{secrets.token_hex(3)}"
            destination = self.backup_dir / f"vault-{stamp}.json"
            shutil.copy2(self.path, destination)
            backups = sorted(
                self.backup_dir.glob("vault-*.json"),
                key=lambda path: path.stat().st_mtime_ns,
                reverse=True,
            )
            for old in backups[self.backup_count :]:
                try:
                    old.unlink()
                except OSError:
                    pass
        except OSError:
            self.backup_warning = True

    def delete(self, entry_id: str) -> bool:
        payload = self._require_payload()
        entry = next((e for e in payload["entries"] if e.get("id") == entry_id), None)
        if entry is None: return False
        payload.setdefault("trash", []).append({"entry": entry, "deleted_at": int(time.time())})
        payload["entries"].remove(entry)
        payload["updated_at"] = int(time.time())
        self.save()
        return True

    @_under_session_lock
    def save(self) -> None:
        if self._batch_depth:
            return
        from .file_lock import exclusive_writer
        try:
            with exclusive_writer(self.path):
                self._save_locked()
        except OSError:
            self._payload = copy.deepcopy(self._committed_payload)
            raise VaultError(t("vault.err.writeFailed")) from None

    def _save_locked(self) -> None:
        payload = self._require_payload()
        if self._key is None or len(self._key) != 32:
            raise VaultLockedError(t("vault.err.keyUnavailable"))
        old_header = copy.deepcopy(self._header)
        if _header_version(self._header) != FORMAT_VERSION and self._pending_v3_header is not None:
            # The first write after a master-password unlock publishes format v3
            # around the unchanged data key.
            promoted = copy.deepcopy(self._pending_v3_header)
            promoted["catalog_version"] = self._catalog_version
            promoted["catalog"] = CATALOG_FORMAT if self._catalog_version == CATALOG_VERSION else LEGACY_CATALOG_IDENTIFIER
            self._header = promoted
        try:
            if self.trash_auto_purge:
                # Expire before validating so state tied to purged items is
                # cleaned up instead of being written to disk unchecked.
                cutoff = int(time.time()) - self.trash_retention_days * 86400
                payload["trash"] = [r for r in payload.get("trash", []) if r["deleted_at"] >= cutoff]
            try:
                _validate_payload(payload, self._catalog_version)
            except ItemSchemaError as exc:
                raise VaultError(str(exc)) from exc
            # Detect another process/recovery operation replacing this vault.
            actual = hashlib.sha256(self.path.read_bytes()).digest() if self.path.exists() else None
            if actual != self._disk_digest:
                raise VaultError(t("vault.err.changedOnDiskChanges"))
            anchor_key = _rollback_anchor_key(self._key)
            vault_id = str(self._header.get("vault_id", ""))
            try:
                anchor_generation, _anchor_upgrade = _read_generation_anchor(
                    self.path, anchor_key, vault_id, require_mac=_header_version(old_header) == FORMAT_VERSION)
            finally:
                _zero(anchor_key)
            current_generation = int(payload.get("generation", 0))
            if current_generation < anchor_generation:
                raise VaultError(t("vault.err.rollbackNewest"))
            payload["generation"] = max(1, current_generation, self._generation_floor,
                                        anchor_generation + (1 if self._disk_digest is not None else 0))
            if _header_version(self._header) == FORMAT_VERSION:
                # Authenticated record that this vault always has a MAC anchor,
                # so a deleted anchor is detected at the next unlock.
                payload[ANCHOR_REQUIRED_KEY] = True
            nonce = os.urandom(12)
            header = copy.deepcopy(self._header)
            header["cipher"]["nonce"] = _b64e(nonce)
            if _header_version(header) == FORMAT_VERSION:
                header["generation"] = int(payload["generation"])
                # R-8: bind the unlock-throttle key in use here (authenticated by the AAD below).
                binding = UnlockThrottle(self.path).binding()
                if binding is not None:
                    header[THROTTLE_BINDING_FIELD] = binding
            # The plaintext catalog lives only in a buffer that is zeroed once
            # it is encrypted, and the data key is used without a copy.
            plaintext = _canonical_json_buffer(payload)
            try:
                if len(plaintext) > MAX_VAULT_BYTES // 2:
                    raise VaultError(t("vault.err.tooLarge"))
                ciphertext = AESGCM(self._key).encrypt(nonce, plaintext, _aad(header))
            finally:
                _zero(plaintext)
                del plaintext
            header["cipher"]["ciphertext"] = _b64e(ciphertext)
            committed = copy.deepcopy(payload)
            disk_digest = hashlib.sha256(json.dumps(header, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode("utf-8")).digest()
            self._rolling_backup()
            atomic_write_json(self.path, header)
            anchor_key = _rollback_anchor_key(self._key)
            try:
                _write_generation_anchor(self.path, int(payload["generation"]), anchor_key, vault_id)
            except OSError:
                self.backup_warning = True
            finally:
                _zero(anchor_key)
            self._header = header
            self._pending_v3_header = None
            self._disk_digest = disk_digest
            self._committed_payload = committed
        except BaseException:
            self._payload = copy.deepcopy(self._committed_payload)
            self._header = old_header
            raise

    def lock(self) -> None:
        scheduler = self._reminder_scheduler
        self._reminder_scheduler = None
        self._reminder_service = None
        if scheduler is not None:
            # Outside the session lock: its thread may be waiting for it.
            scheduler.stop()
        # Waits for a save or transaction running on another thread, so the
        # key is never zeroed while it is encrypting or writing.
        with self._state_lock:
            _zero(self._key)
            self._key = None
            _zero(self._edit_token_key)
            self._edit_token_key = None
            self._payload = None
            self._committed_payload = None
            self._last_catalog_migration_result = None
            self._last_envelope_upgrade_result = None
            self.recovery_unlocked = False
            _zero(self._recovery_entropy)
            self._recovery_entropy = None
            self._workspace_session_generation = uuid.uuid4().hex
        try:
            from .attachments import AttachmentStore
            AttachmentStore.cleanup_profile_temporary(self.path.parent)
        except Exception:
            pass
        gc.collect()


def _validated_sha256(value: str) -> str:
    if not isinstance(value, str):
        raise VaultError("exe_sha256 must be text")
    normalized = value.upper()
    if len(normalized) != 64 or any(ch not in "0123456789ABCDEF" for ch in normalized):
        raise VaultError("exe_sha256 must be a 64-character hexadecimal SHA-256")
    return normalized



def _validated_text(value: str, field: str, max_len: int, *, allow_empty: bool) -> str:
    if not isinstance(value, str):
        raise VaultError(f"{field} must be text")
    if not allow_empty and not value:
        raise VaultError(f"{field} cannot be empty")
    if len(value) > max_len:
        raise VaultError(f"{field} is too long")
    if "\x00" in value:
        raise VaultError(f"{field} contains a null character")
    return value


def _catalog_version_of(header: dict[str, Any]) -> int:
    version = _header_version(header)
    if version == FORMAT_VERSION:
        try:
            catalog_version = int(header.get("catalog_version", CATALOG_VERSION))
        except (TypeError, ValueError) as exc:
            raise VaultError("Vault catalog version is malformed") from exc
        if catalog_version not in (LEGACY_FORMAT_VERSION, CATALOG_VERSION):
            raise VaultError("Unsupported vault catalog version")
        return catalog_version
    return version


def create_vault(
    path: Path,
    master_password: str | SecretText,
    *,
    kdf_overrides: dict[str, int] | None = None,
    backup_dir: Path | None = None,
    backup_count: int = 0,
) -> VaultSession:
    if path.exists():
        raise VaultError(t("vault.err.exists", path=path))
    secret, owned = _master_secret(master_password, t("vault.err.passwordTooShortPrototype"))
    try:
        return _create_vault_with(path, secret, kdf_overrides, backup_dir, backup_count)
    finally:
        if owned:
            secret.wipe()


def _create_vault_with(path: Path, secret: SecretText, kdf_overrides: dict[str, int] | None,
                       backup_dir: Path | None, backup_count: int) -> VaultSession:
    if secret.char_count < 12:
        raise VaultError(t("vault.err.passwordTooShortPrototype"))

    kdf = dict(DEFAULT_KDF)
    if kdf_overrides:
        for key in ("time_cost", "memory_cost_kib", "parallelism", "hash_len"):
            if key in kdf_overrides:
                kdf[key] = int(kdf_overrides[key])
    kdf["salt"] = _b64e(os.urandom(16))
    header: dict[str, Any] = {
        "version": FORMAT_VERSION,
        "format": FORMAT_V3_IDENTIFIER,
        "catalog": CATALOG_FORMAT,
        "catalog_version": CATALOG_VERSION,
        "vault_id": uuid.uuid4().hex,
        "generation": 1,
        "key_generation": 1,
        "kdf": kdf,
        "wrappers": {},
        "cipher": {"name": "aes-256-gcm", "nonce": "", "ciphertext": ""},
    }
    data_key = bytearray(os.urandom(32))
    kek = _derive_key(secret, kdf)
    try:
        nonce, ciphertext = _wrap_key(kek, data_key, _wrapper_aad(header, "password", {"kdf": kdf}))
    finally:
        _zero(kek)
    header["wrappers"]["password"] = {"nonce": _b64e(nonce), "ciphertext": _b64e(ciphertext)}
    session = VaultSession(path, header, data_key, _empty_payload(), backup_dir=backup_dir, backup_count=backup_count)
    session._disk_digest = None  # Creation must not overwrite a concurrently created vault.
    session.save()
    return session


def _validate_v3_header(header: dict[str, Any]) -> None:
    """Structural, bounded validation of the public v3 header before any crypto."""
    if header.get("format") != FORMAT_V3_IDENTIFIER:
        raise VaultError("Unsupported vault format identifier")
    _catalog_version_of(header)
    expected_catalog = CATALOG_FORMAT if header.get("catalog_version", CATALOG_VERSION) == CATALOG_VERSION \
        else LEGACY_CATALOG_IDENTIFIER
    if header.get("catalog") != expected_catalog:
        raise VaultError("Unsupported vault catalog identifier")
    vault_id = header.get("vault_id")
    if not isinstance(vault_id, str) or len(vault_id) != 32 or any(c not in "0123456789abcdef" for c in vault_id):
        raise VaultError("Vault identity is malformed")
    for name in ("generation", "key_generation"):
        value = header.get(name)
        if type(value) is not int or not 0 <= value <= 2**63 - 1:
            raise VaultError(f"Vault {name} is malformed")
    wrappers = header.get("wrappers")
    if not isinstance(wrappers, dict) or not wrappers or len(wrappers) > MAX_WRAPPERS:
        raise VaultError("Vault key wrappers are malformed")
    for name, wrapper in wrappers.items():
        if name not in ("password", "recovery") or not isinstance(wrapper, dict) or len(wrapper) > 8:
            raise VaultError("Vault key wrapper is malformed")
        for field, value in wrapper.items():
            if not isinstance(field, str) or len(field) > 32:
                raise VaultError("Vault key wrapper is malformed")
            if isinstance(value, str):
                if len(value) > MAX_WRAPPER_FIELD_CHARS:
                    raise VaultError("Vault key wrapper is malformed")
            elif type(value) is not int:
                raise VaultError("Vault key wrapper is malformed")
        _validated_wrapper_field(wrapper, "nonce", 12)
        _validated_wrapper_field(wrapper, "ciphertext", 48)
    if "password" not in wrappers:
        raise VaultError("Vault has no master-password key wrapper")
    recovery = wrappers.get("recovery")
    if recovery is not None:
        if recovery.get("kind") != RECOVERY_WRAPPER_KIND:
            raise VaultError("Unsupported recovery wrapper")
        _validated_wrapper_field(recovery, "salt", 16)
    if THROTTLE_BINDING_FIELD in header and not _valid_throttle_binding(header[THROTTLE_BINDING_FIELD]):
        raise VaultError("Vault unlock-throttle binding is malformed")


def _reject_json_constant(name: str) -> Any:
    raise ValueError(f"non-finite number {name}")


def _read_vault_header(path: Path) -> tuple[dict[str, Any], bytes]:
    try:
        if path.stat().st_size > MAX_VAULT_BYTES:
            raise VaultError(t("vault.err.tooLargeAccepted"))
        with path.open("rb") as handle:
            source_bytes = handle.read(MAX_VAULT_BYTES + 1)
        if len(source_bytes) > MAX_VAULT_BYTES:
            raise VaultError(t("vault.err.tooLargeAccepted"))
        # NaN/Infinity are not JSON and the writer never emits them; refusing them here keeps
        # int() on KDF fields from raising OverflowError.
        header = json.loads(source_bytes, parse_constant=_reject_json_constant)
        if not isinstance(header, dict):
            raise VaultError("Vault header must be an object")
    except (OSError, ValueError, RecursionError) as exc:
        # RecursionError: Python 3.14's C decoder raises it for deeply nested input.
        raise VaultError(t("vault.err.unableToRead", detail=exc)) from exc
    if header.get("version") not in SUPPORTED_FORMAT_VERSIONS:
        raise VaultError("Unsupported vault format version")
    if header.get("version") == CATALOG_ENVELOPE_VERSION:
        if header.get("format") != FORMAT_V2_IDENTIFIER or header.get("catalog") != CATALOG_FORMAT:
            raise VaultError("Unsupported vault format identifier")
    cipher = header.get("cipher")
    if not isinstance(cipher, dict) or cipher.get("name") != "aes-256-gcm":
        raise VaultError("Unsupported vault cipher")
    if not isinstance(header.get("kdf"), dict):
        raise VaultError("Vault KDF metadata is missing")
    if header.get("version") == FORMAT_VERSION:
        _validate_v3_header(header)
    return header, source_bytes


def _decrypt_vault(path: Path, header: dict[str, Any], source_bytes: bytes,
                   key: bytearray, *, backup_dir: Path | None = None,
                   backup_count: int = 0, check_anchor: bool = True) -> VaultSession:
    """Consume ownership of the catalog key on success, zero it on every failure."""
    try:
        if len(key) != 32:
            raise VaultError("Invalid vault key length")
        cipher = header["cipher"]
        nonce = _b64d(str(cipher["nonce"]))
        ciphertext = _b64d(str(cipher["ciphertext"]))
        if len(nonce) != 12:
            raise VaultError("Vault nonce has an invalid length")
        version = _catalog_version_of(header)
        # Decrypted into a buffer that is zeroed as soon as it is parsed.
        plaintext = _aesgcm_decrypt(key, nonce, ciphertext, _aad(header))
        try:
            parsed = _json_from_buffer(plaintext)
        finally:
            _zero(plaintext)
            del plaintext
        payload = _validate_payload(parsed, version)
        if _header_version(header) == FORMAT_VERSION and int(payload.get("generation", 0)) != int(header["generation"]):
            raise VaultError("Vault header generation does not match its encrypted catalog")
        anchor_missing = False
        if check_anchor:
            anchor_key = _rollback_anchor_key(key)
            try:
                anchor_missing = _check_generation_anchor(
                    path, payload, anchor_key, str(header.get("vault_id", "")),
                    require_mac=_header_version(header) == FORMAT_VERSION)
            finally:
                _zero(anchor_key)
        session = VaultSession(path, header, key, payload, backup_dir=backup_dir,
                               backup_count=backup_count)
        session._disk_digest = hashlib.sha256(source_bytes).digest()
        session.rollback_anchor_missing = anchor_missing
        return session
    except BaseException as exc:
        key[:] = b"\0" * len(key)
        if isinstance(exc, (InvalidTag, UnicodeDecodeError, json.JSONDecodeError, KeyError)):
            raise InvalidMasterPassword(t("vault.err.wrongPasswordOrModified")) from exc
        raise


def _unwrap_password_wrapper(header: dict[str, Any], master_password: SecretText) -> bytearray:
    """Argon2id(master password) -> KEK -> data key.  The KEK never outlives this call."""
    wrapper = header["wrappers"]["password"]
    nonce = _validated_wrapper_field(wrapper, "nonce", 12)
    ciphertext = _validated_wrapper_field(wrapper, "ciphertext", 48)
    kek = _derive_key(master_password, header["kdf"])
    try:
        try:
            return _unwrap_key(kek, nonce, ciphertext, _wrapper_aad(header, "password", {"kdf": header["kdf"]}))
        except InvalidTag as exc:
            raise InvalidMasterPassword(t("vault.err.wrongPasswordOrModified")) from exc
    finally:
        _zero(kek)


def _unwrap_recovery_wrapper(header: dict[str, Any], wrapper: dict[str, Any], entropy: bytes) -> bytearray:
    salt = _validated_wrapper_field(wrapper, "salt", 16)
    nonce = _validated_wrapper_field(wrapper, "nonce", 12)
    ciphertext = _validated_wrapper_field(wrapper, "ciphertext", 48)
    metadata = {"kind": RECOVERY_WRAPPER_KIND, "salt": wrapper["salt"]}
    recovery_key = _recovery_key(entropy, salt)
    try:
        try:
            return _unwrap_key(recovery_key, nonce, ciphertext, _wrapper_aad(header, "recovery", metadata))
        except InvalidTag as exc:
            raise RecoveryPhraseError(t("vault.err.recoveryWrongVault")) from exc
    finally:
        _zero(recovery_key)


def _open_with_password(path: Path, header: dict[str, Any], source_bytes: bytes, master_password: SecretText, *,
                        backup_dir: Path | None, backup_count: int) -> VaultSession:
    if _header_version(header) == FORMAT_VERSION:
        data_key = _unwrap_password_wrapper(header, master_password)
    else:
        data_key = _derive_key(master_password, header["kdf"])
    return _decrypt_vault(path, header, source_bytes, data_key, backup_dir=backup_dir, backup_count=backup_count)


def _rebind_throttle(session: VaultSession, throttle: UnlockThrottle) -> None:
    """After a verified unlock, re-record a throttle key that had to be replaced (R-8).

    An unreadable key (a profile copied to another Windows account) is
    replaced at the reset; without a save the header would keep naming the
    old key and every later start would fail closed.  Best effort.
    """
    try:
        if _header_version(session._header) == FORMAT_VERSION and throttle._binding_broken():
            session.save()
    except (VaultError, OSError):
        _LOG.warning("Could not re-record the unlock-throttle key for %s.", session.path.name)


def unlock_vault(path: Path, master_password: str | SecretText, *, backup_dir: Path | None = None,
                 backup_count: int = 0, upgrade_envelope: bool = True) -> VaultSession:
    """Open the vault with its master password.

    ``upgrade_envelope=False`` is for read-only probes of a copy (backup
    verification): a v1/v2 envelope is opened as-is, so no migration journal
    or encrypted pre-migration snapshot is written next to the copy.
    """
    path = Path(path)
    if not isinstance(master_password, (str, SecretText)):
        raise InvalidMasterPassword(t("vault.err.passwordEmpty"))
    secret, owned = _master_secret(master_password, t("vault.err.passwordTextInvalid"))
    try:
        throttle = UnlockThrottle(path)
        throttle.check()
        _recover_vault_migration(path)
        header, source_bytes = _read_vault_header(path)
        try:
            session = _open_with_password(path, header, source_bytes, secret,
                                          backup_dir=backup_dir, backup_count=backup_count)
        except InvalidMasterPassword:
            throttle.record_failure()
            raise
        throttle.reset()
        if upgrade_envelope:
            _rebind_throttle(session, throttle)
        if _header_version(header) != FORMAT_VERSION and upgrade_envelope:
            try:
                session._prepare_promotion(secret)
                session._upgrade_envelope_on_unlock()
            except BaseException:
                session.lock()
                raise
        return session
    finally:
        if owned:
            secret.wipe()


def unlock_with_recovery_phrase(path: Path, phrase: str, *, backup_dir: Path | None = None,
                                backup_count: int = 0) -> VaultSession:
    """Open the vault with its 24-word recovery phrase.

    The returned session is marked ``recovery_unlocked`` so the caller can set a
    new master password with ``set_master_password_after_recovery``.  Recovery
    attempts share the master-password throttle.
    """
    path = Path(path)
    throttle = UnlockThrottle(path)
    throttle.check()
    entropy = entropy_from_phrase(phrase)
    _recover_vault_migration(path)
    header, source_bytes = _read_vault_header(path)
    wrapper = header.get("wrappers", {}).get("recovery") if _header_version(header) == FORMAT_VERSION else None
    if not isinstance(wrapper, dict):
        raise RecoveryPhraseError(t("vault.err.noRecoveryPhrase"))
    try:
        data_key = _unwrap_recovery_wrapper(header, wrapper, entropy)
    except RecoveryPhraseError:
        throttle.record_failure()
        raise
    session = _decrypt_vault(path, header, source_bytes, data_key, backup_dir=backup_dir, backup_count=backup_count)
    throttle.reset()
    _rebind_throttle(session, throttle)
    session.recovery_unlocked = True
    session._recovery_entropy = bytearray(entropy)
    return session


def _unlock_vault_with_key(path: Path, key: bytearray, *, expected_context: str,
                           expected_binding: str, backup_dir: Path | None = None,
                           backup_count: int = 0) -> VaultSession:
    """Internal Hello route; consume a key released by the OS cryptographic operation.

    Not exposed in the browser/native-message protocol. A plaintext setting or
    a 'verified' boolean is never accepted as authority to release credentials.
    """
    session = None
    try:
        if not expected_binding:
            raise VaultError(t("vault.err.helloNotAuthorized"))
        header, source_bytes = _read_vault_header(path)
        context = unlock_context_for_header(header)
        if not secrets.compare_digest(context, expected_context):
            raise VaultError(t("vault.err.passwordOrHeaderChanged"))
        session = _decrypt_vault(path, header, source_bytes, key, backup_dir=backup_dir,
                                  backup_count=backup_count)
        if not secrets.compare_digest(session.hello_binding(), expected_binding):
            raise VaultError(t("vault.err.helloRevoked"))
        return session
    except BaseException:
        if session is not None:
            session.lock()
        key[:] = b"\0" * len(key)
        raise


def _unlock_vault_with_face_key(path: Path, key: bytearray, *, expected_context: str,
                                expected_binding: str, backup_dir: Path | None = None,
                                backup_count: int = 0) -> VaultSession:
    """Internal ordinary-webcam route after local liveness and face matching.

    The encrypted vault binding, not a plaintext setting or UI boolean, remains
    the final authority.  This path is intentionally separate from Windows Hello
    so its lower assurance is explicit in code and UI.
    """
    session = None
    try:
        if not expected_binding:
            raise VaultError(t("vault.err.cameraNotAuthorized"))
        header, source_bytes = _read_vault_header(path)
        context = unlock_context_for_header(header)
        if not secrets.compare_digest(context, expected_context):
            raise VaultError(t("vault.err.passwordOrHeaderChanged"))
        session = _decrypt_vault(path, header, source_bytes, key, backup_dir=backup_dir,
                                  backup_count=backup_count)
        if not secrets.compare_digest(session.face_binding(), expected_binding):
            raise VaultError(t("vault.err.cameraRevoked"))
        return session
    except BaseException:
        if session is not None:
            session.lock()
        key[:] = b"\0" * len(key)
        raise


def choose_newest(entries: Iterable[dict[str, Any]]) -> dict[str, Any] | None:
    values = list(entries)
    if not values:
        return None
    return max(values, key=lambda item: int(item.get("updated_at", 0)))
