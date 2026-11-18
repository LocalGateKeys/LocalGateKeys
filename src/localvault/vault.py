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
from collections.abc import Callable, Iterable, Mapping
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from . import composite_key, keyfile, outside_marks, secret_text
from .composite_key import FactorSpec
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
# Format v4: v3 plus key-file / YubiKey factors in the password wrapper (docs/formats/COMPOSITE_KEY_V1.md
# §5).  Written only while a factor is set; every AAD keeps the literal v3 identity.
VERSION_V4 = 4
SUPPORTED_FORMAT_VERSIONS = (LEGACY_FORMAT_VERSION, CATALOG_ENVELOPE_VERSION, FORMAT_VERSION, VERSION_V4)
# Versions with a random data key behind wrappers (same catalog, wrapper and unlock-context encodings).
WRAPPED_KEY_VERSIONS = (FORMAT_VERSION, VERSION_V4)
FORMAT_V2_IDENTIFIER = "localgatekeys-vault-v2"
FORMAT_V3_IDENTIFIER = "localgatekeys-vault-v3"
FORMAT_V4 = "localgatekeys-vault-v4"
MAX_PASSWORD_WRAPPER_FIELDS_V4 = 3  # nonce, ciphertext, factors
MAX_FACTORS = len(composite_key.KINDS)
LEGACY_CATALOG_IDENTIFIER = "localgatekeys-credentials-v1"
AAD_PREFIX = b"localvault-prototype|vault|v1|"
AAD_PREFIX_V2 = b"localgatekeys|vault|v2|"
AAD_PREFIX_V3 = b"localgatekeys|vault|v3|"
WRAPPER_AAD_PREFIX = b"localgatekeys|vault-key-wrapper|v3|"
UNLOCK_CONTEXT_PREFIX = b"localgatekeys|unlock-context|v3|"
ROLLBACK_ANCHOR_INFO = b"localgatekeys|rollback-anchor|v1"
# HKDF info of the key behind BaseVaultSession.site_pair_id (phishing-shield "same account" ids).
SITE_PAIR_INFO = b"localgatekeys|site-pair|v1"
RECOVERY_KEY_INFO = b"localgatekeys|recovery-key|v1"
ROLLBACK_ANCHOR_SCHEME = "hkdf-hmac-sha256-v1"
# Recorded inside the encrypted payload of v3 vaults: an anchor must exist.
ANCHOR_REQUIRED_KEY = "rollback_anchor_required"
RECOVERY_WRAPPER_KIND = "bip39-english-24"
BIP39_ENGLISH_SHA256 = "2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda"
# 256 MiB since 2026-10-30 (was 64 MiB).  The vault, ``.lgk``, ``.lgkfull`` and
# selective-transfer files copy this default; their only readers are Windows and
# the Mac (``FullBackupV2.KDF.isAccepted`` / ``DesktopVaultFile``), both of which
# accept 8-512 MiB.  Phone backup, sync keyring, share and the phone app-password
# KDFs are separate fixed formats and do not follow it.
DEFAULT_KDF = {
    "name": "argon2id",
    "time_cost": 3,
    "memory_cost_kib": 262144,
    "parallelism": 4,
    "hash_len": 32,
}
# Machines with less physical RAM keep the previous 64 MiB for new vaults and are
# never upgraded on unlock (an unknown RAM size counts as low).
KDF_LOW_MEMORY_RAM_BYTES = 4 * 1024 ** 3
LOW_MEMORY_KDF_MEMORY_KIB = 64 * 1024
# Encrypted-payload preference written by a KDF upgrade while Hello/camera were
# bound: the unlock context the sidecars had before it, so a crash between the
# vault publish and the sidecar rewrite is repaired at the next password unlock.
KDF_UPGRADE_CONTEXT_PREF = "kdf_upgrade_previous_context"

MIN_KDF_MEMORY_KIB = 8 * 1024
MAX_KDF_MEMORY_KIB = 512 * 1024
MAX_MASTER_PASSWORD_LENGTH = 4096
MAX_VAULT_BYTES = 24 * 1024 * 1024
MAX_WRAPPER_FIELD_CHARS = 512
MAX_WRAPPERS = 4
VAULT_MIGRATION_JOURNAL_VERSION = 2
MIGRATION_OPERATIONS = ("catalog-v1-to-v2", "envelope-v2-to-v3", "kdf-upgrade")

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


_CLOCK_SLACK_SECONDS = 2 * 86400
# A stored time may run ahead of this computer's clock by at most this much when it moves the clock
# anchor forward (W-L12): a synced record from a peer whose clock is far in the future cannot lift
# the anchor (and so switch off the clock-jump guard) beyond local time plus one day.
_CLOCK_FUTURE_SKEW_SECONDS = 86400


def _newest_payload_time(payload: Any, *, now: float | None = None) -> int:
    """The newest updated/deleted time stored in a payload (0 when none), capped at local ``now``
    plus ``_CLOCK_FUTURE_SKEW_SECONDS``."""
    newest = 0
    if not isinstance(payload, dict):
        return 0
    cap = int(time.time() if now is None else now) + _CLOCK_FUTURE_SKEW_SECONDS
    for key in ("updated_at", "created_at"):
        value = payload.get(key)
        if isinstance(value, int) and not isinstance(value, bool):
            newest = max(newest, min(value, cap))
    for group in ("items", "entries", "trash"):
        for record in payload.get(group) or ():
            if isinstance(record, dict):
                for key in ("updated_at", "deleted_at", "created_at"):
                    value = record.get(key)
                    if isinstance(value, int) and not isinstance(value, bool):
                        newest = max(newest, min(value, cap))
    return newest


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


class VaultTooNew(VaultError):
    """The vault's format version is above the newest this build knows (``VERSION_V4``)."""

    def __init__(self, version: int):
        self.version = int(version)
        super().__init__(t("vault.err.tooNew"))


_FACTOR_REQUIRED_MESSAGES = {
    (composite_key.KEYFILE,): "vault.err.factorRequiredKeyFile",
    (composite_key.YUBIKEY_HMAC,): "vault.err.factorRequiredYubiKey",
    composite_key.KINDS: "vault.err.factorRequiredBoth",
}


class FactorRequired(VaultError):
    """The vault lists key-file / YubiKey factors that were not supplied (``kinds``, in list order).

    Raised before any key derivation; it is not a password failure.  The recovery phrase opens the
    vault without the factors.
    """

    def __init__(self, kinds: Iterable[str]):
        kinds = list(kinds)
        self.kinds = [kind for kind in composite_key.KINDS if kind in kinds]
        super().__init__(t(_FACTOR_REQUIRED_MESSAGES.get(tuple(self.kinds), "vault.err.factorRequiredBoth")))


class FactorMismatch(VaultError, composite_key.FactorMismatch):
    """``composite_key.FactorMismatch`` as a user error: the key file or YubiKey is not this vault's.

    Raised from the factor's ``check`` before Argon2 runs, and never counted by ``UnlockThrottle``.
    """

    def __init__(self, kind: str):
        Exception.__init__(self, t("vault.err.keyFileMismatch" if kind == composite_key.KEYFILE
                                   else "vault.err.yubiKeyMismatch"))
        self.kind = kind


@dataclass(frozen=True)
class FactorSecrets:
    """What the user supplies for a vault's factors at unlock.

    ``keyfile`` is the key file's bytes (``keyfile.key_from_bytes`` turns them into the secret);
    ``yubikey_response`` receives the 64-byte padded challenge and returns the YubiKey's 20-byte
    HMAC-SHA1 response, so the vault code never touches hardware.
    """

    keyfile: bytes | None = None
    yubikey_response: Callable[[bytes], bytes] | None = None


@dataclass(frozen=True)
class FactorInput:
    """A factor to add: ``kind`` "keyfile" (``keyfile_bytes``) or "yubikey-hmac" (``responder``, ``slot`` 1/2)."""

    kind: str
    keyfile_bytes: bytes | None = None
    slot: int | None = None
    responder: Callable[[bytes], bytes] | None = None


class _HeldFactors:
    """The factors a session was unlocked with, for later password checks; ``lock()`` wipes them.

    Only the key file's 32-byte secret is kept (a zeroable buffer).  A YubiKey is kept as its
    responder callable and asked again each time: its response is never stored beyond one use.
    """

    def __init__(self, keyfile_secret: bytearray | None = None,
                 responder: Callable[[bytes], bytes] | None = None) -> None:
        self.keyfile_secret = keyfile_secret
        self.responder = responder

    def wipe(self) -> None:
        _zero(self.keyfile_secret)
        self.keyfile_secret = None
        self.responder = None


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
        "sharing": "vault.proNeededSharing",
        "travel": "travel.needsPro",
        "hygiene_bulk": "hygiene.bulkNeedsPro",
        "access_policies": "access.needsPro",
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


def _has_wrapped_key(header: dict[str, Any]) -> bool:
    """Format 3 or 4: a random data key behind password / recovery wrappers."""
    return _header_version(header) in WRAPPED_KEY_VERSIONS


def _v3_identity(header: dict[str, Any]) -> dict[str, Any]:
    """Public, stable identity fields shared by every v3 authenticated encoding.

    A v4 header authenticates the literal v3 identity (COMPOSITE_KEY_V1.md §5), so its catalog,
    recovery wrapper and unlock context match the same header written as v3.
    """
    return {
        "version": FORMAT_VERSION,
        "format": FORMAT_V3_IDENTIFIER if _header_version(header) == VERSION_V4
        else header.get("format", FORMAT_V3_IDENTIFIER),
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
    if version in WRAPPED_KEY_VERSIONS:
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


def _header_factor_specs(header: dict[str, Any]) -> list[FactorSpec]:
    """The factor list of a v4 header (validated, §2 order); ``[]`` for any other version."""
    if _header_version(header) != VERSION_V4:
        return []
    wrappers = header.get("wrappers")
    wrapper = wrappers.get("password") if isinstance(wrappers, dict) else None
    value = wrapper.get("factors") if isinstance(wrapper, dict) else None
    if not isinstance(value, list) or not 1 <= len(value) <= MAX_FACTORS:
        raise VaultError("Vault key factors are malformed")
    try:
        specs = [FactorSpec.from_json(item) for item in value]
        composite_key.validate_specs(specs)
    except (ValueError, TypeError) as exc:
        raise VaultError("Vault key factors are malformed") from exc
    return specs


def _password_metadata(header: dict[str, Any], specs: list[FactorSpec]) -> dict[str, Any]:
    """The password wrapper's authenticated metadata: the KDF, plus the factor list in v4."""
    metadata: dict[str, Any] = {"kdf": header["kdf"]}
    if specs:
        metadata["factors"] = [spec.to_json() for spec in specs]
    return metadata


def _set_factor_format(header: dict[str, Any], specs: list[FactorSpec]) -> None:
    """v4 while a factor is set, v3 otherwise (a vault without factors stays v3 byte for byte)."""
    if specs:
        header["version"], header["format"] = VERSION_V4, FORMAT_V4
    else:
        header["version"], header["format"] = FORMAT_VERSION, FORMAT_V3_IDENTIFIER


def _zero_all(buffers: Iterable[bytearray]) -> None:
    for buffer in buffers:
        _zero(buffer)


def _factor_secret(spec: FactorSpec, factors: FactorSecrets | None, held: _HeldFactors | None) -> bytearray:
    """One factor's 32-byte secret, checked against ``spec.check`` (raises ``FactorMismatch``)."""
    if spec.kind == composite_key.KEYFILE:
        if factors is not None and factors.keyfile is not None:
            try:
                secret = bytearray(keyfile.key_from_bytes(bytes(factors.keyfile)))
            except ValueError:  # KeyFileError: not a usable key file
                raise FactorMismatch(spec.kind) from None
        else:
            if held is None or held.keyfile_secret is None:
                raise FactorRequired([spec.kind])
            secret = bytearray(held.keyfile_secret)
    else:
        responder = factors.yubikey_response if factors is not None and factors.yubikey_response else None
        if responder is None:
            if held is None or held.responder is None:
                raise FactorRequired([spec.kind])
            responder = held.responder
        try:
            response = responder(spec.padded_challenge)
        except VaultError:
            raise
        except Exception as exc:  # noqa: BLE001 - no answer from the YubiKey: treat it as not there
            raise FactorRequired([spec.kind]) from exc
        try:
            secret = bytearray(composite_key.yubikey_secret(response))
        except (ValueError, TypeError):
            raise FactorMismatch(spec.kind) from None
        finally:
            if isinstance(response, bytearray):
                _zero(response)
    if not hmac.compare_digest(composite_key.factor_check(secret), spec.check):
        _zero(secret)
        raise FactorMismatch(spec.kind)
    return secret


def _resolve_factor_secrets(specs: list[FactorSpec], factors: FactorSecrets | None,
                            held: _HeldFactors | None = None) -> list[bytearray]:
    """The secrets for ``specs`` in list order (the caller zeroes them); no key derivation runs.

    Every factor must be supplied (``factors`` first, then what the session holds), else
    ``FactorRequired`` names the missing ones before anything is asked of a YubiKey.  Each secret
    is checked as soon as it is known, so a wrong key file is reported before the YubiKey is used.
    """
    missing = []
    for spec in specs:
        if spec.kind == composite_key.KEYFILE:
            supplied = (factors is not None and factors.keyfile is not None) or \
                (held is not None and held.keyfile_secret is not None)
        else:
            supplied = (factors is not None and factors.yubikey_response is not None) or \
                (held is not None and held.responder is not None)
        if not supplied:
            missing.append(spec.kind)
    if missing:
        raise FactorRequired(missing)
    found: list[bytearray] = []
    try:
        for spec in specs:
            found.append(_factor_secret(spec, factors, held))
    except BaseException:
        _zero_all(found)
        raise
    return found


def _password_kek(password: str | SecretText, kdf: dict[str, Any], specs: list[FactorSpec],
                  factor_secrets: list[bytearray]) -> bytearray:
    """The password wrapper's key: the Argon2id KEK, combined with the factor secrets in v4 (§4)."""
    try:
        return composite_key.derive_wrapping_key(lambda: _derive_key(password, kdf), specs, factor_secrets)
    except composite_key.FactorMismatch as exc:
        if isinstance(exc, FactorMismatch):
            raise
        raise FactorMismatch(exc.kind) from None


def _enrol_yubikey(responder: Callable[[bytes], bytes], slot: int) -> tuple[FactorSpec, bytearray]:
    """A ``yubikey-hmac`` factor with a new challenge, answered by ``responder`` now."""
    challenge = composite_key.new_challenge()
    try:
        response = responder(composite_key.pad_challenge(challenge))
    except VaultError:
        raise
    except Exception as exc:  # noqa: BLE001 - no answer from the YubiKey: treat it as not there
        raise FactorRequired([composite_key.YUBIKEY_HMAC]) from exc
    try:
        secret = bytearray(composite_key.yubikey_secret(response))
    except (ValueError, TypeError):
        # Not a 20-byte HMAC-SHA1 answer: the slot is most likely not set up for challenge-response.
        raise VaultError(t("vault.err.yubiKeyBadAnswer", slot=slot)) from None
    finally:
        if isinstance(response, bytearray):
            _zero(response)
    spec = FactorSpec(kind="yubikey-hmac", check=composite_key.factor_check(secret), slot=slot,
                      challenge=challenge.hex())
    return spec, secret


def _enrol_factor(new: FactorInput) -> tuple[FactorSpec, bytearray]:
    """The spec and secret of a factor being added (the caller zeroes the secret)."""
    if not isinstance(new, FactorInput):
        raise VaultError("Unknown unlock factor")
    if new.kind == composite_key.KEYFILE:
        if not isinstance(new.keyfile_bytes, (bytes, bytearray)):
            raise VaultError(t("vault.err.keyFileInvalid"))
        try:
            secret = bytearray(keyfile.key_from_bytes(bytes(new.keyfile_bytes)))
        except ValueError:
            raise VaultError(t("vault.err.keyFileInvalid")) from None
        return FactorSpec(kind="keyfile", check=composite_key.factor_check(secret)), secret
    if new.kind == composite_key.YUBIKEY_HMAC:
        slot = 2 if new.slot is None else new.slot
        if type(slot) is not int or slot not in composite_key.YUBIKEY_SLOTS or not callable(new.responder):
            raise VaultError("A YubiKey factor needs slot 1 or 2 and a responder")
        return _enrol_yubikey(new.responder, slot)
    raise VaultError("Unknown unlock factor")


def _unlock_sidecar_kinds() -> list[tuple[str, str, Any]]:
    """``(name, payload binding key, upgrade_envelope_context)`` for every local unlock sidecar."""
    from .face_unlock import upgrade_envelope_context as upgrade_face
    from .fido_unlock import upgrade_envelope_context as upgrade_fido
    from .hello_unlock import upgrade_envelope_context as upgrade_hello
    return [("face", "face_binding", upgrade_face), ("fido", "fido_binding", upgrade_fido),
            ("hello", "hello_binding", upgrade_hello)]


def unlock_context_for_header(header: dict[str, Any]) -> str:
    """Hex digest that local unlock sidecars (Hello/camera) bind to.

    It is stable across ordinary saves, and changes when the master password,
    the key generation or the vault format changes, so a stale sidecar is
    refused before any native prompt is shown.  Adding or removing a key-file /
    YubiKey factor (v3 <-> v4) does not change it: v4 uses the v3 identity.
    """
    if _has_wrapped_key(header):
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


def _total_physical_memory_bytes() -> int | None:
    """Installed physical RAM in bytes, or None when it cannot be read."""
    try:
        if sys.platform == "win32":
            class _MemoryStatusEx(ctypes.Structure):
                _fields_ = [("dwLength", ctypes.c_ulong), ("dwMemoryLoad", ctypes.c_ulong),
                            ("ullTotalPhys", ctypes.c_ulonglong), ("ullAvailPhys", ctypes.c_ulonglong),
                            ("ullTotalPageFile", ctypes.c_ulonglong), ("ullAvailPageFile", ctypes.c_ulonglong),
                            ("ullTotalVirtual", ctypes.c_ulonglong), ("ullAvailVirtual", ctypes.c_ulonglong),
                            ("ullAvailExtendedVirtual", ctypes.c_ulonglong)]

            status = _MemoryStatusEx()
            status.dwLength = ctypes.sizeof(_MemoryStatusEx)
            if not ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(status)):
                return None
            return int(status.ullTotalPhys) or None
        total = int(os.sysconf("SC_PAGE_SIZE")) * int(os.sysconf("SC_PHYS_PAGES"))
        return total if total > 0 else None
    except (AttributeError, OSError, ValueError, TypeError):
        return None


def _low_memory_machine() -> bool:
    total = _total_physical_memory_bytes()
    return total is None or total < KDF_LOW_MEMORY_RAM_BYTES


def _default_kdf() -> dict[str, Any]:
    """KDF parameters for a new password wrapper on this machine (no salt)."""
    kdf: dict[str, Any] = dict(DEFAULT_KDF)
    if _low_memory_machine():
        kdf["memory_cost_kib"] = min(int(kdf["memory_cost_kib"]), LOW_MEMORY_KDF_MEMORY_KIB)
    return kdf


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


#: DPAPI entropy of the high-water mark kept outside the vault folder (``outside_marks``).
_THROTTLE_MARK_ENTROPY = b"localgatekeys|unlock-throttle-mark|v1"
_THROTTLE_MARK_PURPOSE = "unlock-throttle"
_THROTTLE_ID_MARK_PURPOSE = "unlock-throttle-id"


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

    Audit 2026-11-10: all of these files sit in the vault folder, so copying
    the folder before guessing and putting it back reset the count.  Each
    failure therefore also raises a high-water mark kept outside the folder
    (``outside_marks``: HKCU on Windows, DPAPI-sealed when available), and the
    count read at start is the larger of the two.  A missing or unreadable
    mark falls back to the folder counter (never a lock-out, never lower); a
    malformed one fails closed like a forged counter.  A success clears both.
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
        if not isinstance(header, dict) or header.get("version") not in WRAPPED_KEY_VERSIONS:
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

    # -- high-water mark outside the vault folder (audit 2026-11-10) ----------
    def _mark_name(self) -> str:
        return outside_marks.name_for(_THROTTLE_MARK_PURPOSE, self.path)

    def _header_vault_id(self) -> str | None:
        return header_vault_id(self.path)

    def _id_mark_name(self) -> str | None:
        """Design decision 2026-11-12: a second mark keyed by the vault id, so a copy of the folder opened from
        another path still finds the count (the path mark alone starts at zero there)."""
        vault_id = self._header_vault_id()
        if vault_id is None:
            return None
        return outside_marks.name_for_id(_THROTTLE_ID_MARK_PURPOSE, vault_id)

    def _outside_failures(self) -> int | None:
        """The larger count of the path and vault-id marks; None when neither can be read (the folder counter
        then decides)."""
        counts = [self._path_mark_failures()]
        vault_id = self._header_vault_id()
        if vault_id is not None:
            counts.append(self._read_mark(outside_marks.name_for_id(_THROTTLE_ID_MARK_PURPOSE, vault_id),
                                          "vault_id", vault_id))
        known = [count for count in counts if count is not None]
        return max(known) if known else None

    def _path_mark_failures(self) -> int | None:
        return self._read_mark(self._mark_name(), "location", _throttle_location(self.path))

    def _read_mark(self, name: str, bound_field: str, bound_value: str) -> int | None:
        """One mark's count; None when it is missing or cannot be read; malformed fails closed."""
        try:
            raw = outside_marks.read(name)
        except OSError:
            return None
        if raw is None:
            return None
        try:
            record = json.loads(raw)
            if not isinstance(record, dict):
                raise ValueError
            if "dpapi" in record:
                if not isinstance(record["dpapi"], str):
                    raise ValueError
                opened = _dpapi_unprotect(record["dpapi"], _THROTTLE_MARK_ENTROPY)
                if opened is None:
                    return None  # no DPAPI here: cannot read it, which must not lock the owner out
                record = json.loads(opened)
                if not isinstance(record, dict):
                    raise ValueError
            failures = record.get("failures")
            if type(failures) is not int or failures < 0 or record.get(bound_field) != bound_value:
                raise ValueError
            return failures
        except (ValueError, TypeError, RecursionError):
            _LOG.warning("Unlock attempt mark for %s is malformed; failing closed.", self.path.name)
            return THROTTLE_FAIL_CLOSED_FAILURES

    def _raise_outside_mark(self, failures: int) -> None:
        """Best effort; never lowers a mark another process raised meanwhile."""
        failures = max(int(failures), self._outside_failures() or 0)
        marks = [(self._mark_name(), {"failures": failures, "location": _throttle_location(self.path)})]
        vault_id = self._header_vault_id()
        if vault_id is not None:
            marks.append((outside_marks.name_for_id(_THROTTLE_ID_MARK_PURPOSE, vault_id),
                          {"failures": failures, "vault_id": vault_id}))
        for name, record in marks:
            body = _canonical_json(record)
            sealed = _dpapi_protect(body, "LocalGateKeys unlock attempts", _THROTTLE_MARK_ENTROPY)
            value = json.dumps({"dpapi": sealed}) if sealed is not None else body.decode("utf-8")
            outside_marks.write(name, value)

    def _delete_outside_marks(self) -> None:
        outside_marks.delete(self._mark_name())
        id_mark = self._id_mark_name()
        if id_mark is not None:
            outside_marks.delete(id_mark)

    def _load_failures(self) -> int:
        folder = self._load_folder_failures()
        outside = self._outside_failures()
        return folder if outside is None else max(folder, outside)

    def _load_folder_failures(self) -> int:
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
            self._raise_outside_mark(failures)

    def reset(self) -> None:
        with _THROTTLE_LOCK:
            _THROTTLE_STATE[self._id] = {"failures": 0.0, "not_before": _monotonic()}
            self._store_failures(0)
            self._delete_outside_marks()


def header_vault_id(path: Path | str) -> str | None:
    """The v3/v4 header's ``vault_id`` (authenticated by the catalog AAD), read without unlocking; None when the
    file is missing, unreadable or older.  Keys the outside marks that must follow a copy to another folder."""
    path = Path(path)
    try:
        if not path.is_file() or path.stat().st_size > MAX_VAULT_BYTES:
            return None
        header = json.loads(path.read_bytes())
    except (OSError, ValueError, RecursionError):
        return None
    if not isinstance(header, dict) or header.get("version") not in WRAPPED_KEY_VERSIONS:
        return None
    vault_id = header.get("vault_id")
    return vault_id if isinstance(vault_id, str) and 0 < len(vault_id) <= 128 else None


def unlock_throttle(path: Path) -> UnlockThrottle:
    return UnlockThrottle(path)


def remaining_backoff_seconds(path: Path) -> float:
    """Seconds until the next master-password attempt for this vault is accepted."""
    return UnlockThrottle(path).remaining_backoff_seconds()


# --------------------------------------------------------------------------
# Rollback marks outside the vault folder (known-limitations plan, item 1)
# --------------------------------------------------------------------------
#
# The anchor beside the vault cannot tell an older vault+anchor pair copied back from the real one, so every
# committed generation is also recorded outside the folder (``outside_marks``: HKCU on Windows, DPAPI-sealed when
# available): generation + HMAC under the rollback-anchor key, bound to the vault id.  Two values, as the unlock
# throttle keeps: one named by the vault's path, one by its vault id (which also holds, encrypted under the anchor
# key, the path where it was last raised).
#
# Rules (a false "rolled back" refusal locks the owner out of a good vault, so each refusal needs proof):
# - A mark refuses only when it authenticates under this vault's data key and is higher than the vault.
# - A mark that does not authenticate (another vault that lived at this path, a copy whose data key was rotated,
#   garbage) is ignored and replaced, never a refusal: whoever can write it can also delete it, so refusing on it
#   adds no protection and only creates lock-outs.  An unreadable store (or a sealed value without DPAPI here) is
#   ignored and left as it is.  A missing mark is minted again.
# - The path mark decides at its path.  The vault-id mark decides only on the app's own unlock of the live vault
#   (``MARKS_LIVE``) at a path without a valid path mark (a moved folder): it refuses when the place it was raised
#   at is this path or no longer holds this vault (the folder was moved, then an older copy put there); when that
#   place still holds the vault (two live copies, e.g. a backup restored as a second profile) the unlock is only
#   flagged (``rollback_anchor_missing``), since refusing would lock the restored profile out.
# - Copies (``check_anchor=False``, read-only probes) never read or write a mark.  Restores set the destination's
#   marks to exactly the restored generation once the restored vault is in place (``write_rollback_anchor``,
#   ``mark_restored``), never before: a restore that stops earlier leaves them as they were.
# - A data-key rotation (every master-password change) keeps a record under each retired key, the last
#   ``_ROLLBACK_MARK_RETIRED_MAX`` of them, so a copy under one of those keys is refused too; the v3 upgrade keeps
#   one for the format 1/2 vault it replaced (no vault id).

_ROLLBACK_MARK_ENTROPY = b"localgatekeys|rollback-mark|v1"
_ROLLBACK_MARK_PLACE_INFO = b"localgatekeys|rollback-mark-place|v1"
_ROLLBACK_MARK_NONCE_INFO = b"localgatekeys|rollback-mark-place-nonce|v1"
_ROLLBACK_MARK_SCHEME = "localgatekeys-rollback-mark-v1"
_ROLLBACK_MARK_PURPOSE = "rollback-mark"
_ROLLBACK_ID_MARK_PURPOSE = "rollback-mark-id"
#: ``_decrypt_vault`` mark handling: none (copies and probes), the path mark only, or the app's live unlock.
MARKS_OFF, MARKS_COPY, MARKS_LIVE = "off", "copy", "live"


@dataclass(frozen=True)
class _RollbackMark:
    state: str  # "ok", "missing", "foreign" (does not authenticate) or "unreadable"
    generation: int = 0
    place: str | None = None  # vault-id mark: where it was last raised (normalised absolute path)
    settled: bool = True  # False while it still carries a data-key rotation's second MAC
    retired: Any = None  # the records of the data keys rotations retired (newest first), carried forward by raises
    own: bool = True  # False: it authenticated only through one of those records (a vault under a retired key)


def _mark_place(path: Path) -> str:
    return os.path.normcase(str(Path(path).absolute()))


def _mark_location(path: Path) -> str:
    return hashlib.sha256(b"localgatekeys|rollback-mark-location|v1|"
                          + _mark_place(path).encode("utf-8")).hexdigest()[:32]


def _rollback_mark_names(path: Path, vault_id: str) -> list[tuple[str, str]]:
    names = [("path", outside_marks.name_for(_ROLLBACK_MARK_PURPOSE, path))]
    if vault_id:
        names.append(("id", outside_marks.name_for_id(_ROLLBACK_ID_MARK_PURPOSE, vault_id)))
    return names


def _rollback_mark_mac(anchor_key: bytes | bytearray, kind: str, generation: int, vault_id: str,
                       place: str) -> bytes:
    body = _canonical_json({"scheme": _ROLLBACK_MARK_SCHEME, "kind": kind, "generation": int(generation),
                            "vault_id": vault_id, "place": place})
    return hmac.new(anchor_key, body, hashlib.sha256).digest()


def _seal_mark_place(anchor_key: bytes | bytearray, vault_id: str, generation: int, path: Path) -> str:
    """The place, encrypted under the anchor key with the vault id as AAD.  The nonce is derived (HMAC under its own
    subkey over the generation, vault id and place), never drawn: raising a mark must take nothing from the random
    source, or it would shift every later random byte of the save it follows (the deterministic backup vectors
    replay that stream).  A nonce repeats only for the same generation, vault id and place, i.e. the same
    plaintext and AAD, which gives the same ciphertext again and reveals nothing new."""
    key = _hkdf(anchor_key, _ROLLBACK_MARK_PLACE_INFO)
    nonce_key = _hkdf(anchor_key, _ROLLBACK_MARK_NONCE_INFO)
    try:
        place = _mark_place(path)
        nonce = hmac.new(nonce_key, _canonical_json({"generation": int(generation), "vault_id": vault_id,
                                                     "place": place}), hashlib.sha256).digest()[:12]
        # As for the catalog: the key is handed over as its bytearray and the plaintext is a buffer zeroed after.
        plaintext = bytearray(place.encode("utf-8"))
        try:
            return _b64e(nonce + AESGCM(key).encrypt(nonce, plaintext, vault_id.encode("utf-8")))
        finally:
            _zero(plaintext)
    finally:
        _zero(key)
        _zero(nonce_key)


def _open_mark_place(anchor_key: bytes | bytearray, vault_id: str, sealed: str) -> str | None:
    key = _hkdf(anchor_key, _ROLLBACK_MARK_PLACE_INFO)
    try:
        raw = _b64d(sealed)
        if len(raw) < 12 + 16:
            return None
        plaintext = _aesgcm_decrypt(key, raw[:12], raw[12:], vault_id.encode("utf-8"))
        try:
            return plaintext.decode("utf-8")
        finally:
            _zero(plaintext)
    except (VaultError, InvalidTag, ValueError):
        return None  # sealed under a rotation's other key
    finally:
        _zero(key)


#: Retired-key records a mark keeps (newest first): a copy from before more data-key changes than this (each
#: master-password change is one) is no longer recognised by the marks.  Bounded so a value stays small.
_ROLLBACK_MARK_RETIRED_MAX = 8


def _retired_mark(retired_key: bytes | bytearray, kind: str, generation: int, vault_id: str,
                  path: Path) -> dict[str, Any]:
    """After a data-key rotation: the generation the new key starts at, under the retired key.  Any vault still
    under that key is older, so a copy taken before a master-password change and put back is refused too.
    ``vault_id`` is the one the retired vault had: "" for a format 1/2 vault the v3 upgrade gave its id."""
    place = _mark_location(path) if kind == "path" else ""
    return {"generation": int(generation),
            "mac": _b64e(_rollback_mark_mac(retired_key, "retired-" + kind, generation, vault_id, place))}


def _retired_records(value: Any) -> list[dict[str, Any]]:
    """A stored ``retired`` field as a list (values written before the chain kept a single record)."""
    if isinstance(value, dict):
        return [value]
    if isinstance(value, list):
        return [record for record in value[:_ROLLBACK_MARK_RETIRED_MAX] if isinstance(record, dict)]
    return []


def _rollback_mark_value(anchor_key: bytes | bytearray, kind: str, generation: int, vault_id: str, path: Path, *,
                         previous_key: bytes | bytearray | None = None, retired: Any = None) -> str:
    """The stored value; ``previous_key`` adds a second MAC so a data-key rotation cut short opens either vault,
    ``retired`` keeps the records of the data keys rotations retired (``_retired_mark``, newest first)."""
    place = _mark_location(path) if kind == "path" else _seal_mark_place(anchor_key, vault_id, generation, path)
    record: dict[str, Any] = {"version": 1, "generation": int(generation), "place": place,
                              "mac": _b64e(_rollback_mark_mac(anchor_key, kind, generation, vault_id, place))}
    if previous_key is not None:
        record["previous"] = _b64e(_rollback_mark_mac(previous_key, kind, generation, vault_id, place))
    retired = _retired_records(retired)
    if retired:
        record["retired"] = retired
    body = _canonical_json(record)
    sealed = _dpapi_protect(body, "LocalGateKeys rollback mark", _ROLLBACK_MARK_ENTROPY)
    return json.dumps({"dpapi": sealed}) if sealed is not None else body.decode("utf-8")


def _read_rollback_mark(name: str, kind: str, anchor_key: bytes | bytearray, vault_id: str,
                        path: Path) -> _RollbackMark:
    try:
        raw = outside_marks.read(name)
    except OSError:
        return _RollbackMark("unreadable")
    if raw is None:
        return _RollbackMark("missing")
    try:
        record = json.loads(raw)
        if not isinstance(record, dict):
            raise ValueError
        if "dpapi" in record:
            if not isinstance(record["dpapi"], str):
                raise ValueError
            opened = _dpapi_unprotect(record["dpapi"], _ROLLBACK_MARK_ENTROPY)
            if opened is None:
                return _RollbackMark("unreadable")  # sealed, and no DPAPI here to open it
            record = json.loads(opened)
            if not isinstance(record, dict):
                raise ValueError
        generation, place = record.get("generation"), record.get("place")
        if type(generation) is not int or not 0 <= generation <= 2**63 - 1 or not isinstance(place, str):
            raise ValueError
        if kind == "path" and place != _mark_location(path):
            raise ValueError
        expected = _rollback_mark_mac(anchor_key, kind, generation, vault_id, place)
        macs = [record.get(field) for field in ("mac", "previous")]
        retired = _retired_records(record.get("retired"))
        if any(isinstance(mac, str) and hmac.compare_digest(_b64d(mac), expected) for mac in macs):
            where = _open_mark_place(anchor_key, vault_id, place) if kind == "id" else None
            return _RollbackMark("ok", generation, where, "previous" not in record, retired or None)
        for entry in retired:
            retired_generation, retired_mac = entry.get("generation"), entry.get("mac")
            if (type(retired_generation) is int and 0 <= retired_generation <= 2**63 - 1
                    and isinstance(retired_mac, str)
                    and hmac.compare_digest(retired_mac,
                                            _retired_mark(anchor_key, kind, retired_generation, vault_id,
                                                          path)["mac"])):
                # A vault under a key a rotation retired (or from before the v3 upgrade gave it its id).
                return _RollbackMark("ok", retired_generation, own=False)
        raise ValueError
    except (ValueError, TypeError, RecursionError, VaultError):
        return _RollbackMark("foreign")


def _rollback_mark_refusal() -> str:
    """The refusal when a mark is newer than the vault: unlike the anchor's message, it names the way back to an
    older state on purpose (a vault folder put back by hand, for example from File History, is refused)."""
    return t("vault.err.rollbackMarkOlder", restore=t("command.backup-restore.title"))


def _check_rollback_marks(path: Path, generation: int, anchor_key: bytes | bytearray, vault_id: str, *,
                          live: bool) -> tuple[bool, bool]:
    """Refuse a vault older than an authenticated mark (rules above); nothing is written.

    Returns (the path mark authenticated, flag the unlock: an older second copy of a vault that is still live).
    """
    path_mark = _read_rollback_mark(outside_marks.name_for(_ROLLBACK_MARK_PURPOSE, path), "path", anchor_key,
                                    vault_id, path)
    if path_mark.state == "ok":
        if path_mark.generation > generation:
            raise VaultError(_rollback_mark_refusal())
        return True, False
    if path_mark.state == "foreign":
        _LOG.warning("Rollback mark for %s does not belong to this vault; it is replaced.", path.name)
    if not live or not vault_id:
        return False, False
    id_mark = _read_rollback_mark(outside_marks.name_for_id(_ROLLBACK_ID_MARK_PURPOSE, vault_id), "id",
                                  anchor_key, vault_id, path)
    if id_mark.state != "ok" or id_mark.generation <= generation:
        return False, False
    place = id_mark.place
    if place is not None and (place == _mark_place(path) or header_vault_id(Path(place)) != vault_id):
        raise VaultError(_rollback_mark_refusal())
    # Another copy still holds this vault id (or the mark is from a key a rotation retired, so where it was
    # raised cannot be read): flag it instead of locking this copy out.
    _LOG.warning("A newer copy of the vault at %s may still be on this PC.", path.name)
    return False, True


def _raise_rollback_marks(path: Path, generation: int, anchor_key: bytes | bytearray, vault_id: str, *,
                          exact: bool = False, previous_key: bytes | bytearray | None = None,
                          retired_key: bytes | bytearray | None = None,
                          retired_vault_id: str | None = None) -> None:
    """Best effort: raise both marks to ``generation`` (never lower an authenticated one), or with ``exact`` set
    them to it (a confirmed restore, a data-key rotation).  ``previous_key`` / ``retired_key``: a rotation's
    old key (``_rollback_mark_value``, ``_retired_mark``); ``retired_vault_id`` the retired vault's id when it
    differs (the v3 upgrade).  The retired-key records of a mark that authenticates under this key (or
    ``previous_key``) are carried forward, newest first, at most ``_ROLLBACK_MARK_RETIRED_MAX``.  A failure never
    blocks an unlock or a save."""
    try:
        for kind, name in _rollback_mark_names(path, vault_id):
            mark = _read_rollback_mark(name, kind, anchor_key, vault_id, path)
            if not exact:
                if mark.state == "unreadable":
                    continue
                if mark.state == "ok" and (
                        mark.generation > generation
                        or (mark.generation == generation and mark.settled
                            and (kind == "path" or mark.place == _mark_place(path)))):
                    continue
            elif not (mark.state == "ok" and mark.own) and previous_key is not None:
                mark = _read_rollback_mark(name, kind, previous_key, vault_id, path)  # mid-rotation: the old key
            retired = list(mark.retired or []) if mark.state == "ok" and mark.own else []
            if retired_key is not None:
                retired.insert(0, _retired_mark(retired_key, kind, generation,
                                                vault_id if retired_vault_id is None else retired_vault_id, path))
            outside_marks.write(name, _rollback_mark_value(anchor_key, kind, generation, vault_id, path,
                                                           previous_key=previous_key,
                                                           retired=retired[:_ROLLBACK_MARK_RETIRED_MAX]))
    except Exception:  # noqa: BLE001 - the marks are best effort
        _LOG.warning("Could not update the rollback mark for %s.", Path(path).name)


def forget_rollback_marks(path: Path | str) -> None:
    """Best effort: delete the rollback marks of the vault at ``path`` (its path mark, and its vault-id mark when
    the file is still there to name it), for a vault being removed for good (the duress vault, an erased
    profile), so the store does not keep a value computed from its path.  Call it before the files go."""
    path = Path(path)
    names = [outside_marks.name_for(_ROLLBACK_MARK_PURPOSE, path)]
    vault_id = header_vault_id(path)
    if vault_id:
        names.append(outside_marks.name_for_id(_ROLLBACK_ID_MARK_PURPOSE, vault_id))
    for name in names:
        outside_marks.delete(name)


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
    wrappers = header.get("wrappers") if _has_wrapped_key(header) else None
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
        self._last_kdf_upgrade_result: dict[str, Any] | None = None
        self._pending_v3_header: dict[str, Any] | None = None
        self.reenroll_required: tuple[str, ...] = ()
        self.recovery_unlocked = False
        # Entropy of the recovery phrase that opened a ``recovery_unlocked``
        # session, kept only until the new master password is set so the same
        # phrase can be re-wrapped under the rotated data key; lock() zeroes it.
        self._recovery_entropy: bytearray | None = None
        # Key file / YubiKey of a v4 vault this session was opened (or last re-authenticated) with,
        # so password checks for sensitive actions can include them; lock() wipes it.
        self._held_factors: _HeldFactors | None = None
        # Public, non-secret unlock-generation identity for controllers that
        # must reject in-flight work after lock/profile replacement.  It is
        # deliberately independent of catalog contents and survives the
        # locked state long enough for a bound controller to fail closed.
        self._workspace_session_generation = uuid.uuid4().hex
        self._committed_payload = copy.deepcopy(payload)
        # Clock anchor for trash expiry: the newest time the vault itself has
        # seen, plus a monotonic reading, so a forward wall-clock jump cannot
        # make every trash record look expired at once.
        self._clock_anchor = (_newest_payload_time(payload), time.monotonic())
        self._last_catalog_migration_result: dict[str, Any] | None = None
        self._disk_digest = hashlib.sha256(path.read_bytes()).digest() if path.exists() else None
        self._reminder_service = None
        self._reminder_scheduler = None
        self.backup_warning = False
        # True when the encrypted payload says a rollback anchor must exist but
        # none was found at unlock (deleted, or the vault was copied without
        # it).  A new anchor has been written; callers should tell the user.
        self.rollback_anchor_missing = False
        # Where this session's commits raise the rollback marks kept outside the folder: its own path, None for
        # a copy (``_decrypt_vault`` decides).  A restore marks its destination once published (``mark_restored``).
        self._rollback_marks_target: Path | None = Path(path)
        self._rollback_marks_off = False  # a copy opened without its anchor check: never reads or writes a mark
        self._rollback_marks_deferred = False  # while a journaled promotion may still be rolled back
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
        # Live items in this profile's other vaults (free plan counts them together; sub-plan 12).
        self.item_limit_offset: int = 0
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
    def read_only_collection_ids(self) -> frozenset[str]:
        """Collections shared with this vault read-only (sub-plan 07): the item service refuses edits there.

        Also those another of this person's devices holds read-only (a share link received through
        personal collections sync), so a second device never edits a read-only shared item.
        """
        from .sync.share_group import linked_read_only_collection_ids, read_only_collection_ids
        return read_only_collection_ids(self) | linked_read_only_collection_ids(self)

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
        source = self._header if _has_wrapped_key(self._header) else self._pending_v3_header
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
        if _has_wrapped_key(self._header) or self._pending_v3_header is not None:
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
        # The rollback marks are raised once the journal is gone: a recovery from it puts the older vault back.
        deferred, self._rollback_marks_deferred = self._rollback_marks_deferred, True
        try:
            atomic_write_json(journal_path, {**journal, "status": "publishing"})
            if before_save is not None:
                before_save()
            self.save()
            journal_path.unlink(missing_ok=True)
            self._rollback_marks_deferred = deferred
            if not deferred:
                # A format 1/2 vault that just got its id: a copy from before the upgrade is an older copy too.
                self._raise_own_rollback_marks(retired_vault_id=str(old_header.get("vault_id", "")))
        except BaseException:
            self._rollback_marks_deferred = deferred
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
        upgraded_payload = copy.deepcopy(payload)
        upgraded_prefs = upgraded_payload.setdefault("preferences", {})
        for name, binding_key, convert in _unlock_sidecar_kinds():
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

    @property
    def last_kdf_upgrade_result(self) -> dict[str, Any] | None:
        """Result of the Argon2id parameter upgrade attempted by this unlock, if any."""
        return copy.deepcopy(self._last_kdf_upgrade_result)

    def _bound_unlock_sidecars(self) -> list[tuple[str, Any]]:
        """``(name, upgrade_envelope_context)`` for each Hello/camera/security-key grant recorded in the payload."""
        prefs = self._require_payload().get("preferences", {})
        if not isinstance(prefs, dict):
            return []
        return [(name, convert) for name, binding_key, convert in _unlock_sidecar_kinds() if prefs.get(binding_key)]

    def _upgrade_kdf_on_unlock(self, password: SecretText, factor_secrets: list[bytearray] | None = None) -> None:
        """Re-wrap the data key under the current Argon2id default after a master-password unlock.

        Only the password wrapper changes: same data key, fresh salt, stronger
        memory cost (time cost is never lowered).  The recovery wrapper and the
        catalog stay valid because neither authenticates the KDF.  The new
        wrapper is checked with a fresh derivation before anything is written,
        then published through the crash-safe migration journal.  Hello/camera
        sidecars are moved to the new unlock context after the publish; the old
        context is kept in the payload (``KDF_UPGRADE_CONTEXT_PREF``) so a crash
        in between is repaired by the next password unlock.  Any failure leaves
        the vault as it was and the session usable; the next password unlock
        tries again.  Machines with < 4 GiB RAM are skipped.
        """
        self._last_kdf_upgrade_result = None
        header = self._header
        if self._key is None or not _has_wrapped_key(header):
            return
        target: dict[str, Any] = dict(DEFAULT_KDF)
        current = header.get("kdf")
        try:
            current_memory = int(current["memory_cost_kib"])  # type: ignore[index]
            current_time = int(current["time_cost"])  # type: ignore[index]
        except (KeyError, TypeError, ValueError, OverflowError):
            return
        target_memory = int(target["memory_cost_kib"])
        if current_memory >= target_memory:
            return
        result: dict[str, Any] = {"from_memory_cost_kib": current_memory, "to_memory_cost_kib": target_memory}
        if _low_memory_machine():
            self._last_kdf_upgrade_result = {**result, "outcome": "skipped", "reason": "low-memory"}
            return
        new_kdf = {**target, "time_cost": max(current_time, int(target["time_cost"])),
                   "salt": _b64e(os.urandom(16))}
        old_context = unlock_context_for_header(header)
        try:
            upgraded = copy.deepcopy(header)
            specs = _header_factor_specs(header)
            factor_secrets = factor_secrets or []
            upgraded["wrappers"]["password"] = self._password_wrapper(upgraded, password, new_kdf, specs,
                                                                      factor_secrets)
            if not self._password_wrapper_matches(password, upgraded, factor_secrets):
                raise VaultError("The re-wrapped password key did not verify")
            new_context = unlock_context_for_header(upgraded)
            sidecars = self._bound_unlock_sidecars()
            payload = copy.deepcopy(self._require_payload())
            prefs = payload.get("preferences")
            if sidecars and isinstance(prefs, dict):
                # Keep the context this upgrade produced too: the repair below applies only
                # while the header still carries it, never against a later context.
                prefs[KDF_UPGRADE_CONTEXT_PREF] = {"previous": old_context, "target": new_context}
            snapshot = self._journaled_promotion("kdf-upgrade", upgraded, payload, self._catalog_version)
        except Exception as exc:  # noqa: BLE001 - an upgrade failure must never block the unlock
            self._last_kdf_upgrade_result = {**result, "outcome": "failed", "error": str(exc)}
            _LOG.warning("Vault KDF upgrade deferred: %s", exc)
            return
        converted: list[str] = []
        pending: list[str] = []
        for name, convert in sidecars:
            (converted if convert(self.path, old_context, new_context) else pending).append(name)
        # The pre-upgrade snapshot holds the same data key behind the weaker wrapper:
        # drop it once the published file is confirmed (rolling backups age out as usual).
        snapshot_removed = False
        if self._published_header_matches(upgraded):
            try:
                snapshot.unlink()
                snapshot_removed = True
            except OSError:
                _LOG.warning("Could not remove the pre-upgrade vault snapshot %s.", snapshot.name)
        self._last_kdf_upgrade_result = {
            **result, "outcome": "upgraded", "data_key": "inherited", "converted": sorted(converted),
            "sidecars_pending": sorted(pending), "snapshot_removed": snapshot_removed,
        }

    def _published_header_matches(self, header: dict[str, Any]) -> bool:
        """The vault on disk carries ``header``'s password wrapper and decrypts with the data key."""
        try:
            disk_header, _source = _read_vault_header(self.path)
            if (disk_header.get("kdf") != header.get("kdf")
                    or disk_header.get("wrappers", {}).get("password") != header["wrappers"]["password"]):
                return False
            cipher = disk_header["cipher"]
            nonce = _b64d(str(cipher["nonce"]))
            if len(nonce) != 12 or self._key is None:
                return False
            plaintext = _aesgcm_decrypt(self._key, nonce, _b64d(str(cipher["ciphertext"])), _aad(disk_header))
            _zero(plaintext)
            return True
        except (InvalidTag, OSError, ValueError, TypeError, KeyError, VaultError):
            return False

    def _repair_unlock_sidecars_after_kdf_upgrade(self) -> list[str]:
        """Finish moving Hello/camera sidecars when a KDF upgrade was interrupted after its publish."""
        if not _has_wrapped_key(self._header):
            return []
        prefs = self._require_payload().get("preferences", {})
        stored = prefs.get(KDF_UPGRADE_CONTEXT_PREF) if isinstance(prefs, dict) else None
        target = None
        if isinstance(stored, dict):
            previous, target = stored.get("previous"), stored.get("target")
            if not isinstance(target, str) or len(target) != 64:
                return []
        else:
            previous = stored  # the single-string form written by earlier builds
        if not isinstance(previous, str) or len(previous) != 64:
            return []
        current = unlock_context_for_header(self._header)
        if secrets.compare_digest(previous, current):
            return []
        if target is not None and not secrets.compare_digest(target, current):
            return []  # the header moved on since that upgrade: the stored context is stale
        return [name for name, convert in self._bound_unlock_sidecars() if convert(self.path, previous, current)]

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

    def site_pair_id(self, page_origin: str, saved_origin: str) -> str:
        """Opaque id of a (page origin, saved origin) pair for the phishing shield.

        HMAC-SHA256 with a subkey of this vault's data key, so the id the browser
        extension stores for a "same account" answer cannot be matched against a
        list of popular sites by anyone who reads the browser profile.
        """
        key = self._key
        if key is None:
            raise VaultLockedError(t("vault.err.locked"))
        subkey = _hkdf(key, SITE_PAIR_INFO)
        try:
            return hmac.new(bytes(subkey), f"{page_origin}\n{saved_origin}".encode(), hashlib.sha256).hexdigest()[:32]
        finally:
            _zero(subkey)

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

    def set_ai_agent_use(self, entry_id: str, allowed: bool) -> bool:
        """Store "AI agents may use this login" (``scope.ai_agents``, agent_gate) on a website login.

        Off removes the key, so a login that was never opted in and one turned off look the same. The flag
        syncs with the scope; returns False when nothing changed.
        """
        from .agent_gate import AGENT_SCOPE_KEY

        if type(allowed) is not bool:
            raise VaultError("ai_agents is malformed")
        payload = self._require_payload()
        for item in payload["entries"]:
            if item.get("id") != entry_id:
                continue
            if item.get("kind") != "web":
                raise VaultError("Only website logins can be used by AI agents")
            scope = item.get("scope")
            if not isinstance(scope, dict):
                raise VaultError("Website login scope is malformed")
            if (scope.get(AGENT_SCOPE_KEY) is True) == allowed:
                return False
            if allowed:
                scope[AGENT_SCOPE_KEY] = True
            else:
                scope.pop(AGENT_SCOPE_KEY, None)
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
        count = self.live_item_count() + max(0, int(getattr(self, "item_limit_offset", 0) or 0))
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
                if self._batch_depth == 1:
                    self._history_marks = {}  # the labelled changes were rolled back with the block
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

    def _password_wrapper_matches(self, password: SecretText, header: dict[str, Any] | None = None,
                                  factor_secrets: list[bytearray] | None = None) -> bool:
        """Derive the KEK and compare the unwrapped data key; no file is written.

        ``header`` checks a prepared (not yet published) header instead of the current one;
        ``factor_secrets`` are that header's factor secrets in list order (v4).
        """
        if self._key is None:
            raise VaultLockedError(t("vault.err.locked"))
        header = self._header if header is None else header
        specs = _header_factor_specs(header)
        kek = _password_kek(password, header["kdf"], specs, factor_secrets or [])
        try:
            if not _has_wrapped_key(header):
                return self._matches_key(kek)
            wrapper = header["wrappers"]["password"]
            try:
                unwrapped = _unwrap_key(kek, _validated_wrapper_field(wrapper, "nonce", 12),
                                        _validated_wrapper_field(wrapper, "ciphertext", 48),
                                        _wrapper_aad(header, "password", _password_metadata(header, specs)))
            except InvalidTag:
                return False
            try:
                return self._matches_key(unwrapped)
            finally:
                _zero(unwrapped)
        finally:
            _zero(kek)

    def verify_master_password(self, password: str | SecretText, *, factors: FactorSecrets | None = None) -> bool:
        """Throttled, in-memory check of the master password for sensitive actions.

        For a v4 vault the factors are part of the check: ``factors`` if given (they are then held
        for later checks), else the ones this session holds.  A missing or wrong factor raises
        ``FactorRequired`` / ``FactorMismatch`` and is not counted as a failed password.
        """
        _zero_all(self._verify_password(password, factors))
        return True

    def _verify_password(self, password: str | SecretText, factors: FactorSecrets | None) -> list[bytearray]:
        """``verify_master_password`` returning the verified factor secrets (the caller zeroes them)."""
        self._require_payload()
        throttle = UnlockThrottle(self.path)
        throttle.check()
        secret, owned = _master_secret(password, t("vault.err.wrongPassword"))
        try:
            specs = _header_factor_specs(self._header)
            factor_secrets = _resolve_factor_secrets(specs, factors, self._held_factors)
            try:
                if not self._password_wrapper_matches(secret, factor_secrets=factor_secrets):
                    throttle.record_failure()
                    raise InvalidMasterPassword(t("vault.err.wrongPassword"))
            except (InvalidMasterPassword, FactorRequired, FactorMismatch):
                _zero_all(factor_secrets)
                raise
            except VaultError as exc:
                _zero_all(factor_secrets)
                # Malformed wrappers must not count as a password failure nor pass.
                raise VaultError(t("vault.err.passwordNotVerified", detail=exc)) from exc
            except BaseException:
                _zero_all(factor_secrets)
                raise
        finally:
            if owned:
                secret.wipe()
        throttle.reset()
        self._hold_factors(specs, factor_secrets, factors)
        return factor_secrets

    def held_factor_secrets(self) -> FactorSecrets | None:
        """The key file / YubiKey this session holds since its unlock, as ``FactorSecrets`` (``None``: none).

        The key file comes back as its 32-byte KeePass key (a valid raw key file of its own); the
        YubiKey as its responder, asked again on each use.  Sessions opened by Windows Hello, a
        security key or the camera hold none, and ``lock()`` wipes them.
        """
        held = self._held_factors
        if held is None or (held.keyfile_secret is None and held.responder is None):
            return None
        keyfile_secret = None if held.keyfile_secret is None else bytes(held.keyfile_secret)
        return FactorSecrets(keyfile=keyfile_secret, yubikey_response=held.responder)

    def _hold_factors(self, specs: list[FactorSpec], factor_secrets: list[bytearray],
                      factors: FactorSecrets | None) -> None:
        """Keep the verified factors supplied in ``factors`` for later password checks (see ``_HeldFactors``)."""
        if factors is None or not specs:
            return
        held = self._held_factors or _HeldFactors()
        for spec, secret in zip(specs, factor_secrets, strict=True):
            if spec.kind == composite_key.KEYFILE and factors.keyfile is not None:
                _zero(held.keyfile_secret)
                held.keyfile_secret = bytearray(secret)
            elif spec.kind == composite_key.YUBIKEY_HMAC and factors.yubikey_response is not None:
                held.responder = factors.yubikey_response
        self._held_factors = held

    def _password_wrapper(self, header: dict[str, Any], password: SecretText, kdf: dict[str, Any],
                          specs: list[FactorSpec] | None = None,
                          factor_secrets: list[bytearray] | None = None) -> dict[str, Any]:
        """Wrap the data key under ``password`` (+ the factor ``specs`` and their secrets).

        Also sets ``header``'s KDF and its version: v4 with factors, v3 without, so a vault
        without factors is written exactly as before.
        """
        if not isinstance(password, SecretText) or not 12 <= password.char_count <= MAX_MASTER_PASSWORD_LENGTH:
            raise VaultError(t("vault.err.passwordLength"))
        specs = list(specs or [])
        kek = _password_kek(password, kdf, specs, list(factor_secrets or []))
        try:
            header["kdf"] = kdf
            _set_factor_format(header, specs)
            nonce, ciphertext = _wrap_key(kek, self._key or b"",
                                          _wrapper_aad(header, "password", _password_metadata(header, specs)))
        finally:
            _zero(kek)
        # No created_at: it sat outside the wrapper AAD and nothing read it (old vaults may still carry it).
        wrapper: dict[str, Any] = {"nonce": _b64e(nonce), "ciphertext": _b64e(ciphertext)}
        if specs:
            wrapper["factors"] = [spec.to_json() for spec in specs]
        return wrapper

    def _require_new_wrapper_opens(self, password: SecretText, header: dict[str, Any],
                                   factor_secrets: list[bytearray]) -> None:
        """Before a new password wrapper is committed: it must open with what is in memory.

        The wrapping key is derived again (Argon2id + the factor secrets already held, no YubiKey
        touch) and must unwrap the session's data key, as the KDF upgrade checks.
        """
        if not self._password_wrapper_matches(password, header, factor_secrets):
            raise VaultError("The re-wrapped password key did not verify")

    def _renewed_factors(self, factor_secrets: list[bytearray],
                         factors: FactorSecrets | None) -> tuple[list[FactorSpec], list[bytearray]]:
        """The current factors for a rotated data key: same key file, a new YubiKey challenge.

        The YubiKey (``factors`` or the held responder) must answer the new challenge now; the
        caller zeroes the returned secrets.
        """
        specs = _header_factor_specs(self._header)
        renewed: list[FactorSpec] = []
        renewed_secrets: list[bytearray] = []
        try:
            for spec, secret in zip(specs, factor_secrets, strict=True):
                if spec.kind == composite_key.KEYFILE:
                    renewed.append(spec)
                    renewed_secrets.append(bytearray(secret))
                    continue
                responder = factors.yubikey_response if factors is not None and factors.yubikey_response \
                    else (self._held_factors.responder if self._held_factors is not None else None)
                if responder is None:
                    raise FactorRequired([spec.kind])
                # The key answering the new challenge must be the one that matches the current
                # factor: re-ask the old challenge first (FactorMismatch from its check otherwise),
                # so a swapped YubiKey can never become the vault's factor.
                _zero(_factor_secret(spec, FactorSecrets(yubikey_response=responder), None))
                new_spec, new_secret = _enrol_yubikey(responder, spec.slot or 2)
                renewed.append(new_spec)
                renewed_secrets.append(new_secret)
        except BaseException:
            _zero_all(renewed_secrets)
            raise
        return renewed, renewed_secrets

    @_under_session_lock
    def add_factor(self, password: str | SecretText, new: FactorInput, *,
                   factors: FactorSecrets | None = None) -> list[FactorSpec]:
        """Add a key file or YubiKey to the password wrapper (writes format v4); returns the factor list.

        Needs the master password and the factors already set (``factors`` or the held ones).
        Only the password wrapper is rewritten, with the same KDF and salt: the data key, the
        recovery wrapper and the Hello / security-key / camera sidecars stay valid.  The data key
        is not rotated, so copies of the vault made before still open with the password alone
        (COMPOSITE_KEY_V1.md §5); changing the master password rotates it.
        """
        secret, owned = _master_secret(password, t("vault.err.wrongPassword"))
        try:
            current = self._verify_password(secret, factors)
            added: bytearray | None = None
            try:
                if not _has_wrapped_key(self._header):
                    raise VaultError("Save the vault once before adding a key file or YubiKey")
                specs = _header_factor_specs(self._header)
                if any(spec.kind == new.kind for spec in specs):
                    raise VaultError(t("vault.err.factorAlreadySet"))
                new_spec, added = _enrol_factor(new)
                pairs = sorted([*zip(specs, current, strict=True), (new_spec, added)],
                               key=lambda pair: composite_key.KINDS.index(pair[0].kind))
                merged = [spec for spec, _secret in pairs]
                header = copy.deepcopy(self._header)
                merged_secrets = [value for _spec, value in pairs]
                header["wrappers"]["password"] = self._password_wrapper(
                    header, secret, copy.deepcopy(self._header["kdf"]), merged, merged_secrets)
                self._require_new_wrapper_opens(secret, header, merged_secrets)
                self._commit_header_change(header)
                held_input = FactorSecrets(keyfile=new.keyfile_bytes, yubikey_response=new.responder)
                self._hold_factors([new_spec], [added], held_input)
                return merged
            finally:
                _zero_all(current)
                _zero(added)
        finally:
            if owned:
                secret.wipe()

    @_under_session_lock
    def remove_factor(self, password: str | SecretText, kind: str, *,
                      factors: FactorSecrets | None = None) -> list[FactorSpec]:
        """Remove the factor of ``kind``; returns the remaining list (none left: format v3 again)."""
        secret, owned = _master_secret(password, t("vault.err.wrongPassword"))
        try:
            current = self._verify_password(secret, factors)
            try:
                specs = _header_factor_specs(self._header)
                if not any(spec.kind == kind for spec in specs):
                    raise VaultError(t("vault.err.factorNotSet"))
                kept = [(spec, value) for spec, value in zip(specs, current, strict=True) if spec.kind != kind]
                remaining = [spec for spec, _value in kept]
                header = copy.deepcopy(self._header)
                kept_secrets = [value for _spec, value in kept]
                header["wrappers"]["password"] = self._password_wrapper(
                    header, secret, copy.deepcopy(self._header["kdf"]), remaining, kept_secrets)
                self._require_new_wrapper_opens(secret, header, kept_secrets)
                self._commit_header_change(header)
                if self._held_factors is not None:
                    if kind == composite_key.KEYFILE:
                        _zero(self._held_factors.keyfile_secret)
                        self._held_factors.keyfile_secret = None
                    else:
                        self._held_factors.responder = None
                return remaining
            finally:
                _zero_all(current)
        finally:
            if owned:
                secret.wipe()

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
                               recovery_phrase: str | None = None,
                               factors: FactorSecrets | None = None) -> dict[str, Any]:
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

        A v4 vault keeps its factors: ``factors`` (or the held ones) must include the YubiKey,
        which answers a new challenge for the new wrapper.
        """
        new_secret, new_owned = _master_secret(new_password, t("vault.err.passwordLength"))
        current_secret = None
        current_owned = False
        try:
            if not 12 <= new_secret.char_count <= 4096:
                raise VaultError(t("vault.err.passwordLength"))
            current_secret, current_owned = _master_secret(current_password, t("vault.err.wrongPassword"))
            factor_secrets = self._verify_password(current_secret, factors)
            try:
                return self._rotate_data_key(current_secret, new_secret, recovery_phrase=recovery_phrase,
                                             remove_unlock_envelopes=False, factor_secrets=factor_secrets,
                                             factors=factors)
            finally:
                _zero_all(factor_secrets)
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

        A key file / YubiKey set on the vault is dropped, since the phrase is
        what opens a vault whose factor was lost: the new password alone opens
        it (format 3 again) and ``factors_removed`` lists the kinds.
        """
        if not self.recovery_unlocked:
            raise VaultError(t("vault.err.newPasswordNeedsRecovery"))
        new_secret, new_owned = _master_secret(new_password, t("vault.err.passwordLength"))
        try:
            if not 12 <= new_secret.char_count <= 4096:
                raise VaultError(t("vault.err.passwordLength"))
            if not _has_wrapped_key(self._header):
                raise VaultError(t("vault.err.recoveryNeedsFormat3"))
            entropy = self._recovery_entropy
            result = self._rotate_data_key(None, new_secret, recovery_phrase=None, recovery_entropy=entropy,
                                           remove_unlock_envelopes=False, drop_factors=True)
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
        wrappers = self._header.get("wrappers") if _has_wrapped_key(self._header) else None
        return isinstance(wrappers, dict) and isinstance(wrappers.get("recovery"), dict)

    def recovery_entropy(self, phrase: str | None, *, reauthenticate: Callable[[], bool] | None) -> bytes:
        """The 32-byte entropy of this vault's current recovery phrase, for emergency-access shards (sub-plan 08).

        The vault never stores the phrase or its entropy, so the owner types the phrase (a session opened with
        the phrase may pass ``None``).  ``reauthenticate`` is called first and must return exactly ``True``
        (the app asks for the master password or Windows Hello); anything else raises ``PermissionError``
        before the phrase is looked at.  The phrase must open this vault's current recovery wrapper and yield
        this session's data key, else ``RecoveryPhraseError``.  The caller owns the returned bytes.
        """
        self._require_payload()
        if reauthenticate is None or reauthenticate() is not True:
            raise PermissionError(t("error.cancelled"))
        if phrase is None:
            held = self._recovery_entropy if self.recovery_unlocked else None
            if held is None:
                raise RecoveryPhraseError(t("vault.err.recovery24Words"))
            entropy = bytes(held)
        else:
            entropy = entropy_from_phrase(phrase)
        data_key = self._unwrap_recovery(entropy)
        try:
            if not self._matches_key(data_key):
                raise RecoveryPhraseError(t("vault.err.recoveryWrongVault"))
        finally:
            _zero(data_key)
        return entropy

    _HEIR_PLAN = "heir_plan"

    def heir_plan_record(self) -> dict[str, Any] | None:
        """The stored emergency-access plan record (``heir.py`` validates it), or ``None``."""
        value = self._read_prefs().get(self._HEIR_PLAN)
        return copy.deepcopy(value) if value is not None else None

    @_under_session_lock
    def set_heir_plan_record(self, record: dict[str, Any] | None) -> None:
        """Store (or with ``None`` remove) the emergency-access plan record in one save."""
        if record is not None and not isinstance(record, dict):
            raise VaultError("The emergency access plan is malformed")
        self._commit_prefs({self._HEIR_PLAN: record})

    _HEIR_IDENTITY = "heir_identity"

    def heir_identity_record(self) -> dict[str, Any] | None:
        """This vault's emergency-access requester keys (``heir_flow.RequesterIdentity``), or ``None``."""
        value = self._read_prefs().get(self._HEIR_IDENTITY)
        return copy.deepcopy(value) if value is not None else None

    @_under_session_lock
    def set_heir_identity_record(self, record: dict[str, Any] | None) -> None:
        """Store (or with ``None`` remove) the requester keys in one save."""
        if record is not None and not isinstance(record, dict):
            raise VaultError("The emergency access keys are malformed")
        self._commit_prefs({self._HEIR_IDENTITY: record})

    _HEIR_RECEIVED = "heir_received"

    def heir_received_record(self) -> dict[str, Any] | None:
        """The emergency-access shards and shared folder this vault holds as a holder, or ``None``."""
        value = self._read_prefs().get(self._HEIR_RECEIVED)
        return copy.deepcopy(value) if isinstance(value, dict) else None

    @_under_session_lock
    def set_heir_received_record(self, record: dict[str, Any] | None) -> None:
        """Store (or with ``None`` remove) the holder's shards and folder in one save."""
        if record is not None and not isinstance(record, dict):
            raise VaultError("The emergency access shards are malformed")
        self._commit_prefs({self._HEIR_RECEIVED: record})

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
        factor_secrets: list[bytearray] = []
        try:
            factor_secrets = self._verify_password(secret, None)
            words = bip39_words()  # fail early if the word list is damaged
            assert len(words) == 2048
            entropy = os.urandom(32)
            salt = os.urandom(16)
            # Owner decision Q2 (backup-public-key design): a new phrase cannot reset the scheduled-backup
            # password until the record's reset authority is re-bound with the backup password.
            flagged = self._flag_backup_key_rebind()
            try:
                if self.has_recovery_phrase() or self._recovery_wrapper_outlives_removal():
                    result = self._rotate_data_key(secret, secret, recovery_phrase=None,
                                                   new_recovery_entropy=entropy, factor_secrets=factor_secrets)
                    self.last_recovery_phrase_change = {"operation": "replace", **result}
                    return phrase_from_entropy(entropy)
                header = self._promoted_header(catalog_version=self._catalog_version, password=secret)
            except BaseException:
                if flagged:
                    self._prefs().pop(self._BACKUP_KEY_REBIND, None)
                raise
        finally:
            _zero_all(factor_secrets)
            if owned:
                secret.wipe()
        metadata = {"kind": RECOVERY_WRAPPER_KIND, "salt": _b64e(salt)}
        recovery_key = _recovery_key(entropy, salt)
        try:
            nonce, ciphertext = _wrap_key(recovery_key, self._key or b"", _wrapper_aad(header, "recovery", metadata))
        finally:
            _zero(recovery_key)
        header["wrappers"]["recovery"] = {**metadata, "nonce": _b64e(nonce), "ciphertext": _b64e(ciphertext)}
        try:
            self._commit_header_change(header)
        except BaseException:
            if flagged:
                self._prefs().pop(self._BACKUP_KEY_REBIND, None)
            raise
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
        factor_secrets: list[bytearray] = []
        try:
            factor_secrets = self._verify_password(secret, None)
            if not self.has_recovery_phrase():
                return None
            result = self._rotate_data_key(secret, secret, recovery_phrase=None, factor_secrets=factor_secrets)
        finally:
            _zero_all(factor_secrets)
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
        factor_secrets: list[bytearray] = []
        try:
            factor_secrets = self._verify_password(secret, None)
            return self._rotate_data_key(secret, secret, recovery_phrase=recovery_phrase,
                                         factor_secrets=factor_secrets)
        finally:
            _zero_all(factor_secrets)
            if owned:
                secret.wipe()

    @_under_session_lock
    def _rotate_data_key(self, current_password: SecretText | None, new_password: SecretText, *, recovery_phrase: str | None,
                         remove_unlock_envelopes: bool = True,
                         recovery_entropy: bytes | bytearray | None = None,
                         new_recovery_entropy: bytes | bytearray | None = None,
                         factor_secrets: list[bytearray] | None = None, factors: FactorSecrets | None = None,
                         drop_factors: bool = False) -> dict[str, Any]:
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

        A v4 vault's factors are kept (``factor_secrets``: the verified secrets of the current
        list) with a new YubiKey challenge, which ``factors`` or the held responder answers before
        anything changes; ``drop_factors`` writes the new wrapper without them (``factors_removed``).
        """
        payload = self._require_payload()
        old_key = self._key
        if old_key is None:
            raise VaultLockedError(t("vault.err.keyUnavailable"))
        current_specs = _header_factor_specs(self._header)
        new_specs: list[FactorSpec] = []
        new_factor_secrets: list[bytearray] = []
        if current_specs and not drop_factors:
            if factor_secrets is None:
                raise FactorRequired([spec.kind for spec in current_specs])
            new_specs, new_factor_secrets = self._renewed_factors(factor_secrets, factors)
        try:
            return self._rotate_data_key_with(
                payload, old_key, current_password, new_password, recovery_phrase=recovery_phrase,
                remove_unlock_envelopes=remove_unlock_envelopes, recovery_entropy=recovery_entropy,
                new_recovery_entropy=new_recovery_entropy, new_specs=new_specs,
                new_factor_secrets=new_factor_secrets,
                factors_removed=[spec.kind for spec in current_specs] if drop_factors else [])
        finally:
            _zero_all(new_factor_secrets)

    def _rotate_data_key_with(self, payload: dict[str, Any], old_key: bytearray, current_password: SecretText | None,
                              new_password: SecretText, *, recovery_phrase: str | None, remove_unlock_envelopes: bool,
                              recovery_entropy: bytes | bytearray | None,
                              new_recovery_entropy: bytes | bytearray | None, new_specs: list[FactorSpec],
                              new_factor_secrets: list[bytearray], factors_removed: list[str]) -> dict[str, Any]:
        """``_rotate_data_key`` once the new factor list and its secrets are known."""
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
        if factors_removed:
            result["factors_removed"] = factors_removed
        try:
            header["wrappers"]["password"] = self._password_wrapper(
                header, new_password, {**_default_kdf(), "salt": _b64e(os.urandom(16))}, new_specs,
                new_factor_secrets)
            if new_specs:  # self._key is already the new data key here
                self._require_new_wrapper_opens(new_password, header, new_factor_secrets)
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
                    for name, binding in (("hello", "hello_binding"), ("face", "face_binding"),
                                          ("fido", "fido_binding")):
                        if prefs.pop(binding, None):
                            result["reenroll_required"].append(name)
                    # Emergency access (sub-plan 08): shards split the old phrase, which no longer opens the vault.
                    # Only the device that made the plan (home) holds its phrase; a plan received by sync from
                    # another of the owner's devices (home False) is not about this vault's phrase.
                    plan = prefs.get(self._HEIR_PLAN)
                    if result["recovery_phrase_invalidated"] and isinstance(plan, dict) \
                            and plan.get("home", True) is not False:
                        plan["stale"] = True
                        result["heir_plan_stale"] = True

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
                # The marks outside the folder follow the anchor: both keys until the commit (which raises them
                # under the new key alone), the old key again if it fails.  A mark that ends up under the other
                # key never refuses an unlock; it is replaced.
                marks_target = self._rollback_marks_target
                if marks_target is not None and vault_id == old_vault_id:
                    _raise_rollback_marks(marks_target, generation, new_anchor_key, vault_id,
                                          exact=True, previous_key=old_anchor_key)
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
                    if marks_target is not None and vault_id == old_vault_id:
                        _raise_rollback_marks(marks_target, generation, old_anchor_key, old_vault_id, exact=True)
                    raise
                if marks_target is not None:
                    # Committed: the old key is retired, so a copy still under it (taken before this change, or
                    # before up to ``_ROLLBACK_MARK_RETIRED_MAX`` changes) is refused like any older copy.  A
                    # restore's staged copy has no marks target: its destination is marked once published.  A
                    # format 1/2 vault whose upgrade did not run gets its id here: the retired record carries the
                    # old id ("" ), as the v3 upgrade's does, so its copy from before (no id) is refused too.
                    committed = int((self._committed_payload or {}).get("generation", 0))
                    _raise_rollback_marks(marks_target, committed, new_anchor_key, vault_id, exact=True,
                                          retired_key=old_anchor_key,
                                          retired_vault_id=None if vault_id == old_vault_id else old_vault_id)
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
                elif name == "fido":
                    from .fido_unlock import envelope_path as fido_envelope
                    fido_envelope(self.path).unlink(missing_ok=True)
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
                        if (isinstance(header, dict) and _has_wrapped_key(header)
                                and header.get("vault_id") == self._header.get("vault_id")
                                and header.get("key_generation") == generation):
                            continue
                except (OSError, ValueError, RecursionError, VaultError):
                    pass
                found.append(candidate)
        return sorted(found)

    def _unwrap_recovery(self, entropy: bytes) -> bytearray:
        header = self._header
        wrapper = header.get("wrappers", {}).get("recovery") if _has_wrapped_key(header) else None
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
                    if isinstance(header, dict) and _has_wrapped_key(header) \
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

    def fido_binding(self) -> str:
        """Security-key unlock authorization, stored inside the authenticated, encrypted payload."""
        prefs = self._require_payload().get("preferences", {})
        value = prefs.get("fido_binding", "") if isinstance(prefs, dict) else ""
        if (isinstance(value, str) and len(value) == 32
                and all(c in "0123456789abcdef" for c in value)):
            return value
        return ""

    def set_fido_binding(self, record_id: str | None) -> None:
        if record_id is not None and (not isinstance(record_id, str) or len(record_id) != 32
                                     or any(c not in "0123456789abcdef" for c in record_id)):
            raise VaultError("Invalid security key binding")
        payload = self._require_payload()
        prefs = payload.setdefault("preferences", {})
        if not isinstance(prefs, dict):
            raise VaultError("Vault preferences are malformed")
        if record_id is None:
            prefs.pop("fido_binding", None)
        else:
            prefs["fido_binding"] = record_id
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

    # -- scheduled-backup public key (docs/design/backup-public-key-2026-10-31.md) -------------
    # The vault keeps only the public backup key *record* (section 3.3).  Releases before it stored
    # the backup password itself; ``migrate_scheduled_backup_password`` is the only reader of that
    # old field and removes it in the same save that adds the record (section 5).
    _LEGACY_BACKUP_PASSWORD = "scheduled_backup_password"  # noqa: S105 - a preference name
    _BACKUP_KEY = "scheduled_backup_key"
    _BACKUP_KEY_REBIND = "scheduled_backup_key_rebind"

    def _prefs(self) -> dict[str, Any]:
        payload = self._require_payload()
        prefs = payload.setdefault("preferences", {})
        if not isinstance(prefs, dict):
            raise VaultError("Vault preferences are malformed")
        return prefs

    def _read_prefs(self) -> dict[str, Any]:
        """The preferences for reading: never adds an empty object to the payload."""
        prefs = self._require_payload().get("preferences", {})
        return prefs if isinstance(prefs, dict) else {}

    def scheduled_backup_key(self) -> dict[str, Any] | None:
        """The validated public backup key record, or ``None`` when none is set.

        A stored value that does not validate raises ``backup_key.DamagedRecordError``:
        scheduled backups then skip with a warning (design section 3.3).
        """
        from .backup_key import validate_record

        value = self._read_prefs().get(self._BACKUP_KEY)
        return None if value is None else validate_record(value)

    def has_scheduled_backup_key(self) -> bool:
        return self._read_prefs().get(self._BACKUP_KEY) is not None

    def scheduled_backup_key_rebind_needed(self) -> bool:
        """Set when a recovery phrase was created or replaced while a backup key record existed (owner Q2)."""
        return self._read_prefs().get(self._BACKUP_KEY_REBIND) is True

    def recovery_wrapper_snapshot(self) -> dict[str, str] | None:
        """The reset authority of the current recovery phrase (``recovery-wrapper-v1``); ``None`` without one."""
        from .backup_key import capture_wrapper_authority

        self._require_payload()
        return capture_wrapper_authority(self._header)

    def _commit_prefs(self, changes: dict[str, Any]) -> None:
        """Apply ``{name: value | None}`` (``None`` removes) in one save; put every value back if it fails."""
        prefs = self._prefs()
        missing = object()
        previous = {name: copy.deepcopy(prefs[name]) if name in prefs else missing for name in changes}
        for name, value in changes.items():
            if value is None:
                prefs.pop(name, None)
            else:
                prefs[name] = copy.deepcopy(value)
        try:
            self.save()
        except BaseException:
            prefs = self._prefs()
            for name, value in previous.items():
                if value is missing:
                    prefs.pop(name, None)
                else:
                    prefs[name] = value
            raise

    @_under_session_lock
    def set_scheduled_backup_key(self, record: dict[str, Any] | None | Callable[[dict[str, str] | None], Any], *,
                                 predecessor: dict[str, Any] | None = None) -> dict[str, Any] | None:
        """Store (or with ``None`` remove) the record and return it.  The caller has checked the proof (section 4).

        ``record`` may be a callable that gets the current recovery-phrase snapshot
        (``recovery_wrapper_snapshot``), taken under the session lock, and returns the record to store, so the
        authority it binds is the phrase that is current when it is saved (review L8).

        A record replaces an existing valid one only as its successor: the same key (a re-bind) or one
        whose newest history entry is the existing key (a change or reset).  ``predecessor`` names the record
        the caller proved instead (design 16c: the record last seen on this device, after a rollback); the
        successor rule is then checked against it.  A damaged record may be replaced by any valid one.  An old
        stored backup password is removed in the same save.  The re-bind flag is cleared only when the
        stored record's authority is the current phrase's; otherwise it is set.
        """
        from .backup_key import DamagedRecordError, validate_record

        rebind: bool | None = None
        if record is not None:
            snapshot = self.recovery_wrapper_snapshot()
            if callable(record):
                record = record(snapshot)
            record = validate_record(record)
            if predecessor is not None:
                base = validate_record(predecessor)
            else:
                try:
                    base = self.scheduled_backup_key()
                except DamagedRecordError:
                    base = None
            if base is not None and record["key_id"] != base["key_id"] and (
                    not record["history"] or record["history"][0]["key_id"] != base["key_id"]):
                raise VaultError("A backup key can only be replaced by its change, reset or re-bind")
            if snapshot is not None and record["reset_authority"] != snapshot:
                rebind = True
        self._commit_prefs({self._BACKUP_KEY: record, self._LEGACY_BACKUP_PASSWORD: None,
                            self._BACKUP_KEY_REBIND: rebind})
        return record

    def _flag_backup_key_rebind(self) -> bool:
        """Before a phrase is created or replaced: mark that the record's reset authority must be re-bound."""
        prefs = self._require_payload().get("preferences")  # never adds an empty preferences object
        if not isinstance(prefs, dict) or prefs.get(self._BACKUP_KEY) is None or prefs.get(self._BACKUP_KEY_REBIND) is True:
            return False
        prefs[self._BACKUP_KEY_REBIND] = True
        return True

    def _legacy_scheduled_backup_password(self) -> str:
        """Migration only (design section 5): where releases before the public key kept the backup password."""
        value = self._read_prefs().get(self._LEGACY_BACKUP_PASSWORD, "")
        return value if isinstance(value, str) and 12 <= len(value) <= 4096 and "\x00" not in value else ""

    def scheduled_backup_migration_pending(self) -> bool:
        """An old stored backup password is still in the vault and ``migrate_scheduled_backup_password`` would act."""
        prefs = self._read_prefs()
        return self._LEGACY_BACKUP_PASSWORD in prefs and (
            prefs.get(self._BACKUP_KEY) is not None or bool(self._legacy_scheduled_backup_password()))

    def migrate_scheduled_backup_password(self, now: int) -> dict[str, Any] | None:
        """Section 5: turn a stored backup password into the public key record and return it (``None``: nothing done).

        Argon2 runs before the session lock is taken (call this on a worker thread).  The record is added
        and the password removed in one save; if that save fails both are put back and the error is raised,
        so the caller retries on the next unlock.  No backup file is read or touched.
        """
        from . import backup
        from .backup_key import build_record, derive_backup_key, new_kdf

        prefs = self._read_prefs()
        if prefs.get(self._BACKUP_KEY) is not None:
            if self._LEGACY_BACKUP_PASSWORD in prefs:
                # Both exist (one save makes this impossible; checked anyway): keep the record.
                with self._state_lock:
                    self._commit_prefs({self._LEGACY_BACKUP_PASSWORD: None})
            return None
        password = self._legacy_scheduled_backup_password()
        if not password:
            return None
        key = derive_backup_key(password, new_kdf(parameters=backup.BACKUP_KDF))
        try:
            with self._state_lock:
                prefs = self._prefs()
                if prefs.get(self._BACKUP_KEY) is not None or self._legacy_scheduled_backup_password() != password:
                    return None  # changed while Argon2 ran
                record = build_record(key, now=int(now), set_by="migrated",
                                      reset_authority=self.recovery_wrapper_snapshot())
                self._commit_prefs({self._BACKUP_KEY: record, self._LEGACY_BACKUP_PASSWORD: None})
                return record
        finally:
            key.wipe()
            password = ""

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
        """Write an authenticated rollback anchor for this session's committed generation.

        A restore (``backup._restore_verified``) calls this for the file it just published: the rollback marks
        outside the folder are set to exactly this generation first (a confirmed restore lowers them), so a crash
        between the two leaves marks that are not above the anchor.
        """
        payload = self._require_payload()
        target = Path(path or self.path)
        generation = int(payload.get("generation", 0))
        vault_id = str(self._header.get("vault_id", ""))
        anchor_key = _rollback_anchor_key(self._key or b"")
        try:
            if not self._rollback_marks_off:
                _raise_rollback_marks(target, generation, anchor_key, vault_id, exact=True)
            _write_generation_anchor(target, generation, anchor_key, vault_id)
        finally:
            _zero(anchor_key)

    @_under_session_lock
    def mark_restored(self, path: Path) -> None:
        """A restore just put this session's committed vault (and its anchor) in place at ``path``: set both
        rollback marks there to exactly its generation (a confirmed restore may lower them).  Only once the
        restored file is there, never for a staged copy that may still be dropped.  Best effort."""
        payload = self._committed_payload if isinstance(self._committed_payload, dict) else self._require_payload()
        if self._rollback_marks_off or self._key is None or len(self._key) != 32:
            return
        anchor_key = _rollback_anchor_key(self._key)
        try:
            _raise_rollback_marks(Path(path), int(payload.get("generation", 0)), anchor_key,
                                  str(self._header.get("vault_id", "")), exact=True)
        finally:
            _zero(anchor_key)

    def _raise_own_rollback_marks(self, *, retired_vault_id: str | None = None) -> None:
        """Best effort: this session's committed generation to its marks (``_rollback_marks_target``).

        ``retired_vault_id``: the vault just got its id (the v3 upgrade, which keeps the data key), so a copy
        from before, which has no id, is recorded as retired (``_retired_mark``) and refused like an older one.
        """
        target = self._rollback_marks_target
        if target is None or self._rollback_marks_deferred or self._key is None or len(self._key) != 32:
            return
        committed = self._committed_payload if isinstance(self._committed_payload, dict) else {}
        anchor_key = _rollback_anchor_key(self._key)
        try:
            vault_id = str(self._header.get("vault_id", ""))
            _raise_rollback_marks(target, int(committed.get("generation", 0)), anchor_key, vault_id)
            if retired_vault_id is not None and retired_vault_id != vault_id:
                _raise_rollback_marks(target, int(committed.get("generation", 0)), anchor_key, vault_id,
                                      exact=True, retired_key=anchor_key, retired_vault_id=retired_vault_id)
        finally:
            _zero(anchor_key)

    @_under_session_lock
    def rollback_anchor_generation(self, path: Path | None = None) -> int | None:
        """Return the anchor generation stored next to ``path`` if it authenticates under this data key.

        ``None`` means there is no anchor; a VaultError means the anchor exists
        but was minted for a different data key or has been tampered with.

        Asked about another path (``backup._check_restore_rollback``), this session is a restore copy headed
        there.  Nothing is marked for that path until the copy is in place (``mark_restored``): a restore that
        stops before (cancelled, failed) leaves the vault there and its marks as they were.
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

    @_under_session_lock
    def resealed(self, vault_json: dict[str, Any], change: Callable[[dict[str, Any]], None]) -> dict[str, Any]:
        """``vault_json`` (this vault's encrypted file, e.g. as read from disk for a backup) with ``change``
        applied to its catalog, encrypted again under this session's data key with a fresh nonce.

        The header is otherwise unchanged (the same generation, so the rollback anchor beside the file still
        matches it) and the live vault is not touched.  A file that does not open with this key raises
        ``VaultError``; the plaintext lives only in buffers that are zeroed.
        """
        self._require_payload()
        if self._key is None or len(self._key) != 32:
            raise VaultLockedError(t("vault.err.keyUnavailable"))
        header = copy.deepcopy(vault_json)
        try:
            cipher = header["cipher"]
            nonce = _b64d(str(cipher["nonce"]))
            ciphertext = _b64d(str(cipher["ciphertext"]))
            if len(nonce) != 12:
                raise VaultError("Vault nonce has an invalid length")
            version = _catalog_version_of(header)
            plaintext = _aesgcm_decrypt(self._key, nonce, ciphertext, _aad(header))
            try:
                parsed = _json_from_buffer(plaintext)
            finally:
                _zero(plaintext)
                del plaintext
        except VaultError:
            raise
        except (InvalidTag, UnicodeDecodeError, ValueError, KeyError, TypeError) as exc:
            raise VaultError("This vault file does not open with the unlocked vault's key") from exc
        change(parsed)
        try:
            payload = _validate_payload(parsed, version)
        except ItemSchemaError as exc:
            raise VaultError(str(exc)) from exc
        if _has_wrapped_key(header) and int(payload.get("generation", 0)) != int(header["generation"]):
            raise VaultError("Vault header generation does not match its encrypted catalog")
        new_nonce = os.urandom(12)
        header["cipher"]["nonce"] = _b64e(new_nonce)
        buffer = _canonical_json_buffer(payload)
        try:
            sealed = AESGCM(self._key).encrypt(new_nonce, buffer, _aad(header))
        finally:
            _zero(buffer)
            del buffer
        header["cipher"]["ciphertext"] = _b64e(sealed)
        return header

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

    def check_rolling_backup(self) -> tuple[Path, int] | None:
        """Sub-plan 12 restore test at unlock: decrypt the newest rolling backup with a copy of this session's
        data key (nothing is written; no password is used or kept) and count its entries.

        ``None`` when there is no rolling backup under the current key generation; ``VaultError`` when the
        newest one does not open.
        """
        if self.backup_dir is None or not self.backup_dir.exists():
            return None
        rows = [p for p in self.backup_dir.glob("vault-*.json") if p.is_file() and not p.is_symlink()]
        if not rows:
            return None
        newest = max(rows, key=lambda p: p.stat().st_mtime_ns)
        try:
            source = newest.read_bytes()
            if len(source) > MAX_VAULT_BYTES:
                raise VaultError("Rolling backup is too large")
            header = json.loads(source)
            if not isinstance(header, dict):
                raise VaultError("Rolling backup is malformed")
        except (OSError, ValueError, RecursionError) as exc:
            raise VaultError("Rolling backup could not be read") from exc
        if _has_wrapped_key(header) and header.get("key_generation") != self._header.get("key_generation"):
            return None  # written under an older key: not this session's to test
        with self._state_lock:
            if self._key is None:
                raise VaultError("Vault is locked")
            key = bytearray(self._key)
        copy = _decrypt_vault(newest, header, source, key, check_anchor=False)
        try:
            return newest, len(copy.summaries())
        finally:
            copy.lock()

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

    # --- Login history (feature pack 2026-11-15, section 1): device-local, never synced -------------
    def mark_history_change(self, entry_ids: Iterable[str], change_type: str) -> None:
        """Label the next captured snapshot of these logins (``sync``, ``restore``, ``import``, ``merge``)."""
        marks = getattr(self, "_history_marks", None)
        if not isinstance(marks, dict):
            marks = self._history_marks = {}
        for entry_id in entry_ids:
            marks[str(entry_id)] = str(change_type)

    def entry_history_rows(self, entry_id: str) -> list[dict[str, Any]]:
        """This login's stored snapshots, newest first (copies)."""
        from . import item_history

        rows = self._require_payload().get(item_history.ENTRY_HISTORY_KEY)
        if not isinstance(rows, list):
            return []
        mine = [copy.deepcopy(r) for r in rows if item_history.valid_row(r) and r["item_id"] == str(entry_id)]
        mine.sort(key=lambda r: (-int(r["created_at"]), str(r["snapshot_id"])))
        return mine

    def _capture_entry_history(self, payload: dict[str, Any]) -> None:
        """Snapshot every login whose synced content differs from the last committed version.

        Runs on every save, after the trash auto-purge: rows of logins that are neither live nor in the
        trash (deleted forever by any path) are dropped, and the age limit is applied (W-M5), so a purged
        password does not live on in history and old rows go even when no login is edited.
        """
        from . import item_history

        committed = getattr(self, "_committed_payload", None)
        now = int(time.time())
        self._drop_stale_entry_history(payload, now)
        if not isinstance(committed, dict):
            return
        before = {str(e.get("id")): e for e in committed.get("entries", []) if isinstance(e, dict)}
        marks = getattr(self, "_history_marks", None) or {}
        added: list[dict[str, Any]] = []
        for entry in payload.get("entries", []):
            if not isinstance(entry, dict):
                continue
            old = before.get(str(entry.get("id")))
            if old is None or old == entry or old.get("kind") != entry.get("kind"):
                continue
            if item_history.comparable(old) == item_history.comparable(entry):
                continue
            added.append(item_history.make_row(old, ns="entry", now=now,
                                               change_type=marks.get(str(entry.get("id")), "update")))
        if not added:
            return
        existing = payload.get(item_history.ENTRY_HISTORY_KEY)
        rows = [r for r in existing if item_history.valid_row(r)] if isinstance(existing, list) else []
        payload[item_history.ENTRY_HISTORY_KEY] = item_history.prune(rows + added, now,
                                                                     self._entry_history_limits())

    def _entry_history_limits(self) -> dict[str, int]:
        from . import item_history

        allowed = getattr(self, "pro_features", None)
        pro = allowed is None or "item_history_long" in allowed
        return item_history.limits_for(pro, max_bytes=item_history.WINDOWS_ENTRY_HISTORY_BYTES)

    def _drop_stale_entry_history(self, payload: dict[str, Any], now: int) -> None:
        """Cheap per-save clean-up of ``entry_history``: no row of a login that is neither live nor in the
        trash, and none older than the age limit.  Leaves the key untouched when nothing goes."""
        from . import item_history

        rows = payload.get(item_history.ENTRY_HISTORY_KEY)
        if not isinstance(rows, list) or not rows:
            return
        known = {str(e.get("id")) for e in payload.get("entries", []) if isinstance(e, dict)}
        known.update(str(r["entry"].get("id")) for r in payload.get("trash", [])
                     if isinstance(r, dict) and isinstance(r.get("entry"), dict))
        cutoff = now - int(self._entry_history_limits()["max_age_days"]) * 86400
        kept = [r for r in rows if item_history.valid_row(r) and r["item_id"] in known
                and int(r["created_at"]) >= cutoff]
        if len(kept) != len(rows):
            payload[item_history.ENTRY_HISTORY_KEY] = kept

    def set_entry_access(self, entry_id: str, access: dict[str, Any] | None) -> bool:
        """Write a login's ``scope.access`` (contract 4.1 write form; ``None`` removes it). False when unchanged."""
        from .access_policy import ACCESS_SCOPE_KEY

        payload = self._require_payload()
        for item in payload["entries"]:
            if item.get("id") != entry_id:
                continue
            scope = item.get("scope")
            if not isinstance(scope, dict):
                raise VaultError("Login scope is malformed")
            if scope.get(ACCESS_SCOPE_KEY) == access or (access is None and ACCESS_SCOPE_KEY not in scope):
                return False
            original = copy.deepcopy(item)
            if access is None:
                scope.pop(ACCESS_SCOPE_KEY, None)
            else:
                scope[ACCESS_SCOPE_KEY] = copy.deepcopy(access)
            now = int(time.time())
            item["updated_at"] = now
            payload["updated_at"] = now
            try:
                self.save()
            except BaseException:
                item.clear()
                item.update(original)
                raise
            return True
        raise VaultError(t("vault.err.deletedNotFound"))

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
            self._history_marks = {}
            raise VaultError(t("vault.err.writeFailed")) from None

    def _trusted_now(self) -> float:
        """Wall-clock time, capped at the vault's newest stored time plus 2 days plus the
        monotonic time since unlock: a clock that jumped forward cannot expire the trash."""
        newest, mono = getattr(self, "_clock_anchor", (0, time.monotonic()))
        now = time.time()
        if newest <= 0:
            return now
        return min(now, newest + _CLOCK_SLACK_SECONDS + max(0.0, time.monotonic() - mono))

    def _save_locked(self) -> None:
        payload = self._require_payload()
        if self._key is None or len(self._key) != 32:
            raise VaultLockedError(t("vault.err.keyUnavailable"))
        old_header = copy.deepcopy(self._header)
        if not _has_wrapped_key(self._header) and self._pending_v3_header is not None:
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
                cutoff = int(self._trusted_now()) - self.trash_retention_days * 86400
                payload["trash"] = [r for r in payload.get("trash", []) if r["deleted_at"] >= cutoff]
            self._capture_entry_history(payload)
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
                    self.path, anchor_key, vault_id, require_mac=_has_wrapped_key(old_header))
            finally:
                _zero(anchor_key)
            current_generation = int(payload.get("generation", 0))
            if current_generation < anchor_generation:
                raise VaultError(t("vault.err.rollbackNewest"))
            payload["generation"] = max(1, current_generation, self._generation_floor,
                                        anchor_generation + (1 if self._disk_digest is not None else 0))
            if _has_wrapped_key(self._header):
                # Authenticated record that this vault always has a MAC anchor,
                # so a deleted anchor is detected at the next unlock.
                payload[ANCHOR_REQUIRED_KEY] = True
            nonce = os.urandom(12)
            header = copy.deepcopy(self._header)
            header["cipher"]["nonce"] = _b64e(nonce)
            if _has_wrapped_key(header):
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
            self._history_marks = {}
            # After the vault and its anchor: a mark is never above the vault on disk.  A format 1/2 vault that
            # got its id in this save (its upgrade at unlock failed): its copy from before, with no id, is
            # recorded as retired like after the upgrade (``_raise_own_rollback_marks``).
            self._raise_own_rollback_marks(retired_vault_id=str(old_header.get("vault_id") or ""))
        except BaseException:
            self._payload = copy.deepcopy(self._committed_payload)
            self._header = old_header
            # The failed write's change is rolled back, so are its history labels: a later save must not reuse
            # them for another change ("Arrived by sync" on a local edit, or the reverse).
            self._history_marks = {}
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
            self._last_kdf_upgrade_result = None
            self.recovery_unlocked = False
            _zero(self._recovery_entropy)
            self._recovery_entropy = None
            if self._held_factors is not None:
                self._held_factors.wipe()
                self._held_factors = None
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
    if version in WRAPPED_KEY_VERSIONS:
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

    kdf = _default_kdf()
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


def _validate_v4_header(header: dict[str, Any]) -> None:
    """``_validate_v3_header`` for a v4 header: its own format identifier and a factor list.

    ``wrappers.password`` must hold ``factors`` (1-2 objects valid under COMPOSITE_KEY_V1.md §2, in
    §2 order) and at most three fields; the rest is checked by the v3 rules on a copy without it.
    """
    if header.get("format") != FORMAT_V4:
        raise VaultError("Unsupported vault format identifier")
    wrappers = header.get("wrappers")
    if not isinstance(wrappers, dict):
        raise VaultError("Vault key wrappers are malformed")
    password = wrappers.get("password")
    if not isinstance(password, dict) or "factors" not in password \
            or len(password) > MAX_PASSWORD_WRAPPER_FIELDS_V4:
        raise VaultError("Vault key wrapper is malformed")
    _header_factor_specs(header)
    without_factors = {name: value for name, value in password.items() if name != "factors"}
    _validate_v3_header({**header, "format": FORMAT_V3_IDENTIFIER,
                         "wrappers": {**wrappers, "password": without_factors}})


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
    version = header.get("version")
    if version not in SUPPORTED_FORMAT_VERSIONS:
        if type(version) is int and version > max(WRAPPED_KEY_VERSIONS):
            raise VaultTooNew(version)
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
    elif header.get("version") == VERSION_V4:
        _validate_v4_header(header)
    return header, source_bytes


def _decrypt_vault(path: Path, header: dict[str, Any], source_bytes: bytes,
                   key: bytearray, *, backup_dir: Path | None = None,
                   backup_count: int = 0, check_anchor: bool = True,
                   rollback_marks: str = MARKS_LIVE) -> VaultSession:
    """Consume ownership of the catalog key on success, zero it on every failure.

    ``rollback_marks`` (with ``check_anchor``): ``MARKS_LIVE`` for the app's own unlock of the vault at ``path``
    (password through ``unlock_vault(upgrade_kdf=True)``, Hello, camera, security key, the duress vault),
    ``MARKS_COPY`` for other unlocks (the path mark only; a copy without its anchor or path mark is not
    marked), ``MARKS_OFF`` for read-only probes.  ``check_anchor=False`` is ``MARKS_OFF``.
    """
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
        if _has_wrapped_key(header) and int(payload.get("generation", 0)) != int(header["generation"]):
            raise VaultError("Vault header generation does not match its encrypted catalog")
        anchor_missing = False
        marks_mode = rollback_marks if check_anchor else MARKS_OFF
        marked = False
        if check_anchor:
            anchor_key = _rollback_anchor_key(key)
            vault_id = str(header.get("vault_id", ""))
            generation = int(payload.get("generation", 0))
            try:
                if marks_mode != MARKS_OFF:
                    # Before the anchor is touched: a refusal writes nothing.
                    marked, second_copy = _check_rollback_marks(path, generation, anchor_key, vault_id,
                                                                 live=marks_mode == MARKS_LIVE)
                    anchor_missing = second_copy
                anchor_missing = _check_generation_anchor(
                    path, payload, anchor_key, vault_id,
                    require_mac=_has_wrapped_key(header)) or anchor_missing
                # Only the live vault, or a path already marked, is marked: a restore's or a check's
                # private copy leaves nothing in the store.
                marked = marked or marks_mode == MARKS_LIVE
                if marked:
                    _raise_rollback_marks(path, generation, anchor_key, vault_id)
            finally:
                _zero(anchor_key)
        session = VaultSession(path, header, key, payload, backup_dir=backup_dir,
                               backup_count=backup_count)
        session._disk_digest = hashlib.sha256(source_bytes).digest()
        session.rollback_anchor_missing = anchor_missing
        session._rollback_marks_off = marks_mode == MARKS_OFF
        session._rollback_marks_target = Path(path) if marked else None
        return session
    except BaseException as exc:
        key[:] = b"\0" * len(key)
        if isinstance(exc, (InvalidTag, UnicodeDecodeError, json.JSONDecodeError, KeyError)):
            raise InvalidMasterPassword(t("vault.err.wrongPasswordOrModified")) from exc
        raise


def _unwrap_password_wrapper(header: dict[str, Any], master_password: SecretText,
                             factor_secrets: list[bytearray] | None = None) -> bytearray:
    """Argon2id(master password) [+ factor secrets] -> KEK -> data key.  The KEK never outlives this call.

    ``factor_secrets`` are the v4 factors' secrets in list order (``_resolve_factor_secrets``).
    """
    wrapper = header["wrappers"]["password"]
    nonce = _validated_wrapper_field(wrapper, "nonce", 12)
    ciphertext = _validated_wrapper_field(wrapper, "ciphertext", 48)
    specs = _header_factor_specs(header)
    kek = _password_kek(master_password, header["kdf"], specs, factor_secrets or [])
    try:
        try:
            return _unwrap_key(kek, nonce, ciphertext,
                               _wrapper_aad(header, "password", _password_metadata(header, specs)))
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
                        backup_dir: Path | None, backup_count: int,
                        factor_secrets: list[bytearray] | None = None,
                        rollback_marks: str = MARKS_LIVE) -> VaultSession:
    if _has_wrapped_key(header):
        data_key = _unwrap_password_wrapper(header, master_password, factor_secrets)
    else:
        data_key = _derive_key(master_password, header["kdf"])
    return _decrypt_vault(path, header, source_bytes, data_key, backup_dir=backup_dir, backup_count=backup_count,
                          rollback_marks=rollback_marks)


def _rebind_throttle(session: VaultSession, throttle: UnlockThrottle) -> None:
    """After a verified unlock, re-record a throttle key that had to be replaced (R-8).

    An unreadable key (a profile copied to another Windows account) is
    replaced at the reset; without a save the header would keep naming the
    old key and every later start would fail closed.  Best effort.
    """
    try:
        if _has_wrapped_key(session._header) and throttle._binding_broken():
            session.save()
    except (VaultError, OSError):
        _LOG.warning("Could not re-record the unlock-throttle key for %s.", session.path.name)


def unlock_vault(path: Path, master_password: str | SecretText, *, factors: FactorSecrets | None = None,
                 backup_dir: Path | None = None, backup_count: int = 0, upgrade_envelope: bool = True,
                 upgrade_kdf: bool = False) -> VaultSession:
    """Open the vault with its master password (and, for a v4 vault, its key file / YubiKey).

    A v4 vault raises ``FactorRequired`` when ``factors`` lacks one of its factors and
    ``FactorMismatch`` when one is not this vault's; both come before Argon2 runs and neither
    counts as a failed password.  Factors given for a vault without any are ignored.  The session
    keeps what it was opened with (``_HeldFactors``) for later password checks until ``lock()``.

    ``upgrade_envelope=False`` is for read-only probes of a copy (backup
    verification): a v1/v2 envelope is opened as-is, so no migration journal
    or encrypted pre-migration snapshot is written next to the copy.

    ``upgrade_kdf=True`` (the app's own password unlock of the live vault only;
    restores, probes and checks leave it off) re-wraps the data key under the
    current Argon2id default when the vault uses weaker parameters, see
    ``VaultSession._upgrade_kdf_on_unlock``.  Hello, camera and recovery-phrase
    unlocks have no password and never upgrade.

    The rollback marks kept outside the folder follow the same split: ``upgrade_kdf=True`` is the live vault
    (both marks), ``upgrade_envelope=False`` a probe (no mark is read or written), anything else a copy that
    may be headed elsewhere (the path mark only), see ``_decrypt_vault``.
    """
    path = Path(path)
    marks_mode = MARKS_LIVE if upgrade_kdf else MARKS_COPY if upgrade_envelope else MARKS_OFF
    if not isinstance(master_password, (str, SecretText)):
        raise InvalidMasterPassword(t("vault.err.passwordEmpty"))
    secret, owned = _master_secret(master_password, t("vault.err.passwordTextInvalid"))
    try:
        throttle = UnlockThrottle(path)
        throttle.check()
        _recover_vault_migration(path)
        header, source_bytes = _read_vault_header(path)
        specs = _header_factor_specs(header)
        factor_secrets = _resolve_factor_secrets(specs, factors)  # not a password attempt: never throttled
        try:
            try:
                session = _open_with_password(path, header, source_bytes, secret, backup_dir=backup_dir,
                                              backup_count=backup_count, factor_secrets=factor_secrets,
                                              rollback_marks=marks_mode)
            except InvalidMasterPassword:
                throttle.record_failure()
                raise
            throttle.reset()
            session._hold_factors(specs, factor_secrets, factors)
            if upgrade_envelope:
                _rebind_throttle(session, throttle)
            if not _has_wrapped_key(header) and upgrade_envelope:
                try:
                    session._prepare_promotion(secret)
                    session._upgrade_envelope_on_unlock()
                except BaseException:
                    session.lock()
                    raise
            if upgrade_kdf and upgrade_envelope:
                try:
                    try:
                        session._repair_unlock_sidecars_after_kdf_upgrade()
                    except Exception as exc:  # noqa: BLE001 - a sidecar repair never blocks the unlock
                        _LOG.warning("Could not finish moving the unlock sidecars: %s", exc)
                    session._upgrade_kdf_on_unlock(secret, factor_secrets)
                except BaseException:
                    session.lock()
                    raise
            return session
        finally:
            _zero_all(factor_secrets)
    finally:
        if owned:
            secret.wipe()


def vault_identifier(path: Path) -> str:
    """The vault's ``vault_id`` from its public header (empty when the header has none)."""
    header, _source = _read_vault_header(Path(path))
    return str(header.get("vault_id") or "")


def vault_factors(path: Path) -> list[FactorSpec]:
    """The vault's key-file / YubiKey factors from its public header (no secret is read); ``[]`` for none."""
    header, _source = _read_vault_header(Path(path))
    return _header_factor_specs(header)


def add_factor(path: Path, password: str | SecretText, factors: FactorSecrets | None, new: FactorInput, *,
               backup_dir: Path | None = None, backup_count: int = 0) -> list[FactorSpec]:
    """Open the vault with ``password`` and its current ``factors``, add ``new`` and lock it again.

    Returns the new factor list.  See ``VaultSession.add_factor`` (the data key is not rotated).
    """
    session = unlock_vault(path, password, factors=factors, backup_dir=backup_dir, backup_count=backup_count)
    try:
        added: list[FactorSpec] = session.add_factor(password, new)
        return added
    finally:
        session.lock()


def remove_factor(path: Path, password: str | SecretText, factors: FactorSecrets | None, kind: str, *,
                  backup_dir: Path | None = None, backup_count: int = 0) -> list[FactorSpec]:
    """Open the vault, remove the factor of ``kind`` (the last one writes v3 again) and lock it."""
    session = unlock_vault(path, password, factors=factors, backup_dir=backup_dir, backup_count=backup_count)
    try:
        remaining: list[FactorSpec] = session.remove_factor(password, kind)
        return remaining
    finally:
        session.lock()


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
    wrapper = header.get("wrappers", {}).get("recovery") if _has_wrapped_key(header) else None
    if not isinstance(wrapper, dict):
        raise RecoveryPhraseError(t("vault.err.noRecoveryPhrase"))
    try:
        data_key = _unwrap_recovery_wrapper(header, wrapper, entropy)
    except RecoveryPhraseError:
        throttle.record_failure()
        raise
    # Also how a backup's copy is opened with its phrase: the path mark only (``_decrypt_vault``).
    session = _decrypt_vault(path, header, source_bytes, data_key, backup_dir=backup_dir, backup_count=backup_count,
                             rollback_marks=MARKS_COPY)
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


def _unlock_vault_with_security_key(path: Path, key: bytearray, *, expected_context: str,
                                   expected_binding: str, backup_dir: Path | None = None,
                                   backup_count: int = 0) -> VaultSession:
    """Internal security-key route; consume a key unwrapped with the key's hmac-secret.

    Same checks as the Windows Hello route, against the separate ``fido_binding``
    so revoking one method never leaves the other authorized by mistake.
    """
    session = None
    try:
        if not expected_binding:
            raise VaultError(t("vault.err.securityKeyNotAuthorized"))
        header, source_bytes = _read_vault_header(path)
        context = unlock_context_for_header(header)
        if not secrets.compare_digest(context, expected_context):
            raise VaultError(t("vault.err.passwordOrHeaderChanged"))
        session = _decrypt_vault(path, header, source_bytes, key, backup_dir=backup_dir,
                                  backup_count=backup_count)
        if not secrets.compare_digest(session.fido_binding(), expected_binding):
            raise VaultError(t("vault.err.securityKeyRevoked"))
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
