"""The scheduled-backup key pair, its public record and the reset authority.

Byte-exact specification: ``docs/design/backup-public-key-2026-10-31.md`` sections 3.2, 3.3, 3.4 (the wrap of
one data key only; the v3 container lives in ``backup.py``) and 3.6.  Vectors: ``tests/vectors/backup/v3``.

* The private key is derived from the backup password (Argon2id, HKDF, explicit RFC 7748 clamping); only the
  public key, a one-way ``key_id`` and the KDF parameters are ever stored (the *record*).
* A data key is wrapped to the public key with an ephemeral X25519 exchange, HKDF-SHA256 and AES-256-GCM.
* The reset authority proves, later, that a typed recovery phrase is the one that was active when the key was set.

Nothing here reads the clock: every time value is an integer argument (design section 12.1).  Secrets are
returned in ``bytearray`` buffers the caller wipes (best effort: the Argon2 output of a ``str`` password and the
values handed to ``cryptography`` pass through immutable ``bytes``).

``backup.py`` must import this module lazily (inside functions): this module imports ``backup`` at load time.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import os
import re
from dataclasses import dataclass
from typing import Any

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from .backup import BACKUP_KDF, BackupError, _derive, _full_canonical, _kdf_parameters
from .secret_text import SecretText

# --------------------------------------------------------------------------- labels (section 3)
BACKUP_KEY_INFO = b"localgatekeys|backup-key|x25519|v1"
KEY_ID_PREFIX = b"localgatekeys|backup-key-id|v1|"
WRAP_INFO = b"localgatekeys|backup-wrap|v1"
WRAP_AAD_PREFIX = b"localgatekeys|backup-recipient|v1|"
RECOVERY_KEY_INFO = b"localgatekeys|recovery-key|v1"  # == vault.RECOVERY_KEY_INFO
AUTHORITY_MAC_PREFIX = b"localgatekeys|backup-reset-authority|v1|"
RECIPIENT_SCHEME = "x25519-hkdf-sha256-aes-256-gcm-v1"

RECORD_VERSION = 1
HISTORY_LIMIT = 16
SET_BY = ("set", "migrated", "changed", "reset")
AUTHORITY_WRAPPER = "recovery-wrapper-v1"
AUTHORITY_MAC = "recovery-key-mac-v1"
MAX_TIMESTAMP = 2**53 - 1
MAX_AUTHORITY_AAD_BYTES = 4096

WRAP_NONCE = bytes(12)
HKDF_ZERO_SALT = bytes(32)  # an "absent" HKDF salt (RFC 5869): Swift and Kotlin pass it explicitly
SALT_BYTES = 16
KEY_BYTES = 32
WRAPPED_BYTES = KEY_BYTES + 16

RECORD_FIELDS = frozenset({"v", "key_id", "public_key", "kdf", "set_at", "set_by", "reset_at", "reset_authority",
                           "history"})
KDF_FIELDS = frozenset({"name", "time_cost", "memory_cost_kib", "parallelism", "salt"})
HISTORY_FIELDS = frozenset({"key_id", "set_at", "set_by", "replaced_at"})
WRAPPER_AUTHORITY_FIELDS = frozenset({"kind", "salt", "nonce", "ciphertext", "aad"})
MAC_AUTHORITY_FIELDS = frozenset({"kind", "salt", "mac"})

WRONG_PASSWORD_MESSAGE = "Wrong backup password or modified full backup"  # noqa: S105 - == backup.py v2 (3.4)
INVALID_PUBLIC_KEY_MESSAGE = "The backup public key is not usable"
NOT_CURRENT_PASSWORD_MESSAGE = "That is not the current backup password."  # noqa: S105 - section 7.1 text
_KEY_ID = re.compile(r"[0-9a-f]{32}")


class BackupKeyError(BackupError):
    pass


class WrongBackupPasswordError(BackupKeyError):
    """Wrong password, a key id that does not match, or a wrap that does not open: one message for all three."""

    def __init__(self) -> None:
        super().__init__(WRONG_PASSWORD_MESSAGE)


class DamagedRecordError(BackupKeyError):
    """The stored record is not one this code wrote (section 3.3): scheduled backups skip, the page offers reset."""

    def __init__(self, reason: str) -> None:
        self.reason = reason
        super().__init__(f"The backup key record is damaged: {reason}")


class NotCurrentPasswordError(BackupKeyError):
    """Proof (a) failed: the typed password does not derive the record's public key (section 7.1)."""

    def __init__(self) -> None:
        super().__init__(NOT_CURRENT_PASSWORD_MESSAGE)


class DamagedAuthorityError(BackupKeyError):
    def __init__(self, reason: str) -> None:
        self.reason = reason
        super().__init__(f"The reset authority is damaged: {reason}")


def _zero(buffer: bytearray | None) -> None:
    if buffer is not None:
        buffer[:] = bytes(len(buffer))


def _b64e(value: bytes | bytearray) -> str:
    return base64.b64encode(bytes(value)).decode("ascii")


def _b64_field(value: Any, size: int | None, error) -> bytes:
    """Strict base64 (RFC 4648 section 4, padded, canonical) of exactly ``size`` bytes."""
    if not isinstance(value, str) or not value.isascii() or len(value) > 8192:
        raise error
    try:
        decoded = base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError):
        raise error from None
    if _b64e(decoded) != value or (size is not None and len(decoded) != size):
        raise error
    return decoded


def _hkdf(ikm: bytes | bytearray, *, salt: bytes, info: bytes) -> bytearray:
    return bytearray(HKDF(algorithm=hashes.SHA256(), length=KEY_BYTES, salt=salt, info=info).derive(bytes(ikm)))


def _timestamp(value: Any) -> bool:
    return type(value) is int and 0 <= value <= MAX_TIMESTAMP


def clamp(raw: bytes | bytearray) -> bytearray:
    """RFC 7748 clamping, done explicitly so the vector value of a private key is the same everywhere."""
    if len(raw) != KEY_BYTES:
        raise BackupKeyError("An X25519 private key is 32 bytes")
    key = bytearray(raw)
    key[0] &= 0xF8
    key[31] &= 0x7F
    key[31] |= 0x40
    return key


def x25519_public(private_key: bytes | bytearray) -> bytes:
    return X25519PrivateKey.from_private_bytes(bytes(private_key)).public_key().public_bytes_raw()


def _shared_secret(private_key: bytes | bytearray, peer_public: bytes) -> bytearray:
    """X25519; an all-zero result (a low-order peer key) is refused (``ValueError``)."""
    if len(peer_public) != KEY_BYTES:
        raise ValueError("bad public key length")
    shared = bytearray(X25519PrivateKey.from_private_bytes(bytes(private_key)).exchange(
        X25519PublicKey.from_public_bytes(bytes(peer_public))))  # cryptography raises on all-zero itself
    if not any(shared):
        raise ValueError("all-zero shared secret")
    return shared


def key_id(public_key: bytes) -> str:
    """``hex(SHA-256("localgatekeys|backup-key-id|v1|" || pk)[0:16])``: 32 lowercase hex characters."""
    if not isinstance(public_key, (bytes, bytearray)) or len(public_key) != KEY_BYTES:
        raise BackupKeyError(INVALID_PUBLIC_KEY_MESSAGE)
    return hashlib.sha256(KEY_ID_PREFIX + bytes(public_key)).digest()[:16].hex()


# --------------------------------------------------------------------------- 3.2: the key pair
def new_kdf(*, salt: bytes | None = None, parameters: dict[str, int] | None = None) -> dict[str, Any]:
    """A record/header ``kdf`` object: ``BACKUP_KDF`` (or ``parameters``) plus a fresh (or the given) 16-byte salt."""
    base: dict[str, Any] = dict(BACKUP_KDF)
    if parameters:
        base.update({k: parameters[k] for k in ("time_cost", "memory_cost_kib", "parallelism") if k in parameters})
    salt = os.urandom(SALT_BYTES) if salt is None else salt
    if not isinstance(salt, bytes) or len(salt) != SALT_BYTES:
        raise BackupKeyError("The backup key salt is 16 bytes")
    return {**_kdf_parameters(base), "salt": _b64e(salt)}


def parse_kdf(kdf: Any) -> tuple[dict[str, int | str], bytes]:
    """Strictly validate a ``kdf`` object (exactly its five keys, ``_kdf_parameters`` bounds, a 16-byte salt)."""
    error = BackupError("Unsupported backup encryption parameters")
    if not isinstance(kdf, dict) or set(kdf) != KDF_FIELDS:
        raise error
    parameters = _kdf_parameters(kdf)
    return parameters, _b64_field(kdf.get("salt"), SALT_BYTES, error)


@dataclass
class BackupKey:
    """A derived key pair and the ``kdf`` object (with salt) it came from.  ``private_key`` is clamped; call
    ``wipe()`` when done."""

    private_key: bytearray
    public_key: bytes
    key_id: str
    kdf: dict[str, Any]

    def wipe(self) -> None:
        _zero(self.private_key)


def _derive_parts(password: str | SecretText, kdf: Any) -> tuple[bytearray, bytearray, bytearray]:
    """``(seed, sk_raw, sk)`` of section 3.2 (vectors only expose all three)."""
    parameters, salt = parse_kdf(kdf)
    seed = bytearray(_derive(password, salt, parameters))  # 12-4096 characters, UTF-8 as typed, no normalisation
    sk_raw = bytearray()
    try:
        sk_raw = _hkdf(seed, salt=HKDF_ZERO_SALT, info=BACKUP_KEY_INFO)
        return seed, sk_raw, clamp(sk_raw)
    except BaseException:
        _zero(seed)
        _zero(sk_raw)
        raise


def derive_backup_key(password: str | SecretText, kdf: Any) -> BackupKey:
    """The key pair for ``password`` under a ``kdf`` object (from ``new_kdf``, a record or a v3 header)."""
    seed, sk_raw, sk = _derive_parts(password, kdf)
    _zero(seed)
    _zero(sk_raw)
    try:
        public = x25519_public(sk)
    except BaseException:
        _zero(sk)
        raise
    return BackupKey(private_key=sk, public_key=public, key_id=key_id(public), kdf=dict(kdf))


# --------------------------------------------------------------------------- 3.4: wrap and unwrap one data key
def wrap_aad(core: dict[str, Any], recipient_body: dict[str, Any]) -> bytes:
    """``"localgatekeys|backup-recipient|v1|" || canon({"header": core, "recipient": rcpt_body})``.

    ``core`` is the v3 header without ``recipient``; ``recipient_body`` is the recipient without ``wrapped_key``
    (it holds ``ephemeral_public_key``, so make the ephemeral key first: ``new_ephemeral_key``).
    """
    if not isinstance(core, dict) or "recipient" in core:
        raise BackupKeyError("wrap_aad takes the header without its recipient")
    if not isinstance(recipient_body, dict) or "wrapped_key" in recipient_body:
        raise BackupKeyError("wrap_aad takes the recipient without its wrapped key")
    return WRAP_AAD_PREFIX + _full_canonical({"header": core, "recipient": recipient_body})


@dataclass
class EphemeralKey:
    """``esk`` (clamped, wipe after the writer's self-verify, section 9.1) and ``epk = X25519(esk, 9)``."""

    secret: bytearray
    public: bytes

    def wipe(self) -> None:
        _zero(self.secret)


def new_ephemeral_key(raw: bytes | None = None) -> EphemeralKey:
    """32 random bytes (or ``raw``, for vectors), clamped as in 3.2."""
    source = bytearray(os.urandom(KEY_BYTES) if raw is None else raw)
    try:
        secret = clamp(source)
    finally:
        _zero(source)
    return EphemeralKey(secret=secret, public=x25519_public(secret))


def _wrap_kek(shared: bytes | bytearray, ephemeral_public: bytes, public_key: bytes) -> bytearray:
    return _hkdf(shared, salt=bytes(ephemeral_public) + bytes(public_key), info=WRAP_INFO)


def wrap_data_key(data_key: bytes | bytearray, public_key: bytes, ephemeral: EphemeralKey, aad: bytes) -> bytes:
    """``AES-256-GCM(kek, 12 zero bytes, dk, aad)`` (48 bytes); ``kek = HKDF(X25519(esk, pk), epk || pk, info)``."""
    if len(data_key) != KEY_BYTES:
        raise BackupKeyError("A backup data key is 32 bytes")
    if not isinstance(public_key, (bytes, bytearray)) or len(public_key) != KEY_BYTES:
        raise BackupKeyError(INVALID_PUBLIC_KEY_MESSAGE)
    try:
        shared = _shared_secret(ephemeral.secret, bytes(public_key))
    except ValueError:
        raise BackupKeyError(INVALID_PUBLIC_KEY_MESSAGE) from None
    kek = bytearray()
    try:
        kek = _wrap_kek(shared, ephemeral.public, bytes(public_key))
        return AESGCM(bytes(kek)).encrypt(WRAP_NONCE, bytes(data_key), aad)
    finally:
        _zero(shared)
        _zero(kek)


def unwrap_data_key(private_key: bytes | bytearray, ephemeral_public: bytes, wrapped: bytes, aad: bytes) -> bytearray:
    """Open a wrap with the (clamped) private key; any failure is ``WrongBackupPasswordError``."""
    if len(private_key) != KEY_BYTES or len(ephemeral_public) != KEY_BYTES or len(wrapped) != WRAPPED_BYTES:
        raise WrongBackupPasswordError()
    shared = kek = bytearray()
    try:
        try:
            shared = _shared_secret(private_key, bytes(ephemeral_public))
        except ValueError:
            raise WrongBackupPasswordError() from None
        kek = _wrap_kek(shared, bytes(ephemeral_public), x25519_public(private_key))
        try:
            return bytearray(AESGCM(bytes(kek)).decrypt(WRAP_NONCE, bytes(wrapped), aad))
        except InvalidTag:
            raise WrongBackupPasswordError() from None
    finally:
        _zero(shared)
        _zero(kek)


def unwrap_with_password(password: str | SecretText, *, kdf: Any, expected_key_id: str, ephemeral_public: bytes,
                         wrapped: bytes, aad: bytes) -> bytearray:
    """The reader's order (3.4): Argon2 → key id check (no GCM attempt on a mismatch) → unwrap.

    ``kdf`` and ``expected_key_id`` come from the v3 header's recipient, which the caller has validated.
    A password outside 12-4096 characters raises the ``_derive`` length error, as v2 does.
    """
    key = derive_backup_key(password, kdf)
    try:
        if not hmac.compare_digest(key.key_id.encode("ascii"), str(expected_key_id).encode("ascii", "replace")):
            raise WrongBackupPasswordError()
        return unwrap_data_key(key.private_key, ephemeral_public, wrapped, aad)
    finally:
        key.wipe()


# --------------------------------------------------------------------------- 3.6: reset authority
def phrase_key(entropy: bytes | bytearray, salt: bytes) -> bytearray:
    """``K(s) = HKDF(ikm=entropy, salt=s, info="localgatekeys|recovery-key|v1")`` (``vault._recovery_key``)."""
    if len(entropy) != KEY_BYTES or len(salt) != SALT_BYTES:
        raise BackupKeyError("A recovery phrase key needs 32 bytes of entropy and a 16-byte salt")
    return _hkdf(entropy, salt=bytes(salt), info=RECOVERY_KEY_INFO)


def capture_wrapper_authority(vault_header: dict[str, Any]) -> dict[str, str] | None:
    """Windows: a frozen copy of the vault header's ``wrappers.recovery`` plus its AAD; ``None`` with no phrase."""
    from .vault import RECOVERY_WRAPPER_KIND, _has_wrapped_key, _wrapper_aad
    if not isinstance(vault_header, dict) or not _has_wrapped_key(vault_header):  # v3, or v4 with factors
        return None
    wrappers = vault_header.get("wrappers")
    wrapper = wrappers.get("recovery") if isinstance(wrappers, dict) else None
    if not isinstance(wrapper, dict):
        return None
    error = DamagedAuthorityError("the vault's recovery wrapper is malformed")
    if wrapper.get("kind") != RECOVERY_WRAPPER_KIND:
        raise error
    salt = _b64_field(wrapper.get("salt"), SALT_BYTES, error)
    nonce = _b64_field(wrapper.get("nonce"), 12, error)
    ciphertext = _b64_field(wrapper.get("ciphertext"), WRAPPED_BYTES, error)
    aad = _wrapper_aad(vault_header, "recovery", {"kind": RECOVERY_WRAPPER_KIND, "salt": wrapper["salt"]})
    return validate_authority({"kind": AUTHORITY_WRAPPER, "salt": _b64e(salt), "nonce": _b64e(nonce),
                               "ciphertext": _b64e(ciphertext), "aad": _b64e(aad)})


def _authority_mac(key: bytes | bytearray, key_id_text: str) -> bytes:
    return hmac.new(bytes(key), AUTHORITY_MAC_PREFIX + key_id_text.encode("ascii"), hashlib.sha256).digest()


def capture_mac_authority(salt: bytes, recovery_key: bytes | bytearray, backup_key_id: str) -> dict[str, str]:
    """Mac: ``{"kind", "salt": VaultKey.salt, "mac": HMAC-SHA256(VaultKey.key, prefix || key_id)}``."""
    if len(salt) != SALT_BYTES or len(recovery_key) != KEY_BYTES or not _KEY_ID.fullmatch(str(backup_key_id)):
        raise BackupKeyError("A Mac reset authority needs the 16-byte salt, the 32-byte key and a key id")
    return {"kind": AUTHORITY_MAC, "salt": _b64e(salt), "mac": _b64e(_authority_mac(recovery_key, backup_key_id))}


def validate_authority(value: Any) -> dict[str, str]:
    """Strict shape check of either kind (no secret needed)."""
    if not isinstance(value, dict):
        raise DamagedAuthorityError("not an object")
    kind = value.get("kind")
    if kind == AUTHORITY_WRAPPER:
        fields, sizes = WRAPPER_AUTHORITY_FIELDS, {"salt": SALT_BYTES, "nonce": 12, "ciphertext": WRAPPED_BYTES}
    elif kind == AUTHORITY_MAC:
        fields, sizes = MAC_AUTHORITY_FIELDS, {"salt": SALT_BYTES, "mac": 32}
    else:
        raise DamagedAuthorityError("unknown kind")
    if set(value) != fields:
        raise DamagedAuthorityError("unexpected or missing fields")
    for name, size in sizes.items():
        _b64_field(value[name], size, DamagedAuthorityError(f"bad {name}"))
    if kind == AUTHORITY_WRAPPER:
        aad = _b64_field(value["aad"], None, DamagedAuthorityError("bad aad"))
        if not 1 <= len(aad) <= MAX_AUTHORITY_AAD_BYTES:
            raise DamagedAuthorityError("bad aad")
    return dict(value)


def verify_authority(authority: Any, entropy: bytes | bytearray, backup_key_id: str) -> bool:
    """Does the phrase with this ``entropy`` (``vault.entropy_from_phrase``) pass the authority?

    ``backup_key_id`` is the key id of the record that holds the authority (the Mac kind binds it; the Windows
    kind does not need it).  A damaged authority raises ``DamagedAuthorityError``.

    This is the low-level check of one authority.  A reset must use ``verify_reset_phrase`` (owner decision Q2:
    the phrase must also be the vault's current one).
    """
    authority = validate_authority(authority)
    salt = base64.b64decode(authority["salt"])
    key = phrase_key(entropy, salt)
    try:
        if authority["kind"] == AUTHORITY_WRAPPER:
            try:
                opened = bytearray(AESGCM(bytes(key)).decrypt(base64.b64decode(authority["nonce"]),
                                                              base64.b64decode(authority["ciphertext"]),
                                                              base64.b64decode(authority["aad"])))
            except InvalidTag:
                return False
            _zero(opened)  # the vault data key of that time: never kept
            return True
        if not _KEY_ID.fullmatch(str(backup_key_id)):
            return False
        return hmac.compare_digest(_authority_mac(key, str(backup_key_id)), base64.b64decode(authority["mac"]))
    finally:
        _zero(key)



def verify_reset_phrase(record: Any, entropy: bytes | bytearray, current_authority: dict[str, str] | None) -> bool:
    """Owner decision Q2 (design section 16, strict): may this phrase reset the backup password?

    Both must hold: the phrase passes the record's bound ``reset_authority``, **and** it is the vault's current
    recovery phrase.  ``current_authority`` is captured from the current state just before the check, with the same
    kind as the bound one: Windows ``capture_wrapper_authority(<current vault header>)``, Mac
    ``capture_mac_authority(<current VaultKey.salt>, <current VaultKey.key>, record["key_id"])``; ``None`` when no
    phrase is enrolled now.  A replaced phrase fails the second test; a phrase enrolled later fails the first until
    the authority is re-bound (``rebind_record``).  A record without an authority never resets.
    """
    record = validate_record(record)
    bound = record["reset_authority"]
    if bound is None or current_authority is None:
        return False
    current = validate_authority(current_authority)
    if current["kind"] != bound["kind"]:
        return False
    is_bound = verify_authority(bound, entropy, record["key_id"])
    is_current = verify_authority(current, entropy, record["key_id"])
    return is_bound and is_current

# --------------------------------------------------------------------------- 3.3: the public record
def build_record(key: BackupKey, *, now: int, set_by: str, reset_authority: dict[str, str] | None,
                 previous: dict[str, Any] | None = None) -> dict[str, Any]:
    """A new record for ``key`` (``derive_backup_key`` output, with its ``kdf``), set at ``now`` (integer Unix seconds, from the caller).

    ``set`` and ``migrated`` start a new history; ``changed`` and ``reset`` need the ``previous`` record, which
    goes to the front of ``history`` (``replaced_at = now``; at most 16 entries).  ``reset`` sets ``reset_at = now``.
    The proof (old password or phrase) is the caller's: this only builds the record.
    """
    if set_by not in SET_BY:
        raise BackupKeyError("Unknown backup key operation")
    if not _timestamp(now):
        raise BackupKeyError("A backup key time is integer Unix seconds")
    parse_kdf(key.kdf)
    if x25519_public(key.private_key) != key.public_key or key_id(key.public_key) != key.key_id:
        raise BackupKeyError("The backup key pair does not match")
    history: list[dict[str, Any]] = []
    if set_by in ("changed", "reset"):
        if previous is None:
            raise BackupKeyError("A change or reset replaces an existing backup key record")
        old = validate_record(previous)
        history = [{"key_id": old["key_id"], "set_at": old["set_at"], "set_by": old["set_by"], "replaced_at": now},
                   *old["history"]][:HISTORY_LIMIT]
    elif previous is not None:
        raise BackupKeyError("A first set or a migration starts without a record")
    record = {
        "v": RECORD_VERSION,
        "key_id": key.key_id,
        "public_key": _b64e(key.public_key),
        "kdf": dict(key.kdf),
        "set_at": now,
        "set_by": set_by,
        "reset_at": now if set_by == "reset" else None,
        "reset_authority": None if reset_authority is None else dict(reset_authority),
        "history": history,
    }
    return validate_record(record)


def validate_record(value: Any) -> dict[str, Any]:
    """Section 3.3 validation on read.  Returns a copy; raises ``DamagedRecordError`` with the reason."""
    if not isinstance(value, dict):
        raise DamagedRecordError("not an object")
    if set(value) != RECORD_FIELDS:
        raise DamagedRecordError("unexpected or missing fields")
    if type(value["v"]) is not int or value["v"] != RECORD_VERSION:
        raise DamagedRecordError("unsupported version")
    public = _b64_field(value["public_key"], KEY_BYTES, DamagedRecordError("bad public key"))
    if not isinstance(value["key_id"], str) or not _KEY_ID.fullmatch(value["key_id"]):
        raise DamagedRecordError("bad key id")
    if not hmac.compare_digest(value["key_id"], key_id(public)):
        raise DamagedRecordError("the key id does not match the public key")
    try:
        parse_kdf(value["kdf"])
    except BackupError:
        raise DamagedRecordError("bad key derivation parameters") from None
    if not _timestamp(value["set_at"]):
        raise DamagedRecordError("bad set time")
    if value["set_by"] not in SET_BY:
        raise DamagedRecordError("bad operation")
    if value["set_by"] == "reset":
        if not _timestamp(value["reset_at"]):
            raise DamagedRecordError("bad reset time")
    elif value["reset_at"] is not None:
        raise DamagedRecordError("a reset time on a key that was not reset")
    if value["reset_authority"] is not None:
        try:
            validate_authority(value["reset_authority"])
        except DamagedAuthorityError as exc:
            raise DamagedRecordError(f"bad reset authority ({exc.reason})") from None
    history = value["history"]
    if not isinstance(history, list) or len(history) > HISTORY_LIMIT:
        raise DamagedRecordError("bad history")
    for entry in history:
        if (not isinstance(entry, dict) or set(entry) != HISTORY_FIELDS
                or not isinstance(entry["key_id"], str) or not _KEY_ID.fullmatch(entry["key_id"])
                or not _timestamp(entry["set_at"]) or entry["set_by"] not in SET_BY
                or not _timestamp(entry["replaced_at"])):
            raise DamagedRecordError("bad history entry")
    return {
        **value,
        "kdf": dict(value["kdf"]),
        "reset_authority": None if value["reset_authority"] is None else dict(value["reset_authority"]),
        "history": [dict(entry) for entry in history],
    }


def record_public_key(record: dict[str, Any]) -> bytes:
    """The 32-byte public key of a valid record (for the v3 writer)."""
    return base64.b64decode(validate_record(record)["public_key"])


def password_matches(record: dict[str, Any], password: str | SecretText) -> bool:
    """Proof (a), section 4: re-derive with the record's salt and parameters; constant-time compare of ``pk``."""
    record = validate_record(record)
    try:
        key = derive_backup_key(password, record["kdf"])
    except BackupError:
        return False
    try:
        return hmac.compare_digest(key.public_key, base64.b64decode(record["public_key"]))
    finally:
        key.wipe()


def rebind_record(record: dict[str, Any], password: str | SecretText,
                  reset_authority: dict[str, str] | None) -> dict[str, Any]:
    """Owner decision Q2: after the recovery phrase is replaced, re-bind the authority to the new phrase.

    Needs proof (a), the current backup password (re-derive, match the public key), else
    ``NotCurrentPasswordError``.  Only ``reset_authority`` changes (the key, ``set_at``, ``set_by``, ``reset_at``
    and ``history`` stay; no clock is needed).  ``None`` records that no phrase is enrolled now.
    """
    record = validate_record(record)
    if not password_matches(record, password):
        raise NotCurrentPasswordError()
    rebound = dict(record, reset_authority=None if reset_authority is None else validate_authority(reset_authority))
    return validate_record(rebound)


def encode_record(record: dict[str, Any]) -> bytes:
    """``canon(record)`` of a valid record (what the vectors pin)."""
    return _full_canonical(validate_record(record))
