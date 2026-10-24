"""Password- and device-wrapped group keyring for LocalGateKeys device sync.

The keyring is the file in the user's cloud folder that holds the sync group key
``G`` wrapped by the sync password and by every member device's key.  The iOS app
implements it byte-for-byte, so every rule below is part of the format.

Format rules (version 1)
------------------------
* JSON shape (exactly these fields at every level)::

    {"format":1,"group_id","epoch",
     "kdf":{"name":"argon2id","salt","memory_kib":131072,"iterations":4,"parallelism":4},
     "password_wrap":{"nonce","ct"},
     "device_wraps":{device_id:{"eph","nonce","ct"}},
     "members":[{"device_id","name_ct","exchange_public","added_at"}],
     "prev_mac":null|base64,"mac":base64}

* Canonical JSON is ``localvault.updates.canonical_json``; base64 is standard with
  padding, decoded strictly (see ``group.py``); non-finite numbers are rejected.
  Identifiers (``group_id`` and every ``device_id``) are ASCII ``[A-Za-z0-9._:-]``,
  1..128 chars.  ``epoch`` starts at 1.  ``members`` has 1..16 entries with unique
  ``device_id``; ``added_at`` is an int in 0..2**53-1; ``exchange_public`` is a raw
  32-byte X25519 key; ``name_ct`` is the encrypted device name (below), 29..92 raw bytes.
* KDF (fixed for format 1): Argon2id, memory 131072 KiB, iterations 4, parallelism 4,
  16-byte random salt, 32-byte output, password encoded as UTF-8.  A keyring whose
  ``kdf`` differs in any field is rejected.
* Password wrap: AES-256-GCM, key = Argon2id(password), 12 random nonce bytes,
  plaintext ``G`` (32 bytes), ``ct`` = ciphertext || 16-byte tag (48 bytes), AAD =
  ``b"lgk-keyring-password-wrap-v1|" + group_id + b"|" + str(epoch)``.
* Device wrap: ephemeral X25519 key pair, ``shared = X25519(eph_private,
  member.exchange_public)``, key = ``HKDF(SHA256, length=32, salt=group_id utf-8,
  info=b"localgatekeys|sync|device-wrap|v1|" + device_id)``, AES-256-GCM over ``G``
  with AAD = ``b"lgk-keyring-device-wrap-v1|" + group_id + b"|" + str(epoch) + b"|" +
  device_id``.  ``eph`` is the raw 32-byte ephemeral public key.
* Member name: the device's name (plaintext 1..64 UTF-8 bytes, checked before
  encrypting) is never stored in clear.  ``name_key = HKDF(SHA256, length=32,
  salt=group_id utf-8, info=b"localgatekeys|sync|member-name|v1|" + str(epoch)).derive(G)``;
  ``name_ct`` = base64(nonce (12 random bytes) || AES-256-GCM(name_key).encrypt(nonce,
  name utf-8, AAD = ``b"lgk-keyring-member-name-v1|" + group_id + b"|" + str(epoch) + b"|" +
  device_id``)), so 12 + 1..64 + 16 = 29..92 raw bytes.  The structure check validates only
  the base64 and that length (``bad-name`` otherwise); names are decrypted
  (``member_names``) only from a keyring the caller has already accepted.  A name that fails
  to decrypt (or is not 1..64 bytes of UTF-8) reads as ``None``: the UI shows "Unnamed
  device" and the folder run reports ``bad-name`` without stopping.  Every rotation
  re-encrypts all remaining names under the new epoch's key (a name that cannot be read is
  re-encrypted as "Unnamed device").  The default name of a Windows device is the generic
  ``DEFAULT_DEVICE_NAME_PC`` ("Windows PC"), not its host name.
* Random draw order (deterministic test vectors replace ``os.urandom`` with one stream):
  ``create_group`` draws G (32), the KDF salt (16), the password-wrap nonce (12), then per
  member in member order the device wrap (ephemeral X25519 private key 32, wrap nonce 12)
  followed by that member's name nonce (12).  ``join_with_password`` draws the new
  member's ephemeral key (32), wrap nonce (12) and name nonce (12).  ``rotate`` draws like
  ``create_group`` (new G, salt, password nonce, then wrap + name nonce per remaining
  member in member order).  ``create_for_existing_group`` draws like ``create_group``
  without G (salt, password nonce, wrap, name nonce); ``attach_with_password`` like
  ``join_with_password``.
* Sync password: at least 12 characters and ``estimate_strength(pw).score >= 3``.

Trust model
-----------
There is NO writer signature: anyone with cloud-folder access could produce one.
The keyring is authenticated by knowledge of ``G``.

* ``mac_key(G, e)`` = ``HKDF(SHA256, 32, salt=group_id utf-8,
  info=b"localgatekeys|sync|keyring-mac|v1|" + str(e)).derive(G)``.
  ``mac`` = HMAC-SHA256(mac_key(G, epoch), canonical_json(keyring without "mac"));
  it therefore covers ``prev_mac``.
  ``prev_mac`` (``null`` at epoch 1, and in the first keyring of a group that existed
  before it had one, at any epoch) = HMAC-SHA256(mac_key(G_e, e), b"rotate|" +
  group_id + b"|" + str(e+1) + b"|" + lowercase-hex(SHA256(mac_key(G_{e+1}, e+1))))
  with e = epoch - 1: the previous key commits to the new MAC key, independent of the
  body, so a later join (which rewrites members, wraps and ``mac`` but keeps
  ``prev_mac``) does not break the chain for a device that missed the rotation.
* Each device stores a trusted ``(group_id, epoch, G)``.  A keyring is accepted only
  if ``group_id`` matches and either: epoch == stored epoch and ``mac`` verifies
  under the stored ``G``; or epoch == stored epoch + 1, ``prev_mac`` verifies under
  the device's wrap opens the new ``G``, ``prev_mac`` verifies under the stored ``G``
  against the commitment computed from that new ``G``, and ``mac`` verifies under the
  new ``G``.  An older epoch is a rollback, a larger jump is a missed rotation
  (re-join with the sync password); a bad MAC is "tampered".
* Joining with the password: unwrap ``G`` from the password wrap, require ``mac`` to
  verify under ``G``, add the member and its device wrap, recompute ``mac``.
* A Wi-Fi-only group (``G`` delivered by QR enrollment, no keyring) adds a cloud folder
  with ``create_for_existing_group``: a first keyring for the stored ``(group_id, epoch,
  G)`` with ``prev_mac`` null.  Its other devices ``attach_with_password``: like a join,
  but the password must open exactly the stored ``G`` at the stored group id and epoch, and
  the device keeps its identity.  The chain rule is unchanged: a keyring at the trusted
  epoch + 1 still needs a valid ``prev_mac``, so a null one there is "tampered".
* Every rotation (removing a device, changing the password) is ``rotate``: new ``G``,
  epoch + 1, new salt, a NEW sync password (reusing the current one is rejected by
  trying to open the current password wrap with it), wraps for the remaining members.  A
  removed participant who knew the old password or old ``G`` cannot open the new
  epoch.
* Residual risk: a device that was offline during a removal accepts the first valid
  epoch + 1 keyring it sees; a removed device that still has cloud access and the old
  ``G`` can race the genuine rotation.  Users removing a lost device should also sign
  it out of the cloud account.

Canonical JSON (must be byte-identical on iOS)
----------------------------------------------
Python ``json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"),
allow_nan=False)`` encoded as UTF-8: no whitespace; object keys sorted by Unicode code
point; strings escape only the double quote and the backslash (each preceded by a
backslash), the short forms backslash-b, -f, -n, -r, -t, and every other C0 control
character as backslash-u00xx with lowercase hex; nothing else is escaped (slash, DEL
and all non-ASCII are emitted literally as UTF-8).  Integers are plain decimal.  Object keys sort by
Unicode code point (equivalently by UTF-8 bytes), NOT by UTF-16 code unit, so the key U+FF5A sorts
before the key U+1F511.  Floats are Python ``repr(float)``: the shortest decimal that round-trips,
lowercase ``e`` with a signed two-digit-minimum exponent when the exponent is below -4 or at least 16
(``1e-07``, ``1e+16``, ``1.5e+300``), plain positional notation otherwise (``0.1``, ``100.0``,
``123456789012345.0``), always with a ``.0`` or an exponent, and ``-0.0`` keeps its sign.  NaN and the
infinities are rejected.  A float is never equal to an int on the wire (``100.0`` is not ``100``).
Digests of canonical JSON (``conflict_copy_id``, item ranking, the vector ``canonical_sha256`` values)
hash exactly these bytes.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import math
import os
import time
import uuid
from collections.abc import Callable, Iterable, Mapping

from argon2.low_level import Type, hash_secret_raw
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from localvault.password_tools import estimate_strength
from localvault.sync.engine import is_valid_id
from localvault.sync.group import GroupKey
from localvault.sync.pairing import DeviceIdentity
from localvault.updates import canonical_json

FORMAT = 1
KDF_NAME = "argon2id"
KDF_MEMORY_KIB = 131072
KDF_ITERATIONS = 4
KDF_PARALLELISM = 4
KDF_SALT_LEN = 16
MAX_MEMBERS = 16
MAX_KEYRING_BYTES = 256 * 1024
MIN_PASSWORD_LEN = 12
MIN_PASSWORD_SCORE = 3
MAX_NAME_LEN = 64
#: The name a Windows device gives itself in the keyring (no host name: it would leak to the cloud).
DEFAULT_DEVICE_NAME_PC = "Windows PC"
#: Re-encrypted in place of a name that cannot be read when rotating.
UNNAMED_DEVICE = "Unnamed device"

PASSWORD_AAD = b"lgk-keyring-password-wrap-v1|"
DEVICE_AAD = b"lgk-keyring-device-wrap-v1|"
DEVICE_INFO = b"localgatekeys|sync|device-wrap|v1|"
MAC_INFO = b"localgatekeys|sync|keyring-mac|v1|"
NAME_AAD = b"lgk-keyring-member-name-v1|"
NAME_INFO = b"localgatekeys|sync|member-name|v1|"

_MAX_INT = 2**53 - 1
_NONCE_LEN = 12
_KEY_LEN = 32
_WRAP_CT_LEN = _KEY_LEN + 16
_MAC_LEN = 32
_TAG_LEN = 16
_NAME_CT_MIN = _NONCE_LEN + 1 + _TAG_LEN
_NAME_CT_MAX = _NONCE_LEN + MAX_NAME_LEN + _TAG_LEN

_TOP_FIELDS = frozenset(
    {"format", "group_id", "epoch", "kdf", "password_wrap", "device_wraps", "members", "prev_mac", "mac"}
)
_KDF_FIELDS = frozenset({"name", "salt", "memory_kib", "iterations", "parallelism"})
_PW_WRAP_FIELDS = frozenset({"nonce", "ct"})
_DEV_WRAP_FIELDS = frozenset({"eph", "nonce", "ct"})
_MEMBER_FIELDS = frozenset({"device_id", "name_ct", "exchange_public", "added_at"})

# (memory_kib, iterations, parallelism); tests substitute a cheap profile.
_PRODUCTION_KDF = (KDF_MEMORY_KIB, KDF_ITERATIONS, KDF_PARALLELISM)


# Test-vector hook (``_rand``): a ``Callable[[int], bytes]`` replacing ``os.urandom`` for every
# random value a keyring operation draws (group key, salts, nonces, ephemeral X25519 keys).
# Only ``scripts/make_sync_vectors.py`` passes it; production code never does
# (``tests/test_sync_vectors.py`` scans the source tree for that).
RandomSource = Callable[[int], bytes]


class KeyringError(ValueError):
    """A keyring is malformed, fails authentication, or an operation is not allowed."""

    def __init__(self, reason: str, detail: str = "") -> None:
        super().__init__(f"{reason}: {detail}" if detail else reason)
        self.reason = reason


class WeakSyncPassword(ValueError):
    """The sync password is too short or too guessable."""


def _random(rand: RandomSource | None, n: int) -> bytes:
    raw = (rand or os.urandom)(n)
    if not isinstance(raw, bytes) or len(raw) != n:
        raise KeyringError("bad-random", f"random source must return exactly {n} bytes")
    return raw


def _profile(override: tuple[int, int, int] | None) -> tuple[int, int, int]:
    if override is None:
        return _PRODUCTION_KDF
    mem, its, par = override
    return int(mem), int(its), int(par)


def _check_password(password: object) -> str:
    if not isinstance(password, str):
        raise WeakSyncPassword("sync password must be text")
    if len(password) < MIN_PASSWORD_LEN or estimate_strength(password).score < MIN_PASSWORD_SCORE:
        raise WeakSyncPassword("sync password is too short or too easy to guess")
    return password


def _argon2(password: str, salt: bytes, profile: tuple[int, int, int]) -> bytes:
    mem, its, par = profile
    return hash_secret_raw(
        secret=password.encode("utf-8"),
        salt=salt,
        time_cost=its,
        memory_cost=mem,
        parallelism=par,
        hash_len=_KEY_LEN,
        type=Type.ID,
    )


def _b64e(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def _b64d_any(value: object, what: str) -> bytes:
    if not isinstance(value, str):
        raise KeyringError("bad-base64", what)
    try:
        raw = base64.b64decode(value, validate=True)
        if base64.b64encode(raw).decode("ascii") != value:
            raise ValueError("non-canonical base64")
    except (binascii.Error, ValueError) as exc:
        raise KeyringError("bad-base64", what) from exc
    return raw


def _b64d(value: object, length: int, what: str) -> bytes:
    raw = _b64d_any(value, what)
    if len(raw) != length:
        raise KeyringError("bad-length", what)
    return raw


def _is_int(value: object, minimum: int = 0) -> bool:
    return type(value) is int and minimum <= value <= _MAX_INT


def _password_aad(group_id: str, epoch: int) -> bytes:
    return PASSWORD_AAD + group_id.encode("ascii") + b"|" + str(epoch).encode("ascii")


def _device_aad(group_id: str, epoch: int, device_id: str) -> bytes:
    return (
        DEVICE_AAD + group_id.encode("ascii") + b"|" + str(epoch).encode("ascii") + b"|" + device_id.encode("ascii")
    )


def _device_key(shared: bytes, group_id: str, device_id: str) -> bytes:
    return HKDF(
        algorithm=hashes.SHA256(),
        length=_KEY_LEN,
        salt=group_id.encode("utf-8"),
        info=DEVICE_INFO + device_id.encode("ascii"),
    ).derive(shared)


def _wrap_password(
    gk: GroupKey, password: str, salt: bytes, profile: tuple[int, int, int], rand: RandomSource | None = None
) -> dict:
    nonce = _random(rand, _NONCE_LEN)
    key = _argon2(password, salt, profile)
    ct = AESGCM(key).encrypt(nonce, gk.key, _password_aad(gk.group_id, gk.epoch))
    return {"nonce": _b64e(nonce), "ct": _b64e(ct)}


def _wrap_device(
    gk: GroupKey, device_id: str, exchange_public: bytes, rand: RandomSource | None = None
) -> dict:
    if rand is None:
        eph = x25519.X25519PrivateKey.generate()
    else:
        eph = x25519.X25519PrivateKey.from_private_bytes(_random(rand, 32))
    try:
        shared = eph.exchange(x25519.X25519PublicKey.from_public_bytes(exchange_public))
    except ValueError as exc:
        raise KeyringError("bad-member-key", "exchange key unusable") from exc
    nonce = _random(rand, _NONCE_LEN)
    ct = AESGCM(_device_key(shared, gk.group_id, device_id)).encrypt(
        nonce, gk.key, _device_aad(gk.group_id, gk.epoch, device_id)
    )
    eph_pub = eph.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return {"eph": _b64e(eph_pub), "nonce": _b64e(nonce), "ct": _b64e(ct)}


def _name_key(gk: GroupKey) -> bytes:
    return HKDF(
        algorithm=hashes.SHA256(),
        length=_KEY_LEN,
        salt=gk.group_id.encode("utf-8"),
        info=NAME_INFO + str(gk.epoch).encode("ascii"),
    ).derive(gk.key)


def _name_aad(group_id: str, epoch: int, device_id: str) -> bytes:
    return NAME_AAD + group_id.encode("ascii") + b"|" + str(epoch).encode("ascii") + b"|" + device_id.encode("ascii")


def _seal_name(gk: GroupKey, device_id: str, name: str, rand: RandomSource | None = None) -> str:
    """``name_ct`` for *device_id* at *gk*'s epoch (*name* already checked by ``_check_name``)."""
    nonce = _random(rand, _NONCE_LEN)
    ct = AESGCM(_name_key(gk)).encrypt(nonce, name.encode("utf-8"), _name_aad(gk.group_id, gk.epoch, device_id))
    return _b64e(nonce + ct)


def _open_name(key: bytes, gk: GroupKey, device_id: object, value: object) -> str | None:
    if not isinstance(device_id, str) or not is_valid_id(device_id):
        return None
    try:
        raw = _b64d_any(value, "member name_ct")
        if not _NAME_CT_MIN <= len(raw) <= _NAME_CT_MAX:
            return None
        plain = AESGCM(key).decrypt(raw[:_NONCE_LEN], raw[_NONCE_LEN:], _name_aad(gk.group_id, gk.epoch, device_id))
        return _check_name(plain.decode("utf-8"))
    except (KeyringError, InvalidTag, UnicodeDecodeError, ValueError):
        return None


def member_names(keyring: Mapping, gk: GroupKey) -> dict[str, str | None]:
    """Decrypt every member's name: ``{device_id: name}``, ``None`` for a name that cannot be read.

    Call it ONLY on a keyring the caller has already accepted (``accept_keyring``,
    ``create_group``, ``join_with_password``, ``rotate`` or a stored accepted copy) with that
    keyring's group key; it does not authenticate the keyring.
    """
    key = _name_key(gk)
    out: dict[str, str | None] = {}
    for m in keyring["members"]:
        out[m["device_id"]] = _open_name(key, gk, m["device_id"], m.get("name_ct"))
    return out


def _member_entry(gk: GroupKey, member: Mapping, rand: RandomSource | None = None) -> tuple[dict, dict]:
    """(member entry, device wrap) for *member* (``device_id``, ``name``, ``exchange_public``, ``added_at``).

    Draw order: the device wrap (eph 32, nonce 12), then the name nonce (12).
    """
    device_id = member["device_id"]
    wrap = _wrap_device(gk, device_id, _b64d(member["exchange_public"], 32, "exchange_public"), rand)
    entry = {
        "device_id": device_id,
        "name_ct": _seal_name(gk, device_id, member["name"], rand),
        "exchange_public": member["exchange_public"],
        "added_at": member["added_at"],
    }
    return entry, wrap


def _new_member(identity: DeviceIdentity, name: str, now: int | None = None) -> dict:
    return {
        "device_id": identity.device_id,
        "name": name,
        "exchange_public": _b64e(identity.exchange_public_key),
        "added_at": int(time.time()) if now is None else now,
    }


def _check_name(name: object) -> str:
    if not isinstance(name, str):
        raise KeyringError("bad-name", "device name must be text")
    try:
        size = len(name.encode("utf-8"))
    except UnicodeEncodeError as exc:
        raise KeyringError("bad-name", "device name is not encodable") from exc
    if not 1 <= size <= MAX_NAME_LEN:
        raise KeyringError("bad-name", "device name must be 1..64 UTF-8 bytes")
    return name


def _check_identity(identity: DeviceIdentity) -> None:
    if not is_valid_id(identity.device_id):
        raise KeyringError("bad-device-id", "device id must be ASCII [A-Za-z0-9._:-], 1..128 chars")


def _mac_key(key: bytes, group_id: str, epoch: int) -> bytes:
    return HKDF(
        algorithm=hashes.SHA256(),
        length=_KEY_LEN,
        salt=group_id.encode("utf-8"),
        info=MAC_INFO + str(epoch).encode("ascii"),
    ).derive(key)


def _mac(key: bytes, group_id: str, epoch: int, ring: Mapping) -> bytes:
    body = {k: v for k, v in ring.items() if k != "mac"}
    return hmac.new(_mac_key(key, group_id, epoch), canonical_json(body), hashlib.sha256).digest()


def _chain_mac(old: GroupKey, new: GroupKey) -> bytes:
    """``prev_mac``: the old epoch's key commits to the new epoch's MAC key."""
    commitment = hashlib.sha256(_mac_key(new.key, new.group_id, new.epoch)).hexdigest()
    message = b"rotate|" + new.group_id.encode("ascii") + b"|" + str(new.epoch).encode("ascii") + b"|"
    message += commitment.encode("ascii")
    return hmac.new(_mac_key(old.key, old.group_id, old.epoch), message, hashlib.sha256).digest()


def _chain_ok(value: object, old: GroupKey, new: GroupKey) -> bool:
    try:
        return hmac.compare_digest(_b64d(value, _MAC_LEN, "prev_mac"), _chain_mac(old, new))
    except (KeyringError, ValueError, TypeError):
        return False


def _mac_ok(value: object, key: bytes, group_id: str, epoch: int, ring: Mapping) -> bool:
    try:
        given = _b64d(value, _MAC_LEN, "mac")
        return hmac.compare_digest(given, _mac(key, group_id, epoch, ring))
    except (KeyringError, ValueError, TypeError):
        return False


def _finish(body: Mapping, gk: GroupKey, prev: GroupKey | None, prev_mac: object = None) -> dict:
    """Return *body* with ``prev_mac`` and ``mac`` set (``prev_mac`` carried over if *prev* is None)."""
    out = {k: v for k, v in body.items() if k not in ("mac", "prev_mac")}
    out["prev_mac"] = _b64e(_chain_mac(prev, gk)) if prev is not None else prev_mac
    out["mac"] = _b64e(_mac(gk.key, gk.group_id, gk.epoch, out))
    return out


def _no_dup_pairs(pairs: list[tuple[str, object]]) -> dict:
    out: dict = {}
    for k, v in pairs:
        if k in out:
            raise ValueError(f"duplicate JSON key: {k!r}")
        out[k] = v
    return out


def _reject_constant(name: str) -> object:
    raise ValueError(f"non-finite number: {name}")


def _parse_float(text: str) -> float:
    value = float(text)
    if not math.isfinite(value):
        raise ValueError("non-finite number")
    return value


def parse_keyring(raw: bytes) -> dict:
    """Parse keyring bytes: size bound, UTF-8, no duplicate keys, finite numbers, object only."""
    if not isinstance(raw, bytes):
        raise KeyringError("bad-keyring", "keyring must be bytes")
    if len(raw) > MAX_KEYRING_BYTES:
        raise KeyringError("too-large", f"{len(raw)} > {MAX_KEYRING_BYTES}")
    try:
        value = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_no_dup_pairs,
            parse_constant=_reject_constant,
            parse_float=_parse_float,
        )
    except (ValueError, RecursionError) as exc:
        raise KeyringError("bad-json", "keyring is not valid JSON") from exc
    if not isinstance(value, dict):
        raise KeyringError("bad-keyring", "keyring must be an object")
    return value


def _fields(value: object, expected: frozenset[str], what: str) -> Mapping:
    if not isinstance(value, dict) or set(value) != expected:
        raise KeyringError("bad-fields", what)
    return value


def verify_keyring_structure(keyring: object, *, _kdf_override: tuple[int, int, int] | None = None) -> None:
    """Validate shape, bounds, KDF parameters and wrap/member sets (no authentication)."""
    profile = _profile(_kdf_override)
    ring = _fields(keyring, _TOP_FIELDS, "keyring fields")
    if type(ring["format"]) is not int or ring["format"] != FORMAT:
        raise KeyringError("bad-format", "unsupported keyring format")
    group_id, epoch = ring["group_id"], ring["epoch"]
    if not is_valid_id(group_id):
        raise KeyringError("bad-group-id", "group_id")
    if not _is_int(epoch, 1):
        raise KeyringError("bad-epoch", "epoch")

    kdf = _fields(ring["kdf"], _KDF_FIELDS, "kdf fields")
    if kdf["name"] != KDF_NAME or not isinstance(kdf["name"], str):
        raise KeyringError("bad-kdf", "unsupported kdf")
    for field_name, expected in zip(("memory_kib", "iterations", "parallelism"), profile, strict=True):
        if type(kdf[field_name]) is not int or kdf[field_name] != expected:
            raise KeyringError("bad-kdf", f"{field_name} differs from the format parameters")
    _b64d(kdf["salt"], KDF_SALT_LEN, "kdf salt")

    pw = _fields(ring["password_wrap"], _PW_WRAP_FIELDS, "password_wrap fields")
    _b64d(pw["nonce"], _NONCE_LEN, "password_wrap nonce")
    _b64d(pw["ct"], _WRAP_CT_LEN, "password_wrap ct")

    members = ring["members"]
    if not isinstance(members, list) or not members:
        raise KeyringError("bad-members", "members must be a non-empty list")
    if len(members) > MAX_MEMBERS:
        raise KeyringError("too-many-members", "members must have at most 16 entries")
    ids: set[str] = set()
    for m in members:
        m = _fields(m, _MEMBER_FIELDS, "member fields")
        if not is_valid_id(m["device_id"]):
            raise KeyringError("bad-device-id", "member device_id")
        if m["device_id"] in ids:
            raise KeyringError("duplicate-member", "member device ids must be unique")
        ids.add(m["device_id"])
        if not _NAME_CT_MIN <= len(_b64d_any(m["name_ct"], "member name_ct")) <= _NAME_CT_MAX:
            raise KeyringError("bad-name", "member name_ct must be 29..92 bytes")
        if not _is_int(m["added_at"]):
            raise KeyringError("bad-fields", "member added_at")
        _b64d(m["exchange_public"], 32, "member exchange_public")

    wraps = ring["device_wraps"]
    if not isinstance(wraps, dict) or set(wraps) != ids:
        raise KeyringError("wrap-mismatch", "device_wraps must match members exactly")
    for wrap in wraps.values():
        w = _fields(wrap, _DEV_WRAP_FIELDS, "device wrap fields")
        _b64d(w["eph"], 32, "device wrap eph")
        _b64d(w["nonce"], _NONCE_LEN, "device wrap nonce")
        _b64d(w["ct"], _WRAP_CT_LEN, "device wrap ct")

    if epoch == 1:
        if ring["prev_mac"] is not None:
            raise KeyringError("bad-fields", "prev_mac must be null at epoch 1")
    elif ring["prev_mac"] is not None:  # null: the first keyring of an existing group
        _b64d(ring["prev_mac"], _MAC_LEN, "prev_mac")
    _b64d(ring["mac"], _MAC_LEN, "mac")


def _member(ring: Mapping, identity: DeviceIdentity) -> Mapping:
    for m in ring["members"]:
        if m["device_id"] == identity.device_id:
            if m["exchange_public"] != _b64e(identity.exchange_public_key):
                raise KeyringError("key-mismatch", "device key differs from the registered member")
            return m
    raise KeyringError("not-member", "device is not a member of this keyring")


def _unwrap_password(ring: Mapping, password: str, profile: tuple[int, int, int]) -> GroupKey:
    pw = ring["password_wrap"]
    salt = _b64d(ring["kdf"]["salt"], KDF_SALT_LEN, "kdf salt")
    key = _argon2(password, salt, profile)
    try:
        plain = AESGCM(key).decrypt(
            _b64d(pw["nonce"], _NONCE_LEN, "nonce"),
            _b64d(pw["ct"], _WRAP_CT_LEN, "ct"),
            _password_aad(ring["group_id"], ring["epoch"]),
        )
    except InvalidTag as exc:
        raise KeyringError("password", "wrong sync password or damaged keyring") from exc
    return GroupKey(ring["group_id"], ring["epoch"], plain)


def _unwrap_device(ring: Mapping, identity: DeviceIdentity) -> GroupKey:
    _member(ring, identity)
    wrap = ring["device_wraps"][identity.device_id]
    try:
        shared = identity.exchange_key.exchange(
            x25519.X25519PublicKey.from_public_bytes(_b64d(wrap["eph"], 32, "eph"))
        )
        plain = AESGCM(_device_key(shared, ring["group_id"], identity.device_id)).decrypt(
            _b64d(wrap["nonce"], _NONCE_LEN, "nonce"),
            _b64d(wrap["ct"], _WRAP_CT_LEN, "ct"),
            _device_aad(ring["group_id"], ring["epoch"], identity.device_id),
        )
    except (InvalidTag, ValueError) as exc:
        raise KeyringError("device-wrap", "device wrap cannot be opened") from exc
    return GroupKey(ring["group_id"], ring["epoch"], plain)


def _fresh_body(
    gk: GroupKey,
    password: str,
    members: list[dict],
    profile: tuple[int, int, int],
    rand: RandomSource | None = None,
) -> dict:
    """A new epoch's body; *members* hold plaintext ``name`` (see ``_member_entry``)."""
    salt = _random(rand, KDF_SALT_LEN)
    mem, its, par = profile
    password_wrap = _wrap_password(gk, password, salt, profile, rand)
    entries: list[dict] = []
    wraps: dict[str, dict] = {}
    for member in members:
        entry, wrap = _member_entry(gk, member, rand)
        entries.append(entry)
        wraps[entry["device_id"]] = wrap
    return {
        "format": FORMAT,
        "group_id": gk.group_id,
        "epoch": gk.epoch,
        "kdf": {
            "name": KDF_NAME,
            "salt": _b64e(salt),
            "memory_kib": mem,
            "iterations": its,
            "parallelism": par,
        },
        "password_wrap": password_wrap,
        "device_wraps": wraps,
        "members": entries,
    }


def _with_member(keyring: Mapping, gk: GroupKey, identity: DeviceIdentity, name: str,
                 rand: RandomSource | None, now: int | None) -> dict:
    """*keyring* (authenticated under *gk*) plus *identity* and its wrap; ``prev_mac`` carried over."""
    body = {k: v for k, v in keyring.items() if k != "mac"}
    entry, wrap = _member_entry(gk, _new_member(identity, name, now), rand)
    body["members"] = [*keyring["members"], entry]
    body["device_wraps"] = {**keyring["device_wraps"], identity.device_id: wrap}
    return _finish(body, gk, None, keyring["prev_mac"])


def create_group(
    password: str,
    identity: DeviceIdentity,
    name: str,
    *,
    _kdf_override: tuple[int, int, int] | None = None,
    _rand: RandomSource | None = None,
    _now: int | None = None,
    _group_id: str | None = None,
) -> tuple[dict, GroupKey]:
    """Create a new group (epoch 1) with *identity* as its first member.

    ``_rand``, ``_now`` and ``_group_id`` exist only for the deterministic test vectors.
    """
    _check_password(password)
    _check_identity(identity)
    _check_name(name)
    profile = _profile(_kdf_override)
    gk = GroupKey(str(uuid.uuid4()) if _group_id is None else _group_id, 1, _random(_rand, _KEY_LEN))
    body = _fresh_body(gk, password, [_new_member(identity, name, _now)], profile, _rand)
    return _finish(body, gk, None), gk


def join_with_password(
    keyring: dict,
    password: str,
    identity: DeviceIdentity,
    name: str,
    *,
    _kdf_override: tuple[int, int, int] | None = None,
    _rand: RandomSource | None = None,
    _now: int | None = None,
) -> tuple[dict, GroupKey]:
    """Join by sync password: open ``G``, require the MAC, add this device, recompute the MAC."""
    profile = _profile(_kdf_override)
    verify_keyring_structure(keyring, _kdf_override=_kdf_override)
    _check_identity(identity)
    _check_name(name)
    if not isinstance(password, str):
        raise KeyringError("password", "wrong sync password or damaged keyring")
    if any(m["device_id"] == identity.device_id for m in keyring["members"]):
        raise KeyringError("already-member", "device is already a member")
    if len(keyring["members"]) >= MAX_MEMBERS:
        raise KeyringError("too-many-members", "the group already has 16 devices")
    gk = _unwrap_password(keyring, password, profile)
    if not _mac_ok(keyring["mac"], gk.key, gk.group_id, gk.epoch, keyring):
        raise KeyringError("tampered", "keyring MAC does not verify under the group key")
    return _with_member(keyring, gk, identity, name, _rand, _now), gk


def create_for_existing_group(
    gk: GroupKey,
    password: str,
    identity: DeviceIdentity,
    name: str,
    *,
    _kdf_override: tuple[int, int, int] | None = None,
    _rand: RandomSource | None = None,
    _now: int | None = None,
) -> dict:
    """The first keyring of an existing group (*gk* from Wi-Fi enrollment), *identity* its only member.

    Same body as ``create_group`` but for the given ``(group_id, epoch, G)``; ``prev_mac``
    is null at any epoch.  ``_rand`` and ``_now`` exist only for the deterministic test vectors.
    """
    if not isinstance(gk, GroupKey):
        raise KeyringError("bad-group-key", "a GroupKey is required")
    _check_password(password)
    _check_identity(identity)
    _check_name(name)
    profile = _profile(_kdf_override)
    body = _fresh_body(gk, password, [_new_member(identity, name, _now)], profile, _rand)
    return _finish(body, gk, None)


def attach_with_password(
    keyring: dict,
    password: str,
    identity: DeviceIdentity,
    name: str,
    stored: GroupKey,
    *,
    _kdf_override: tuple[int, int, int] | None = None,
    _rand: RandomSource | None = None,
    _now: int | None = None,
) -> dict:
    """Add a device that is already in the group (*stored* key, e.g. from Wi-Fi) to *keyring*.

    Like ``join_with_password``, but the password must open exactly *stored*: a keyring of
    another group id or another key gives ``different-group-key``, another epoch
    ``epoch-mismatch``; ``password``, ``tampered`` and ``too-many-members`` as for a join.
    The device keeps its identity.  Returns the new keyring (``prev_mac`` carried over).
    Idempotent: if this identity is already listed with its own exchange key and its
    device wrap opens to *stored* (an earlier attach that did not finish), *keyring*
    itself is returned unchanged; a listed device id that fails either check is
    ``already-member``.
    """
    profile = _profile(_kdf_override)
    if not isinstance(stored, GroupKey):
        raise KeyringError("bad-group-key", "a GroupKey is required")
    verify_keyring_structure(keyring, _kdf_override=_kdf_override)
    _check_identity(identity)
    _check_name(name)
    if not isinstance(password, str):
        raise KeyringError("password", "wrong sync password or damaged keyring")
    if keyring["group_id"] != stored.group_id:
        raise KeyringError("different-group-key", "the folder holds another sync group")
    if keyring["epoch"] != stored.epoch:
        raise KeyringError("epoch-mismatch", "the folder's group key is from another epoch")
    listed = any(m["device_id"] == identity.device_id for m in keyring["members"])
    if listed and not any(m["device_id"] == identity.device_id
                          and m["exchange_public"] == _b64e(identity.exchange_public_key)
                          for m in keyring["members"]):
        raise KeyringError("already-member", "another device is listed under this device id")
    if not listed and len(keyring["members"]) >= MAX_MEMBERS:
        raise KeyringError("too-many-members", "the group already has 16 devices")
    gk = _unwrap_password(keyring, password, profile)
    if not hmac.compare_digest(gk.key, stored.key):
        raise KeyringError("different-group-key", "the password opens a different group key")
    if not _mac_ok(keyring["mac"], gk.key, gk.group_id, gk.epoch, keyring):
        raise KeyringError("tampered", "keyring MAC does not verify under the group key")
    if listed:
        # An earlier attach wrote the keyring but did not finish (vault locked, save failed):
        # this exact device is already in, so the attach succeeds without a rewrite.
        try:
            own = _unwrap_device(keyring, identity)
        except KeyringError as exc:
            raise KeyringError("already-member", "device is already a member") from exc
        if not hmac.compare_digest(own.key, stored.key):
            raise KeyringError("already-member", "device is already a member")
        return keyring
    return _with_member(keyring, gk, identity, name, _rand, _now)


def accept_keyring(
    keyring: dict,
    trusted: GroupKey,
    identity: DeviceIdentity,
    *,
    _kdf_override: tuple[int, int, int] | None = None,
) -> GroupKey:
    """Authenticate *keyring* against the device's trusted ``(group_id, epoch, G)``.

    Returns the trusted key (same epoch) or the new key (epoch + 1).  Raises
    ``KeyringError`` with reason ``group-mismatch``, ``rollback``, ``missed-rotation``
    or ``tampered`` (or a structural reason).
    """
    verify_keyring_structure(keyring, _kdf_override=_kdf_override)
    if keyring["group_id"] != trusted.group_id:
        raise KeyringError("group-mismatch", "keyring belongs to another group")
    epoch = keyring["epoch"]
    if epoch < trusted.epoch:
        raise KeyringError("rollback", "keyring is older than the trusted epoch")
    if epoch > trusted.epoch + 1:
        raise KeyringError("missed-rotation", "rejoin with the sync password")
    if epoch == trusted.epoch:
        if not _mac_ok(keyring["mac"], trusted.key, trusted.group_id, trusted.epoch, keyring):
            raise KeyringError("tampered", "keyring MAC does not verify")
        return trusted
    new_gk = _unwrap_device(keyring, identity)
    if not _chain_ok(keyring["prev_mac"], trusted, new_gk):
        raise KeyringError("tampered", "keyring does not chain from the trusted epoch")
    if not _mac_ok(keyring["mac"], new_gk.key, new_gk.group_id, new_gk.epoch, keyring):
        raise KeyringError("tampered", "keyring MAC does not verify under the new group key")
    return new_gk


def open_with_device_wrap(
    keyring: dict,
    identity: DeviceIdentity,
    *,
    _kdf_override: tuple[int, int, int] | None = None,
) -> GroupKey:
    """Open *keyring* with this device's own wrap and require ``mac`` under that key.

    It does NOT establish trust (anyone can wrap a key of their choosing to a
    member's public key); callers use it only to tell a competing rotation at
    the trusted epoch apart from a keyring that is plainly damaged.  Raises
    ``KeyringError`` (``not-member``, ``key-mismatch``, ``device-wrap``,
    ``tampered`` or a structural reason).
    """
    verify_keyring_structure(keyring, _kdf_override=_kdf_override)
    gk = _unwrap_device(keyring, identity)
    if not _mac_ok(keyring["mac"], gk.key, gk.group_id, gk.epoch, keyring):
        raise KeyringError("tampered", "keyring MAC does not verify under the wrapped key")
    return gk


def rotate(
    keyring: dict,
    trusted: GroupKey,
    identity: DeviceIdentity,
    new_password: str,
    *,
    remove: Iterable[str] = (),
    _kdf_override: tuple[int, int, int] | None = None,
    _rand: RandomSource | None = None,
) -> tuple[dict, GroupKey]:
    """New ``G``, epoch + 1, new salt and a NEW sync password; drop the *remove* devices."""
    profile = _profile(_kdf_override)
    _check_password(new_password)
    gk = accept_keyring(keyring, trusted, identity, _kdf_override=_kdf_override)
    if gk.epoch != trusted.epoch:
        raise KeyringError("stale-trust", "adopt the current keyring before rotating")
    _member(keyring, identity)
    drop = set(remove)
    have = {m["device_id"] for m in keyring["members"]}
    if identity.device_id in drop:
        raise KeyringError("cannot-remove-self", "a device cannot remove itself")
    if not drop <= have:
        raise KeyringError("not-member", "device to remove is not a member")
    try:
        _unwrap_password(keyring, new_password, profile)
    except KeyringError:
        pass
    else:
        raise KeyringError("password-reused", "choose a sync password different from the current one")
    new_gk = GroupKey(gk.group_id, gk.epoch + 1, _random(_rand, _KEY_LEN))
    names = member_names(keyring, gk)
    remaining = [
        {
            "device_id": m["device_id"],
            "name": names[m["device_id"]] or UNNAMED_DEVICE,
            "exchange_public": m["exchange_public"],
            "added_at": m["added_at"],
        }
        for m in keyring["members"]
        if m["device_id"] not in drop
    ]
    body = _fresh_body(new_gk, new_password, remaining, profile, _rand)
    return _finish(body, new_gk, gk), new_gk
