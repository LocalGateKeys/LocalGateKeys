"""Emergency access, owner side (sub-plan 08, Task 2): heir plans, signed ``.lgkheir`` shard packages, the sheet.

The owner splits the 32-byte recovery entropy (``VaultSession.recovery_entropy``, behind re-authentication)
with Shamir's secret sharing (``sss.py``) into ``n`` shards, any ``k`` of which recover it.  Each shard
travels in a signed ``.lgkheir`` package (``envelope.py``; byte rules in ``docs/formats/LGKHEIR_V1.md``) made
out to one holder by nickname, as a file, a QR text or a printed sheet (``sheet_facts``, printed by the browser like the emergency kit).

Every package of a plan carries the same plan id, plan public key and entropy check value.  The check is
HKDF-SHA256 of the entropy with a random per-plan salt and the plan id as context; it lets the requester
confirm a combined secret before using it (Task 3) and reveals nothing practical, because the entropy is 256
uniformly random bits (never a hash of the phrase words).  The plan's Ed25519 private key stays in the owner's
encrypted vault (``heir_plan`` preference) so the owner's devices can sign later plan files (deny, grant).

The owner keeps no shard.  A new plan replaces the stored one, but shards of an older plan still recover the
same entropy until the recovery phrase is replaced: replacing the phrase is how holders are revoked, and the
vault then marks the stored plan ``stale`` (re-issue shards).

Task 3 (``heir_flow.py``) adds, per plan, an X25519 *backup key* derived from the entropy
(``backup_private_key``; only its public half is stored) that the owner's app locks the heir folder's backups
to, and one *holder key* per shard (``holder_key``, an HKDF of the share, kept in the encrypted record) with
which a holder proves in an access request that they hold a shard of this plan, so "Grant now" never wraps
the entropy to a stranger's key.

Limit (serverless): the waiting period and the owner's refusal are enforced only by honest copies of the app.
Any ``k`` holders acting together can recover the entropy at once and open the owner's backups; holders must be
people who would not act together.  Zeroing of the entropy here is best effort only: Python ``bytes`` copies
(the phrase decoding, ``sss.split``) cannot be wiped.
"""
from __future__ import annotations

import base64
import binascii
import copy
import hmac
import os
import re
import secrets
import unicodedata
import uuid
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from . import envelope, sss
from .vault import ProFeatureRequired, require_pro_feature

__all__ = [
    "FORMAT", "VERSION", "FEATURE", "MAX_PACKAGE", "QR_LIMIT", "PREF_KEY", "HeirError", "ProRequired", "Holder",
    "HeirPlan", "Shard", "create_plan", "load_plan", "remove_plan", "plan_signing_key", "holder_nicknames",
    "read_package", "combine_packages", "entropy_check", "verify_entropy", "shard_qr_text",
    "package_from_qr_text", "sheet_facts", "holder_key", "backup_private_key", "backup_public_key",
    "owner_material", "add_denied", "check_shards", "DENIED_LIMIT", "set_plan_folder", "synced_record",
    "merge_synced", "LOCAL_ONLY_KEYS",
]

FORMAT = "localgatekeys-heir"
VERSION = 1
KIND = "heir-shard"
#: The Pro feature that gates creating a plan (``licensing.Feature.EMERGENCY_ACCESS``).
FEATURE = "emergency_access"
MAX_PACKAGE = 4096
QR_PREFIX = "lgkheir:"
#: Longest QR text (byte mode, error correction M fits 2331 bytes at version 40).
QR_LIMIT = 2048
NICKNAME_LIMIT = 32
MIN_WAIT_DAYS, MAX_WAIT_DAYS = 1, 30
CHECK_INFO = b"LocalGateKeys heir check v1\n"
HOLDER_INFO = b"LocalGateKeys heir holder v1\n"
BACKUP_KEY_INFO = b"LocalGateKeys heir backup key v1\n"
PREF_KEY = "heir_plan"
_PAYLOAD_KEYS = {"kind", "plan_id", "index", "holder", "k", "n", "wait_days", "created", "share", "check_salt",
                 "check"}
_RECORD_KEYS = {"version", "plan_id", "k", "n", "holders", "wait_days", "folder", "created", "owner", "signer",
                "signing_key", "check_salt", "check", "backup_public", "holder_keys"}
#: Set by the vault when the recovery phrase is replaced or removed: the plan's shards no longer open it.
STALE_KEY = "stale"
#: The request ids the owner refused (Task 3): their deny files are written again if they go missing.
DENIED_KEY = "denied"
DENIED_LIMIT = 64
#: Local to each device: ``True`` on the device that made the plan (its vault's phrase is the plan's, so only it
#: writes the heir folder's backups and marks the plan stale); ``False`` on a device that received it by sync.
HOME_KEY = "home"
_OPTIONAL_RECORD_KEYS = {STALE_KEY, DENIED_KEY, HOME_KEY}
#: Never synced (``sync/vault_bridge.py`` namespace ``heir``): the shared folder's path on this device, and home.
LOCAL_ONLY_KEYS = ("folder", HOME_KEY)
_SYNCED_KEYS = (_RECORD_KEYS - {"folder"}) | {STALE_KEY, DENIED_KEY}
OWNER_LIMIT = envelope.SENDER_LIMIT
#: Split randomness; a module seam for tests, never a ``create_plan`` argument.
_rng: Callable[[int], bytes] = secrets.token_bytes

#: Raised by ``create_plan`` on the free plan (the vault's ``ProFeatureRequired``).
ProRequired = ProFeatureRequired


class HeirError(ValueError):
    """``reason``: ``invalid`` (plan parameters), ``malformed``, ``conflict`` (a synced plan that re-keys the
    stored one), ``unsupported``, ``bad-signature``,
    ``need-more`` (``missing`` shards short), ``duplicate``, ``mixed-plans`` or ``check-failed``."""

    def __init__(self, reason: str, message: str = "", *, missing: int = 0) -> None:
        super().__init__(message or reason)
        self.reason = reason
        self.missing = missing


@dataclass(frozen=True)
class Holder:
    nickname: str


@dataclass(frozen=True)
class HeirPlan:
    k: int
    n: int
    holders: tuple[Holder, ...]
    wait_days: int
    folder: Path | None
    created: int
    plan_id: str = ""
    owner: str = ""
    signer: bytes = b""
    check_salt: bytes = b""
    check: bytes = b""
    #: The recovery phrase was replaced or removed since: the shards are dead, re-issue them.
    stale: bool = False
    #: The public X25519 key the heir folder's backups are locked to (``backup_private_key`` of the entropy).
    backup_public: bytes = b""
    #: Request ids the owner refused.
    denied: tuple[str, ...] = ()
    #: Made on this device (``False``: received from another of the owner's devices by sync).
    home: bool = True


@dataclass(frozen=True)
class Shard:
    """One verified package: the shard (``share`` = ``[index, 32 bytes]``) and the plan facts it carries."""

    package_id: str
    plan_id: str
    index: int
    holder: str
    k: int
    n: int
    wait_days: int
    created: int
    owner: str
    signer: bytes
    share: bytes
    check_salt: bytes
    check: bytes


# ------------------------------------------------------------------------------------------- validation
def _is_int(value: Any) -> bool:
    return type(value) is int


def _printable(raw: Any, limit: int, *, allow_empty: bool = False) -> str:
    if not isinstance(raw, str):
        raise HeirError("invalid", "A name must be text")
    name = unicodedata.normalize("NFC", raw).strip()
    if (not name and not allow_empty) or len(name) > limit \
            or any(unicodedata.category(ch).startswith("C") for ch in name):
        raise HeirError("invalid", f"A name must be 1 to {limit} printable characters")
    return name


def _nickname(value: Any) -> str:
    return _printable(value.nickname if isinstance(value, Holder) else value, NICKNAME_LIMIT)


def _owner(value: Any) -> str:
    return _printable(value, OWNER_LIMIT, allow_empty=True)


def _check_counts(k: Any, n: Any, wait_days: Any) -> None:
    if not (_is_int(k) and _is_int(n) and sss.MIN_K <= k <= n <= sss.MAX_N):
        raise HeirError("invalid", f"Choose {sss.MIN_K} <= k <= n <= {sss.MAX_N}")
    if not (_is_int(wait_days) and MIN_WAIT_DAYS <= wait_days <= MAX_WAIT_DAYS):
        raise HeirError("invalid", f"The waiting period is {MIN_WAIT_DAYS} to {MAX_WAIT_DAYS} days")


def _holders(holders: Iterable[Any], n: int) -> tuple[Holder, ...]:
    if isinstance(holders, (str, bytes)):
        raise HeirError("invalid", "Holders must be a list of nicknames")
    names = [_nickname(h) for h in holders]
    if len(names) != n:
        raise HeirError("invalid", "Name one holder per shard")
    if len({name.casefold() for name in names}) != len(names):
        raise HeirError("invalid", "Each holder needs a different nickname")
    return tuple(Holder(name) for name in names)


def entropy_check(entropy: bytes | bytearray, *, plan_id: str, salt: bytes) -> bytes:
    """``HKDF-SHA256(ikm=entropy, salt=salt, info=CHECK_INFO || plan_id)``, 32 bytes."""
    if len(entropy) != sss.SECRET_LEN or len(salt) != 16:
        raise HeirError("invalid", "The entropy is 32 bytes and the salt 16")
    return HKDF(hashes.SHA256(), 32, salt, CHECK_INFO + plan_id.encode("ascii")).derive(bytes(entropy))


def holder_key(share: bytes | bytearray, *, plan_id: str, salt: bytes) -> bytes:
    """``HKDF-SHA256(ikm=share (33 bytes), salt=salt, info=HOLDER_INFO || plan_id)``: a holder's proof key."""
    if len(share) != sss.SHARE_LEN or len(salt) != 16:
        raise HeirError("invalid", "A share is 33 bytes and the salt 16")
    return HKDF(hashes.SHA256(), 32, salt, HOLDER_INFO + plan_id.encode("ascii")).derive(bytes(share))


def backup_private_key(entropy: bytes | bytearray, *, plan_id: str, salt: bytes) -> bytearray:
    """The clamped X25519 key the heir folder's backups are locked to; the caller wipes it."""
    from .backup_key import clamp

    if len(entropy) != sss.SECRET_LEN or len(salt) != 16:
        raise HeirError("invalid", "The entropy is 32 bytes and the salt 16")
    info = BACKUP_KEY_INFO + plan_id.encode("ascii")
    raw = bytearray(HKDF(hashes.SHA256(), 32, salt, info).derive(bytes(entropy)))
    try:
        return clamp(raw)
    finally:
        raw[:] = bytes(len(raw))


def backup_public_key(entropy: bytes | bytearray, *, plan_id: str, salt: bytes) -> bytes:
    from .backup_key import x25519_public

    private = backup_private_key(entropy, plan_id=plan_id, salt=salt)
    try:
        return x25519_public(private)
    finally:
        private[:] = bytes(len(private))


def verify_entropy(plan: HeirPlan | Shard, entropy: bytes | bytearray) -> bool:
    """Whether ``entropy`` is the one the plan was made from (constant-time compare)."""
    if not isinstance(entropy, (bytes, bytearray)) or len(entropy) != sss.SECRET_LEN:
        return False
    return hmac.compare_digest(entropy_check(entropy, plan_id=plan.plan_id, salt=plan.check_salt), plan.check)


# ------------------------------------------------------------------------------------------------- plan
def create_plan(session: Any, *, k: int, n: int, holders: Sequence[Holder | str], wait_days: int,
                folder: Path | str | None, phrase: str | None = None,
                reauthenticate: Callable[[], bool] | None = None, owner: str = "",
                now: int | None = None) -> tuple[HeirPlan, list[bytes]]:
    """Make and store a plan; returns it with one ``.lgkheir`` package per holder (in holder order).

    Order of checks: parameters, Pro (``ProRequired``), then ``session.recovery_entropy`` which calls
    ``reauthenticate`` (not exactly ``True`` -> ``PermissionError``) and checks ``phrase`` against the vault.
    """
    _check_counts(k, n, wait_days)
    members = _holders(holders, n)
    owner = _owner(owner or "")
    created = int(datetime.now(UTC).timestamp()) if now is None else now
    if not _is_int(created) or created < 0:
        raise HeirError("invalid", "The creation time is invalid")
    require_pro_feature(session, FEATURE)
    entropy = bytearray(session.recovery_entropy(phrase, reauthenticate=reauthenticate))
    try:
        plan_id = str(uuid.uuid4())
        key = ed25519.Ed25519PrivateKey.generate()
        salt = os.urandom(16)
        check = entropy_check(entropy, plan_id=plan_id, salt=salt)
        backup_public = backup_public_key(entropy, plan_id=plan_id, salt=salt)
        shares = sss.split(entropy, k=k, n=n, rng=_rng)
    finally:
        entropy[:] = bytes(len(entropy))  # best effort: immutable copies elsewhere cannot be wiped
    holder_keys = tuple(holder_key(share, plan_id=plan_id, salt=salt) for share in shares)
    plan = HeirPlan(k=k, n=n, holders=members, wait_days=wait_days, folder=Path(folder) if folder else None,
                    created=created, plan_id=plan_id, owner=owner,
                    signer=key.public_key().public_bytes_raw(), check_salt=salt, check=check,
                    backup_public=backup_public)
    packages = []
    for holder, share in zip(members, shares, strict=True):
        payload = {"kind": KIND, "plan_id": plan_id, "index": share[0], "holder": holder.nickname, "k": k,
                   "n": n, "wait_days": wait_days, "created": created, "share": envelope.b64e(share),
                   "check_salt": envelope.b64e(salt), "check": envelope.b64e(check)}
        packages.append(envelope.seal_signed(FORMAT, VERSION, package_id=str(uuid.uuid4()), sender=owner,
                                             payload=payload, signing_key=key))
    del shares
    session.set_heir_plan_record(_record(plan, key, holder_keys))
    return plan, packages


def _record(plan: HeirPlan, key: ed25519.Ed25519PrivateKey, holder_keys: Sequence[bytes]) -> dict[str, Any]:
    return {"version": VERSION, "plan_id": plan.plan_id, "k": plan.k, "n": plan.n,
            "holders": [h.nickname for h in plan.holders], "wait_days": plan.wait_days,
            "folder": str(plan.folder) if plan.folder is not None else None, "created": plan.created,
            "owner": plan.owner, "signer": envelope.b64e(plan.signer),
            "signing_key": envelope.b64e(key.private_bytes_raw()),
            "check_salt": envelope.b64e(plan.check_salt), "check": envelope.b64e(plan.check),
            "backup_public": envelope.b64e(plan.backup_public),
            "holder_keys": [envelope.b64e(value) for value in holder_keys], HOME_KEY: True}


def _load(session: Any) -> tuple[HeirPlan, ed25519.Ed25519PrivateKey, tuple[bytes, ...]] | None:
    record = session.heir_plan_record()
    if record is None:
        return None
    return _parse(record)


def _parse(record: Any) -> tuple[HeirPlan, ed25519.Ed25519PrivateKey, tuple[bytes, ...]]:
    try:
        if not isinstance(record, dict) or set(record) - _OPTIONAL_RECORD_KEYS != _RECORD_KEYS \
                or record["version"] != VERSION or type(record.get(STALE_KEY, False)) is not bool \
                or type(record.get(HOME_KEY, True)) is not bool:
            raise HeirError("malformed")
        _check_counts(record["k"], record["n"], record["wait_days"])
        members = _holders(record["holders"], record["n"])
        folder = record["folder"]
        if folder is not None and not isinstance(folder, str):
            raise HeirError("malformed")
        key = ed25519.Ed25519PrivateKey.from_private_bytes(envelope.b64d(record["signing_key"], 32))
        signer = envelope.b64d(record["signer"], 32)
        if key.public_key().public_bytes_raw() != signer or not _is_int(record["created"]) \
                or _owner(record["owner"]) != record["owner"]:
            raise HeirError("malformed")
        keys = record["holder_keys"]
        if not isinstance(keys, list) or len(keys) != record["n"]:
            raise HeirError("malformed")
        holder_keys = tuple(envelope.b64d(value, 32) for value in keys)
        denied = record.get(DENIED_KEY, [])
        if not isinstance(denied, list) or len(denied) > DENIED_LIMIT:
            raise HeirError("malformed")
        denied_ids = tuple(envelope.checked_id(value) for value in denied)
        plan = HeirPlan(k=record["k"], n=record["n"], holders=members, wait_days=record["wait_days"],
                        folder=Path(folder) if folder else None, created=record["created"],
                        plan_id=envelope.checked_id(record["plan_id"]), owner=record["owner"], signer=signer,
                        check_salt=envelope.b64d(record["check_salt"], 16),
                        check=envelope.b64d(record["check"], 32), stale=record.get(STALE_KEY) is True,
                        backup_public=envelope.b64d(record["backup_public"], 32), denied=denied_ids,
                        home=record.get(HOME_KEY, True) is True)
    except (envelope.EnvelopeError, HeirError, KeyError, TypeError, ValueError):
        raise HeirError("malformed", "The stored emergency access plan is damaged") from None
    return plan, key, holder_keys


def load_plan(session: Any) -> HeirPlan | None:
    """The stored plan, ``None`` without one; a damaged record raises ``HeirError("malformed")``."""
    loaded = _load(session)
    return None if loaded is None else loaded[0]


def plan_signing_key(session: Any) -> ed25519.Ed25519PrivateKey:
    """The plan's Ed25519 key (in the encrypted vault), for signing later plan files such as a deny."""
    loaded = _load(session)
    if loaded is None:
        raise HeirError("malformed", "There is no emergency access plan")
    return loaded[1]


def owner_material(session: Any) -> tuple[HeirPlan, ed25519.Ed25519PrivateKey, tuple[bytes, ...]] | None:
    """The stored plan, its signing key and the holder keys (index order), for the owner's flows (Task 3)."""
    return _load(session)


def add_denied(session: Any, request_id: str) -> None:
    """Remember a refused request id in the stored plan (the newest ``DENIED_LIMIT`` are kept)."""
    request_id = envelope.checked_id(request_id)
    if _load(session) is None:
        raise HeirError("malformed", "There is no emergency access plan")
    record = session.heir_plan_record()
    denied = [value for value in record.get(DENIED_KEY, []) if value != request_id]
    record[DENIED_KEY] = [*denied, request_id][-DENIED_LIMIT:]
    session.set_heir_plan_record(record)


def set_plan_folder(session: Any, folder: Path | str | None) -> HeirPlan:
    """Set the shared folder of the stored plan on this device (the path is local: it never syncs)."""
    record = session.heir_plan_record()
    if record is None:
        raise HeirError("malformed", "There is no emergency access plan")
    record["folder"] = str(folder) if folder else None
    plan = _parse(record)[0]
    session.set_heir_plan_record(record)
    return plan


def synced_record(record: Any) -> dict[str, Any]:
    """The form of a stored plan record that syncs between the owner's devices: no local-only keys, with
    ``stale`` and ``denied`` always present.  Raises ``HeirError("malformed")`` for a damaged record."""
    _parse(record)
    out = {key: copy.deepcopy(value) for key, value in record.items() if key not in LOCAL_ONLY_KEYS}
    out.setdefault(STALE_KEY, False)
    out.setdefault(DENIED_KEY, [])
    return out


def merge_synced(local: Any, remote: Any) -> dict[str, Any]:
    """The record to store when ``remote`` (a synced record from another of the owner's devices) arrives.

    The same plan keeps this device's folder and home, ``stale`` is either side's, and ``denied`` is the union
    (the newest ``DENIED_LIMIT``).  Every other field of the same plan is pinned: a remote that differs in
    any of them (another signing key, holder keys, check, holders, owner, ...) is refused
    (``HeirError("conflict")``), so no device can silently re-key a plan.  Another plan replaces the local one
    (the sync engine already chose it): no folder here yet, not home.
    """
    if not isinstance(remote, dict) or set(remote) != _SYNCED_KEYS:
        raise HeirError("malformed", "The synced emergency access plan is damaged")
    remote = synced_record({**remote, "folder": None, HOME_KEY: False})
    same = isinstance(local, dict) and local.get("plan_id") == remote["plan_id"]
    if not same:
        stored = {**remote, "folder": None, HOME_KEY: False}
    else:
        local = synced_record(local) | {key: local[key] for key in LOCAL_ONLY_KEYS if key in local}
        mutable = {STALE_KEY, DENIED_KEY}
        if any(local[key] != remote[key] for key in _SYNCED_KEYS - mutable):
            raise HeirError("conflict", "The synced emergency access plan differs from this one")
        denied = [*local[DENIED_KEY], *(value for value in remote[DENIED_KEY] if value not in local[DENIED_KEY])]
        if set(denied) == set(remote[DENIED_KEY]):
            denied = list(remote[DENIED_KEY])  # nothing new here: keep the remote's order, so devices converge
        stored = {**remote, "folder": local.get("folder"), HOME_KEY: local.get(HOME_KEY, True),
                  STALE_KEY: bool(local[STALE_KEY] or remote[STALE_KEY]), DENIED_KEY: denied[-DENIED_LIMIT:]}
    _parse(stored)
    return stored


def remove_plan(session: Any) -> None:
    """Forget the stored plan (its shards keep working until the recovery phrase is replaced)."""
    session.set_heir_plan_record(None)


def holder_nicknames(session: Any) -> list[str]:
    """The holders' nicknames for the emergency kit page; empty without a readable, current plan or session."""
    if session is None or not callable(getattr(session, "heir_plan_record", None)):
        return []
    try:
        plan = load_plan(session)
    except Exception:  # noqa: BLE001 - locked, damaged: the kit page simply lists no holders
        return []
    return [] if plan is None or plan.stale else [h.nickname for h in plan.holders]


# ---------------------------------------------------------------------------------------------- packages
def read_package(data: bytes) -> Shard:
    """Parse and verify one ``.lgkheir`` package (signature first, then every payload rule)."""
    try:
        opened = envelope.open_signed(data, FORMAT, VERSION, limit=MAX_PACKAGE)
    except envelope.EnvelopeError as exc:
        raise HeirError(exc.reason, "This is not a valid emergency access shard") from None
    p = opened.payload
    try:
        if set(p) != _PAYLOAD_KEYS or p["kind"] != KIND:
            raise HeirError("malformed")
        _check_counts(p["k"], p["n"], p["wait_days"])
        if not (_is_int(p["index"]) and 1 <= p["index"] <= p["n"]) or not _is_int(p["created"]) \
                or p["created"] < 0 or _nickname(p["holder"]) != p["holder"] \
                or _owner(opened.sender) != opened.sender:
            raise HeirError("malformed")
        share = envelope.b64d(p["share"], sss.SHARE_LEN)
        if share[0] != p["index"]:
            raise HeirError("malformed")
        shard = Shard(package_id=opened.id, plan_id=envelope.checked_id(p["plan_id"]), index=p["index"],
                      holder=p["holder"], k=p["k"], n=p["n"], wait_days=p["wait_days"], created=p["created"],
                      owner=opened.sender, signer=opened.signer, share=share,
                      check_salt=envelope.b64d(p["check_salt"], 16), check=envelope.b64d(p["check"], 32))
    except (envelope.EnvelopeError, HeirError):
        raise HeirError("malformed", "This emergency access shard is damaged") from None
    return shard


def _plan_facts(shard: Shard) -> tuple[Any, ...]:
    return (shard.plan_id, shard.signer, shard.k, shard.n, shard.wait_days, shard.created, shard.owner,
            shard.check_salt, shard.check)


def check_shards(packages: Iterable[bytes]) -> list[Shard]:
    """Read packages that must belong to one plan, each shard once (at least one)."""
    shards = [read_package(data) for data in packages]
    if not shards:
        raise HeirError("need-more", "Add the shards you were given", missing=sss.MIN_K)
    facts = _plan_facts(shards[0])
    if any(_plan_facts(s) != facts for s in shards):
        raise HeirError("mixed-plans", "These shards come from different plans")
    indices = [s.index for s in shards]
    if len(set(indices)) != len(indices):
        raise HeirError("duplicate", "The same shard was added twice")
    return shards


def combine_packages(packages: Iterable[bytes]) -> bytes:
    """The recovery entropy from at least ``k`` packages of one plan, confirmed against the plan's check."""
    shards = check_shards(packages)
    k = shards[0].k
    if len(shards) < k:
        raise HeirError("need-more", f"{k - len(shards)} more shard(s) needed", missing=k - len(shards))
    entropy = sss.combine([s.share for s in shards])
    if not verify_entropy(shards[0], entropy):
        raise HeirError("check-failed", "These shards do not recover the owner's recovery phrase")
    return entropy


def shard_qr_text(package: bytes) -> str:
    """``lgkheir:`` + unpadded base64url of the package bytes; the package is verified first."""
    read_package(package)
    text = QR_PREFIX + base64.urlsafe_b64encode(bytes(package)).decode("ascii").rstrip("=")
    if len(text) > QR_LIMIT:
        raise HeirError("invalid", "This shard is too large for one QR code")
    return text


_QR_BODY = re.compile(r"[A-Za-z0-9_-]+")


def package_from_qr_text(text: str) -> bytes:
    """The package bytes from a scanned ``lgkheir:`` text (verified)."""
    if not isinstance(text, str) or not text.startswith(QR_PREFIX) or len(text) > QR_LIMIT:
        raise HeirError("malformed", "This QR code is not an emergency access shard")
    body = text[len(QR_PREFIX):]
    if not _QR_BODY.fullmatch(body):
        raise HeirError("malformed", "This QR code is not an emergency access shard")
    try:
        data = base64.urlsafe_b64decode(body + "=" * (-len(body) % 4))
    except (ValueError, binascii.Error):
        raise HeirError("malformed", "This QR code is not an emergency access shard") from None
    read_package(data)
    return data


# ------------------------------------------------------------------------------------------- the sheet
def _qr_path(text: str) -> tuple[int, str]:
    """The QR code (error correction M, 4-module border) as ``(size, svg path data)`` of 1-module runs."""
    import segno

    rows = [list(row) for row in segno.make(text, error="m", micro=False).matrix_iter(scale=1, border=4)]
    parts = []
    for y, row in enumerate(rows):
        x = 0
        while x < len(row):
            if not row[x]:
                x += 1
                continue
            start = x
            while x < len(row) and row[x]:
                x += 1
            parts.append(f"M{start} {y}h{x - start}v1h-{x - start}z")
    return len(rows), "".join(parts)


def sheet_facts(plan: HeirPlan, packages: Sequence[bytes]) -> dict[str, Any]:
    """What the printable shard sheet shows (``webui/src/components/HeirSheet.svelte``), one page per holder.

    The sheet is HTML printed by the browser with system fonts, like the emergency kit, so every script prints.
    Each page carries the holder's QR code as SVG path data (``qr_size`` modules square, border included).
    """
    shards = [read_package(data) for data in packages]
    if len(shards) != plan.n or sorted(s.index for s in shards) != list(range(1, plan.n + 1)) \
            or any(s.plan_id != plan.plan_id or s.signer != plan.signer for s in shards):
        raise HeirError("mixed-plans", "These shards are not the packages of this plan")
    pages = []
    for shard, package in sorted(zip(shards, packages, strict=True), key=lambda pair: pair[0].index):
        size, path = _qr_path(shard_qr_text(package))
        pages.append({"holder": shard.holder, "index": shard.index, "package_id": shard.package_id,
                      "qr_size": size, "qr_path": path})
    return {"owner": plan.owner, "plan_id": plan.plan_id, "k": plan.k, "n": plan.n, "wait_days": plan.wait_days,
            "created": datetime.fromtimestamp(plan.created, UTC).strftime("%Y-%m-%d"), "pages": pages}
