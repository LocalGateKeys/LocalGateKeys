"""Emergency access flows with no server (sub-plan 08, Task 3): request, deny, grant now, combine and restore.

Everything travels through one folder the owner shares with the holders (a cloud drive, a USB stick); nothing
in it is trusted.  Each plan has its own subfolder, ``<folder>/LocalGateKeys Emergency/<plan id>/``:

* ``request-<id>.lgkheirreq`` - a holder asks for access.  Signed by the requester's own Ed25519 key, it carries
  the requester's X25519 key (for "Grant now") and a *holder proof*: an HMAC with ``heir.holder_key`` of the
  holder's share over the plan id, request id, signer, X25519 key and time.  The owner's vault keeps the holder
  keys, so only requests by someone holding a shard of this plan are listed.
* ``deny-<id>.lgkheirdeny`` - the owner refuses (the veto).  Signed by the plan key (``heir.plan_signing_key``),
  which the shards name, so nobody else can write one.  A valid deny present when the requester combines wins,
  whatever its time says.  The owner's app remembers refused ids and writes a deny again if it goes missing.
* ``grant-<id>.lgkheirgrant`` - "Grant now": the recovery entropy wrapped to the request's X25519 key
  (ephemeral X25519, HKDF-SHA256, AES-256-GCM), signed by the plan key.  It skips the waiting period and the
  need for ``k`` shards; the requester still checks the entropy against the plan's HKDF check.
* ``backup-<time>-<rand>.lgk`` + ``.lgkheirbackup`` - the owner's full backup (format v3) locked to the plan's
  backup key (``heir.backup_private_key`` of the entropy, so only the recovered entropy opens it), and its
  descriptor signed by the plan key (file name, size, SHA-256, time written).  The newest two are kept.

Combining (``combine_and_restore``): the requester's newest request must exist and have no deny; then either a
grant for it, or ``k`` shards once the waiting period (from the request's time) is over.  The entropy is checked
with the plan's HKDF check before anything else uses it.  The backup must be newer than the plan ("no recent
backup" otherwise: Review Focus 2), match its signed digest and be locked to the backup key of this entropy.  It
is restored as a new profile opened with the recovery phrase, under the heir's new master password.

Limits: honest apps only (see ``heir.py``); the requester's clock decides the waiting period; anyone with write
access to the folder can delete files (a deleted request or grant only delays, a deleted deny is written again
by the owner's app on its next look).  Times: integer Unix seconds; ``LGK_HEIR_NOW`` overrides the clock for
tests and manual checks.
"""
from __future__ import annotations

import hashlib
import hmac
import math
import os
import re
import secrets
import shutil
import tempfile
import time
import uuid
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from . import envelope, heir, sss
from .secret_text import SecretText

__all__ = [
    "FOLDER_NAME", "NOW_ENV", "HeirFlowError", "RequesterIdentity", "Request", "Status", "BackupTarget",
    "plan_dir", "is_heir_file", "purge_backups", "request_access", "pending_requests", "deny", "grant_now", "backup_target",
    "write_backup", "backup_due", "backup_key_id", "request_status", "combine_and_restore",
]

FOLDER_NAME = "LocalGateKeys Emergency"
NOW_ENV = "LGK_HEIR_NOW"
DAY = 86400
REQUEST_SUFFIX = ".lgkheirreq"
DENY_SUFFIX = ".lgkheirdeny"
GRANT_SUFFIX = ".lgkheirgrant"
DESCRIPTOR_SUFFIX = ".lgkheirbackup"
BACKUP_SUFFIX = ".lgk"
HEIR_SUFFIXES = (".lgkheir", REQUEST_SUFFIX, DENY_SUFFIX, GRANT_SUFFIX, DESCRIPTOR_SUFFIX)
REQUEST_KIND, DENY_KIND, GRANT_KIND, BACKUP_KIND = "heir-request", "heir-deny", "heir-grant", "heir-backup"
MAX_FILE = 8192
MAX_SCAN = 512
#: Requests are all read and checked (signature, holder proof) up to this many well-named files, so junk
#: files with request names cannot push a real request out of a sorted cap; beyond it the owner is warned.
MAX_REQUEST_SCAN = 4096
KEEP_BACKUPS = 2
BACKUP_EVERY = DAY
PROOF_CONTEXT = b"LocalGateKeys heir request v1\n"
GRANT_INFO = b"LocalGateKeys heir grant v1\n"
IDENTITY_VERSION = 1
_BACKUP_NAME = re.compile(r"backup-\d{8}-\d{6}-[0-9a-f]{8}")
_UUID = r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"
#: The names each scan reads, checked before the ``MAX_SCAN`` cap so junk names cannot push real files out.
#: Denies and grants also match a provider's conflict copy of the name (" (1)", "-DESKTOP-ABC").
_REQUEST_NAME = re.compile(rf"request-{_UUID}\{REQUEST_SUFFIX}")
_DENY_NAME = re.compile(rf"deny-({_UUID})[ ()A-Za-z0-9_-]{{0,40}}\{DENY_SUFFIX}")
_GRANT_NAME = re.compile(rf"grant-({_UUID})[ ()A-Za-z0-9_-]{{0,40}}\{GRANT_SUFFIX}")
_DESCRIPTOR_NAME = re.compile(rf"backup-\d{{8}}-\d{{6}}-[0-9a-f]{{8}}\{DESCRIPTOR_SUFFIX}")
_REQUEST_FIELDS = {"kind", "plan_id", "holder_index", "box_public", "created", "proof"}
_DENY_FIELDS = {"kind", "plan_id", "request_id", "created"}
_GRANT_FIELDS = {"kind", "plan_id", "request_id", "box_public", "ephemeral", "wrapped", "created"}
_BACKUP_FIELDS = {"kind", "plan_id", "file", "size", "sha256", "written_at", "backup_public"}
_HEX64 = re.compile(r"[0-9a-f]{64}")

MESSAGES = {
    "no-folder": "The shared folder is not available.",
    "no-plan": "There is no emergency access plan.",
    "no-request": "Ask for access first.",
    "denied": "The owner denied this request.",
    "stale-plan": "The recovery phrase was replaced since this plan was made: re-issue the shards.",
    "no-backup": "No recent backup: the owner's app has not written a backup to this folder since the plan "
                 "was made.",
    "check-failed": "These shards do not recover the owner's recovery phrase.",
    "malformed": "This emergency access file is damaged.",
    "exists": "The new profile location already exists.",
    "wrong-phrase": "This is not the recovery phrase the plan was made from.",
}


class HeirFlowError(ValueError):
    """``reason``: ``no-folder``, ``no-plan``, ``no-request``, ``denied``, ``waiting`` (``days_left``),
    ``need-more`` (``missing``), ``no-backup``, ``check-failed``, ``stale-plan``, ``malformed``, ``exists``,
    ``mixed-plans`` or ``duplicate``."""

    def __init__(self, reason: str, message: str = "", *, missing: int = 0, days_left: int = 0) -> None:
        super().__init__(message or MESSAGES.get(reason, reason))
        self.reason = reason
        self.missing = missing
        self.days_left = days_left


def _need_more(missing: int) -> HeirFlowError:
    return HeirFlowError("need-more", f"You need {missing} more shard{'s' if missing != 1 else ''}.",
                         missing=missing)


def _waiting(days_left: int) -> HeirFlowError:
    return HeirFlowError("waiting", f"The waiting period is not over: {days_left} day(s) left.",
                         days_left=days_left)


def _from_heir(exc: heir.HeirError) -> HeirFlowError:
    if exc.reason == "need-more":
        return _need_more(exc.missing)
    reason = exc.reason if exc.reason in ("check-failed", "mixed-plans", "duplicate") else "malformed"
    return HeirFlowError(reason, str(exc))


def _clock(now: int | None = None) -> int:
    """``now`` when given, else ``LGK_HEIR_NOW`` in a developer install (a source run: tests and manual checks;
    never a frozen release build, where a requester could skip the waiting period with it), else the clock."""
    if now is not None:
        if type(now) is not int or now < 0:
            raise HeirFlowError("malformed", "A time is integer Unix seconds")
        return now
    from .config import is_developer_install

    override = os.environ.get(NOW_ENV, "").strip()
    if override.isdigit() and is_developer_install():
        return int(override)
    return int(time.time())


def _days_left(deadline: int, now: int) -> int:
    return max(0, math.ceil((deadline - now) / DAY))


# ------------------------------------------------------------------------------------------- the folder
def plan_dir(folder: Path | str, plan_id: str) -> Path:
    """``<folder>/LocalGateKeys Emergency/<plan id>``; the emergency folder or the plan folder itself also work."""
    plan_id = envelope.checked_id(plan_id)
    folder = Path(folder)
    if folder.name == plan_id and folder.parent.name == FOLDER_NAME:
        return folder
    if folder.name == FOLDER_NAME:
        return folder / plan_id
    return folder / FOLDER_NAME / plan_id


def _root(folder: Path | str | None) -> Path:
    """The chosen folder, which must exist: a disconnected drive never redirects files somewhere else."""
    if folder is None or not str(folder).strip():
        raise HeirFlowError("no-folder")
    root = Path(folder)
    try:
        if not root.is_dir():
            raise HeirFlowError("no-folder")
    except OSError:
        raise HeirFlowError("no-folder") from None
    return root


def _writable_plan_dir(folder: Path | str | None, plan_id: str) -> Path:
    directory = plan_dir(_root(folder), plan_id)
    try:
        directory.mkdir(parents=True, exist_ok=True)
    except OSError:
        raise HeirFlowError("no-folder") from None
    return directory


def is_heir_file(name: str) -> bool:
    """Whether a folder entry belongs to emergency access (the folder sync ignores these silently)."""
    if name == FOLDER_NAME or name.endswith(HEIR_SUFFIXES):
        return True
    return name.endswith(BACKUP_SUFFIX) and bool(_BACKUP_NAME.fullmatch(name[: -len(BACKUP_SUFFIX)]))


def _atomic_write(path: Path, data: bytes) -> None:
    fd, name = tempfile.mkstemp(prefix=".lgk-heir-", suffix=".tmp", dir=path.parent)
    temporary = Path(name)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    except OSError:
        temporary.unlink(missing_ok=True)
        raise HeirFlowError("no-folder") from None


def _read_small(path: Path, limit: int = MAX_FILE) -> bytes | None:
    try:
        if path.is_symlink() or not path.is_file() or path.stat().st_size > limit:
            return None
        with open(path, "rb") as handle:
            data = handle.read(limit + 1)
    except OSError:
        return None
    return data if len(data) <= limit else None


def _entries(directory: Path, pattern: re.Pattern[str], cap: int | None = None) -> list[Path]:
    """The folder's names that fully match ``pattern``, sorted, at most ``cap`` (``MAX_SCAN``)."""
    try:
        names = sorted(entry.name for entry in os.scandir(directory) if pattern.fullmatch(entry.name))
    except OSError:
        return []
    return [directory / name for name in names[:MAX_SCAN if cap is None else cap]]


def _flooded(directory: Path) -> bool:
    """More well-named request files than ``MAX_REQUEST_SCAN``: some may be unread (the owner is warned)."""
    try:
        return sum(1 for entry in os.scandir(directory) if _REQUEST_NAME.fullmatch(entry.name)) > MAX_REQUEST_SCAN
    except OSError:
        return False


def _open(data: bytes | None, kind: str, fields: set[str]) -> envelope.SignedEnvelope | None:
    """A signed heir file of ``kind`` with exactly ``fields``, or ``None`` (never raises)."""
    if data is None:
        return None
    try:
        opened = envelope.open_signed(data, heir.FORMAT, heir.VERSION, limit=MAX_FILE)
    except envelope.EnvelopeError:
        return None
    payload = opened.payload
    if set(payload) != fields or payload.get("kind") != kind:
        return None
    return opened


def _signed(fmt_payload: dict[str, Any], key: ed25519.Ed25519PrivateKey, *, sender: str = "",
            package_id: str | None = None) -> bytes:
    return envelope.seal_signed(heir.FORMAT, heir.VERSION, package_id=package_id or str(uuid.uuid4()),
                                sender=sender, payload=fmt_payload, signing_key=key)


def _time(value: Any) -> bool:
    return type(value) is int and 0 <= value <= 2**53 - 1


# ------------------------------------------------------------------------------------ the requester's keys
@dataclass(frozen=True)
class RequesterIdentity:
    """A requester's keys, kept in the requester's own (encrypted) vault: Ed25519 signs requests, X25519
    receives a grant."""

    signing_key: ed25519.Ed25519PrivateKey
    box_key: X25519PrivateKey

    @classmethod
    def generate(cls) -> RequesterIdentity:
        return cls(ed25519.Ed25519PrivateKey.generate(), X25519PrivateKey.generate())

    @property
    def signer(self) -> bytes:
        return self.signing_key.public_key().public_bytes_raw()

    @property
    def box_public(self) -> bytes:
        return self.box_key.public_key().public_bytes_raw()

    def to_record(self) -> dict[str, Any]:
        return {"version": IDENTITY_VERSION, "signing_key": envelope.b64e(self.signing_key.private_bytes_raw()),
                "box_key": envelope.b64e(self.box_key.private_bytes_raw())}

    @classmethod
    def from_record(cls, record: Any) -> RequesterIdentity:
        try:
            if not isinstance(record, dict) or set(record) != {"version", "signing_key", "box_key"} \
                    or record["version"] != IDENTITY_VERSION or type(record["version"]) is not int:
                raise HeirFlowError("malformed")
            return cls(ed25519.Ed25519PrivateKey.from_private_bytes(envelope.b64d(record["signing_key"], 32)),
                       X25519PrivateKey.from_private_bytes(envelope.b64d(record["box_key"], 32)))
        except (envelope.EnvelopeError, ValueError):
            raise HeirFlowError("malformed", "The stored emergency access keys are damaged") from None


# --------------------------------------------------------------------------------------------- requests
@dataclass(frozen=True)
class Request:
    request_id: str
    plan_id: str
    holder_index: int
    requester: str
    signer: bytes
    box_public: bytes
    created: int
    proof: bytes = field(repr=False)
    path: Path | None = None
    holder: str = ""
    days_left: int = 0
    denied: bool = False
    granted: bool = False


def _proof_message(*, plan_id: str, request_id: str, holder_index: int, signer: bytes, box_public: bytes,
                   created: int) -> bytes:
    return PROOF_CONTEXT + envelope.canonical({
        "plan_id": plan_id, "request_id": request_id, "holder_index": holder_index,
        "signer": envelope.b64e(signer), "box_public": envelope.b64e(box_public), "created": created})


def _proof(key: bytes, request: Request) -> bytes:
    return hmac.new(key, _proof_message(plan_id=request.plan_id, request_id=request.request_id,
                                        holder_index=request.holder_index, signer=request.signer,
                                        box_public=request.box_public, created=request.created),
                    hashlib.sha256).digest()


def _read_request(path: Path, plan_id: str) -> Request | None:
    opened = _open(_read_small(path), REQUEST_KIND, _REQUEST_FIELDS)
    if opened is None:
        return None
    p = opened.payload
    try:
        if p["plan_id"] != plan_id or type(p["holder_index"]) is not int \
                or not 1 <= p["holder_index"] <= sss.MAX_N or not _time(p["created"]):
            return None
        return Request(request_id=opened.id, plan_id=plan_id, holder_index=p["holder_index"],
                       requester=opened.sender, signer=opened.signer, box_public=envelope.b64d(p["box_public"], 32),
                       created=p["created"], proof=envelope.b64d(p["proof"], 32), path=path)
    except envelope.EnvelopeError:
        return None


def _requests(directory: Path, plan_id: str) -> list[Request]:
    found = [r for r in (_read_request(path, plan_id)
                         for path in _entries(directory, _REQUEST_NAME, MAX_REQUEST_SCAN)) if r]
    return sorted(found, key=lambda r: (r.created, r.request_id), reverse=True)


def request_access(folder: Path | str, shard: bytes, requester_identity: RequesterIdentity, *,
                   now: int | None = None) -> Path:
    """Write a signed access request for the plan of ``shard`` (a holder's package) into the shared folder."""
    try:
        holder_shard = heir.read_package(shard)
    except heir.HeirError as exc:
        raise _from_heir(exc) from None
    created = _clock(now)
    directory = _writable_plan_dir(folder, holder_shard.plan_id)
    request = Request(request_id=str(uuid.uuid4()), plan_id=holder_shard.plan_id,
                      holder_index=holder_shard.index, requester=holder_shard.holder,
                      signer=requester_identity.signer, box_public=requester_identity.box_public, created=created,
                      proof=b"")
    key = heir.holder_key(holder_shard.share, plan_id=holder_shard.plan_id, salt=holder_shard.check_salt)
    payload = {"kind": REQUEST_KIND, "plan_id": request.plan_id, "holder_index": request.holder_index,
               "box_public": envelope.b64e(request.box_public), "created": created,
               "proof": envelope.b64e(_proof(key, request))}
    data = _signed(payload, requester_identity.signing_key, sender=holder_shard.holder,
                   package_id=request.request_id)
    path = directory / f"request-{request.request_id}{REQUEST_SUFFIX}"
    _atomic_write(path, data)
    return path


# ------------------------------------------------------------------------------------ deny and grant files
def _valid_deny(path: Path, signer: bytes, plan_id: str) -> str | None:
    """The request id a deny file refuses, when it is a deny of this plan by the plan key."""
    opened = _open(_read_small(path), DENY_KIND, _DENY_FIELDS)
    if opened is None or not hmac.compare_digest(opened.signer, signer) or opened.payload["plan_id"] != plan_id:
        return None
    request_id = opened.payload["request_id"]
    return request_id if isinstance(request_id, str) else None


def _denials(directory: Path, signer: bytes, plan_id: str) -> set[str]:
    """Every request id refused by a valid deny in the folder (one read of each deny file)."""
    return {rid for rid in (_valid_deny(path, signer, plan_id) for path in _entries(directory, _DENY_NAME)) if rid}


def _deny_present(directory: Path, signer: bytes, plan_id: str, request_id: str) -> bool:
    """Any valid deny for this request, by the plan key, whatever its time (the veto).  The file under its own
    name is read first, so junk names in the folder cannot hide it."""
    if _valid_deny(directory / f"deny-{request_id}{DENY_SUFFIX}", signer, plan_id) == request_id:
        return True
    return request_id in _denials(directory, signer, plan_id)


def _grant_index(directory: Path, signer: bytes, plan_id: str) -> dict[tuple[str, str], list[envelope.SignedEnvelope]]:
    """(request id, recipient key) -> valid grants by the plan key (one read of each grant file)."""
    out: dict[tuple[str, str], list[envelope.SignedEnvelope]] = {}
    for path in _entries(directory, _GRANT_NAME):
        opened = _open(_read_small(path), GRANT_KIND, _GRANT_FIELDS)
        if opened is None or not hmac.compare_digest(opened.signer, signer) or opened.payload["plan_id"] != plan_id:
            continue
        p = opened.payload
        if isinstance(p["request_id"], str) and isinstance(p["box_public"], str):
            out.setdefault((p["request_id"], p["box_public"]), []).append(opened)
    return out


def _grants(directory: Path, signer: bytes, plan_id: str, request_id: str,
            box_public: bytes) -> list[envelope.SignedEnvelope]:
    return _grant_index(directory, signer, plan_id).get((request_id, envelope.b64e(box_public)), [])


def _grant_aad(plan_id: str, request_id: str, box_public: bytes) -> bytes:
    return GRANT_INFO + envelope.canonical({"plan_id": plan_id, "request_id": request_id,
                                            "box_public": envelope.b64e(box_public)})


def _grant_kek(shared: bytes, ephemeral: bytes, box_public: bytes, plan_id: str, request_id: str) -> bytes:
    info = GRANT_INFO + plan_id.encode("ascii") + b"\n" + request_id.encode("ascii")
    return HKDF(hashes.SHA256(), 32, ephemeral + box_public, info).derive(shared)


def _seal_grant(plan: heir.HeirPlan, key: ed25519.Ed25519PrivateKey, request: Request,
                entropy: bytes | bytearray, *, now: int | None = None) -> bytes:
    """The grant file: ``entropy`` wrapped to the request's X25519 key, signed by the plan key."""
    ephemeral = X25519PrivateKey.generate()
    epk = ephemeral.public_key().public_bytes_raw()
    shared = ephemeral.exchange(X25519PublicKey.from_public_bytes(request.box_public))
    kek = _grant_kek(shared, epk, request.box_public, plan.plan_id, request.request_id)
    wrapped = AESGCM(kek).encrypt(bytes(12), bytes(entropy),
                                  _grant_aad(plan.plan_id, request.request_id, request.box_public))
    payload = {"kind": GRANT_KIND, "plan_id": plan.plan_id, "request_id": request.request_id,
               "box_public": envelope.b64e(request.box_public), "ephemeral": envelope.b64e(epk),
               "wrapped": envelope.b64e(wrapped), "created": _clock(now)}
    return _signed(payload, key)


def _open_grant(grant: envelope.SignedEnvelope, identity: RequesterIdentity) -> bytearray | None:
    p = grant.payload
    try:
        epk = envelope.b64d(p["ephemeral"], 32)
        wrapped = envelope.b64d(p["wrapped"], 48)
        shared = identity.box_key.exchange(X25519PublicKey.from_public_bytes(epk))
        kek = _grant_kek(shared, epk, identity.box_public, p["plan_id"], p["request_id"])
        return bytearray(AESGCM(kek).decrypt(bytes(12), wrapped,
                                             _grant_aad(p["plan_id"], p["request_id"], identity.box_public)))
    except (envelope.EnvelopeError, InvalidTag, ValueError):
        return None


# ------------------------------------------------------------------------------------------ owner's side
def _material(session: Any) -> tuple[heir.HeirPlan, ed25519.Ed25519PrivateKey, tuple[bytes, ...]]:
    try:
        material = heir.owner_material(session)
    except heir.HeirError as exc:
        raise HeirFlowError("malformed", str(exc)) from None
    if material is None:
        raise HeirFlowError("no-plan")
    return material


def _verified(request: Request, plan: heir.HeirPlan, holder_keys: Sequence[bytes]) -> bool:
    if request.plan_id != plan.plan_id or not 1 <= request.holder_index <= plan.n:
        return False
    return hmac.compare_digest(_proof(holder_keys[request.holder_index - 1], request), request.proof)


def _write_deny(directory: Path, plan: heir.HeirPlan, key: ed25519.Ed25519PrivateKey, request_id: str,
                now: int) -> Path:
    payload = {"kind": DENY_KIND, "plan_id": plan.plan_id, "request_id": request_id, "created": now}
    path = directory / f"deny-{request_id}{DENY_SUFFIX}"
    _atomic_write(path, _signed(payload, key))
    return path


def pending_requests(session: Any, folder: Path | str | None = None, *, now: int | None = None) -> list[Request]:
    """The owner's open requests (newest first): only those that prove a shard of this plan, not denied.

    A request the owner refused whose deny file is missing gets it written again (best effort).
    """
    material = heir.owner_material(session)
    if material is None:
        return []
    return pending_for(material, folder, now=now)


class Pending(list):
    """``pending_for`` result: the open requests, plus ``flooded`` (too many request files to read them all)."""

    flooded: bool = False


def pending_for(material: tuple[heir.HeirPlan, ed25519.Ed25519PrivateKey, tuple[bytes, ...]],
                folder: Path | str | None = None, *, now: int | None = None) -> Pending:
    """``pending_requests`` from the plan material taken on the vault's thread (for a worker thread)."""
    plan, key, holder_keys = material
    folder = folder if folder is not None else plan.folder
    if folder is None:
        return Pending()
    try:
        directory = plan_dir(_root(folder), plan.plan_id)
    except HeirFlowError:
        return Pending()
    if plan.stale:
        purge_backups(directory)  # the replaced phrase's backups: old shards must find nothing to open
    current = _clock(now)
    denials = _denials(directory, plan.signer, plan.plan_id)
    grants = _grant_index(directory, plan.signer, plan.plan_id)
    out = Pending()
    out.flooded = _flooded(directory)
    for request in _requests(directory, plan.plan_id):
        if not _verified(request, plan, holder_keys):
            continue
        if request.request_id in denials:
            continue
        if request.request_id in plan.denied:
            try:
                _write_deny(directory, plan, key, request.request_id, current)
            except HeirFlowError:
                pass  # the folder is read-only or gone: the next look tries again
            continue
        granted = (request.request_id, envelope.b64e(request.box_public)) in grants
        out.append(Request(**{**request.__dict__, "holder": plan.holders[request.holder_index - 1].nickname,
                              "days_left": _days_left(request.created + plan.wait_days * DAY, current),
                              "granted": granted}))
    return out


def _find_request(session: Any, request: Request) -> tuple[heir.HeirPlan, ed25519.Ed25519PrivateKey, Path,
                                                            Request]:
    """The request as it is in the folder now, re-verified (never the caller's copy)."""
    plan, key, holder_keys = _material(session)
    if plan.folder is None:
        raise HeirFlowError("no-folder")
    directory = _writable_plan_dir(plan.folder, plan.plan_id)
    request_id = envelope.checked_id(request.request_id)
    for found in _requests(directory, plan.plan_id):
        if found.request_id == request_id and _verified(found, plan, holder_keys):
            return plan, key, directory, found
    raise HeirFlowError("no-request", "This request is no longer in the shared folder.")


def deny(session: Any, request: Request, *, now: int | None = None) -> Path:
    """Refuse a request: a deny file signed by the plan key, remembered in the vault (written again if lost)."""
    plan, key, _holder_keys = _material(session)
    if request.plan_id != plan.plan_id:
        raise HeirFlowError("malformed", "This request is for another plan.")
    request_id = envelope.checked_id(request.request_id)
    directory = _writable_plan_dir(plan.folder, plan.plan_id)
    heir.add_denied(session, request_id)
    return _write_deny(directory, plan, key, request_id, _clock(now))


def grant_now(session: Any, request: Request, *, phrase: str | None,
              reauthenticate: Callable[[], bool] | None, now: int | None = None) -> Path:
    """Give access before the waiting period ends: the entropy wrapped to the requester's X25519 key.

    Order: the request (still in the folder, proving a shard), not denied, plan current, then
    re-authentication and the typed phrase, and the plan's entropy check.  On the device that made the plan
    ``session.recovery_entropy`` also checks the phrase against this vault; on another of the owner's devices
    (the plan arrived by sync, and its vault may have a phrase of its own) the plan's check alone decides.
    """
    plan, key, directory, found = _find_request(session, request)
    if found.request_id in plan.denied or _deny_present(directory, plan.signer, plan.plan_id, found.request_id):
        raise HeirFlowError("denied")
    if plan.stale:
        raise HeirFlowError("stale-plan")
    if plan.home:
        entropy = bytearray(session.recovery_entropy(phrase, reauthenticate=reauthenticate))
    else:
        from .vault import entropy_from_phrase

        if reauthenticate is None or reauthenticate() is not True:
            raise PermissionError("Not authorized")
        entropy = bytearray(entropy_from_phrase(phrase or ""))
    try:
        if not heir.verify_entropy(plan, entropy):
            raise HeirFlowError("stale-plan" if plan.home else "wrong-phrase")
        data = _seal_grant(plan, key, found, entropy, now=now)
    finally:
        entropy[:] = bytes(len(entropy))
    path = directory / f"grant-{found.request_id}{GRANT_SUFFIX}"
    _atomic_write(path, data)
    return path


# ------------------------------------------------------------------------------------- owner's backups
@dataclass(frozen=True)
class BackupTarget:
    """What a backup worker needs (no session): taken on the vault's thread, used on a worker thread."""

    folder: Path
    plan_id: str
    created: int
    backup_public: bytes
    signing_key: ed25519.Ed25519PrivateKey = field(repr=False)


def backup_target(session: Any) -> BackupTarget | None:
    """The current plan's backup target; ``None`` without a plan or a folder, with a stale plan, or on a device
    that received the plan by sync (its vault opens with its own phrase, not the plan's)."""
    try:
        material = heir.owner_material(session)
    except heir.HeirError:
        return None
    if material is None:
        return None
    plan, key, _holder_keys = material
    if plan.stale or not plan.home or plan.folder is None or len(plan.backup_public) != 32:
        return None
    return BackupTarget(plan.folder, plan.plan_id, plan.created, plan.backup_public, key)


def _key_id(public: bytes) -> str:
    from .backup_key import key_id

    return key_id(public)


def backup_key_id(plan: heir.HeirPlan) -> str:
    """The v3 recipient ``key_id`` of the heir folder's backups of ``plan``."""
    return _key_id(plan.backup_public)


def _backup_record(target: BackupTarget) -> dict[str, Any]:
    """A public backup key record (``backup_key`` 3.3) for the plan's backup key: the v3 writer wraps to it.

    No password derives this key (the entropy does), so its ``kdf`` only satisfies the record shape.
    """
    from .backup_key import new_kdf, validate_record

    salt = hashlib.sha256(b"LocalGateKeys heir backup record v1\n" + target.backup_public).digest()[:16]
    return validate_record({"v": 1, "key_id": _key_id(target.backup_public),
                            "public_key": envelope.b64e(target.backup_public), "kdf": new_kdf(salt=salt),
                            "set_at": target.created, "set_by": "set", "reset_at": None,
                            "reset_authority": None, "history": []})


@dataclass(frozen=True)
class _Backup:
    path: Path
    descriptor: Path
    size: int
    sha256: str
    written_at: int
    backup_public: bytes


def _backups(directory: Path, signer: bytes, plan_id: str) -> list[_Backup]:
    """Valid descriptors by the plan key, newest first."""
    out = []
    for path in _entries(directory, _DESCRIPTOR_NAME):
        opened = _open(_read_small(path), BACKUP_KIND, _BACKUP_FIELDS)
        if opened is None or not hmac.compare_digest(opened.signer, signer):
            continue
        p = opened.payload
        name = p["file"]
        if p["plan_id"] != plan_id or not isinstance(name, str) or not name.endswith(BACKUP_SUFFIX) \
                or not _BACKUP_NAME.fullmatch(name[: -len(BACKUP_SUFFIX)]) or not _time(p["written_at"]) \
                or type(p["size"]) is not int or p["size"] <= 0 or not isinstance(p["sha256"], str) \
                or not _HEX64.fullmatch(p["sha256"]):
            continue
        try:
            public = envelope.b64d(p["backup_public"], 32)
        except envelope.EnvelopeError:
            continue
        out.append(_Backup(directory / name, path, p["size"], p["sha256"], p["written_at"], public))
    return sorted(out, key=lambda b: (b.written_at, b.path.name), reverse=True)


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def write_backup(target: BackupTarget, *, profile_dir: Path | str, profile_name: str | None = None,
                 now: int | None = None) -> Path:
    """Write a full backup (v3) of the profile locked to the plan's backup key, and its signed descriptor.

    The file is verified as the scheduled backups are (structure, key wrap, restore dry run) before the
    descriptor is written; the newest ``KEEP_BACKUPS`` stay.
    """
    from .backup import export_full_backup_to_key

    written_at = _clock(now)
    directory = _writable_plan_dir(target.folder, target.plan_id)
    stem = f"backup-{time.strftime('%Y%m%d-%H%M%S', time.gmtime(written_at))}-{secrets.token_hex(4)}"
    path = directory / f"{stem}{BACKUP_SUFFIX}"
    record = _backup_record(target)
    result = export_full_backup_to_key(path, record=record, profile_dir=Path(profile_dir),
                                       profile_name=profile_name)
    try:
        with result["verifier"] as verifier:
            checked = verifier.verify(path, record=record)
        payload = {"kind": BACKUP_KIND, "plan_id": target.plan_id, "file": path.name, "size": path.stat().st_size,
                   "sha256": checked["sha256"], "written_at": written_at,
                   "backup_public": envelope.b64e(target.backup_public)}
        _atomic_write(directory / f"{stem}{DESCRIPTOR_SUFFIX}", _signed(payload, target.signing_key))
    except BaseException:
        path.unlink(missing_ok=True)
        raise
    signer = target.signing_key.public_key().public_bytes_raw()
    for old in _backups(directory, signer, target.plan_id)[KEEP_BACKUPS:]:
        for stale in (old.path, old.descriptor):
            try:
                stale.unlink(missing_ok=True)
            except OSError:
                pass
    return path


def purge_backups(directory: Path) -> int:
    """Delete every backup file and descriptor in a plan's folder (best effort; the number deleted).

    Run on each look at a stale plan: the backups there are locked to the replaced phrase, so once they are gone
    the plan's old shards have nothing left to open (``LGKHEIR_V1.md`` "Stale plans").
    """
    try:
        names = [entry.name for entry in os.scandir(directory)]
    except OSError:
        return 0
    removed = 0
    for name in names:
        backup = name.endswith(BACKUP_SUFFIX) and _BACKUP_NAME.fullmatch(name[: -len(BACKUP_SUFFIX)])
        if backup or _DESCRIPTOR_NAME.fullmatch(name):
            try:
                (directory / name).unlink()
                removed += 1
            except OSError:
                pass  # read-only or locked: the next look tries again
    return removed


def backup_due(target: BackupTarget, *, now: int | None = None, every: int = BACKUP_EVERY) -> bool:
    """Whether the heir folder lacks a backup written within ``every`` seconds (a missing folder: not due)."""
    try:
        directory = plan_dir(_root(target.folder), target.plan_id)
    except HeirFlowError:
        return False
    signer = target.signing_key.public_key().public_bytes_raw()
    newest = _backups(directory, signer, target.plan_id)
    return not newest or abs(_clock(now) - newest[0].written_at) >= every


# ------------------------------------------------------------------------------------- requester's side
@dataclass(frozen=True)
class Status:
    """What the requester's screen says: ``none`` (ask first), ``denied``, ``need-more`` (``missing``),
    ``waiting`` (``days_left``), ``no-backup`` or ``ready``."""

    state: str
    plan_id: str = ""
    owner: str = ""
    k: int = 0
    have: int = 0
    request_id: str = ""
    days_left: int = 0
    missing: int = 0
    granted: bool = False


@dataclass
class _Evaluation:
    status: Status
    shards: list[heir.Shard]
    directory: Path
    request: Request | None = None
    grant: envelope.SignedEnvelope | None = None


def _evaluate(folder: Path | str, packages: Sequence[bytes], identity: RequesterIdentity,
              now: int | None) -> _Evaluation:
    try:
        shards = heir.check_shards(packages)
    except heir.HeirError as exc:
        raise _from_heir(exc) from None
    base = shards[0]
    directory = plan_dir(_root(folder), base.plan_id)
    current = _clock(now)
    facts = {"plan_id": base.plan_id, "owner": base.owner, "k": base.k, "have": len(shards)}
    mine = [r for r in _requests(directory, base.plan_id)
            if hmac.compare_digest(r.signer, identity.signer) and hmac.compare_digest(r.box_public,
                                                                                      identity.box_public)]
    if not mine:
        return _Evaluation(Status("none", **facts), shards, directory)
    request = mine[0]  # the newest: a refused request stays refused, a new one starts its own wait
    facts["request_id"] = request.request_id
    if _deny_present(directory, base.signer, base.plan_id, request.request_id):
        return _Evaluation(Status("denied", **facts), shards, directory, request)
    grants = _grants(directory, base.signer, base.plan_id, request.request_id, identity.box_public)
    grant = grants[0] if grants else None
    if grant is None:
        if len(shards) < base.k:
            return _Evaluation(Status("need-more", missing=base.k - len(shards), **facts), shards, directory,
                               request)
        left = _days_left(request.created + base.wait_days * DAY, current)
        if left > 0:
            return _Evaluation(Status("waiting", days_left=left, **facts), shards, directory, request)
    if not any(b.written_at >= base.created for b in _backups(directory, base.signer, base.plan_id)):
        return _Evaluation(Status("no-backup", granted=grant is not None, **facts), shards, directory, request,
                           grant)
    return _Evaluation(Status("ready", granted=grant is not None, **facts), shards, directory, request, grant)


def request_status(folder: Path | str, shards: Sequence[bytes], requester_identity: RequesterIdentity, *,
                   now: int | None = None) -> Status:
    """Where the requester stands (reads the folder; recovers nothing)."""
    return _evaluate(folder, shards, requester_identity, now).status


def _backup_header(path: Path) -> tuple[bytes, Any]:
    from .backup import _v3_read_header_only

    return _v3_read_header_only(path)


def _open_backup(directory: Path, base: heir.Shard, entropy: bytes | bytearray,
                 private: Path) -> tuple[Path, bytearray]:
    """A private copy of the newest usable backup (newer than the plan, as signed, locked to this entropy's
    backup key) and its data key; else ``no-backup``."""
    from .backup import MAX_FULL_BACKUP_BYTES, BackupError, _v3_parse_header
    from .backup_key import BackupKeyError, unwrap_data_key

    expected = heir.backup_public_key(entropy, plan_id=base.plan_id, salt=base.check_salt)
    for index, candidate in enumerate(_backups(directory, base.signer, base.plan_id)):
        if candidate.written_at < base.created or not hmac.compare_digest(candidate.backup_public, expected) \
                or candidate.size > MAX_FULL_BACKUP_BYTES:
            continue
        copy = private / f"heir-backup-{index}.lgk"
        try:
            if candidate.path.is_symlink() or not candidate.path.is_file():
                continue
            with open(candidate.path, "rb") as reader, open(copy, "wb") as writer:
                shutil.copyfileobj(reader, writer, 1024 * 1024)
            if copy.stat().st_size != candidate.size \
                    or not hmac.compare_digest(_sha256_file(copy), candidate.sha256):
                continue
            header_data, header = _backup_header(copy)
            parsed = _v3_parse_header(header_data, header)
            if parsed.recipient["key_id"] != _key_id(expected):
                continue
            private_key = heir.backup_private_key(entropy, plan_id=base.plan_id, salt=base.check_salt)
            try:
                data_key = unwrap_data_key(private_key, parsed.ephemeral_public, parsed.wrapped, parsed.wrap_aad())
            finally:
                private_key[:] = bytes(len(private_key))
            return copy, data_key
        except (OSError, BackupError, BackupKeyError, ValueError):
            continue
    raise HeirFlowError("no-backup")


def _heirs_copy(stage: Path, new_password: str | SecretText) -> None:
    """Make the restored profile the heir's: no owner's plan (and plan key) in it.  Its trust state is switched
    off as it is published (``recovery._sanitize_restored_profile`` in ``combine_and_restore``)."""
    from .vault import unlock_vault

    session = unlock_vault(stage / "vault.json", new_password)
    try:
        if session.heir_plan_record() is not None:
            session.set_heir_plan_record(None)
    finally:
        session.lock()


def _remove_my_requests(directory: Path, plan_id: str, identity: RequesterIdentity) -> None:
    """After a restore, delete this requester's own requests so the owner's devices stop listing a used request
    (best effort: a request left behind only keeps showing)."""
    for request in _requests(directory, plan_id):
        if hmac.compare_digest(request.signer, identity.signer) and request.path is not None:
            try:
                request.path.unlink()
            except OSError:
                pass


def combine_and_restore(folder: Path | str, shards: Sequence[bytes], requester_identity: RequesterIdentity, *,
                        destination: Path | str, new_password: str | SecretText, now: int | None = None) -> Path:
    """Recover the entropy (a grant, or ``k`` shards after the waiting period), check it, and restore the owner's
    newest backup as a new profile at ``destination`` under ``new_password``.  Returns ``destination``.

    Refused with ``HeirFlowError``: ``no-request``, ``denied`` (checked again just before the profile is
    published), ``need-more``, ``waiting``, ``check-failed``, ``no-backup``.
    """
    from .backup import BackupError, private_temporary_directory, restore_full_backup
    from .recovery import _sanitize_restored_profile
    from .vault import phrase_from_entropy

    destination = Path(destination)
    if destination.exists():
        raise HeirFlowError("exists")
    evaluation = _evaluate(folder, shards, requester_identity, now)
    status = evaluation.status
    if status.state == "none":
        raise HeirFlowError("no-request")
    if status.state == "denied":
        raise HeirFlowError("denied")
    if status.state == "need-more":
        raise _need_more(status.missing)
    if status.state == "waiting":
        raise _waiting(status.days_left)
    base, directory, request = evaluation.shards[0], evaluation.directory, evaluation.request
    if request is None:
        raise HeirFlowError("no-request")

    def vetoed() -> None:
        if _deny_present(directory, base.signer, base.plan_id, request.request_id):
            raise HeirFlowError("denied")

    if evaluation.grant is not None:
        opened = _open_grant(evaluation.grant, requester_identity)
        if opened is None:
            raise HeirFlowError("malformed", "The owner's grant does not open with this app's keys.")
        entropy = opened
    else:
        try:
            entropy = bytearray(heir.combine_packages(shards))
        except heir.HeirError as exc:
            raise _from_heir(exc) from None
    try:
        # The recovered secret is checked against the plan's HKDF check before anything uses it.
        if not heir.verify_entropy(base, entropy):
            raise HeirFlowError("check-failed")
        with private_temporary_directory("lgk-heir-restore-") as private:
            copy, data_key = _open_backup(directory, base, entropy, Path(private))
            stage = destination.parent / f".lgk-heir-restore-{uuid.uuid4().hex}"
            published = False

            def publish() -> Path:
                nonlocal published
                vetoed()
                if destination.exists():
                    raise HeirFlowError("exists")
                os.rename(stage, destination)
                published = True
                return destination / "vault.json"

            try:
                vetoed()
                # A staging folder: the profile's rollback marks are set where it ends up (``publish``).
                restore_full_backup(copy, profile_dir=stage, backup_password=None, vault_password=new_password,
                                    recovery_phrase=phrase_from_entropy(bytes(entropy)), _data_key=data_key,
                                    replace=False, _heir_restore=True, _mark_destination=False)
                _heirs_copy(stage, new_password)
                # Trust state off, then (unless a deny landed meanwhile) into place, marked there.
                _sanitize_restored_profile(stage, new_password, publish=publish)
                _remove_my_requests(directory, base.plan_id, requester_identity)
            except BackupError as exc:
                raise HeirFlowError("no-backup", str(exc)) from None
            finally:
                data_key[:] = bytes(len(data_key))
                if not published:
                    shutil.rmtree(stage, ignore_errors=True)
    finally:
        entropy[:] = bytes(len(entropy))
    return destination
