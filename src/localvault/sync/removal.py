"""Signed removal notices: how a device removed from a cloud-folder group learns it for certain.

Design: ``docs/design/security-2026-10-30/wp-a-design.md``.  The existing "maybe removed" issues
(``removed-or-conflict``, ``rejoin-required``...) are inferences anyone with the group key or folder
access can cause, so nothing ever erases on them.  A notice is signed by the member that removed the
device, with the member signing key the removed device already trusted (``signing_public`` in the
keyring it accepted before the removal); only a verified notice may lead to an erase.

Notice (``LocalGateKeys Sync/removed/<device id>.lgkremoved``, canonical JSON, at most 4 KiB)::

    {"format":1,"group_id","device_id","epoch","signer","issued_at","sig"}

``sig`` is standard base64 of the Ed25519 signature over ``NOTICE_LABEL + canonical_json(body)``
(the notice without ``sig``).  ``epoch`` is the epoch the removal created.  Older builds and the
Mac/iPhone/Android apps never list ``removed/``, so they ignore it.

A notice is accepted (``verify_notice``) only when it names this device and group, its epoch is above
the trusted one, the signer is another member of the trusted keyring with a signing key and the
signature verifies, and the folder's current keyring is of this group, at the notice's epoch or later,
and does not list this device.

Watch file (``<vault>.sync-watch.json`` next to the vault, plain JSON): the trusted group id, device
id, epoch, install id, folder and the member signing keys of the trusted keyring, so the app can check
for a notice while the vault is locked.  It is written from the trusted sync state on every folder
run and deleted when the vault leaves or resets sync.  Someone who can edit it could only stop an
erase (or already delete the vault file itself).
"""
from __future__ import annotations

import base64
import binascii
import contextlib
import json
import os
import time
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import ed25519

from ..updates import canonical_json
from .engine import is_valid_id
from .keyring import KeyringError, member_signing_keys, parse_keyring

NOTICE_FORMAT = 1
NOTICE_LABEL = b"localgatekeys|sync|removal-notice|v1|"
REMOVED_DIR_NAME = "removed"
NOTICE_SUFFIX = ".lgkremoved"
MAX_NOTICE_BYTES = 4096
WATCH_VERSION = 1
WATCH_SUFFIX = ".sync-watch.json"
MAX_WATCH_BYTES = 16 * 1024
# The folder layout of folder_transport (not imported: that module imports this one).
_SYNC_DIR_NAME = "LocalGateKeys Sync"
_KEYRING_NAME = "keyring.lgkkeys"
_MAX_KEYRING_BYTES = 256 * 1024
_MAX_INT = 2**53 - 1
_NOTICE_FIELDS = frozenset({"format", "group_id", "device_id", "epoch", "signer", "issued_at", "sig"})
_WATCH_FIELDS = frozenset({"version", "group_id", "device_id", "epoch", "install_id", "folder", "signers"})


class RemovalError(Exception):
    """A notice or watch file that is not accepted; ``reason`` is a stable code."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


@dataclass(frozen=True)
class Notice:
    group_id: str
    device_id: str
    epoch: int
    signer: str
    issued_at: int


@dataclass(frozen=True)
class Watch:
    group_id: str
    device_id: str
    epoch: int
    install_id: str
    folder: str
    signers: Mapping[str, str]

    def to_dict(self) -> dict[str, Any]:
        return {"version": WATCH_VERSION, "group_id": self.group_id, "device_id": self.device_id,
                "epoch": self.epoch, "install_id": self.install_id, "folder": self.folder,
                "signers": dict(sorted(self.signers.items()))}


def _is_int(value: object) -> bool:
    return type(value) is int and 0 <= value <= _MAX_INT


def _loads(raw: bytes) -> object:
    def pairs(items: list[tuple[str, object]]) -> dict:
        out: dict = {}
        for key, value in items:
            if key in out:
                raise ValueError("duplicate key")
            out[key] = value
        return out

    def constant(name: str) -> object:
        raise ValueError(name)

    return json.loads(raw.decode("utf-8"), object_pairs_hook=pairs, parse_constant=constant)


def _key(value: object) -> ed25519.Ed25519PublicKey:
    if not isinstance(value, str):
        raise RemovalError("bad-key")
    try:
        raw = base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise RemovalError("bad-key") from exc
    if len(raw) != 32 or base64.b64encode(raw).decode("ascii") != value:
        raise RemovalError("bad-key")
    return ed25519.Ed25519PublicKey.from_public_bytes(raw)


# --- notice -------------------------------------------------------------------------------------------

def notice_name(device_id: str) -> str:
    return f"{device_id}{NOTICE_SUFFIX}"


def make_notice(signing_key: ed25519.Ed25519PrivateKey, *, group_id: str, device_id: str, epoch: int,
                signer: str, now: int | None = None) -> bytes:
    """The notice bytes that *signer* removed *device_id* from *group_id* at *epoch*."""
    issued = int(time.time()) if now is None else int(now)
    body = {"format": NOTICE_FORMAT, "group_id": group_id, "device_id": device_id, "epoch": epoch,
            "signer": signer, "issued_at": issued}
    if (not all(is_valid_id(v) for v in (group_id, device_id, signer)) or not _is_int(epoch)
            or not _is_int(issued) or signer == device_id):
        raise RemovalError("bad-notice")
    sig = signing_key.sign(NOTICE_LABEL + canonical_json(body))
    return canonical_json({**body, "sig": base64.b64encode(sig).decode("ascii")})


def parse_notice(raw: bytes) -> tuple[Notice, bytes, bytes]:
    """(notice, signed message, signature); raises ``RemovalError("bad-notice")``."""
    if not isinstance(raw, bytes) or len(raw) > MAX_NOTICE_BYTES:
        raise RemovalError("bad-notice")
    try:
        doc = _loads(raw)
    except (ValueError, UnicodeDecodeError, RecursionError) as exc:
        raise RemovalError("bad-notice") from exc
    if not isinstance(doc, dict) or set(doc) != _NOTICE_FIELDS:
        raise RemovalError("bad-notice")
    if (doc["format"] != NOTICE_FORMAT or type(doc["format"]) is not int
            or not all(is_valid_id(doc[k]) for k in ("group_id", "device_id", "signer"))
            or not _is_int(doc["epoch"]) or not _is_int(doc["issued_at"]) or not isinstance(doc["sig"], str)):
        raise RemovalError("bad-notice")
    try:
        sig = base64.b64decode(doc["sig"], validate=True)
    except (binascii.Error, ValueError) as exc:
        raise RemovalError("bad-notice") from exc
    if len(sig) != 64 or base64.b64encode(sig).decode("ascii") != doc["sig"]:
        raise RemovalError("bad-notice")
    body = {k: v for k, v in doc.items() if k != "sig"}
    notice = Notice(doc["group_id"], doc["device_id"], doc["epoch"], doc["signer"], doc["issued_at"])
    return notice, NOTICE_LABEL + canonical_json(body), sig


def _ring_members(raw: bytes) -> tuple[str, int, set[str]]:
    """(group id, epoch, member ids) of a keyring, without authenticating it."""
    ring = parse_keyring(raw)
    group, epoch, members = ring.get("group_id"), ring.get("epoch"), ring.get("members")
    if not is_valid_id(group) or not _is_int(epoch) or not isinstance(members, list):
        raise RemovalError("keyring")
    # Entries that are not objects with a text device id are ignored (an unhashable id must not raise).
    return group, epoch, {m["device_id"] for m in members
                          if isinstance(m, Mapping) and isinstance(m.get("device_id"), str)}


def verify_notice(raw: bytes, watch: Watch, folder_keyring: bytes) -> Notice:
    """The notice *raw* if it proves that *watch*'s device was removed; else ``RemovalError``.

    *folder_keyring*: the bytes of the folder's current keyring (corroboration, see module docstring).
    """
    notice, message, sig = parse_notice(raw)
    if notice.group_id != watch.group_id or notice.device_id != watch.device_id:
        raise RemovalError("not-for-this-device")
    if notice.signer == watch.device_id or notice.epoch <= watch.epoch:
        raise RemovalError("stale")
    key = watch.signers.get(notice.signer)
    if key is None:
        raise RemovalError("unknown-signer")
    try:
        _key(key).verify(sig, message)
    except InvalidSignature as exc:
        raise RemovalError("bad-signature") from exc
    try:
        group, epoch, members = _ring_members(folder_keyring)
    except KeyringError as exc:
        raise RemovalError("keyring") from exc
    if group != watch.group_id or epoch < notice.epoch or watch.device_id in members:
        raise RemovalError("keyring")
    return notice


# --- watch file ---------------------------------------------------------------------------------------

def watch_path(vault_path: Path | str) -> Path:
    path = Path(vault_path)
    return path.with_name(path.stem + WATCH_SUFFIX)


def watch_from_state(state: Any, folder: Path | str) -> Watch | None:
    """The watch for a folder member's trusted *state* (``SyncGroupState``); None without a keyring.

    Signers are the members of the trusted keyring with a signing key, except this device and the
    members the user has not confirmed yet (``unacked_members``: anyone with the sync password can
    add one, with a key of their choosing).
    """
    if state is None or state.keyring is None or not isinstance(state.install_id, str):
        return None
    try:
        keys = member_signing_keys(parse_keyring(state.keyring))
    except KeyringError:
        return None
    unconfirmed = set(getattr(state, "unacked_members", ()) or ())
    signers = {d: k for d, k in keys.items() if d != state.device_id and d not in unconfirmed and is_valid_id(d)}
    return Watch(state.group_id, state.device_id, state.epoch, state.install_id, str(folder), signers)


def pinned(fresh: Watch, old: Watch | None) -> Watch:
    """*fresh* with each signer's key pinned to the one *old* (the stored watch) already had.

    Anyone with the group key can rewrite the keyring at the same epoch, including a member's
    ``signing_public`` (the proof is signed by the new key itself).  A device never changes its key
    (re-joining makes a new device id), so the first key seen for a member stays the one a notice
    must carry; members gone from the trusted keyring are dropped.
    """
    if old is None or (old.group_id, old.device_id) != (fresh.group_id, fresh.device_id):
        return fresh
    signers = {d: old.signers.get(d, k) for d, k in fresh.signers.items()}
    return Watch(fresh.group_id, fresh.device_id, fresh.epoch, fresh.install_id, fresh.folder, signers)


def refresh_watch(path: Path | None, fresh: Watch) -> Watch:
    """Store *fresh* (pinned against the watch at *path*) and return what was stored; never raises."""
    if path is None:
        return fresh
    watch = pinned(fresh, load_watch(path))
    save_watch(path, watch)
    return watch


def save_watch(path: Path, watch: Watch) -> bool:
    """Write *watch* unless the file already holds it; never raises (returns whether it was written)."""
    data = canonical_json(watch.to_dict())
    tmp = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    try:
        if path.is_file() and path.read_bytes() == data:
            return False
        with open(tmp, "wb") as fh:
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, path)
    except OSError:
        with contextlib.suppress(OSError):
            tmp.unlink()
        return False
    return True


def forget_watch(path: Path) -> None:
    with contextlib.suppress(OSError):
        path.unlink()


def forget_session_watch(session: Any) -> None:
    """Delete the watch file of *session*'s vault (it leaves or resets sync); never raises."""
    path = getattr(session, "path", None)
    if isinstance(path, (str, os.PathLike)):
        forget_watch(watch_path(path))


def load_watch(path: Path) -> Watch | None:
    """The watch file at *path*, or None when it is missing or not valid."""
    try:
        with open(path, "rb") as fh:
            raw = fh.read(MAX_WATCH_BYTES + 1)
        doc = _loads(raw) if len(raw) <= MAX_WATCH_BYTES else None
    except (OSError, ValueError, UnicodeDecodeError, RecursionError):
        return None
    if (not isinstance(doc, dict) or set(doc) != _WATCH_FIELDS or type(doc["version"]) is not int
            or doc["version"] != WATCH_VERSION):
        return None
    signers = doc["signers"]
    if (not is_valid_id(doc["group_id"]) or not is_valid_id(doc["device_id"]) or not _is_int(doc["epoch"])
            or not isinstance(doc["install_id"], str) or not doc["install_id"]
            or not isinstance(doc["folder"], str) or not doc["folder"] or not isinstance(signers, dict)
            or not all(is_valid_id(k) and isinstance(v, str) for k, v in signers.items())):
        return None
    return Watch(doc["group_id"], doc["device_id"], doc["epoch"], doc["install_id"], doc["folder"],
                 dict(signers))


def _read(path: Path, limit: int) -> bytes:
    with open(path, "rb") as fh:
        data = fh.read(limit + 1)
    if len(data) > limit:
        raise OSError("file too large")
    return data


def check(watch: Watch, *, install_id: str) -> Notice | None:
    """The verified notice for *watch*'s device in its folder, or None (never raises)."""
    if watch.install_id != install_id:
        return None
    sync_dir = Path(watch.folder) / _SYNC_DIR_NAME
    try:
        raw = _read(sync_dir / REMOVED_DIR_NAME / notice_name(watch.device_id), MAX_NOTICE_BYTES)
        ring = _read(sync_dir / _KEYRING_NAME, _MAX_KEYRING_BYTES)
    except (OSError, ValueError):
        return None
    try:
        return verify_notice(raw, watch, ring)
    except (RemovalError, KeyringError, ValueError):
        return None


def check_file(path: Path, *, install_id: str) -> Notice | None:
    watch = load_watch(path)
    return None if watch is None else check(watch, install_id=install_id)


__all__ = [
    "MAX_NOTICE_BYTES", "NOTICE_LABEL", "NOTICE_SUFFIX", "REMOVED_DIR_NAME", "Notice", "RemovalError", "Watch",
    "check", "check_file", "forget_session_watch", "forget_watch", "load_watch", "make_notice", "notice_name", "parse_notice",
    "pinned", "refresh_watch", "save_watch", "verify_notice", "watch_from_state", "watch_path",
]
