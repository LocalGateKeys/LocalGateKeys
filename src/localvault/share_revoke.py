"""Signed revoke notice for one ``.lgkshare`` package (sub-plan 12, Task 5). Best effort.

Signed like ``sync/removal.py`` notices: Ed25519 over ``REVOKE_LABEL + canonical_json(body)`` with the sender
device's member signing key. Paired devices receive the notice over the sync channel and pass verified package ids
to ``share.open_package(revoked=...)``; anyone else only sees "revoked" if the sender shares the notice file and the
receiver opens the package after that. A copy already opened cannot be taken back.

Notice (canonical JSON, at most 1 KiB)::

    {"format":1,"package_id","signer","issued_at","sig"}
"""
from __future__ import annotations

import base64
import binascii
import json
import os
import time
import uuid
from collections.abc import Mapping
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import ed25519

from .updates import canonical_json

REVOKE_LABEL = b"localgatekeys|share|revoke-notice|v1|"
REVOKE_FORMAT = 1
MAX_REVOKE_BYTES = 1024
_FIELDS = {"format", "package_id", "signer", "issued_at", "sig"}


class RevokeError(ValueError):
    pass


def _package_id(value: object) -> str:
    try:
        text = str(uuid.UUID(str(value)))
    except ValueError:
        raise RevokeError("bad-revoke") from None
    if text != value:
        raise RevokeError("bad-revoke")
    return text


def make_revoke(signing_key: ed25519.Ed25519PrivateKey, package_id: str, *, signer: str = "",
                now: int | None = None) -> bytes:
    body = {"format": REVOKE_FORMAT, "package_id": _package_id(package_id), "signer": str(signer)[:64],
            "issued_at": int(time.time()) if now is None else int(now)}
    sig = signing_key.sign(REVOKE_LABEL + canonical_json(body))
    return canonical_json({**body, "sig": base64.b64encode(sig).decode("ascii")})


def verify_revoke(raw: bytes, public_key: ed25519.Ed25519PublicKey, package_id: str) -> str:
    """The revoked package id; raises ``RevokeError`` for another package, a bad signature or a damaged notice."""
    if not isinstance(raw, (bytes, bytearray)) or len(raw) > MAX_REVOKE_BYTES:
        raise RevokeError("bad-revoke")
    try:
        doc = json.loads(bytes(raw).decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        raise RevokeError("bad-revoke") from None
    if not isinstance(doc, dict) or set(doc) != _FIELDS or doc["format"] != REVOKE_FORMAT \
            or type(doc["issued_at"]) is not int or not isinstance(doc["signer"], str) \
            or not isinstance(doc["sig"], str):
        raise RevokeError("bad-revoke")
    if _package_id(doc["package_id"]) != package_id:
        raise RevokeError("other-package")
    try:
        sig = base64.b64decode(doc["sig"], validate=True)
    except (binascii.Error, ValueError):
        raise RevokeError("bad-revoke") from None
    body = {k: v for k, v in doc.items() if k != "sig"}
    try:
        public_key.verify(sig, REVOKE_LABEL + canonical_json(body))
    except InvalidSignature:
        raise RevokeError("bad-signature") from None
    return package_id


# --- over sync (``LocalGateKeys Sync/revoked/<package id>.lgkrevoke``) -------------------------------------------
# The sender writes the notice into its sync folder; each paired device lists ``revoked/`` and accepts a notice only
# when its ``signer`` is a member of the keyring it trusts and the signature verifies with that member's signing key.
# Older builds and the phone apps never list ``revoked/``, so they ignore it.

REVOKED_DIR_NAME = "revoked"
SUFFIX = ".lgkrevoke"
MAX_NOTICES = 512
# A package lives at most 24 h (``share.LIFETIME``), so a notice is useless long before this; the slack covers
# clock skew between devices.  ``publish`` removes older notices so the folder stays well under ``MAX_NOTICES``.
PRUNE_AFTER = 7 * 24 * 3600


def publish(sync_dir: Path, signing_key: ed25519.Ed25519PrivateKey, package_id: str, *, signer: str,
            now: int | None = None) -> Path:
    data = make_revoke(signing_key, package_id, signer=signer, now=now)
    folder = Path(sync_dir) / REVOKED_DIR_NAME
    folder.mkdir(parents=True, exist_ok=True)
    target = folder / f"{_package_id(package_id)}{SUFFIX}"
    temp = target.with_suffix(".tmp")
    temp.write_bytes(data)
    os.replace(temp, target)
    _prune(folder, keep=target, now=time.time())
    return target


def _prune(folder: Path, *, keep: Path, now: float) -> None:
    """Best effort: remove notices whose file is older than ``PRUNE_AFTER`` (their packages expired long ago)."""
    try:
        paths = list(folder.glob(f"*{SUFFIX}"))
    except OSError:
        return
    for path in paths:
        try:
            if path != keep and not path.is_symlink() and now - path.stat().st_mtime > PRUNE_AFTER:
                path.unlink()
        except OSError:
            continue


def _newest_notices(folder: Path) -> list[Path]:
    """At most ``MAX_NOTICES`` notice files, newest first: a revoke matters only while its package (24 h at most)
    can still be opened, so with too many files the old ones are the ones skipped (scan core 3, M2)."""
    rows: list[tuple[float, str, Path]] = []
    for path in folder.glob(f"*{SUFFIX}"):
        try:
            rows.append((path.lstat().st_mtime, path.name, path))
        except OSError:
            continue
    rows.sort(key=lambda row: (-row[0], row[1]))
    return [row[2] for row in rows[:MAX_NOTICES]]


def collect(sync_dir: Path, trusted: Mapping[str, str]) -> set[str]:
    """Package ids revoked by a trusted member (``{device_id: base64 Ed25519 public key}``). Never raises."""
    out: set[str] = set()
    try:
        files = _newest_notices(Path(sync_dir) / REVOKED_DIR_NAME)
    except OSError:
        return out
    for path in files:
        try:
            if path.is_symlink() or path.stat().st_size > MAX_REVOKE_BYTES:
                continue
            raw = path.read_bytes()
            doc = json.loads(raw.decode("utf-8"))
            signer = doc.get("signer") if isinstance(doc, dict) else None
            # A notice is untrusted input: a list or dict "signer" must not reach the dict lookup (scan core 3, M2).
            key = trusted.get(signer) if isinstance(signer, str) else None
            if not isinstance(key, str):
                continue
            public = ed25519.Ed25519PublicKey.from_public_bytes(base64.b64decode(key, validate=True))
            out.add(verify_revoke(raw, public, str(doc.get("package_id"))))
        except (OSError, ValueError, TypeError, RecursionError, RevokeError, binascii.Error):
            continue
    return out
