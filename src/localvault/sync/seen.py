"""When each peer last synced, even when that sync changed nothing (shown on the sync status).

Two sources, both kept in memory only (a sync that changes nothing writes nothing to the vault):

* Wi-Fi: every clean exchange with a peer (``lan_sync.note_peer_synced``).
* Cloud folder: a heartbeat file per device, ``seen/<device id>.lgksync`` with its signature
  ``seen/<device id>.lgksig``.  It is an empty view (``group.encode_view``, counter 0, no items)
  whose header ``written_at`` is the time of that device's last folder run, signed like a view
  (``group.sign_view``).  A device rewrites its own heartbeat at most every
  ``HEARTBEAT_SECONDS``.  A peer's heartbeat counts only when it decodes under the group key at
  this epoch and is signed by the key already trusted for that device (keyring, Wi-Fi pairing or
  pin); it never pins a key.  Times are capped at the reader's clock and only move a time forward,
  so a replayed old file changes nothing.  The folder lives in its own directory, so older builds,
  which only scan ``devices/``, never see it.
"""
from __future__ import annotations

import base64
import contextlib
import os
import threading
from collections.abc import Iterable, Mapping
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric import ed25519

from .group import MAX_SIG_BYTES, GroupKey, SyncFormatError, decode_view, encode_view, sign_view, verify_view_signature

SEEN_DIR_NAME = "seen"
HEARTBEAT_SECONDS = 15 * 60
SUFFIX = ".lgksync"
SIG_SUFFIX = ".lgksig"
MAX_BYTES = 64 * 1024

_lock = threading.Lock()
#: (group id, peer id) -> unix seconds of the last sync this process saw from that peer.
_TIMES: dict[tuple[str, str], int] = {}


def note(group_id: str, peer_id: str, at: int) -> None:
    """Record that *peer_id* synced at *at* (kept when newer than what is known)."""
    at = max(0, int(at))
    with _lock:
        key = (group_id, peer_id)
        if at > _TIMES.get(key, -1):
            _TIMES[key] = at


def times(group_id: str) -> dict[str, int]:
    """Peer id -> last sync time seen in this process, for *group_id*."""
    with _lock:
        return {peer: at for (group, peer), at in _TIMES.items() if group == group_id}


def clear() -> None:
    with _lock:
        _TIMES.clear()


def _paths(sync_dir: Path, device_id: str) -> tuple[Path, Path]:
    folder = Path(sync_dir) / SEEN_DIR_NAME
    return folder / f"{device_id}{SUFFIX}", folder / f"{device_id}{SIG_SUFFIX}"


def _read(path: Path, limit: int) -> bytes | None:
    try:
        if path.is_symlink() or not path.is_file():
            return None
        with path.open("rb") as handle:
            raw = handle.read(limit + 1)
    except OSError:
        return None
    return raw if len(raw) <= limit else None


def _atomic(path: Path, data: bytes) -> None:
    tmp = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    try:
        tmp.write_bytes(data)
        os.replace(tmp, path)
    except OSError:
        with contextlib.suppress(OSError):
            tmp.unlink()
        raise


def read_heartbeat(sync_dir: Path, gk: GroupKey, device_id: str, expected_key: str | None) -> int | None:
    """The time in *device_id*'s heartbeat, or None (missing, bad, or not signed by *expected_key*)."""
    if not expected_key:
        return None
    raw_path, sig_path = _paths(sync_dir, device_id)
    raw, sig = _read(raw_path, MAX_BYTES), _read(sig_path, MAX_SIG_BYTES)
    if raw is None or sig is None:
        return None
    try:
        view = decode_view(gk, raw, expected_device_id=device_id)
        public = verify_view_signature(sig, raw, view.header)
    except SyncFormatError:
        return None
    if base64.b64encode(public).decode("ascii") != expected_key or view.states:
        return None
    return int(view.header["written_at"])


def write_heartbeat(sync_dir: Path, gk: GroupKey, device_id: str, signing_key: ed25519.Ed25519PrivateKey,
                    *, now: int) -> bool:
    """Write this device's heartbeat unless its own valid one is younger than ``HEARTBEAT_SECONDS``."""
    own = base64.b64encode(signing_key.public_key().public_bytes_raw()).decode("ascii")
    last = read_heartbeat(sync_dir, gk, device_id, own)
    if last is not None and 0 <= now - last < HEARTBEAT_SECONDS:
        return False
    raw_path, sig_path = _paths(sync_dir, device_id)
    raw = encode_view(gk, device_id, 0, (), int(now))
    raw_path.parent.mkdir(parents=True, exist_ok=True)
    _atomic(raw_path, raw)
    _atomic(sig_path, sign_view(raw, signing_key))
    return True


def read_peers(sync_dir: Path, gk: GroupKey, group_id: str, peers: Iterable[str], keys: Mapping[str, str],
               *, now: int) -> dict[str, int]:
    """Read each peer's heartbeat (signed by ``keys[peer]``), note it, and return the times found."""
    found: dict[str, int] = {}
    for peer in peers:
        at = read_heartbeat(sync_dir, gk, peer, keys.get(peer))
        if at is None:
            continue
        at = min(at, int(now))
        found[peer] = at
        note(group_id, peer, at)
    return found
