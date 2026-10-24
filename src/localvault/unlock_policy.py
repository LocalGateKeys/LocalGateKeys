"""Persistent "master password required" marker for emergency locks.

An emergency lock promises that the next unlock needs the master password, not
Windows Hello or the camera. Keeping that only in memory let a restart (exit
from the tray, crash, sign-out) bring the alternatives back, so the requirement
is stored per profile under the data directory and is only cleared after a
successful master-password (or recovery-phrase) unlock.

The marker fails closed: any file at the profile's path, whatever it contains
and even if it cannot be read, means "master password required". Clearing it
therefore needs write access to the user's data directory, which is outside
the threat model (same-user code can already replace the app). A marker that
cannot be written leaves the in-memory requirement in place for this run.
"""
from __future__ import annotations

import hashlib
import json
import time
from pathlib import Path

from .config import data_dir

_DIRECTORY_NAME = "unlock-policy"


def _marker_path(profile_id: str) -> Path:
    digest = hashlib.sha256(str(profile_id).encode("utf-8")).hexdigest()[:32]
    return data_dir() / _DIRECTORY_NAME / f"master-required-{digest}.json"


def master_unlock_required(profile_id: str) -> bool:
    """True when an emergency lock for ``profile_id`` has not been cleared yet."""

    try:
        path = _marker_path(profile_id)
        return path.exists() or path.is_symlink()
    except (OSError, ValueError):
        return True


def require_master_unlock(profile_id: str) -> bool:
    """Persist the requirement; False when it could not be written."""

    try:
        path = _marker_path(profile_id)
        path.parent.mkdir(parents=True, exist_ok=True)
        payload = {"format": "localgatekeys-master-unlock-required", "version": 1,
                   "profile": str(profile_id), "since": int(time.time())}
        path.write_text(json.dumps(payload, sort_keys=True), encoding="utf-8")
        return True
    except (OSError, ValueError):
        return False


def clear_master_unlock_requirement(profile_id: str) -> None:
    """Remove the marker after a successful master-password unlock."""

    try:
        _marker_path(profile_id).unlink(missing_ok=True)
    except (OSError, ValueError):
        pass
