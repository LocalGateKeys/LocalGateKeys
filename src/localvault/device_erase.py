"""Erase one profile from this PC after a verified sync removal (WP-A).

Unlike ``ProfileManager.delete_profile`` (which archives the folder under ``DeletedProfiles``) this
removes the profile for good: this app's Windows Hello key, then every file in the profile folder
(vault file, journals, Hello/camera sidecars, generation and throttle files, settings, attachments,
OCR cache, opened documents, pre-restore safety copies and rolling vault copies, the sync watch
file), each overwritten once with random bytes, flushed and deleted, then the folder, the profile's
row in ``profiles.json`` and its master-required marker.  The stored scheduled-backup password lives
only in the vault file's encrypted prefs, so it goes with the vault.

Kept (owner decision 2026-10-31): this profile's scheduled backups (``Backups/Scheduled``, the
``backup_schedule`` filename pattern for this profile, encrypted full-backup containers only) are
moved first to ``<data dir>/Kept backups/<profile name> <YYYY-MM-DD>/``.  They are locked with the
separate backup password and hold the vault under the master password, so the master password alone
opens nothing in them.  Everything that only the master password protects is erased.

Overwriting is best effort: an SSD may keep old blocks, and copies outside the profile folder (a
backup mirror folder, the cloud folder, earlier exports) are not touched.  The vault is encrypted in
any case.  ``erased-notice.json`` in the data folder lets the next start say what happened and where
the kept backups are.
"""
from __future__ import annotations

import contextlib
import json
import os
import re
import stat
import sys
import time
from collections.abc import Callable
from datetime import datetime
from pathlib import Path
from typing import Any

from .config import atomic_write_json, data_dir

NOTICE_NAME = "erased-notice.json"
KEPT_DIR_NAME = "Kept backups"
# A started erase remembers its kept folder here, so a retry after a failed erase still reports it.
_PENDING_KEPT = "erase-kept-{profile_id}.json"
_CHUNK = 1024 * 1024
_UNSAFE_NAME = re.compile(r'[<>:"/\\|?*\x00-\x1f]')
_RESERVED_NAMES = frozenset({"CON", "PRN", "AUX", "NUL", *(f"COM{i}" for i in range(1, 10)),
                             *(f"LPT{i}" for i in range(1, 10))})


def _overwrite_and_delete(path: Path) -> None:
    if path.is_symlink():
        path.unlink()
        return
    with contextlib.suppress(OSError):
        os.chmod(path, stat.S_IWRITE | stat.S_IREAD)  # a read-only file cannot be opened for writing
    try:
        size = path.stat().st_size
        with open(path, "r+b", buffering=0) as fh:
            left = size
            while left > 0:
                step = min(left, _CHUNK)
                fh.write(os.urandom(step))
                left -= step
            os.fsync(fh.fileno())
    except OSError:
        pass  # still delete it below
    path.unlink()


def _hello_record_id(profile_dir: Path) -> str | None:
    try:
        raw = json.loads((profile_dir / "vault.hello.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    value = raw.get("id") if isinstance(raw, dict) else None
    return value if isinstance(value, str) else None


def _delete_hello_key(record_id: str) -> None:
    if sys.platform != "win32":
        return
    from .windows_hello import WindowsHello, validate_record_id

    WindowsHello().delete(validate_record_id(record_id))


def erase_tree(folder: Path, *, last: Path | None = None) -> list[str]:
    """Overwrite and delete everything under *folder* and the folder itself; the paths that remain.

    *last* (a file directly in *folder*) goes only once everything else is gone; while anything
    remains it stays too, so a later attempt still finds it.
    """
    left: list[str] = []
    if not folder.exists():
        return left
    for current, dirs, files in os.walk(folder, topdown=False):
        base = Path(current)
        for name in files:
            if last is not None and base / name == last:
                continue
            try:
                _overwrite_and_delete(base / name)
            except OSError:
                left.append(str(base / name))
        for name in dirs:
            target = base / name
            try:
                target.unlink() if target.is_symlink() else target.rmdir()
            except OSError:
                left.append(str(target))
    if left:
        return left
    if last is not None and last.exists():
        try:
            _overwrite_and_delete(last)
        except OSError:
            return [str(last)]
    try:
        folder.rmdir()
    except OSError:
        left.append(str(folder))
    return left


def erase_profile(profiles: Any, profile_id: str, *, reason: str = "sync-removal",
                  delete_hello_key: Callable[[str], None] = _delete_hello_key,
                  now: Callable[[], float] = time.time) -> list[str]:
    """Erase *profile_id* (a ``ProfileManager``'s profile) for good; returns the paths that could not go.

    The caller locks the vault first.  When a file cannot be removed (still open elsewhere), the
    profile row and the sync watch file stay, so the next check tries again.
    """
    folder = Path(profiles.root) / "Profiles" / profile_id
    if folder.resolve().parent != (Path(profiles.root) / "Profiles").resolve():
        raise ValueError("profile folder escapes the profiles folder")
    record = _hello_record_id(folder)
    if record is not None:
        with contextlib.suppress(Exception):  # noqa: BLE001 - the sidecar goes either way
            delete_hello_key(record)
    from .sync.removal import watch_path

    kept = _read_pending(profile_id)  # an earlier attempt that already moved them
    name = next((p.name for p in profiles.list_profiles() if p.id == profile_id), "")
    try:
        moved = keep_scheduled_backups(folder, profile_id, name, when=now())
    except OSError:
        moved = None  # cannot keep them: they are erased with the rest (the safe direction)
    if moved is not None:
        kept.append(str(moved))
        with contextlib.suppress(OSError):
            atomic_write_json(_pending_path(profile_id), {"version": 1, "kept_folders": kept})
    from . import duress, vault

    # Before the files go (a vault-id mark is named from the file's header): the marks kept outside the folder
    # for this vault and its second vault, so nothing left on this PC names them.
    for marked in (folder / "vault.json", duress.decoy_path(folder / "vault.json")):
        with contextlib.suppress(Exception):  # noqa: BLE001 - best effort, like the marks themselves
            vault.forget_rollback_marks(marked)
    left = erase_tree(folder, last=watch_path(folder / "vault.json"))
    if left:
        return left
    profiles.forget_erased_profile(profile_id)
    from .unlock_policy import clear_master_unlock_requirement

    clear_master_unlock_requirement(profile_id)
    notice: dict[str, Any] = {"version": 1, "reason": reason, "erased_at": int(now())}
    folders = [*_notice_folders(_read_notice()), *kept]  # an unread earlier notice keeps its folders
    if folders:
        notice["kept_folders"] = folders
    with contextlib.suppress(OSError):
        atomic_write_json(data_dir() / NOTICE_NAME, notice)
    with contextlib.suppress(OSError):
        _pending_path(profile_id).unlink()
    return left


def safe_folder_name(name: str, *, fallback: str = "Vault", limit: int = 60) -> str:
    """*name* as one Windows-safe path component: no separators, control or reserved names, trailing dots."""
    cleaned = _UNSAFE_NAME.sub("_", str(name or "")).strip()[:limit].rstrip(". ").strip()
    if not cleaned:
        return fallback
    if cleaned.split(".")[0].strip().upper() in _RESERVED_NAMES:
        cleaned = f"_{cleaned}"
    return cleaned


def _scheduled_backups(folder: Path, profile_id: str) -> list[Path]:
    """This profile's scheduled backups in its own folder: its filename pattern and an encrypted container."""
    from .backup_schedule import (
        SCHEDULED_DIR_NAME,
        ScheduleError,
        ensure_encrypted_container,
        owned_backups,
        profile_tag,
    )

    found: list[Path] = []
    for path in owned_backups(folder / "Backups" / SCHEDULED_DIR_NAME, profile_tag(profile_id)):
        try:
            ensure_encrypted_container(path)
        except ScheduleError:
            continue  # not a backup-password container: erased with the rest
        found.append(path)
    return found


def _kept_destination(name: str, when: float) -> Path:
    base = f"{safe_folder_name(name)} {datetime.fromtimestamp(when).strftime('%Y-%m-%d')}"
    parent = data_dir() / KEPT_DIR_NAME
    for counter in range(1, 1000):
        candidate = parent / (base if counter == 1 else f"{base} ({counter})")
        if not candidate.exists():
            return candidate
    raise OSError("too many kept backup folders share one name")


def keep_scheduled_backups(folder: Path, profile_id: str, profile_name: str, *, when: float) -> Path | None:
    """Move this profile's scheduled backups out of *folder* before the erase; the kept folder or None.

    Only files inside *folder* are moved.  One that cannot be moved stays and is erased with the rest.
    """
    sources = _scheduled_backups(folder, profile_id)
    if not sources:
        return None
    target = _kept_destination(profile_name, when)
    target.mkdir(parents=True)
    moved = 0
    for source in sources:
        try:
            os.replace(source, target / source.name)
            moved += 1
        except OSError:
            continue
    if not moved:
        with contextlib.suppress(OSError):
            target.rmdir()
        return None
    return target


def _pending_path(profile_id: str) -> Path:
    return data_dir() / _PENDING_KEPT.format(profile_id=profile_id)


def _string_list(value: Any) -> list[str]:
    return [item for item in value if isinstance(item, str)] if isinstance(value, list) else []


def _read_pending(profile_id: str) -> list[str]:
    try:
        raw = json.loads(_pending_path(profile_id).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return []
    return _string_list(raw.get("kept_folders")) if isinstance(raw, dict) else []


def _read_notice() -> dict[str, Any] | None:
    try:
        raw = json.loads((data_dir() / NOTICE_NAME).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    return raw if isinstance(raw, dict) else {}


def _notice_folders(raw: dict[str, Any] | None) -> list[str]:
    return _string_list(raw.get("kept_folders")) if raw else []


def erased_notice() -> dict[str, Any] | None:
    """``{"erased_at": seconds}`` while the "this device was erased" notice waits to be read.

    Plus ``"kept_folders": [path, ...]`` when scheduled backups were moved out before the erase.
    """
    raw = _read_notice()
    if raw is None:
        return None
    when = raw.get("erased_at")
    notice: dict[str, Any] = {"erased_at": when if type(when) is int else 0}
    folders = _notice_folders(raw)
    if folders:
        notice["kept_folders"] = folders
    return notice


def dismiss_erased_notice() -> None:
    with contextlib.suppress(OSError):
        (data_dir() / NOTICE_NAME).unlink()
