"""Per-device state of the scheduled-backup key (``docs/design/backup-public-key-2026-10-31.md``).

The design calls it the ``settings.json`` fields; it lives in its own small file next to the profile's
``settings.json`` instead, because ``settings.json`` travels inside full backups (``AppSettings`` fields,
pinned by the v2 vectors) and a restored backup must never bring back an older ``backup_key_seen``.

* ``seen_record``: the full public record (public key, kdf, key id, set time, reset authority, history; no
  secret) of the newest record this device set, changed, reset, re-bound, migrated or confirmed (sections 2.3
  and 16c).  A vault record older than it, a missing record or a damaged one pauses scheduled backups; only
  the backup password of ``seen_record`` or a strict reset with the phrase bound in it goes on (16c).
  ``seen_key_id`` / ``seen_set_at`` mirror it.  Files written before 16c hold only ``seen = {key_id,
  set_at}``; ``seen_record`` is then ``None`` (``legacy_seen``) and adopted from the vault when they match.
* ``confirm_key_id``: a record migrated after a newer key had been seen here (an old vault copy that
  still held the stored password was brought back); it is paused the same way.
* ``notice_dismissed_at`` / ``reminder_dismissed_at``: owner decision Q1 (the "change your backup
  password to finish the upgrade" notice, and its one reminder 30 days later).
* ``protect_old``: owner decision Q3 (file names of the newest pre-migration scheduled backup and its
  mirror copy; ``backup_schedule.prune`` never removes them and does not count them against ``keep``).
  Never truncated.
* ``keep_all_old``: set when an unreadable state file had to be replaced: which names were protected is
  unknown, so pruning keeps every old-format file from then on (fail closed, review L5).

Read-modify-write goes through ``update`` (one lock per state file).  Times are integer Unix seconds
passed in by the caller.  Nothing here holds a secret.
"""
from __future__ import annotations

import os
import re
import threading
from collections.abc import Callable
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any

from .config import atomic_write_json, read_json

STATE_FILENAME = "backup-key-device.json"
UNREADABLE_SUFFIX = ".unreadable"
STATE_VERSION = 1
REMINDER_AFTER_SECONDS = 30 * 86400
MAX_PROTECTED = 4096  # a sanity bound on the file, not a truncation: a longer list makes the file unreadable
_KEY_ID = re.compile(r"[0-9a-f]{32}")
_NAME = re.compile(r"LocalGateKeys-scheduled-[0-9a-f]{8}-\d{8}-\d{6}(?:-\d{1,3})?\.lgk", re.IGNORECASE)


class NewerStateError(OSError):
    """The state file was written by a newer release: it is never overwritten."""


@dataclass(frozen=True)
class DeviceKeyState:
    seen_key_id: str = ""
    seen_set_at: int | None = None
    seen_record: dict[str, Any] | None = None
    confirm_key_id: str = ""
    notice_dismissed_at: int | None = None
    reminder_dismissed_at: int | None = None
    protect_old: tuple[str, ...] = field(default_factory=tuple)
    keep_all_old: bool = False
    # The file exists but could not be read (damaged, or from a newer release): protection is unknown.
    unreadable: bool = False
    newer: bool = False

    @property
    def legacy_seen(self) -> bool:
        """A pre-16c file: the key id and time are known, the public key is not."""
        return bool(self.seen_key_id) and self.seen_record is None


def state_file(profile_dir: Path) -> Path:
    return Path(profile_dir) / STATE_FILENAME


def _time(value: Any) -> int | None:
    return value if type(value) is int and 0 <= value <= 2**53 - 1 else None


_UNREADABLE = DeviceKeyState(unreadable=True)


def load(profile_dir: Path) -> DeviceKeyState:
    """The stored state; a missing file is the empty state, an unreadable one has ``unreadable`` set."""
    from .backup_key import DamagedRecordError, validate_record

    path = state_file(profile_dir)
    try:
        raw = read_json(path)
    except FileNotFoundError:
        return DeviceKeyState()
    except (OSError, ValueError, TypeError, RecursionError):
        return _UNREADABLE
    version = raw.get("version")
    if type(version) is int and version > STATE_VERSION:
        return DeviceKeyState(unreadable=True, newer=True)
    if version != STATE_VERSION:
        return _UNREADABLE
    seen_id, seen_at, record = "", None, None
    stored = raw.get("seen_record")
    if stored is not None:
        try:
            record = validate_record(stored)
        except DamagedRecordError:
            return _UNREADABLE
        seen_id, seen_at = record["key_id"], record["set_at"]
    else:
        seen = raw.get("seen")
        if isinstance(seen, dict) and isinstance(seen.get("key_id"), str) and _KEY_ID.fullmatch(seen["key_id"]):
            seen_at = _time(seen.get("set_at"))
            seen_id = seen["key_id"] if seen_at is not None else ""
    confirm = raw.get("confirm_key_id")
    names = raw.get("protect_old")
    protected: tuple[str, ...] = ()
    if names is not None:
        if not isinstance(names, list) or len(names) > MAX_PROTECTED:
            return _UNREADABLE
        protected = tuple(dict.fromkeys(n for n in names if isinstance(n, str) and _NAME.fullmatch(n)))
    keep_all = raw.get("keep_all_old", False)
    return DeviceKeyState(
        seen_key_id=seen_id, seen_set_at=seen_at, seen_record=record,
        confirm_key_id=confirm if isinstance(confirm, str) and _KEY_ID.fullmatch(confirm) else "",
        notice_dismissed_at=_time(raw.get("notice_dismissed_at")),
        reminder_dismissed_at=_time(raw.get("reminder_dismissed_at")),
        protect_old=protected, keep_all_old=keep_all is True,
    )


def save(profile_dir: Path, state: DeviceKeyState) -> None:
    """Write atomically (``OSError`` when it cannot be written).  Prefer ``update`` for read-modify-write."""
    if len(state.protect_old) > MAX_PROTECTED:
        raise OSError("Too many protected backup names")
    atomic_write_json(state_file(profile_dir), {
        "version": STATE_VERSION,
        "seen": {"key_id": state.seen_key_id, "set_at": state.seen_set_at} if state.seen_key_id else None,
        "seen_record": state.seen_record,
        "confirm_key_id": state.confirm_key_id or None,
        "notice_dismissed_at": state.notice_dismissed_at,
        "reminder_dismissed_at": state.reminder_dismissed_at,
        "protect_old": list(state.protect_old),
        "keep_all_old": state.keep_all_old,
    })


_locks_guard = threading.Lock()
_locks: dict[str, threading.RLock] = {}


def _lock_for(profile_dir: Path) -> threading.RLock:
    key = os.path.normcase(os.path.abspath(str(state_file(profile_dir))))
    with _locks_guard:
        lock = _locks.get(key)
        if lock is None:
            lock = _locks[key] = threading.RLock()
        return lock


def update(profile_dir: Path, change: Callable[[DeviceKeyState], DeviceKeyState]) -> DeviceKeyState:
    """Load, apply ``change`` and save under this file's lock (review L5); returns the saved state.

    A file from a newer release is never overwritten (``NewerStateError``).  A damaged file is kept beside
    the new one (``.unreadable``) and the new state has ``keep_all_old`` set, so the names it protected are
    never pruned by mistake.
    """
    with _lock_for(profile_dir):
        state = load(profile_dir)
        if state.newer:
            raise NewerStateError("The backup key state was written by a newer release")
        if state.unreadable:
            path = state_file(profile_dir)
            os.replace(path, path.with_name(path.name + UNREADABLE_SUFFIX))
            state = DeviceKeyState(keep_all_old=True)
        new = change(state)
        if state.keep_all_old and not new.keep_all_old:
            new = replace(new, keep_all_old=True)
        save(profile_dir, new)
        return new


def without_seen(state: DeviceKeyState) -> DeviceKeyState:
    """After a proven removal, or for a brand-new vault: no record is known here (Q3 names stay)."""
    return replace(state, seen_key_id="", seen_set_at=None, seen_record=None, confirm_key_id="")


def forget_seen(profile_dir: Path) -> None:
    """A brand-new vault in ``profile_dir`` starts with no seen record (16c).  No file: nothing to do."""
    if not state_file(profile_dir).exists():
        return
    update(profile_dir, without_seen)


def protection(state: DeviceKeyState) -> tuple[str, ...] | None:
    """Names ``prune`` must keep, or ``None`` when that is unknown (prune then keeps every old-format file)."""
    if state.unreadable or state.keep_all_old:
        return None
    return state.protect_old


def seen(state: DeviceKeyState, record: dict[str, Any]) -> DeviceKeyState:
    """After a set, change, reset, re-bind, migration or confirm through the app: this record is the newest seen."""
    from .backup_key import validate_record

    record = validate_record(record)
    return replace(state, seen_key_id=record["key_id"], seen_set_at=record["set_at"], seen_record=record,
                   confirm_key_id="")


def protect(state: DeviceKeyState, names: list[str]) -> DeviceKeyState:
    kept = tuple(dict.fromkeys([*state.protect_old, *(n for n in names if _NAME.fullmatch(n))]))
    return replace(state, protect_old=kept)


def is_older(record: dict[str, Any], state: DeviceKeyState) -> bool:
    """Section 2.3: ``record`` is older than (or differs at the same time from) the newest seen here."""
    if not state.seen_key_id or state.seen_set_at is None:
        return False
    if record["set_at"] < state.seen_set_at:
        return True
    return record["set_at"] == state.seen_set_at and record["key_id"] != state.seen_key_id


def is_paused(record: dict[str, Any] | None, state: DeviceKeyState) -> bool:
    """Section 2.3 / 16c for a valid vault ``record`` (``None``: missing): older than seen, or flagged at migration.

    A missing record pauses only when a full ``seen_record`` is known (16c); a pre-16c file cannot prove one.
    """
    if record is None:
        return state.seen_record is not None
    if state.confirm_key_id and state.confirm_key_id == record["key_id"]:
        return True
    return is_older(record, state)


def upgrade_notice(record: dict[str, Any] | None, state: DeviceKeyState, now: int) -> str:
    """Owner decision Q1: ``"notice"`` until dismissed, ``"reminder"`` once 30 days later, else ``""``."""
    if record is None or record.get("set_by") != "migrated":
        return ""
    if state.notice_dismissed_at is None:
        return "notice"
    if state.reminder_dismissed_at is None and now >= state.notice_dismissed_at + REMINDER_AFTER_SECONDS:
        return "reminder"
    return ""


def dismiss(state: DeviceKeyState, kind: str, now: int) -> DeviceKeyState:
    if kind == "reminder":
        return replace(state, reminder_dismissed_at=now)
    return replace(state, notice_dismissed_at=now)
