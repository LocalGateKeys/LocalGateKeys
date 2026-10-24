"""Scheduled encrypted backups and the optional mirror folder.

A scheduled backup is a full encrypted ``.lgk`` (``export_full_backup``) made
with the backup password the user keeps inside the encrypted vault payload.
It therefore only runs while the vault is unlocked.  The schedule itself is a
pure function of the clock, the settings and the last successful run, so a
restart never repeats a backup and any number of missed slots catch up once.

Files are written to a temporary name, verified, then renamed; only after
that do older scheduled backups get pruned.  Pruning matches this module's
own filename pattern for this profile, so pre-restore safety backups, rolling
``vault-*.json`` copies, manual exports and foreign files are never touched.

The mirror folder is meant to be a folder a cloud client syncs.  This module
makes no network calls: it copies the finished encrypted ``.lgk`` there and
applies the same retention.  A mirror failure never undoes the local backup.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import tempfile
import zipfile
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

from .backup_filename import BACKUP_EXTENSION

FREQUENCIES = ("off", "daily", "weekly")
KEEP_CHOICES = (1, 2)
DEFAULT_TIME = "12:00"
WEEKDAYS = ("Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday")
SCHEDULED_DIR_NAME = "Scheduled"
STATE_FILENAME = "schedule-state.json"
MIN_BACKUP_PASSWORD_LENGTH = 12
# A failed run is retried at most this often while the vault stays unlocked.
RETRY_AFTER = timedelta(minutes=30)
_FILENAME_PREFIX = "LocalGateKeys-scheduled-"
_TIME = re.compile(r"^([01]?\d|2[0-3]):([0-5]\d)$")
_TAG = re.compile(r"^[0-9a-f]{8}$")
# The encrypted full-backup container header (see backup.FULL_BACKUP_FORMAT).
_FULL_BACKUP_FORMAT = "localgatekeys-full-backup"


class ScheduleError(Exception):
    """A scheduled backup could not be written; any older backup is kept."""


class MirrorError(Exception):
    """The mirror copy failed; the local backup is unaffected."""


# --- schedule ---------------------------------------------------------------

def validated_time(value: Any, default: str = DEFAULT_TIME) -> str:
    try:
        hour, minute = parse_time(value)
    except ValueError:
        return default
    return f"{hour:02d}:{minute:02d}"


def parse_time(value: str) -> tuple[int, int]:
    match = _TIME.match(value.strip()) if isinstance(value, str) else None
    if not match:
        raise ValueError("Use a 24-hour time such as 08:30.")
    return int(match.group(1)), int(match.group(2))


def latest_slot(now: datetime, frequency: str, time_of_day: str, weekday: int = 0) -> datetime | None:
    """Return the most recent scheduled time at or before ``now`` (local time)."""
    if frequency not in ("daily", "weekly"):
        return None
    hour, minute = parse_time(time_of_day)
    slot = now.replace(hour=hour, minute=minute, second=0, microsecond=0)
    if frequency == "daily":
        return slot if slot <= now else slot - timedelta(days=1)
    slot -= timedelta(days=(now.weekday() - int(weekday)) % 7)
    return slot if slot <= now else slot - timedelta(days=7)


def is_due(now: datetime, last_success: datetime | None, frequency: str, time_of_day: str,
           weekday: int = 0) -> bool:
    """True when the latest slot has no successful backup at or after it.

    Comparing with the latest slot only means a week of missed daily runs
    produces one catch-up backup, not seven.  A last-success time in the
    future (the clock moved back) is ignored rather than blocking backups.
    """
    slot = latest_slot(now, frequency, time_of_day, weekday)
    if slot is None:
        return False
    if last_success is None or last_success > now:
        return True
    return last_success < slot


def state_path(directory: Path) -> Path:
    return Path(directory) / STATE_FILENAME


def read_last_success(directory: Path) -> datetime | None:
    try:
        raw = json.loads(state_path(directory).read_text(encoding="utf-8"))
        value = raw.get("last_success") if isinstance(raw, dict) else None
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            return None
        return datetime.fromtimestamp(float(value))
    except (OSError, ValueError, OverflowError):
        return None


def write_last_success(directory: Path, when: datetime) -> None:
    """Persist the last successful run (a timestamp, never a secret)."""
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)
    _atomic_write(state_path(directory), json.dumps({"version": 1, "last_success": when.timestamp()}).encode())


# --- filenames and retention ------------------------------------------------

def profile_tag(profile_id: str) -> str:
    """Short, stable, non-identifying tag so profiles can share a mirror folder."""
    return hashlib.sha256(str(profile_id).encode("utf-8")).hexdigest()[:8]


def scheduled_filename(tag: str, when: datetime, counter: int = 0) -> str:
    if not _TAG.match(tag):
        raise ValueError("Malformed profile tag")
    suffix = f"-{counter}" if counter else ""
    return f"{_FILENAME_PREFIX}{tag}-{when.strftime('%Y%m%d-%H%M%S')}{suffix}{BACKUP_EXTENSION}"


def _pattern(tag: str) -> re.Pattern[str]:
    return re.compile(rf"^{re.escape(_FILENAME_PREFIX)}{re.escape(tag)}-(\d{{8}}-\d{{6}})(?:-(\d{{1,3}}))?"
                      rf"{re.escape(BACKUP_EXTENSION)}$", re.IGNORECASE)


def owned_backups(directory: Path, tag: str) -> list[Path]:
    """This profile's scheduled backups in ``directory``, newest first."""
    pattern = _pattern(tag)
    found: list[tuple[str, int, Path]] = []
    try:
        children = list(Path(directory).iterdir())
    except OSError:
        return []
    for child in children:
        match = pattern.match(child.name)
        if match and child.is_file() and not child.is_symlink():
            found.append((match.group(1), int(match.group(2) or 0), child))
    found.sort(key=lambda row: (row[0], row[1]), reverse=True)
    return [row[2] for row in found]


def prune(directory: Path, tag: str, keep: int, *, protect: Path | None = None) -> list[Path]:
    """Delete this profile's scheduled backups beyond ``keep``; never ``protect``."""
    keep = max(1, int(keep))
    candidates = owned_backups(directory, tag)
    kept: list[Path] = []
    if protect is not None:
        kept.append(Path(protect))
    removed: list[Path] = []
    for path in candidates:
        if protect is not None and path.name == Path(protect).name:
            continue
        if len(kept) < keep:
            kept.append(path)
            continue
        try:
            path.unlink()
            removed.append(path)
        except OSError:
            pass
    return removed


def _unique_destination(directory: Path, tag: str, when: datetime) -> Path:
    for counter in range(0, 1000):
        candidate = directory / scheduled_filename(tag, when, counter)
        if not candidate.exists():
            return candidate
    raise ScheduleError("Too many scheduled backups share one timestamp")


def _atomic_write(path: Path, data: bytes) -> None:
    fd, name = tempfile.mkstemp(prefix=".lgk-state-", suffix=".tmp", dir=path.parent)
    temporary = Path(name)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def write_scheduled_backup(
    directory: Path,
    *,
    tag: str,
    when: datetime,
    keep: int,
    make_backup: Callable[[Path], Any],
    verify: Callable[[Path], Any],
) -> Path:
    """Write, verify, publish, then prune.  Failure leaves older files alone."""
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)
    destination = _unique_destination(directory, tag, when)
    fd, name = tempfile.mkstemp(prefix=".lgk-scheduled-", suffix=".tmp", dir=directory)
    os.close(fd)
    temporary = Path(name)
    try:
        make_backup(temporary)
        if not temporary.is_file() or temporary.stat().st_size == 0:
            raise ScheduleError("The scheduled backup file is empty")
        ensure_encrypted_container(temporary)
        verify(temporary)
        os.replace(temporary, destination)
    except ScheduleError:
        raise
    except Exception as exc:
        raise ScheduleError("Could not write or verify the scheduled backup") from exc
    finally:
        temporary.unlink(missing_ok=True)
    prune(directory, tag, keep, protect=destination)
    return destination


# --- mirror -----------------------------------------------------------------

def ensure_encrypted_container(path: Path) -> None:
    """Refuse anything that is not an encrypted full-backup container.

    The container is a ZIP whose only cleartext member is the KDF header;
    every other member is AES-GCM ciphertext.  This keeps a plaintext file (or
    the live vault.json) from ever being published to a synced folder.
    """
    try:
        with zipfile.ZipFile(path) as archive:
            names = archive.namelist()
            header = json.loads(archive.read("header.json"))
    except (OSError, KeyError, ValueError, zipfile.BadZipFile) as exc:
        raise ScheduleError("Only encrypted LocalGateKeys backups can be copied") from exc
    if (not isinstance(header, dict) or header.get("format") != _FULL_BACKUP_FORMAT
            or "manifest.bin" not in names
            or any(n not in ("header.json", "manifest.bin") and not re.fullmatch(r"data/\d{8}\.bin", n)
                   for n in names)):
        raise ScheduleError("Only encrypted LocalGateKeys backups can be copied")


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def mirror_backup(source: Path, mirror_dir: Path | str, *, tag: str, keep: int) -> Path:
    """Copy one finished scheduled backup into the mirror folder atomically."""
    source = Path(source)
    if not _pattern(tag).match(source.name):
        raise MirrorError("Only scheduled LocalGateKeys backups are mirrored")
    try:
        ensure_encrypted_container(source)
    except ScheduleError as exc:
        raise MirrorError(str(exc)) from exc
    if not str(mirror_dir).strip():
        raise MirrorError("No mirror folder is set")
    mirror = Path(mirror_dir)
    # Do not create a missing root: a disconnected drive or a signed-out cloud
    # client must not silently redirect backups to some other local path.
    if not mirror.is_dir():
        raise MirrorError("The mirror folder is not available")
    try:
        if mirror.resolve() == source.parent.resolve():
            raise MirrorError("The mirror folder must be different from the local backup folder")
    except OSError as exc:
        raise MirrorError("The mirror folder is not available") from exc
    destination = mirror / source.name
    temporary: Path | None = None
    try:
        fd, name = tempfile.mkstemp(prefix=".lgk-mirror-", suffix=".tmp", dir=mirror)
        temporary = Path(name)
        with os.fdopen(fd, "wb") as handle, open(source, "rb") as reader:
            shutil.copyfileobj(reader, handle, 1024 * 1024)
            handle.flush()
            os.fsync(handle.fileno())
        if _sha256(temporary) != _sha256(source):
            raise MirrorError("The mirror copy did not match the backup")
        os.replace(temporary, destination)
    except MirrorError:
        raise
    except OSError as exc:
        raise MirrorError("Could not copy the backup to the mirror folder") from exc
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)
    prune(mirror, tag, keep, protect=destination)
    return destination


# --- one run ----------------------------------------------------------------

@dataclass(frozen=True)
class RunResult:
    path: Path | None
    mirrored: Path | None = None
    mirror_warning: str = ""


def run_scheduled_backup(
    *,
    directory: Path,
    tag: str,
    keep: int,
    when: datetime,
    make_backup: Callable[[Path], Any],
    verify: Callable[[Path], Any],
    mirror_dir: str = "",
    log: Callable[[str, BaseException], Any] | None = None,
) -> RunResult:
    """Make one scheduled backup, record it, then mirror it if configured.

    Raises ScheduleError when the local backup fails (nothing is recorded or
    deleted).  Mirror problems are logged and returned as a warning.
    """
    path = write_scheduled_backup(directory, tag=tag, when=when, keep=keep,
                                  make_backup=make_backup, verify=verify)
    try:
        write_last_success(directory, when)
    except OSError as exc:
        if log is not None:
            log("scheduled-backup-state", exc)
    if not str(mirror_dir or "").strip():
        return RunResult(path)
    try:
        return RunResult(path, mirror_backup(path, mirror_dir, tag=tag, keep=keep))
    except Exception as exc:  # noqa: BLE001 - a mirror problem never fails the local backup
        if log is not None:
            log("backup-mirror", exc)
        message = str(exc) if isinstance(exc, MirrorError) else "Could not copy the backup to the mirror folder"
        return RunResult(path, None, message)


def full_backup_functions(*, profile_dir: Path, profile_name: str, backup_password: str
                          ) -> tuple[Callable[[Path], Any], Callable[[Path], Any]]:
    """Return (make, verify) callables for an encrypted full profile backup."""
    from .backup import export_full_backup, preflight_full_backup

    def make(path: Path) -> Any:
        return export_full_backup(path, profile_dir=profile_dir, profile_name=profile_name,
                                  backup_password=backup_password)

    def verify(path: Path) -> Any:
        probe = Path(tempfile.mkdtemp(prefix=".lgk-scheduled-probe-", dir=str(path.parent)))
        try:
            return preflight_full_backup(path, profile_dir=probe / "profile", backup_password=backup_password)
        finally:
            shutil.rmtree(probe, ignore_errors=True)

    return make, verify
