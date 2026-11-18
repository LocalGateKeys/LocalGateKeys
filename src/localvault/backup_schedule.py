"""Scheduled encrypted backups and the optional mirror folder.

A scheduled backup is a full encrypted ``.lgk``, version 3 since 2026-11
(``export_full_backup_to_key``): it is locked to the public backup key record
kept inside the encrypted vault payload, so no password is needed to write it
and none is stored (``docs/design/backup-public-key-2026-10-31.md``).  It
still only runs while the vault is unlocked.  Older scheduled backups (full
backup v2, made with the stored password) are never rewritten; the retention
rule counts old and new files together by file name.  The schedule itself is a
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
from collections.abc import Callable, Iterable
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


def write_last_success(directory: Path, when: datetime, *, sha256: str = "") -> None:
    """Persist the last successful run and the published file's SHA-256 (never a secret)."""
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)
    state: dict[str, Any] = {"version": 1, "last_success": when.timestamp()}
    if sha256:
        state["last_sha256"] = sha256
    _atomic_write(state_path(directory), json.dumps(state).encode())


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


def prune(directory: Path, tag: str, keep: int, *, protect: Path | None = None,
          protect_old: Iterable[str] | None = ()) -> list[Path]:
    """Delete this profile's scheduled backups beyond ``keep``; never ``protect``.

    Files are chosen by file name only (old-format and version 3 backups count together).  Names in
    ``protect_old`` (owner decision Q3: the newest backup from before the public key) are never removed
    and do not count against ``keep``.  ``protect_old=None`` means the protected names are unknown (the
    device state could not be read): then no file that is not version 3 is removed (fail closed, review L5;
    only its cleartext header is read).
    """
    keep = max(1, int(keep))
    candidates = owned_backups(directory, tag)
    unknown = protect_old is None
    exempt = set() if unknown else {str(name).casefold() for name in protect_old}
    kept: list[Path] = []
    if protect is not None:
        kept.append(Path(protect))
    removed: list[Path] = []
    for path in candidates:
        if protect is not None and path.name == Path(protect).name:
            continue
        if path.name.casefold() in exempt:
            continue
        if len(kept) < keep:
            kept.append(path)
            continue
        if unknown:
            from .backup import is_version3_backup

            if not is_version3_backup(path):
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
    protect_old: Iterable[str] | None = (),
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
    prune(directory, tag, keep, protect=destination, protect_old=protect_old)
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


def mirror_backup(source: Path, mirror_dir: Path | str, *, tag: str, keep: int,
                  protect_old: Iterable[str] | None = (), expected_sha256: str = "") -> Path:
    """Copy one finished scheduled backup into the mirror folder atomically.

    The copy must match ``expected_sha256`` (the digest recorded as ``last_sha256`` when the backup was
    published) when given, else the source file as it is now.
    """
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
        if _sha256(temporary) != (expected_sha256 or _sha256(source)):
            raise MirrorError("The mirror copy did not match the backup")
        os.replace(temporary, destination)
    except MirrorError:
        raise
    except OSError as exc:
        raise MirrorError("Could not copy the backup to the mirror folder") from exc
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)
    prune(mirror, tag, keep, protect=destination, protect_old=protect_old)
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
    protect_old: Iterable[str] | None = (),
) -> RunResult:
    """Make one scheduled backup, record it, then mirror it if configured.

    Raises ScheduleError when the local backup fails (nothing is recorded or
    deleted).  Mirror problems are logged and returned as a warning.
    """
    protect_old = None if protect_old is None else tuple(protect_old)
    path = write_scheduled_backup(directory, tag=tag, when=when, keep=keep,
                                  make_backup=make_backup, verify=verify, protect_old=protect_old)
    digest = ""
    try:
        digest = _sha256(path)
        write_last_success(directory, when, sha256=digest)
    except OSError as exc:
        if log is not None:
            log("scheduled-backup-state", exc)
    if not str(mirror_dir or "").strip():
        return RunResult(path)
    try:
        return RunResult(path, mirror_backup(path, mirror_dir, tag=tag, keep=keep, protect_old=protect_old,
                                             expected_sha256=digest))
    except Exception as exc:  # noqa: BLE001 - a mirror problem never fails the local backup
        if log is not None:
            log("backup-mirror", exc)
        message = str(exc) if isinstance(exc, MirrorError) else "Could not copy the backup to the mirror folder"
        return RunResult(path, None, message)


def full_backup_functions(*, profile_dir: Path, profile_name: str, record: dict[str, Any],
                          current_record: Callable[[], dict[str, Any] | None] | None = None,
                          vault_filter: Callable[[dict[str, Any]], dict[str, Any]] | None = None,
                          ) -> tuple[Callable[[Path], Any], Callable[[Path], Any]]:
    """Return (make, verify) callables for a version 3 full backup locked to the public key ``record``.

    ``vault_filter``: what the vault file becomes in the backup (``backup.without_share_records``).

    ``verify`` is the design's section 9.1 check, which needs no password: the structure, the key wrap
    (with the writer's ephemeral key, against the record as it is *now*: ``current_record()`` when
    given, else ``record``) and a restore preflight dry run with the data key.  The writer's data key
    and ephemeral key are wiped when ``verify`` ends, and also when ``make`` fails.
    """
    from .backup import BackupError, export_full_backup_to_key

    held: dict[str, Any] = {}

    def make(path: Path) -> Any:
        stale = held.pop("verifier", None)
        if stale is not None:
            stale.wipe()
        result = export_full_backup_to_key(path, record=record, profile_dir=profile_dir,
                                           profile_name=profile_name, vault_filter=vault_filter)
        held["verifier"] = result["verifier"]
        return result

    def verify(path: Path) -> Any:
        verifier = held.pop("verifier", None)
        if verifier is None:
            raise BackupError("The scheduled backup was not written by this run")
        with verifier:
            now = current_record() if current_record is not None else record
            if now is None:
                raise BackupError("The backup key was removed while the backup was written")
            return verifier.verify(path, record=now)

    def discard() -> None:
        verifier = held.pop("verifier", None)
        if verifier is not None:
            verifier.wipe()

    make.discard = discard  # type: ignore[attr-defined] - the run's finally wipes a verifier never reached
    return make, verify
