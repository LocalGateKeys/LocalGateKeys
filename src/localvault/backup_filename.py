"""Small helpers for user-facing encrypted backup filenames.

The encrypted recovery container owns its format and authentication in
``localvault.recovery``.  This module only keeps the native Save As options
and the final filename validation in one place so a picker cannot accidentally
turn a backup into an ambiguously named file.
"""
from __future__ import annotations

import os
from collections.abc import Callable
from datetime import date, datetime
from pathlib import Path
from typing import Any

BACKUP_EXTENSION = ".lgk"
BACKUP_FILETYPES = (
    ("LocalGateKeys backup (*.lgk)", "*.lgk"),
)


class BackupFilenameError(ValueError):
    """Raised when a selected backup destination cannot be used safely."""


def _clock_value(clock: Callable[[], Any] | None) -> datetime:
    value = clock() if clock is not None else datetime.now().astimezone()
    if isinstance(value, datetime):
        return value
    if isinstance(value, date):
        return datetime.combine(value, datetime.min.time())
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        try:
            return datetime.fromtimestamp(value).astimezone()
        except (OverflowError, OSError, ValueError) as exc:
            raise BackupFilenameError("The backup clock returned an invalid time") from exc
    raise BackupFilenameError("The backup clock must return a date or datetime")


def default_backup_filename(
    *,
    now: datetime | date | None = None,
    clock: Callable[[], Any] | None = None,
) -> str:
    """Return a nonempty, stable, local-time suggestion for Recovery Save As."""

    if now is not None and clock is not None:
        raise BackupFilenameError("Specify either now or clock, not both")
    value = now if now is not None else _clock_value(clock)
    if not isinstance(value, datetime):
        if isinstance(value, date):
            value = datetime.combine(value, datetime.min.time())
        else:  # defensive: ``now`` is typed, but callers may be dynamic
            raise BackupFilenameError("The backup time is malformed")
    return f"LocalGateKeys-backup-{value.strftime('%Y-%m-%d-%H%M%S')}{BACKUP_EXTENSION}"


def backup_save_as_options(
    *,
    now: datetime | date | None = None,
    clock: Callable[[], Any] | None = None,
) -> dict[str, Any]:
    """Return native ``asksaveasfilename`` options for encrypted backups."""

    return {
        "initialfile": default_backup_filename(now=now, clock=clock),
        "defaultextension": BACKUP_EXTENSION,
        "filetypes": BACKUP_FILETYPES,
    }


def normalize_backup_filename(value: Path | str, *, extension: str = BACKUP_EXTENSION) -> Path:
    """Normalize one selected destination without changing its parent.

    A missing suffix receives the canonical extension once.  A suffix with a
    different meaning is rejected so the caller cannot publish a misleading
    ``.txt`` or ``.json`` file containing an encrypted recovery container.
    Existing case is preserved when the user supplied the accepted suffix.
    """

    if not isinstance(extension, str) or not extension.startswith(".") or "/" in extension or "\\" in extension:
        raise BackupFilenameError("The backup extension is malformed")
    extension = extension.casefold()
    try:
        raw = os.fspath(value)
    except TypeError as exc:
        raise BackupFilenameError("Choose a backup filename") from exc
    if not isinstance(raw, str) or not raw.strip() or "\x00" in raw:
        raise BackupFilenameError("Choose a backup filename")
    if raw.startswith(("\\\\", "//")) or "://" in raw:
        raise BackupFilenameError("Backup destination must be a local path")
    try:
        path = Path(raw)
    except (OSError, RuntimeError, ValueError) as exc:
        raise BackupFilenameError("Choose a usable backup filename") from exc
    if path.name in {"", ".", ".."}:
        raise BackupFilenameError("Choose a backup filename")
    # ``Path('.lgk').suffix`` is empty on some Python versions; checking the
    # name first guarantees that even this edge case is normalized once.
    if path.name.casefold().endswith(extension):
        return path
    suffix = path.suffix.casefold()
    if suffix:
        raise BackupFilenameError(
            f"Backup filename must end in {extension} (or omit the extension)"
        )
    return path.with_name(path.name + extension)


# Descriptive aliases for callers that use the destination/path terminology.
normalize_backup_destination = normalize_backup_filename
recovery_backup_save_as_options = backup_save_as_options


__all__ = [
    "BACKUP_EXTENSION",
    "BACKUP_FILETYPES",
    "BackupFilenameError",
    "backup_save_as_options",
    "default_backup_filename",
    "normalize_backup_destination",
    "normalize_backup_filename",
    "recovery_backup_save_as_options",
]
