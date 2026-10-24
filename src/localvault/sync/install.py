"""This installation's sync identity: a random id kept in the data directory, not in the vault.

A vault stores the install id it joined a sync group on
(``SyncGroupState.install_id``).  When the vault is copied or restored onto
another PC, the ids differ and every transport answers ``rejoin-required``
instead of syncing under a cloned device id (cloned ids would corrupt version
vectors).  The file is created on first use with a random uuid4 and an atomic
write.  Only a missing file (``FileNotFoundError``) or one that does not parse
or validate gets a new id; a malformed file is first renamed to ``.bad`` and
logged.  Any other ``OSError`` (locked, permissions, I/O) propagates, so the
caller skips sync for this unlock instead of rotating this installation's
identity (which would force every vault on this PC to re-join).
"""
from __future__ import annotations

import json
import logging
import os
import uuid
from pathlib import Path

from .. import config

INSTALL_ID_FILENAME = "sync-install-id.json"
_VERSION = 1
_MISSING = object()
_MALFORMED = object()
_log = logging.getLogger(__name__)


def install_id_path(directory: Path | str | None = None) -> Path:
    root = Path(directory) if directory is not None else config.data_dir()
    return root / INSTALL_ID_FILENAME


def _read(path: Path) -> object:
    """The stored id, ``_MISSING`` or ``_MALFORMED``; other OSErrors propagate."""
    try:
        text = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        return _MISSING
    except UnicodeDecodeError:
        return _MALFORMED
    try:
        raw = json.loads(text)
    except ValueError:
        return _MALFORMED
    value = _validated(raw)
    return _MALFORMED if value is None else value


def _validated(raw: object) -> str | None:
    if not isinstance(raw, dict) or raw.get("version") != _VERSION:
        return None
    value = raw.get("install_id")
    if not isinstance(value, str):
        return None
    try:
        parsed = uuid.UUID(value)
    except ValueError:
        return None
    return value if str(parsed) == value and parsed.version == 4 else None


def load_or_create_install_id(directory: Path | str | None = None) -> str:
    """The stored install id; creates it (uuid4, atomic write) only when missing or malformed.

    Raises ``OSError`` when the file exists but cannot be read, or the new one
    cannot be written.
    """
    path = install_id_path(directory)
    existing = _read(path)
    if isinstance(existing, str):
        return existing
    if existing is _MALFORMED:
        bad = path.with_name(path.name + ".bad")
        os.replace(path, bad)
        _log.warning("sync install id file was malformed; kept it as %s and created a new id", bad.name)
    config.atomic_write_json(path, {"version": _VERSION, "install_id": str(uuid.uuid4())})
    stored = _read(path)
    if not isinstance(stored, str):
        raise OSError("The sync install id could not be stored")
    return stored


__all__ = ["INSTALL_ID_FILENAME", "install_id_path", "load_or_create_install_id"]
