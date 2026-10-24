from __future__ import annotations

import json
import shutil
import time
import uuid
from pathlib import Path
from typing import Any

from .config import atomic_write_json, data_dir, legacy_data_dir

MIGRATION_STATE_VERSION = 2
MIGRATION_STATE_FILE = "legacy-migration.json"
MIGRATION_JOURNAL_VERSION = 1
MIGRATION_JOURNAL_FILE = "legacy-migration.journal.json"
LEGACY_PROFILE_FILES = ("vault.json", "settings.json", "trusted-apps.json")
LEGACY_PROFILE_DIRS = ("Backups",)


class MigrationError(Exception):
    pass


def migration_state_path(root: Path | None = None) -> Path:
    return (root or data_dir()) / MIGRATION_STATE_FILE


def migration_journal_path(root: Path | None = None) -> Path:
    """Return the durable legacy-import journal path for ``root``."""
    return (root or data_dir()) / MIGRATION_JOURNAL_FILE


def _read_json_object(path: Path, label: str) -> dict[str, Any] | None:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return None
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        raise MigrationError(f"{label} is damaged; recovery is required") from exc
    if not isinstance(value, dict):
        raise MigrationError(f"{label} is malformed; recovery is required")
    return value


def _state_value(root: Path) -> dict[str, Any] | None:
    value = _read_json_object(migration_state_path(root), "Migration state")
    if value is None:
        return None
    try:
        version = int(value.get("version", 0))
    except (TypeError, ValueError) as exc:
        raise MigrationError("Migration state version is malformed") from exc
    if version > MIGRATION_STATE_VERSION:
        raise MigrationError("Migration state was written by a newer LocalGateKeys version")
    if version not in (1, MIGRATION_STATE_VERSION):
        raise MigrationError("Unsupported migration state version")
    return value


def _safe_profile_path(root: Path, profile_id: str, *, staging: bool) -> Path:
    """Resolve only paths that this module could have created itself."""
    try:
        normalized = str(uuid.UUID(profile_id))
    except (ValueError, AttributeError, TypeError):
        raise MigrationError("Migration journal contains an invalid profile id") from None
    name = f".migration-{normalized}" if staging else normalized
    profiles = (root / "Profiles").resolve()
    path = (profiles / name).resolve()
    if path.parent != profiles or (staging and not path.name.startswith(".migration-")):
        raise MigrationError("Migration journal contains an unsafe path")
    return path


def _journal_payload(root: Path) -> dict[str, Any] | None:
    value = _read_json_object(migration_journal_path(root), "Migration journal")
    if value is None:
        return None
    try:
        version = int(value.get("version", 0))
    except (TypeError, ValueError) as exc:
        raise MigrationError("Migration journal version is malformed") from exc
    if version > MIGRATION_JOURNAL_VERSION:
        raise MigrationError("Migration journal was written by a newer LocalGateKeys version")
    if version != MIGRATION_JOURNAL_VERSION or value.get("operation") != "legacy-import":
        raise MigrationError("Unsupported migration journal")
    profile_id = value.get("profile_id")
    if not isinstance(profile_id, str):
        raise MigrationError("Migration journal profile id is missing")
    _safe_profile_path(root, profile_id, staging=True)
    _safe_profile_path(root, profile_id, staging=False)
    status = value.get("status")
    if status not in {"prepared", "staged", "profile_published", "index_published"}:
        raise MigrationError("Migration journal status is unsupported")
    return value


def _profile_index_matches(root: Path, profile_id: str) -> bool:
    value = _read_json_object(root / "profiles.json", "Profile index")
    if value is None:
        return False
    rows = value.get("profiles")
    if not isinstance(rows, list):
        return False
    return any(isinstance(row, dict) and str(row.get("id")) == profile_id for row in rows)


def _remove_owned_path(path: Path) -> None:
    if path.is_symlink() or path.is_file():
        path.unlink(missing_ok=True)
    elif path.is_dir():
        shutil.rmtree(path)


def recover_legacy_migration(root: Path | None = None) -> str | None:
    """Recover an interrupted legacy import before the next startup.

    A journal is considered committed only when the final migration decision,
    profile index, and profile directory all exist.  Any earlier phase is
    rolled back to the pre-import state.  The source tree is never modified.
    """
    root = (root or data_dir()).resolve()
    journal = _journal_payload(root)
    if journal is None:
        return None
    profile_id = str(journal["profile_id"])
    staging = _safe_profile_path(root, profile_id, staging=True)
    profile_dir = _safe_profile_path(root, profile_id, staging=False)
    state_path = migration_state_path(root)
    state = _state_value(root)
    committed = (
        state is not None
        and state.get("decision") == "imported"
        and _profile_index_matches(root, profile_id)
        and profile_dir.is_dir()
    )
    if committed:
        migration_journal_path(root).unlink(missing_ok=True)
        return "imported"

    # The current import contract starts with no profile index.  Remove only
    # paths named by the journal, leaving installer metadata and user files
    # outside the operation untouched.
    if _profile_index_matches(root, profile_id):
        (root / "profiles.json").unlink(missing_ok=True)
    _remove_owned_path(staging)
    _remove_owned_path(profile_dir)
    if state is not None and state.get("decision") == "imported":
        state_path.unlink(missing_ok=True)
    migration_journal_path(root).unlink(missing_ok=True)
    profiles = root / "Profiles"
    if profiles.is_dir() and not any(profiles.iterdir()):
        profiles.rmdir()
    return "rolled_back"


def localgatekeys_user_data_exists(root: Path | None = None) -> bool:
    """Return True only for real user data, not installer/runtime metadata."""
    root = root or data_dir()
    if (root / "profiles.json").is_file() or (root / "vault.json").is_file():
        return True
    profiles = root / "Profiles"
    if profiles.is_dir():
        for child in profiles.iterdir():
            if child.is_dir() and not child.name.startswith(".migration-") \
                    and any((child / name).exists() for name in LEGACY_PROFILE_FILES):
                return True
    return False


def legacy_user_data_exists(root: Path | None = None) -> bool:
    root = root or legacy_data_dir()
    return (root / "vault.json").is_file()


def migration_decision(root: Path | None = None) -> str | None:
    root = (root or data_dir()).resolve()
    recover_legacy_migration(root)
    value = _state_value(root)
    if value is None:
        return None
    decision = str(value.get("decision", ""))
    return decision if decision in {"start_fresh", "imported"} else None


def migration_prompt_required(
    root: Path | None = None, legacy_root: Path | None = None
) -> bool:
    root = root or data_dir()
    legacy_root = legacy_root or legacy_data_dir()
    recover_legacy_migration(root)
    if localgatekeys_user_data_exists(root):
        return False
    if migration_decision(root) is not None:
        return False
    return legacy_user_data_exists(legacy_root)


def choose_start_fresh(root: Path | None = None, legacy_root: Path | None = None) -> None:
    """Persist the choice without modifying or deleting any legacy data."""
    root = root or data_dir()
    legacy_root = legacy_root or legacy_data_dir()
    recover_legacy_migration(root)
    root.mkdir(parents=True, exist_ok=True)
    atomic_write_json(
        migration_state_path(root),
        {
            "version": MIGRATION_STATE_VERSION,
            "decision": "start_fresh",
            "legacy_source": str(legacy_root),
            "decided_at": int(time.time()),
            "legacy_preserved": True,
        },
    )


def import_legacy_data(
    root: Path | None = None, legacy_root: Path | None = None
) -> str:
    """Copy legacy user data into a new profile; the source is never changed."""
    root = root or data_dir()
    legacy_root = legacy_root or legacy_data_dir()
    recover_legacy_migration(root)
    if localgatekeys_user_data_exists(root):
        raise MigrationError("LocalGateKeys data already exists; legacy import was not performed")
    if not legacy_user_data_exists(legacy_root):
        raise MigrationError("No legacy LocalVaultPrototype vault was found")

    profile_id = str(uuid.uuid4())
    profiles = root / "Profiles"
    profiles_existed = profiles.is_dir()
    profile_dir = _safe_profile_path(root, profile_id, staging=False)
    staging_dir = _safe_profile_path(root, profile_id, staging=True)
    profiles.mkdir(parents=True, exist_ok=True)
    try:
        atomic_write_json(
            migration_journal_path(root),
            {
                "version": MIGRATION_JOURNAL_VERSION,
                "operation": "legacy-import",
                "status": "prepared",
                "profile_id": profile_id,
                "legacy_source": str(legacy_root),
                "started_at": int(time.time()),
                "profiles_dir_existed": profiles_existed,
            },
        )
        staging_dir.mkdir(parents=True, exist_ok=False)
        for name in LEGACY_PROFILE_FILES:
            source = legacy_root / name
            if source.is_file():
                shutil.copy2(source, staging_dir / name)
        for name in LEGACY_PROFILE_DIRS:
            source = legacy_root / name
            if source.is_dir():
                shutil.copytree(source, staging_dir / name)

        atomic_write_json(
            migration_journal_path(root),
            {
                "version": MIGRATION_JOURNAL_VERSION,
                "operation": "legacy-import",
                "status": "staged",
                "profile_id": profile_id,
                "legacy_source": str(legacy_root),
                "started_at": int(time.time()),
                "profiles_dir_existed": profiles_existed,
            },
        )
        staging_dir.replace(profile_dir)
        atomic_write_json(
            migration_journal_path(root),
            {
                "version": MIGRATION_JOURNAL_VERSION,
                "operation": "legacy-import",
                "status": "profile_published",
                "profile_id": profile_id,
                "legacy_source": str(legacy_root),
                "started_at": int(time.time()),
                "profiles_dir_existed": profiles_existed,
            },
        )

        now = int(time.time())
        index: dict[str, Any] = {
            "version": 1,
            "active_profile_id": profile_id,
            "profiles": [
                {
                    "id": profile_id,
                    "name": "My profile",
                    "color": "#28C7FA",
                    "created_at": now,
                    "last_used_at": now,
                }
            ],
            "migration": {
                "source": str(legacy_root),
                "copied_at": now,
                "legacy_preserved": True,
                "explicit": True,
            },
        }
        atomic_write_json(root / "profiles.json", index)
        atomic_write_json(
            migration_journal_path(root),
            {
                "version": MIGRATION_JOURNAL_VERSION,
                "operation": "legacy-import",
                "status": "index_published",
                "profile_id": profile_id,
                "legacy_source": str(legacy_root),
                "started_at": int(time.time()),
                "profiles_dir_existed": profiles_existed,
            },
        )
        atomic_write_json(
            migration_state_path(root),
            {
                "version": MIGRATION_STATE_VERSION,
                "decision": "imported",
                "legacy_source": str(legacy_root),
                "profile_id": profile_id,
                "decided_at": now,
                "legacy_preserved": True,
            },
        )
        migration_journal_path(root).unlink(missing_ok=True)
        return profile_id
    except Exception:
        # If a write raised after replace, inspect the journal and restore the
        # old complete state.  A process killed between these lines is handled
        # by recover_legacy_migration() on the next startup.
        try:
            recover_legacy_migration(root)
        except MigrationError:
            # Preserve the original failure while leaving the journal for a
            # later explicit recovery attempt rather than deleting unknown data.
            pass
        _remove_owned_path(staging_dir)
        raise
