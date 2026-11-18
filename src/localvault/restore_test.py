"""Weekly backup restore test (sub-plan 12, Task 1).

Restores the newest encrypted backup into ``LOCALGATEKEYS_DATA_DIR/restore-test/<uuid>``, unlocks it once, counts
its items and deletes the scratch folder again. The live vault is never touched. The result (no secret, no title)
is kept in ``restore-test.json`` next to the profile's settings so Security check can show
"Last backup restore test: passed N days ago / failed: reason / never run".
"""
from __future__ import annotations

import dataclasses
import shutil
import uuid
from pathlib import Path
from typing import Any

from .backup import RestoreTestFailure, restore_to_scratch
from .config import atomic_write_json, data_dir, read_json
from .i18n import t
from .secret_text import SecretText

WEEK = 7 * 24 * 3600
REASONS = ("unreadable", "old_password", "no_backup")
STATE_FILE = "restore-test.json"


@dataclasses.dataclass(frozen=True)
class RestoreTestResult:
    ok: bool
    backup_path: str
    backup_age: int  # seconds between the backup's export and the test
    items: int
    reason: str  # "" when ok, else one of REASONS
    tested_at: int = 0


def scratch_root() -> Path:
    return data_dir() / "restore-test"


def newest_backup(directory: Path) -> Path | None:
    try:
        rows = [p for p in Path(directory).glob("*.lgk") if p.is_file()]
    except OSError:
        return None
    return max(rows, key=lambda p: p.stat().st_mtime, default=None)


def run(settings: Any, now: int, *, backup_path: Path | None, backup_password: str | SecretText,
        vault_password: str | SecretText | None = None) -> RestoreTestResult:
    """Test-restore ``backup_path``. ``settings`` is read only for ``restore_test_weekly`` callers; unused here."""
    del settings
    if backup_path is None or not Path(backup_path).is_file():
        return RestoreTestResult(False, str(backup_path or ""), 0, 0, "no_backup", int(now))
    scratch = scratch_root() / str(uuid.uuid4())
    try:
        if Path(backup_path).suffix.lower() == ".lgkfull":
            return _run_full(Path(backup_path), backup_password, vault_password, scratch, int(now))
        restored = restore_to_scratch(Path(backup_path), backup_password, scratch, vault_password=vault_password)
    except RestoreTestFailure as exc:
        return RestoreTestResult(False, str(backup_path), 0, 0, exc.reason, int(now))
    finally:
        shutil.rmtree(scratch, ignore_errors=True)
    age = max(0, int(now) - restored.exported_at) if restored.exported_at else 0
    return RestoreTestResult(True, str(backup_path), age, restored.items, "", int(now))


def _run_full(path: Path, backup_password: str | SecretText, vault_password: str | SecretText | None,
              scratch: Path, now: int) -> RestoreTestResult:
    """A full (.lgkfull v2/v3) backup: the restore preflight dry run, staged inside ``scratch``."""
    from .backup import BackupError, preflight_full_backup
    from .secret_text import as_secret

    owned: list[SecretText] = []

    def secret(value: str | SecretText) -> SecretText:
        text, mine = as_secret(value)
        if mine:
            owned.append(text)
        return text

    try:
        # Staged inside ``scratch`` (in the data folder), never beside the backup: it may sit in a mirror (cloud)
        # folder, and the stage holds the inner layer with the backup password removed (scan core 3, M1).
        kwargs: dict[str, Any] = {"profile_dir": scratch / "profile", "backup_password": secret(backup_password),
                                  "_stage_parent": scratch / "stage"}
        if vault_password is not None:
            kwargs.update(vault_password=secret(vault_password), validate_vault_password=True)
        info = preflight_full_backup(path, **kwargs)
    except BackupError as exc:
        reason = "old_password" if "password" in str(exc).lower() else "unreadable"
        return RestoreTestResult(False, str(path), 0, 0, reason, now)
    except Exception:  # noqa: BLE001 - a vault that does not open with the given password, or a damaged file
        return RestoreTestResult(False, str(path), 0, 0, "old_password" if vault_password else "unreadable", now)
    finally:
        for text in owned:
            text.wipe()
    return RestoreTestResult(True, str(path), 0, int(info.get("vault_entries") or 0), "", now)


def record_scheduled(state: Path, backup_path: Path | None, now: int) -> RestoreTestResult:
    """The weekly test for scheduled backups: the writer's self-verify already ran the full restore dry run with
    its in-memory data key (``KeyBackupVerifier``), so a verified scheduled backup is recorded as a passed test.
    The backup password is never needed or kept."""
    result = RestoreTestResult(True, str(backup_path or ""), 0, 0, "", int(now))
    save(state, result)
    return result


def run_at_unlock(session: Any, state: Path, now: int, *, enabled: bool) -> RestoreTestResult | None:
    """The weekly test when no scheduled backup recorded one: at unlock, open the newest rolling backup with the
    unlocked session's data key (``VaultSession.check_rolling_backup``). No password is asked for or stored.
    ``None`` when the test is not due or there is nothing to test."""
    if not due(load(state), now, enabled=enabled):
        return None
    try:
        found = session.check_rolling_backup()
    except Exception:  # noqa: BLE001 - a damaged or foreign file: the test failed, say so
        result = RestoreTestResult(False, "", 0, 0, "unreadable", int(now))
    else:
        if found is None:
            return None
        path, items = found
        result = RestoreTestResult(True, str(path), max(0, int(now) - int(path.stat().st_mtime)), items, "", int(now))
    save(state, result)
    return result


def state_path(profile_dir: Path) -> Path:
    return Path(profile_dir) / STATE_FILE


def due(last: RestoreTestResult | None, now: int, *, enabled: bool) -> bool:
    return bool(enabled) and (last is None or int(now) - last.tested_at >= WEEK)


def save(path: Path, result: RestoreTestResult) -> None:
    atomic_write_json(Path(path), dataclasses.asdict(result))


def load(path: Path) -> RestoreTestResult | None:
    try:
        raw = read_json(Path(path))
        if not isinstance(raw, dict):
            return None
        reason = str(raw.get("reason", ""))
        if reason and reason not in REASONS:
            return None
        return RestoreTestResult(bool(raw["ok"]), str(raw["backup_path"]), int(raw["backup_age"]),
                                 int(raw["items"]), reason, int(raw.get("tested_at", 0)))
    except (OSError, ValueError, KeyError, TypeError):
        return None


def row_text(result: RestoreTestResult | None, now: int) -> str:
    """The Security check row text for the last result."""
    if result is None:
        return t("restoreTest.neverRun")
    if result.ok:
        return t("restoreTest.passed", days=max(0, (int(now) - result.tested_at) // 86400))
    return t("restoreTest.failed", reason=t(f"restoreTest.reason.{result.reason}"))
