"""The run log of ``run_with_secrets``: which agent ran which command line, where, with which item fields.

The hash-chained activity log keeps each run's item ids (``agent.request``, ``agent.read``, ``agent.complete``), but
its events have no room for text, and the vault format stays as it is. The command line and the field names go here
instead: a small file in the profile folder, encrypted for this Windows account with DPAPI, newest
``MAX_RECORDS`` rows. It never holds a value: rows are rebuilt from a fixed set of keys. Without DPAPI (not Windows)
nothing is written to disk and the rows live for this app session only.
"""
from __future__ import annotations

import base64
import json
import threading
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

MAX_RECORDS = 200
FILE_NAME = "agent-runs.json"
_ENTROPY = b"LocalGateKeys agent run log v1"
_TEXT = {"stage": 16, "run": 64, "agent": 80, "process": 80, "command": 8000, "cwd": 1024, "purpose": 300,
         "result": 32}
_ITEM = {"variable": 128, "item_id": 64, "field": 100}
# "filled": an agent's approved password fill reached a page (one login id, no command); agent_exposure reads it.
STAGES = ("refused", "denied", "approved", "released", "finished", "filled")


def run_log_path(controller: Any) -> Path | None:
    """The log file of the active profile, or None when there is none."""
    profiles = getattr(controller, "profiles", None)
    try:
        if profiles is None or profiles.active_profile() is None:
            return None
        return Path(profiles.profile_dir()) / FILE_NAME
    except Exception:  # noqa: BLE001 - no profile folder: memory only
        return None


def clean_record(record: Any) -> dict[str, Any] | None:
    """Only the known keys, bounded; anything else (a value among them) is dropped."""
    if not isinstance(record, dict) or record.get("stage") not in STAGES:
        return None
    out: dict[str, Any] = {}
    for key, limit in _TEXT.items():
        value = record.get(key)
        if isinstance(value, str):
            out[key] = value[:limit]
    at = record.get("at")
    out["at"] = at if type(at) is int and at >= 0 else 0
    for key in ("timeout", "exit_code"):
        value = record.get(key)
        if type(value) is int:
            out[key] = value
    for key in ("timed_out", "started"):
        if isinstance(record.get(key), bool):
            out[key] = record[key]
    items = record.get("items")
    out["items"] = [{key: str(row.get(key, ""))[:limit] for key, limit in _ITEM.items()}
                    for row in (items if isinstance(items, list) else [])[:20] if isinstance(row, dict)]
    return out


def _dpapi() -> tuple[Callable[[bytes], bytes], Callable[[bytes], bytes]] | None:
    try:
        import win32crypt  # type: ignore[import-not-found]
    except Exception:  # noqa: BLE001 - not Windows: memory only
        return None

    def protect(data: bytes) -> bytes:
        return bytes(win32crypt.CryptProtectData(data, None, _ENTROPY, None, None, 0x1))

    def unprotect(blob: bytes) -> bytes:
        return bytes(win32crypt.CryptUnprotectData(blob, _ENTROPY, None, None, 0x1)[1])
    return protect, unprotect


class AgentRunLog:
    def __init__(self, path: Callable[[], Path | None] | Path | None = None, *,
                 crypto: tuple[Callable[[bytes], bytes], Callable[[bytes], bytes]] | None | bool = True,
                 clock: Callable[[], float] = time.time) -> None:
        self._path = path if callable(path) else (lambda: path)
        self._crypto = _dpapi() if crypto is True else (crypto or None)
        self._clock = clock
        self._lock = threading.Lock()
        self._memory: list[dict[str, Any]] = []

    def _read(self, path: Path | None) -> list[dict[str, Any]]:
        if path is None or self._crypto is None:
            return list(self._memory)
        if not path.is_file():
            return []
        try:
            from .config import read_json

            blob = base64.b64decode(str(read_json(path).get("blob") or ""), validate=True)
            rows = json.loads(self._crypto[1](blob).decode("utf-8"))
        except Exception:  # noqa: BLE001 - unreadable (another account, damaged): start again
            return []
        if not isinstance(rows, list):
            return []
        return [row for row in (clean_record(r) for r in rows) if row]

    def append(self, record: dict[str, Any]) -> None:
        row = clean_record({**record, "at": int(self._clock())})
        if row is None:
            return
        with self._lock:
            path = self._path()
            rows = (self._read(path) + [row])[-MAX_RECORDS:]
            self._memory = rows
            if path is None or self._crypto is None:
                return
            from .config import atomic_write_json

            blob = self._crypto[0](json.dumps(rows, ensure_ascii=False).encode("utf-8"))
            atomic_write_json(path, {"version": 1, "blob": base64.b64encode(blob).decode("ascii")})

    def recent(self, limit: int = 20) -> list[dict[str, Any]]:
        """The newest rows first."""
        with self._lock:
            rows = self._read(self._path())
        return list(reversed(rows))[:max(0, int(limit))]
