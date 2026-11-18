"""Device-local switches that must never travel in a backup or a sync (auto-type, feature C4).

They live in ``device-settings.json`` in the data folder, not in ``AppSettings``: a full backup carries
``settings.json`` built from every ``AppSettings`` field (``backup._full_validate_settings`` uses
``dataclasses.asdict``), so a new field changes the committed v2/v3 backup vectors' bytes, and a restored or
synced backup must not switch auto-type on for another computer.

Unreadable, damaged or wrong-typed values read as the safe defaults: auto-type off, confirm on.
Nothing here holds a secret.
"""
from __future__ import annotations

import threading
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any

from .config import atomic_write_json, data_dir, read_json

FILENAME = "device-settings.json"
VERSION = 1


@dataclass(frozen=True)
class DeviceSettings:
    auto_type_enabled: bool = False
    auto_type_confirm_window: bool = True


class DeviceSettingsStore:
    """Read and write ``DeviceSettings``; ``path`` defaults to the data folder (resolved on each use)."""

    def __init__(self, path: Path | None = None) -> None:
        self._path = Path(path) if path is not None else None
        self._lock = threading.Lock()

    @property
    def path(self) -> Path:
        return self._path if self._path is not None else data_dir() / FILENAME

    def load(self) -> DeviceSettings:
        try:
            raw = read_json(self.path)
        except (OSError, ValueError):
            return DeviceSettings()
        auto_type: Any = raw.get("auto_type")
        auto_type = auto_type if isinstance(auto_type, dict) else {}
        return DeviceSettings(
            auto_type_enabled=auto_type.get("enabled") is True,
            # Anything but an explicit false keeps the confirm step.
            auto_type_confirm_window=auto_type.get("confirm") is not False,
        )

    def save(self, settings: DeviceSettings) -> DeviceSettings:
        with self._lock:
            try:
                raw = read_json(self.path)
            except (OSError, ValueError):
                raw = {}
            raw["version"] = VERSION
            raw["auto_type"] = {"enabled": settings.auto_type_enabled is True,
                                "confirm": settings.auto_type_confirm_window is not False}
            atomic_write_json(self.path, raw)
        return self.load()

    def update(self, **changes: bool) -> DeviceSettings:
        return self.save(replace(self.load(), **changes))


__all__ = ["DeviceSettings", "DeviceSettingsStore", "FILENAME"]
