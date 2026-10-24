"""Startup decisions for the WebView UI, from ``agent._handle_legacy_migration_prompt``.

Data from an earlier development version is never loaded automatically: the
page asks first (import a copy, or start fresh; both leave the original
untouched), and no profile is created until the user has chosen.
"""
from __future__ import annotations

import threading
from typing import Any, Callable

from ..api.result import ApiError

LEGACY_TITLE = "Legacy LocalGateKeys data found"
LEGACY_TEXT = ("LocalGateKeys found data from an earlier development version. It will not be loaded automatically.\n\n"
               "Import legacy data copies it into LocalGateKeys and keeps the original untouched. Start fresh ignores "
               "the legacy data and also leaves it untouched.")


def _required() -> bool:
    from ..migration import migration_prompt_required

    return migration_prompt_required()


def _import() -> str:
    from ..migration import import_legacy_data

    return import_legacy_data()


def _fresh() -> None:
    from ..migration import choose_start_fresh

    choose_start_fresh()


def _location() -> Any:
    from ..config import legacy_data_dir

    return legacy_data_dir()


class DeferredProfiles:
    """Stands in for ``ProfileManager`` until the legacy-data choice is made.

    ``ProfileManager()`` writes ``profiles.json`` at once, and that file counts
    as LocalGateKeys data, which would silently cancel the prompt. Until the
    choice is made there are no profiles, and anything that would create or
    change one is refused.
    """

    def __init__(self, root: Any = None) -> None:
        self._root = root
        self._real: Any = None

    def activate(self) -> Any:
        from ..profiles import ProfileManager

        if self._real is None:
            self._real = ProfileManager(self._root)
        return self._real

    def list_profiles(self) -> list[Any]:
        return self._real.list_profiles() if self._real is not None else []

    def active_profile(self) -> Any:
        return self._real.active_profile() if self._real is not None else None

    def __getattr__(self, name: str) -> Any:
        real = self.__dict__.get("_real")
        if real is None:
            raise ApiError("legacy_pending", "Choose what to do with the earlier data first.")
        return getattr(real, name)


def prepare_startup(*, root: Any = None, legacy_root: Any = None) -> tuple["StartupService", Any]:
    """Decide whether the legacy prompt is needed before any LocalGateKeys file is written."""
    from ..migration import choose_start_fresh, import_legacy_data, migration_prompt_required

    required = migration_prompt_required(root, legacy_root)
    profiles = DeferredProfiles(root)

    def location() -> Any:
        if legacy_root is not None:
            return legacy_root
        from ..config import legacy_data_dir

        return legacy_data_dir()

    startup = StartupService(profiles, required=lambda: required,
                             importer=lambda: import_legacy_data(root, legacy_root),
                             fresh=lambda: choose_start_fresh(root, legacy_root), location=location)
    if not required:
        profiles.activate()
        profiles.ensure_profile()
    return startup, profiles


class StartupService:
    def __init__(self, profiles: Any, *, required: Callable[[], bool] = _required,
                 importer: Callable[[], Any] = _import, fresh: Callable[[], None] = _fresh,
                 location: Callable[[], Any] = _location) -> None:
        self._profiles = profiles
        self._importer = importer
        self._fresh = fresh
        self._location = location
        self._lock = threading.Lock()
        self.pending = bool(required())
        self.on_ready: list[Callable[[], None]] = []

    def legacy_state(self) -> dict[str, Any]:
        return {"title": LEGACY_TITLE, "text": LEGACY_TEXT, "location": f"Legacy location: {self._location()}"}

    def _done(self) -> None:
        self.pending = False
        if hasattr(self._profiles, "activate"):
            self._profiles.activate()
        self._profiles.ensure_profile()
        for hook in list(self.on_ready):
            hook()

    def import_legacy(self) -> dict[str, Any]:
        from ..migration import MigrationError

        with self._lock:
            if not self.pending:
                raise ApiError("invalid", "This choice was already made.")
            try:
                self._importer()
            except (MigrationError, OSError, ValueError) as exc:
                raise ApiError("legacy_failed", f"Legacy data could not be imported.\n\n{exc}") from None
            self._done()
        return {}

    def fresh(self) -> dict[str, Any]:
        with self._lock:
            if not self.pending:
                raise ApiError("invalid", "This choice was already made.")
            try:
                self._fresh()
            except OSError as exc:
                raise ApiError("legacy_failed", str(exc) or "The choice could not be saved.") from None
            self._done()
        return {}
