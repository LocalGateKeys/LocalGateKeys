"""Getting started (the seven-stage setup guide) for the WebView UI, from ``FeatureUI.onboarding_clicked``.

Progress lives in the profile's ``onboarding.json`` through the Tk-free
``OnboardingController``; only choices and stage names are stored. Stages
that need another screen return a ``route`` for the page to open.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any, Callable

from ..api.result import ApiError

STAGES = ("welcome", "security", "demo", "bridge_diagnostic", "first_item", "backup", "complete")
LABELS = {"welcome": "Welcome", "security": "Security check", "demo": "Safe walkthrough",
          "bridge_diagnostic": "Browser connection", "first_item": "First item", "backup": "Recovery backup",
          "complete": "Complete"}
PRIMARY = {"welcome": "Save safety choice", "security": "Review security", "demo": "Save demo choice",
           "bridge_diagnostic": "Test connection", "first_item": "Add first item", "backup": "Verify backup",
           "complete": "Done"}
SPECS = {
    "welcome": ("Choose the local safety default for this profile.",
                "Choose whether to keep strict offline mode enabled."),
    "security": ("Review password health and session controls.", "Open Security check."),
    "demo": ("Choose whether to open the safe metadata walkthrough.",
             "Save your choice. No demo records or secrets are created."),
    "bridge_diagnostic": ("Check the local browser connection.",
                          "Test the connection. If it is unavailable, retry or open Connections."),
    "first_item": ("Add a real item to the active profile.", "Save an item in Add item, then confirm it here."),
    "backup": ("Create and verify an encrypted recovery backup.",
               "Verify a backup in Backups & recovery, then confirm it here."),
    "complete": ("Review completed or skipped steps. You can return to setup anytime.",
                 "Select Done to close onboarding."),
}
INTRO = ("Nothing is filled or shared automatically during setup. You choose which optional connections to enable.")


def _collect_report() -> dict[str, Any]:
    from ..bridge_diagnostics import collect_report

    return collect_report()


class OnboardingWebService:
    def __init__(self, controller: Any, recovery: Any = None, *,
                 diagnostics: Callable[[], dict[str, Any]] = _collect_report,
                 apply_setting: Callable[[str, Any], Any] | None = None) -> None:
        self._controller = controller
        self._recovery = recovery
        self._diagnostics = diagnostics
        self._apply_setting = apply_setting or self._save_setting
        self._connection: bool | None = None
        self._message = ""
        self._first_item_count: int | None = None
        self._flow: Any = None
        self._flow_key: Any = None
        controller.on_lock.append(self._reset)

    def _save_setting(self, key: str, value: Any) -> None:
        settings = self._controller.settings
        setattr(settings, key, value)
        try:
            settings.save()
        except OSError:
            raise ApiError("invalid", "The setting could not be saved.") from None

    def test_connection(self) -> dict[str, Any]:
        """The browser-connection check, run as its own call (outside the vault lock): it can take seconds."""
        try:
            report = self._diagnostics()
        except Exception:  # noqa: BLE001 - an unavailable bridge is a normal answer here
            report = {}
        connection = report.get("connection", {}) if isinstance(report, dict) else {}
        self._connection = connection.get("status") == "connected"
        return {"connected": self._connection}

    def _reset(self) -> None:
        if self._flow is not None:
            try:
                self._flow.invalidate()
            except Exception:  # noqa: BLE001, S110
                pass
        self._flow = None
        self._message = ""
        self._first_item_count = None

    def _onboarding(self) -> Any:
        from ..next_release_ui import OnboardingController, OnboardingStore

        controller = self._controller
        if not controller.is_unlocked():
            raise ApiError("locked", "Unlock this profile first.")
        lease = controller.guard.lease()
        controller.require_lease(lease)
        profile = controller.profiles.active_profile()
        key = (profile.id, controller.guard.stamp())
        if self._flow is None or self._flow_key != key:
            store = OnboardingStore(Path(controller.session.path).parent / "onboarding.json")
            self._flow = OnboardingController(str(profile.id), store,
                                              session_checker=lambda: controller.require_lease(lease))
            self._flow_key = key
        return self._flow

    def view(self) -> dict[str, Any]:
        flow = self._onboarding()
        state = flow.state
        stage = state.stage
        purpose, action = SPECS[stage]
        status = ("Completed" if stage in state.completed else "Skipped" if stage in state.skipped else "Pending")
        primary = PRIMARY[stage]
        if self._message and stage == "first_item":
            primary = "Confirm saved item"
            action = "Save a real item in Add item, then select Confirm saved item."
        elif self._message and stage == "backup":
            primary = "Confirm backup"
        return {
            "title": "Getting started",
            "subtitle": "Follow setup at your pace. Progress is saved locally and can be resumed later.",
            "intro": INTRO,
            "stages": [{"key": s, "label": LABELS[s], "state": "done" if s in state.completed else "skipped"
                        if s in state.skipped else "current" if s == stage else "todo"} for s in STAGES],
            "stage": stage, "heading": f"Stage {STAGES.index(stage) + 1} of {len(STAGES)} · {LABELS[stage]}",
            "purpose": purpose, "action": f"Next: {action}", "status": self._message or status,
            "primary": primary, "can_skip": stage != "complete",
            "offline": bool(getattr(self._controller.settings, "strict_offline_mode", True)),
        }

    def _next(self, flow: Any, stage: str) -> None:
        index = STAGES.index(stage)
        if index < len(STAGES) - 1:
            flow.advance(STAGES[index + 1])
        self._message = ""

    def perform(self, choice: bool | None = None) -> dict[str, Any]:
        flow = self._onboarding()
        stage = flow.state.stage
        route = None
        if stage == "welcome":
            value = bool(choice) if choice is not None else True
            self._apply_setting("strict_offline_mode", value)  # through Settings: validation, events
            flow.choose("offline_mode", value)
            self._next(flow, stage)
        elif stage == "security":
            route = {"route": "security"}
            self._next(flow, stage)
        elif stage == "demo":
            value = bool(choice)
            flow.choose("demo_enabled", value)
            if value:
                route = {"route": "collections"}
            self._next(flow, stage)
        elif stage == "bridge_diagnostic":
            if self._connection is None:
                self.test_connection()  # the page normally ran it already, outside the vault lock
            connected, self._connection = self._connection, None
            if not connected:
                self._message = "Connection unavailable. Retry or open Connections for help."
            else:
                flow.choose("bridge_diagnostic", True)
                self._next(flow, stage)
        elif stage == "first_item":
            count = len(self._controller.session.item_service.all_metadata_summaries())
            if self._first_item_count is None:
                self._first_item_count = count
                self._message = "Add item is open. Save an item in your profile, then confirm below."
                route = {"route": "new-item"}
            elif count <= self._first_item_count:
                self._message = "No saved item yet. Save one in Add item, then confirm below."
            else:
                flow.choose("first_item_created", True)
                self._next(flow, stage)
        elif stage == "backup":
            if not getattr(self._recovery, "verified_backup", False):
                self._message = "Backups & recovery is open. Verify a backup, then confirm below."
                route = {"route": "recovery", "params": {"initial": "verify"}}
            else:
                flow.choose("backup_verified", True)
                self._next(flow, stage)
        elif stage == "complete":
            return {**self.view(), "done": True}
        return {**self.view(), **({"open": route} if route else {})}

    def skip(self) -> dict[str, Any]:
        flow = self._onboarding()
        stage = flow.state.stage
        if stage == "complete":
            return self.view()
        # One save: advance (which marks the stage completed), then mark it skipped instead.
        index = STAGES.index(stage)
        state = flow._state
        state.advance(STAGES[index + 1])
        state.skip(stage)
        flow._save()
        self._message = ""
        return self.view()
