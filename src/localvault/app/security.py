"""The Security center for the WebView UI.

Builds ``shell.security_model.security_center`` from secret-free inputs, the
same way ``FeatureUI._security_center_model`` does, and turns each Tk
``Action(method, kwargs)`` into a page route the Svelte UI understands.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any

from ..api.result import ApiError
from ..i18n import t

# Tk app method -> (page route, {Tk kwarg: page param}).
ROUTES: dict[str, tuple[str, dict[str, str]]] = {
    "password_health_clicked": ("health", {"initial_filter": "filter", "scan_all": "scan_all"}),
    "change_master_clicked": ("master", {}),
    "hello_settings_clicked": ("hello", {}),
    "face_settings_clicked": ("face", {}),
    "recovery_center_clicked": ("recovery", {"initial": "initial"}),
    "settings_clicked": ("settings", {"section": "section"}),
    "export_clicked": ("export", {}),
    "transfer_clicked": ("transfer", {}),
    "import_clicked": ("import", {}),
    "security_set_setting": ("set", {"key": "key", "value": "value"}),
}
SWITCHES = ("breach_check_enabled", "strict_offline_mode")


def route_for(action: Any) -> dict[str, Any]:
    route, names = ROUTES.get(action.method, (action.method, {}))
    params = {names[k]: v for k, v in dict(action.kwargs).items() if k in names}
    if route == "recovery" and "initial" not in params:
        # "Back up now" opens straight at the create form.
        params["initial"] = "create"
    return {"label": action.label, "route": route, "params": params}


class SecurityService:
    def __init__(self, controller: Any, home: Any) -> None:
        self._controller = controller
        self._home = home

    def _session(self) -> Any:
        if not self._controller.is_unlocked():
            raise ApiError("locked", t("error.lockedProfile"))
        self._controller.require_lease(self._controller.guard.lease())
        return self._controller.session

    def unlock_methods(self) -> Any:
        from ..shell.security_model import UnlockMethods

        session = self._session()
        hello_available = hello_enrolled = False
        try:
            from ..hello_unlock import has_envelope
            from ..windows_hello import WindowsHello

            hello_available = bool(WindowsHello.supported_platform())
            if hello_available:
                profile = self._controller.profiles.active_profile()
                hello_enrolled = bool(has_envelope(self._controller.profiles.vault_path(profile.id), profile.id))
        except Exception:  # noqa: BLE001 - a status row, never a failure
            hello_enrolled = False
        try:
            face = bool(session.face_binding())
        except Exception:  # noqa: BLE001
            face = None
        try:
            phrase = bool(session.has_recovery_phrase())
        except Exception:  # noqa: BLE001
            phrase = None
        return UnlockMethods(hello_available, hello_enrolled, face, phrase)

    def center(self) -> dict[str, Any]:
        from ..password_tools import vault_health
        from ..shell.overview_model import BackupStatus, backup_status
        from ..shell.security_model import security_center

        session = self._session()
        entries = session.all_entries()
        try:
            health = vault_health(entries)
        finally:
            for entry in entries:
                entry.clear()
            entries.clear()
        warning = t("home.backupFailed") if getattr(session, "backup_warning", None) else ""
        try:
            directory = getattr(session, "backup_dir", None) or (Path(session.path).parent / "Backups")
            backup = backup_status(directory, warning)
        except Exception:  # noqa: BLE001
            backup = BackupStatus(None, 0, warning)
        model = security_center(health, set(self._home.breached_ids), self.unlock_methods(), backup,
                                self._controller.settings)
        return {
            "score": model.score, "label": model.label, "headline": model.headline,
            "issues": [{"key": i.key, "count": i.count, "title": i.title, "description": i.description,
                        "tone": i.tone, "action": route_for(i.action)} for i in model.issues],
            "panels": [{"title": p.title,
                        "rows": [{"label": r.label, "meta": r.meta, "meta_tone": r.meta_tone,
                                  "action": route_for(r.action)} for r in p.rows]} for p in model.panels],
            "footnote": model.footnote,
        }

    def set_setting(self, key: str, value: Any) -> dict[str, Any]:
        from ..settings_ui import settings_candidate

        if key not in SWITCHES:
            raise ApiError("invalid", t("settings.error.unknownPreference"))
        self._session()
        try:
            candidate = settings_candidate(self._controller.settings, {key: value})
        except ValueError as exc:
            raise ApiError("invalid", str(exc)) from None
        candidate.save()
        self._controller.settings = candidate
        return {"message": t("settings.saved")}
