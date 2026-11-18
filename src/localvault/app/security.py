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
from ..travel import hidden_id_set


def _visible_entries(session: Any) -> list[Any]:
    """Logins not hidden by travel mode on this device (feature pack 2026-11-15, 2.3)."""
    hidden = hidden_id_set(session)
    return [e for e in session.all_entries() if str(e.get("id")) not in hidden]



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
    "developer_clicked": ("developer", {}),
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
        #: Set by the bridge: session -> how many logins and secrets an AI agent has seen (HealthService).
        self.agent_exposed: Any = None

    def _agent_issue(self, session: Any) -> list[dict[str, Any]]:
        """"Exposed to an AI agent" in Fix these first: the only way to that list in a vault without logins."""
        try:
            count = int(self.agent_exposed(session)) if self.agent_exposed else 0
        except Exception:  # noqa: BLE001 - the page still opens when the count cannot be read
            count = 0
        if count <= 0:
            return []
        return [{"key": "agent_exposed", "count": count, "title": t("health.filter.agent"),
                 "description": t("health.summary.agent", count=count), "tone": "warning",
                 "action": {"label": t("security.review", count=count), "route": "health",
                            "params": {"filter": "agent"}}}]

    def _session(self) -> Any:
        if not self._controller.is_unlocked():
            raise ApiError("locked", t("error.lockedProfile"))
        self._controller.require_lease(self._controller.guard.lease())
        return self._controller.session

    @staticmethod
    def _access_log_ok(session: Any) -> bool | None:
        try:
            return bool(session.activity.verify_chain().ok)
        except Exception:  # noqa: BLE001 - the row is optional; never break the page
            return None

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
        key_available, key_reason = False, ""
        key_enrolled = False
        try:
            from ..app.unlock_methods import security_key_availability
            from ..fido_unlock import has_envelope as has_key_envelope

            key_available, key_reason = security_key_availability()
            if key_available:
                profile = self._controller.profiles.active_profile()
                key_enrolled = bool(session.fido_binding()) and bool(
                    has_key_envelope(self._controller.profiles.vault_path(profile.id), profile.id))
        except Exception:  # noqa: BLE001 - a status row, never a failure
            key_enrolled = False
        try:
            face = bool(session.face_binding())
        except Exception:  # noqa: BLE001
            face = None
        try:
            phrase = bool(session.has_recovery_phrase())
        except Exception:  # noqa: BLE001
            phrase = None
        return UnlockMethods(hello_available, hello_enrolled, face, phrase,
                             security_key_available=key_available, security_key_enrolled=key_enrolled,
                             security_key_reason=key_reason)

    def center(self) -> dict[str, Any]:
        from .. import site_features
        from ..password_tools import vault_health
        from ..shell.overview_model import BackupStatus, backup_status
        from ..shell.security_model import security_center

        session = self._session()
        entries = _visible_entries(session)
        try:
            health = vault_health(entries, features=site_features.load(),
                                  passkey_domains=site_features.passkey_domains(session))
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
        from .health import plain_secrets_count

        model = security_center(health, set(self._home.breached_ids), self.unlock_methods(), backup,
                                self._controller.settings,
                                plain_secrets=plain_secrets_count(self._controller.settings),
                                access_log_ok=self._access_log_ok(session))
        return {
            "score": model.score, "label": model.label, "headline": model.headline,
            "issues": [{"key": i.key, "count": i.count, "title": i.title, "description": i.description,
                        "tone": i.tone, "action": route_for(i.action)} for i in model.issues]
                      + self._agent_issue(session),
            "panels": [{"title": p.title,
                        "rows": [{"label": r.label, "meta": r.meta, "meta_tone": r.meta_tone,
                                  "action": route_for(r.action)} for r in p.rows]} for p in model.panels],
            "footnote": model.footnote,
        }

    def network_activity(self) -> dict[str, Any]:
        """The network ledger (``net_ledger.view``): unlocked only, since this run's entries name saved sites."""
        from .. import net_ledger

        self._session()
        return net_ledger.view()

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
