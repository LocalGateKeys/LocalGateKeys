"""Settings for the WebView UI.

``page()`` runs the classic ``shell.settings_sections`` builders against a
recording form, so the WebView page shows the same sections, rows, titles and
descriptions as the classic one. Button commands are resolved against an
adapter that only returns page routes, so recording never runs a classic
action. ``apply()`` ports ``FeatureUI.apply_settings_change``.
"""
from __future__ import annotations

from dataclasses import asdict, replace
from pathlib import Path
from typing import Any, Callable

from ..api.result import ApiError
from ..i18n import t
from ..secret_text import SecretText, as_secret, secrets_match
from ..startup import set_start_with_windows
from ..vault import VaultError

SCHEDULE_SETTINGS = frozenset({
    "scheduled_backup_frequency", "scheduled_backup_time",
    "scheduled_backup_weekday", "scheduled_backup_keep", "backup_mirror_dir",
})
# Switches the WebView page adds itself (the shared builders and settings_ui
# do not know them): key -> (title key, description key), shown after ``after``.
WEBVIEW_SWITCHES = {
    "website_icons": ("settings.websiteIcons.title", "settings.websiteIcons.desc"),
}
WEBVIEW_SWITCH_AFTER = {"strict_offline_mode": "website_icons"}
# Classic Tk command -> WebView page route.
ROUTES = {
    "hello_settings_clicked": "hello", "face_settings_clicked": "face", "change_master_clicked": "master",
    "recovery_center_clicked": "recovery", "check_updates_clicked": "updates", "licence_clicked": "licence",
    "sync_clicked": "sync", "show_shortcuts_clicked": "shortcuts", "onboarding_clicked": "onboarding",
    "connections_clicked": "connections", "open_error_log_clicked": "errorlog", "rate_clicked": "rate",
}


def _jsonable(value: Any) -> Any:
    return value if isinstance(value, (str, int, float, bool)) or value is None else str(value)


class _Adapter:
    """The ``form.app`` the builders see: secret-free statuses, and routes instead of actions."""

    def __init__(self, service: "SettingsService") -> None:
        self._service = service

    @property
    def session(self) -> Any:
        controller = self._service._controller
        return controller.session if controller.is_unlocked() else None

    def __getattr__(self, name: str) -> Callable[..., dict[str, Any]]:
        if name in ROUTES:
            return lambda *args, **kwargs: {"route": ROUTES[name], "params": {}}
        raise AttributeError(name)

    def _settings_backup_password_action(self, _window: Any = None, *, clear: bool = False) -> dict[str, Any]:
        return {"route": "backup_password", "params": {"clear": bool(clear)}}

    def _unlock_methods(self) -> Any:
        from .security import SecurityService

        return SecurityService(self._service._controller, None).unlock_methods()

    def _settings_face_state(self) -> dict[str, str]:
        session = self.session
        if session is None:
            return {"label": t("settings.btn.setUp"), "status": t("settings.face.lockedStatus")}
        try:
            configured = bool(session.face_binding())
        except Exception:  # noqa: BLE001
            return {"label": t("settings.btn.setUp"), "status": t("settings.face.errorStatus")}
        return {"label": t("settings.btn.manage") if configured else t("settings.btn.setUp"), "status": t("settings.face.configured") if configured else t("settings.notSetUp")}

    def _settings_backup_state(self) -> dict[str, Any]:
        return self._service.backup_state()


class _Recorder:
    """A ``SettingsForm`` that records rows as JSON-ready dicts."""

    def __init__(self, app: _Adapter, settings: Any) -> None:
        self.app = app
        self.settings = settings
        self.rows: list[dict[str, Any]] = []

    def _value(self, key: str) -> Any:
        return _jsonable(getattr(self.settings, key, None))

    def _options(self, key: str) -> list[dict[str, Any]]:
        from ..settings_ui import choice_options

        current = getattr(self.settings, key, None)
        return [{"label": label, "value": _jsonable(value)} for label, value in choice_options(key, current).items()]

    def switch(self, key: str, title: str, description: str = "") -> None:
        self.rows.append({"type": "switch", "key": key, "title": title, "description": description,
                          "value": bool(getattr(self.settings, key, False))})
        extra = WEBVIEW_SWITCH_AFTER.get(key)
        if extra is not None and hasattr(self.settings, extra):
            self.switch(extra, *(t(text) for text in WEBVIEW_SWITCHES[extra]))

    def choice(self, key: str, title: str, description: str = "") -> None:
        self.rows.append({"type": "choice", "key": key, "title": title, "description": description,
                          "value": self._value(key), "options": self._options(key)})

    def segmented(self, key: str, title: str, description: str = "") -> None:
        self.rows.append({"type": "segmented", "key": key, "title": title, "description": description,
                          "value": self._value(key), "options": self._options(key)})

    def text(self, key: str, title: str, description: str = "") -> None:
        self.rows.append({"type": "text", "key": key, "title": title, "description": description,
                          "value": str(getattr(self.settings, key, "") or "")})

    def button(self, title: str, description: str, label: str, command: Callable[[], Any], *,
               refresh: bool = False, primary: bool = False) -> None:
        target = command()
        if not isinstance(target, dict) or "route" not in target:
            return  # never run anything that is not a route
        self.rows.append({"type": "button", "title": title, "description": description, "label": label,
                          "route": target["route"], "params": target.get("params", {}), "primary": bool(primary)})

    def shortcut(self, title: str, description: str, keys: str) -> None:
        self.rows.append({"type": "shortcut", "title": title, "description": description, "keys": keys})

    def note(self, text: str) -> None:
        self.rows.append({"type": "note", "text": text})

    def link(self, title: str, description: str, label: str, url: str) -> None:
        if not url.startswith("https://"):
            return  # only web pages, opened in the browser through system_open_url
        self.rows.append({"type": "link", "title": title, "description": description, "label": label, "url": url})

    def choose_folder(self, key: str, title: str) -> None:
        self.rows.append({"type": "folder", "key": key, "title": title, "value": str(getattr(self.settings, key, "") or "")})


class SettingsService:
    def __init__(self, controller: Any, port: Any, bus: Any, *, dialogs: Any = None,
                 schedule: Any = None) -> None:
        self._controller = controller
        self._port = port
        self._bus = bus
        self._dialogs = dialogs
        self._schedule = schedule
        # Python-side listeners (the agent host re-registers hotkeys, refreshes the tray).
        self.on_change: list[Any] = []

    def _lease(self) -> Any:
        controller = self._controller
        if not controller.is_unlocked():
            raise ApiError("locked", t("error.lockedProfile"))
        lease = controller.guard.lease()
        controller.require_lease(lease)
        return lease

    # ------------------------------------------------------------- page
    def page(self) -> dict[str, Any]:
        from ..shell.settings_sections import sections

        self._lease()
        adapter = _Adapter(self)
        out = []
        for section in sections():
            form = _Recorder(adapter, self._controller.settings)
            try:
                section.build(form)
            except Exception:  # noqa: BLE001 - one broken card must not hide the others
                out.append({"key": section.key, "title": section.title_text, "column": section.column,
                            "rows": [], "error": t("settings.sectionError")})
                continue
            out.append({"key": section.key, "title": section.title_text, "column": section.column,
                        "subtitle": section.subtitle_text, "keywords": list(section.keywords), "rows": form.rows})
        return {"sections": out, "saved_text": t("settings.savedText")}

    # ------------------------------------------------------------ apply
    def apply(self, key: str, value: Any) -> dict[str, Any]:
        from ..settings_ui import settings_candidate

        controller = self._controller
        lease = self._lease()
        previous = controller.settings
        try:
            if key in WEBVIEW_SWITCHES:
                if type(value) is not bool:
                    raise ValueError(t("settings.error.invalidSwitch", setting=key))
                candidate = replace(settings_candidate(previous, {}), **{key: value})
            else:
                candidate = settings_candidate(previous, {key: value})
        except ValueError as exc:
            raise ApiError("invalid", str(exc) or t("settings.error.invalidValue")) from None
        changed = {name for name, old in asdict(previous).items() if getattr(candidate, name) != old}
        if not changed:
            return {"message": t("settings.saved"), "value": _jsonable(getattr(candidate, key, None))}
        if candidate.fill_and_sign_in and not previous.fill_and_sign_in:
            if not self._port.confirm(t("settings.fillSignIn.confirmTitle"), t("settings.fillSignIn.confirmText")):
                raise ApiError("cancelled", t("error.cancelled"))
            controller.require_lease(lease)
        session = controller.session
        try:
            if "start_with_windows" in changed:
                set_start_with_windows(candidate.start_with_windows)
            if "fill_and_sign_in" in changed:
                session.set_fill_and_sign_in_enabled(candidate.fill_and_sign_in)
        except (OSError, VaultError, ValueError) as exc:
            self._undo_side_effects(session, previous, changed - {"fill_and_sign_in"})
            raise ApiError("invalid", str(exc) or t("settings.error.notSaved")) from None
        try:
            candidate.save()
        except OSError:
            self._undo_side_effects(session, previous, changed)
            raise ApiError("invalid", t("settings.error.notSaved")) from None
        controller.settings = candidate
        session.trash_retention_days = candidate.trash_retention_days
        session.trash_auto_purge = candidate.trash_auto_purge
        if "max_session_seconds" in changed:
            controller.guard.set_max_seconds(candidate.max_session_seconds)
        if "clipboard_clear_seconds" in changed:
            controller.clipboard.timeout_seconds = candidate.clipboard_clear_seconds
        if "language" in changed:
            from .. import i18n

            i18n.set_language(i18n.resolve(candidate.language, i18n.os_locale()))
            self._bus.emit("language_changed", {"lang": i18n.current()})
        if "appearance" in changed:
            self._bus.emit("appearance", {"appearance": candidate.appearance})
        if changed & SCHEDULE_SETTINGS and self._schedule is not None:
            self._schedule.settings_changed()
            controller._scheduler.call_later(1, self._schedule._safe_check)
        controller.touch()
        self._bus.emit("settings.changed", {"key": key})
        for listener in list(self.on_change):
            try:
                listener(key)
            except Exception:  # noqa: BLE001, S110 - a listener never blocks a saved setting
                pass
        return {"message": t("settings.saved"), "value": _jsonable(getattr(candidate, key, None))}

    @staticmethod
    def _undo_side_effects(session: Any, previous: Any, changed: set[str]) -> None:
        """settings.json could not be written: put the vault flag and autostart back as they were."""
        if "fill_and_sign_in" in changed:
            try:
                session.set_fill_and_sign_in_enabled(previous.fill_and_sign_in)
            except Exception:  # noqa: BLE001, S110 - the save error is what the person sees
                pass
        if "start_with_windows" in changed:
            try:
                set_start_with_windows(previous.start_with_windows)
            except Exception:  # noqa: BLE001, S110
                pass

    def choose_folder(self, key: str) -> dict[str, Any]:
        if key != "backup_mirror_dir":
            raise ApiError("invalid", t("settings.error.unknownPreference"))
        self._lease()
        if self._dialogs is None:
            raise ApiError("unavailable", t("error.dialogsUnavailable"))
        folder = self._dialogs.choose_folder(t("settings.chooseFolder.title"))
        if not folder:
            raise ApiError("cancelled", t("error.noFolderChosen"))
        return self.apply(key, str(Path(folder)))

    # ------------------------------------------------- backup password
    def backup_state(self) -> dict[str, Any]:
        controller = self._controller
        try:
            has_password = bool(controller.session.has_scheduled_backup_password())
        except Exception:  # noqa: BLE001
            has_password = False
        return {"has_password": has_password, "status": self._schedule_status(has_password)}

    def _schedule_status(self, has_password: bool) -> str:
        from ..backup_schedule import SCHEDULED_DIR_NAME, read_last_success

        controller = self._controller
        if controller.settings.scheduled_backup_frequency == "off":
            return t("settings.status.off")
        if not controller.is_unlocked():
            return t("settings.status.unlockedOnly")
        if not has_password:
            return t("settings.status.noPassword")
        profile = controller.profiles.active_profile()
        try:
            last = read_last_success(controller.profiles.backups_dir(profile.id) / SCHEDULED_DIR_NAME)
        except Exception:  # noqa: BLE001
            last = None
        return t("settings.status.last", when=last.strftime("%Y-%m-%d %H:%M")) if last else t("settings.status.none")

    def backup_password(self, first: str | SecretText, second: str | SecretText) -> dict[str, Any]:
        """Store the scheduled-backup password. ``SecretText`` stays the caller's (the bridge wipes it);
        the vault keeps a ``str``, made only for that one call."""
        lease = self._lease()
        try:
            if not secrets_match(first, second):
                raise ApiError("invalid", t("settings.backupPassword.mismatch"))
            secret, owned = as_secret(first)
            try:
                if secret.char_count < 12:
                    raise ApiError("invalid", t("settings.backupPassword.tooShort"))
                value = secret.buffer.decode("utf-8")
            finally:
                if owned:
                    secret.wipe()
            self._controller.require_lease(lease)
            try:
                self._controller.session.set_scheduled_backup_password(value)
            except VaultError as exc:
                raise ApiError("invalid", str(exc)) from None
        finally:
            first = second = value = ""
        if self._schedule is not None:
            self._schedule.settings_changed()
            self._controller._scheduler.call_later(1, self._schedule._safe_check)
        self._controller.touch()
        return {"message": t("settings.backupPassword.saved")}

    def clear_backup_password(self) -> dict[str, Any]:
        lease = self._lease()
        if not self._port.confirm(t("settings.backupPasswordClear.confirmTitle"),
                                  t("settings.backupPasswordClear.confirmText")):
            raise ApiError("cancelled", t("error.cancelled"))
        self._controller.require_lease(lease)
        self._controller.session.set_scheduled_backup_password(None)
        self._controller.touch()
        return {"message": t("settings.backupPasswordClear.done")}
