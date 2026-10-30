"""Settings page sections: one builder function per card, registered in page order.

Each section is a :class:`SettingsSection` whose ``build`` function adds rows
through a :class:`SettingsForm`.  The page knows nothing about individual
settings, so a new card is one function and one call::

    def build_licence(form: SettingsForm) -> None:
        form.button("Licence", "LocalGateKeys Pro · active", "Manage…", form.app.licence_clicked)

    register_section(SettingsSection("licence", "Licence", build_licence, column=1,
                                     keywords=("pro", "key", "purchase")), before="backups")

A section's ``title`` and ``subtitle`` may be catalog keys (translated when shown) or plain text.
A registered section also gets a Ctrl+K entry ("Settings › Licence").
Builders run on every page build, so statuses (Windows Hello, backup
password, …) are read fresh each time; they must not keep secrets.
"""
from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Any, Protocol

from ..i18n import t


class SettingsForm(Protocol):
    """Row API the page gives each section builder.

    ``key`` arguments are ``AppSettings`` field names; a change is validated
    and saved at once by the page through ``app.apply_settings_change``.
    """

    app: Any
    settings: Any

    def switch(self, key: str, title: str, description: str = "") -> None: ...

    def choice(self, key: str, title: str, description: str = "") -> None: ...

    def segmented(self, key: str, title: str, description: str = "") -> None: ...

    def text(self, key: str, title: str, description: str = "") -> None: ...

    def button(self, title: str, description: str, label: str, command: Callable[[], Any], *,
               refresh: bool = False, primary: bool = False) -> None: ...

    def shortcut(self, title: str, description: str, keys: str) -> None: ...

    def note(self, text: str) -> None: ...

    def link(self, title: str, description: str, label: str, url: str) -> None: ...

    def choose_folder(self, key: str, title: str) -> None: ...


@dataclass(frozen=True)
class SettingsSection:
    key: str
    title: str  # a catalog key (or plain text); ``title_text`` is the text in the active language
    build: Callable[[SettingsForm], None]
    column: int = 0
    keywords: tuple[str, ...] = ()
    subtitle: str = ""  # likewise

    @property
    def title_text(self) -> str:
        return t(self.title)

    @property
    def subtitle_text(self) -> str:
        return t(self.subtitle) if self.subtitle else ""


_SECTIONS: list[SettingsSection] = []


def register_section(section: SettingsSection, *, before: str | None = None, after: str | None = None) -> None:
    """Add a section to the page; ``before``/``after`` name an existing section key."""

    if any(existing.key == section.key for existing in _SECTIONS):
        raise ValueError(f"Settings section {section.key!r} is already registered.")
    if before is not None and after is not None:
        raise ValueError("Use before= or after=, not both.")
    anchor = before or after
    if anchor is None:
        _SECTIONS.append(section)
        return
    index = next((i for i, existing in enumerate(_SECTIONS) if existing.key == anchor), None)
    if index is None:
        raise KeyError(anchor)
    _SECTIONS.insert(index if before is not None else index + 1, section)


def unregister_section(key: str) -> None:
    """Remove a section (tests, or a feature that turns itself off)."""

    _SECTIONS[:] = [section for section in _SECTIONS if section.key != key]


def sections() -> tuple[SettingsSection, ...]:
    return tuple(_SECTIONS)


def section(key: str) -> SettingsSection | None:
    return next((item for item in _SECTIONS if item.key == key), None)


# ----------------------------------------------------------------- builders
def _call(app: Any, name: str, *args: Any, **kwargs: Any) -> Callable[[], Any]:
    """A command that calls ``app.<name>`` when clicked (resolved late, so tests can patch it)."""

    def run() -> Any:
        return getattr(app, name)(*args, **kwargs)

    return run


def build_locking(form: SettingsForm) -> None:
    form.choice("auto_lock_seconds", t("settings.autoLock.title"), t("settings.autoLock.desc"))
    form.switch("lock_on_session_lock", t("settings.lockOnSessionLock.title"), t("settings.lockOnSessionLock.desc"))
    form.switch("lock_on_sleep", t("settings.lockOnSleep.title"), t("settings.lockOnSleep.desc"))
    form.choice("max_session_seconds", t("settings.maxSession.title"), t("settings.maxSession.desc"))
    form.choice("idle_source", t("settings.idleSource.title"),
                t("settings.idleSource.desc"))
    form.switch("totp_confirm", t("settings.totpConfirm.title"),
                t("settings.totpConfirm.desc"))


def _status(app: Any, name: str) -> Any:
    method = getattr(app, name, None)
    if method is None:
        return None
    try:
        return method()
    except Exception:  # noqa: BLE001 - a status line must never break the page
        return None


def build_unlocking(form: SettingsForm) -> None:
    app = form.app
    methods = _status(app, "_unlock_methods")
    if methods is not None and methods.hello_available:
        enrolled = methods.hello_enrolled
        form.button(t("settings.hello.title"), t("settings.hello.on") if enrolled else t("settings.notSetUp"),
                    t("settings.btn.manage") if enrolled else t("settings.btn.setUp"), _call(app, "hello_settings_clicked"), refresh=True,
                    primary=not enrolled)
    form.switch("hello_auto_start", t("settings.helloAutoStart.title"), t("settings.helloAutoStart.desc"))
    face = _status(app, "_settings_face_state") or {}
    form.button(t("settings.camera.title"), t("settings.camera.status", status=str(face.get("status", t("settings.notSetUp")))),
                str(face.get("label", t("settings.btn.setUp"))), _call(app, "face_settings_clicked"), refresh=True)
    form.button(t("settings.master.title"), t("settings.master.desc"),
                t("settings.btn.change"), _call(app, "change_master_clicked"))
    phrase = None if methods is None else methods.recovery_phrase
    form.button(t("settings.recovery.title"),
                {True: t("settings.recovery.set"), False: t("settings.notSet")}.get(phrase, ""),
                t("settings.btn.manage") if phrase else t("settings.btn.setUp"), _call(app, "recovery_center_clicked"), refresh=True)


def build_privacy(form: SettingsForm) -> None:
    form.choice("clipboard_clear_seconds", t("settings.clipboard.title"), t("settings.clipboard.desc"))
    form.switch("breach_check_enabled", t("settings.breach.title"),
                t("settings.breach.desc"))
    form.switch("strict_offline_mode", t("settings.offline.title"),
                t("settings.offline.desc"))
    form.switch("hide_from_capture", t("settings.hideFromCapture.title"), t("settings.hideFromCapture.desc"))
    form.switch("trash_auto_purge", t("settings.trashPurge.title"),
                t("settings.trashPurge.desc"))
    form.choice("trash_retention_days", t("settings.trashRetention.title"), t("settings.trashRetention.desc"))
    form.switch("document_open_enabled", t("settings.docOpen.title"),
                t("settings.docOpen.desc"))


def build_autofill(form: SettingsForm) -> None:
    form.switch("browser_enabled", t("settings.browser.title"), t("settings.browser.desc"))
    form.switch("passkeys_enabled", t("settings.passkeys.title"),
                t("settings.passkeys.desc"))
    form.switch("desktop_overlay_enabled", t("settings.overlay.title"),
                t("settings.overlay.desc"))
    form.switch("fill_and_sign_in", t("settings.signIn.title"),
                t("settings.signIn.desc"))
    form.text("quick_access_hotkey", t("settings.quickAccess.title"), t("settings.quickAccess.desc"))
    form.shortcut(t("settings.fillShortcut.title"), t("settings.fillShortcut.desc"), "Ctrl+Shift+Space")
    form.shortcut(t("settings.emergencyShortcut.title"), t("settings.emergencyShortcut.desc"), "Ctrl+Alt+L")


def build_appearance(form: SettingsForm) -> None:
    from ..version import APP_VERSION

    form.segmented("appearance", t("settings.theme.title"), t("settings.theme.desc"))
    form.choice("language", t("settings.language.label"), t("settings.language.description"))
    form.switch("start_with_windows", t("settings.startup.title"), t("settings.startup.desc"))
    form.switch("minimize_to_tray", t("settings.tray.title"),
                t("settings.tray.desc"))
    form.button(t("settings.updates.title"), t("settings.updates.version", version=APP_VERSION), t("settings.updates.button"), _call(form.app, "check_updates_clicked"))
    from ..app import rating

    if rating.available():
        form.button(t("settings.rate.title"), t("settings.rate.desc"), t("settings.rate.button"),
                    _call(form.app, "rate_clicked"))


def build_backups(form: SettingsForm) -> None:
    app = form.app
    form.choice("automatic_backup_count", t("settings.autoBackups.title"),
                t("settings.autoBackups.desc"))
    form.choose_folder("backup_mirror_dir", t("settings.cloudCopy.title"))
    form.choice("scheduled_backup_frequency", t("settings.schedule.title"),
                t("settings.schedule.desc"))
    form.text("scheduled_backup_time", t("settings.scheduleTime.title"), t("settings.scheduleTime.desc"))
    form.choice("scheduled_backup_weekday", t("settings.scheduleDay.title"), t("settings.scheduleDay.desc"))
    form.choice("scheduled_backup_keep", t("settings.scheduleKeep.title"),
                t("settings.scheduleKeep.desc"))
    state = _status(app, "_settings_backup_state") or {}
    has_password = bool(state.get("has_password"))
    form.button(t("settings.backupPassword.title"),
                t("settings.backupPassword.set") if has_password
                else t("settings.backupPassword.notSet"),
                t("settings.btn.change") if has_password else t("settings.btn.set"),
                _call(app, "_settings_backup_password_action", None, clear=False), refresh=True,
                primary=not has_password)
    if has_password:
        form.button(t("settings.backupPasswordClear.title"), t("settings.backupPasswordClear.desc"), t("settings.btn.clear"),
                    _call(app, "_settings_backup_password_action", None, clear=True), refresh=True)
    if state.get("status"):
        form.note(str(state["status"]))


def build_plan(form: SettingsForm) -> None:
    app = form.app
    try:
        from .. import licensing
        from ..app.licence_view import licence_view

        session = getattr(app, "session", None)
        count = session.live_item_count() if session is not None and hasattr(session, "live_item_count") else None
        headline = licence_view(licensing.status(), count).headline
    except Exception:  # noqa: BLE001 - a licence problem never blocks Settings
        headline = t("settings.licence.unavailable")
    form.button(t("settings.licence.title"), headline, t("settings.btn.open"), _call(app, "licence_clicked"))
    form.button(t("settings.sync.title"), t("settings.sync.desc"), t("settings.btn.open"),
                _call(app, "sync_clicked"))


# The website's legal pages (the licence agreement also covers the iPhone app).
PRIVACY_POLICY_URL = "https://localgatekeys.app/legal/privacy.html"
LICENCE_AGREEMENT_URL = "https://localgatekeys.app/legal/eula.html"


def build_help(form: SettingsForm) -> None:
    app = form.app
    form.button(t("settings.shortcuts.title"), t("settings.shortcuts.desc"), t("settings.btn.view"), _call(app, "show_shortcuts_clicked"))
    form.button(t("settings.setup.title"), t("settings.setup.desc"), t("settings.btn.open"), _call(app, "onboarding_clicked"))
    form.button(t("settings.connections.title"), t("settings.connections.desc"), t("settings.btn.open"),
                _call(app, "connections_clicked"))
    form.button(t("settings.errorLog.title"), t("settings.errorLog.desc"), t("settings.btn.open"),
                _call(app, "open_error_log_clicked"))
    form.link(t("settings.privacyPolicy.title"), t("settings.privacyPolicy.desc"), t("settings.btn.open"), PRIVACY_POLICY_URL)
    form.link(t("settings.eula.title"), t("settings.eula.desc"), t("settings.btn.open"), LICENCE_AGREEMENT_URL)


BUILT_IN_SECTIONS: tuple[SettingsSection, ...] = (
    SettingsSection("locking", "settings.section.locking", build_locking, 0, ("lock", "timeout", "idle", "auto-lock", "sleep")),
    SettingsSection("unlocking", "settings.section.unlocking", build_unlocking, 0,
                    ("hello", "face", "camera", "biometric", "master", "recovery", "phrase")),
    SettingsSection("privacy", "settings.section.privacy", build_privacy, 0,
                    ("clipboard", "breach", "offline", "trash", "documents", "network", "screenshot", "screen sharing", "capture")),
    SettingsSection("autofill", "settings.section.autofill", build_autofill, 1,
                    ("fill", "browser", "extension", "desktop", "shortcut", "hotkey")),
    SettingsSection("appearance", "settings.section.appearance", build_appearance, 1,
                    ("theme", "dark", "light", "startup", "tray", "updates", "version")),
    SettingsSection("backups", "settings.section.backups", build_backups, 1, ("backup", "schedule", "folder", "cloud", "mirror")),
    SettingsSection("plan", "settings.section.plan", build_plan, 1, ("licence", "license", "pro", "upgrade", "sync", "devices")),
    SettingsSection("help", "settings.section.help", build_help, 1,
                    ("shortcuts", "guide", "diagnostics", "log", "support", "privacy", "terms", "licence",
                     "legal", "eula")),
)

for _section in BUILT_IN_SECTIONS:
    register_section(_section)
del _section
