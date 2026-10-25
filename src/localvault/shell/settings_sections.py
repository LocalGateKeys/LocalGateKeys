"""Settings page sections: one builder function per card, registered in page order.

Each section is a :class:`SettingsSection` whose ``build`` function adds rows
through a :class:`SettingsForm`.  The page knows nothing about individual
settings, so a new card is one function and one call::

    def build_licence(form: SettingsForm) -> None:
        form.button("Licence", "LocalGateKeys Pro · active", "Manage…", form.app.licence_clicked)

    register_section(SettingsSection("licence", "Licence", build_licence, column=1,
                                     keywords=("pro", "key", "purchase")), before="backups")

A registered section also gets a Ctrl+K entry ("Settings › Licence").
Builders run on every page build, so statuses (Windows Hello, backup
password, …) are read fresh each time; they must not keep secrets.
"""
from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Any, Protocol


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
    title: str
    build: Callable[[SettingsForm], None]
    column: int = 0
    keywords: tuple[str, ...] = ()
    subtitle: str = ""


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
    form.choice("auto_lock_seconds", "Lock after inactivity", "When you have not used your computer or the vault")
    form.switch("lock_on_session_lock", "Lock when Windows locks", "Win+L, switching user or signing out")
    form.switch("lock_on_sleep", "Lock on sleep", "Laptop lid closed, sleep or hibernation")
    form.choice("max_session_seconds", "Never stay unlocked longer than", "Even while you are using it")
    form.choice("idle_source", "Count activity from",
                "Computer: keyboard or mouse anywhere. Vault: using or saving items.")
    form.switch("totp_confirm", "Ask before releasing 2FA codes",
                "Confirm on this PC each time the browser extension asks for a one-time code")


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
        form.button("Windows Hello", "On · fingerprint, face or PIN" if enrolled else "Not set up",
                    "Manage" if enrolled else "Set up", _call(app, "hello_settings_clicked"), refresh=True,
                    primary=not enrolled)
    form.switch("hello_auto_start", "Start Windows Hello automatically", "When the unlock screen opens")
    face = _status(app, "_settings_face_state") or {}
    form.button("Camera check", str(face.get("status", "Not set up")) + " · less secure than Windows Hello",
                str(face.get("label", "Set up")), _call(app, "face_settings_clicked"), refresh=True)
    form.button("Master password", "Re-encrypts this vault. Backups keep the password they were made with.",
                "Change…", _call(app, "change_master_clicked"))
    phrase = None if methods is None else methods.recovery_phrase
    form.button("Recovery phrase",
                {True: "Set · unlocks if you forget the master password", False: "Not set"}.get(phrase, ""),
                "Manage" if phrase else "Set up", _call(app, "recovery_center_clicked"), refresh=True)


def build_privacy(form: SettingsForm) -> None:
    form.choice("clipboard_clear_seconds", "Clear clipboard after", "Only what LocalGateKeys copied is cleared")
    form.switch("breach_check_enabled", "Breach checks",
                "You start each check. It sends 5 characters of a hash, never the password.")
    form.switch("strict_offline_mode", "Strict offline mode",
                "Blocks background internet requests, website icons and breach checks")
    form.switch("trash_auto_purge", "Empty trash automatically",
                "When off, deleted items stay in the trash until you delete them")
    form.choice("trash_retention_days", "Keep deleted items for", "Used while automatic emptying is on")
    form.switch("document_open_enabled", "Open documents in other apps",
                "Puts a decrypted copy on this PC while you use it; deleted when you close it")


def build_autofill(form: SettingsForm) -> None:
    form.switch("browser_enabled", "Browser autofill", "Through the LocalGateKeys browser extension")
    form.switch("passkeys_enabled", "Offer LocalGateKeys for passkeys",
                "Create and use passkeys from this vault when a website asks. Off: the browser handles passkeys itself")
    form.switch("desktop_overlay_enabled", "Desktop app autofill",
                "Show a fill button beside supported desktop password fields")
    form.switch("fill_and_sign_in", "Sign in after filling",
                "Submit one supported sign-in form after you start a fill. CAPTCHA and MFA stay manual.")
    form.text("quick_access_hotkey", "Quick access", "Search and copy from anywhere · Ctrl, Alt, Shift or Win + a key")
    form.shortcut("Fill the focused app", "Desktop fill", "Ctrl+Shift+Space")
    form.shortcut("Emergency lock", "Lock and cancel pending fills", "Ctrl+Alt+L")


def build_appearance(form: SettingsForm) -> None:
    from ..version import APP_VERSION

    form.segmented("appearance", "Theme", "Match Windows or choose one")
    form.switch("start_with_windows", "Start with Windows", "Starts locked in the background for this Windows account")
    form.switch("minimize_to_tray", "Keep running in the tray",
                "Closing the window keeps autofill working; it does not lock the vault")
    form.button("Updates", f"Version {APP_VERSION}", "Check now", _call(form.app, "check_updates_clicked"))
    from ..app import rating

    if rating.available():
        form.button("Rate LocalGateKeys", "Tell others what you think on the Microsoft Store", "Rate",
                    _call(form.app, "rate_clicked"))


def build_backups(form: SettingsForm) -> None:
    app = form.app
    form.choice("automatic_backup_count", "Automatic backups to keep",
                "Copies made as you save. Older ones may still hold deleted items.")
    form.choose_folder("backup_mirror_dir", "Cloud copy")
    form.choice("scheduled_backup_frequency", "Scheduled backups",
                "Runs while unlocked. A run missed while the app was closed happens at the next unlock.")
    form.text("scheduled_backup_time", "Time of day", "24-hour local time, for example 08:30")
    form.choice("scheduled_backup_weekday", "Day of the week", "For weekly backups")
    form.choice("scheduled_backup_keep", "Old scheduled backups",
                "A new backup is written and checked before the oldest is deleted")
    state = _status(app, "_settings_backup_state") or {}
    has_password = bool(state.get("has_password"))
    form.button("Backup password",
                "Set · kept only inside your encrypted vault" if has_password
                else "Not set · scheduled backups need one",
                "Change…" if has_password else "Set…",
                _call(app, "_settings_backup_password_action", None, clear=False), refresh=True,
                primary=not has_password)
    if has_password:
        form.button("Clear backup password", "Scheduled backups stop until you set one again", "Clear",
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
        headline = "Licence status unavailable"
    form.button("Licence", headline, "Open", _call(app, "licence_clicked"))
    form.button("Device sync", "Wi-Fi and cloud-folder sync between your devices", "Open",
                _call(app, "sync_clicked"))


# The website's legal pages (the licence agreement also covers the iPhone app).
PRIVACY_POLICY_URL = "https://localgatekeys.app/legal/privacy.html"
LICENCE_AGREEMENT_URL = "https://localgatekeys.app/legal/eula.html"


def build_help(form: SettingsForm) -> None:
    app = form.app
    form.button("Keyboard shortcuts", "Also with F1", "View", _call(app, "show_shortcuts_clicked"))
    form.button("Setup guide", "Walk through the basics again", "Open", _call(app, "onboarding_clicked"))
    form.button("Devices & connections", "Browser extension status and diagnostics", "Open",
                _call(app, "connections_clicked"))
    form.button("Error log", "Technical log files; they contain no secrets", "Open",
                _call(app, "open_error_log_clicked"))
    form.link("Privacy policy", "How LocalGateKeys handles your data", "Open", PRIVACY_POLICY_URL)
    form.link("Licence agreement", "The terms for using LocalGateKeys", "Open", LICENCE_AGREEMENT_URL)


BUILT_IN_SECTIONS: tuple[SettingsSection, ...] = (
    SettingsSection("locking", "Locking", build_locking, 0, ("lock", "timeout", "idle", "auto-lock", "sleep")),
    SettingsSection("unlocking", "Unlocking", build_unlocking, 0,
                    ("hello", "face", "camera", "biometric", "master", "recovery", "phrase")),
    SettingsSection("privacy", "Privacy", build_privacy, 0,
                    ("clipboard", "breach", "offline", "trash", "documents", "network")),
    SettingsSection("autofill", "Autofill", build_autofill, 1,
                    ("fill", "browser", "extension", "desktop", "shortcut", "hotkey")),
    SettingsSection("appearance", "Appearance & app", build_appearance, 1,
                    ("theme", "dark", "light", "startup", "tray", "updates", "version")),
    SettingsSection("backups", "Backups", build_backups, 1, ("backup", "schedule", "folder", "cloud", "mirror")),
    SettingsSection("plan", "Plan & sync", build_plan, 1, ("licence", "license", "pro", "upgrade", "sync", "devices")),
    SettingsSection("help", "Help & diagnostics", build_help, 1,
                    ("shortcuts", "guide", "diagnostics", "log", "support", "privacy", "terms", "licence",
                     "legal", "eula")),
)

for _section in BUILT_IN_SECTIONS:
    register_section(_section)
del _section
