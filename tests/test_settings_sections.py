"""Settings page sections: registry, builders and search, without Tk."""
from __future__ import annotations

from dataclasses import fields
from types import SimpleNamespace

import pytest

from localvault.settings import AppSettings
from localvault.settings_ui import CHOICE_LABELS, choice_label, choice_options, settings_candidate
from localvault.shell import settings_sections as registry
from localvault.shell.commands import palette_results, registered_section_commands
from localvault.shell.settings_sections import (
    SettingsSection,
    register_section,
    sections,
    unregister_section,
)


class RecordingForm:
    """Records what a builder asks for; buttons keep their commands."""

    def __init__(self, app=None, settings=None) -> None:
        self.app = app or _app()
        self.settings = settings or AppSettings()
        self.keys: list[tuple[str, str]] = []
        self.buttons: dict[str, tuple[str, object, bool]] = {}
        self.texts: list[str] = []
        self.links: dict[str, str] = {}

    def _key(self, kind, key, title, description=""):
        self.keys.append((kind, key))
        self.texts.append(f"{title} {description}")

    def switch(self, key, title, description=""):
        self._key("switch", key, title, description)

    def choice(self, key, title, description=""):
        assert key in CHOICE_LABELS, key
        self._key("choice", key, title, description)

    def segmented(self, key, title, description=""):
        assert key in CHOICE_LABELS, key
        self._key("segmented", key, title, description)

    def text(self, key, title, description=""):
        self._key("text", key, title, description)

    def choose_folder(self, key, title):
        self._key("folder", key, title)

    def button(self, title, description, label, command, *, refresh=False, primary=False):
        self.buttons[title] = (label, command, refresh)
        self.texts.append(f"{title} {description}")

    def shortcut(self, title, description, keys):
        self.texts.append(f"{title} {description} {keys}")

    def note(self, text):
        self.texts.append(text)

    def link(self, title, description, label, url):
        self.links[title] = url
        self.texts.append(f"{title} {description}")


def _app(**overrides):
    calls: list = []
    names = ("hello_settings_clicked", "face_settings_clicked", "change_master_clicked", "recovery_center_clicked",
             "check_updates_clicked", "show_shortcuts_clicked", "onboarding_clicked", "connections_clicked",
             "open_error_log_clicked", "licence_clicked", "sync_clicked")
    app = SimpleNamespace(calls=calls, **{name: (lambda *a, n=name, **k: calls.append((n, a, k))) for name in names})
    app._unlock_methods = lambda: SimpleNamespace(hello_available=True, hello_enrolled=False, recovery_phrase=True)
    app._settings_face_state = lambda: {"label": "Set up", "status": "Not set up"}
    app._settings_backup_state = lambda: {"has_password": True, "status": "Next backup tomorrow 08:30"}
    app._settings_backup_password_action = lambda *a, **k: calls.append(("backup_password", a, k))
    for key, value in overrides.items():
        setattr(app, key, value)
    return app


def _all_keys() -> list[str]:
    keys = []
    for item in sections():
        form = RecordingForm()
        item.build(form)
        keys.extend(key for _kind, key in form.keys)
    return keys


def test_built_in_sections_follow_the_mockup_order():
    assert [s.title for s in sections()] == ["Locking", "Unlocking", "Privacy", "Autofill", "Appearance & app",
                                             "Backups", "Plan & sync", "Help & diagnostics"]
    assert [s.column for s in sections()] == [0, 0, 0, 1, 1, 1, 1, 1]


def test_every_editable_preference_appears_exactly_once():
    from localvault.settings_ui import BOOLEAN_KEYS, INTEGER_KEYS

    editable = {*BOOLEAN_KEYS, *INTEGER_KEYS, "idle_source", "quick_access_hotkey", "appearance",
                "scheduled_backup_frequency", "scheduled_backup_time", "backup_mirror_dir"}
    keys = _all_keys()
    assert sorted(keys) == sorted(set(keys)), "a preference is shown twice"
    assert set(keys) == editable
    stored = {f.name for f in fields(AppSettings)}
    assert set(keys) <= stored


def test_every_key_is_accepted_by_validation():
    original = AppSettings()
    for key in _all_keys():
        settings_candidate(original, {key: getattr(original, key)})


def test_register_section_places_it_and_refuses_duplicates():
    licence = SettingsSection("licence", "Licence", lambda form: form.note("Pro"), column=1, keywords=("pro",))
    try:
        register_section(licence, before="backups")
        keys = [s.key for s in sections()]
        assert keys.index("licence") == keys.index("backups") - 1
        with pytest.raises(ValueError):
            register_section(licence)
        with pytest.raises(KeyError):
            register_section(SettingsSection("sync", "Sync", lambda form: None), after="missing")
    finally:
        unregister_section("licence")
    assert "licence" not in [s.key for s in sections()]


def test_registered_sections_get_a_palette_entry():
    sync = SettingsSection("sync", "Sync", lambda form: None, column=1, keywords=("devices", "cloud"),
                           subtitle="Keep your vault on every PC")
    try:
        register_section(sync, after="backups")
        extra = registered_section_commands()
        assert [c.id for c in extra] == ["settings-sync"]
        assert dict(extra[0].kwargs) == {"section": "sync"}
        rows = palette_results("sync", [], unlocked=True, scope="settings")
        assert any(r.title == "Sync" for r in rows)
    finally:
        unregister_section("sync")
    assert registered_section_commands() == ()


def test_buttons_call_the_existing_app_actions():
    app = _app()
    for item in sections():
        form = RecordingForm(app)
        item.build(form)
        for _label, command, _refresh in form.buttons.values():
            command()
    called = [name for name, _a, _k in app.calls]
    for name in ("hello_settings_clicked", "face_settings_clicked", "change_master_clicked",
                 "recovery_center_clicked", "check_updates_clicked", "show_shortcuts_clicked",
                 "onboarding_clicked", "open_error_log_clicked", "backup_password",
                 "licence_clicked", "sync_clicked"):
        assert name in called, name
    clears = [k for name, _a, k in app.calls if name == "backup_password"]
    assert {"clear": False} in clears and {"clear": True} in clears


def test_unlocking_reflects_status_and_hides_hello_where_unavailable():
    form = RecordingForm()
    registry.build_unlocking(form)
    assert form.buttons["Windows Hello"][0] == "Set up"
    assert form.buttons["Recovery phrase"][0] == "Manage"
    no_hello = RecordingForm(_app(_unlock_methods=lambda: SimpleNamespace(
        hello_available=False, hello_enrolled=False, recovery_phrase=None)))
    registry.build_unlocking(no_hello)
    assert "Windows Hello" not in no_hello.buttons


def test_a_failing_status_does_not_break_a_section():
    def boom():
        raise RuntimeError("locked")

    form = RecordingForm(_app(_settings_backup_state=boom, _unlock_methods=boom, _settings_face_state=boom))
    registry.build_backups(form)
    registry.build_unlocking(form)
    assert form.buttons["Backup password"][0] == "Set…"


def test_choice_options_keep_custom_stored_values():
    assert choice_label("auto_lock_seconds", 900) == "15 minutes"
    options = choice_options("auto_lock_seconds", 420)
    assert options["7 minutes"] == 420
    assert choice_label("trash_retention_days", 17) == "17 days"
    assert choice_options("automatic_backup_count", 8)["8 backups"] == 8
    assert choice_label("appearance", "system") == "System"
    assert list(choice_options("appearance", "dark")) == ["System", "Light", "Dark"]


def test_help_links_to_the_privacy_policy_and_licence_agreement():
    from localvault.shell.settings_sections import LICENCE_AGREEMENT_URL, PRIVACY_POLICY_URL, section

    form = RecordingForm(_app())
    section("help").build(form)
    assert form.links == {"Privacy policy": PRIVACY_POLICY_URL, "Licence agreement": LICENCE_AGREEMENT_URL}
    assert PRIVACY_POLICY_URL == "https://localgatekeys.app/legal/privacy.html"
    assert LICENCE_AGREEMENT_URL == "https://localgatekeys.app/legal/eula.html"


def test_recorded_link_rows_are_web_pages_only():
    from localvault.app.settings import _Recorder

    form = _Recorder(None, AppSettings())
    form.link("Privacy policy", "How LocalGateKeys handles your data", "Open", "https://localgatekeys.app/legal/privacy.html")
    form.link("Bad", "", "Open", "file:///C:/Windows/system32/calc.exe")
    assert form.rows == [{"type": "link", "title": "Privacy policy", "description": "How LocalGateKeys handles your data",
                          "label": "Open", "url": "https://localgatekeys.app/legal/privacy.html"}]

