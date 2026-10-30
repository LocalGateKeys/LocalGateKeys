"""Python-side UI text goes through the catalog: pseudo-locale coverage and stable ids next to the text."""
from __future__ import annotations

import re
from types import SimpleNamespace

import pytest

from localvault import i18n
from localvault.app import health as health_module
from localvault.app.home import HomeService
from localvault.shell import settings_sections
from localvault.shell.commands import palette_results
from localvault.shell.nav import build_nav
from localvault.shell.overview_model import age_text
from localvault.tray import TrayController

# Two plain ASCII words in a row: the mark of an English sentence that was not translated.
ENGLISH = re.compile(r"[A-Za-z]{3,} [A-Za-z]{2,}")


def use(monkeypatch, code):
    """Switch the active language (the test setup pins it to English through the environment)."""
    monkeypatch.setenv("LOCALGATEKEYS_LANG", code)
    i18n.set_language(code)


@pytest.fixture
def pseudo(monkeypatch):
    use(monkeypatch, "en-XA")
    yield
    monkeypatch.setenv("LOCALGATEKEYS_LANG", "en")
    i18n.set_language("en")


class _Form:
    """A SettingsForm that keeps every text a row would show."""

    def __init__(self, app):
        self.app = app
        self.settings = None
        self.texts: list[str] = []

    def _add(self, *texts):
        self.texts.extend(str(text) for text in texts)

    def switch(self, key, title, description=""):
        self._add(title, description)

    choice = segmented = text = switch

    def choose_folder(self, key, title):
        self._add(title)

    def button(self, title, description, label, command, **_kwargs):
        self._add(title, description, label)

    def shortcut(self, title, description, keys):
        self._add(title, description)

    def note(self, text):
        self._add(text)

    def link(self, title, description, label, url):
        self._add(title, description, label)


def _app():
    app = SimpleNamespace(session=None)
    app._unlock_methods = lambda: SimpleNamespace(hello_available=True, hello_enrolled=False, recovery_phrase=True)
    app._settings_face_state = lambda: {"label": i18n.t("settings.btn.setUp"), "status": i18n.t("settings.notSetUp")}
    app._settings_backup_state = lambda: {"has_password": False, "status": ""}
    for name in ("hello_settings_clicked", "face_settings_clicked", "change_master_clicked", "recovery_center_clicked",
                 "check_updates_clicked", "show_shortcuts_clicked", "onboarding_clicked", "connections_clicked",
                 "open_error_log_clicked", "licence_clicked", "sync_clicked", "rate_clicked",
                 "_settings_backup_password_action"):
        setattr(app, name, lambda *a, **k: None)
    return app


def test_settings_rows_have_no_english_under_the_pseudo_locale(pseudo):
    form = _Form(_app())
    titles = []
    for section in settings_sections.sections():
        titles.append(section.title_text)
        section.build(form)
    assert len(form.texts) > 40
    leftovers = [text for text in [*titles, *form.texts] if ENGLISH.search(text)]
    assert leftovers == []


def test_option_labels_follow_the_language(pseudo):
    from localvault.settings_ui import choice_options

    for key, current in (("auto_lock_seconds", 900), ("scheduled_backup_weekday", 2), ("appearance", "dark"),
                         ("clipboard_clear_seconds", 45), ("trash_retention_days", 17)):
        assert [label for label in choice_options(key, current) if ENGLISH.search(label)] == []


def test_tray_menu_labels_have_no_english_under_the_pseudo_locale(pseudo):
    labels = TrayController._menu_labels()
    assert len(labels) == 9 and [text for text in labels.values() if ENGLISH.search(text)] == []
    tray = TrayController(on_open=lambda: None, on_lock=lambda: None, on_unlock=lambda: None,
                          on_toggle_browser=lambda: None, on_toggle_desktop=lambda: None, on_exit=lambda: None,
                          state=dict)
    assert not ENGLISH.search(tray._title())


def test_shell_texts_have_no_english_under_the_pseudo_locale(pseudo):
    groups = build_nav([], [], [], unlocked=True)
    texts = [group.name for group in groups] + [entry.label for group in groups for entry in group.entries]
    rows = palette_results("", [], unlocked=True, limit=100)
    texts += [row.title for row in rows] + [row.subtitle for row in rows]
    texts += [age_text(5), age_text(7200)]
    assert [text for text in texts if ENGLISH.search(text)] == []


def test_texts_follow_a_language_change_at_runtime(monkeypatch):
    english = [e.label for e in build_nav([], [], [], unlocked=False)[-1].entries]
    use(monkeypatch, "en-XA")
    assert [e.label for e in build_nav([], [], [], unlocked=False)[-1].entries] != english
    use(monkeypatch, "en")
    assert [e.label for e in build_nav([], [], [], unlocked=False)[-1].entries] == english


def test_api_error_keeps_its_code_when_the_message_changes(monkeypatch):
    from localvault.api.result import ApiError

    english = ApiError("invalid", i18n.t("error.lockedProfile"))
    use(monkeypatch, "en-XA")
    translated = ApiError("invalid", i18n.t("error.lockedProfile"))
    assert english.code == translated.code == "invalid" and english.message != translated.message


def test_empty_states_carry_an_action_id():
    home = HomeService(SimpleNamespace(is_unlocked=lambda: False))
    items = home.items(None, None, "")
    assert items["empty"]["action_id"] == "unlock"
    from localvault.app.home import _EMPTY_FILTERED, _EMPTY_NONE, _empty

    assert _empty(_EMPTY_FILTERED)["action_id"] == "clear_filters"
    assert _empty(_EMPTY_NONE)["action_id"] == "new_item"


def test_empty_state_id_is_the_same_in_every_language(pseudo):
    from localvault.app.home import _EMPTY_FILTERED, _empty

    empty = _empty(_EMPTY_FILTERED)
    assert empty["action_id"] == "clear_filters" and empty["action"] != "Clear filters"


def test_breach_state_is_a_code_beside_the_text():
    assert health_module.HealthService._breach_text(("found", 3)) == "Found in 3 breaches"
    assert health_module.HealthService._breach_text(None) == "Not checked"
    assert health_module.HealthService._breach_text(("clear",)) == "Not found"


def test_strength_labels_are_translated_at_use(pseudo):
    from localvault.password_tools import assess_password, strength_label

    assert not ENGLISH.search(strength_label(0)) and strength_label(0) != "Very weak"
    assert assess_password("abc").label != "Very weak"


def test_sync_view_texts_have_no_plain_english(pseudo):
    from localvault.app import sync_view as sv
    from localvault.sync.runner import SyncIssue

    texts = [sv.PASSWORD_ADVICE, sv.LEAVE_TEXT, sv.RESET_TEXT_1, sv.ROLLBACK_TITLE]
    texts = [i18n.t(key) for key in texts]
    texts += [i18n.t(key) for key in sv.ISSUE_COPY.values()]
    texts += [i18n.t(key) for key in sv.ERROR_COPY.values()]
    texts += [sv.issue_text(SyncIssue(kind, "")) for kind in sv.ISSUE_COPY]
    texts += [sv.remove_wifi_device_text("X1"), sv.reset_result_text(True), sv.ago_text(None, 5.0),
              sv.ago_text(0, 7200.0), sv.countdown_text(75), sv.countdown_text(0), sv.validate_lan_endpoint("")[1],
              sv.validate_lan_endpoint("1.2.3.4:80")[1], sv.check_sync_password("a", "b").message]
    view = sv.sync_view(None, None, lan_endpoint="", now=1.0, available=True)
    for card in (view.wifi, view.folder):
        texts += [card.title, card.state_text, card.hint or ""]
    plain = [text for text in texts if ENGLISH.search(text.replace("{subject}", ""))]
    assert plain == []


def test_sync_view_texts_follow_a_language_change(monkeypatch):
    from localvault.app import sync_view as sv

    english = sv.reset_result_text(True)
    use(monkeypatch, "en-XA")
    assert sv.reset_result_text(True) != english
    use(monkeypatch, "en")
    assert sv.reset_result_text(True) == english


def test_recovery_center_notes_have_no_plain_english(pseudo):
    from localvault.app.recovery_center import recovery_phrase_change_warnings

    notes = recovery_phrase_change_warnings({"operation": "replace", "reenroll_required": ["hello", "face"],
                                             "retained_old_copies": 2})
    assert len(notes) == 3 and [note for note in notes if ENGLISH.search(note)] == []


def test_import_export_texts_have_no_plain_english(pseudo):
    from localvault.app import import_export as ie

    plan = SimpleNamespace(summary=lambda: {"add": 1, "replace": 0, "merge": 0, "skip": 1, "total": 2, "limited": 1,
                                            "skipped_rows": 1},
                           limit_note=lambda: "", diagnostics=())
    summary = SimpleNamespace(count=2, path="C:/x", format="csv", label="CSV", skipped=1, encrypted=False,
                              warnings=())
    texts = [ie.import_summary_text(plan, 1), ie.export_summary_text(summary), ie._summary_line(plan),
             i18n.t(ie.IMPORT_SUBTITLE, label="CSV", count=2), i18n.t(ie.EXPORT_INTRO)]
    texts += [i18n.t(key) for key in ie._MAPPING_LABELS.values()]
    assert [text for text in texts if ENGLISH.search(text)] == []


# ---------------------------------------------------------------- 6c: errors, notices, services

def test_api_error_keeps_its_code_and_translates_the_message(pseudo):
    from localvault.api.result import ApiError, fail, guarded

    error = ApiError("locked", i18n.t("error.lockedProfile"))
    assert error.code == "locked" and not ENGLISH.search(error.message)

    @guarded
    def boom():
        raise RuntimeError("secret detail")

    result = boom()
    assert result["error"]["code"] == "internal" and not ENGLISH.search(result["error"]["message"])
    assert result["error"]["error_log"] is True
    assert "secret detail" not in result["error"]["message"]
    assert "error_log" not in fail("invalid", "x")["error"]


def test_error_log_flag_travels_with_the_message_in_every_language(monkeypatch):
    from localvault.api.result import ERROR_LOG_KEYS, ApiError, points_to_error_log

    for code in ("en", "en-XA"):
        use(monkeypatch, code)
        for key in ERROR_LOG_KEYS:
            assert ApiError("x", i18n.t(key)).error_log is True
            assert points_to_error_log(f"Title {i18n.t(key)}")
        assert ApiError("x", i18n.t("error.cancelled")).error_log is False
    use(monkeypatch, "en")
    assert ApiError("x", "See the error log.").error_log is False  # no guessing from wording
    assert ApiError("x", "free text", error_log=True).error_log is True


def test_every_catalog_message_naming_the_error_log_is_flagged():
    import json
    from localvault.api.result import ERROR_LOG_KEYS

    catalog = json.loads((i18n.CATALOG_DIR / "en.json").read_text(encoding="utf-8"))
    labels = {"command.error-log.title", "command.settings-help.subtitle", "errorLogLink.notOpened", "errorLogLink.open",
              "home.errorLogNotOpened", "settings.errorLog.title", "toast.openErrorLog"}
    named = {key for key, value in catalog.items() if isinstance(value, str) and "error log" in value.lower()}
    assert named - labels == set(ERROR_LOG_KEYS)


def test_toast_and_notice_events_carry_the_error_log_flag(pseudo):
    from localvault.web.bus import EventBus

    sent: list[str] = []
    bus = EventBus(sent.append)
    bus.emit("toast", {"kind": "error", "message": i18n.t("schedule.scheduledBackupFailedThePrevious")})
    bus.emit("toast", {"kind": "info", "message": i18n.t("error.cancelled")})
    assert '"error_log":true' in sent[0] and "error_log" not in sent[1]


def test_6c_service_payloads_have_no_plain_english(pseudo):
    from localvault.app import connections, licence_view, onboarding, qr_accounts
    from localvault.face_unlock import STALE_MESSAGE

    texts = [i18n.t(STALE_MESSAGE), i18n.t(connections.FOOTER), i18n.t(licence_view.PRO_PITCH)]
    texts += [i18n.t(key) for key in onboarding.LABELS.values()] + [i18n.t(key) for key in onboarding.TEXT.values()]
    texts += [i18n.t(key) for key in onboarding.PRIMARY.values()]
    texts += [i18n.t(key) for key in connections.FRIENDLY.values()]
    texts += [i18n.t("qrAccounts.newLoginsWith2fa", count=2), i18n.t("trash.restoredItems", count=1),
              i18n.t("phoneBackupWeb.skippedWere", count=3), i18n.t("phoneBackupWeb.missingWillBe", count=1),]
    assert [text for text in texts if ENGLISH.search(text)] == []


def test_recovery_errors_are_translated_but_keep_their_type(pseudo):
    from localvault.recovery import RecoveryError, sha256_file

    with pytest.raises(RecoveryError) as raised:
        sha256_file("Z:/definitely/missing/file.bin")
    assert not ENGLISH.search(str(raised.value))


def test_engine_errors_shown_to_users_are_translated(pseudo):
    from localvault.export import ExportWarning, ExportSummary

    from localvault import vault

    errors = [vault.LoginChangedError(), vault.DuplicateLoginError("x"), vault.ItemLimitReached(4, 4),
              vault.ProFeatureRequired("totp"), vault.ProFeatureRequired("other")]
    texts = [str(error) for error in errors] + list(ExportWarning.for_format("csv", include_totp=True))
    texts.append(ExportSummary(path="x", format="kdbx", count=1).label)
    assert [text for text in texts if ENGLISH.search(text)] == []


def test_qr_needs_password_note_stays_english_in_the_vault(monkeypatch):
    from localvault.app import qr_accounts

    use(monkeypatch, "de")
    try:
        assert qr_accounts.NEEDS_PASSWORD_NOTE.startswith("Password not set")
        assert "qr_accounts" and not qr_accounts.NEEDS_PASSWORD_NOTE.startswith("qrAccounts.")
    finally:
        use(monkeypatch, "en")
