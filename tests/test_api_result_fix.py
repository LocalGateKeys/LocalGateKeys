"""A failure caused by a setting carries a ``fix`` the page turns into buttons."""
from localvault.api.result import ApiError, guarded
from localvault.app import schedule


def test_fix_reaches_the_page_and_plain_errors_stay_unchanged():
    fix = {"section": "privacy", "key": "breach_check_enabled", "value": True}

    @guarded
    def blocked():
        raise ApiError("needs_setting", "Off.", fix=fix)

    @guarded
    def plain():
        raise ApiError("refused", "No.")

    assert blocked() == {"ok": False, "error": {"code": "needs_setting", "message": "Off.", "fix": fix}}
    assert plain() == {"ok": False, "error": {"code": "refused", "message": "No."}}


def test_skipped_backup_toast_links_to_backups_settings():
    assert schedule.SKIPPED_ACTION == {"label": "Open Backups settings", "route": "settings",
                                       "params": {"section": "backups"}}


def test_copy_links_to_the_clipboard_setting_only_when_auto_clear_is_off():
    from types import SimpleNamespace

    from localvault.app.setting_links import clipboard_result

    assert clipboard_result("Password copied.", SimpleNamespace(timeout_seconds=30)) == {
        "message": "Password copied. Clipboard clears in 30 seconds."}
    off = clipboard_result("Password copied.", SimpleNamespace(timeout_seconds=0))
    assert off["message"] == "Password copied. Clipboard auto-clear is off."
    assert off["action"]["params"] == {"section": "privacy"}


def test_scan_all_question_counts_unique_passwords_and_time():
    from localvault.app.health import scan_all_text

    assert scan_all_text(1, 3).startswith("Checks 1 unique password from 3 logins")
    assert "(under a minute)" in scan_all_text(10, 12)
    assert "(about 3 minutes)" in scan_all_text(120, 150)


def test_palette_hides_commands_this_window_cannot_open():
    from localvault.app.tools import NOT_IN_WINDOW
    from localvault.shell.commands import COMMANDS

    assert NOT_IN_WINDOW <= {c.id for c in COMMANDS}


def test_settings_page_sends_section_keywords_for_search():
    from localvault.shell.settings_sections import sections

    privacy = next(s for s in sections() if s.key == "privacy")
    assert "clipboard" in privacy.keywords  # the page searches these, like the command palette
