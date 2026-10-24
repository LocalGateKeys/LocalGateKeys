from localvault.app.catalog import _classify_browser_submission
from localvault.app.desktop import _embedded as _is_embedded_web_selector


def test_embedded_web_selector_detects_chromium_frameworks() -> None:
    assert _is_embedded_web_selector(
        {
            "framework_id": "Chrome",
            "class_name": "Chrome_RenderWidgetHostHWND",
        }
    )
    assert _is_embedded_web_selector(
        {
            "framework_id": "Win32",
            "class_name": "CefBrowserWindow",
        }
    )


def test_embedded_web_selector_does_not_flag_native_edit_control() -> None:
    assert not _is_embedded_web_selector(
        {
            "framework_id": "Win32",
            "class_name": "Edit",
        }
    )


def test_browser_submission_classifies_exact_changed_and_new_account() -> None:
    entries = [
        {"id": "one", "username": "alice@example.com", "password": "old-secret"},
        {"id": "two", "username": "bob@example.com", "password": "bob-secret"},
    ]

    assert _classify_browser_submission(
        entries, "alice@example.com", "old-secret"
    ) == {"status": "exact", "match": True, "entry_id": "one"}

    assert _classify_browser_submission(
        entries, "alice@example.com", "new-secret"
    ) == {"status": "password_changed", "match": False, "entry_id": "one"}

    assert _classify_browser_submission(
        entries, "charlie@example.com", "charlie-secret"
    ) == {"status": "new_account", "match": False, "entry_id": None}


def test_revoke_entry_grants_drops_only_matching_grants():
    from localvault.session_guard import SessionGuard

    guard = SessionGuard("profile")
    guard.open(600)
    a = guard.grant("https://a.test", "ctx", ["entry-1"], ttl=30)
    b = guard.grant("https://b.test", "ctx", ["entry-2"], ttl=30)
    assert guard.revoke_entry_grants("entry-1") == 1
    assert guard._grants.get(a) is None and guard._grants.get(b) is not None
    assert guard.revoke_entry_grants("missing") == 0
