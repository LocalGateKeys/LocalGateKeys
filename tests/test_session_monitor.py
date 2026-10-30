from __future__ import annotations

import pytest

from localvault import session_monitor as sm


@pytest.mark.parametrize("code, text", [
    (0x7, "locked"), (0x6, "signed out"), (0x2, "user switched"), (0x4, "Remote Desktop"),
])
def test_session_changes_that_lock(code, text):
    assert text in sm.session_lock_reason(sm.WM_WTSSESSION_CHANGE, code)


def test_session_changes_that_do_not_lock():
    for code in (0x1, 0x3, 0x5, 0x8):  # console connect, remote connect, logon, unlock
        assert sm.session_lock_reason(sm.WM_WTSSESSION_CHANGE, code) is None
    assert sm.session_lock_reason(0x0001, 0x7) is None  # another window message


def test_user_switch_and_remote_disconnect_follow_the_session_lock_setting():
    # web/host.py maps any reason without "sleep"/"suspend" to lock_on_session_lock
    for reason in sm.SESSION_LOCK_REASONS.values():
        lower = reason.lower()
        assert "sleep" not in lower and "suspend" not in lower
