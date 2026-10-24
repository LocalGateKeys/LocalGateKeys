"""Settings save as you change them: SettingsService.apply in the WebView app.

Ported from the classic FeatureUI.apply_settings_change tests; the shared fixture lives in
test_app_settings.
"""
from __future__ import annotations

import pytest

from localvault.api.result import ApiError
from test_app_settings import env  # noqa: F401 - pytest fixture


def test_a_policy_change_is_saved_and_applied_without_locking(env):  # noqa: F811
    service, controller, _port, _bus, saved, _ = env
    service.apply("clipboard_clear_seconds", 60)
    assert controller.settings.clipboard_clear_seconds == 60
    assert controller.clipboard.timeout_seconds == 60
    assert saved == [controller.settings]
    assert controller.is_unlocked()
    assert controller.guard.valid(controller.guard.lease())


def test_lowering_the_session_maximum_applies_to_the_open_session(env):  # noqa: F811
    service, controller, *_ = env
    service.apply("max_session_seconds", 3600)
    assert controller.guard.max_seconds == 3600
    assert controller.guard.remaining() <= 3600


def test_an_invalid_value_raises_and_writes_nothing(env):  # noqa: F811
    service, controller, _port, _bus, saved, _ = env
    before = controller.settings
    with pytest.raises(ApiError):
        service.apply("clipboard_clear_seconds", 3)
    with pytest.raises(ApiError):
        service.apply("quick_access_hotkey", "K")
    assert controller.settings is before
    assert saved == []


def test_locked_vault_refuses_without_writing(env):  # noqa: F811
    service, controller, _port, _bus, saved, _ = env
    controller.lock()
    with pytest.raises(ApiError) as locked:
        service.apply("lock_on_sleep", False)
    assert locked.value.code == "locked"
    assert saved == []


def test_unchanged_value_is_a_no_op(env):  # noqa: F811
    service, controller, _port, _bus, saved, _ = env
    service.apply("lock_on_sleep", controller.settings.lock_on_sleep)
    assert saved == []
