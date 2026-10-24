"""Change master password reachability and per-entry policy invalidation."""
from __future__ import annotations

from types import SimpleNamespace

import pytest

from localvault.session_guard import StaleSession
from localvault.settings import AppSettings
from test_app_login_extras import env  # noqa: F401 - pytest fixture


def test_settings_unlocking_section_calls_change_master() -> None:
    from localvault.shell.settings_sections import build_unlocking

    clicks: list[bool] = []
    buttons: dict[str, object] = {}
    form = SimpleNamespace(
        app=SimpleNamespace(change_master_clicked=lambda: clicks.append(True)),
        settings=AppSettings(),
        switch=lambda *_a, **_k: None,
        button=lambda title, _desc, _label, command, **_k: buttons.update({title: command}),
    )
    build_unlocking(form)
    buttons["Master password"]()
    assert clicks == [True]


def test_policy_change_revokes_only_that_entrys_pending_fill_grants(env) -> None:  # noqa: F811
    extras, controller, _port, _editor, ref = env
    guard = controller.guard
    lease = guard.lease()
    entry = ref["id"]
    token_a = guard.grant("https://a.test", "ctx", [entry])
    token_ab = guard.grant("https://b.test", "ctx", [entry, "entry-b"])
    token_b = guard.grant("https://b.test", "ctx", ["entry-b"])

    result = extras.policy_save(ref, {"require_master_password": True})

    assert "2 pending fill permission(s)" in result["message"]
    assert controller.is_unlocked()
    assert guard.valid(lease)
    with pytest.raises(StaleSession):
        guard.permission(token_a, "https://a.test", "ctx", entry)
    with pytest.raises(StaleSession):
        guard.permission(token_ab, "https://b.test", "ctx", "entry-b")
    assert guard.permission(token_b, "https://b.test", "ctx", "entry-b") == lease


def test_unchanged_policy_revokes_nothing(env) -> None:  # noqa: F811
    extras, controller, _port, _editor, ref = env
    token = controller.guard.grant("https://a.test", "ctx", [ref["id"]])
    current = extras.policy(ref)["policy"]
    extras.policy_save(ref, {"fill": current["fill"]})
    assert controller.guard.permission(token, "https://a.test", "ctx", ref["id"])
