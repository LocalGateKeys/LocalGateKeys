"""Audit 2026-10-18 M2/M3: a strict login's extras need the master password; un-hiding a kept hidden value needs reauth."""
from __future__ import annotations

import pytest
from test_app_login_extras import KDF, MASTER, Bus, FakeClipboard, Port, Sched

from localvault.api.result import ApiError
from localvault.app.controller import WebController
from localvault.app.login_editor import LoginEditorService
from localvault.app.login_extras import LoginExtrasService
from localvault.app.secrets import SecretService
from localvault.profiles import ProfileManager
from localvault.settings import AppSettings

STRICT = {"fill": "click", "sign_in": "inherit", "require_master_password": True, "save_prompts": True}
FIELDS = [{"name": "PIN", "value": "9999", "hidden": True}, {"name": "Hint", "value": "blue", "hidden": False}]


@pytest.fixture
def env(tmp_path, monkeypatch):
    monkeypatch.setattr("localvault.app.controller.clear_master_unlock_requirement", lambda _pid: None)
    profiles = ProfileManager(tmp_path / "data")
    profiles.ensure_profile()
    controller = WebController(profiles=profiles, settings=AppSettings(idle_source="vault"), bus=Bus(),
                               scheduler=Sched(), create_kwargs={"kdf_overrides": KDF})
    controller.create(MASTER, MASTER)
    controller.clipboard = FakeClipboard()
    hellos: list[str] = []
    controller.hello_reauth = lambda title, lease: hellos.append(title) or True
    session = controller.session
    refs = {}
    for key, policy in (("plain", None), ("strict", STRICT)):
        entry = session.create_web_login(urls=[{"url": f"https://{key}.test", "match": "exact_origin"}],
                                         username=f"user-{key}", password="pw-first-1234567", label=key,
                                         notes="keep me", recovery_codes=["code-1", "code-2"],
                                         custom_fields=[dict(f) for f in FIELDS], policy=policy)
        session.update_entry_fields(entry, password="pw-second-1234567")
        refs[key] = {"source": "credential", "id": entry, "kind": "web"}
    port = Port()
    extras = LoginExtrasService(controller, port, LoginEditorService(controller, port, generate=lambda: "Gen-Pass-123456!"))
    return extras, controller, port, hellos, refs


def _grace(controller):
    """A routine reauth grace from an earlier Hello prompt (SecretService.reauthenticate(allow_hello=True))."""
    SecretService(controller, Port()).reauthenticate("Earlier routine prompt", controller.guard.lease(), allow_hello=True)
    assert controller.routine_reauth[1] > controller._clock()


STRICT_CALLS = [
    ("history", lambda x, r: x.history(r), "Enter your master password to view password history"),
    ("recovery_codes", lambda x, r: x.recovery_codes(r), "Confirm to reveal recovery codes"),
    ("recovery_codes_save", lambda x, r: x.recovery_codes_save(r, ["code-9"]),
     "Enter your master password to save recovery codes"),
    ("recovery_use_next", lambda x, r: x.recovery_use_next(r), "Enter your master password to use a recovery code"),
    ("fields_plain", lambda x, r: x.custom_fields(r, reveal=False), "Open sensitive credential"),
    ("fields_reveal", lambda x, r: x.custom_fields(r, reveal=True), "Confirm to reveal hidden fields"),
    ("fields_save", lambda x, r: x.custom_fields_save(r, [{"name": "New", "value": "v", "hidden": False}],
                                                            removed=[0, 1]),
     "Enter your master password to save custom fields"),
    ("policy_save", lambda x, r: x.policy_save(r, {"save_prompts": False}),
     "Enter your master password to change this login's rules"),
]


@pytest.mark.parametrize(("name", "call", "title"), STRICT_CALLS, ids=[c[0] for c in STRICT_CALLS])
def test_strict_login_extras_need_the_master_password_not_hello_or_grace(env, name, call, title):
    extras, controller, port, hellos, refs = env
    _grace(controller)
    hellos.clear()
    before = controller.session.credential_detail(refs["strict"]["id"])
    with pytest.raises(ApiError) as cancelled:  # no password typed: Hello and the grace must not stand in
        call(extras, refs["strict"])
    assert cancelled.value.code == "cancelled" and hellos == [] and port.asked == [title]
    assert controller.clipboard.value is None
    assert controller.session.credential_detail(refs["strict"]["id"]) == before
    port.asked.clear()
    port.passwords = [MASTER]
    call(extras, refs["strict"])
    assert port.asked[0] == title and hellos == []


def test_history_copy_on_a_strict_login_asks_for_the_master_password(env):
    extras, controller, port, hellos, refs = env
    port.passwords = [MASTER]
    row = extras.history(refs["strict"])["rows"][0]
    _grace(controller)
    hellos.clear()
    port.asked.clear()
    with pytest.raises(ApiError) as cancelled:
        extras.history_copy(refs["strict"], row["index"], row["changed_at"])
    assert cancelled.value.code == "cancelled" and hellos == [] and controller.clipboard.value is None
    assert port.asked == ["Enter your master password to copy this previous password"]
    port.passwords = [MASTER]
    extras.history_copy(refs["strict"], row["index"], row["changed_at"])
    assert controller.clipboard.value == "pw-first-1234567"


def test_strict_master_password_prompt_does_not_start_a_grace(env):
    extras, controller, port, _hellos, refs = env
    port.passwords = [MASTER]
    extras.recovery_codes(refs["strict"])
    assert controller.routine_reauth == (None, 0.0)
    with pytest.raises(ApiError):
        extras.recovery_codes(refs["strict"])


def test_wrong_master_password_denies_a_strict_login(env):
    extras, controller, port, _hellos, refs = env
    port.passwords = ["wrong password!!"]
    with pytest.raises(ApiError) as denied:
        extras.recovery_use_next(refs["strict"])
    assert denied.value.code == "not_authorized" and controller.clipboard.value is None
    assert controller.session.credential_detail(refs["strict"]["id"])["recovery_codes"] == ["code-1", "code-2"]


def test_strict_recovery_count_is_locked_without_a_prompt(env):
    extras, _controller, port, hellos, refs = env
    locked = extras.recovery_count(refs["strict"])
    assert locked["count"] is None and locked["locked"] is True and port.asked == [] and hellos == []
    assert extras.recovery_count(refs["plain"])["count"] == 2


def test_policy_read_needs_no_prompt_so_the_ui_can_tell_a_strict_login(env):
    extras, _controller, port, _hellos, refs = env
    assert extras.policy(refs["strict"])["policy"]["require_master_password"] is True and port.asked == []


def test_turning_strict_off_needs_the_master_password(env):
    extras, controller, port, hellos, refs = env
    _grace(controller)
    hellos.clear()
    with pytest.raises(ApiError):
        extras.policy_save(refs["strict"], {"require_master_password": False})
    assert hellos == [] and controller.session.credential_detail(refs["strict"]["id"])["policy"]["require_master_password"]
    port.passwords = [MASTER]
    extras.policy_save(refs["strict"], {"require_master_password": False})
    assert controller.session.credential_detail(refs["strict"]["id"])["policy"]["require_master_password"] is False


def test_turning_strict_on_and_plain_rules_need_no_prompt(env):
    extras, controller, port, hellos, refs = env
    extras.policy_save(refs["plain"], {"save_prompts": False})
    extras.policy_save(refs["plain"], {"require_master_password": True})
    assert port.asked == [] and hellos == []
    assert controller.session.credential_detail(refs["plain"]["id"])["policy"]["require_master_password"] is True


def test_non_strict_routine_secrets_still_accept_hello_and_the_grace(env):
    extras, controller, port, hellos, refs = env
    extras.history(refs["plain"])
    assert hellos == ["Enter your master password to view password history"] and port.asked == []
    extras.recovery_codes(refs["plain"])
    extras.custom_fields(refs["plain"], reveal=True)
    assert len(hellos) == 1 and port.asked == []  # the grace covers the next routine prompts


def test_non_strict_plain_reads_and_writes_need_no_prompt(env):
    extras, controller, port, hellos, refs = env
    assert extras.custom_fields(refs["plain"], reveal=False)["fields"][0]["value"] is None
    extras.recovery_codes_save(refs["plain"], ["code-9"])
    extras.recovery_use_next(refs["plain"])
    assert controller.clipboard.value == "code-9"
    assert hellos == [] and port.asked == ["Use next recovery code?"]


def test_unhiding_a_kept_hidden_value_needs_reauth(env):
    extras, controller, port, hellos, refs = env
    controller.hello_reauth = None
    unhide = [{"index": 0, "name": "PIN", "value": None, "hidden": False}, {"index": 1, "name": "Hint", "value": None,
                                                                            "hidden": False}]
    with pytest.raises(ApiError) as cancelled:
        extras.custom_fields_save(refs["plain"], unhide)
    assert cancelled.value.code == "cancelled" and port.asked == ["Confirm to reveal hidden fields"]
    assert controller.session.credential_detail(refs["plain"]["id"])["custom_fields"] == FIELDS
    port.passwords = [MASTER]
    extras.custom_fields_save(refs["plain"], unhide)
    saved = controller.session.credential_detail(refs["plain"]["id"])["custom_fields"]
    assert saved == [{"name": "PIN", "value": "9999", "hidden": False}, {"name": "Hint", "value": "blue", "hidden": False}]


def test_unhiding_on_a_plain_login_accepts_hello(env):
    extras, controller, port, hellos, refs = env
    extras.custom_fields_save(refs["plain"], [{"index": 0, "name": "PIN", "value": None, "hidden": False}], removed=[1])
    assert hellos == ["Confirm to reveal hidden fields"] and port.asked == []
    assert controller.session.credential_detail(refs["plain"]["id"])["custom_fields"][0]["hidden"] is False


def test_keeping_hidden_or_hiding_a_value_needs_no_prompt(env):
    extras, controller, port, hellos, refs = env
    extras.custom_fields_save(refs["plain"], [{"index": 0, "name": "Code", "value": None, "hidden": True},
                                              {"index": 1, "name": "Hint", "value": None, "hidden": True},
                                              {"name": "Typed", "value": "x", "hidden": False}])
    assert port.asked == [] and hellos == []
    saved = controller.session.credential_detail(refs["plain"]["id"])["custom_fields"]
    assert saved == [{"name": "Code", "value": "9999", "hidden": True}, {"name": "Hint", "value": "blue", "hidden": True},
                     {"name": "Typed", "value": "x", "hidden": False}]


def test_unhiding_on_a_strict_login_is_covered_by_its_master_password_prompt(env):
    extras, controller, port, hellos, refs = env
    port.passwords = [MASTER]
    extras.custom_fields_save(refs["strict"], [{"index": 0, "name": "PIN", "value": None, "hidden": False}], removed=[1])
    assert port.asked == ["Enter your master password to save custom fields"] and hellos == []
    assert controller.session.credential_detail(refs["strict"]["id"])["custom_fields"][0] == {
        "name": "PIN", "value": "9999", "hidden": False}


def test_detail_shows_a_strict_logins_username(env):
    # Strictness covers secrets only: list, health and trash rows show the username too.
    _extras, controller, port, _hellos, refs = env
    service = SecretService(controller, port)
    strict, plain = service.detail(refs["strict"]), service.detail(refs["plain"])
    assert strict["strict"] and strict["username"] == "user-strict" and strict["notes"] is None
    assert plain["username"] == "user-plain" and "has_username" not in strict
