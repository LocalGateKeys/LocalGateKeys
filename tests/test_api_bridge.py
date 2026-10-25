"""Stage 1: the bridge object exposed to the page as window.pywebview.api."""
from __future__ import annotations

import json

import pytest

from localvault.api.bridge import Api
from localvault.app.controller import WebController
from localvault.profiles import ProfileManager
from localvault.settings import AppSettings
from localvault.web.ui_port import WebUiPort

KDF = {"time_cost": 1, "memory_cost_kib": 8192, "parallelism": 1, "hash_len": 32}
PUBLIC = {
    "app_info", "vault_state", "profiles_list", "profiles_select", "vault_unlock", "vault_create",
    "vault_lock", "modal_answer", "window_minimize", "window_toggle_maximize", "window_close",
    "system_open_url",
    "security_center", "security_set", "health_report", "health_scan", "health_cancel", "master_info",
    "master_change", "backup_status", "backup_create", "backup_verify", "backup_restore", "backup_test",
    "backup_verify_trial", "backup_kit", "backup_cancel_trial", "phrase_create", "phrase_confirm", "phrase_close",
    "vault_recover", "lock_emergency", "lock_switch",
    "hello_status", "hello_enable", "hello_disable", "hello_auto_start", "hello_offer", "hello_offer_answer",
    "vault_unlock_hello", "face_status", "face_enable", "face_disable", "face_cancel", "face_switch_camera",
    "vault_unlock_face", "window_theme_sync",
    "sync_view", "sync_refresh", "sync_now", "sync_acknowledge_members", "sync_choose_folder", "sync_password_check", "sync_create", "sync_join",
    "sync_setup_text", "sync_folder_setup", "sync_rotation_text", "sync_change_password", "sync_remove_info",
    "sync_remove_device", "sync_orphans", "sync_remove_orphans", "sync_leave", "sync_reset", "sync_qr_show",
    "sync_qr_poll", "sync_qr_copy", "sync_qr_close", "sync_join_qr", "sync_wifi_suggest", "sync_wifi_enable",
    "sync_wifi_disable", "sync_firewall_status", "sync_firewall_allow",
    "import_open", "import_plan", "import_review", "import_decide", "import_decide_all", "import_apply", "import_cancel",
    "import_close", "export_formats", "export_run", "transfer_info", "transfer_choose", "transfer_inspect",
    "transfer_preview", "transfer_commit", "transfer_cancel", "legacy_import", "legacy_fresh",
    "phone_backup_choose", "phone_backup_preview", "phone_backup_commit", "phone_backup_cancel",
    "reminders_list", "reminders_complete", "reminders_snooze", "activity_list", "shortcuts_list", "collections_list",
    "collections_create", "collections_rename", "collections_archive", "catalog_status", "catalog_update",
    "onboarding_state", "onboarding_perform", "onboarding_skip", "onboarding_test_connection",
    "desktop_bind_scan", "desktop_bind_form", "desktop_bind_save", "desktop_fill",
    "desktop_signin_scan", "desktop_signin_save", "desktop_web_warning_reset",
    "qr_scan_image", "qr_scan_camera", "qr_cancel", "qr_switch_camera",
    "settings_page", "settings_set", "settings_choose_folder", "backup_password_set", "backup_password_clear",
    "licence_view", "licence_install", "licence_install_file", "licence_remove", "updates_check",
    "updates_open_release", "updates_reminder", "updates_snooze", "rating_prompt", "rating_answer", "rating_open",
    "profiles_manage", "profiles_create",
    "profiles_update", "profiles_photo", "profiles_remove_photo", "profiles_delete", "connections_view",
    "connections_repair", "connections_export", "errorlog_open",
    "nav_get", "items_list", "quick_search", "overview_get", "codes_list", "status_get",
    "item_detail", "item_reveal", "item_copy", "item_totp", "item_favorite", "item_trash", "item_open_website",
    "login_new", "login_open", "login_update", "login_regenerate", "login_save", "login_close",
    "generator_get", "generator_generate", "generator_username", "generator_copy",
    "palette_query", "palette_run",
    "typed_schema", "typed_detail", "typed_open", "typed_save", "typed_reveal", "typed_copy",
    "doc_create", "doc_replace", "doc_info", "doc_preview", "doc_open", "doc_save_copy",
    "trash_list", "trash_restore", "trash_purge", "trash_empty",
    "history_list", "history_copy", "recovery_count", "recovery_get", "recovery_save", "recovery_use_next",
    "fields_get", "fields_save", "policy_get", "policy_save", "ga_parse", "ga_apply",
}


class Bus:
    def __init__(self):
        self.events = []

    def emit(self, name, detail):
        self.events.append((name, detail))


class Ops:
    def __init__(self):
        self.calls = []

    def minimize(self):
        self.calls.append("minimize")

    def toggle_maximize(self):
        self.calls.append("toggle_maximize")

    def close(self):
        self.calls.append("close")


class Sched:
    def call_later(self, delay, fn):
        return fn

    def cancel(self, handle):
        pass


@pytest.fixture
def api(tmp_path, monkeypatch):
    monkeypatch.setattr("localvault.app.controller.clear_master_unlock_requirement", lambda _pid: None)
    profiles = ProfileManager(tmp_path / "data")
    profiles.ensure_profile()
    bus = Bus()
    # idle measured from vault use, not Windows input (the owner may be away while tests run)
    controller = WebController(profiles=profiles, settings=AppSettings(idle_source="vault"), bus=bus, scheduler=Sched(),
                               create_kwargs={"kdf_overrides": KDF})
    return Api(controller, WebUiPort(bus, timeout=1), Ops())


def test_public_surface_is_exactly_documented(api):
    public = {name for name in dir(api) if not name.startswith("_") and callable(getattr(api, name))}
    assert public == PUBLIC


def test_unlock_rejects_non_string_and_huge(api):
    assert api.vault_unlock(123)["error"]["code"] == "invalid"
    assert api.vault_unlock("x" * 1025)["error"]["code"] == "invalid"
    assert api.vault_create("a" * 12, None)["error"]["code"] == "invalid"


def _ids(values):
    return [id(v) for v in values]


def _wipe_spy(monkeypatch):
    """Record every SecretText the bridge creates and every wipe of one."""
    from localvault.secret_text import SecretText

    created, wiped = [], []
    original_from_str, original_wipe = SecretText.from_str.__func__, SecretText.wipe

    def from_str(cls, value):
        secret = original_from_str(cls, value)
        created.append(secret)
        return secret

    def wipe(self):
        wiped.append(self)
        original_wipe(self)

    monkeypatch.setattr(SecretText, "from_str", classmethod(from_str))
    monkeypatch.setattr(SecretText, "wipe", wipe)
    return created, wiped


def test_unlock_wipes_the_password_buffer_after_the_call(api, monkeypatch):
    password = "pässwörd ünlock 12"
    assert api.vault_create(password, password)["ok"] is True
    api.vault_lock()
    received = []
    real_unlock = api._controller.unlock
    monkeypatch.setattr(api._controller, "unlock", lambda secret: received.append(secret) or real_unlock(secret))
    created, wiped = _wipe_spy(monkeypatch)
    wrong = api.vault_unlock("not the password!!")
    assert wrong["ok"] is False and wrong["error"]["code"] == "wrong_password"
    assert len(created) == 1 and _ids(wiped) == _ids(created) == _ids(received)
    created.clear(), wiped.clear(), received.clear()
    assert api.vault_unlock(password)["ok"] is True
    assert len(created) == 1 and _ids(wiped) == _ids(created) == _ids(received)
    with pytest.raises(ValueError, match="secret was wiped"):
        _ = created[0].buffer


def test_create_wipes_both_buffers_even_on_mismatch(api, monkeypatch):
    created, wiped = _wipe_spy(monkeypatch)
    assert api.vault_create("first password 1", "other password 2")["error"]["code"] == "mismatch"
    assert len(created) == 2 and sorted(map(id, wiped)) == sorted(map(id, created))


def test_secret_args_reject_non_string_and_huge(api, monkeypatch):
    created, wiped = _wipe_spy(monkeypatch)
    ok_pw = "a valid password 1"
    assert api.master_change(123, ok_pw, ok_pw)["error"]["code"] == "invalid"
    assert api.master_change(ok_pw, "x" * 1025, ok_pw)["error"]["code"] == "invalid"
    assert api.master_change(ok_pw, ok_pw, None)["error"]["code"] == "invalid"
    assert api.backup_restore("Restored", "backup password 1", 123)["error"]["code"] == "invalid"
    assert api.backup_restore("Restored", "backup password 1", "x" * 1025)["error"]["code"] == "invalid"
    # Text that cannot be encoded is refused with a fixed message that never echoes it.
    lone = api.master_change(ok_pw, "bad \ud800 surrogate", ok_pw)
    assert lone["error"] == {"code": "invalid", "message": "Invalid password."}
    # A conversion that fails after another succeeded still wipes the first.
    assert sorted(map(id, wiped)) == sorted(map(id, created))


def test_errors_never_include_traceback_text(api, monkeypatch):
    def boom():
        raise RuntimeError("C:/secret/path traceback")

    monkeypatch.setattr(api._controller, "state", boom)
    result = api.vault_state()
    assert result["error"]["code"] == "internal"
    assert "secret" not in json.dumps(result)


def test_open_url_rejects_javascript_and_file(api, monkeypatch):
    opened = []
    monkeypatch.setattr("localvault.api.bridge.webbrowser.open", lambda url: opened.append(url))
    assert api.system_open_url("javascript:alert(1)")["error"]["code"] == "invalid"
    assert api.system_open_url("file:///C:/Windows")["error"]["code"] == "invalid"
    assert api.system_open_url(5)["error"]["code"] == "invalid"
    assert api.system_open_url("https://localgatekeys.app/help")["ok"] is True
    assert opened == ["https://localgatekeys.app/help"]


def test_modal_answer_routes_to_port(api):
    assert api.modal_answer("unknown", True) == {"ok": True, "accepted": False}
    assert api.modal_answer(7, True)["error"]["code"] == "invalid"


def test_window_ops(api):
    api.window_minimize()
    api.window_toggle_maximize()
    api.window_close()
    assert api._window_ops.calls == ["minimize", "toggle_maximize", "close"]


def test_unlock_happy_path_returns_state(api):
    created = api.vault_create("correct horse battery", "correct horse battery")
    assert created["ok"] is True and created["state"] == "unlocked"
    assert api.vault_lock()["state"] == "locked"
    wrong = api.vault_unlock("not the right one!!")
    assert wrong["ok"] is False and wrong["error"]["code"] in {"wrong_password", "throttled"}
    assert api.vault_unlock("correct horse battery")["state"] == "unlocked"
    assert api.profiles_list()["profiles"][0]["active"] is True
    assert api.app_info()["ok"] is True


def test_ref_validation(api):
    bad = [None, "id", {"source": "x", "id": "1", "kind": "web"}, {"source": "credential", "id": 5, "kind": "web"},
           {"source": "credential", "id": "1", "kind": "web", "extra": 1}]
    for ref in bad:
        assert api.item_detail(ref)["error"]["code"] == "invalid", ref


def test_home_groups_happy_path(api, monkeypatch):
    api.vault_create("correct horse battery", "correct horse battery")
    session = api._controller.session
    entry = session.create_web_login(urls=[{"url": "https://alpha.test", "match": "exact_origin"}],
                                     username="ann", password="pw-alpha-1234567", label="Alpha")
    listed = api.items_list(None, None, "")
    assert listed["ok"] and listed["items"][0]["title"] == "Alpha"
    assert api.nav_get()["ok"] and api.overview_get()["ok"] and api.status_get()["ok"]
    ref = {"source": "credential", "id": entry, "kind": "web"}
    assert api.item_detail(ref)["username"] == "ann"
    assert api.items_list(None, None, "x" * 600)["error"]["code"] == "invalid"
    assert api.item_favorite(ref, True)["message"] == "Added to favorites."
    view = api.login_new()
    assert view["ok"] and view["is_new"]
    updated = api.login_update(view["draft_id"], {"urls": [{"url": "https://beta.test", "match": "exact_origin"}],
                                                  "username": "bob"})
    assert updated["ok"]
    saved = api.login_save(view["draft_id"])
    assert saved["ok"] and saved["ref"]["kind"] == "web"
    generated = api.generator_generate({"length": 24})
    assert generated["ok"] and len(generated["value"]) == 24
    assert api.palette_query("alp", "everything")["rows"]
    events = [name for name, _ in api._controller._bus.events]
    assert "items.changed" in events


def test_stage3_groups_happy_path(api):
    api.vault_create("correct horse battery", "correct horse battery")
    assert api.typed_schema()["ok"]
    saved = api.typed_save(None, "note", {"title": "Router", "tags": [], "favorite": False,
                                          "values": {"body": "codes"}, "protected": {}, "clear": []})
    assert saved["ok"] and saved["ref"]["source"] == "typed"
    assert api.typed_detail(saved["ref"])["title"] == "Router"
    assert api.typed_save(None, "nope", {"title": "x"})["error"]["code"] == "invalid"
    assert api.item_trash(saved["ref"])["ok"] is False  # the web UiPort confirm times out in tests: cancelled
    session = api._controller.session
    session.item_service.delete_item(saved["ref"]["id"])
    assert api.trash_list()["rows"][0]["id"] == saved["ref"]["id"]
    assert api.trash_restore([saved["ref"]["id"]])["message"] == "Restored 1 item(s)."
    assert api.trash_restore("not-a-list")["error"]["code"] == "invalid"
    assert api.doc_create("x", "")["error"]["code"] in {"unavailable", "cancelled"}
    entry = session.create_web_login(urls=[{"url": "https://a.test", "match": "exact_origin"}], username="u",
                                     password="pw-alpha-1234567")
    ref = {"source": "credential", "id": entry, "kind": "web"}
    assert api.policy_get(ref)["policy"]["fill"] == "click"
    assert api.recovery_count(ref)["count"] == 0
    assert api.fields_get(ref, False)["fields"] == []


def test_update_check_cannot_skip_the_offline_question(api):
    import inspect

    assert list(inspect.signature(api.updates_check).parameters) == []


def test_vault_calls_wait_for_the_vault_lock_but_answers_do_not(api):
    import threading

    lock = api._controller.vault_lock
    lock.acquire()
    done = threading.Event()
    threading.Thread(target=lambda: (api.vault_state(), api.modal_answer("x", None), done.set()), daemon=True).start()
    assert done.wait(2)  # state and modal answers never wait
    blocked = threading.Event()
    threading.Thread(target=lambda: (api.items_list(None, None, ""), blocked.set()), daemon=True).start()
    assert not blocked.wait(0.3)
    lock.release()
    assert blocked.wait(2)
