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
    "vault_lock", "vault_dismiss_erased", "modal_answer", "window_minimize", "window_toggle_maximize", "window_close",
    "system_open_url", "i18n_bundle",
    "security_center", "network_activity", "security_set", "health_report", "health_scan", "health_cancel", "master_info",
    "master_change", "backup_status", "backup_create", "backup_choose", "backup_verify", "backup_restore", "backup_test",
    "backup_verify_trial", "backup_kit", "backup_cancel_trial", "backup_restore_phrase", "backup_factors",
    "backup_factor_keyfile", "backup_factors_clear", "factors_status", "factors_pick_keyfile", "factors_add_keyfile",
    "factors_create_keyfile", "factors_add_yubikey", "factors_check_backup_yubikey", "factors_remove", "factors_set_always_ask", "factors_set_remember",
    "factors_cancel", "phrase_create", "phrase_confirm", "phrase_close", "recovery_kit_facts",
    "vault_recover", "lock_emergency", "lock_switch",
    "hello_status", "hello_enable", "hello_disable", "hello_auto_start", "hello_offer", "hello_offer_answer",
    "vault_unlock_hello", "face_status", "face_enable", "face_disable", "face_cancel", "face_switch_camera",
    "vault_unlock_face", "window_theme_sync",
    "security_key_status", "security_key_enable", "security_key_disable", "vault_unlock_security_key",
    "sync_view", "sync_refresh", "sync_now", "sync_acknowledge_members", "sync_acknowledge_rollback",
    "sync_dismiss_peer_rollback", "sync_choose_folder", "sync_password_check", "sync_create", "sync_join",
    "sync_setup_text", "sync_folder_setup", "sync_rotation_text", "sync_change_password", "sync_remove_info",
    "sync_remove_device", "sync_lost_device", "sync_orphans", "sync_remove_orphans", "sync_leave", "sync_reset", "sync_qr_show",
    "sync_qr_poll", "sync_qr_copy", "sync_qr_close", "sync_join_qr", "sync_find_again_qr", "sync_wifi_suggest", "sync_wifi_enable",
    "sync_wifi_disable", "sync_firewall_status", "sync_firewall_allow",
    "import_open", "import_plan", "import_review", "import_decide", "import_decide_all", "import_apply", "import_cancel",
    "import_close", "import_undo", "export_formats", "export_coverage", "export_items", "export_run", "transfer_info", "transfer_choose", "transfer_inspect",
    "transfer_preview", "transfer_commit", "transfer_cancel", "legacy_import", "legacy_fresh",
    "share_start", "share_revoke", "restore_test_status", "restore_test_pick", "restore_test_run", "change_password_open", "health_report_print", "estate_create", "share_save_file", "share_qr", "share_cancel", "share_receive_file", "share_receive_text",
    "share_receive_qr_image", "share_incoming",
    "share_preview", "share_save", "share_reject",
    "phone_backup_choose", "phone_backup_preview", "phone_backup_commit", "phone_backup_cancel",
    "reminders_list", "reminders_complete", "reminders_snooze", "activity_list", "activity_verify", "activity_export", "developer_agents_set", "shortcuts_list", "collections_list",
    "collections_create", "collections_rename", "collections_archive", "catalog_status", "catalog_update",
    "collection_share_members", "collection_share_choose_folder", "collection_share_create", "collection_share_join",
    "collection_share_rejoin", "collection_share_approve", "collection_share_remove_member", "collection_share_leave",
    "collection_share_forget_link", "collection_share_upgrade", "onboarding_state", "onboarding_perform", "onboarding_skip", "onboarding_test_connection",
    "onboarding_card", "history_restore", "sync_status", "onboarding_skip_all", "onboarding_hide", "onboarding_show",
    "desktop_bind_scan", "desktop_bind_form", "desktop_bind_save", "desktop_fill",
    "desktop_signin_scan", "desktop_signin_save", "desktop_web_warning_reset",
    "qr_scan_image", "qr_scan_camera", "qr_cancel", "qr_switch_camera",
    "qr_sheet_scan_image", "qr_sheet_scan_camera", "qr_sheet_open", "qr_sheet_add", "qr_sheet_discard",
    "settings_page", "settings_set", "settings_choose_folder", "backup_password_set", "backup_password_change",
    "backup_password_reset", "backup_key_rebind", "backup_key_confirm", "backup_key_remove", "backup_notice_dismiss",
    "licence_view", "licence_install", "licence_install_file", "licence_remove", "updates_check",
    "updates_open_release", "updates_reminder", "updates_snooze", "rating_prompt", "rating_answer", "rating_open",
    "store_move_notice", "store_move_answer", "store_move_open",
    "profiles_manage", "profiles_create",
    "profiles_update", "profiles_photo", "profiles_remove_photo", "profiles_delete", "connections_view", "developer_status", "developer_set", "developer_key_toggle",
    "developer_generate_key", "developer_copy_public_key", "developer_env_apply", "developer_env_undo",
    "developer_git_plan", "developer_git_apply", "developer_git_undo", "developer_cli_get", "developer_cli_set",
    "developer_cli_item_toggle", "developer_copy_reference", "developer_agent_item_get", "developer_agent_item_set",
    "agent_exposure_get", "agent_exposure_dismiss",
    "secret_scan_choose_folder", "secret_scan_start", "secret_scan_cancel", "secret_scan_import",
    "secret_scan_rewrite_preview", "secret_scan_rewrite_apply",
    "connections_repair", "connections_export", "passkey_doctor_view", "passkey_doctor_status", "passkey_doctor_open_settings", "errorlog_open",
    # feature pack 2026-11-15
    "access_get", "access_save", "item_history_list", "item_history_diff", "item_history_restore_field",
    "travel_get", "travel_save", "travel_off", "hygiene_scan", "hygiene_merge_preview", "hygiene_merge",
    "hygiene_merge_all", "hygiene_delete", "hygiene_undo", "privacy_proof_get", "privacy_proof_export",
    "autotype_settings_get", "autotype_settings_set", "autotype_run",
    "nav_get", "items_list", "items_sort_set", "import_card_dismiss", "notes_formatting_get", "notes_formatting_set", "quick_search", "overview_get", "codes_list", "codes_collapsed_set", "status_get",
    "item_detail", "item_reveal", "item_copy", "item_totp", "item_favorite", "item_trash", "item_open_website",
    "login_new", "login_open", "login_update", "login_regenerate", "login_save", "login_close", "login_copy_password",
    "generator_get", "generator_generate", "generator_username", "generator_copy",
    "palette_query", "palette_run", "palette_copy", "palette_fill", "palette_hide",
    "typed_schema", "typed_detail", "typed_open", "typed_save", "typed_reveal", "typed_wifi_qr", "typed_copy",
    "doc_create", "doc_replace", "doc_info", "doc_preview", "doc_open", "doc_save_copy",
    "trash_list", "trash_restore", "trash_purge", "trash_empty",
    "history_list", "history_copy", "recovery_count", "recovery_get", "recovery_save", "recovery_use_next",
    "fields_get", "fields_save", "policy_get", "policy_save", "ga_parse", "ga_apply",
    "heir_plan_list", "heir_plan_choose_folder", "heir_plan_create", "heir_plan_sheet", "heir_plan_save",
    "heir_plan_set_folder",
    "heir_plan_done", "heir_plan_deny", "heir_plan_grant", "heir_backup_now", "heir_receive_view",
    "heir_shard_add_file", "heir_shard_add_text", "heir_shards_clear", "heir_receive_folder",
    "heir_request_create", "heir_restore", "duress_status", "duress_setup", "duress_remove",
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


def _dispatch_unlock(api, monkeypatch, prepare):
    """Send vault_unlock through pywebview's own dispatch (guard, worker thread, page facade) like a page message.

    Returns (extra references to the password str while the controller unlocks, the page's argument list).
    """
    import sys
    import threading

    util = pytest.importorskip("webview.util")
    from localvault.api.bridge import PAGE_CALLS, page_api
    from localvault.web import window as web_window

    password = "".join(["correct horse ", "battery staple"])  # a fresh str, as json.loads makes one

    def count():
        return sys.getrefcount(password)

    baseline = count()
    seen = []
    real_unlock = api._controller.unlock

    def unlock(secret, **kwargs):
        seen.append(count() - baseline)
        return real_unlock(secret, **kwargs)

    monkeypatch.setattr(api._controller, "unlock", unlock)
    threads = []

    class Recorded(threading.Thread):
        def start(self):
            threads.append(self)
            super().start()

    monkeypatch.setattr(util, "Thread", Recorded)

    class Window:
        _functions: dict = {}
        _js_api = page_api(api)
        evaluated: list = []

        def evaluate_js(self, code):
            self.evaluated.append(code)

    window = Window()
    guard = web_window.guard_js_bridge_call(util.js_bridge_call, PAGE_CALLS, prepare)
    message = [password, False]  # what pywebview decoded from the page message
    guard(window, "vault_unlock", message, "1")
    for thread in threads:
        thread.join(10)
    assert len(window.evaluated) == 1 and "unlocked" in window.evaluated[0]
    return seen, message


def test_page_password_is_released_before_the_key_derivation(api, monkeypatch):
    from localvault.api.bridge import PageSecret, hold_page_secrets

    assert api.vault_create("correct horse battery staple", "correct horse battery staple")["ok"] is True
    api.vault_lock()
    seen, message = _dispatch_unlock(api, monkeypatch, hold_page_secrets)
    # While the controller derives the key, nothing but this test refers to the page's str.
    assert seen == [0]
    assert isinstance(message[0], PageSecret) and message[0].take() is None and message[1] is False


def test_without_the_holder_pywebview_keeps_the_password_for_the_whole_call(api, monkeypatch):
    """Why the holder exists: pywebview's worker and the frames down to the bridge keep their arguments."""
    assert api.vault_create("correct horse battery staple", "correct horse battery staple")["ok"] is True
    api.vault_lock()
    seen, _message = _dispatch_unlock(api, monkeypatch, None)
    assert seen[0] > 0


def test_page_secret_is_taken_once_and_never_shown(api):
    from localvault.api.bridge import PAGE_SECRET_ARGS, PageSecret, hold_page_secrets

    holder = PageSecret("correct horse battery")
    assert "correct" not in repr(holder) and "correct" not in str(holder)
    assert api.vault_create(holder, PageSecret("correct horse battery"))["ok"] is True
    assert holder.take() is None
    # A holder already taken is an invalid argument, not a crash.
    assert api.vault_unlock(holder)["error"]["code"] == "invalid"
    # Only non-empty strings at the listed positions are swapped; other calls are left alone.
    args = ["Restored", "backup pw", "", None]
    hold_page_secrets("backup_restore", args)
    assert args[0] == "Restored" and isinstance(args[1], PageSecret) and args[2] == "" and args[3] is None
    other = ["correct horse battery"]
    hold_page_secrets("profiles_select", other)
    assert other == ["correct horse battery"]
    assert PAGE_SECRET_ARGS["vault_unlock"] == {0} and PAGE_SECRET_ARGS["master_change"] == {0, 1, 2}
    assert PAGE_SECRET_ARGS["restore_test_run"] == {1, 2}


def test_every_page_secret_position_reaches_only_secret_text(api, monkeypatch):
    """Each listed argument, sent as a holder, is taken by _secret (so no call compares or keeps the str)."""
    import inspect

    from localvault.api.bridge import PAGE_SECRET_ARGS, PageSecret

    taken = []
    original_take = PageSecret.take

    def take(self):
        taken.append(self)
        return original_take(self)

    monkeypatch.setattr(PageSecret, "take", take)
    for name, positions in PAGE_SECRET_ARGS.items():
        params = list(inspect.signature(getattr(api, name)).parameters)
        args = ["a valid value 12"] * len(params)
        if name in ("duress_setup",):
            args[3] = 24
        if name == "export_run":
            args[1] = False
        if name == "backup_password_change":
            args[3] = True
        if name in ("duress_setup", "export_run"):
            args[-1] = None
        holders = []
        for index in positions:
            holders.append(PageSecret("a valid password 1"))
            args[index] = holders[-1]
        taken.clear()
        assert isinstance(getattr(api, name)(*args), dict), name
        assert len(taken) == len(holders) and all(any(h is t for t in taken) for h in holders), name


def test_unlock_failure_keeps_the_password_out_of_reply_and_error_log(api, monkeypatch):
    import logging

    from localvault import error_log

    password = "hunter2 unique Pw 77"

    def boom(secret, **kwargs):
        raise RuntimeError(f"failed while unlocking with {password}")

    monkeypatch.setattr(api._controller, "unlock", boom)
    logger = error_log._logger()
    lines = []
    handler = logging.Handler()
    handler.emit = lambda record: lines.append(record.getMessage())
    logger.addHandler(handler)
    try:
        result = api.vault_unlock(password)
        too_many = api.vault_unlock(password, False, "extra")  # a malformed page call: a TypeError inside
    finally:
        logger.removeHandler(handler)
    assert result["error"]["code"] == "internal" and too_many["error"]["code"] == "internal"
    assert lines and all("hunter2" not in line for line in lines)
    assert "hunter2" not in json.dumps([result, too_many])


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
    assert api.trash_restore([saved["ref"]["id"]])["message"] == "Restored 1 item."
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


def test_i18n_bundle_returns_current_language_and_catalog(api):
    from localvault import i18n
    r = api.i18n_bundle()
    assert r["ok"] is True
    assert r["lang"] == i18n.current()
    assert r["messages"] == i18n.catalog()


def test_notes_formatting_switch_round_trips(api, monkeypatch):
    settings = api._controller.settings
    saved = []
    monkeypatch.setattr(settings, "save", lambda: saved.append(settings.notes_show_formatting))
    assert api.notes_formatting_get() == {"ok": True, "enabled": True}
    assert api.notes_formatting_set(False) == {"ok": True, "enabled": False}
    assert api.notes_formatting_get()["enabled"] is False and saved == [False]
    assert api.notes_formatting_set("no")["error"]["code"] == "invalid"
    assert api.notes_formatting_set(None)["error"]["code"] == "invalid"
    assert api.notes_formatting_get()["enabled"] is False


def test_notes_formatting_setting_persists(tmp_path):
    path = tmp_path / "settings.json"
    assert AppSettings().notes_show_formatting is True
    AppSettings(notes_show_formatting=False).save(path)
    assert AppSettings.load(path).notes_show_formatting is False


# ------------------------------------------------------- quick-search palette
_LOGIN = {"source": "credential", "id": "abc", "kind": "desktop"}


def test_palette_copy_rejects_an_unknown_field(api):
    api.vault_create("correct horse battery", "correct horse battery")
    assert api.palette_copy(_LOGIN, "notes")["error"]["code"] == "invalid"
    assert api.palette_copy("nope", "password")["error"]["code"] == "invalid"


def test_palette_copy_uses_the_item_copy_service(api, monkeypatch):
    api.vault_create("correct horse battery", "correct horse battery")
    seen = []
    monkeypatch.setattr(api._palette_secrets, "copy", lambda ref, field: seen.append((ref, field)) or {"message": "ok"})
    for field in ("username", "password", "totp"):
        assert api.palette_copy(_LOGIN, field)["ok"] is True
    assert seen == [(_LOGIN, "username"), (_LOGIN, "password"), (_LOGIN, "totp")]


def test_palette_copy_on_a_locked_vault_is_refused(api):
    assert api.palette_copy(_LOGIN, "password")["ok"] is False


class _Desktop:
    def __init__(self):
        self.calls = []

    def fill_entry_into(self, entry_id, hwnd, *, hide, show_again):
        self.calls.append((entry_id, hwnd))
        return {}


def test_palette_fill_fills_the_chosen_desktop_login_into_the_saved_window(api):
    api.vault_create("correct horse battery", "correct horse battery")
    api._desktop = desktop = _Desktop()
    api._palette_target = lambda: 4242
    assert api.palette_fill(_LOGIN)["ok"] is True
    assert desktop.calls == [("abc", 4242)]


def test_palette_fill_never_fills_another_login_for_an_unfillable_row(api):
    api.vault_create("correct horse battery", "correct horse battery")
    api._desktop = desktop = _Desktop()
    api._palette_target = lambda: 4242
    for ref in ({"source": "credential", "id": "w1", "kind": "web"}, {"source": "typed", "id": "n1", "kind": "note"}):
        reply = api.palette_fill(ref)
        assert reply["error"]["code"] == "cannot_fill"
        assert reply["error"]["message"] == "This item can't fill that app. Copy it instead."
    assert desktop.calls == []


def test_palette_fill_checks_the_vault_and_the_item(api):
    api._desktop = desktop = _Desktop()
    assert api.palette_fill(_LOGIN)["error"]["code"] == "locked"
    api.vault_create("correct horse battery", "correct horse battery")
    assert api.palette_fill({"id": "x"})["error"]["code"] == "invalid"
    assert desktop.calls == []


def test_palette_prompts_go_to_the_palette_window(api):
    assert api._palette_secrets._port._surface == "palette"
    assert api._secrets._port is api._port


def test_palette_hide_runs_the_app_hook(api):
    hidden = []
    api._palette_hide = lambda: hidden.append(True)
    assert api.palette_hide()["ok"] is True and hidden == [True]


# --- shared collections (sub-plan 07 Task 3) --------------------------------------------------------------

SHARE_PW = "correct horse battery staple 7!"
SHARE_PW2 = "another very long passphrase 42?"
CHEAP_KDF = (1024, 1, 1)


class FakeDialogs:
    def __init__(self, folder):
        self.folder = folder

    def choose_folder(self, title):
        return str(self.folder)


class AskPort:
    """Answers every confirmation (``yes``) and records what it showed."""

    def __init__(self, yes=True):
        self.yes = yes
        self.asked = []
        self.upgrades = []

    def confirm(self, title, text):
        self.asked.append((title, text))
        return self.yes

    def show_upgrade(self, *, limit, message, on_enter):
        self.upgrades.append(message)


@pytest.fixture
def pro(monkeypatch):
    from localvault import licensing

    class Switch:
        on = True

    switch = Switch()
    monkeypatch.setattr(licensing, "item_limit", lambda st=None: None if switch.on else licensing.FREE_ITEM_LIMIT)
    return switch


def _share_api(tmp_path, name, folder):
    profiles = ProfileManager(tmp_path / name)
    profiles.ensure_profile()
    controller = WebController(profiles=profiles, settings=AppSettings(idle_source="vault"), bus=Bus(),
                               scheduler=Sched(), create_kwargs={"kdf_overrides": KDF})
    api = Api(controller, WebUiPort(Bus(), timeout=1), Ops(), dialogs=FakeDialogs(folder))
    assert api.vault_create("master password 12", "master password 12")["ok"] is True
    service = api._collection_share
    service._port = AskPort()
    service._kdf = CHEAP_KDF
    service._install_id = lambda: f"install-{name}"
    service._confirm_handover = lambda: None
    return api


@pytest.fixture
def two(tmp_path, monkeypatch, pro):
    monkeypatch.setattr("localvault.app.controller.clear_master_unlock_requirement", lambda _pid: None)
    folder = tmp_path / "Family folder"
    folder.mkdir()
    return _share_api(tmp_path, "owner", folder), _share_api(tmp_path, "member", folder), folder


def _keyring_file(folder):
    return folder / "LocalGateKeys Sync" / "keyring.lgkkeys"


def _share(owner, cid, can_edit=False, name="Anna"):
    token = owner.collection_share_choose_folder()["token"]
    return owner.collection_share_create(cid, token, SHARE_PW, SHARE_PW, can_edit, name)


def _join(member, password=SHARE_PW, name="Ben"):
    token = member.collection_share_choose_folder()["token"]
    return member.collection_share_join(token, password, name)


def _owner_adopts(owner, folder):
    """What the owner's share run does with a join it finds in the folder."""
    from localvault.sync import share_group as sg

    session = owner._controller.session
    gid = sg.list_share_groups(session)[0].group_id
    sg.adopt_keyring(session, gid, _keyring_file(folder).read_bytes(), _kdf_override=CHEAP_KDF)
    return gid


def test_share_a_collection_join_approve_by_name_and_remove(two):
    owner, member, folder = two
    cid = owner.collections_create("Family")["collections"][0]["id"]
    view = owner.collection_share_members(cid)
    assert view["ok"] and view["shared"] is False and view["pro"] is True
    shared = _share(owner, cid)
    assert shared["ok"], shared
    assert shared["shared"] and shared["is_owner"] and shared["mode"] == "read"
    assert [(m["name"], m["state"]) for m in shared["members"]] == [("Anna", "owner")]
    assert _keyring_file(folder).exists()

    wrong = _join(member, password="not the share password 9!")
    assert wrong["ok"] is False and wrong["error"]["code"] == "password"
    joined = _join(member)
    assert joined["ok"], joined
    assert joined["role"] == "member" and joined["mode"] == "read" and joined["collection"]["name"] == "Family"
    assert [m["state"] for m in joined["members"] if m["is_self"]] == ["pending"]

    _owner_adopts(owner, folder)
    view = owner.collection_share_members(cid)
    assert [p["name"] for p in view["pending"]] == ["Ben"]
    ben = view["pending"][0]["id"]
    assert owner.collection_share_approve(cid, ["not-a-pending-id"])["error"]["code"] == "invalid"
    assert owner.collection_share_approve(cid, [ben, "not-a-pending-id"])["error"]["code"] == "invalid"
    approved = owner.collection_share_approve(cid, [ben])
    assert approved["ok"] and approved["pending"] == []
    assert "Ben" in owner._collection_share._port.asked[-1][1], "the confirmation names who gets in"
    assert [(m["name"], m["state"]) for m in approved["members"]] == [("Anna", "owner"), ("Ben", "member")]

    # Removing needs a new share password, typed twice, and the confirmation says why.
    assert owner.collection_share_remove_member(cid, ben, "short", "short")["ok"] is False
    removed = owner.collection_share_remove_member(cid, ben, SHARE_PW2, SHARE_PW2)
    assert removed["ok"], removed
    title, text = owner._collection_share._port.asked[-1]
    assert "Ben" in title and "new share password" in text
    assert [m["name"] for m in removed["members"]] == ["Anna"]
    assert [r["name"] for r in removed["removed"]] == ["Ben"]
    assert len(list((folder / "LocalGateKeys Sync" / "removed").iterdir())) == 1
    # Nothing secret reaches the page.
    blob = json.dumps([view, approved, removed])
    for secret in (SHARE_PW, SHARE_PW2, "device_wraps", "password_wrap"):
        assert secret not in blob


def test_the_owner_upgrades_an_older_share_and_members_see_no_offer(two, monkeypatch):
    from localvault.sync import keyring as kr
    from localvault.sync import share_group as sg

    owner, member, folder = two
    cid = owner.collections_create("Family")["collections"][0]["id"]
    monkeypatch.setattr(sg, "_NEW_SHARE_FORMAT", 2)  # a share made by an app from before share v2
    shared = _share(owner, cid)
    monkeypatch.setattr(sg, "_NEW_SHARE_FORMAT", kr.SHARE_FORMAT)
    assert shared["upgrade"]["title"] == "Make this share safer"
    joined = _join(member)
    assert joined["ok"] and joined["upgrade"] is None
    assert owner.collection_share_upgrade(cid, SHARE_PW, "typed differently 99?")["ok"] is False
    done = owner.collection_share_upgrade(cid, SHARE_PW, SHARE_PW)  # keeping the share password is fine
    assert done["ok"], done
    assert done["upgrade"] is None and "Only the people you let in" in done["message"]
    assert kr.parse_keyring(_keyring_file(folder).read_bytes())["format"] == kr.SHARE_FORMAT
    again = owner.collection_share_upgrade(cid, SHARE_PW, SHARE_PW)
    assert again["error"]["code"] == "already-upgraded"
    assert member.collection_share_upgrade(member.collection_share_members(cid)["collection"]["id"], SHARE_PW,
                                           SHARE_PW)["error"]["code"] == "not-owner"
    assert SHARE_PW not in json.dumps([shared, done])


def test_update_required_is_an_error_status(two):
    from localvault.sync.service import SyncIssue, SyncStatusView, TransportStatus

    owner, _member, _folder = two
    cid = owner.collections_create("Family")["collections"][0]["id"]
    _share(owner, cid)
    gid = _owner_gid(owner)
    owner._sync.status = SyncStatusView(shares=(TransportStatus(gid, True, 1, 1,
                                                                (SyncIssue("update-required", "keyring.lgkkeys"),)),))
    shown = owner.collection_share_members(cid)["status"]
    assert shown["severity"] == "error" and "Update the app" in shown["text"]


def _owner_gid(api):
    from localvault.sync import share_group as sg

    return sg.list_share_groups(api._controller.session)[0].group_id


def test_create_and_join_on_the_free_plan_show_the_upgrade_sheet(two, pro):
    owner, member, _folder = two
    cid = owner.collections_create("Family")["collections"][0]["id"]
    pro.on = False
    result = _share(owner, cid)
    assert result["ok"] is False and result["error"]["code"] == "pro_required"
    assert owner._collection_share._port.upgrades
    assert _join(member)["error"]["code"] == "pro_required"
    assert member._collection_share._port.upgrades


def test_the_owner_removes_a_member_after_pro_lapsed(two, pro):
    from localvault.sync import share_group as sg

    owner, member, folder = two
    cid = owner.collections_create("Family")["collections"][0]["id"]
    _share(owner, cid, can_edit=True)
    _join(member)
    gid = _owner_adopts(owner, folder)
    ben = owner.collection_share_members(cid)["pending"][0]["id"]
    pro.on = False
    removed = owner.collection_share_remove_member(cid, ben, SHARE_PW2, SHARE_PW2)
    assert removed["ok"], removed
    # The rotated keyring reached the folder although the share run is off without Pro.
    assert sg.share_state(owner._controller.session, gid).keyring == _keyring_file(folder).read_bytes()


def test_create_refuses_a_folder_that_already_holds_a_group(two):
    owner, _member, folder = two
    cid = owner.collections_create("Family")["collections"][0]["id"]
    _keyring_file(folder).parent.mkdir()
    _keyring_file(folder).write_bytes(b"{}")
    result = _share(owner, cid)
    assert result["error"]["code"] == "folder-in-use"
    assert owner.collection_share_members(cid)["shared"] is False


def test_share_status_merged_is_a_notice_superseded_offers_join_again_removed_says_trash(two):
    from localvault.sync import share_group as sg
    from localvault.sync.service import SyncIssue, SyncStatusView, TransportStatus

    owner, member, _folder = two
    cid = owner.collections_create("Family")["collections"][0]["id"]
    _share(owner, cid)
    gid = sg.list_share_groups(owner._controller.session)[0].group_id

    def status(api, *issues):
        api._sync.status = SyncStatusView(shares=(TransportStatus(gid, True, 1, 1, tuple(issues)),))

    status(owner, SyncIssue("keyring-merged", "keyring.lgkkeys"))
    shown = owner.collection_share_members(cid)["status"]
    assert shown["severity"] == "info" and "waiting for your approval" in shown["text"]
    assert not SyncStatusView(issues=(SyncIssue("keyring-merged", "x"),)).needs_attention
    status(owner, SyncIssue("awaiting-approval", gid))
    shown = owner.collection_share_members(cid)["status"]
    assert shown["severity"] == "info" and "Nothing syncs" in shown["text"]
    status(owner, SyncIssue("superseded", gid))
    shown = owner.collection_share_members(cid)["status"]
    assert shown["severity"] == "warning" and shown["action"] == "rejoin" and "Join again" in shown["text"]
    status(owner, SyncIssue("tampered", "x"))
    assert owner.collection_share_members(cid)["status"]["severity"] == "error"
    # A removed member: the group is gone, the collection says what happened.
    other = member.collections_create("Family")["collections"][0]["id"]
    member._sync.status = SyncStatusView(shares=(TransportStatus(gid, True, 1, 1,
                                                                 (SyncIssue("share-removed", other),)),))
    shown = member.collection_share_members(other)
    assert shown["shared"] is False and "trash" in shown["status"]["text"]


def test_view_shows_the_owner_loss_help_and_the_fixed_mode(two):
    owner, _member, _folder = two
    cid = owner.collections_create("Family")["collections"][0]["id"]
    view = owner.collection_share_members(cid)
    assert "PC is lost" in view["owner_loss"] and view["mode_hint"]
    shared = _share(owner, cid, can_edit=True)
    assert shared["mode"] == "edit" and shared["mode_text"] and shared["mode_hint"]


def test_leave_asks_first_and_unshares(two):
    owner, _member, _folder = two
    cid = owner.collections_create("Family")["collections"][0]["id"]
    _share(owner, cid)
    owner._collection_share._port.yes = False
    assert owner.collection_share_leave(cid)["error"]["code"] == "cancelled"
    owner._collection_share._port.yes = True
    left = owner.collection_share_leave(cid)
    assert left["ok"] and left["shared"] is False


def test_a_received_share_link_offers_forget_with_a_confirmation(two):
    from localvault.sync.vault_bridge import LINKS_KEY

    owner, _member, _folder = two
    cid = owner.collections_create("Family")["collections"][0]["id"]
    session = owner._controller.session
    with session.transaction():  # what personal sync stores for a share another of this person's devices holds
        session._payload[LINKS_KEY] = {cid: {"mode": "read", "role": "owner"}}
    view = owner.collection_share_members(cid)
    assert view["shared"] is False and "Another of your devices shared" in view["linked"]["text"]
    assert "Forget share link" in view["owner_loss"]
    port = owner._collection_share._port
    port.yes = False
    assert owner.collection_share_forget_link(cid)["error"]["code"] == "cancelled"
    assert LINKS_KEY in session._payload
    port.yes = True
    done = owner.collection_share_forget_link(cid)
    assert done["ok"] and done["linked"] is None and "forgotten" in done["message"]
    assert port.asked[-1][0] == "Forget the share link?"
    assert LINKS_KEY not in session._payload
    assert owner.collection_share_forget_link(cid)["error"]["code"] == "no-link"
    # The collection is this person's own again: it can be shared from here.
    assert _share(owner, cid)["ok"]
# ------------------------------------------------------------------- emergency access (sub-plan 08, Task 3)
class _HeirDialogs:
    def __init__(self, folders):
        self.folders = list(folders)

    def choose_folder(self, title):
        return self.folders.pop(0)

    def open_file(self, title, file_types=None):
        return None


class _HeirPort:
    def __init__(self):
        self.confirms = []

    def confirm(self, title, text):
        self.confirms.append(text)
        return True


@pytest.fixture
def heir_api(api, tmp_path, monkeypatch):
    import localvault.vault as vault_module

    monkeypatch.setattr(vault_module, "DEFAULT_KDF", {**vault_module.DEFAULT_KDF, **KDF})
    password = "correct horse battery"
    assert api.vault_create(password, password)["ok"] is True
    phrase = api._controller.session.create_recovery_phrase(password)
    api._controller.session.upsert_web(origin="https://bank.example", username="o", password="owner secret 1")
    shared, saved = tmp_path / "shared", tmp_path / "saved"
    shared.mkdir(), saved.mkdir()
    heir = api._heir
    heir._spawn = lambda fn: fn()  # the heir-folder backup runs at once
    heir._auth.reauthenticate = lambda *a, **k: None  # the master password prompt, answered
    heir._port = _HeirPort()
    heir._dialogs = _HeirDialogs([saved, shared])
    return api, phrase, shared, saved


def test_heir_bridge_owner_and_heir_round_trip(heir_api):
    api, phrase, shared, saved = heir_api
    assert api.heir_plan_list()["plan"] is None
    made = api.heir_plan_create(2, ["Anna", "Ben", "Χρήστος"], 7, str(shared), "Ilias", phrase)
    assert made["ok"] is True and made["plan"]["n"] == 3 and made["plan"]["holders"][2] == "Χρήστος"
    view = api.heir_plan_list()
    assert view["plan"]["k"] == 2 and view["requests"] == [] and "act together" in view["collusion"]
    sheet = api.heir_plan_sheet(made["handle"])
    assert sheet["ok"] is True and [p["holder"] for p in sheet["pages"]] == ["Anna", "Ben", "Χρήστος"]
    assert api.heir_plan_save(made["handle"])["ok"] is True
    files = sorted(saved.glob("*.lgkheir"))
    assert len(files) == 3
    assert api.heir_plan_done(made["handle"])["ok"] is True
    assert api.heir_plan_sheet(made["handle"])["error"]["code"] == "stale"
    assert list((shared / "LocalGateKeys Emergency").glob("*/backup-*.lgk"))  # written at once

    # The heir side (here the same vault, for the bridge's sake): two shards, the folder, a request.
    for path in files[:2]:
        assert api.heir_shard_add_text(path.read_text(encoding="utf-8"))["ok"] is True
    assert api.heir_shard_add_text("lgkheir:not-a-shard")["error"]["code"] == "malformed"
    assert api.heir_receive_folder()["folder"] == str(shared)
    assert api.heir_receive_view()["status"]["state"] == "none"
    assert api.heir_request_create()["ok"] is True
    received = api.heir_receive_view()
    assert received["status"]["state"] == "waiting" and received["status"]["days_left"] == 7
    assert len(received["shards"]) == 2 and received["plan"]["owner"] == "Ilias"
    (request,) = api.heir_plan_list()["requests"]
    assert request["days_left"] == 7 and not request["granted"]
    early = api.heir_restore("Inherited", "new heir password 1", "new heir password 1")
    assert early["error"]["code"] == "waiting"
    granted = api.heir_plan_grant(request["id"], phrase)
    assert granted["ok"] is True and api._heir._port.confirms
    assert api.heir_receive_view()["status"]["state"] == "ready"
    restored = api.heir_restore("Inherited", "new heir password 1", "new heir password 1")
    assert restored["ok"] is True and restored["restored"] is True
    assert "Inherited" in [p.name for p in api._controller.profiles.list_profiles()]
    assert api.heir_receive_view()["shards"] == []


def test_heir_bridge_deny_is_seen_by_the_requester(heir_api):
    api, phrase, shared, saved = heir_api
    made = api.heir_plan_create(2, ["Anna", "Ben"], 3, str(shared), "", phrase)
    sheet_packages = api._heir._issued[made["handle"]]["packages"]
    assert api.heir_shard_add_text(sheet_packages[0].decode())["ok"] is True
    api._heir._dialogs = _HeirDialogs([shared])
    api.heir_receive_folder()
    api.heir_request_create()
    (request,) = api.heir_plan_list()["requests"]
    assert api.heir_plan_deny(request["id"])["ok"] is True
    assert api.heir_plan_list()["requests"] == []
    assert api.heir_receive_view()["status"]["state"] == "denied"
    assert api.heir_plan_deny(request["id"])["error"]["code"] == "not_found"


def test_heir_bridge_checks_its_arguments(heir_api, monkeypatch):
    api, phrase, shared, _saved = heir_api
    assert api.heir_plan_create(2, "Anna", 7, str(shared), "", phrase)["error"]["code"] == "invalid"
    assert api.heir_plan_create(2, ["A"], 7, str(shared), "", phrase)["error"]["code"] == "invalid"
    assert api.heir_plan_create("2", ["A", "B"], 7, str(shared), "", phrase)["error"]["code"] == "invalid"
    assert api.heir_plan_create(2, ["A", "B"], 7, str(shared / "gone"), "", phrase)["error"]["code"] == "no_folder"
    assert api.heir_plan_create(2, ["A", "B"], 0, str(shared), "", phrase)["error"]["code"] == "invalid"
    assert api.heir_shard_add_text("x" * 9000)["error"]["code"] == "invalid"
    created, wiped = _wipe_spy(monkeypatch)
    assert api.heir_restore("X", "one password 123", "two password 123")["error"]["code"] == "invalid"
    assert len(created) == 2 and sorted(map(id, wiped)) == sorted(map(id, created))
    api.vault_lock()
    assert api.heir_plan_list()["error"]["code"] == "locked"
    assert api.heir_receive_view()["error"]["code"] == "locked"


def test_heir_timer_announces_requests_and_writes_a_deleted_deny_again(heir_api):
    """Review finding 3: every owner device looks at the folder on the schedule timer, not only on a page visit."""
    from localvault import heir_flow

    api, phrase, shared, _saved = heir_api
    made = api.heir_plan_create(2, ["Anna", "Ben"], 3, str(shared), "", phrase)
    packages = api._heir._issued[made["handle"]]["packages"]
    events = api._controller._bus.events
    first = heir_flow.RequesterIdentity.generate()
    heir_flow.request_access(shared, packages[0], first)
    api._heir._looked = 0
    api._schedule._heir_check()
    (toast,) = [d for name, d in events if name == "toast" and "Anna" in d.get("message", "")]
    assert toast["action"]["route"] == "recovery" and toast["action"]["params"] == {"initial": "heir"}
    api._heir._looked = 0
    api._schedule._heir_check()  # announced once per unlock
    assert len([d for name, d in events if name == "toast" and "Anna" in d.get("message", "")]) == 1
    (request,) = api.heir_plan_list()["requests"]
    assert api.heir_plan_deny(request["id"])["ok"] is True
    deny_file = heir_flow.plan_dir(shared, made["plan"]["plan_id"]) / f"deny-{request['id']}.lgkheirdeny"
    deny_file.unlink()
    api._schedule._heir_check()  # within 10 minutes: no look yet
    assert not deny_file.exists()
    api._heir._looked = 0
    api._schedule._heir_check()
    assert deny_file.is_file()  # written again by the timer, without opening the page


def test_heir_bridge_sets_this_devices_folder(heir_api, tmp_path):
    api, phrase, shared, saved = heir_api
    api.heir_plan_create(2, ["Anna", "Ben"], 3, str(shared), "", phrase)
    other = tmp_path / "other-folder"
    other.mkdir()
    api._heir._dialogs = _HeirDialogs([other])
    result = api.heir_plan_set_folder()
    assert result["ok"] is True and result["plan"]["folder"] == str(other) and result["plan"]["home"] is True
    assert api.heir_plan_list()["plan"]["folder"] == str(other)


# ------------------------------------------------------------------- duress password (sub-plan 08, Task 4)
def test_duress_bridge_sets_up_unlocks_and_removes(api, monkeypatch):
    from localvault import duress

    password, second = "correct horse battery", "orange tractor sunset"
    assert api.vault_create(password, password)["ok"] is True
    assert api.duress_status()["configured"] is False
    assert api.duress_setup(password, second, second, "6")["error"]["code"] == "invalid"
    assert api.duress_setup(password, second, second, 6, "not a list")["error"]["code"] == "invalid"
    assert api.duress_setup(password, password, password, 6)["error"]["code"] == "same"
    done = api.duress_setup(password, second, second, 6, [])
    assert done["ok"] is True and done["configured"] is True and done["lock_hours"] == 6
    api.vault_lock()
    assert api.vault_unlock(second)["state"] == "unlocked"
    inside = api.duress_status()
    assert inside["configured"] is False and "decoy" not in json.dumps(inside).lower()
    assert api.duress_remove()["error"]["code"] == "generic"
    api.vault_lock()
    api._controller._wall = lambda: 10**12  # the hold is over
    monkeypatch.setattr(duress, "_boot_clock", lambda: (None, 10**9))  # ... on the monotonic clock too
    assert api.vault_unlock(password)["state"] == "unlocked"
    api._duress._port = _HeirPort()  # the confirmation, answered yes
    assert api.duress_remove()["configured"] is False
    assert not duress.configured(api._controller.session.path)



def test_no_page_view_shows_the_duress_folder(api):
    """Review R1: inside a duress session no path the page shows names the second vault's own folder."""
    from localvault import duress

    password, second = "correct horse battery", "orange tractor sunset"
    api.vault_create(password, password)
    api.duress_setup(password, second, second, 6, [])
    api.vault_lock()
    assert api.vault_unlock(second)["state"] == "unlocked"
    assert duress.is_decoy(api._controller.session)
    shown = []
    for name in ("recovery_kit_facts", "settings_page", "security_center", "backup_status", "duress_status",
                 "overview_get", "status_get", "connections_view", "developer_status", "licence_view", "sync_view",
                 "heir_plan_list", "nav_get", "factors_status", "hello_status", "face_status",
                 "security_key_status", "backup_factors", "onboarding_state", "vault_state"):
        method = getattr(api, name, None)
        if method is not None:
            shown.append(json.dumps(method(), default=str))
    text = "\n".join(shown)
    assert duress.DECOY_DIR not in text
    kit = api.recovery_kit_facts()
    assert kit["ok"] is True and kit["vault_path"].endswith("vault.json")
