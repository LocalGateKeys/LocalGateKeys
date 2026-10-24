"""Stage 2: login editor drafts kept in Python; the page edits only safe fields."""
from __future__ import annotations

import json

import pytest

from localvault.api.result import ApiError
from localvault.app.controller import WebController
from localvault.app.login_editor import LoginEditorService
from localvault.profiles import ProfileManager
from localvault.secret_text import SecretText
from localvault.settings import AppSettings

KDF = {"time_cost": 1, "memory_cost_kib": 8192, "parallelism": 1, "hash_len": 32}
MASTER = "correct horse battery"
TOTP = {"secret": "JBSWY3DPEHPK3PXP", "algorithm": "SHA1", "digits": 6, "period": 30}


class Bus:
    def emit(self, name, detail):
        pass


class Sched:
    def call_later(self, delay, fn):
        return fn

    def cancel(self, handle):
        pass


class Port:
    def __init__(self):
        self.passwords, self.upgrades, self.asked = [], [], []

    def ask_password(self, title, message):
        self.asked.append(title)
        answer = self.passwords.pop(0) if self.passwords else None
        return None if answer is None else SecretText.from_str(answer)

    def notify(self, kind, title, message):
        self.asked.append(title)

    def show_upgrade(self, *, limit, message, on_enter):
        self.upgrades.append(limit)


@pytest.fixture
def env(tmp_path, monkeypatch):
    monkeypatch.setattr("localvault.app.controller.clear_master_unlock_requirement", lambda _pid: None)
    profiles = ProfileManager(tmp_path / "data")
    profiles.ensure_profile()
    controller = WebController(profiles=profiles, settings=AppSettings(auto_lock_seconds=300, idle_source="vault"),
                               bus=Bus(), scheduler=Sched(), create_kwargs={"kdf_overrides": KDF})
    controller.create(MASTER, MASTER)
    port = Port()
    editor = LoginEditorService(controller, port, generate=lambda: "Generated-Pass-123!")
    return editor, controller, port


def _ref(entry_id):
    return {"source": "credential", "id": entry_id, "kind": "web"}


def test_new_login_saves_with_create_web_login(env):
    editor, controller, _port = env
    view = editor.open_new()
    assert view["is_new"] and view["password_set"] and view["label_hint"] == "Untitled login"
    view = editor.update(view["draft_id"], {"urls": [{"url": "example.test", "match": "exact_origin"}],
                                            "username": "ann"})
    assert view["label_hint"] == "example.test"  # friendly_origin_label: the host, as in Tk
    saved = editor.save(view["draft_id"])
    entry = controller.session.credential_detail(saved["ref"]["id"])
    assert entry["username"] == "ann" and entry["label"] == "example.test"
    assert controller.session.credential_secret(saved["ref"]["id"]) == "Generated-Pass-123!"


def test_edit_keeps_password_when_none_and_keeps_recovery_codes(env):
    editor, controller, _port = env
    entry_id = controller.session.create_web_login(
        urls=[{"url": "https://alpha.test", "match": "exact_origin"}], username="ann", password="old-pw-1234567",
        label="Alpha", totp=TOTP, recovery_codes=["rc-1"], custom_fields=[{"name": "PIN", "value": "9", "hidden": True}])
    view = editor.open(_ref(entry_id))
    assert view["password_set"] is False and view["totp_configured"] is True
    editor.update(view["draft_id"], {"username": "anna", "notes": "new notes"})
    editor.save(view["draft_id"])
    detail = controller.session.credential_detail(entry_id)
    assert detail["username"] == "anna" and detail["notes"] == "new notes"
    assert detail["recovery_codes"] == ["rc-1"] and detail["custom_fields"][0]["value"] == "9"
    assert detail["totp"]["secret"] == TOTP["secret"]
    assert controller.session.credential_secret(entry_id) == "old-pw-1234567"


def test_view_never_contains_password_or_totp_secret(env):
    editor, controller, _port = env
    entry_id = controller.session.create_web_login(
        urls=[{"url": "https://alpha.test", "match": "exact_origin"}], username="ann", password="old-pw-1234567",
        totp=TOTP, recovery_codes=["rc-1"], custom_fields=[{"name": "PIN", "value": "9999", "hidden": True}])
    view = editor.open(_ref(entry_id))
    view = editor.update(view["draft_id"], {"password": "brand-new-pw-123"})
    blob = json.dumps(view)
    for secret in ("old-pw-1234567", "brand-new-pw-123", TOTP["secret"], "rc-1", "9999"):
        assert secret not in blob
    assert view["password_set"] is True


def test_validate_errors_surface_by_field(env):
    editor, _controller, _port = env
    view = editor.open_new()
    view = editor.update(view["draft_id"], {"urls": [{"url": "", "match": "exact_origin"}]})
    with pytest.raises(ApiError) as invalid:
        editor.save(view["draft_id"])
    assert invalid.value.code == "invalid"
    fields = {e["field"] for e in editor.view(view["draft_id"])["errors"]}
    assert any(f.startswith("urls") for f in fields)


def test_duplicate_and_changed_errors(env):
    editor, controller, _port = env
    controller.session.create_web_login(urls=[{"url": "https://dup.test", "match": "exact_origin"}],
                                        username="ann", password="pw-dup-1234567")
    view = editor.open_new()
    editor.update(view["draft_id"], {"urls": [{"url": "https://dup.test", "match": "exact_origin"}], "username": "ann"})
    with pytest.raises(ApiError) as duplicate:
        editor.save(view["draft_id"])
    assert duplicate.value.code == "duplicate"

    entry_id = controller.session.create_web_login(urls=[{"url": "https://chg.test", "match": "exact_origin"}],
                                                   username="c", password="pw-chg-1234567")
    view = editor.open(_ref(entry_id))
    controller.session.update_entry_fields(entry_id, username="someone-else")
    editor.update(view["draft_id"], {"notes": "x"})
    with pytest.raises(ApiError) as changed:
        editor.save(view["draft_id"])
    assert changed.value.code == "changed"


def test_item_limit_calls_upgrade(env):
    editor, controller, port = env
    controller.session.item_limit = 0
    view = editor.open_new()
    editor.update(view["draft_id"], {"urls": [{"url": "https://new.test", "match": "exact_origin"}], "username": "n"})
    with pytest.raises(ApiError) as full:
        editor.save(view["draft_id"])
    assert full.value.code == "item_limit" and port.upgrades == [0]


def test_strict_open_requires_reauth(env):
    editor, controller, port = env
    entry_id = controller.session.create_web_login(
        urls=[{"url": "https://bank.test", "match": "exact_origin"}], username="b", password="pw-bank-1234567",
        notes="bank notes", policy={"fill": "ask", "sign_in": False, "require_master_password": True,
                                    "save_prompts": True})
    with pytest.raises(ApiError):
        editor.open(_ref(entry_id))
    port.passwords = [MASTER]
    assert editor.open(_ref(entry_id))["notes"] == "bank notes"


def test_drafts_dropped_on_lock(env):
    editor, controller, _port = env
    view = editor.open_new()
    controller.lock()
    with pytest.raises(ApiError) as gone:
        editor.view(view["draft_id"])
    assert gone.value.code == "not_found"


def test_regenerate_pin_is_8_digits(env):
    editor, controller, _port = env
    view = editor.open_new()
    editor.regenerate(view["draft_id"], "PIN")
    secret = editor._drafts[view["draft_id"]].draft.password
    assert len(secret) == 8 and secret.isdigit()


def test_remove_totp(env):
    editor, controller, _port = env
    entry_id = controller.session.create_web_login(
        urls=[{"url": "https://alpha.test", "match": "exact_origin"}], username="ann", password="pw-alpha-1234567",
        totp=TOTP)
    view = editor.open(_ref(entry_id))
    editor.update(view["draft_id"], {"totp_remove": True})
    editor.save(view["draft_id"])
    assert not controller.session.credential_detail(entry_id).get("totp")


def test_typing_does_not_decrypt_the_vault_again(env, monkeypatch):
    editor, controller, _port = env
    view = editor.open_new()
    calls = []
    real = controller.session.all_entries
    monkeypatch.setattr(controller.session, "all_entries", lambda: calls.append(1) or real())
    for text in ("a", "ab", "abc"):
        editor.update(view["draft_id"], {"notes": text})
    assert calls == []
    editor.update(view["draft_id"], {"password": "a-new-password-123"})
    assert len(calls) == 1


def test_open_reads_the_token_before_the_reauth_prompt(env):
    editor, controller, port = env
    entry_id = controller.session.create_web_login(
        urls=[{"url": "https://bank.test", "match": "exact_origin"}], username="b", password="pw-bank-1234567",
        policy={"fill": "ask", "sign_in": False, "require_master_password": True, "save_prompts": True})
    original_ask = port.ask_password

    def ask_and_change(title, message):
        controller.session.update_entry_fields(entry_id, username="changed-meanwhile")
        return SecretText.from_str(MASTER)

    port.ask_password = ask_and_change
    view = editor.open(_ref(entry_id))
    port.ask_password = original_ask
    editor.update(view["draft_id"], {"notes": "x"})
    with pytest.raises(ApiError) as changed:
        editor.save(view["draft_id"])
    assert changed.value.code == "changed"


def test_desktop_login_edits_username_password_and_totp_and_keeps_binding(env):
    editor, controller, _port = env
    entry_id = controller.session.add_desktop(
        label="Example app", username="ann", password="pw-desktop-12345", exe_path=r"C:\Apps\example.exe",
        exe_sha256="a" * 64, window_title="Sign in",
        control_fingerprint=[{"index": 0, "control_type": "Edit", "is_password": True}], username_selector=None,
        password_selector={"automation_id": "pw", "class_name": "Edit", "name": "", "control_type": "Edit",
                           "framework_id": "Win32"},
        signer=None, binding_mode="strict")
    view = editor.open({"source": "credential", "id": entry_id, "kind": "desktop"})
    assert view["kind"] == "desktop" and view["urls"] == [] and view["app_path"].endswith("example.exe")
    assert view["errors"] == []
    editor.update(view["draft_id"], {"username": "anna", "password": "new-desktop-pw-1", "totp_text": TOTP["secret"]})
    saved = editor.save(view["draft_id"])
    assert saved["ref"] == {"source": "credential", "id": entry_id, "kind": "desktop"}
    detail = controller.session.credential_detail(entry_id)
    assert detail["username"] == "anna" and detail["totp"]["secret"] == TOTP["secret"]
    assert detail["scope"]["exe_path"].endswith("example.exe")
    assert controller.session.credential_secret(entry_id) == "new-desktop-pw-1"
