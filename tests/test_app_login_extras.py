"""Stage 3: a login's extra content — history, recovery codes, custom fields, autofill rules, GA import."""
from __future__ import annotations

import base64
import json

import pytest

from localvault.api.result import ApiError
from localvault.app.controller import WebController
from localvault.app.login_editor import LoginEditorService
from localvault.app.login_extras import LoginExtrasService
from localvault.profiles import ProfileManager
from localvault.secret_text import SecretText
from localvault.settings import AppSettings

KDF = {"time_cost": 1, "memory_cost_kib": 8192, "parallelism": 1, "hash_len": 32}
MASTER = "correct horse battery"


class Bus:
    def emit(self, name, detail):
        pass


class Sched:
    def call_later(self, delay, fn):
        return fn

    def cancel(self, handle):
        pass


class FakeClipboard:
    timeout_seconds = 30

    def __init__(self):
        self.value = None

    def copy(self, text):
        self.value = text

    def clear(self):
        self.value = None


class Port:
    def __init__(self):
        self.passwords, self.asked, self.answers = [], [], []

    def ask_password(self, title, message):
        self.asked.append(title)
        answer = self.passwords.pop(0) if self.passwords else None
        return None if answer is None else SecretText.from_str(answer)

    def confirm(self, title, message):
        self.asked.append(title)
        return self.answers.pop(0) if self.answers else True

    def notify(self, kind, title, message):
        self.asked.append(title)

    def show_upgrade(self, **kwargs):
        pass


@pytest.fixture
def env(tmp_path, monkeypatch):
    monkeypatch.setattr("localvault.app.controller.clear_master_unlock_requirement", lambda _pid: None)
    profiles = ProfileManager(tmp_path / "data")
    profiles.ensure_profile()
    controller = WebController(profiles=profiles, settings=AppSettings(idle_source="vault"), bus=Bus(),
                               scheduler=Sched(), create_kwargs={"kdf_overrides": KDF})
    controller.create(MASTER, MASTER)
    controller.clipboard = FakeClipboard()
    session = controller.session
    entry = session.create_web_login(urls=[{"url": "https://alpha.test", "match": "exact_origin"}], username="ann",
                                     password="pw-first-1234567", label="Alpha", notes="keep me",
                                     recovery_codes=["code-1", "code-2"],
                                     custom_fields=[{"name": "PIN", "value": "9999", "hidden": True},
                                                    {"name": "Hint", "value": "blue", "hidden": False}])
    session.update_entry_fields(entry, password="pw-second-1234567")
    port = Port()
    editor = LoginEditorService(controller, port, generate=lambda: "Gen-Pass-123456!")
    extras = LoginExtrasService(controller, port, editor)
    return extras, controller, port, editor, {"source": "credential", "id": entry, "kind": "web"}


def test_history_lists_dates_only_after_reauth(env):
    extras, _controller, port, _editor, ref = env
    port.passwords = [MASTER]
    rows = extras.history(ref)["rows"]
    assert port.asked == ["Enter your master password to view password history"]
    assert len(rows) == 1 and set(rows[0]) == {"index", "changed_at"}
    assert "pw-first" not in json.dumps(rows)


def test_history_copy_checks_the_row(env):
    extras, controller, port, _editor, ref = env
    port.passwords = [MASTER, MASTER]
    row = extras.history(ref)["rows"][0]
    with pytest.raises(ApiError) as moved:
        extras.history_copy(ref, row["index"], row["changed_at"] + 1)
    assert moved.value.code == "changed"
    extras.history_copy(ref, row["index"], row["changed_at"])
    assert controller.clipboard.value == "pw-first-1234567"


def test_recovery_codes_reveal_and_save(env):
    extras, controller, port, _editor, ref = env
    port.passwords = [MASTER]
    assert extras.recovery_codes(ref)["codes"] == ["code-1", "code-2"]
    assert port.asked == ["Confirm to reveal recovery codes"]
    extras.recovery_codes_save(ref, ["code-9"])
    detail = controller.session.credential_detail(ref["id"])
    assert detail["recovery_codes"] == ["code-9"] and detail["notes"] == "keep me"
    assert detail["custom_fields"][0]["value"] == "9999"


def test_use_next_code_copies_and_removes(env):
    extras, controller, port, _editor, ref = env
    result = extras.recovery_use_next(ref)
    assert "Use next recovery code?" in port.asked
    assert controller.clipboard.value == "code-1" and result["message"]
    assert controller.session.credential_detail(ref["id"])["recovery_codes"] == ["code-2"]


def test_use_next_refuses_when_codes_changed_during_confirm(env):
    extras, controller, port, _editor, ref = env

    def confirm_and_change(title, message):
        controller.session.consume_recovery_code(ref["id"], 0)
        return True

    port.confirm = confirm_and_change
    with pytest.raises(ApiError) as changed:
        extras.recovery_use_next(ref)
    assert changed.value.code == "changed" and controller.clipboard.value is None


def test_custom_fields_hidden_values_need_reauth(env):
    extras, controller, port, _editor, ref = env
    plain = extras.custom_fields(ref, reveal=False)
    assert plain["fields"] == [{"index": 0, "name": "PIN", "value": None, "hidden": True},
                               {"index": 1, "name": "Hint", "value": "blue", "hidden": False}]
    port.passwords = [MASTER]
    revealed = extras.custom_fields(ref, reveal=True)
    assert revealed["fields"][0]["value"] == "9999"
    extras.custom_fields_save(ref, [{"index": 0, "name": "PIN", "value": None, "hidden": True},
                                    {"name": "Color", "value": "red", "hidden": False}], removed=[1])
    saved = controller.session.credential_detail(ref["id"])["custom_fields"]
    assert saved == [{"name": "PIN", "value": "9999", "hidden": True}, {"name": "Color", "value": "red", "hidden": False}]


def test_policy_save_and_enable_sign_in_confirm(env):
    extras, controller, port, _editor, ref = env
    assert extras.policy(ref)["policy"]["fill"] == "click"
    port.answers = [False]
    with pytest.raises(ApiError):
        extras.policy_save(ref, {"sign_in": "enabled"})
    assert "Enable sign-in for this entry?" in port.asked
    result = extras.policy_save(ref, {"require_master_password": True})
    assert result["message"] == "Access policy saved. It applies from the next fill."
    detail = controller.session.credential_detail(ref["id"])
    assert detail["policy"]["require_master_password"] is True and detail["notes"] == "keep me"


def _migration_uri(secret: bytes, name: str, issuer: str) -> str:
    def field(number, payload):
        return bytes([(number << 3) | 2, len(payload)]) + payload
    otp = field(1, secret) + field(2, name.encode()) + field(3, issuer.encode()) + bytes([4 << 3, 1, 5 << 3, 1, 6 << 3, 2])
    blob = field(1, otp)
    return "otpauth-migration://offline?data=" + base64.b64encode(blob).decode()


def test_ga_import_keeps_secrets_in_python_and_applies_to_a_draft(env):
    extras, _controller, _port, editor, _ref = env
    parsed = extras.ga_parse(_migration_uri(b"0123456789", "ann@alpha.test", "Alpha"), label="Alpha",
                             origin="https://alpha.test")
    assert parsed["accounts"][0]["issuer"] == "Alpha" and "secret" not in json.dumps(parsed)
    view = editor.open_new()
    applied = extras.ga_apply(view["draft_id"], parsed["token"], 0)
    assert applied["totp_configured"] is True
    assert editor._drafts[view["draft_id"]].draft.totp_text.startswith("otpauth://totp/")
