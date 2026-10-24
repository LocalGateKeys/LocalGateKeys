"""Stage 2: re-authentication, reveal, copy, 2FA, favorite, trash and open website for the WebView UI."""
from __future__ import annotations

import json

import pytest

from localvault.api.result import ApiError
from localvault.app.controller import WebController
from localvault.app.secrets import SecretService
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


class Clock:
    def __init__(self):
        self.now = 1000.0

    def __call__(self):
        return self.now


class FakeClipboard:
    def __init__(self):
        self.value, self.cleared, self.timeout_seconds = None, 0, 30

    def copy(self, text):
        self.value = text

    def clear(self):
        self.value, self.cleared = None, self.cleared + 1

    def remaining(self):
        return 30 if self.value is not None else None


class Port:
    def __init__(self):
        self.passwords: list = []
        self.confirms: list = []
        self.asked: list = []

    def ask_password(self, title, message):
        self.asked.append(title)
        answer = self.passwords.pop(0) if self.passwords else None
        return None if answer is None else SecretText.from_str(answer)

    def confirm(self, title, message):
        self.asked.append(title)
        return self.confirms.pop(0) if self.confirms else False

    def notify(self, kind, title, message):
        self.asked.append(f"{kind}:{title}")


@pytest.fixture
def env(tmp_path, monkeypatch):
    monkeypatch.setattr("localvault.app.controller.clear_master_unlock_requirement", lambda _pid: None)
    profiles = ProfileManager(tmp_path / "data")
    profiles.ensure_profile()
    clock = Clock()
    controller = WebController(profiles=profiles, settings=AppSettings(auto_lock_seconds=300, idle_source="vault"),
                               bus=Bus(), clock=clock, scheduler=Sched(), create_kwargs={"kdf_overrides": KDF})
    controller.create(MASTER, MASTER)
    controller.clipboard = FakeClipboard()
    session = controller.session
    plain = session.create_web_login(urls=[{"url": "https://alpha.test", "match": "exact_origin"}],
                                     username="ann", password="pw-alpha-1234567", label="Alpha", totp=TOTP,
                                     notes="alpha notes")
    strict = session.create_web_login(urls=[{"url": "https://bank.test", "match": "exact_origin"}],
                                      username="bob", password="pw-bank-1234567", label="Bank", totp=TOTP,
                                      notes="bank notes",
                                      policy={"fill": "ask", "sign_in": False, "require_master_password": True,
                                              "save_prompts": True},
                                      custom_fields=[{"name": "PIN", "value": "9999", "hidden": True}],
                                      recovery_codes=["rc-1111"])
    note = session.item_service.create_note("Router", "wifi codes inside")
    port = Port()
    service = SecretService(controller, port)
    refs = {
        "plain": {"source": "credential", "id": plain, "kind": "web"},
        "strict": {"source": "credential", "id": strict, "kind": "web"},
        "note": {"source": "typed", "id": note, "kind": "note"},
    }
    return service, controller, port, clock, refs


def test_reveal_needs_reauth_and_wrong_password_denies(env):
    service, _controller, port, _clock, refs = env
    port.passwords = ["wrong password!!"]
    with pytest.raises(ApiError) as denied:
        service.reveal_password(refs["plain"])
    assert denied.value.code == "not_authorized"
    assert port.asked[0] == "Confirm to reveal this password"
    port.passwords = [MASTER]
    assert service.reveal_password(refs["plain"]) == {"password": "pw-alpha-1234567", "mask_after": 30}


def test_reauth_grace_skips_second_prompt_within_120s(env):
    service, _controller, port, clock, refs = env
    port.passwords = [MASTER]
    service.reveal_password(refs["plain"])
    clock.now += 60
    service.reveal_password(refs["plain"])
    assert port.asked.count("Confirm to reveal this password") == 1
    clock.now += 121
    port.passwords = []
    with pytest.raises(ApiError):
        service.reveal_password(refs["plain"])


def test_copy_password_uses_clipboard_and_touches(env):
    service, controller, port, clock, refs = env
    port.passwords = [MASTER]
    clock.now += 50
    result = service.copy(refs["plain"], "password")
    assert controller.clipboard.value == "pw-alpha-1234567"
    assert result == {"message": "Password copied. Clipboard clears in 30 seconds."}
    assert controller.last_secret_use == clock.now


def test_copy_username_plain_needs_no_reauth(env):
    service, controller, port, _clock, refs = env
    assert service.copy(refs["plain"], "username")["message"].startswith("Username copied.")
    assert controller.clipboard.value == "ann" and port.asked == []


def test_copy_username_on_strict_needs_reauth_without_grace(env):
    service, controller, port, _clock, refs = env
    port.passwords = [MASTER, MASTER]
    service.copy(refs["strict"], "username")
    service.copy(refs["strict"], "username")
    assert port.asked == ["Open sensitive credential", "Open sensitive credential"]
    assert controller.clipboard.value == "bob"


def test_stale_revision_is_changed_error(env):
    service, controller, port, _clock, refs = env
    real = controller.session.credential_secret

    def bumped(entry_id, *, expected_revision=None):
        return real(entry_id, expected_revision=(expected_revision or 0) + 99)

    controller.session.credential_secret = bumped
    port.passwords = [MASTER]
    with pytest.raises(ApiError) as changed:
        service.reveal_password(refs["plain"])
    assert changed.value.code == "changed"


def test_totp_format_and_strict_refusal(env):
    service, _controller, _port, _clock, refs = env
    code = service.totp(refs["plain"])
    assert len(code["code"]) == 7 and code["code"][3] == " " and code["period"] == 30
    with pytest.raises(ApiError) as strict:
        service.totp(refs["strict"])
    assert strict.value.code == "strict"


def test_copy_totp_message(env):
    service, controller, _port, _clock, refs = env
    message = service.copy(refs["plain"], "totp")["message"]
    assert message.startswith("Two-factor code copied; it changes in ")
    assert len(controller.clipboard.value) == 6


def test_trash_confirm_text_and_cancel(env):
    service, controller, port, _clock, refs = env
    port.confirms = [False]
    with pytest.raises(ApiError) as cancelled:
        service.trash(refs["plain"])
    assert cancelled.value.code == "cancelled"
    port.confirms = [True]
    moved = service.trash(refs["plain"])
    assert moved["message"].startswith("Moved ") and moved["message"].endswith(" to Trash.")
    assert moved["undo"] == {"ids": [refs["plain"]["id"]]}
    assert port.asked[-1] == "Move to trash?"
    assert all(e["id"] != refs["plain"]["id"] for e in controller.session.all_entries())


def test_favorite_toggle_for_login_and_note(env):
    service, controller, _port, _clock, refs = env
    assert service.set_favorite(refs["plain"], True) == {"message": "Added to favorites."}
    assert service.set_favorite(refs["note"], True) == {"message": "Added to favorites."}
    assert service.set_favorite(refs["note"], False) == {"message": "Removed from favorites."}


def test_detail_never_returns_password_totp_secret_or_hidden_fields(env):
    service, _controller, _port, _clock, refs = env
    plain = service.detail(refs["plain"])
    strict = service.detail(refs["strict"])
    note = service.detail(refs["note"])
    assert plain["notes"] == "alpha notes" and plain["has_totp"] and plain["origin"] == "https://alpha.test"
    assert strict["strict"] and strict["notes"] is None
    blob = json.dumps([plain, strict, note])
    for secret in ("pw-alpha-1234567", "pw-bank-1234567", TOTP["secret"], "9999", "rc-1111", "bank notes",
                   "wifi codes inside"):
        assert secret not in blob
    assert note["kind"] == "note" and note["title"] == "Router"


def test_unknown_ref_is_not_found(env):
    service, _controller, _port, _clock, _refs = env
    with pytest.raises(ApiError) as missing:
        service.detail({"source": "credential", "id": "nope", "kind": "web"})
    assert missing.value.code == "not_found"


def test_lock_clears_clipboard(env):
    _service, controller, _port, _clock, _refs = env
    controller.clipboard.copy("x")
    controller.lock()
    assert controller.clipboard.cleared == 1


def test_open_website_confirms_then_opens(env, monkeypatch):
    service, _controller, port, _clock, refs = env
    opened = []
    monkeypatch.setattr("localvault.app.secrets.webbrowser.open", lambda url: opened.append(url))
    port.confirms = [True]
    service.open_website(refs["plain"])
    assert opened == ["https://alpha.test"] and port.asked[-1] == "Open website?"


def test_ask_password_web_port_cancel_is_none():
    from localvault.web.ui_port import WebUiPort

    class RecordingBus:
        def emit(self, name, detail):
            pass

    assert WebUiPort(RecordingBus(), timeout=0.05).ask_password("T", "M") is None


def test_totp_reports_the_configured_period(env):
    service, controller, _port, _clock, _refs = env
    entry = controller.session.create_web_login(
        urls=[{"url": "https://slow.test", "match": "exact_origin"}], username="s", password="pw-slow-1234567",
        totp={"secret": "JBSWY3DPEHPK3PXP", "algorithm": "SHA1", "digits": 8, "period": 60})
    code = service.totp({"source": "credential", "id": entry, "kind": "web"})
    assert code["period"] == 60 and len(code["code"]) == 9


def test_wrong_password_attempts_wipe_every_buffer(env, monkeypatch):
    from localvault.vault import unlock_throttle

    service, controller, port, _clock, refs = env
    asked, wiped = [], []
    original_ask, original_wipe = port.ask_password, SecretText.wipe

    def ask_password(title, message):
        secret = original_ask(title, message)
        asked.append(secret)
        return secret

    def wipe(self):
        wiped.append(self)
        original_wipe(self)

    monkeypatch.setattr(port, "ask_password", ask_password)
    monkeypatch.setattr(SecretText, "wipe", wipe)
    throttle = unlock_throttle(controller.session.path)
    port.passwords = ["wrong password 1!", "wrong password 2!", "wrong password 3!", MASTER]
    for attempt in range(1, 4):
        with pytest.raises(ApiError) as denied:
            service.reveal_password(refs["plain"])
        assert denied.value.code == "not_authorized"
        assert throttle.failures == attempt
    assert service.reveal_password(refs["plain"]) == {"password": "pw-alpha-1234567", "mask_after": 30}
    assert throttle.failures == 0
    assert len(asked) == 4 and len({id(s) for s in asked}) == 4
    assert [id(s) for s in wiped] == [id(s) for s in asked]


@pytest.mark.parametrize("answer, expected", [("pässwörd ok 12", "pässwörd ok 12"), (123, None), ("", None),
                                              ("bad \ud800 text", None)])
def test_ask_password_web_port_returns_secret_text_and_drops_the_str(answer, expected):
    import threading

    from localvault.web.ui_port import WebUiPort

    captured = {}

    class AnsweringBus:
        def emit(self, name, detail):
            if name == "modal.request":
                captured["pending"] = port._pending[detail["id"]]
                threading.Thread(target=port.answer, args=(detail["id"], answer)).start()

    port = WebUiPort(AnsweringBus(), timeout=5)
    result = port.ask_password("T", "M")
    assert captured["pending"].value is None
    if expected is None:
        assert result is None
    else:
        assert isinstance(result, SecretText)
        assert result.equals(SecretText.from_str(expected)) and result.char_count == len(expected)
        result.wipe()
