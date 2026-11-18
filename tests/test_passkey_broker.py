"""Broker passkey ceremonies: consent, user verification, silence, fallback and cooldown."""
from __future__ import annotations

import hashlib
import json
from types import SimpleNamespace

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

import localvault.browser_broker as broker_module
from localvault.browser_broker import BrowserBroker
from localvault.passkeys import b64u_decode, b64u_encode
from broker_host import BrokerHostBase as RuntimeActions
from localvault.session_guard import SessionGuard
from localvault.settings import AppSettings
from localvault.vault import create_vault

KDF = {"time_cost": 1, "memory_cost_kib": 8192, "parallelism": 1, "hash_len": 32}
ORIGIN = "https://login.example.test"


class _Broker(RuntimeActions, BrowserBroker):
    def __init__(self, session) -> None:
        self.session = session
        self.guard = SessionGuard("redacted-profile")
        self.guard.open(3600)
        self.root = None
        self.settings = AppSettings(auto_lock_seconds=0)
        self.active_profile = SimpleNamespace(id="redacted-profile", name="Redacted", color="#123456")
        self._remote_busy = False
        self.last_extension_seen = 0.0
        self.last_extension_version = ""
        self.last_secret_use = 0.0
        self._closing = False
        self.prompts: list[dict] = []
        self.answer: tuple[str, str | None] = ("approve", None)
        self.reauths: list[str] = []
        self.reauth_ok = True
        self.unlock_ok = True

    def ensure_unlocked(self):
        return self.unlock_ok and self._session_available()

    def run_on_ui(self, function, timeout=0):
        return function()

    def refresh_entries(self):
        return None

    def _touch_secret(self):
        self.last_secret_use = 1.0

    def passkey_prompt(self, mode, *, origin, rp_id, accounts, excluded):
        self.prompts.append({"mode": mode, "origin": origin, "rp_id": rp_id, "accounts": accounts,
                             "excluded": excluded})
        return self.answer

    def reauthenticate(self, title, lease, *, allow_hello=False, fresh=False):
        assert fresh is True  # P-02: a passkey's UV never comes from the routine grace
        self.reauths.append(title)
        return self.reauth_ok

    def request(self, action: str, *, origin: str = ORIGIN, **payload):
        return self.dispatch_remote({
            "action": action, "protocol": 2, "passkey_protocol": 1, "extension_version": "0.4.0",
            "origin": origin, "context": json.dumps([17, "document-redacted", origin, "operation-redacted"]),
            "user_activation": True,  # the bridge saw a click (audit 2026-10-24 L-17)
            **payload,
        })


def _broker(tmp_path) -> _Broker:
    return _Broker(create_vault(tmp_path / "pk.json", "passkey broker master", kdf_overrides=KDF))


def _create_options(**overrides):
    options = {
        "rp": {"id": "example.test", "name": "Example"},
        "user": {"id": b64u_encode(b"user-1"), "name": "ada", "displayName": "Ada"},
        "challenge": b64u_encode(b"c" * 32),
        "pubKeyCredParams": [{"type": "public-key", "alg": -7}],
    }
    options.update(overrides)
    return options


def _get_options(**overrides):
    options = {"rpId": "example.test", "challenge": b64u_encode(b"g" * 32)}
    options.update(overrides)
    return options


def _register(broker) -> dict:
    reply = broker.request("passkey_create_browser", options=_create_options())
    assert reply["ok"] is True, reply
    return reply["credential"]


def test_create_stores_item_and_returns_verifiable_credential(tmp_path) -> None:
    broker = _broker(tmp_path)
    credential = _register(broker)
    assert broker.prompts[0]["mode"] == "create"
    assert broker.prompts[0]["rp_id"] == "example.test"
    assert broker.prompts[0]["accounts"][0]["user_name"] == "ada"
    assert broker.reauths == ["Confirm passkey for example.test"]
    records = broker.session.items.passkey_records("example.test")
    assert len(records) == 1
    assert records[0]["credential_id"] == credential["credential_id"]
    assert records[0]["title"] == "Example (ada)"
    auth_data = b64u_decode(credential["authenticator_data"], max_bytes=4096)
    assert auth_data[32] & 0x04  # UV after reauthentication
    assert "private_key" not in json.dumps(credential)
    assert broker.last_secret_use == 1.0


def test_get_with_no_stored_passkey_falls_back_without_prompt(tmp_path) -> None:
    broker = _broker(tmp_path)
    reply = broker.request("passkey_get_browser", options=_get_options())
    assert reply == {"ok": False, "error": "fallback"}
    assert broker.prompts == [] and broker.reauths == []


def test_get_with_allow_list_matching_none_falls_back_silently(tmp_path) -> None:
    broker = _broker(tmp_path)
    _register(broker)
    broker.prompts.clear()
    reply = broker.request("passkey_get_browser", options=_get_options(
        allowCredentials=[{"type": "public-key", "id": b64u_encode(b"someone-else")}]))
    assert reply["error"] == "fallback"
    assert broker.prompts == []


def test_get_signs_with_chosen_record_and_discouraged_skips_reauth(tmp_path) -> None:
    broker = _broker(tmp_path)
    created = _register(broker)
    record = broker.session.items.passkey_records("example.test")[0]
    broker.prompts.clear(); broker.reauths.clear()
    broker.answer = ("approve", record["id"])
    reply = broker.request("passkey_get_browser", options=_get_options(
        userVerification="discouraged",
        allowCredentials=[{"type": "public-key", "id": created["credential_id"]}]))
    assert reply["ok"] is True, reply
    assertion = reply["credential"]
    assert broker.reauths == []
    assert broker.prompts[0]["mode"] == "get"
    assert broker.prompts[0]["accounts"] == [{"id": record["id"], "title": "Example (ada)", "user_name": "ada"}]
    auth_data = b64u_decode(assertion["authenticator_data"], max_bytes=4096)
    assert auth_data[32] == 0x19
    public_key = serialization.load_der_public_key(b64u_decode(created["public_key_spki"], max_bytes=4096))
    client = b64u_decode(assertion["client_data_json"], max_bytes=4096)
    assert json.loads(client)["origin"] == ORIGIN
    public_key.verify(b64u_decode(assertion["signature"], max_bytes=128),
                      auth_data + hashlib.sha256(client).digest(), ec.ECDSA(hashes.SHA256()))


def test_get_rejects_a_record_the_user_did_not_choose_from(tmp_path) -> None:
    broker = _broker(tmp_path)
    _register(broker)
    broker.answer = ("approve", "not-a-candidate")
    reply = broker.request("passkey_get_browser", options=_get_options())
    assert reply["error"] == "user_cancelled"


def test_cancel_returns_user_cancelled_and_starts_10s_cooldown(tmp_path, monkeypatch) -> None:
    clock = [1000.0]
    monkeypatch.setattr(broker_module.time, "monotonic", lambda: clock[0])
    broker = _broker(tmp_path)
    broker.answer = ("cancel", None)
    assert broker.request("passkey_create_browser", options=_create_options())["error"] == "user_cancelled"
    assert len(broker.prompts) == 1
    clock[0] += 9.9
    assert broker.request("passkey_create_browser", options=_create_options())["error"] == "fallback"
    assert len(broker.prompts) == 1
    other = broker.request("passkey_create_browser", origin="https://other.test",
                           options=_create_options(rp={"id": "other.test"}))
    assert other["error"] == "user_cancelled" and len(broker.prompts) == 2
    clock[0] += 0.2
    assert broker.request("passkey_create_browser", options=_create_options())["error"] == "user_cancelled"
    assert len(broker.prompts) == 3


def test_browser_choice_falls_back(tmp_path) -> None:
    broker = _broker(tmp_path)
    broker.answer = ("browser", None)
    assert broker.request("passkey_create_browser", options=_create_options())["error"] == "fallback"
    assert broker.session.items.passkey_records("example.test") == []
    assert broker.reauths == []


def test_exclude_credentials_match_returns_invalid_state_after_prompt(tmp_path) -> None:
    broker = _broker(tmp_path)
    created = _register(broker)
    broker.prompts.clear()
    reply = broker.request("passkey_create_browser", options=_create_options(
        excludeCredentials=[{"type": "public-key", "id": created["credential_id"]}]))
    assert reply["error"] == "invalid_state"
    assert broker.prompts[0]["excluded"] is True
    assert len(broker.session.items.passkey_records("example.test")) == 1


def test_wrong_rp_id_is_security_error_and_never_prompts(tmp_path) -> None:
    broker = _broker(tmp_path)
    reply = broker.request("passkey_create_browser", options=_create_options(rp={"id": "evil.test"}))
    assert reply["error"] == "security_error"
    reply = broker.request("passkey_get_browser", options=_get_options(rpId="evil.test"))
    assert reply["error"] == "security_error"
    assert broker.prompts == []


def test_disabled_setting_falls_back(tmp_path) -> None:
    broker = _broker(tmp_path)
    broker.settings.passkeys_enabled = False
    assert broker.request("passkey_create_browser", options=_create_options())["error"] == "fallback"
    assert broker.prompts == []


def test_cancelled_unlock_falls_back(tmp_path) -> None:
    broker = _broker(tmp_path)
    broker.unlock_ok = False
    assert broker.request("passkey_get_browser", options=_get_options())["error"] == "fallback"
    assert broker.prompts == []


def test_missing_passkey_protocol_is_version_mismatch(tmp_path) -> None:
    broker = _broker(tmp_path)
    reply = broker.request("passkey_create_browser", options=_create_options(), passkey_protocol=None)
    assert reply["error"] == "version_mismatch"


def test_malformed_options_fall_back(tmp_path) -> None:
    broker = _broker(tmp_path)
    assert broker.request("passkey_create_browser", options="nope")["error"] == "fallback"
    assert broker.request("passkey_get_browser", options=_get_options(challenge="short"))["error"] == "fallback"
    assert broker.prompts == []


def test_reauth_failure_cancels(tmp_path) -> None:
    broker = _broker(tmp_path)
    broker.reauth_ok = False
    assert broker.request("passkey_create_browser", options=_create_options())["error"] == "user_cancelled"
    assert broker.session.items.passkey_records("example.test") == []


def test_every_prompt_without_a_credential_starts_the_cooldown(tmp_path) -> None:
    broker = _broker(tmp_path)
    broker.answer = ("browser", None)
    assert broker.request("passkey_create_browser", options=_create_options())["error"] == "fallback"
    assert broker.request("passkey_create_browser", options=_create_options())["error"] == "fallback"
    assert len(broker.prompts) == 1

    broker = _broker(tmp_path / "excluded")
    created = _register(broker)
    broker.prompts.clear()
    excluded = _create_options(excludeCredentials=[{"type": "public-key", "id": created["credential_id"]}])
    assert broker.request("passkey_create_browser", options=excluded)["error"] == "invalid_state"
    assert broker.request("passkey_create_browser", options=excluded)["error"] == "fallback"
    assert len(broker.prompts) == 1


def test_a_locked_vault_never_shows_the_unlock_so_a_page_cannot_loop_it(tmp_path) -> None:
    broker = _broker(tmp_path)
    unlock_prompts = []
    broker._session_available = lambda: False

    def cancelled_unlock():
        unlock_prompts.append(1)
        return False
    broker.ensure_unlocked = cancelled_unlock
    assert broker.request("passkey_get_browser", options=_get_options())["error"] == "fallback"
    assert broker.request("passkey_get_browser", options=_get_options())["error"] == "fallback"
    assert unlock_prompts == [] and broker.prompts == []


def test_focus_returns_to_the_browser_after_a_prompt_but_not_without_one(tmp_path) -> None:
    broker = _broker(tmp_path)
    restored = []
    broker._passkey_foreground = lambda: 4242
    broker._passkey_return_focus = restored.append
    assert broker.request("passkey_get_browser", options=_get_options())["error"] == "fallback"
    assert restored == []  # nothing stored, no prompt shown
    broker.answer = ("browser", None)
    assert broker.request("passkey_create_browser", options=_create_options())["error"] == "fallback"
    assert restored == [4242]


def test_a_late_approval_does_not_store_a_passkey_the_page_gave_up_on(tmp_path, monkeypatch) -> None:
    clock = [1000.0]
    monkeypatch.setattr(broker_module.time, "monotonic", lambda: clock[0])
    broker = _broker(tmp_path)
    broker.settings.auto_lock_seconds = 0

    def slow_prompt(mode, **kwargs):
        clock[0] += 81
        return ("approve", None)
    broker.passkey_prompt = slow_prompt
    reply = broker.request("passkey_create_browser", options=_create_options())
    assert reply["error"] == "user_cancelled"
    assert broker.session.items.passkey_records("example.test") == []


# -- Windows passkey provider on: the extension steps aside (Task 7) --------------------------------------------------
def _provider(monkeypatch, broker, *, setting: bool, state: str | None):
    """Install a fresh registration cache that never starts a process; returns it."""
    import localvault.windows_passkey_provider as wpp

    refreshes = []
    registration = wpp.RegistrationState(spawn=lambda work: refreshes.append(work))
    registration.record(state)
    monkeypatch.setattr(wpp, "REGISTRATION", registration)
    broker.settings.windows_passkey_provider = setting
    return registration, refreshes


def test_browser_ops_answer_system_provider_when_active(tmp_path, monkeypatch) -> None:
    broker = _broker(tmp_path)
    _provider(monkeypatch, broker, setting=True, state="enabled")
    for action, options in (("passkey_create_browser", _create_options()), ("passkey_get_browser", _get_options())):
        assert broker.request(action, options=options) == {"ok": False, "error": "system_provider"}
    # Before the activation check, the parser and the locked notice: no prompt, no unlock, nothing stored.
    assert broker.request("passkey_create_browser", options="nope", user_activation=False) == {
        "ok": False, "error": "system_provider"}
    broker._session_available = lambda: False
    assert broker.request("passkey_get_browser", options=_get_options())["error"] == "system_provider"
    assert broker.prompts == [] and broker.reauths == []
    assert "_passkey_locked_notice" not in broker.__dict__
    assert broker.session.items.passkey_records("example.test") == []


def test_browser_ops_unchanged_when_setting_on_but_not_registered(tmp_path, monkeypatch) -> None:
    for setting, state in ((True, None), (True, "not_registered"), (True, "disabled"), (False, "enabled")):
        broker = _broker(tmp_path / f"{setting}-{state}")
        _provider(monkeypatch, broker, setting=setting, state=state)
        _register(broker)  # the extension's own path: dialog, verification, stored passkey
        assert broker.prompts[-1]["mode"] == "create"
        broker.request("passkey_get_browser", options=_get_options())
        assert broker.prompts[-1]["mode"] == "get", (setting, state)  # the extension's dialog offers the passkey


def test_logins_unaffected_when_provider_active(tmp_path, monkeypatch) -> None:
    broker = _broker(tmp_path)
    _provider(monkeypatch, broker, setting=True, state="enabled")
    item = broker.session.upsert_web(origin=ORIGIN, username="ada", password="login-pw")
    start = broker.request("begin_browser", user_gesture=True)
    assert start["ok"] is True, start
    assert [row["entry_id"] for row in start["choices"]] == [item]
    released = broker.request("get_browser", grant=start["grant"], entry_id=item,
                              gesture_nonce=start["gesture_nonce"])
    assert released["ok"] is True and released["credential"]["password"] == "login-pw"


def test_system_provider_sets_no_cooldown(tmp_path, monkeypatch) -> None:
    broker = _broker(tmp_path)
    registration, _ = _provider(monkeypatch, broker, setting=True, state="enabled")
    restored = []
    broker._passkey_foreground = lambda: 4242
    broker._passkey_return_focus = restored.append
    for _ in range(3):
        assert broker.request("passkey_get_browser", options=_get_options())["error"] == "system_provider"
    assert broker._passkey_cooldowns() == {} and restored == []
    # Turned off: the very next request gets the extension's dialog, with no cooldown left behind.
    registration.record("not_registered")
    _register(broker)
    assert len(broker.prompts) == 1


def test_system_provider_comes_from_app_state_not_the_request(tmp_path, monkeypatch) -> None:
    # Both gates: setting on but not enabled in Windows, and enabled in Windows but the setting off.
    for setting, state in ((True, "disabled"), (False, "enabled")):
        broker = _broker(tmp_path / f"{setting}")
        _provider(monkeypatch, broker, setting=setting, state=state)
        for extra in ({"system_provider": True}, {"error": "system_provider"}, {"state": "enabled"},
                      {"windows_passkey_provider": True}):
            reply = broker.request("passkey_create_browser", options=_create_options(), **extra)
            assert reply.get("error") != "system_provider", (setting, extra)
            broker._passkey_cooldowns().clear()


def _clocked(monkeypatch, tmp_path, state):
    import localvault.windows_passkey_provider as wpp

    clock = [1000.0]
    monkeypatch.setattr(wpp.time, "monotonic", lambda: clock[0])
    broker = _broker(tmp_path)
    registration, refreshes = _provider(monkeypatch, broker, setting=True, state=state)
    return broker, registration, refreshes, clock


def test_fresh_enabled_state_answers_system_provider(tmp_path, monkeypatch) -> None:
    broker, _, _, clock = _clocked(monkeypatch, tmp_path, "enabled")
    clock[0] += 29.9
    assert broker.request("passkey_get_browser", options=_get_options())["error"] == "system_provider"


def test_stale_enabled_state_keeps_the_extension_path_while_it_refreshes(tmp_path, monkeypatch) -> None:
    # LocalGateKeys may have been turned off in Windows Settings since: never hand over on an old answer.
    broker, _, refreshes, clock = _clocked(monkeypatch, tmp_path, "enabled")
    clock[0] += 30
    _register(broker)  # the extension's dialog, verification and stored passkey
    assert broker.prompts[-1]["mode"] == "create"
    assert len(refreshes) == 1  # a refresh was started off the UI thread (queued by the fake spawn, not run)


def test_refresh_failure_keeps_the_extension_path(tmp_path, monkeypatch) -> None:
    broker, registration, _, clock = _clocked(monkeypatch, tmp_path, "enabled")
    clock[0] += 30
    registration._spawn = lambda work: work()
    registration.refresh_later(run=lambda *_args: {"ok": False, "error": "timeout"}, is_available=lambda: True)
    assert registration.enabled() is False
    _register(broker)
    assert broker.prompts[-1]["mode"] == "create"
    # A successful refresh hands over again.
    clock[0] += 10
    registration.refresh_later(run=lambda *_args: {"ok": True, "state": "enabled"}, is_available=lambda: True)
    assert broker.request("passkey_get_browser", options=_get_options())["error"] == "system_provider"


def test_active_check_refreshes_in_the_background_at_most_every_10s(tmp_path, monkeypatch) -> None:
    broker, _, refreshes, clock = _clocked(monkeypatch, tmp_path, "disabled")
    assert broker._system_provider_active() is False
    assert refreshes == []  # just recorded
    clock[0] += 10
    assert broker._system_provider_active() is False
    assert len(refreshes) == 1  # spawned, not run on the UI thread
    clock[0] += 10
    assert broker._system_provider_active() is False
    assert len(refreshes) == 1  # one at a time
    broker.settings.windows_passkey_provider = False
    clock[0] += 60
    assert broker._system_provider_active() is False
    assert len(refreshes) == 1  # setting off: no process at all


def test_default_refresh_runs_on_a_worker_thread() -> None:
    import threading
    import time

    import localvault.windows_passkey_provider as wpp

    registration = wpp.RegistrationState()  # the real threading.Thread spawn
    threads = []

    def run(*args):
        threads.append(threading.current_thread().name)
        return {"ok": True, "state": "enabled"}
    registration.refresh_later(run=run, is_available=lambda: True)
    deadline = time.monotonic() + 5
    while registration._refreshing and time.monotonic() < deadline:
        time.sleep(0.01)
    assert registration._refreshing is False
    assert threads == ["lgk-passkey-provider-state"]
    assert registration.enabled() is True


def test_attach_refreshes_on_a_timer_only_while_the_setting_is_on(monkeypatch) -> None:
    import localvault.windows_passkey_provider as wpp

    ticks = []
    monkeypatch.setattr(wpp, "_start_ticker", ticks.append)
    registration = wpp.RegistrationState(spawn=lambda work: work())
    monkeypatch.setattr(wpp, "REGISTRATION", registration)
    calls = []

    def run(*args):
        calls.append(args)
        return {"ok": True, "state": "enabled"}
    controller = SimpleNamespace(settings=AppSettings(windows_passkey_provider=False), on_unlock=[],
                                 is_unlocked=lambda: False)
    bus = SimpleNamespace(listeners=[], emit=lambda *_a: None)
    wpp.attach(controller=controller, bus=bus, run_on_ui=lambda fn, timeout=0: fn(), toast=lambda *_a: None,
               start=lambda _work: None, run=run, is_available=lambda: True)
    assert len(ticks) == 1
    ticks[0]()
    assert calls == []  # setting off: no process
    controller.settings = AppSettings(windows_passkey_provider=True)
    ticks[0]()
    assert calls == [("--state",)] and registration.enabled() is True


def test_registration_refresh_records_the_state_windows_reports() -> None:
    import localvault.windows_passkey_provider as wpp

    def refreshed(answer=None, *, available=True, raises=False):
        registration = wpp.RegistrationState(spawn=lambda work: work())
        registration.record("enabled", stale=True)
        calls = []

        def run(*args):
            calls.append(args)
            if raises:
                raise OSError("boom")
            return answer
        registration.refresh_later(run=run, is_available=lambda: available)
        return registration, calls

    registration, calls = refreshed({"ok": True, "state": "enabled"})
    assert registration.enabled() is True and calls == [("--state",)]
    for answer in ({"ok": True, "state": "disabled"}, {"ok": True, "state": "not_registered"},
                   {"ok": True, "state": "weird"}, {"ok": False, "error": "timeout"}):
        assert refreshed(answer)[0].enabled() is False, answer
    registration, calls = refreshed({"ok": True, "state": "enabled"}, available=False)
    assert registration.enabled() is False and calls == []
    assert refreshed(raises=True)[0].enabled() is False


def test_switch_and_start_up_keep_the_registration_cache_current(monkeypatch) -> None:
    import localvault.windows_passkey_provider as wpp

    registration = wpp.RegistrationState(spawn=lambda work: None)
    monkeypatch.setattr(wpp, "REGISTRATION", registration)
    answers = {"--state": {"ok": True, "state": "enabled"}, "--register": {"ok": True}, "--unregister": {"ok": True}}
    run = lambda *args: answers[args[0]]  # noqa: E731
    assert wpp.reconcile(True, run=run, is_available=lambda: True) == "registered"
    assert registration.enabled() is True
    assert wpp.disable(run=run)["ok"] is True
    assert registration.enabled() is False
    assert wpp.enable(run=run, open_settings=lambda: None)["ok"] is True
    # Registered, but Windows lists a new provider as off until the user turns it on there: not active yet,
    # and the next check re-reads the state.
    assert registration.enabled() is False
    assert registration._attempted == float("-inf")  # the next check refreshes at once
    assert wpp.reconcile(False, run=run, is_available=lambda: True) == "unregistered"
    assert registration.enabled() is False
    registration.record("enabled")
    assert wpp.reconcile(True, run=run, is_available=lambda: False, native=lambda: "none") == "none"
    assert registration.enabled() is False
