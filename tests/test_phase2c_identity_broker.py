from __future__ import annotations

import json
from types import SimpleNamespace

import pytest

import localvault.uia as uia
from localvault.browser_broker import BrowserBroker
from broker_host import BrokerHostBase as RuntimeActions
from localvault.session_guard import SessionGuard
from localvault.settings import AppSettings
from localvault.uia import ControlDescriptor, WindowSnapshot, validate_desktop_entry
from localvault.vault import create_vault

KDF = {"memory_cost_kib": 8192, "time_cost": 1, "parallelism": 1}


def _control(index: int, automation_id: str, *, password: bool = False) -> ControlDescriptor:
    return ControlDescriptor(
        index=index,
        name="" if password else automation_id,
        automation_id=automation_id,
        class_name="Chrome_RenderWidgetHostHWND",
        framework_id="Chrome",
        is_password=password,
        enabled=True,
        visible=True,
        rectangle=(10, 10, 200, 40),
    )


def _snapshot(*, hwnd: int = 100, pid: int = 200, controls: list[ControlDescriptor] | None = None) -> WindowSnapshot:
    return WindowSnapshot(
        hwnd=hwnd,
        pid=pid,
        title="Sign in to redacted app",
        exe_path=r"C:\Apps\Redacted\Redacted.exe",
        exe_sha256="A" * 64,
        controls=controls or [_control(0, "user"), _control(1, "secret", password=True)],
        signer=None,
    )


def _selector(control: ControlDescriptor) -> dict[str, object]:
    return control.selector()


def _entry(snapshot: WindowSnapshot) -> dict[str, object]:
    return {
        "kind": "desktop",
        "scope": {
            "exe_path": snapshot.exe_path,
            "exe_sha256": snapshot.exe_sha256,
            "window_title": snapshot.title,
            "control_fingerprint": snapshot.control_fingerprint(),
            "username_selector": _selector(snapshot.controls[0]),
            "password_selector": _selector(snapshot.controls[1]),
        },
    }


def test_desktop_binding_ignores_transient_pid_hwnd_and_uia_runtime_identity() -> None:
    original = _snapshot()
    current = _snapshot(
        hwnd=901,
        pid=902,
        controls=[_control(5, "user"), _control(8, "secret", password=True)],
    )

    username, password = validate_desktop_entry(_entry(original), current)

    assert username is current.controls[0]
    assert password is current.controls[1]
    assert "runtime_id" not in username.selector()
    assert "runtime_id" not in password.selector()


@pytest.mark.parametrize(
    "version",
    ["app-1.0.1", "app-1.0.2", "app-999.123.456"],
)
def test_supported_discord_version_folders_are_recognized(monkeypatch, version: str) -> None:
    monkeypatch.setenv("LOCALAPPDATA", r"C:\Users\redacted\AppData\Local")
    path = rf"C:\Users\redacted\AppData\Local\Discord\{version}\Discord.exe"

    assert uia._is_discord_executable(path)


@pytest.mark.parametrize(
    "path",
    [
        r"C:\Users\redacted\AppData\Local\Discord\app-1.0.1\Launcher.exe",
        r"C:\Users\redacted\AppData\Local\Discord\app-1.0.1\electron.exe",
        r"C:\Users\redacted\AppData\Local\Discord\portable\Discord.exe",
        r"C:\Users\redacted\AppData\Local\DiscordPTB\app-1.0.1\Discord.exe",
        r"C:\Users\redacted\Downloads\Discord\app-1.0.1\Discord.exe",
    ],
)
def test_discord_matcher_rejects_lookalike_or_unsupported_install_folders(
    monkeypatch, path: str
) -> None:
    monkeypatch.setenv("LOCALAPPDATA", r"C:\Users\redacted\AppData\Local")

    assert not uia._is_discord_executable(path)


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

    def ensure_unlocked(self):
        return self._session_available()

    def run_on_ui(self, function, timeout=0):
        return function()

    def refresh_entries(self):
        return None

    def _touch_secret(self):
        self.last_secret_use = 1.0

    def _validate_remote_text(self, value, *args):
        if not isinstance(value, str):
            raise ValueError
        return value

    def request(self, action: str, *, origin: str = "https://example.test", context=None, **payload):
        return self.dispatch_remote(
            {
                "action": action,
                "protocol": 2,
                "card_protocol": 1,
                "extension_version": "0.3.3",
                "origin": origin,
                "context": context or json.dumps([17, "document-redacted", origin, "operation-redacted"]),
                **payload,
            }
        )


def test_locked_capture_is_deferred_then_exact_match_clears_without_prompt(tmp_path) -> None:
    session = create_vault(tmp_path / "redacted.json", "redacted-master", kdf_overrides=KDF)
    session.upsert_web(
        origin="https://example.test",
        username="redacted-account",
        password="redacted-password",
    )
    broker = _Broker(session)
    broker.guard.invalidate()

    captured = broker.request(
        "capture_browser",
        username="redacted-account",
        password="redacted-password",
    )

    assert captured["ok"] and captured["stored"]
    assert captured["status"] == "deferred"
    assert captured["pending_token"] == captured["token"]
    broker.guard.open(3600)
    pending = broker.request("pending_browser")
    assert pending["pending"] and pending["status"] == "deferred"
    assert "password" not in json.dumps(pending)

    nonce = broker.request("begin_gesture_browser", user_gesture=True)["gesture_nonce"]
    resolved = broker.request(
        "save_pending_browser",
        pending_token=pending["pending_token"],
        gesture_nonce=nonce,
    )

    assert resolved == {"ok": True, "status": "existing"}
    assert broker.request("pending_browser") == {"ok": True, "pending": False}


def test_pending_capture_is_scoped_to_its_site_and_update_status_is_preserved(tmp_path) -> None:
    session = create_vault(tmp_path / "redacted-origin.json", "redacted-master", kdf_overrides=KDF)
    session.upsert_web(
        origin="https://example.test",
        username="redacted-account",
        password="redacted-old-password",
    )
    broker = _Broker(session)

    captured = broker.request(
        "capture_browser",
        password="redacted-new-password",
        username="redacted-account",
    )
    assert captured["status"] == "password_changed"
    assert broker.request("pending_browser", origin="https://other-example.test")["pending"] is False
    # A sign-in that lands on a subdomain sees it, named for the origin it is saved for.
    landed = broker.request("pending_browser", origin="https://sub.example.test")
    assert landed["pending"] and landed["origin"] == "https://example.test"
    pending = broker.request("pending_browser")
    assert pending["pending"] and pending["status"] == "password_changed"
    redacted = json.dumps(pending)
    assert "redacted-old-password" not in redacted
    assert "redacted-new-password" not in redacted


# ---------------------------------------------------------------------------
# Card fill: begin -> approve -> release, mirroring the identity flow
# ---------------------------------------------------------------------------

CARD_KDF = {"time_cost": 1, "memory_cost_kib": 8192, "parallelism": 1, "hash_len": 32}


def _card_session(tmp_path, name="card.json"):
    session = create_vault(tmp_path / name, "redacted-master", kdf_overrides=CARD_KDF)
    card_id = session.items.create_card("Visa", cardholder="Ada Example", number="4111111111111111",
                                        expiry="07/29", cvv="123", pin="4321", favorite=True)
    return session, card_id


def test_begin_card_browser_returns_metadata_only_with_gesture_nonce(tmp_path) -> None:
    session, card_id = _card_session(tmp_path)
    broker = _Broker(session)
    assert broker.request("begin_card_browser") == {"ok": False, "error": "user_gesture_required"}
    start = broker.request("begin_card_browser", user_gesture=True)
    assert start["ok"] and start["card_protocol"] == 1
    choice = start["choices"][0]
    assert choice["entry_id"] == card_id and choice["revision"] == 1 and choice["favorite"] is True
    assert choice["brand"] == "visa" and choice["last4"] == "1111"
    assert choice["fields"]["cc-number"] == {"label": "Card number", "protected": True, "present": True}
    assert choice["fields"]["cc-csc"]["protected"] is True and choice["fields"]["cc-name"]["present"] is True
    assert "pin" not in json.dumps(choice["fields"])
    serialized = json.dumps(start["choices"])
    assert "4111111111111111" not in serialized and "123" not in serialized and "4321" not in serialized
    assert "4111111111111111" not in json.dumps(start)
    assert len(start["gesture_nonce"]) == 32 and start["gesture_expires_in"] == 30
    assert start["session_id"] == broker.guard.lease().token
    # Protocol gate mirrors identity_protocol.
    no_protocol = broker.dispatch_remote({
        "action": "begin_card_browser", "protocol": 2, "extension_version": "0.3.3",
        "origin": "https://example.test",
        "context": json.dumps([17, "document-redacted", "https://example.test", "operation-redacted"]),
        "user_gesture": True,
    })
    assert no_protocol["error"] == "version_mismatch"
    empty = _Broker(create_vault(tmp_path / "empty.json", "redacted-master", kdf_overrides=CARD_KDF))
    assert empty.request("begin_card_browser", user_gesture=True) == {"ok": False, "error": "card_not_found"}


def test_card_approve_masks_protected_values_and_release_is_selected_only(tmp_path, monkeypatch) -> None:
    session, card_id = _card_session(tmp_path)
    broker = _Broker(session)
    start = broker.request("begin_card_browser", user_gesture=True)
    prompts = []
    monkeypatch.setattr("broker_host.confirm", lambda *args: prompts.append(args[2]) or True)
    denied = broker.request("approve_card_browser", entry_id=card_id, revision=1,
                            fields=["cc-number"], session_id=start["session_id"])
    assert denied == {"ok": False, "error": "user_gesture_required"}
    approved = broker.request("approve_card_browser", user_gesture=True, entry_id=card_id, revision=1,
                              fields=["cc-name", "cc-number", "cc-csc", "cc-exp"],
                              session_id=start["session_id"])
    assert approved["ok"] and approved["card_protocol"] == 1
    assert approved["fields"] == ["cc-name", "cc-number", "cc-csc", "cc-exp"]
    assert approved["entry_id"] == card_id and approved["revision"] == 1
    assert len(approved["gesture_nonce"]) == 32 and "values" not in approved
    assert "4111111111111111" not in json.dumps(approved)
    # The trusted review dialog shows the cardholder and masked card/CVV only.
    assert len(prompts) == 1
    assert "Ada Example" in prompts[0] and "1111" in prompts[0] and "07/2029" in prompts[0]
    assert "4111111111111111" not in prompts[0] and "123" not in prompts[0] and "4321" not in prompts[0]

    released = broker.request("release_card_browser", approval=approved["approval"], entry_id=card_id,
                              revision=1, fields=["cc-name", "cc-number", "cc-csc", "cc-exp"],
                              gesture_nonce=approved["gesture_nonce"])
    assert released["ok"] and released["card_protocol"] == 1
    assert released["values"] == {"cc-name": "Ada Example", "cc-number": "4111111111111111",
                                  "cc-csc": "123", "cc-exp": "07/2029"}
    assert "4321" not in json.dumps(released) and "session_id" not in released
    # One use only.
    replay = broker.request("release_card_browser", approval=approved["approval"], entry_id=card_id,
                            revision=1, fields=["cc-name", "cc-number", "cc-csc", "cc-exp"],
                            gesture_nonce=start["gesture_nonce"])
    assert replay["error"] == "session_changed" and "values" not in replay


def test_card_release_uses_get_browser_gesture_nonce_gating(tmp_path, monkeypatch) -> None:
    session, card_id = _card_session(tmp_path)
    broker = _Broker(session)
    monkeypatch.setattr("broker_host.confirm", lambda *args: True)

    def approve():
        start = broker.request("begin_card_browser", user_gesture=True)
        return broker.request("approve_card_browser", user_gesture=True, entry_id=card_id, revision=1,
                              fields=["cc-number"], session_id=start["session_id"])

    approved = approve()
    wrong_tab = broker.request("release_card_browser", approval=approved["approval"], entry_id=card_id,
                               revision=1, fields=["cc-number"], gesture_nonce=approved["gesture_nonce"],
                               context=json.dumps([99, "other-document", "https://example.test", "op"]))
    assert wrong_tab["error"] == "gesture_nonce_invalid"
    bogus = broker.request("release_card_browser", approval=approved["approval"], entry_id=card_id,
                           revision=1, fields=["cc-number"], gesture_nonce="f" * 32)
    assert bogus["error"] == "gesture_nonce_invalid"
    # The nonce from the wrong tab was not consumed; the right tab still works.
    released = broker.request("release_card_browser", approval=approved["approval"], entry_id=card_id,
                              revision=1, fields=["cc-number"], gesture_nonce=approved["gesture_nonce"])
    assert released["values"] == {"cc-number": "4111111111111111"}

    # Legacy compat: no nonce is accepted (with a diagnostics warning) only
    # while the setting is on; otherwise a fresh nonce is required.
    approved = approve()
    broker.settings = AppSettings(auto_lock_seconds=0, legacy_gesture_compat=False)
    required = broker.request("release_card_browser", approval=approved["approval"], entry_id=card_id,
                              revision=1, fields=["cc-number"])
    assert required["error"] == "gesture_nonce_required" and "values" not in required
    broker.settings = AppSettings(auto_lock_seconds=0, legacy_gesture_compat=True)
    legacy = broker.request("release_card_browser", approval=approved["approval"], entry_id=card_id,
                            revision=1, fields=["cc-number"])
    assert legacy["ok"] and legacy["values"] == {"cc-number": "4111111111111111"}


def test_card_fill_rejects_pin_cancel_revision_change_and_scope_drift(tmp_path, monkeypatch) -> None:
    session, card_id = _card_session(tmp_path)
    broker = _Broker(session)
    monkeypatch.setattr("broker_host.confirm", lambda *args: True)
    start = broker.request("begin_card_browser", user_gesture=True)
    pin = broker.request("approve_card_browser", user_gesture=True, entry_id=card_id, revision=1,
                         fields=["pin"], session_id=start["session_id"])
    assert pin["ok"] is False and "approval" not in pin
    approved = broker.request("approve_card_browser", user_gesture=True, entry_id=card_id, revision=1,
                              fields=["cc-number"], session_id=start["session_id"])
    assert broker.request("cancel_card_browser", approval=approved["approval"]) == {"ok": True}
    cancelled = broker.request("release_card_browser", approval=approved["approval"], entry_id=card_id,
                               revision=1, fields=["cc-number"], gesture_nonce=approved["gesture_nonce"])
    assert cancelled["ok"] is False and "values" not in cancelled

    approved = broker.request("approve_card_browser", user_gesture=True, entry_id=card_id, revision=1,
                              fields=["cc-number"], session_id=start["session_id"])
    other_origin = broker.request("release_card_browser", origin="https://other.test",
                                  approval=approved["approval"], entry_id=card_id, revision=1,
                                  fields=["cc-number"], gesture_nonce=approved["gesture_nonce"])
    assert other_origin["ok"] is False and "values" not in other_origin
    # Releasing more than was approved is refused and consumes the approval.
    approved = broker.request("approve_card_browser", user_gesture=True, entry_id=card_id, revision=1,
                              fields=["cc-number"], session_id=start["session_id"])
    wider = broker.request("release_card_browser", approval=approved["approval"], entry_id=card_id,
                           revision=1, fields=["cc-number", "cc-csc"], gesture_nonce=approved["gesture_nonce"])
    assert wider["ok"] is False and "values" not in wider

    approved = broker.request("approve_card_browser", user_gesture=True, entry_id=card_id, revision=1,
                              fields=["cc-number"], session_id=start["session_id"])
    session.items.update_typed_item(card_id, payload={"expiry": "08/30"}, expected_revision=1)
    stale = broker.request("release_card_browser", approval=approved["approval"], entry_id=card_id,
                           revision=1, fields=["cc-number"], gesture_nonce=approved["gesture_nonce"])
    assert stale["error"] == "session_changed" and "values" not in stale
    unknown = broker.request("dump_card_browser")
    assert unknown["error"] == "unsupported_action"
