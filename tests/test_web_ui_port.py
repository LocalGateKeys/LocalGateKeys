"""Stage 1: prompts raised by Python are answered by the page through modal.request events."""
from __future__ import annotations

import threading
import time

import pytest

from localvault.app.ui_port import safe_confirm
from localvault.web.ui_port import WebUiPort


class RecordingBus:
    def __init__(self) -> None:
        self.events: list[tuple[str, dict]] = []

    def emit(self, name, detail):
        self.events.append((name, detail))

    def last(self, name):
        for event_name, detail in reversed(self.events):
            if event_name == name:
                return detail
        raise AssertionError(f"no {name} event in {self.events}")


def _wait_for(bus, name, timeout=2.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if any(n == name for n, _ in bus.events):
            return bus.last(name)
        time.sleep(0.005)
    raise AssertionError(f"{name} never emitted")


def _in_thread(fn):
    box: dict = {}

    def run():
        try:
            box["value"] = fn()
        except BaseException as exc:  # noqa: BLE001
            box["error"] = exc

    thread = threading.Thread(target=run)
    thread.start()
    return thread, box


def test_confirm_returns_page_answer():
    bus = RecordingBus()
    port = WebUiPort(bus, timeout=5)
    thread, box = _in_thread(lambda: port.confirm("Save new login?", "Origin: x"))
    request = _wait_for(bus, "modal.request")
    assert request["kind"] == "confirm" and request["title"] == "Save new login?"
    assert port.answer(request["id"], True) is True
    thread.join(2)
    assert box == {"value": True}


def test_confirm_times_out_as_timeouterror():
    port = WebUiPort(RecordingBus(), timeout=0.05)
    with pytest.raises(TimeoutError):
        port.confirm("T", "M")


def test_answer_unknown_or_repeated_id_is_false():
    bus = RecordingBus()
    port = WebUiPort(bus, timeout=5)
    assert port.answer("nope", True) is False
    thread, _box = _in_thread(lambda: port.confirm("T", "M"))
    request = _wait_for(bus, "modal.request")
    assert port.answer(request["id"], False) is True
    thread.join(2)
    assert port.answer(request["id"], True) is False


def test_cancel_all_releases_waiters_as_denied():
    bus = RecordingBus()
    port = WebUiPort(bus, timeout=5)
    thread, box = _in_thread(lambda: port.confirm("T", "M"))
    request = _wait_for(bus, "modal.request")
    port.cancel_all()
    thread.join(2)
    assert isinstance(box.get("error"), TimeoutError)
    assert request["id"] in bus.last("modal.cancel")["ids"]


def test_notify_does_not_block():
    bus = RecordingBus()
    WebUiPort(bus, timeout=5).notify("error", "Passkey not saved", "m")
    assert bus.last("toast") == {"kind": "error", "title": "Passkey not saved", "message": "m"}


def test_passkey_malformed_answer_is_cancel():
    bus = RecordingBus()
    port = WebUiPort(bus, timeout=5)
    thread, box = _in_thread(lambda: port.ask_passkey("get", origin="https://a.test", rp_id="a.test",
                                                      profile_name="P", accounts=[], excluded=False))
    request = _wait_for(bus, "modal.request")
    assert request["kind"] == "passkey"
    port.answer(request["id"], {"weird": 1})
    thread.join(2)
    assert box == {"value": ("cancel", None)}


def test_passkey_approve_answer():
    bus = RecordingBus()
    port = WebUiPort(bus, timeout=5)
    thread, box = _in_thread(lambda: port.ask_passkey("get", origin="https://a.test", rp_id="a.test",
                                                      profile_name="P", accounts=[{"id": "i1"}], excluded=False))
    request = _wait_for(bus, "modal.request")
    port.answer(request["id"], {"choice": "approve", "item_id": "i1"})
    thread.join(2)
    assert box == {"value": ("approve", "i1")}


def test_upgrade_enter_calls_back_without_blocking():
    bus = RecordingBus()
    port = WebUiPort(bus, timeout=5)
    entered = threading.Event()
    port.show_upgrade(limit=4, message="Full", on_enter=entered.set)
    request = bus.last("modal.request")
    assert request["kind"] == "upgrade" and request["limit"] == 4
    assert request["purchase_url"] == "https://localgatekeys.app/buy"
    port.answer(request["id"], "enter")
    assert entered.wait(2)


def test_safe_confirm_over_web_port_denies_on_timeout():
    assert safe_confirm(WebUiPort(RecordingBus(), timeout=0.05), "T", "M") is False


def test_unanswered_prompt_is_cancelled_on_the_page():
    bus = RecordingBus()
    port = WebUiPort(bus, timeout=0.05)
    with pytest.raises(TimeoutError):
        port.confirm("T", "M")
    request = bus.last("modal.request")
    assert bus.last("modal.cancel") == {"ids": [request["id"]]}


def test_passkey_prompt_carries_the_dialog_copy_and_safe_accounts():
    import threading

    from localvault.web.ui_port import WebUiPort

    events = []

    class Bus:
        def emit(self, name, detail):
            events.append((name, detail))

    port = WebUiPort(Bus(), timeout=5)
    result = {}
    worker = threading.Thread(target=lambda: result.setdefault("v", port.ask_passkey(
        "get", origin="https://a.test", rp_id="a.test", profile_name="Ann",
        accounts=[{"item_id": "i1", "title": "ann@a.test", "private_key": "SECRET"}], excluded=False)))
    worker.start()
    for _ in range(50):
        if events:
            break
        threading.Event().wait(0.02)
    name, detail = events[0]
    assert detail["kind"] == "passkey" and detail["text"]["title"] == "Sign in with a passkey?"
    assert "SECRET" not in repr(detail)
    port.answer(detail["id"], {"choice": "approve", "item_id": "i1"})
    worker.join(2)
    assert result["v"] == ("approve", "i1")


def test_passkey_request_carries_only_display_fields_and_offered_ids():
    bus = RecordingBus()
    port = WebUiPort(bus, timeout=5)
    thread, box = _in_thread(lambda: port.ask_passkey("get", origin="https://a.test", rp_id="a.test",
                                                      profile_name="P", accounts=[{"id": "i1", "title": "Ann"}],
                                                      excluded=False))
    request = _wait_for(bus, "modal.request")
    assert set(request) == {"id", "kind", "mode", "accounts", "text"}
    port.answer(request["id"], {"choice": "approve", "item_id": "not-offered"})
    thread.join(2)
    assert box == {"value": ("cancel", None)}


def test_a_popup_view_marks_its_prompts_and_shows_then_hides_the_popup():
    bus = RecordingBus()
    port = WebUiPort(bus, timeout=5)
    shown, idle = [], []
    popup = port.popup_view(on_show=lambda: shown.append(1), on_idle=lambda: idle.append(1))
    thread, box = _in_thread(lambda: popup.choose("Choose account for this app", "", [{"id": "a", "label": "ann"}]))
    request = _wait_for(bus, "modal.request")
    assert request["surface"] == "popup" and shown == [1] and idle == []
    assert port.pending_on("popup") == 1
    assert port.answer(request["id"], "a")  # the bridge answers through the main port
    thread.join(2)
    assert box == {"value": "a"} and idle == [1] and port.pending_on("popup") == 0


def test_main_window_prompts_carry_no_surface():
    bus = RecordingBus()
    port = WebUiPort(bus, timeout=5)
    thread, _box = _in_thread(lambda: port.confirm("Save?", "m"))
    request = _wait_for(bus, "modal.request")
    assert "surface" not in request
    port.answer(request["id"], True)
    thread.join(2)


def test_closing_the_popup_cancels_only_its_prompts():
    bus = RecordingBus()
    port = WebUiPort(bus, timeout=5)
    popup = port.popup_view(on_show=lambda: None, on_idle=lambda: None)
    t1, b1 = _in_thread(lambda: popup.confirm("Fill this app?", "m"))
    _wait_for(bus, "modal.request")
    t2, b2 = _in_thread(lambda: port.confirm("Main window question", "m"))
    deadline = time.monotonic() + 2
    while sum(1 for n, _ in bus.events if n == "modal.request") < 2 and time.monotonic() < deadline:
        time.sleep(0.005)
    port.cancel_surface("popup")
    t1.join(2)
    assert isinstance(b1.get("error"), TimeoutError)  # cancelled: callers treat it as a refusal
    assert t2.is_alive()  # the main window's prompt is untouched
    main = [d for n, d in bus.events if n == "modal.request" and "surface" not in d][0]
    port.answer(main["id"], True)
    t2.join(2)
    assert b2 == {"value": True}


def test_password_answer_is_wiped_if_the_port_fails_after_conversion(monkeypatch):
    from localvault.secret_text import SecretText

    created = []
    real_from_str = SecretText.from_str.__func__

    def spy(cls, value):
        secret = real_from_str(cls, value)
        created.append(secret)
        return secret

    monkeypatch.setattr(SecretText, "from_str", classmethod(spy))
    bus = RecordingBus()
    port = WebUiPort(bus, timeout=5)

    def boom():
        raise RuntimeError("idle hook failed")

    popup = port.popup_view(on_show=lambda: None, on_idle=boom)
    thread, box = _in_thread(lambda: popup.ask_password("Re-enter", ""))
    request = _wait_for(bus, "modal.request")
    assert port.answer(request["id"], "hunter2")
    thread.join(2)
    assert isinstance(box.get("error"), RuntimeError)
    assert len(created) == 1
    with pytest.raises(ValueError):
        created[0].buffer  # wiped
