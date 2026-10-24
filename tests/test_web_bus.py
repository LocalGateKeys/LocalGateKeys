"""Stage 1: Python → page event bus and the bridge's result shape."""
from __future__ import annotations

import json
import re

from localvault.api.result import ApiError, fail, guarded, ok
from localvault.web.bus import EventBus


def _detail(js: str) -> dict:
    match = re.search(r"\{detail:(.*)\}\)\)$", js)
    assert match, js
    return json.loads(match.group(1))


def test_emit_builds_custom_event():
    sent = []
    EventBus(sent.append).emit("vault.state", {"state": "locked"})
    assert 'new CustomEvent("lgk"' in sent[0]
    assert _detail(sent[0]) == {"name": "vault.state", "detail": {"state": "locked"}}


def test_emit_escapes_script_breakers():
    sent = []
    EventBus(sent.append).emit("toast", {"t": "</script><x>&\u2028\u2029"})
    js = sent[0]
    for raw in ("</script>", "<x>", "&", "\u2028", "\u2029"):
        assert raw not in js
    assert _detail(js)["detail"]["t"] == "</script><x>&\u2028\u2029"


def test_sink_failure_is_swallowed():
    def boom(_js):
        raise RuntimeError("window gone")

    EventBus(boom).emit("toast", {})


def test_attach_replaces_noop_sink():
    bus, sent = EventBus(), []
    bus.emit("toast", {})
    bus.attach(sent.append)
    bus.emit("toast", {})
    assert len(sent) == 1


def test_ok_and_fail_shapes():
    assert ok(a=1) == {"ok": True, "a": 1}
    assert fail("busy", "Busy") == {"ok": False, "error": {"code": "busy", "message": "Busy"}}


def test_guarded_maps_apierror_and_unexpected(monkeypatch):
    logged = []
    monkeypatch.setattr("localvault.error_log.log_exception", lambda where, exc: logged.append(where))

    @guarded
    def busy():
        raise ApiError("busy", "Busy")

    @guarded
    def broken():
        raise ValueError("secret detail /path")

    assert busy() == fail("busy", "Busy")
    result = broken()
    assert result["error"]["code"] == "internal"
    assert "secret detail" not in json.dumps(result)
    assert logged == ["api"]


def test_queued_sink_never_blocks_the_caller_and_keeps_order():
    import threading
    import time

    from localvault.web.bus import QueuedSink

    release, delivered = threading.Event(), []

    def slow(js):
        release.wait(5)
        delivered.append(js)

    sink = QueuedSink(slow)
    started = time.monotonic()
    for n in range(3):
        sink(f"js{n}")
    assert time.monotonic() - started < 0.5  # a hung page cannot stall the emitter
    release.set()
    deadline = time.monotonic() + 5
    while len(delivered) < 3 and time.monotonic() < deadline:
        time.sleep(0.01)
    assert delivered == ["js0", "js1", "js2"]
    sink.close()


def test_queued_sink_survives_a_failing_delivery():
    import time

    from localvault.web.bus import QueuedSink

    delivered = []

    def flaky(js):
        if js == "bad":
            raise RuntimeError("renderer gone")
        delivered.append(js)

    sink = QueuedSink(flaky)
    sink("bad")
    sink("good")
    deadline = time.monotonic() + 5
    while not delivered and time.monotonic() < deadline:
        time.sleep(0.01)
    assert delivered == ["good"]
    sink.close()


def test_events_reach_the_popup_window_too():
    from localvault.web.bus import EventBus

    main, popup = [], []
    bus = EventBus()
    bus.attach(main.append)
    bus.attach(popup.append, key="popup")
    bus.emit("vault.state", {"state": "locked"})
    assert len(main) == 1 and main == popup
    bus.attach(lambda _js: None)  # the main page detached at close: the popup still gets events
    bus.emit("toast", {"message": "x"})
    assert len(popup) == 2
