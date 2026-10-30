"""Python → page events: ``window.dispatchEvent(new CustomEvent("lgk", {detail}))``."""
from __future__ import annotations

import json
import logging
from collections.abc import Callable
from typing import Any

_log = logging.getLogger(__name__)

# Characters that could end a script context or a JS string literal when the
# JSON is embedded in evaluated code. Built with chr() so no source escape can
# be mangled by an editor or shell.
_ESCAPES = {chr(code): "\\u%04x" % code for code in (0x3C, 0x3E, 0x26, 0x2028, 0x2029)}


def _js_literal(value: Any) -> str:
    text = json.dumps(value, ensure_ascii=False, separators=(",", ":"))
    for raw, escaped in _ESCAPES.items():
        text = text.replace(raw, escaped)
    return text


class QueuedSink:
    """Deliver scripts on one background thread so emitting never blocks the caller.

    pywebview's ``evaluate_js`` waits for the page without a timeout and must not
    run on the WinForms UI thread or while a controller lock is held; a queue in
    front of it keeps a hung page from stalling auto-lock or the close handler.
    """

    _STOP = object()

    def __init__(self, deliver: Callable[[str], Any]) -> None:
        import queue
        import threading

        self._deliver = deliver
        self._queue: queue.SimpleQueue[Any] = queue.SimpleQueue()
        self._thread = threading.Thread(target=self._run, name="localgatekeys-ui-events", daemon=True)
        self._thread.start()

    def __call__(self, js: str) -> None:
        self._queue.put(js)

    def _run(self) -> None:
        while True:
            js = self._queue.get()
            if js is self._STOP:
                return
            try:
                self._deliver(js)
            except Exception:  # noqa: BLE001 - one failed delivery must not stop the rest
                _log.debug("UI event not delivered", exc_info=True)

    def close(self) -> None:
        self._queue.put(self._STOP)


class EventBus:
    def __init__(self, sink: Callable[[str], None] | None = None) -> None:
        self._sinks: dict[str, Callable[[str], None]] = {"main": sink or (lambda _js: None)}

    def attach(self, sink: Callable[[str], None], *, key: str = "main") -> None:
        """Deliver events to one window's page (``main`` or ``popup``); attaching again replaces it."""
        self._sinks = {**self._sinks, key: sink}

    def emit(self, name: str, detail: dict[str, Any]) -> None:
        if name in ("toast", "notice") and not detail.get("error_log"):
            from ..api.result import points_to_error_log

            if points_to_error_log(f"{detail.get('title', '')} {detail.get('message', '')}"):
                detail = {**detail, "error_log": True}  # the page offers "Open error log"
        payload = _js_literal({"name": name, "detail": detail})
        js = f'window.dispatchEvent(new CustomEvent("lgk",{{detail:{payload}}}))'
        for sink in list(self._sinks.values()):
            try:
                sink(js)
            except Exception:  # noqa: BLE001 - a closed window must not break the caller
                _log.debug("Event %s was not delivered", name, exc_info=True)
