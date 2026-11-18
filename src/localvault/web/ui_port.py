"""``UiPort`` for the WebView page: prompts become ``modal.request`` events the page answers."""
from __future__ import annotations

import secrets
import threading
import time
from collections.abc import Callable
from typing import Any, Literal, Protocol

from ..app.licence_view import PURCHASE_URL
from ..secret_text import SecretText

_CANCELLED = object()


class Bus(Protocol):
    def emit(self, name: str, detail: dict[str, Any]) -> None: ...


class _Pending:
    __slots__ = ("event", "value")

    def __init__(self) -> None:
        self.event = threading.Event()
        self.value: Any = _CANCELLED


def _password_answer(answer: Any) -> SecretText | None:
    if not isinstance(answer, str) or not answer:
        return None
    try:
        return SecretText.from_str(answer)
    except ValueError:
        return None  # unencodable text is a cancel, never an error that could carry it


class WebUiPort:
    """Blocking prompts for worker threads; the page answers with ``answer(id, value)``."""

    def __init__(self, bus: Bus, *, timeout: float = 90.0) -> None:
        self._bus = bus
        self._timeout = timeout
        self._lock = threading.Lock()
        self._pending: dict[str, _Pending] = {}
        self._callbacks: dict[str, Callable[[Any], None]] = {}
        self._surfaces: dict[str, str] = {}  # request id -> "popup" (shared by every view)
        self._surface: str | None = None
        self._on_show: Callable[[], None] | None = None
        self._on_idle: Callable[[], None] | None = None

    def popup_view(self, *, on_show: Callable[[], None], on_idle: Callable[[], None]) -> "WebUiPort":
        """The same port for prompts the small popup window shows (fills started outside the app).

        Requests carry ``surface: "popup"``; ``on_show`` runs before each one and ``on_idle`` once none is left.
        Answers still arrive through this port's ``answer`` (the views share their pending requests).
        """
        return self.surface_view("popup", on_show=on_show, on_idle=on_idle)

    def surface_view(self, surface: str, *, on_show: Callable[[], None] | None = None,
                     on_idle: Callable[[], None] | None = None) -> "WebUiPort":
        """The same port for prompts another window shows (``popup``, or the quick-search ``palette``)."""
        import copy

        view = copy.copy(self)
        view._surface, view._on_show, view._on_idle = surface, on_show, on_idle
        return view

    def pending_on(self, surface: str) -> int:
        with self._lock:
            return sum(1 for rid, where in self._surfaces.items() if where == surface and rid in self._pending)

    def cancel_surface(self, surface: str) -> None:
        """The popup was closed: its open prompts are cancelled (a cancel is never an approval)."""
        with self._lock:
            ids = [rid for rid, where in self._surfaces.items() if where == surface and rid in self._pending]
            for rid in ids:
                self._pending[rid].value = _CANCELLED
                self._pending[rid].event.set()
        if ids:
            self._bus.emit("modal.cancel", {"ids": ids})

    # ------------------------------------------------------------ requests
    def _wait(self, pending: _Pending, cancel: threading.Event | None, timeout: float | None) -> bool:
        """True once answered; False on the timeout or a set ``cancel`` (this request only)."""
        limit = self._timeout if timeout is None else max(0.0, min(float(timeout), self._timeout))
        if cancel is None:
            return pending.event.wait(limit)
        deadline = time.monotonic() + limit
        while True:
            remaining = deadline - time.monotonic()
            if cancel.is_set() or remaining <= 0:
                return pending.event.is_set() and not cancel.is_set()
            if pending.event.wait(min(0.05, remaining)):
                return True

    def _ask(self, detail: dict[str, Any], convert: Callable[[Any], Any] | None = None, *,
             cancel: threading.Event | None = None, timeout: float | None = None) -> Any:
        """Emit the request and wait for its answer; ``convert`` runs on the answer before it leaves ``_Pending``.

        ``cancel`` (set from another thread) and ``timeout`` end only this request, like an unanswered prompt.
        """
        request_id = secrets.token_urlsafe(16)
        pending = _Pending()
        if self._surface:
            detail = {**detail, "surface": self._surface}
        with self._lock:
            self._pending[request_id] = pending
            if self._surface:
                self._surfaces[request_id] = self._surface
        converted: Any = None
        try:
            if self._on_show is not None:
                self._on_show()
            self._bus.emit("modal.request", {"id": request_id, **detail})
            if not self._wait(pending, cancel, timeout):
                # Take the unanswered prompt off the page too.
                self._bus.emit("modal.cancel", {"ids": [request_id]})
                raise TimeoutError("The prompt was not answered")
            if pending.value is _CANCELLED:
                raise TimeoutError("The prompt was not answered")
            return pending.value if convert is None else (converted := convert(pending.value))
        finally:
            with self._lock:
                self._pending.pop(request_id, None)
                self._surfaces.pop(request_id, None)
                # Off the table, so no late answer lands; the answer (a password, for one) is not kept.
                pending.value = None
                idle = self._surface is not None and not any(
                    where == self._surface for where in self._surfaces.values())
            try:
                if idle and self._on_idle is not None:
                    self._on_idle()
            except BaseException:
                # The idle hook failed after the conversion: the caller never gets the secret, so wipe it here.
                if isinstance(converted, SecretText):
                    converted.wipe()
                raise

    def confirm(self, title: str, message: str) -> bool:
        return self._ask({"kind": "confirm", "title": title, "message": message}) is True

    def notify(self, kind: Literal["info", "error"], title: str, message: str) -> None:
        self._bus.emit("toast", {"kind": kind, "title": title, "message": message})

    def ask_passkey(self, mode: str, *, origin: str, rp_id: str, profile_name: str,
                    accounts: list[dict[str, Any]], excluded: bool, surface: str = "browser",
                    caller: dict[str, Any] | None = None, cancel: threading.Event | None = None,
                    timeout: float | None = None, top_origin: str | None = None) -> tuple[str, str | None]:
        from ..passkey_dialog import dialog_text

        text = dialog_text(mode, origin=origin, rp_id=rp_id, profile_name=profile_name, accounts=accounts,
                           excluded=excluded, surface=surface, caller=caller, top_origin=top_origin)
        # Only what the dialog shows: titles and ids, never key material.
        safe_accounts = [{"item_id": str(a.get("item_id") or a.get("id") or ""), "title": str(a.get("title") or ""),
                          "user_name": str(a.get("user_name") or "")} for a in accounts]
        try:
            # The page shows the prepared text; raw origin and profile values stay in Python.
            answer = self._ask({"kind": "passkey", "mode": mode, "accounts": safe_accounts, "text": text},
                               cancel=cancel, timeout=timeout)
        except TimeoutError:
            return ("cancel", None)
        if not isinstance(answer, dict):
            return ("cancel", None)
        choice = answer.get("choice")
        item_id = answer.get("item_id")
        if choice not in ("approve", "browser", "cancel"):
            return ("cancel", None)
        if choice == "browser" and not text["browser_label"]:
            return ("cancel", None)  # the system dialog offers no browser fallback
        if choice != "approve" or not isinstance(item_id, str):
            return (choice, None)
        if item_id not in {a["item_id"] for a in safe_accounts}:
            return ("cancel", None)  # only an account the dialog offered
        return (choice, item_id)

    def choose(self, title: str, message: str, options: list[dict[str, Any]]) -> str | None:
        """Pick one of ``options`` ({id, label, detail}); cancel or timeout is None."""
        try:
            answer = self._ask({"kind": "choose", "title": title, "message": message, "options": options})
        except TimeoutError:
            return None
        ids = {str(o.get("id")) for o in options}
        return answer if isinstance(answer, str) and answer in ids else None

    def confirm_remember(self, title: str, message: str, remember_label: str) -> dict[str, bool]:
        """A confirm with an optional "remember" box; cancel or timeout is not approved."""
        try:
            answer = self._ask({"kind": "confirm_remember", "title": title, "message": message,
                                "remember_label": remember_label})
        except TimeoutError:
            return {"approved": False, "remember": False}
        if not isinstance(answer, dict):
            return {"approved": False, "remember": False}
        return {"approved": answer.get("approved") is True, "remember": answer.get("remember") is True}

    def confirm_agent(self, request: Any, *, timeout: float | None = None) -> bool:
        """An AI agent's request (agent_gate.AgentRequest) in the approval view; only ``{"approved": true}`` approves.

        Every field goes to the page as plain text (the view renders text, never markup). Cancel, timeout or any
        other answer is a refusal; there is no "always" answer.
        """
        detail = {"kind": "agent", "action": str(request.action), "agent": str(request.agent),
                  "process": str(request.process), "site": str(request.site), "purpose": str(request.purpose),
                  "hello": bool(request.hello),
                  "method": "passkey" if getattr(request, "method", "") == "passkey" else "password"}
        if request.action == "run":  # run_with_secrets: the exact command line, its folder, each item and field
            detail.update(command=str(request.command), cwd=str(request.cwd), timeout=int(request.timeout),
                          secrets=[{"variable": str(variable), "item": str(item), "field": str(field)}
                                   for variable, item, field in request.secrets])
        try:
            answer = self._ask(detail, timeout=timeout)
        except TimeoutError:
            return False
        return isinstance(answer, dict) and answer.get("approved") is True

    def ask_password(self, title: str, message: str) -> SecretText | None:
        """Master-password prompt in the page; cancel, timeout or an empty, non-string or unencodable answer is None.

        The answered ``str`` becomes a ``SecretText`` before it leaves the pending request; the caller owns
        (and wipes) the result.
        """
        try:
            return self._ask({"kind": "password", "title": title, "message": message}, _password_answer)
        except TimeoutError:
            return None

    def show_upgrade(self, *, limit: int, message: str, on_enter: Callable[[], None]) -> None:
        request_id = secrets.token_urlsafe(16)

        def answered(value: Any) -> None:
            if value == "enter":
                threading.Thread(target=on_enter, name="localgatekeys-upgrade", daemon=True).start()

        with self._lock:
            self._callbacks[request_id] = answered
        # The page offers "Buy Pro" (opened in the browser) when a checkout link is set.
        self._bus.emit("modal.request", {"id": request_id, "kind": "upgrade", "limit": limit,
                                         "message": message, "purchase_url": PURCHASE_URL or ""})

    # ------------------------------------------------------------- answers
    def answer(self, request_id: str, value: Any) -> bool:
        with self._lock:
            pending = self._pending.get(request_id)
            callback = self._callbacks.pop(request_id, None)
            if pending is not None and not pending.event.is_set():
                pending.value = value
                pending.event.set()
                return True
        if callback is not None:
            callback(value)
            return True
        return False

    def cancel_all(self) -> None:
        with self._lock:
            ids = list(self._pending) + list(self._callbacks)
            for pending in self._pending.values():
                pending.value = _CANCELLED
                pending.event.set()
            self._callbacks.clear()
        if ids:
            self._bus.emit("modal.cancel", {"ids": ids})
