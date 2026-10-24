"""The seam between application logic and whichever UI asks the user things.

Brokers, the item-limit gate and (later) the controller never import a UI
toolkit. They call a :class:`UiPort`; the Tk app plugs in ``TkUiPort`` and the
WebView app plugs in its own port. A port method may block the calling thread
until the user answers.
"""
from __future__ import annotations

from collections.abc import Callable
from typing import Any, Literal, Protocol

from ..secret_text import SecretText


class UiPort(Protocol):
    def confirm(self, title: str, message: str) -> bool: ...

    def notify(self, kind: Literal["info", "error"], title: str, message: str) -> None: ...

    def ask_passkey(self, mode: str, *, origin: str, rp_id: str, profile_name: str,
                    accounts: list[dict[str, Any]], excluded: bool) -> tuple[str, str | None]: ...

    def show_upgrade(self, *, limit: int, message: str, on_enter: Callable[[], None]) -> None: ...

    def ask_password(self, title: str, message: str) -> SecretText | None: ...


class UiPortHost:
    """Mixin giving ``self.ui``; the WebView host sets it before any prompt."""

    @property
    def ui(self) -> UiPort:
        port = self.__dict__.get("_ui")
        if port is None:
            raise RuntimeError("No UI port is attached to this host")
        return port

    @ui.setter
    def ui(self, port: UiPort) -> None:
        self.__dict__["_ui"] = port


def ui_port_of(host: Any) -> UiPort:
    """``host.ui``; every host the app builds has one."""
    port = getattr(host, "ui", None)
    if port is None:
        raise RuntimeError("No UI port is attached to this host")
    return port


def safe_confirm(port: UiPort, title: str, message: str) -> bool:
    """Ask for approval; any failure to get an answer (timeout, closed UI) is a denial."""
    try:
        return bool(port.confirm(title, message))
    except Exception as exc:  # noqa: BLE001 - an unanswered approval must never approve
        try:
            from .. import error_log

            error_log.log_exception("approval", exc)
        except Exception:  # noqa: BLE001, S110 - logging must not turn a denial into a crash
            pass
        return False
