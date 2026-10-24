"""Test-only host pieces for exercising the real browser broker without a UI.

The Tk agent supplied these through ``RuntimeActions`` and the Tk dialogs; the WebView host
(``localvault.web.host.WebAgentHost``) supplies them in the app. Tests patch the prompt functions
below (``broker_host.confirm`` and friends), which ``ShimPort`` looks up at call time.
"""
from __future__ import annotations

import time
from typing import Any

from localvault.secret_text import SecretText
from localvault.session_guard import Lease, StaleSession


def confirm(parent: Any, title: str, message: str) -> bool:
    return False  # an unanswered approval never approves


def ask_string(title: str, message: str, **_kw: Any) -> str | None:
    return None


def show_error(parent: Any, title: str, message: str) -> None:
    pass


def show_info(parent: Any, title: str, message: str) -> None:
    pass


class ShimPort:
    """A ``UiPort`` whose prompts call the patchable module functions above."""

    def __init__(self, host: Any) -> None:
        self._host = host

    def confirm(self, title: str, message: str) -> bool:
        import broker_host

        return bool(broker_host.confirm(None, title, message))

    def notify(self, kind: str, title: str, message: str) -> None:
        import broker_host

        (broker_host.show_error if kind == "error" else broker_host.show_info)(None, title, message)

    def ask_password(self, title: str, message: str) -> SecretText | None:
        import broker_host

        answer = broker_host.ask_string(title, message, show="*")
        return SecretText.from_str(answer) if isinstance(answer, str) and answer else None

    def ask_passkey(self, mode: str, **kw: Any) -> tuple[str, str | None]:
        return ("cancel", None)

    def show_upgrade(self, *, limit: int, message: str, on_enter: Any) -> None:
        self.notify("info", "LocalGateKeys", message)


class BrokerHostBase:
    """Lease checks as the app host does them, plus a prompt port tests can steer."""

    @property
    def ui(self) -> ShimPort:
        port = self.__dict__.get("_ui")
        if port is None:
            port = self.__dict__["_ui"] = ShimPort(self)
        return port

    @ui.setter
    def ui(self, port: Any) -> None:
        self.__dict__["_ui"] = port

    def require_lease(self, lease: Lease) -> None:
        self.guard.require(lease)
        if not self.session or not self.session.is_unlocked:
            raise StaleSession("Vault is locked")
        timeout = self.settings.auto_lock_seconds
        last = getattr(self, "last_secret_use", 0)
        if timeout and last and time.monotonic() - last >= timeout:
            raise StaleSession("Inactivity timeout reached")
