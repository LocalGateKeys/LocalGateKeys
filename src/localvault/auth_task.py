"""Cancelable ownership transfer for local authentication worker results.

A native Windows prompt can outlive its parent dialog. Late decrypted sessions
must be destroyed rather than queued for another user/profile/window.
"""
from __future__ import annotations

import threading
from collections.abc import Callable
from typing import Generic, TypeVar

T = TypeVar("T")


class AuthTask(Generic[T]):
    def __init__(self, action: Callable[[threading.Event], T], dispose: Callable[[T], None]):
        self.cancelled = threading.Event()
        self._lock = threading.Lock()
        self._dispose = dispose
        self._ready = False
        self._value: T | None = None
        self._error: str | None = None
        self.thread = threading.Thread(target=self._run, args=(action,), daemon=True,
                                       name="LocalGateKeys-auth")
        self.thread.start()

    def _run(self, action: Callable[[threading.Event], T]) -> None:
        value: T | None = None
        error = None
        try:
            if not self.cancelled.is_set():
                value = action(self.cancelled)
        except Exception as exc:
            # Do not retain tracebacks/frames containing passwords or vault keys.
            from .vault import VaultError
            from .windows_hello import HelloError
            error = str(exc) if isinstance(exc, (HelloError, VaultError)) else (
                "Local authentication could not complete. Use your master password or retry.")
        finally:
            action = None
        with self._lock:
            if not self.cancelled.is_set():
                self._value, self._error, self._ready = value, error, True
                return
        if value is not None:
            self._dispose(value)

    def cancel(self) -> None:
        with self._lock:
            self.cancelled.set()
            value, self._value = self._value, None
            self._error = None
        if value is not None:
            self._dispose(value)

    def poll(self) -> tuple[bool, T | None, str | None]:
        with self._lock:
            if not self._ready or self.cancelled.is_set():
                return False, None, None
            value, error = self._value, self._error
            self._value = self._error = None
            self._ready = False
            return True, value, error
