"""Result shape of every bridge method: ``{"ok": True, ...}`` or ``{"ok": False, "error": {...}}``."""
from __future__ import annotations

import functools
from collections.abc import Callable
from typing import Any, TypeVar

F = TypeVar("F", bound=Callable[..., dict[str, Any]])

INTERNAL_MESSAGE = "Something went wrong. Details are in the error log."


class ApiError(Exception):
    """Raised inside a bridge method to return a user-facing failure."""

    def __init__(self, code: str, message: str, *, fix: dict[str, Any] | None = None) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        # The setting that would allow this: {"section", "key"?, "value"?, "label"?}. The page offers a
        # button that turns it on (when "key" is given) and one that opens that Settings section.
        self.fix = fix


def ok(**fields: Any) -> dict[str, Any]:
    return {"ok": True, **fields}


def fail(code: str, message: str, fix: dict[str, Any] | None = None) -> dict[str, Any]:
    error: dict[str, Any] = {"code": code, "message": message}
    if fix:
        error["fix"] = fix
    return {"ok": False, "error": error}


def guarded(fn: F) -> F:
    """Never let an exception (or its text) reach the page."""

    @functools.wraps(fn)
    def wrapper(*args: Any, **kwargs: Any) -> dict[str, Any]:
        try:
            return fn(*args, **kwargs)
        except ApiError as exc:
            return fail(exc.code, exc.message, exc.fix)
        except Exception as exc:  # noqa: BLE001 - mapped to a generic, logged failure
            try:
                from .. import error_log

                error_log.log_exception("api", exc)
            except Exception:  # noqa: BLE001, S110 - logging must not break the reply
                pass
            return fail("internal", INTERNAL_MESSAGE)

    return wrapper  # type: ignore[return-value]
