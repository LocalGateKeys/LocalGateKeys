"""Result shape of every bridge method: ``{"ok": True, ...}`` or ``{"ok": False, "error": {...}}``."""
from __future__ import annotations

import functools
from collections.abc import Callable
from typing import Any, TypeVar

F = TypeVar("F", bound=Callable[..., dict[str, Any]])

# Catalog keys of messages that send the user to the error log. The page offers an "Open error log" button
# for a failure or notice carrying ``error_log: true``; it never guesses from the (translated) wording.
ERROR_LOG_KEYS: tuple[str, ...] = (
    "error.internal",
    "controller.localgatekeysCouldNotReadOr",
    "connections.repairFailedDetailsAreIn",
    "schedule.scheduledBackupFailedThePrevious",
    "sync.syncCouldNotBeReset",
    "sync.syncCouldNotFinishThat",
    "sync.syncHitAnUnexpectedProblem",
    "sync.syncReportedAProblemDetails",
)


def points_to_error_log(text: object) -> bool:
    """Does this (already translated) text contain one of the messages that point at the error log?"""
    from ..i18n import t

    value = str(text or "")
    return bool(value) and any(t(key) in value for key in ERROR_LOG_KEYS)


class ApiError(Exception):
    """Raised inside a bridge method to return a user-facing failure."""

    def __init__(self, code: str, message: str, *, fix: dict[str, Any] | None = None,
                 error_log: bool | None = None) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        # True when the message tells the user to look in the error log (the page then offers a button).
        self.error_log = points_to_error_log(message) if error_log is None else bool(error_log)
        # The setting that would allow this: {"section", "key"?, "value"?, "label"?}. The page offers a
        # button that turns it on (when "key" is given) and one that opens that Settings section.
        self.fix = fix


def ok(**fields: Any) -> dict[str, Any]:
    return {"ok": True, **fields}


def fail(code: str, message: str, fix: dict[str, Any] | None = None, error_log: bool = False) -> dict[str, Any]:
    error: dict[str, Any] = {"code": code, "message": message}
    if fix:
        error["fix"] = fix
    if error_log:
        error["error_log"] = True
    return {"ok": False, "error": error}


def guarded(fn: F) -> F:
    """Never let an exception (or its text) reach the page."""

    @functools.wraps(fn)
    def wrapper(*args: Any, **kwargs: Any) -> dict[str, Any]:
        try:
            return fn(*args, **kwargs)
        except ApiError as exc:
            return fail(exc.code, exc.message, exc.fix, exc.error_log)
        except Exception as exc:  # noqa: BLE001 - mapped to a generic, logged failure
            try:
                from .. import error_log

                error_log.log_exception("api", exc)
            except Exception:  # noqa: BLE001, S110 - logging must not break the reply
                pass
            from ..i18n import t

            return fail("internal", t("error.internal"), error_log=True)

    return wrapper  # type: ignore[return-value]
