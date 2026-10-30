"""Unlock backoff, profile chips and the locked subtitle: pure unlock-screen logic."""
from __future__ import annotations

import math
import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass

from ..vault import UnlockThrottled
from ..i18n import t


def backoff_seconds_from_error(error: BaseException | None) -> float:
    """Seconds the unlock dialog must wait, taken only from a throttling error."""
    if isinstance(error, UnlockThrottled):
        return max(0.0, float(error.retry_after))
    return 0.0


class UnlockBackoff:
    """Monotonic countdown shown while master-password attempts are throttled.

    A new wait never shortens one that is already running, so a stale or
    smaller ``retry_after`` cannot unlock the button early.
    """

    def __init__(self, clock: Callable[[], float] = time.monotonic) -> None:
        self._clock = clock
        self._until = clock()

    def start(self, seconds: float) -> None:
        self._until = max(self._until, self._clock() + max(0.0, float(seconds)))

    def remaining(self) -> float:
        return max(0.0, self._until - self._clock())

    def message(self) -> str:
        remaining = self.remaining()
        if remaining <= 0:
            return ""
        return t("unlockBackoff.tooManyIncorrectAttemptsTry", v1=math.ceil(remaining))


@dataclass(frozen=True)
class ProfileChip:
    profile_id: str
    name: str
    initial: str
    active: bool


def _display_name(value: str, limit: int = 24) -> str:
    text = "".join(c for c in str(value) if c.isprintable()).strip()
    return text[:limit] + ("…" if len(text) > limit else "")


def profile_chips(profiles: Sequence[tuple[str, str]], active_id: str | None) -> list[ProfileChip]:
    """One chip per profile for the unlock screen; names are shortened and made printable."""
    chips = []
    for profile_id, name in profiles:
        shown = _display_name(name) or "Profile"
        initial = next((c.upper() for c in shown if c.isalnum()), "?")
        chips.append(ProfileChip(str(profile_id), shown, initial, str(profile_id) == str(active_id)))
    return chips


def locked_subtitle(locked_at: float | None, now: float | None = None) -> str:
    """The line under the unlock title: "Locked 12 minutes ago", or a plain one before any lock."""
    if locked_at is None:
        return t("unlockBackoff.yourVaultIsLocked")
    from ..shell.overview_model import age_text

    now = time.time() if now is None else now
    return f"Locked {age_text(max(0.0, now - float(locked_at)))}"
