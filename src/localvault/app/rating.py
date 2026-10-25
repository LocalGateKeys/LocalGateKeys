"""Rating LocalGateKeys on the Microsoft Store: the Settings row and the one-time prompt.

Only Store builds offer it: the review page is found by the running package's
family name, so no Store product id is stored. Opening it hands off to the
Store app; LocalGateKeys itself sends nothing. The prompt appears once, at the
first unlock from the third on, and never in strict offline mode (the Settings
row still works there, because the user asks for it).
"""
from __future__ import annotations

import os
import re
import threading
from typing import Any, Callable

from .. import distribution
from ..api.result import ApiError
from ..settings import UNLOCK_COUNT_CAP

PROMPT_AFTER_UNLOCKS = 3
PROMPT_TITLE = "Enjoying LocalGateKeys?"
PROMPT_TEXT = ("A rating on the Microsoft Store helps other people find LocalGateKeys.\n\nRate it now? This opens "
               "the Microsoft Store app. LocalGateKeys sends nothing, and won't ask again.")
_FAMILY_NAME = re.compile(r"^[A-Za-z0-9.\-]{3,50}_[a-z0-9]{13}$")


def review_uri(family_name: str | None) -> str | None:
    if not family_name or not _FAMILY_NAME.match(family_name):
        return None
    return f"ms-windows-store://review/?PFN={family_name}"


def available() -> bool:
    return distribution.is_store_build() and review_uri(distribution.package_family_name()) is not None


class RatingService:
    def __init__(self, controller: Any, *, opener: Callable[[str], None] | None = None,
                 is_available: Callable[[], bool] = available) -> None:
        self._controller = controller
        self._opener = opener or getattr(os, "startfile", None)
        self._available = is_available
        self._lock = threading.Lock()
        controller.on_unlock.append(self.count_unlock)

    def _save(self) -> None:
        try:
            self._controller.settings.save()
        except OSError:
            pass  # a lost count only delays the prompt

    def count_unlock(self) -> None:
        with self._lock:
            settings = self._controller.settings
            if settings.unlock_count < UNLOCK_COUNT_CAP:
                settings.unlock_count += 1
                self._save()

    def prompt(self) -> dict[str, Any]:
        """After unlock: is the one-time rating prompt due? Uses no network."""
        settings = self._controller.settings
        if (settings.rate_prompt_answered or settings.unlock_count < PROMPT_AFTER_UNLOCKS
                or bool(getattr(settings, "strict_offline_mode", True)) or not self._available()):
            return {"due": False}
        return {"due": True, "title": PROMPT_TITLE, "text": PROMPT_TEXT}

    def answer(self, rate: bool) -> dict[str, Any]:
        with self._lock:
            self._controller.settings.rate_prompt_answered = True
            self._save()
        return self.open() if rate else {}

    def open(self) -> dict[str, Any]:
        uri = review_uri(distribution.package_family_name()) if self._available() else None
        if uri is None or self._opener is None:
            raise ApiError("invalid", "Rating is available in the Microsoft Store version of LocalGateKeys.")
        try:
            self._opener(uri)
        except OSError:
            raise ApiError("invalid", "The Microsoft Store could not be opened.") from None
        return {}
