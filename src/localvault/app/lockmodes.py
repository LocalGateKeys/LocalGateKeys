"""Emergency lock and lock & switch person, following ``RuntimeActions``."""
from __future__ import annotations

from typing import Any

from ..unlock_policy import require_master_unlock

EMERGENCY = "Emergency lock. Master password required; signed-in websites/apps remain signed in."
HANDOVER = "Handover: sign out of websites and desktop apps separately before changing person."


class LockModes:
    def __init__(self, controller: Any) -> None:
        self._controller = controller

    def emergency_lock(self) -> dict[str, Any]:
        profile = self._controller.profiles.active_profile()
        if profile is not None:
            # Persisted so exit + relaunch cannot bring Windows Hello / camera back.
            require_master_unlock(profile.id)
        return self._controller.lock(EMERGENCY)

    def lock_and_switch(self) -> dict[str, Any]:
        profile = self._controller.profiles.active_profile()
        if profile is not None:
            require_master_unlock(profile.id)
        self._controller.handover = True
        try:
            return self._controller.lock(HANDOVER)
        except BaseException:
            self._controller.handover = False
            raise
