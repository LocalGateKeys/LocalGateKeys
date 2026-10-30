"""Emergency lock and lock & switch person, following ``RuntimeActions``."""
from __future__ import annotations

from typing import Any

from ..unlock_policy import require_master_unlock
from ..i18n import t

EMERGENCY = "lockmodes.emergencyLockMasterPasswordRequired"
HANDOVER = "lockmodes.handoverSignOutOfWebsites"


class LockModes:
    def __init__(self, controller: Any) -> None:
        self._controller = controller

    def emergency_lock(self) -> dict[str, Any]:
        profile = self._controller.profiles.active_profile()
        if profile is not None:
            # Persisted so exit + relaunch cannot bring Windows Hello / camera back.
            require_master_unlock(profile.id)
        return self._controller.lock(t(EMERGENCY))

    def lock_and_switch(self) -> dict[str, Any]:
        profile = self._controller.profiles.active_profile()
        if profile is not None:
            require_master_unlock(profile.id)
        self._controller.handover = True
        try:
            return self._controller.lock(t(HANDOVER))
        except BaseException:
            self._controller.handover = False
            raise
