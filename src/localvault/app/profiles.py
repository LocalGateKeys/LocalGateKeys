"""Profiles for the WebView UI: list, add, edit, photo, remove (``profile_ui`` / ``agent.profiles_clicked`` without Tk)."""
from __future__ import annotations

from typing import Any

from ..api.result import ApiError
from ..profiles import CAMERA_UNLOCK_BLOCKS_DELETE, ProfileError

REMOVE_TEXT = ("Remove {name!r} from LocalGateKeys?\n\nIts encrypted data will be moved to the local DeletedProfiles "
               "archive rather than erased immediately.")
HANDOVER_NOTE = ("Locking LocalGateKeys does not sign out websites or apps. Sign out of them separately before handing "
                 "over this computer.")
INTRO = ("Select a LocalGateKeys profile. Each person gets a separate encrypted vault, settings, backups, and trusted "
         "app bindings.")


def initials(name: str) -> str:
    words = [w for w in str(name).split() if w[:1].isalnum()]
    if not words:
        return "?"
    return (words[0][0] + (words[1][0] if len(words) > 1 else "")).upper()


class ProfilesService:
    def __init__(self, controller: Any, port: Any, dialogs: Any) -> None:
        self._controller = controller
        self._port = port
        self._dialogs = dialogs

    def _unlocked(self) -> None:
        """Changes to existing profiles are made from an unlocked vault (the lock screen only chooses or adds one)."""
        if not self._controller.is_unlocked():
            raise ApiError("locked", "Unlock this profile first.")
        self._controller.require_lease(self._controller.guard.lease())

    def _refresh(self) -> None:
        self._controller._extras_cache = None
        self._controller._publish()

    @property
    def _profiles(self) -> Any:
        return self._controller.profiles

    def _row(self, record: Any, active_id: str | None) -> dict[str, Any]:
        return {"id": record.id, "name": record.name, "color": record.color, "initials": initials(record.name),
                "active": record.id == active_id, "last_used_at": int(record.last_used_at or 0),
                "photo": f"data:image/png;base64,{record.photo_data}" if record.photo_data else ""}

    def list(self) -> dict[str, Any]:
        active = self._profiles.active_profile()
        active_id = active.id if active else None
        return {"profiles": [self._row(p, active_id) for p in self._profiles.list_profiles()],
                "intro": INTRO, "note": HANDOVER_NOTE}

    def _find(self, profile_id: str) -> Any:
        record = next((p for p in self._profiles.list_profiles() if p.id == profile_id), None)
        if record is None:
            raise ApiError("not_found", "That profile no longer exists.")
        return record

    def create(self, name: str) -> dict[str, Any]:
        # Adding works from the lock screen too: a new profile is an empty vault and
        # opens no other profile's data. From an unlocked vault the lease still applies.
        if self._controller.is_unlocked():
            self._unlocked()
        try:
            record = self._profiles.create_profile(str(name))
        except (ProfileError, ValueError) as exc:
            raise ApiError("invalid", str(exc)) from None
        self._controller._extras_cache = None
        active = self._profiles.active_profile()
        return {"profile": self._row(record, active.id if active else None)}

    def update(self, profile_id: str, *, name: str | None = None, color: str | None = None) -> dict[str, Any]:
        self._unlocked()
        self._find(profile_id)
        try:
            record = self._profiles.update_profile(profile_id, name=name, color=color)
        except (ProfileError, ValueError) as exc:
            raise ApiError("invalid", str(exc)) from None
        self._controller._extras_cache = None
        self._controller._publish()
        return {"profile": self._row(record, getattr(self._profiles.active_profile(), "id", None)),
                "message": "Profile updated."}

    def photo(self, profile_id: str) -> dict[str, Any]:
        self._unlocked()
        self._find(profile_id)
        source = self._dialogs.open_file("Choose a profile photo")
        if not source:
            raise ApiError("cancelled", "No file was chosen.")
        try:
            record = self._profiles.set_profile_photo(profile_id, source)
        except (ProfileError, ValueError, OSError) as exc:
            raise ApiError("invalid", str(exc) or "That image could not be used.") from None
        return {"profile": self._row(record, getattr(self._profiles.active_profile(), "id", None))}

    def remove_photo(self, profile_id: str) -> dict[str, Any]:
        self._unlocked()
        self._find(profile_id)
        record = self._profiles.set_profile_photo(profile_id, None)
        return {"profile": self._row(record, getattr(self._profiles.active_profile(), "id", None))}

    def _refuse_camera_unlock(self, profile_id: str) -> None:
        if self._profiles.camera_unlock_blocks_delete(profile_id):
            raise ApiError("invalid", CAMERA_UNLOCK_BLOCKS_DELETE)

    def delete(self, profile_id: str) -> dict[str, Any]:
        self._unlocked()
        record = self._find(profile_id)
        if len(self._profiles.list_profiles()) <= 1:
            raise ApiError("invalid", "Create another profile before deleting the only profile")
        # delete_profile refuses a profile with camera unlock; say so before
        # asking, and above all before locking the vault for nothing.
        self._refuse_camera_unlock(profile_id)
        lease = self._controller.guard.lease()
        if not self._port.confirm("Remove profile", REMOVE_TEXT.format(name=record.name)):
            raise ApiError("cancelled", "Cancelled.")
        self._controller.require_lease(lease)  # locked or switched while the confirm was open
        self._refuse_camera_unlock(profile_id)
        active = self._profiles.active_profile()
        was_active = active is not None and active.id == profile_id
        if was_active:
            self._controller.lock("Profile removed. Vault locked.")
        try:
            try:
                self._profiles.delete_profile(profile_id)
            except (ProfileError, ValueError, OSError) as exc:
                raise ApiError("invalid", str(exc) or "The profile could not be removed.") from None
            if was_active:
                remaining = self._profiles.list_profiles()
                if remaining:
                    self._controller.select_profile(remaining[0].id)
        finally:
            # Whatever happened, the page must see the profiles and lock state as they now are.
            self._refresh()
        return {"message": f"Removed {record.name}."}
