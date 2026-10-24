"""Change the master password from the WebView UI, following ``FeatureUI.change_master_clicked``.

The page collects every field in one form and submits it once; the
confirmation goes through ``UiPort.confirm`` with the Tk text.
"""
from __future__ import annotations

from typing import Any

from ..api.result import ApiError
from ..secret_text import SecretText, secrets_match
from ..unlock_policy import require_master_unlock
from ..vault import VaultError

CONFIRM_TITLE = "Change master password?"
CONFIRM_TEXT = ("The vault will be re-encrypted with a new key. Old .lgk exports and backups will no longer open the "
                "current vault; they keep their old contents under the old master password, so protect or replace "
                "them. The current vault will lock after the change.")
LOCK_REASON = ("Master password changed. Camera verification and Windows Hello must be set up again; unlock with "
               "the new password.")
PHRASE_NOTE = {"title": "Create a new recovery phrase",
               "text": "Your previous recovery phrase no longer opens this vault. After unlocking, create a new one "
                       "in Recovery."}
CLEANUP_NOTE = {"title": "Old local unlock cleanup incomplete",
                "text": "The current vault has been re-encrypted and previous biometric unlock bindings are invalid. "
                        "Some old encrypted local key material could not be removed. Older backup copies may still "
                        "use their old key; keep those backups protected."}


class MasterService:
    def __init__(self, controller: Any, port: Any) -> None:
        self._controller = controller
        self._port = port

    def _session_lease(self) -> tuple[Any, Any]:
        if not self._controller.is_unlocked():
            raise ApiError("locked", "Unlock this profile first.")
        lease = self._controller.guard.lease()
        self._controller.require_lease(lease)
        return self._controller.session, lease

    def info(self) -> dict[str, Any]:
        session, _lease = self._session_lease()
        return {"needs_phrase": bool(session.has_recovery_phrase())}

    def change(self, current: str | SecretText, new: str | SecretText, confirm: str | SecretText,
               phrase: str | None) -> dict[str, Any]:
        """The passwords stay the caller's: the bridge wipes them once this returns, never kept here."""
        from ..face_unlock import cleanup_after_password_change as cleanup_face
        from ..hello_unlock import cleanup_after_password_change as cleanup_hello

        session, lease = self._session_lease()
        if not secrets_match(new, confirm):
            raise ApiError("invalid", "The new passwords did not match.")
        phrase = (phrase or "").strip() or None
        if not self._port.confirm(CONFIRM_TITLE, CONFIRM_TEXT):
            raise ApiError("cancelled", "Cancelled.")
        self._controller.require_lease(lease)
        profile_id = self._controller.profiles.active_profile().id
        record_id = session.hello_binding()
        had_face = bool(session.face_binding())
        vault_path = session.path
        try:
            result = session.change_master_password(current, new, recovery_phrase=phrase)
        except VaultError as exc:
            raise ApiError("invalid", str(exc)) from None
        require_master_unlock(profile_id)
        hello_cleaned = cleanup_hello(vault_path, record_id)
        face_cleaned = cleanup_face(vault_path) if had_face else True
        self._controller.lock(LOCK_REASON)
        notes = []
        if result.get("recovery_phrase_invalidated"):
            notes.append(dict(PHRASE_NOTE))
        if not hello_cleaned or not face_cleaned:
            notes.append(dict(CLEANUP_NOTE))
        return {"notes": notes}
