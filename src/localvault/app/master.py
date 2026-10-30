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
from ..i18n import t

CONFIRM_TITLE = "master.changeMasterPassword"
CONFIRM_TEXT = ("master.theVaultWillBeRe")
LOCK_REASON = ("master.masterPasswordChangedCameraVerification")
PHRASE_NOTE = {"title": "controller.createANewRecoveryPhrase",
               "text": "master.yourPreviousRecoveryPhraseNo"}
CLEANUP_NOTE = {"title": "controller.oldLocalUnlockCleanupIncomplete",
                "text": "master.theCurrentVaultHasBeen"}


class MasterService:
    def __init__(self, controller: Any, port: Any) -> None:
        self._controller = controller
        self._port = port

    def _session_lease(self) -> tuple[Any, Any]:
        if not self._controller.is_unlocked():
            raise ApiError("locked", t("error.lockedProfile"))
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
            raise ApiError("invalid", t("masterSheet.mismatch"))
        phrase = (phrase or "").strip() or None
        if not self._port.confirm(t(CONFIRM_TITLE), t(CONFIRM_TEXT)):
            raise ApiError("cancelled", t("error.cancelled"))
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
        self._controller.lock(t(LOCK_REASON))
        notes = []
        if result.get("recovery_phrase_invalidated"):
            notes.append(dict(PHRASE_NOTE))
        if not hello_cleaned or not face_cleaned:
            notes.append(dict(CLEANUP_NOTE))
        return {"notes": notes}
