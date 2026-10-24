"""Windows Hello and camera verification for the WebView UI.

Follows ``auth_ui.show_hello_settings``, ``face_ui`` and the unlock paths in
``RuntimeActions``. Both are optional conveniences: they are refused while the
master-password marker is set (emergency lock, password change), and unlocking
with them never clears that marker. pywebview runs each bridge call on its own
worker thread, so a Windows Security prompt or a camera loop simply blocks that
call; Windows Hello runs on a further thread so a hung prompt times out.
"""
from __future__ import annotations

import sys
import threading
from pathlib import Path
from typing import Any, Callable

from .. import face_unlock, hello_unlock
from ..api.result import ApiError
from ..unlock_policy import master_unlock_required
from ..vault import InvalidMasterPassword, VaultError

NO_WINDOW = "A visible LocalGateKeys window is required for Windows Hello."
HELLO_TIMEOUT = 65
HELLO_ENABLED = "Enabled for this profile."
HELLO_INCOMPLETE = "Previous setup is incomplete. Remove it, then enroll again. Your master password still works."
HELLO_OFF = "Not enabled. Password entry remains the default; Windows Hello never starts automatically."
HELLO_UNSUPPORTED = "Windows Hello requires Windows. Master-password unlocking is unchanged."
HELLO_GUIDANCE = (
    "Windows Hello uses the methods enabled for your Windows account: face, fingerprint, or PIN. It is not "
    "face-only access.\n\nLocalGateKeys keeps an encrypted unlock key for this profile. It does not store your "
    "Windows password or biometric data. Keep your master password for recovery and sensitive changes.\n\n"
    "Setup asks you to confirm your master password, then Windows Security verifies enrollment. Face "
    "verification requires a compatible infrared camera.")
HELLO_CONFIRM = ("Anyone who can verify with this Windows account's Hello face, fingerprint or PIN will be able to "
                 "unlock this profile. No biometric data is sent by LocalGateKeys. Your master password remains "
                 "available. Enable this optional method?")
HELLO_OFFER_TITLE = "Unlock faster next time?"
HELLO_OFFER_TEXT = ("Use Windows Hello (face, fingerprint or PIN) to unlock LocalGateKeys, including when the browser "
                    "asks to save or fill a login.\n\nYour master password keeps working, and you can turn this off "
                    "in Settings › Unlocking.")
FACE_SETUP_MISSING = ("Camera verification is not set up for this profile, or its setup is damaged. Unlock with your "
                      "master password; Unlocking settings open next so you can set it up again.")
FACE_ENABLED = "Enabled for this profile. Master-password entry remains the default unlock method."
FACE_DAMAGED = ("The encrypted vault still authorizes camera verification, but its device-local sidecar is missing "
                "or damaged. Remove it and enroll again; the master password still works.")
FACE_OFF = "Not enabled. The camera starts only after you explicitly choose setup or Use camera."
FACE_UNSUPPORTED = "This compatibility route currently requires the Windows desktop app."
FACE_CONFIRM = ("This is a convenience unlock method, not hardware-backed authentication. It uses local face "
                "matching and a passive liveness check. While it is on, this vault is only as strong as your "
                "Windows account password: anyone who can sign in to this Windows account, or who has its password "
                "and a copy of this PC's user files, can open the vault without your master password. Keep your "
                "master password and do not enable it on an untrusted shared Windows account. Continue?")
FACE_DISABLE_CONFIRM = ("This revokes camera unlocking for this profile. Your master password and "
                        "Windows Hello, if configured, are unchanged.")
FACE_DISABLE_ROTATE_CONFIRM = ("This revokes camera unlocking for this profile and re-encrypts the vault under a new "
                               "key, so no earlier copy of the camera setup can open it. Your master password is "
                               "unchanged. Windows Hello, if configured, must be set up again.")
FACE_DISABLE_NEW_PHRASE_CONFIRM = ("This revokes camera unlocking for this profile and re-encrypts the vault under a "
                                   "new key, so no earlier copy of the camera setup can open it. Your recovery "
                                   "phrase is replaced: the old phrase stops working and a new one is shown once. "
                                   "Your master password is unchanged. Windows Hello, if configured, must be set up "
                                   "again.")
FACE_DISABLE_NEW_PHRASE_NOTE = "Your old recovery phrase no longer works. Write down the new one shown below."
MASTER_REQUIRED = ("Use your master password this time. Windows Hello and camera verification stay off until a "
                   "master-password unlock.")


def hello_supported() -> bool:
    try:
        from ..windows_hello import WindowsHello

        return bool(WindowsHello.supported_platform())
    except Exception:  # noqa: BLE001 - only decides whether the option is shown
        return False


def face_supported() -> bool:
    return sys.platform == "win32"


def _clean(exc: BaseException) -> BaseException:
    exc.__traceback__ = None  # never keep frames that held keys or passwords
    return exc


def run_with_timeout(action: Callable[[threading.Event], Any], dispose: Callable[[Any], None],
                     timeout: float, *, finished: Callable[[], None] = lambda: None) -> Any:
    """Run ``action(cancelled)`` on its own thread; a late result after a timeout is disposed of.

    ``finished`` runs on the worker once the action has really returned, even after a timeout,
    so a hung Windows Security prompt keeps new prompts out until it closes. An error raised
    after a timeout is dropped: there is nothing to dispose of and no caller left to tell.
    """
    box: dict[str, Any] = {}
    done = threading.Event()
    cancelled = threading.Event()
    lock = threading.Lock()

    def work() -> None:
        value = None
        try:
            value = action(cancelled)
        except BaseException as exc:  # noqa: BLE001 - re-raised on the caller's thread
            box["error"] = _clean(exc)
        finally:
            finished()
        with lock:
            if cancelled.is_set():
                if value is not None:
                    dispose(value)
                return
            box["value"] = value
            done.set()

    threading.Thread(target=work, daemon=True, name="lgk-hello").start()
    if not done.wait(timeout):
        with lock:
            if not done.is_set():
                cancelled.set()
                raise TimeoutError
    if "error" in box:
        raise box["error"]
    return box.get("value")


class _Methods:
    def __init__(self, controller: Any, port: Any) -> None:
        from .secrets import SecretService

        self._controller = controller
        self._port = port
        self._auth = SecretService(controller, port)

    def _profile(self) -> Any:
        profile = self._controller.profiles.active_profile()
        if profile is None:
            raise ApiError("no_profile", "Choose a profile first.")
        return profile

    def _path(self, profile: Any) -> Path:
        return self._controller.profiles.vault_path(profile.id)

    def _session_lease(self) -> tuple[Any, Any]:
        if not self._controller.is_unlocked():
            raise ApiError("locked", "Unlock this profile first.")
        lease = self._controller.guard.lease()
        self._controller.require_lease(lease)
        return self._controller.session, lease

    def _alternatives_allowed(self, profile: Any) -> bool:
        try:
            return not master_unlock_required(profile.id)
        except Exception:  # noqa: BLE001 - fail closed
            return False


class HelloService(_Methods):
    def __init__(self, controller: Any, port: Any, *, hwnd: Callable[[], int | None],
                 timeout: float = HELLO_TIMEOUT) -> None:
        super().__init__(controller, port)
        self._hwnd = hwnd
        self._timeout = timeout
        self._busy = threading.Lock()
        controller.offers["hello"] = self.offered

    def _window(self) -> int:
        handle = self._hwnd()
        if not handle:
            raise ApiError("no_window", NO_WINDOW)
        return int(handle)

    def offered(self) -> bool:
        """Whether the unlock screen shows "Unlock with Windows Hello" for the active profile."""
        try:
            profile = self._profile()
            return (hello_supported() and self._alternatives_allowed(profile)
                    and bool(hello_unlock.has_envelope(self._path(profile), profile.id)))
        except Exception:  # noqa: BLE001
            return False

    def status(self) -> dict[str, Any]:
        if not hello_supported():
            return {"supported": False, "enabled": False, "status": HELLO_UNSUPPORTED, "tone": "neutral",
                    "guidance": HELLO_GUIDANCE}
        session, _lease = self._session_lease()
        profile = self._profile()
        bound = bool(session.hello_binding())
        envelope = bool(hello_unlock.has_envelope(self._path(profile), profile.id))
        if bound and envelope:
            status, tone = HELLO_ENABLED, "success"
        elif bound or envelope:
            status, tone = HELLO_INCOMPLETE, "danger"
        else:
            status, tone = HELLO_OFF, "neutral"
        return {"supported": True, "enabled": bound and envelope, "incomplete": bound != envelope,
                "status": status, "tone": tone, "guidance": HELLO_GUIDANCE,
                "auto_start": bool(self._controller.settings.hello_auto_start)}

    def enable(self) -> dict[str, Any]:
        if not hello_supported():
            raise ApiError("unsupported", HELLO_UNSUPPORTED)
        session, lease = self._session_lease()
        self._auth.reauthenticate("Authorize Windows Hello setup", lease)
        if not self._port.confirm("Enable local Windows Hello?", HELLO_CONFIRM):
            raise ApiError("cancelled", "Setup cancelled. Your master-password access has not changed.")
        hwnd = self._window()
        profile = self._profile()
        context = session.unlock_context()
        if not self._busy.acquire(blocking=False):
            raise ApiError("busy", "Windows Hello is already open. Finish or cancel that prompt first.")
        try:
            prepared = run_with_timeout(
                lambda cancelled: hello_unlock.prepare_enrollment(profile.id, context, hwnd, cancelled),
                lambda late: late.discard(), self._timeout, finished=self._busy.release)
        except TimeoutError:
            raise ApiError("timeout", "Setup timed out. Cancel any Windows Security prompt before retrying. "
                                      "No unlock key was saved by this attempt.") from None
        except Exception as exc:  # noqa: BLE001 - HelloError, VaultError: shown as-is
            from ..windows_hello import HelloCancelled

            if isinstance(exc, HelloCancelled):
                raise ApiError("cancelled", "Setup cancelled. Your master-password access has not changed.") from None
            raise ApiError("hello_failed", str(exc) or "Windows Hello setup failed.") from None
        try:
            self._controller.require_lease(lease)
            hello_unlock.commit_enrollment(session, prepared)
        except Exception as exc:
            prepared.discard()
            raise ApiError("hello_failed", str(exc) or "Windows Hello setup failed.") from None
        self._controller.touch()
        self._controller._extras_cache = None
        return {"message": "Windows Hello is enabled. Lock the vault and choose Windows Hello to test it. "
                           "Typing the master password is still the default."}

    def disable(self) -> dict[str, Any]:
        session, lease = self._session_lease()
        self._auth.reauthenticate("Remove Windows Hello from this profile", lease)
        self._controller.require_lease(lease)
        try:
            hello_unlock.disable_enrollment(session)
        except Exception as exc:  # noqa: BLE001
            raise ApiError("hello_failed", str(exc) or "Windows Hello could not be removed.") from None
        self._controller.touch()
        self._controller._extras_cache = None
        return {"message": "Removed for this profile. Your Windows Hello enrollment was not changed."}

    def set_auto_start(self, value: bool) -> dict[str, Any]:
        self._session_lease()
        settings = self._controller.settings
        settings.hello_auto_start = bool(value)
        settings.save()
        return {"auto_start": settings.hello_auto_start}

    def _verify(self, path: Path, profile_id: str, **kwargs: Any) -> Any:
        hwnd = self._window()
        if not self._busy.acquire(blocking=False):
            raise ApiError("busy", "Windows Hello is already open. Finish or cancel that prompt first.")
        return run_with_timeout(
            lambda cancelled: hello_unlock.unlock_with_hello(path, profile_id, hwnd, cancelled, **kwargs),
            lambda late: late.lock(), self._timeout, finished=self._busy.release)

    def unlock(self) -> dict[str, Any]:
        from ..windows_hello import HelloCancelled

        profile = self._profile()
        if not self._alternatives_allowed(profile):
            raise ApiError("master_required", MASTER_REQUIRED)
        controller = self._controller

        def build(path: Path, backup_dir: Path, backup_count: int) -> Any:
            try:
                return self._verify(path, profile.id, backup_dir=backup_dir, backup_count=backup_count)
            except ApiError:
                raise
            except TimeoutError:
                raise ApiError("timeout", "The request timed out. Cancel any Windows Security prompt and use your "
                                          "master password.") from None
            except HelloCancelled:
                raise ApiError("cancelled", "Unlock cancelled. Try again or use your master password.") from None
            except Exception as exc:  # noqa: BLE001
                text = str(exc)
                if not text:
                    raise ApiError("cancelled", "Unlock cancelled. Try again or use your master password.") from None
                raise ApiError("hello_failed", f"{text} You can retry or use your master password.") from None

        return controller.unlock_alternative(build)

    def reauthenticate(self, title: str, lease: Any) -> bool:
        """Routine re-authentication with Windows Hello; False means "ask for the master password"."""
        try:
            profile = self._profile()
            if not self.offered():
                return False
            session = self._verify(self._path(profile), profile.id)
        except Exception:  # noqa: BLE001 - every failure falls back to the master password
            return False
        try:
            session.lock()
        except Exception:  # noqa: BLE001, S110
            pass
        try:
            self._controller.require_lease(lease)
        except Exception:  # noqa: BLE001
            return False
        return True

    # --------------------------------------------------------------- offer
    def offer(self) -> dict[str, Any]:
        settings = self._controller.settings
        if settings.hello_offer_answered or not hello_supported() or not self._controller.is_unlocked():
            return {"offer": False}
        profile = self._profile()
        if hello_unlock.has_envelope(self._path(profile), profile.id):
            return {"offer": False}
        return {"offer": True, "title": HELLO_OFFER_TITLE, "text": HELLO_OFFER_TEXT}

    def answer_offer(self, accepted: bool) -> dict[str, Any]:
        settings = self._controller.settings
        settings.hello_offer_answered = True
        settings.save()
        return {"accepted": bool(accepted)}


class FaceService(_Methods):
    def __init__(self, controller: Any, port: Any, bus: Any, *, capture_factory: Any = None,
                 engine_factory: Callable[[], Any] | None = None) -> None:
        super().__init__(controller, port)
        if capture_factory is None:
            from .face_capture import FaceCapture as capture_factory
        if engine_factory is None:
            from ..face_models import FaceEngine as engine_factory
        self._bus = bus
        self._capture_factory = capture_factory
        self._engine_factory = engine_factory
        self._busy = threading.Lock()
        self._active: Any = None
        self._cancel_lock = threading.Lock()
        self._cancel_requested = False
        controller.on_lock.append(self.cancel)
        controller.offers["camera"] = self.offered

    def offered(self) -> bool:
        try:
            profile = self._profile()
            return (face_supported() and self._alternatives_allowed(profile)
                    and bool(face_unlock.has_envelope(self._path(profile), profile.id)))
        except Exception:  # noqa: BLE001
            return False

    def status(self) -> dict[str, Any]:
        if not face_supported():
            return {"supported": False, "enabled": False, "status": FACE_UNSUPPORTED, "tone": "neutral"}
        session, _lease = self._session_lease()
        profile = self._profile()
        bound = bool(session.face_binding())
        envelope = bool(face_unlock.has_envelope(self._path(profile), profile.id))
        if bound and envelope:
            status, tone = FACE_ENABLED, "success"
        elif bound:
            status, tone = FACE_DAMAGED, "danger"
        else:
            status, tone = FACE_OFF, "neutral"
        return {"supported": True, "enabled": bound and envelope, "incomplete": bound and not envelope,
                "status": status, "tone": tone}

    def _capture(self, mode: str, **kwargs: Any) -> Any:
        if not self._busy.acquire(blocking=False):
            raise ApiError("busy", "The camera is already in use. Finish or cancel that check first.")
        try:
            with self._cancel_lock:
                self._cancel_requested = False
            capture = self._capture_factory(mode, engine_factory=self._engine_factory, emit=self._bus.emit, **kwargs)
            with self._cancel_lock:
                self._active = capture
                if self._cancel_requested:
                    capture.cancel()
            return capture.run()
        finally:
            with self._cancel_lock:
                self._active = None
            self._busy.release()

    def cancel(self) -> dict[str, Any]:
        with self._cancel_lock:
            self._cancel_requested = True
            active = self._active
        if active is not None:
            active.cancel()
        return {}

    def switch_camera(self) -> dict[str, Any]:
        active = self._active
        if active is not None and hasattr(active, "switch_camera"):
            active.switch_camera()
        return {}

    def enable(self) -> dict[str, Any]:
        if not face_supported():
            raise ApiError("unsupported", FACE_UNSUPPORTED)
        session, lease = self._session_lease()
        self._auth.reauthenticate("Authorize camera verification setup", lease)
        if not self._port.confirm("Enable ordinary-webcam verification?", FACE_CONFIRM):
            raise ApiError("cancelled", "Cancelled.")
        profile = self._profile()
        samples: list[list[float]] = []
        try:
            samples = self._capture("enroll")
            self._controller.require_lease(lease)
            prepared = face_unlock.prepare_enrollment(profile.id, session.unlock_context(), samples)
            face_unlock.commit_enrollment(session, prepared)
        except ApiError:
            raise
        except face_unlock.FaceError as exc:
            raise ApiError("cancelled" if isinstance(exc, face_unlock.FaceCancelled) else "face_failed",
                           str(exc)) from None
        except Exception as exc:  # noqa: BLE001
            raise ApiError("face_failed", str(exc) or "Camera verification could not be set up.") from None
        finally:
            for sample in samples or []:
                for index in range(len(sample)):
                    sample[index] = 0.0
        self._controller.touch()
        self._controller._extras_cache = None
        return {"message": "Camera verification enabled. Lock the vault and test it before relying on it."}

    def disable(self) -> dict[str, Any]:
        """Revoke camera unlock and, when it was set up, rotate the data key.

        The camera sidecar wraps the data key under Windows data protection
        only, so a copy of it taken while camera unlock was on would keep
        opening the vault.  The master password is asked here (not through
        ``reauthenticate``, which does not hand it over) because the rotation
        re-wraps the new key under it.
        """
        session, lease = self._session_lease()
        profile = self._profile()
        # The port hands over a SecretText this method owns: it is wiped however this ends.
        password = self._port.ask_password(
            "Remove camera verification", f"Profile: {profile.name}\nEnter the master password again:")
        try:
            self._controller.require_lease(lease)
            if password is None:
                raise ApiError("cancelled", "Cancelled.")
            try:
                session.verify_master_password(password)
            except (InvalidMasterPassword, VaultError):
                self._port.notify("error", "Not authorized", "Master password did not match, or the vault changed.")
                raise ApiError("not_authorized", "Master password did not match, or the vault changed.") from None
            self._controller.touch()
            # Rotating with a recovery phrase replaces the phrase too (L-4): the old phrase stops working.
            rotate = face_unlock.rotation_on_disable(session)
            new_phrase = rotate and session.has_recovery_phrase()
            hello_record = session.hello_binding() if rotate else ""
            text = (FACE_DISABLE_NEW_PHRASE_CONFIRM if new_phrase else
                    FACE_DISABLE_ROTATE_CONFIRM if rotate else FACE_DISABLE_CONFIRM)
            if not self._port.confirm("Remove camera verification?", text):
                raise ApiError("cancelled", "Cancelled.")
            self._controller.require_lease(lease)
            try:
                result = face_unlock.disable_enrollment(session, password if rotate else None)
            except Exception as exc:  # noqa: BLE001
                raise ApiError("face_failed", str(exc) or "Camera verification could not be removed.") from None
        finally:
            if password is not None:
                password.wipe()
        notes = []
        phrase = None
        phrase_notes: list[str] = []
        if result is not None:
            phrase = result.pop("new_recovery_phrase", None)
            if phrase:
                from .recovery_center import recovery_phrase_change_warnings

                notes.append(FACE_DISABLE_NEW_PHRASE_NOTE)
                phrase_notes = recovery_phrase_change_warnings(result)
            if hello_record:
                # The rotation revoked Windows Hello too; its OS key only wraps the retired data key.
                try:
                    hello_unlock.cleanup_after_password_change(session.path, hello_record)
                except Exception:  # noqa: BLE001, S110 - the revocation is committed; cleanup is best effort
                    pass
                notes.append("Set up Windows Hello again if you use it.")
        self._controller.touch()
        self._controller._extras_cache = None
        response: dict[str, Any] = {"message": " ".join(["Camera verification removed.", *notes])}
        if phrase:
            # Shown once by the page's recovery-phrase card (the bridge turns it into a card); never stored.
            response["new_recovery_phrase"] = phrase
            response["phrase_notes"] = phrase_notes
        return response

    def unlock(self) -> dict[str, Any]:
        profile = self._profile()
        if not self._alternatives_allowed(profile):
            raise ApiError("master_required", MASTER_REQUIRED)
        if self._busy.locked():
            raise ApiError("busy", "The camera is already in use. Finish or cancel that check first.")

        def build(path: Path, backup_dir: Path, backup_count: int) -> Any:
            try:
                material = face_unlock.load_face_material(path, profile.id)
            except face_unlock.FaceError:
                raise ApiError("face_setup", FACE_SETUP_MISSING) from None
            try:
                try:
                    self._capture("verify", templates=material.templates, threshold=material.threshold)
                except face_unlock.FaceCancelled as exc:
                    raise ApiError("cancelled", str(exc)) from None
                except face_unlock.FaceUnavailable as exc:
                    # No face was compared (no camera, stalled feed, missing models): not a failed match.
                    raise ApiError("face_unavailable", str(exc)) from None
                except face_unlock.FaceError as exc:
                    face_unlock.record_failure(material.record_id)
                    raise ApiError("face_failed", str(exc) or "Camera verification was not accepted. Use your "
                                                              "master password.") from None
                return face_unlock.unlock_verified_face(material, backup_dir=backup_dir, backup_count=backup_count)
            finally:
                material.discard()

        return self._controller.unlock_alternative(build)
