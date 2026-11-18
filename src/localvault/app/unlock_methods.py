"""Windows Hello, security key and camera verification for the WebView UI.

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

from .. import face_unlock, fido_unlock, hello_unlock
from ..duress import is_decoy
from ..api.result import ApiError
from ..unlock_policy import master_unlock_required
from ..vault import FactorMismatch, FactorRequired, InvalidMasterPassword, VaultError
from ..i18n import t

NO_WINDOW = "hello.error.windowRequired"
HELLO_TIMEOUT = 65
HELLO_ENABLED = "unlockMethods.enabledForThisProfile"
HELLO_INCOMPLETE = "unlockMethods.previousSetupIsIncompleteRemove"
HELLO_OFF = "unlockMethods.notEnabledPasswordEntryRemains"
HELLO_UNSUPPORTED = "unlockMethods.windowsHelloRequiresWindowsMaster"
HELLO_GUIDANCE = (
    "unlockMethods.windowsHelloUsesTheMethods")
HELLO_CONFIRM = ("unlockMethods.anyoneWhoCanVerifyWith")
HELLO_OFFER_TITLE = "unlockMethods.unlockFasterNextTime"
HELLO_OFFER_TEXT = ("unlockMethods.useWindowsHelloFaceFingerprint")
FACE_SETUP_MISSING = ("unlockMethods.cameraVerificationIsNotSet")
FACE_ENABLED = "unlockMethods.enabledForThisProfileMaster"
FACE_DAMAGED = ("unlockMethods.theEncryptedVaultStillAuthorizes")
FACE_OFF = "unlockMethods.notEnabledTheCameraStarts"
FACE_UNSUPPORTED = "unlockMethods.thisCompatibilityRouteCurrentlyRequires"
FACE_CONFIRM = ("unlockMethods.thisIsAConvenienceUnlock")
FACE_DISABLE_CONFIRM = ("unlockMethods.thisRevokesCameraUnlockingFor")
FACE_DISABLE_ROTATE_CONFIRM = ("unlockMethods.thisRevokesCameraUnlockingFor2")
FACE_DISABLE_NEW_PHRASE_CONFIRM = ("unlockMethods.thisRevokesCameraUnlockingFor3")
FACE_DISABLE_NEW_PHRASE_NOTE = "unlockMethods.yourOldRecoveryPhraseNo"
MASTER_REQUIRED = ("unlockMethods.useYourMasterPasswordThis")
# One Windows Security dialog closes itself after security_key.TIMEOUT_MS (60 s);
# setting up shows two (register, then a test read), so it gets twice the time.
SECURITY_KEY_TIMEOUT = HELLO_TIMEOUT
SECURITY_KEY_ENROLL_TIMEOUT = 2 * HELLO_TIMEOUT


def hello_supported() -> bool:
    try:
        from ..windows_hello import WindowsHello

        return bool(WindowsHello.supported_platform())
    except Exception:  # noqa: BLE001 - only decides whether the option is shown
        return False


def security_key_availability() -> tuple[bool, str]:
    try:
        from ..security_key import availability

        return availability()
    except Exception:  # noqa: BLE001 - only decides whether the option is shown
        return False, t("securityKey.error.componentUnavailable")


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
            raise ApiError("no_profile", t("recovery.chooseAProfileFirst"))
        return profile

    def _path(self, profile: Any) -> Path:
        # In a duress session this is the second vault's own file (the controller's profile paths follow it).
        return self._controller.profiles.vault_path(profile.id)

    def _refuse_in_duress(self) -> None:
        """No unlock shortcut is set up or removed from a duress session: they belong to this PC's profile."""
        if self._controller.is_unlocked() and is_decoy(self._controller.session):
            raise ApiError("unavailable", t("duress.err.unavailable"))

    def _session_lease(self) -> tuple[Any, Any]:
        if not self._controller.is_unlocked():
            raise ApiError("locked", t("error.lockedProfile"))
        lease = self._controller.guard.lease()
        self._controller.require_lease(lease)
        return self._controller.session, lease

    def _alternatives_allowed(self, profile: Any) -> bool:
        try:
            return not master_unlock_required(profile.id)
        except Exception:  # noqa: BLE001 - fail closed
            return False

    def _refuse_when_always_ask(self) -> None:
        """No new shortcut while "Always ask for the key file / YubiKey" is on for this vault (nor in a duress
        session)."""
        self._refuse_in_duress()
        blocked = getattr(self._controller, "shortcuts_blocked", None)
        if callable(blocked) and blocked():
            raise ApiError("always_ask", t("factors.shortcutsOff"))


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
            raise ApiError("no_window", t(NO_WINDOW))
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
            return {"supported": False, "enabled": False, "status": t(HELLO_UNSUPPORTED), "tone": "neutral",
                    "guidance": t(HELLO_GUIDANCE)}
        session, _lease = self._session_lease()
        profile = self._profile()
        bound = bool(session.hello_binding())
        envelope = bool(hello_unlock.has_envelope(self._path(profile), profile.id))
        if bound and envelope:
            status, tone = t(HELLO_ENABLED), "success"
        elif bound or envelope:
            status, tone = t(HELLO_INCOMPLETE), "danger"
        else:
            status, tone = t(HELLO_OFF), "neutral"
        return {"supported": True, "enabled": bound and envelope, "incomplete": bound != envelope,
                "status": status, "tone": tone, "guidance": t(HELLO_GUIDANCE),
                "auto_start": bool(self._controller.settings.hello_auto_start)}

    def enable(self) -> dict[str, Any]:
        if not hello_supported():
            raise ApiError("unsupported", t(HELLO_UNSUPPORTED))
        session, lease = self._session_lease()
        self._refuse_when_always_ask()
        self._auth.reauthenticate(t("unlockMethods.authorizeWindowsHelloSetup"), lease)
        if not self._port.confirm(t("unlockMethods.enableLocalWindowsHello"), t(HELLO_CONFIRM)):
            raise ApiError("cancelled_notice", t("unlockMethods.setupCancelledYourMasterPassword"))
        hwnd = self._window()
        profile = self._profile()
        context = session.unlock_context()
        if not self._busy.acquire(blocking=False):
            raise ApiError("busy", t("unlockMethods.windowsHelloIsAlreadyOpen"))
        try:
            prepared = run_with_timeout(
                lambda cancelled: hello_unlock.prepare_enrollment(profile.id, context, hwnd, cancelled),
                lambda late: late.discard(), self._timeout, finished=self._busy.release)
        except TimeoutError:
            raise ApiError("timeout", t("unlockMethods.setupTimedOutCancelAny")) from None
        except Exception as exc:  # noqa: BLE001 - HelloError, VaultError: shown as-is
            from ..windows_hello import HelloCancelled

            if isinstance(exc, HelloCancelled):
                raise ApiError("cancelled_notice", t("unlockMethods.setupCancelledYourMasterPassword")) from None
            raise ApiError("hello_failed", str(exc) or t("unlockMethods.windowsHelloSetupFailed")) from None
        try:
            self._controller.require_lease(lease)
            hello_unlock.commit_enrollment(session, prepared)
        except Exception as exc:
            prepared.discard()
            raise ApiError("hello_failed", str(exc) or t("unlockMethods.windowsHelloSetupFailed")) from None
        self._controller.touch()
        self._controller._extras_cache = None
        return {"message": t("unlockMethods.windowsHelloIsEnabledLock")}

    def disable(self) -> dict[str, Any]:
        self._refuse_in_duress()
        session, lease = self._session_lease()
        self._auth.reauthenticate(t("unlockMethods.removeWindowsHelloFromThis"), lease)
        self._controller.require_lease(lease)
        try:
            hello_unlock.disable_enrollment(session)
        except Exception as exc:  # noqa: BLE001
            raise ApiError("hello_failed", str(exc) or t("unlockMethods.windowsHelloCouldNotBe")) from None
        self._controller.touch()
        self._controller._extras_cache = None
        return {"message": t("unlockMethods.removedForThisProfileYour")}

    def set_auto_start(self, value: bool) -> dict[str, Any]:
        self._session_lease()
        settings = self._controller.settings
        settings.hello_auto_start = bool(value)
        settings.save()
        return {"auto_start": settings.hello_auto_start}

    def _verify(self, path: Path, profile_id: str, **kwargs: Any) -> Any:
        hwnd = self._window()
        if not self._busy.acquire(blocking=False):
            raise ApiError("busy", t("unlockMethods.windowsHelloIsAlreadyOpen"))
        return run_with_timeout(
            lambda cancelled: hello_unlock.unlock_with_hello(path, profile_id, hwnd, cancelled, **kwargs),
            lambda late: late.lock(), self._timeout, finished=self._busy.release)

    def unlock(self) -> dict[str, Any]:
        from ..windows_hello import HelloCancelled

        profile = self._profile()
        self._refuse_when_always_ask()  # the page offers nothing then; the server refuses too
        if not self._alternatives_allowed(profile):
            raise ApiError("master_required", t(MASTER_REQUIRED))
        controller = self._controller

        def build(path: Path, backup_dir: Path, backup_count: int) -> Any:
            try:
                return self._verify(path, profile.id, backup_dir=backup_dir, backup_count=backup_count)
            except ApiError:
                raise
            except TimeoutError:
                raise ApiError("timeout", t("unlockMethods.theRequestTimedOutCancel")) from None
            except HelloCancelled:
                raise ApiError("cancelled", t("unlockMethods.unlockCancelledTryAgainOr")) from None
            except Exception as exc:  # noqa: BLE001
                text = str(exc)
                if not text:
                    raise ApiError("cancelled", t("unlockMethods.unlockCancelledTryAgainOr")) from None
                raise ApiError("hello_failed", t("unlockMethods.youCanRetryOrUse", text=text)) from None

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
        blocked = getattr(self._controller, "shortcuts_blocked", None)
        if callable(blocked) and blocked():
            return {"offer": False}
        profile = self._profile()
        if hello_unlock.has_envelope(self._path(profile), profile.id):
            return {"offer": False}
        return {"offer": True, "title": t(HELLO_OFFER_TITLE), "text": t(HELLO_OFFER_TEXT)}

    def answer_offer(self, accepted: bool) -> dict[str, Any]:
        settings = self._controller.settings
        settings.hello_offer_answered = True
        settings.save()
        return {"accepted": bool(accepted)}


class SecurityKeyService(_Methods):
    """Unlock with a FIDO2 security key (hmac-secret) through the Windows Security dialog.

    An alternative to the master password, not a second factor: the password and
    the recovery phrase keep working.  Refused while the master-password marker
    is set, like Windows Hello.
    """

    def __init__(self, controller: Any, port: Any, *, hwnd: Callable[[], int | None],
                 timeout: float = SECURITY_KEY_TIMEOUT, enroll_timeout: float = SECURITY_KEY_ENROLL_TIMEOUT,
                 provider_factory: Callable[[], Any] | None = None,
                 availability: Callable[[], tuple[bool, str]] = security_key_availability) -> None:
        super().__init__(controller, port)
        self._hwnd = hwnd
        self._timeout = timeout
        self._enroll_timeout = enroll_timeout
        self._provider_kwargs = {} if provider_factory is None else {"provider_factory": provider_factory}
        self._availability = availability
        self._busy = threading.Lock()
        controller.offers["security_key"] = self.offered

    def _window(self) -> int:
        handle = self._hwnd()
        if not handle:
            raise ApiError("no_window", t("securityKey.error.windowRequired"))
        return int(handle)

    def offered(self) -> bool:
        """Whether the unlock screen shows "Unlock with security key" for the active profile."""
        try:
            profile = self._profile()
            return (self._availability()[0] and self._alternatives_allowed(profile)
                    and bool(fido_unlock.has_envelope(self._path(profile), profile.id)))
        except Exception:  # noqa: BLE001
            return False

    def status(self) -> dict[str, Any]:
        supported, reason = self._availability()
        if not supported:
            return {"supported": False, "enabled": False, "incomplete": False,
                    "status": reason or t("securityKey.status.unsupported"), "tone": "neutral",
                    "guidance": t("securityKey.guidance")}
        session, _lease = self._session_lease()
        profile = self._profile()
        bound = bool(session.fido_binding())
        envelope = bool(fido_unlock.has_envelope(self._path(profile), profile.id))
        if bound and envelope:
            status, tone = t("securityKey.status.enabled"), "success"
        elif bound or envelope:
            status, tone = t("securityKey.status.incomplete"), "danger"
        else:
            status, tone = t("securityKey.status.off"), "neutral"
        return {"supported": True, "enabled": bound and envelope, "incomplete": bound != envelope,
                "status": status, "tone": tone, "guidance": t("securityKey.guidance")}

    def enable(self) -> dict[str, Any]:
        supported, reason = self._availability()
        if not supported:
            raise ApiError("unsupported", reason or t("securityKey.status.unsupported"))
        session, lease = self._session_lease()
        self._refuse_when_always_ask()
        # Always the master password here (Windows Hello never stands in for it).
        self._auth.reauthenticate(t("securityKey.authorizeSetup"), lease)
        if not self._port.confirm(t("securityKey.confirmTitle"), t("securityKey.confirmText")):
            raise ApiError("cancelled_notice", t("securityKey.setupCancelled"))
        hwnd = self._window()
        profile = self._profile()
        context = session.unlock_context()
        if not self._busy.acquire(blocking=False):
            raise ApiError("busy", t("securityKey.error.stillClosing"))
        try:
            prepared = run_with_timeout(
                lambda cancelled: fido_unlock.prepare_enrollment(profile.id, context, hwnd, cancelled,
                                                                 **self._provider_kwargs),
                lambda late: late.discard(), self._enroll_timeout, finished=self._busy.release)
        except TimeoutError:
            raise ApiError("timeout", t("securityKey.timedOut")) from None
        except Exception as exc:  # noqa: BLE001 - SecurityKeyError, VaultError: shown as-is
            from ..security_key import SecurityKeyCancelled

            if isinstance(exc, SecurityKeyCancelled):
                raise ApiError("cancelled_notice", t("securityKey.setupCancelled")) from None
            raise ApiError("security_key_failed", str(exc) or t("securityKey.setupFailed")) from None
        try:
            self._controller.require_lease(lease)
            fido_unlock.commit_enrollment(session, prepared)
        except Exception as exc:
            prepared.discard()
            raise ApiError("security_key_failed", str(exc) or t("securityKey.setupFailed")) from None
        self._controller.touch()
        self._controller._extras_cache = None
        return {"message": t("securityKey.enabled")}

    def disable(self) -> dict[str, Any]:
        self._refuse_in_duress()
        session, lease = self._session_lease()
        self._auth.reauthenticate(t("securityKey.authorizeRemove"), lease)
        if not self._port.confirm(t("securityKey.removeTitle"), t("securityKey.removeText")):
            raise ApiError("cancelled", t("error.cancelled"))
        self._controller.require_lease(lease)
        try:
            fido_unlock.disable_enrollment(session)
        except Exception as exc:  # noqa: BLE001
            raise ApiError("security_key_failed", str(exc) or t("securityKey.removeFailed")) from None
        self._controller.touch()
        self._controller._extras_cache = None
        return {"message": t("securityKey.removed")}

    def _verify(self, path: Path, profile_id: str, **kwargs: Any) -> Any:
        hwnd = self._window()
        if not self._busy.acquire(blocking=False):
            raise ApiError("busy", t("securityKey.error.stillClosing"))
        return run_with_timeout(
            lambda cancelled: fido_unlock.unlock_with_security_key(path, profile_id, hwnd, cancelled,
                                                                   **self._provider_kwargs, **kwargs),
            lambda late: late.lock(), self._timeout, finished=self._busy.release)

    def unlock(self) -> dict[str, Any]:
        from ..security_key import SecurityKeyCancelled

        profile = self._profile()
        self._refuse_when_always_ask()  # the page offers nothing then; the server refuses too
        if not self._alternatives_allowed(profile):
            raise ApiError("master_required", t(MASTER_REQUIRED))
        controller = self._controller

        def build(path: Path, backup_dir: Path, backup_count: int) -> Any:
            try:
                return self._verify(path, profile.id, backup_dir=backup_dir, backup_count=backup_count)
            except ApiError:
                raise
            except TimeoutError:
                raise ApiError("timeout", t("unlockMethods.theRequestTimedOutCancel")) from None
            except SecurityKeyCancelled:
                raise ApiError("cancelled", t("unlockMethods.unlockCancelledTryAgainOr")) from None
            except Exception as exc:  # noqa: BLE001
                text = str(exc)
                if not text:
                    raise ApiError("cancelled", t("unlockMethods.unlockCancelledTryAgainOr")) from None
                raise ApiError("security_key_failed", t("unlockMethods.youCanRetryOrUse", text=text)) from None

        return controller.unlock_alternative(build)


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
            return {"supported": False, "enabled": False, "status": t(FACE_UNSUPPORTED), "tone": "neutral"}
        session, _lease = self._session_lease()
        profile = self._profile()
        bound = bool(session.face_binding())
        envelope = bool(face_unlock.has_envelope(self._path(profile), profile.id))
        if bound and envelope:
            status, tone = t(FACE_ENABLED), "success"
        elif bound:
            status, tone = t(FACE_DAMAGED), "danger"
        else:
            status, tone = t(FACE_OFF), "neutral"
        return {"supported": True, "enabled": bound and envelope, "incomplete": bound and not envelope,
                "status": status, "tone": tone}

    def _capture(self, mode: str, **kwargs: Any) -> Any:
        if not self._busy.acquire(blocking=False):
            raise ApiError("busy", t("unlockMethods.theCameraIsAlreadyIn"))
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
            raise ApiError("unsupported", t(FACE_UNSUPPORTED))
        session, lease = self._session_lease()
        self._refuse_when_always_ask()
        self._auth.reauthenticate(t("unlockMethods.authorizeCameraVerificationSetup"), lease)
        if not self._port.confirm(t("unlockMethods.enableOrdinaryWebcamVerification"), t(FACE_CONFIRM)):
            raise ApiError("cancelled", t("error.cancelled"))
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
            raise ApiError("cancelled_notice" if isinstance(exc, face_unlock.FaceCancelled) else "face_failed",
                           str(exc)) from None
        except Exception as exc:  # noqa: BLE001
            raise ApiError("face_failed", str(exc) or t("unlockMethods.cameraVerificationCouldNotBe")) from None
        finally:
            for sample in samples or []:
                for index in range(len(sample)):
                    sample[index] = 0.0
        self._controller.touch()
        self._controller._extras_cache = None
        return {"message": t("unlockMethods.cameraVerificationEnabledLockThe")}

    def disable(self) -> dict[str, Any]:
        self._refuse_in_duress()
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
            t("unlockMethods.removeCameraVerification"), t("unlockMethods.profileEnterTheMasterPassword", name=profile.name))
        try:
            self._controller.require_lease(lease)
            if password is None:
                raise ApiError("cancelled", t("error.cancelled"))
            from .factors import YubiKeyFailure, verify_password_with_factors

            try:
                # A session opened by Hello / security key / camera holds no key file / YubiKey: asked here.
                verify_password_with_factors(self._controller, session, password)
            except YubiKeyFailure as exc:
                raise exc.api_error() from None
            except (FactorRequired, FactorMismatch) as exc:
                # Not a password failure: said as what it is (a missing or wrong key file / YubiKey).
                self._port.notify("error", t("unlockMethods.notAuthorized"), str(exc))
                code = "factor_required" if isinstance(exc, FactorRequired) else "factor_mismatch"
                raise ApiError(code, str(exc)) from None
            except (InvalidMasterPassword, VaultError):
                self._port.notify("error", t("unlockMethods.notAuthorized"), t("unlockMethods.masterPasswordDidNotMatch"))
                raise ApiError("not_authorized", t("unlockMethods.masterPasswordDidNotMatch")) from None
            self._controller.touch()
            # Rotating with a recovery phrase replaces the phrase too (L-4): the old phrase stops working.
            rotate = face_unlock.rotation_on_disable(session)
            new_phrase = rotate and session.has_recovery_phrase()
            hello_record = session.hello_binding() if rotate else ""
            had_security_key = bool(session.fido_binding()) if rotate else False
            text = (t(FACE_DISABLE_NEW_PHRASE_CONFIRM) if new_phrase else
                    t(FACE_DISABLE_ROTATE_CONFIRM) if rotate else t(FACE_DISABLE_CONFIRM))
            if not self._port.confirm(t("unlockMethods.removeCameraVerification2"), text):
                raise ApiError("cancelled", t("error.cancelled"))
            self._controller.require_lease(lease)
            try:
                result = face_unlock.disable_enrollment(session, password if rotate else None)
            except Exception as exc:  # noqa: BLE001
                raise ApiError("face_failed", str(exc) or t("unlockMethods.cameraVerificationCouldNotBe2")) from None
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

                notes.append(t(FACE_DISABLE_NEW_PHRASE_NOTE))
                phrase_notes = recovery_phrase_change_warnings(result)
            if hello_record:
                # The rotation revoked Windows Hello too; its OS key only wraps the retired data key.
                try:
                    hello_unlock.cleanup_after_password_change(session.path, hello_record)
                except Exception:  # noqa: BLE001, S110 - the revocation is committed; cleanup is best effort
                    pass
                notes.append(t("unlockMethods.setUpWindowsHelloAgain"))
            if had_security_key:
                # The rotation revoked the security key too (its sidecar is already removed).
                notes.append(t("securityKey.setUpAgain"))
        self._controller.touch()
        self._controller._extras_cache = None
        response: dict[str, Any] = {"message": " ".join([t("unlockMethods.cameraVerificationRemoved"), *notes])}
        if phrase:
            # Shown once by the page's recovery-phrase card (the bridge turns it into a card); never stored.
            response["new_recovery_phrase"] = phrase
            response["phrase_notes"] = phrase_notes
        return response

    def unlock(self) -> dict[str, Any]:
        profile = self._profile()
        self._refuse_when_always_ask()  # the page offers nothing then; the server refuses too
        if not self._alternatives_allowed(profile):
            raise ApiError("master_required", t(MASTER_REQUIRED))
        if self._busy.locked():
            raise ApiError("busy", t("unlockMethods.theCameraIsAlreadyIn"))

        def build(path: Path, backup_dir: Path, backup_count: int) -> Any:
            try:
                material = face_unlock.load_face_material(path, profile.id)
            except face_unlock.FaceError:
                raise ApiError("face_setup", t(FACE_SETUP_MISSING)) from None
            try:
                try:
                    self._capture("verify", templates=material.templates, threshold=material.threshold)
                except face_unlock.FaceCancelled as exc:
                    if getattr(exc, "face_rejected", False):
                        face_unlock.record_failure(material.record_id)
                    raise ApiError("cancelled", str(exc)) from None
                except face_unlock.FaceUnavailable as exc:
                    # No face was compared (no camera, stalled feed, missing models): not a failed
                    # match, unless the run had already seen someone else's face.
                    if getattr(exc, "face_rejected", False):
                        face_unlock.record_failure(material.record_id)
                    raise ApiError("face_unavailable", str(exc)) from None
                except face_unlock.FaceError as exc:
                    face_unlock.record_failure(material.record_id)
                    raise ApiError("face_failed", str(exc) or t("unlock.cameraRejected")) from None
                return face_unlock.unlock_verified_face(material, backup_dir=backup_dir, backup_count=backup_count)
            finally:
                material.discard()

        return self._controller.unlock_alternative(build)
