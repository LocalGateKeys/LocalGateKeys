"""Key file and YubiKey unlock factors for the WebView UI (Settings › Unlocking and the unlock screen).

The vault code (``vault.add_factor`` / ``remove_factor``, docs/formats/COMPOSITE_KEY_V1.md) never touches
files or hardware: this module reads key files (bounded, never copied into app storage), answers YubiKey
challenges through ``yubikey_hid`` (with a cancel button and one automatic retry when the key is busy),
remembers a key file's path per vault (device-only setting, unless "Don't remember"), and carries out
"Always ask for the key file / YubiKey", which deletes the Windows Hello, security key and camera
sidecars: their unlock context does not change when a factor is added, so a kept sidecar would still
open the vault without the factors.

YubiKey failures are raised as ``YubiKeyFailure``, a ``VaultError`` the vault code passes on unchanged.
They happen before any key derivation, so ``UnlockThrottle`` never counts them.
"""
from __future__ import annotations

import hmac
import os
import stat
import threading
import time
from collections.abc import Callable, Iterable, Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Literal

from .. import composite_key, yubikey_hid
from ..api.result import ApiError
from ..i18n import t
from ..secret_text import SecretText
from ..vault import (
    FactorInput,
    FactorMismatch,
    FactorRequired,
    FactorSecrets,
    InvalidMasterPassword,
    UnlockThrottled,
    VaultError,
    vault_factors,
    vault_identifier,
)

# Larger than any real key file; KeePass hashes a file of any other shape whole (keyfile.key_material).
MAX_KEYFILE_BYTES = 64 * 1024 * 1024
DEFAULT_SLOT = 2
BUSY_RETRY_DELAY = 0.5
KEYFILE = composite_key.KEYFILE
YUBIKEY = composite_key.YUBIKEY_HMAC
YUBIKEY_MESSAGES = {
    "not_found": "factors.yubikey.notFound",
    "removed": "factors.yubikey.removed",
    "touch_timeout": "factors.yubikey.touchTimeout",
    "slot_not_configured": "factors.yubikey.slotNotConfigured",
    "busy": "factors.yubikey.busy",
    "cancelled": "error.cancelled",
}
FACE_NEW_PHRASE_NOTE = "unlockMethods.yourOldRecoveryPhraseNo"


class YubiKeyFailure(VaultError):
    """The YubiKey did not answer (``code`` as in ``yubikey_hid.YubiKeyError``); never a password failure."""

    def __init__(self, code: str, slot: int = DEFAULT_SLOT) -> None:
        self.code = code if code in YUBIKEY_MESSAGES else "not_found"
        self.slot = slot
        super().__init__(t(YUBIKEY_MESSAGES[self.code], slot=slot))

    def api_error(self) -> ApiError:
        # A cancel is the user's own choice: the page shows nothing for it.
        return ApiError("cancelled" if self.code == "cancelled" else f"yubikey_{self.code}", str(self))


def make_responder(slot: int, *, cancel_source: Callable[[], threading.Event] | None = None,
                   on_touch: Callable[[bool], None] | None = None,
                   sleep: Callable[[float], None] = time.sleep) -> Callable[[bytes], bytes]:
    """The ``FactorSecrets.yubikey_response`` callable for ``slot`` of the first plugged-in YubiKey.

    A busy key (``list_devices`` holds the exchange for up to a second per key) is retried once.
    ``cancel_source`` gives each exchange its cancel Event; ``on_touch(True/False)`` brackets the wait.
    """
    wire_slot: Literal[1, 2] = 1 if slot == 1 else 2

    def respond(challenge64: bytes) -> bytes:
        cancel = cancel_source() if cancel_source is not None else threading.Event()
        for attempt in (1, 2):
            try:
                devices = yubikey_hid.list_devices()
                if not devices:
                    raise yubikey_hid.YubiKeyError("not_found")
                if on_touch is not None:
                    on_touch(True)
                try:
                    return yubikey_hid.challenge_response(devices[0].path, wire_slot, bytes(challenge64), cancel=cancel)
                finally:
                    if on_touch is not None:
                        on_touch(False)
            except yubikey_hid.YubiKeyError as exc:
                if exc.code == "busy" and attempt == 1 and not cancel.is_set():
                    sleep(BUSY_RETRY_DELAY)
                    continue
                raise YubiKeyFailure(exc.code, slot) from None
        raise YubiKeyFailure("busy", slot)  # pragma: no cover - the loop returns or raises

    return respond


def _wipe(data: bytearray | None) -> None:
    if data is not None:
        data[:] = b"\0" * len(data)


# Win32 device and raw-namespace prefixes (\\.\pipe\..., \\?\GLOBALROOT\...): never a key file, and
# opening one can block (a named pipe waits for its server).
_DEVICE_PREFIXES = ("\\\\.\\", "\\\\?\\", "//./", "//?/", "\\??\\")


def is_unc(path: str | Path) -> bool:
    """A network (UNC) path: reaching it can stall, so it is never read unasked."""
    text = str(path)
    return text.startswith(("\\\\", "//")) and not text.startswith(_DEVICE_PREFIXES)


def read_keyfile(path: str | Path) -> bytearray:
    """A key file's bytes, read from one open handle, at most ``MAX_KEYFILE_BYTES`` (the caller wipes them).

    Only a regular file: device paths and anything ``os.stat`` does not report as a regular file
    (folders, pipes, devices) are refused before anything is opened.
    """
    name = Path(path).name
    unreadable = ApiError("keyfile_unreadable", t("factors.keyFileUnreadable", name=name))
    if str(path).startswith(_DEVICE_PREFIXES):
        raise unreadable
    try:
        if not stat.S_ISREG(os.stat(path).st_mode):
            raise unreadable
        with open(path, "rb") as handle:
            data = bytearray(handle.read(MAX_KEYFILE_BYTES + 1))
    except (OSError, ValueError):
        raise unreadable from None
    if len(data) > MAX_KEYFILE_BYTES:
        _wipe(data)
        raise ApiError("keyfile_too_large", t("recovery.keyFileTooLarge"))
    return data


# ------------------------------------------------------------ remembered path
def remembered_keyfile(settings: Any, vault_id: str) -> str | None:
    """The key file path remembered for ``vault_id`` (``None``: none, "Don't remember", or a network
    path, which is read only when the user picks it again)."""
    if not vault_id:
        return None
    path = (getattr(settings, "unlock_keyfile_paths", None) or {}).get(vault_id) or None
    return None if path is None or is_unc(path) else path


def remember_keyfile(settings: Any, vault_id: str, path: str | Path | None) -> None:
    """Remember ``path`` for ``vault_id`` unless "Don't remember" was chosen for it."""
    if not vault_id or not path:
        return
    paths = dict(getattr(settings, "unlock_keyfile_paths", None) or {})
    if paths.get(vault_id) == "" or paths.get(vault_id) == str(path):
        return
    paths[vault_id] = str(path)
    settings.unlock_keyfile_paths = paths
    settings.save()


def forget_keyfile(settings: Any, vault_id: str, *, dont_remember: bool = False) -> None:
    """Drop the remembered path; ``dont_remember`` also stops the next key file from being remembered."""
    if not vault_id:
        return
    paths = dict(getattr(settings, "unlock_keyfile_paths", None) or {})
    if dont_remember:
        if paths.get(vault_id) == "":
            return
        paths[vault_id] = ""
    elif paths.get(vault_id):
        del paths[vault_id]
    else:
        return
    settings.unlock_keyfile_paths = paths
    settings.save()


def safe_vault_id(path: Path) -> str:
    try:
        return vault_identifier(path)
    except (VaultError, OSError):
        return ""


def safe_specs(path: Path) -> list[Any]:
    try:
        return vault_factors(path)
    except (VaultError, OSError):
        return []


def unlock_factors(settings: Any, vault_path: Path, keyfile_path: str | None,
                   responder: Callable[[int], Callable[[bytes], bytes]]) -> tuple[FactorSecrets | None, str | None]:
    """The factors for a master-password unlock: the picked or remembered key file and the YubiKey.

    Returns ``(factors, key file path used)``; nothing for a vault without factors.  A missing key file
    is left out, so ``unlock_vault`` raises ``FactorRequired`` before the YubiKey is asked.
    """
    specs = {spec.kind: spec for spec in safe_specs(vault_path)}
    if not specs:
        return None, None
    chosen = None
    keyfile_bytes = None
    if KEYFILE in specs:
        chosen = keyfile_path or remembered_keyfile(settings, safe_vault_id(vault_path))
        if chosen:
            data = read_keyfile(chosen)
            try:
                keyfile_bytes = bytes(data)
            finally:
                _wipe(data)
    yubikey = specs.get(YUBIKEY)
    respond = responder(yubikey.slot or DEFAULT_SLOT) if yubikey is not None else None
    if keyfile_bytes is None and respond is None:
        return None, chosen
    return FactorSecrets(keyfile=keyfile_bytes, yubikey_response=respond), chosen


def verify_password_with_factors(controller: Any, session: Any, password: str | SecretText) -> None:
    """``verify_master_password``; a session without the factors (Windows Hello, security key, camera)
    asks for them through ``controller.factor_provider`` and then holds them."""
    try:
        session.verify_master_password(password)
    except FactorRequired as exc:
        provider = getattr(controller, "factor_provider", None)
        factors = provider(exc.kinds) if callable(provider) else None
        if factors is None:
            raise
        session.verify_master_password(password, factors=factors)


def with_factors(controller: Any, action: Callable[[FactorSecrets | None], Any]) -> Any:
    """Run ``action(None)``; on ``FactorRequired`` ask ``controller.factor_provider`` and run it once more."""
    try:
        return action(None)
    except FactorRequired as exc:
        provider = getattr(controller, "factor_provider", None)
        factors = provider(exc.kinds) if callable(provider) else None
        if factors is None:
            raise
        return action(factors)


def api_error(exc: BaseException) -> ApiError:
    """A factor operation's failure as the page sees it, each with its own message."""
    if isinstance(exc, ApiError):
        return exc
    if isinstance(exc, YubiKeyFailure):
        return exc.api_error()
    if isinstance(exc, FactorRequired):
        return ApiError("factor_required", str(exc))
    if isinstance(exc, FactorMismatch):
        return ApiError("factor_mismatch", str(exc))
    if isinstance(exc, UnlockThrottled):
        return ApiError("throttled", str(exc))
    if isinstance(exc, InvalidMasterPassword):
        return ApiError("not_authorized", t("unlockMethods.masterPasswordDidNotMatch"))
    if isinstance(exc, VaultError):
        return ApiError("factor_failed", str(exc) or t("factors.failed"))
    return ApiError("factor_failed", t("factors.failed"))


def _restrict_to_current_user(path: Path) -> bool:
    """Owner-only ACL (Windows) / mode 0600: the same best-effort helper the exports use."""
    from ..export import _restrict_permissions

    return _restrict_permissions(path)


def _inside(path: Path, folder: Path) -> bool:
    try:
        return path.resolve().is_relative_to(folder.resolve())
    except (OSError, ValueError):
        return False


class _TwoTouches:
    """A new YubiKey's responder: its first answer is asked twice and both touches must agree."""

    def __init__(self, respond: Callable[[bytes], bytes], again: Callable[[], None]) -> None:
        self._respond = respond
        self._again = again
        self._first = True

    def __call__(self, challenge64: bytes) -> bytes:
        if not self._first:
            return self._respond(challenge64)
        first = bytes(self._respond(challenge64))
        self._again()
        second = bytes(self._respond(challenge64))
        if not hmac.compare_digest(first, second):
            raise VaultError(t("factors.yubikeyTouchesDiffer"))
        self._first = False
        return first


class FactorService:
    def __init__(self, controller: Any, port: Any, dialogs: Any, *, bus: Any = None,
                 sleep: Callable[[float], None] = time.sleep) -> None:
        self._controller = controller
        self._port = port
        self._dialogs = dialogs
        self._bus = bus if bus is not None else controller._bus
        self._sleep = sleep
        self._cancel_lock = threading.Lock()
        self._cancel = threading.Event()
        # Set on the thread of an operation whose page shows its own "Touch your YubiKey" prompt.
        self._local = threading.local()
        # The key file picked on the unlock screen: (vault_id, path). The path never goes to the page.
        self._picked: tuple[str, str] | None = None
        controller.yubikey_responder = self.responder
        controller.factor_provider = self.provide
        controller.on_unlock.append(self._enforce_always_ask)
        controller.on_unlock.append(self._forget_picked)
        # A pending touch is cancelled before any lock waits for the vault's session lock.
        controller.before_lock.append(self.cancel)
        controller.on_lock.append(self._forget_picked)

    # ------------------------------------------------------------ helpers
    def _vault_path(self) -> Path:
        profile = self._controller.profiles.active_profile()
        if profile is None:
            raise ApiError("no_profile", t("recovery.chooseAProfileFirst"))
        return Path(self._controller.profiles.vault_path(profile.id))

    def _session_lease(self) -> tuple[Any, Any]:
        controller = self._controller
        if not controller.is_unlocked():
            raise ApiError("locked", t("error.lockedProfile"))
        from ..duress import is_decoy

        if is_decoy(controller.session):
            # The key file / YubiKey belong to this PC's profile: never changed from a duress session.
            raise ApiError("unavailable", t("duress.err.unavailable"))
        lease = controller.guard.lease()
        controller.require_lease(lease)
        return controller.session, lease

    def _ask_password(self, title: str) -> SecretText:
        profile = self._controller.profiles.active_profile()
        password = self._port.ask_password(
            title, t("unlockMethods.profileEnterTheMasterPassword", name=profile.name if profile else ""))
        if password is None:
            raise ApiError("cancelled", t("error.cancelled"))
        return password

    def _confirm(self, title: str, text: str) -> None:
        if not self._port.confirm(title, text):
            raise ApiError("cancelled", t("error.cancelled"))

    def _changed(self) -> None:
        self._controller.touch()
        self._controller._extras_cache = None

    @contextmanager
    def _page_prompt(self) -> Iterator[None]:
        """An operation started from a page that shows the touch prompt itself (no toast then)."""
        self._local.prompt = True
        try:
            yield
        finally:
            self._local.prompt = False

    def _forget_picked(self) -> None:
        self._picked = None

    def _new_cancel(self) -> threading.Event:
        with self._cancel_lock:
            self._cancel = threading.Event()
            return self._cancel

    # ------------------------------------------------------------- YubiKey
    def responder(self, slot: int) -> Callable[[bytes], bytes]:
        """``slot`` of the plugged-in YubiKey; the page shows "Touch your YubiKey" with Cancel meanwhile.

        The session keeps this responder after the unlock: a later password check (revealing a secret,
        say) has no prompt of its own on screen, so it gets a toast. The unlock screen and the Unlocking
        page show their own prompt (no toast there).
        """
        def on_touch(waiting: bool) -> None:
            self._bus.emit("factors.touch", {"waiting": waiting, "slot": slot})
            if waiting and self._controller.is_unlocked() and not getattr(self._local, "prompt", False):
                self._port.notify("info", t("factors.touchTitle"), t("factors.touchText"))

        return make_responder(slot, cancel_source=self._new_cancel, on_touch=on_touch, sleep=self._sleep)

    def cancel(self) -> dict[str, Any]:
        """The page's Cancel while a YubiKey waits for a touch."""
        with self._cancel_lock:
            self._cancel.set()
        return {}

    def provide(self, kinds: Iterable[str]) -> FactorSecrets | None:
        """The factors for a password check in a session that holds none (opened by Hello, a security
        key or the camera): the remembered key file, else one picked now, and the YubiKey."""
        kinds = list(kinds)
        path = self._vault_path()
        specs = {spec.kind: spec for spec in safe_specs(path)}
        keyfile_bytes = None
        if KEYFILE in kinds:
            chosen = remembered_keyfile(self._controller.settings, safe_vault_id(path))
            if chosen is None:
                selected = self._dialogs.open_file(t("factors.chooseKeyFile"))
                if not selected:
                    return None
                chosen = str(selected)
            data = read_keyfile(chosen)
            try:
                keyfile_bytes = bytes(data)
            finally:
                _wipe(data)
        respond = None
        if YUBIKEY in kinds:
            spec = specs.get(YUBIKEY)
            respond = self.responder(spec.slot if spec is not None and spec.slot else DEFAULT_SLOT)
        if keyfile_bytes is None and respond is None:
            return None
        return FactorSecrets(keyfile=keyfile_bytes, yubikey_response=respond)

    # -------------------------------------------------------------- status
    def status(self) -> dict[str, Any]:
        path = self._vault_path()
        specs = safe_specs(path)
        settings = self._controller.settings
        entry = (settings.unlock_keyfile_paths or {}).get(safe_vault_id(path))
        always = bool(settings.unlock_factors_always_ask)
        return {
            "factors": [{"kind": spec.kind, "slot": spec.slot} for spec in specs],
            "keyfile_name": Path(entry).name if entry else None,
            "remember": entry != "",
            "always_ask": always,
            "shortcuts_off": always and bool(specs),
            "hint": t("factors.addHint"),
            "yubikey_setup": t("factors.yubikeySetup"),
        }

    def pick_keyfile(self) -> dict[str, Any]:
        """The unlock screen's "Choose key file…": the path stays here (only its name goes to the page);
        ``vault_unlock`` then uses it. The file itself is read at unlock."""
        selected = self._dialogs.open_file(t("factors.chooseKeyFile"))
        if not selected:
            raise ApiError("cancelled", t("recovery.noFileWasChosen"))
        chosen = Path(selected)
        self._picked = (safe_vault_id(self._vault_path()), str(chosen))
        return {"name": chosen.name}

    def picked_keyfile(self) -> str | None:
        """The key file picked for the active vault on the unlock screen (``None``: none)."""
        picked = self._picked
        if picked is None or picked[0] != safe_vault_id(self._vault_path()):
            return None
        return picked[1]

    def set_remember(self, value: bool) -> dict[str, Any]:
        path = self._vault_path()
        vault_id = safe_vault_id(path)
        if not vault_id:
            raise ApiError("no_vault", t("controller.thisProfileHasNoVault"))
        settings = self._controller.settings
        if value:
            paths = dict(settings.unlock_keyfile_paths or {})
            if paths.get(vault_id) == "":
                del paths[vault_id]
                settings.unlock_keyfile_paths = paths
                settings.save()
            used = getattr(self._controller, "keyfile_used", None)
            if used and used[0] == vault_id:
                remember_keyfile(settings, vault_id, used[1])
        else:
            forget_keyfile(settings, vault_id, dont_remember=True)
        self._controller._extras_cache = None
        return self.status()

    # ------------------------------------------------------------- add
    def _add_text(self, session: Any) -> str:
        text = t("factors.addConfirm")
        if self._controller.settings.unlock_factors_always_ask and self._shortcuts_present(session):
            text = "\n\n".join([text, t("factors.alwaysAskConfirm")])
        return text

    def _add(self, session: Any, lease: Any, new: FactorInput, title: str) -> dict[str, Any]:
        if any(spec.kind == new.kind for spec in safe_specs(session.path)):
            raise ApiError("exists", t("vault.err.factorAlreadySet"))
        password = self._ask_password(title)
        try:
            self._controller.require_lease(lease)
            self._confirm(title, self._add_text(session))
            self._controller.require_lease(lease)
            try:
                with_factors(self._controller, lambda factors: session.add_factor(password, new, factors=factors))
            except (VaultError, OSError) as exc:
                raise api_error(exc) from None
            extra: dict[str, Any] = {}
            if self._controller.settings.unlock_factors_always_ask and self._shortcuts_present(session):
                extra = self._remove_shortcuts(session, password)
        finally:
            password.wipe()
        self._changed()
        return extra

    def add_keyfile(self, path: str | None = None) -> dict[str, Any]:
        """Add a key file picked in the open dialog (``path`` only from tests)."""
        with self._page_prompt():
            return self._add_keyfile(path)

    def _add_keyfile(self, path: str | None) -> dict[str, Any]:
        session, lease = self._session_lease()
        chosen = Path(path) if path else Path(self._pick(t("factors.chooseKeyFile")))
        data = read_keyfile(chosen)
        try:
            extra = self._add(session, lease, FactorInput(KEYFILE, keyfile_bytes=bytes(data)),
                              t("factors.addKeyFileTitle"))
        finally:
            _wipe(data)
        self._used(session.path, chosen)
        return self._result(t("factors.keyFileAdded", name=chosen.name), extra)

    def create_keyfile(self, path: str | None = None) -> dict[str, Any]:
        """Write a new KeePass XML 2.0 key file where the user chooses in the save dialog (owner-only ACL)
        and add it (``path`` only from tests)."""
        with self._page_prompt():
            return self._create_keyfile(path)

    def _create_keyfile(self, path: str | None) -> dict[str, Any]:
        from ..config import data_dir
        from ..keyfile import new_keepass_xml_v2

        session, lease = self._session_lease()
        if path:
            target = Path(path)
        else:
            selected = self._dialogs.save_file(t("factors.createKeyFileTitle"), "LocalGateKeys.keyx")
            if not selected:
                raise ApiError("cancelled", t("recovery.noFileWasChosen"))
            target = Path(selected)
        if _inside(target, data_dir()):
            # The key file must live apart from the vault (another drive, a USB stick, a safe place).
            raise ApiError("keyfile_location", t("factors.keyFileNotInAppData"))
        content = bytearray(new_keepass_xml_v2())
        try:
            try:
                # Created empty, made owner-only, then filled: the key never sits under a wider ACL.
                with open(target, "xb"):
                    pass
            except FileExistsError:
                raise ApiError("keyfile_exists", t("factors.keyFileExists", name=target.name)) from None
            except OSError:
                raise ApiError("keyfile_unwritable", t("factors.keyFileUnwritable")) from None
            try:
                if not _restrict_to_current_user(target):
                    raise ApiError("keyfile_unwritable", t("factors.keyFileUnwritable"))
                with open(target, "r+b") as handle:
                    handle.write(content)
                    handle.flush()
                extra = self._add(session, lease, FactorInput(KEYFILE, keyfile_bytes=bytes(content)),
                                  t("factors.createKeyFileTitle"))
            except BaseException:
                # Never leave a key file behind that the vault does not use.
                target.unlink(missing_ok=True)
                raise
        except OSError:
            raise ApiError("keyfile_unwritable", t("factors.keyFileUnwritable")) from None
        finally:
            _wipe(content)
        self._used(session.path, target)
        return self._result(t("factors.keyFileCreated", name=target.name), extra)

    def add_yubikey(self, slot: int = DEFAULT_SLOT) -> dict[str, Any]:
        """Register the YubiKey's ``slot`` (one per vault; a backup key is checked with ``check_backup_yubikey``)."""
        with self._page_prompt():
            session, lease = self._session_lease()
            respond = _TwoTouches(self.responder(slot),
                                  lambda: self._bus.emit("factors.touch_again", {"slot": slot}))
            extra = self._add(session, lease, FactorInput(YUBIKEY, slot=slot, responder=respond),
                              t("factors.addYubikeyTitle"))
        return self._result(t("factors.yubikeyAdded", slot=slot), extra)

    def check_backup_yubikey(self) -> dict[str, Any]:
        """A second YubiKey works only if programmed with the same secret: it must give the same response.

        Nothing is written; no password is needed (the answer reveals no secret).
        """
        session, _lease = self._session_lease()
        spec = next((spec for spec in safe_specs(session.path) if spec.kind == YUBIKEY), None)
        if spec is None:
            raise ApiError("invalid", t("vault.err.factorNotSet"))
        respond = self.responder(spec.slot or DEFAULT_SLOT)
        try:
            with self._page_prompt():
                response = respond(spec.padded_challenge)
        except YubiKeyFailure as exc:
            raise exc.api_error() from None
        try:
            check = composite_key.factor_check(composite_key.yubikey_secret(response))
        except (ValueError, TypeError):
            raise ApiError("factor_mismatch", t("factors.backupYubikeyDiffers")) from None
        if not hmac.compare_digest(check, spec.check):
            raise ApiError("factor_mismatch", t("factors.backupYubikeyDiffers"))
        return {"message": t("factors.backupYubikeyMatches")}

    def _pick(self, title: str) -> str:
        selected = self._dialogs.open_file(title)
        if not selected:
            raise ApiError("cancelled", t("recovery.noFileWasChosen"))
        return str(selected)

    def _used(self, vault_path: Path, keyfile_path: Path) -> None:
        vault_id = safe_vault_id(vault_path)
        self._controller.keyfile_used = (vault_id, str(keyfile_path))
        remember_keyfile(self._controller.settings, vault_id, keyfile_path)
        self._controller._extras_cache = None

    @staticmethod
    def _result(message: str, extra: dict[str, Any]) -> dict[str, Any]:
        notes = extra.pop("notes", [])
        return {**extra, "message": " ".join([message, *notes])}

    # ------------------------------------------------------------ remove
    def remove(self, kind: str) -> dict[str, Any]:
        with self._page_prompt():
            return self._remove(kind)

    def _remove(self, kind: str) -> dict[str, Any]:
        if kind not in composite_key.KINDS:
            raise ApiError("invalid", t("bridge.invalid", name="kind"))
        session, lease = self._session_lease()
        if not any(spec.kind == kind for spec in safe_specs(session.path)):
            raise ApiError("invalid", t("vault.err.factorNotSet"))
        title = t("factors.removeKeyFileTitle") if kind == KEYFILE else t("factors.removeYubikeyTitle")
        password = self._ask_password(title)
        try:
            self._controller.require_lease(lease)
            self._confirm(title, t("factors.removeConfirm"))
            self._controller.require_lease(lease)
            try:
                with_factors(self._controller, lambda factors: session.remove_factor(password, kind, factors=factors))
            except (VaultError, OSError) as exc:
                raise api_error(exc) from None
        finally:
            password.wipe()
        if kind == KEYFILE:
            forget_keyfile(self._controller.settings, safe_vault_id(session.path))
            self._controller.keyfile_used = None
        self._changed()
        return {"message": t("factors.keyFileRemoved") if kind == KEYFILE else t("factors.yubikeyRemoved")}

    # -------------------------------------------------------- always ask
    def _shortcuts_present(self, session: Any) -> bool:
        from .. import face_unlock, fido_unlock, hello_unlock

        profile = self._controller.profiles.active_profile()
        profile_id = profile.id if profile else ""
        return bool(session.hello_binding() or hello_unlock.has_envelope(session.path, profile_id)
                    or session.fido_binding() or fido_unlock.has_envelope(session.path, profile_id)
                    or face_unlock.enrollment_present(session) or face_unlock.has_envelope(session.path, profile_id))

    def _remove_shortcuts(self, session: Any, password: SecretText | None) -> dict[str, Any]:
        """Delete the Windows Hello, security key and camera sidecars (and their bindings).

        With the master password, removing camera unlock rotates the data key as Settings does
        (``FaceService.disable``); a recovery phrase is then replaced and returned once.
        """
        from .. import face_unlock, fido_unlock, hello_unlock

        profile = self._controller.profiles.active_profile()
        profile_id = profile.id if profile else ""
        notes: list[str] = []
        response: dict[str, Any] = {}
        try:
            if session.hello_binding() or hello_unlock.has_envelope(session.path, profile_id):
                hello_unlock.disable_enrollment(session)
                notes.append(t("factors.helloRemoved"))
            if session.fido_binding() or fido_unlock.has_envelope(session.path, profile_id):
                fido_unlock.disable_enrollment(session)
                notes.append(t("factors.securityKeyRemoved"))
            if password is None:
                # No master password here (after an unlock): the camera sidecar goes, so camera unlock stops
                # working, but its binding stays so that Settings › Unlocking can still remove it with the
                # data-key rotation that also retires old copies of the sidecar.
                if face_unlock.has_envelope(session.path, profile_id):
                    face_unlock.cleanup_after_password_change(session.path)
                if session.face_binding():
                    response["camera_pending"] = True
            elif face_unlock.enrollment_present(session) or face_unlock.has_envelope(session.path, profile_id):
                rotate = face_unlock.rotation_on_disable(session)
                result = face_unlock.disable_enrollment(session, password if rotate else None)
                notes.append(t("factors.cameraRemoved"))
                phrase = result.pop("new_recovery_phrase", None) if result else None
                if phrase:
                    from .recovery_center import recovery_phrase_change_warnings

                    notes.append(t(FACE_NEW_PHRASE_NOTE))
                    response["new_recovery_phrase"] = phrase
                    response["phrase_notes"] = recovery_phrase_change_warnings(result or {})
        except ApiError:
            raise
        except Exception as exc:  # noqa: BLE001 - VaultError, HelloError, OSError: said as-is
            raise api_error(exc) from None
        finally:
            self._controller._extras_cache = None
        response["notes"] = notes
        return response

    def set_always_ask(self, value: bool) -> dict[str, Any]:
        with self._page_prompt():
            return self._set_always_ask(value)

    def _set_always_ask(self, value: bool) -> dict[str, Any]:
        settings = self._controller.settings
        if not value:
            settings.unlock_factors_always_ask = False
            settings.save()
            self._changed_settings()
            return {"always_ask": False, "message": t("factors.alwaysAskOff")}
        session, lease = self._session_lease()
        if not safe_specs(session.path):
            raise ApiError("no_factors", t("factors.alwaysAskNeedsFactor"))
        extra: dict[str, Any] = {}
        if self._shortcuts_present(session):
            title = t("factors.alwaysAskTitle")
            password = self._ask_password(title)
            try:
                self._controller.require_lease(lease)
                self._confirm(title, t("factors.alwaysAskConfirm"))
                self._controller.require_lease(lease)
                try:
                    # The camera's data-key rotation renews the YubiKey challenge: the factors must be held.
                    verify_password_with_factors(self._controller, session, password)
                except (VaultError, OSError) as exc:
                    raise api_error(exc) from None
                extra = self._remove_shortcuts(session, password)
            finally:
                password.wipe()
        settings.unlock_factors_always_ask = True
        settings.save()
        if self._remove_other_profiles_sidecars(session.path):
            extra.setdefault("notes", []).append(t("factors.otherProfilesShortcutsRemoved"))
        self._changed_settings()
        return {"always_ask": True, **self._result(t("factors.alwaysAskOn"), extra)}

    def _remove_other_profiles_sidecars(self, current: Path) -> bool:
        """"Always ask" is one switch for this PC: every other profile whose vault has factors loses its
        Windows Hello, security key and camera sidecar files now (as a password change does, without a
        session). Their in-vault bindings go at that profile's next unlock (``_enforce_always_ask``)."""
        from .. import face_unlock, fido_unlock, hello_unlock

        profiles = self._controller.profiles
        removed = False
        for profile in profiles.list_profiles():
            path = Path(profiles.vault_path(profile.id))
            if path == Path(current) or not safe_specs(path):
                continue
            had = [hello_unlock.envelope_path(path).exists(), fido_unlock.envelope_path(path).exists(),
                   face_unlock.envelope_path(path).exists()]
            hello_unlock.cleanup_after_password_change(path, "")  # the OS key goes with the binding later
            fido_unlock.cleanup_after_password_change(path)
            face_unlock.cleanup_after_password_change(path)
            removed = removed or any(had)
        return removed

    def _changed_settings(self) -> None:
        self._controller._extras_cache = None

    def _enforce_always_ask(self) -> None:
        """After an unlock: a vault with factors keeps no shortcut while "Always ask" is on.

        "Always ask" is one switch for this PC; a profile set up with Windows Hello before it was turned
        on (in another profile) loses its shortcuts here, without the camera's data-key rotation (the
        master password is not at hand).
        """
        controller = self._controller
        try:
            session = controller.session
            if session is None or not controller.shortcuts_blocked() or not self._shortcuts_present(session):
                return
            result = self._remove_shortcuts(session, None)
        except Exception as exc:  # noqa: BLE001 - logged; the unlock itself stands
            from .. import error_log

            error_log.log_exception("factors-always-ask", exc)
            return
        messages = [t("factors.shortcutsRemovedOnUnlock")] if result.get("notes") else []
        if result.get("camera_pending"):
            messages.append(t("factors.cameraFinishInSettings"))
        if messages:
            self._bus.emit("notice", {"kind": "info", "title": t("factors.alwaysAskTitle"),
                                      "message": " ".join(messages)})
