"""The Windows passkey provider switch: registration, start-up clean-up and the metadata-cache sync.

Design note ``docs/design/WINDOWS_PASSKEY_PROVIDER.md`` (sections 5.4 and 9). Every Windows plugin call is made by
``PasskeyProvider\\LocalGateKeysPasskeyProvider.exe`` from this package's own install directory, started here with
one fixed argument, no shell and no window:

* ``--register`` only when the user turns ``windows_passkey_provider`` on (never at install or start-up);
* ``--unregister`` when it goes off, and at start-up when the setting is off but Windows still lists the provider
  (a reinstall after an orphaned entry); it also empties Windows' metadata cache;
* ``--state`` (read-only) at start-up, and in the background while the setting is on (``RegistrationState``);
* ``--sync`` after unlock and after any item change, debounced, only while the setting is on. The provider asks the
  app for the names over the pipe (``passkey_credentials_system``): site and account names and IDs, never keys.

On lock nothing happens: Windows keeps the names so it can offer the account and the provider then asks for unlock
(owner decision). The switch is shown only with package identity (MSIX) on a Windows build with the plugin API.
Nothing the provider prints is logged.
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
import subprocess
import sys
import threading
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

from . import distribution
from .pipe_transport import PROVIDER_RELATIVE_PATH

_log = logging.getLogger(__name__)

COMMANDS = frozenset({"--register", "--unregister", "--state", "--sync", "--clear-cache"})
MINIMUM_UBR = 6725  # 26100 / 26200 with this UBR or later, or any later build (BuildGate.cs)
# NTE_NOT_SUPPORTED from WebAuthNPluginAddAuthenticator: no Windows Hello PIN (or TPM) for the operation-signing key
# [S10, secondary]; confirm on the packaged install (PENDING).
NEED_PIN_HRESULT = "0x80090029"
# Settings > Accounts. A URI for Passkeys > Advanced options is UNVERIFIED (U3); this page is the documented parent.
SETTINGS_URI = "ms-settings:accounts"
# The provider's own CLSID (ProviderIds.cs): used only by the no-identity clean-up below.
PROVIDER_CLSID = "f1d767c8-6f3e-43a6-953c-d3c1f7a8c414"
MAX_OUTPUT = 64 * 1024
# The provider's own budget for --sync: up to 12 s waiting for the app's answer, then RemoveAll + AddCredentials.
# Killing it between those two calls would leave Windows' cache empty until the next change, so the app waits longer.
COMMAND_TIMEOUTS = {"--sync": 30.0}
# Every package identity this app ships under (build-msix/store-identity.json and the test identity in
# scripts/build_msix_package.ps1; a test keeps them in step). Used to tell an orphaned provider entry from the live
# registration of an installed package.
PACKAGE_IDENTITIES = (
    ("IliasPel.LocalGateKeys", "CN=B458134A-22E8-43B2-A3AC-3BA007F8A6DA"),
    ("LocalGateKeys.Test", "CN=LocalGateKeys Test Signing"),
)
_ERROR_SUCCESS = 0
_ERROR_INSUFFICIENT_BUFFER = 122
_LOAD_LIBRARY_SEARCH_SYSTEM32 = 0x00000800

# One provider command at a time, and a sync never overlaps a register or unregister.
PROVIDER_LOCK = threading.RLock()


# -- availability ---------------------------------------------------------------------------------------------------
def build_supported(build: int, ubr: int) -> bool:
    if build > 26200:
        return True
    return build in (26100, 26200) and ubr >= MINIMUM_UBR


def _windows_build() -> tuple[int, int]:
    """(CurrentBuildNumber, UBR) from the registry; (0, 0) when unreadable."""
    if os.name != "nt":
        return 0, 0
    try:
        import winreg

        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion") as key:
            build = int(str(winreg.QueryValueEx(key, "CurrentBuildNumber")[0]))
            ubr = int(winreg.QueryValueEx(key, "UBR")[0])
        return build, ubr
    except (OSError, ValueError, TypeError):
        return 0, 0


def provider_path() -> Path | None:
    """``<install dir>\\PasskeyProvider\\LocalGateKeysPasskeyProvider.exe`` inside this package, or ``None``.

    The same path the pipe pins for the ``system_passkey`` scope (``pipe_transport._provider_path``), and it must
    lie inside the package's install directory, which Windows keeps read-only.
    """
    root = distribution.package_root()
    if root is None:
        return None
    try:
        package = Path(os.path.abspath(root))
        candidate = Path(os.path.abspath(Path(sys.executable).parent.joinpath(*PROVIDER_RELATIVE_PATH)))
        if os.path.normcase(os.path.commonpath([str(package), str(candidate)])) != os.path.normcase(str(package)):
            return None
        if not candidate.is_file() or candidate.is_symlink():
            return None
        return candidate
    except (OSError, ValueError):
        return None


def available() -> bool:
    """Whether the switch is shown: Windows, package identity (MSIX), a supported build and the provider exe."""
    if os.name != "nt" or not distribution.is_packaged():
        return False
    if not build_supported(*_windows_build()):
        return False
    return provider_path() is not None


# -- running the provider -------------------------------------------------------------------------------------------
_signer_checked: dict[str, bool] = {}


def _same_signer(path: Path) -> bool:
    """When the app itself is validly signed, the provider must carry the same signer (as the pipe pin requires)."""
    key = os.path.normcase(str(path))
    if key in _signer_checked:
        return _signer_checked[key]
    from .pipe_transport import _authenticode_thumbprint

    own = _authenticode_thumbprint(sys.executable)
    ok = True
    if own:
        import hmac

        theirs = _authenticode_thumbprint(str(path))
        ok = bool(theirs) and hmac.compare_digest(theirs, own)
    _signer_checked[key] = ok
    return ok


def run_provider(*args: str, timeout: float | None = None) -> dict[str, Any]:
    """Run the installed provider with one fixed command; its one-line JSON answer, or ``{"ok": False, ...}``."""
    if len(args) != 1 or args[0] not in COMMANDS:
        raise ValueError("unsupported provider command")
    if timeout is None:
        timeout = COMMAND_TIMEOUTS.get(args[0], 15.0)
    path = provider_path()
    if path is None:
        return {"ok": False, "error": "unavailable"}
    if not _same_signer(path):
        return {"ok": False, "error": "signer_mismatch"}
    try:
        completed = subprocess.run(  # noqa: S603 - fixed executable inside the package, fixed argument, no shell
            [str(path), args[0]], stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            cwd=str(path.parent), timeout=timeout, shell=False, check=False,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    except subprocess.TimeoutExpired:
        return {"ok": False, "error": "timeout"}
    except OSError:
        return {"ok": False, "error": "launch_failed"}
    return _parse_output(completed.stdout or b"")


def _parse_output(raw: bytes) -> dict[str, Any]:
    lines = [line for line in raw[:MAX_OUTPUT].decode("utf-8", "replace").splitlines() if line.strip()]
    if not lines:
        return {"ok": False, "error": "no_output"}
    try:
        value = json.loads(lines[-1])
    except ValueError:
        return {"ok": False, "error": "bad_output"}
    if not isinstance(value, dict) or not isinstance(value.get("ok"), bool):
        return {"ok": False, "error": "bad_output"}
    return value


def open_windows_settings() -> None:
    try:
        os.startfile(SETTINGS_URI)  # type: ignore[attr-defined]  # noqa: S606 - fixed ms-settings URI
    except (OSError, AttributeError):
        _log.info("Windows Settings could not be opened")


# -- registration state ---------------------------------------------------------------------------------------------
# A cached state older than MAX_AGE counts as unknown (not enabled): the extension keeps the request. While the
# setting is on, a timer re-reads it every REFRESH_PERIOD, so it is normally fresh; a request may also start a
# refresh, but never more often than MIN_REFRESH_GAP.
MAX_AGE = 30.0
REFRESH_PERIOD = 20.0
MIN_REFRESH_GAP = 10.0
_STATES = frozenset({"enabled", "disabled", "not_registered"})


class RegistrationState:
    """The last provider state Windows reported (``--state``), cached for the browser broker.

    The broker reads it on the UI thread, so it never starts a process there: ``refresh_later`` re-reads
    ``--state`` on a worker thread, at most once per ``MIN_REFRESH_GAP`` and one at a time, which picks up the user
    turning LocalGateKeys on or off in Windows Settings (``attach`` also runs it every ``REFRESH_PERIOD`` while the
    setting is on). ``enable``/``disable``/``reconcile`` record what they did. Fail safe: anything unknown (a failed
    ``--state``, no provider) and any state older than ``MAX_AGE`` counts as not enabled, so the extension keeps its
    own passkey path. Only this process writes it; nothing from a browser request does.
    """

    def __init__(self, *, spawn: Callable[[Callable[[], None]], None] | None = None) -> None:
        self._lock = threading.Lock()
        self._state: str | None = None
        self._recorded = float("-inf")  # when Windows last reported the state (freshness)
        self._attempted = float("-inf")  # when a refresh last started (throttle)
        self._refreshing = False
        self._spawn = spawn

    def record(self, state: Any, *, stale: bool = False) -> None:
        """Store a reported state; ``stale`` asks the next check to read it again from Windows."""
        with self._lock:
            self._state = state if state in _STATES else None
            now = time.monotonic()
            # A fresh answer also restarts the throttle; a stale one lets the next check refresh at once.
            self._recorded = self._attempted = float("-inf") if stale else now

    def current(self) -> str | None:
        """The last reported state while fresh (``enabled`` / ``disabled`` / ``not_registered``), else None."""
        with self._lock:
            return self._state if time.monotonic() - self._recorded < MAX_AGE else None

    def enabled(self) -> bool:
        """``enabled`` as reported less than ``MAX_AGE`` ago; anything older is unknown."""
        with self._lock:
            return self._state == "enabled" and time.monotonic() - self._recorded < MAX_AGE

    def refresh_later(self, *, run: Callable[..., dict[str, Any]] | None = None,
                      is_available: Callable[[], bool] | None = None) -> None:
        """Re-read ``--state`` on a worker thread when due; never blocks the caller."""
        with self._lock:
            now = time.monotonic()
            if self._refreshing or now - self._attempted < MIN_REFRESH_GAP:
                return
            self._refreshing = True
            self._attempted = now
        run_state = run or run_provider
        check = is_available or available

        def work() -> None:
            try:
                if not check():
                    self.record(None)
                    return
                with PROVIDER_LOCK:
                    result = run_state("--state")
                    self.record(result.get("state") if result.get("ok") is True else None)
            except Exception:  # noqa: BLE001 - unknown means "not enabled": the extension keeps its own path
                self.record(None)
            finally:
                with self._lock:
                    self._refreshing = False

        spawn = self._spawn or (lambda target: threading.Thread(target=target, name="lgk-passkey-provider-state",
                                                                daemon=True).start())
        try:
            spawn(work)
        except Exception:  # noqa: BLE001 - no thread: a later check tries again
            with self._lock:
                self._refreshing = False


REGISTRATION = RegistrationState()


def _start_ticker(tick: Callable[[], None]) -> None:
    """Run ``tick`` every ``REFRESH_PERIOD`` on a daemon thread for the life of the app (tests replace this)."""
    def loop() -> None:
        pause = threading.Event()
        while True:
            try:
                tick()
            except Exception:  # noqa: BLE001 - a failed tick only leaves the cache to age out (fail safe)
                _log.info("Windows passkey state refresh failed", exc_info=True)
            pause.wait(REFRESH_PERIOD)

    threading.Thread(target=loop, name="lgk-passkey-provider-ticker", daemon=True).start()


# -- switch actions -------------------------------------------------------------------------------------------------
def enable(*, run: Callable[..., dict[str, Any]] = run_provider,
           open_settings: Callable[[], None] = open_windows_settings) -> dict[str, Any]:
    """Register with Windows (``--register``), then open Windows Settings so the user can turn it on there."""
    with PROVIDER_LOCK:
        result = run("--register")
        # Windows lists a new provider as off until the user turns it on in Settings: not enabled yet, and the
        # next broker check reads the state again.
        REGISTRATION.record("disabled" if result.get("ok") is True else None, stale=True)
    if result.get("ok") is True:
        open_settings()
    return result


def disable(*, run: Callable[..., dict[str, Any]] = run_provider) -> dict[str, Any]:
    """Unregister (``--unregister``): empties Windows' metadata cache, then removes the provider entry."""
    with PROVIDER_LOCK:
        result = run("--unregister")
        REGISTRATION.record("not_registered" if result.get("ok") is True else None, stale=True)
        return result


def reconcile(setting_on: bool, *, run: Callable[..., dict[str, Any]] = run_provider,
              is_available: Callable[[], bool] = available,
              native: Callable[[], str] | None = None) -> str:
    """Start-up check; never registers. Returns what it found or did.

    * With identity: setting off but Windows lists the provider -> ``--unregister`` (``"unregistered"``); setting on
      but not registered (reinstall) -> ``"not_registered"`` so the caller turns the switch off.
    * Without identity (an installed build outside the package): any entry with our CLSID is stale, so it is
      removed through webauthn.dll directly (``native``), best effort.
    """
    if not is_available():
        REGISTRATION.record(None)
        cleanup = native if native is not None else _native_cleanup
        try:
            return cleanup()
        except Exception:  # noqa: BLE001 - best effort; the MSIX uninstall check is U13
            return "unknown"
    with PROVIDER_LOCK:
        state = run("--state")
        if state.get("ok") is not True:
            REGISTRATION.record(None)
            return "unknown"
        found = state.get("state")
        REGISTRATION.record(found)
        if found in ("enabled", "disabled"):
            if setting_on:
                return "registered"
            result = run("--unregister")
            REGISTRATION.record("not_registered" if result.get("ok") is True else None)
            return "unregistered" if result.get("ok") is True else "unknown"
        if found == "not_registered":
            return "not_registered"
        return "unknown"


def _native_cleanup() -> str:
    """Installed build without package identity: remove a stale provider entry left by an uninstalled package.

    Only frozen builds on a supported Windows do this; development runs never touch Windows. webauthn.dll is loaded
    from System32 only. Whether a process without identity may remove the entry is UNVERIFIED (U7/U11); a failure
    leaves it, as before.
    """
    if os.name != "nt" or not getattr(sys, "frozen", False) or distribution.is_packaged():
        return "skipped"
    if not build_supported(*_windows_build()):
        return "skipped"
    if package_installed() is not False:
        return "skipped"  # the entry may be an installed package's live registration (or we cannot tell)
    import ctypes
    import uuid

    try:
        dll = ctypes.WinDLL("webauthn.dll", winmode=_LOAD_LIBRARY_SEARCH_SYSTEM32)
        get_state = dll.WebAuthNPluginGetAuthenticatorState
        remove_all = dll.WebAuthNPluginAuthenticatorRemoveAllCredentials
        remove = dll.WebAuthNPluginRemoveAuthenticator
    except (OSError, AttributeError):
        return "skipped"
    clsid = (ctypes.c_byte * 16).from_buffer_copy(uuid.UUID(PROVIDER_CLSID).bytes_le)
    for function in (get_state, remove_all, remove):
        function.restype = ctypes.c_long
    get_state.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_int)]
    remove_all.argtypes = [ctypes.c_void_p]
    remove.argtypes = [ctypes.c_void_p]
    state = ctypes.c_int(0)
    if get_state(ctypes.byref(clsid), ctypes.byref(state)) != 0:
        return "not_registered"  # NTE_NOT_FOUND or anything else: nothing to remove that we can see
    remove_all(ctypes.byref(clsid))
    return "unregistered" if remove(ctypes.byref(clsid)) == 0 else "unknown"


class _PackageId:  # built lazily: ctypes only on Windows
    _type: Any = None

    @classmethod
    def make(cls, name: str, publisher: str) -> Any:
        import ctypes

        if cls._type is None:
            class PACKAGE_ID(ctypes.Structure):  # noqa: N801 - appmodel.h name
                _fields_ = [("reserved", ctypes.c_uint32), ("processorArchitecture", ctypes.c_uint32),
                            ("version", ctypes.c_uint64), ("name", ctypes.c_wchar_p),
                            ("publisher", ctypes.c_wchar_p), ("resourceId", ctypes.c_wchar_p),
                            ("publisherId", ctypes.c_wchar_p)]

            cls._type = PACKAGE_ID
        return cls._type(name=name, publisher=publisher)


def package_family_name(name: str, publisher: str) -> str | None:
    """``PackageFamilyNameFromId`` (appmodel.h) for a package name and publisher; None on any failure."""
    if os.name != "nt":
        return None
    try:
        import ctypes

        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        function = kernel32.PackageFamilyNameFromId
        function.restype = ctypes.c_long
        function.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_uint32), ctypes.c_wchar_p]
        package_id = _PackageId.make(name, publisher)
        length = ctypes.c_uint32(0)
        if function(ctypes.byref(package_id), ctypes.byref(length), None) != _ERROR_INSUFFICIENT_BUFFER:
            return None
        buffer = ctypes.create_unicode_buffer(length.value)
        if function(ctypes.byref(package_id), ctypes.byref(length), buffer) != _ERROR_SUCCESS:
            return None
        return buffer.value or None
    except (OSError, AttributeError, ValueError):
        return None


def _packages_in_family(family: str) -> int | None:
    """``GetPackagesByPackageFamily`` for the current user: how many are installed; None when it cannot tell."""
    import ctypes

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    function = kernel32.GetPackagesByPackageFamily
    function.restype = ctypes.c_long
    function.argtypes = [ctypes.c_wchar_p, ctypes.POINTER(ctypes.c_uint32), ctypes.c_void_p,
                         ctypes.POINTER(ctypes.c_uint32), ctypes.c_void_p]
    count = ctypes.c_uint32(0)
    length = ctypes.c_uint32(0)
    result = function(family, ctypes.byref(count), None, ctypes.byref(length), None)
    if result == _ERROR_SUCCESS:
        return int(count.value)
    if result == _ERROR_INSUFFICIENT_BUFFER:
        return max(1, int(count.value))
    return None


def package_installed() -> bool | None:
    """Whether any LocalGateKeys package is installed for this user: True, False, or None when unsure."""
    if os.name != "nt":
        return None
    try:
        found = False
        for name, publisher in PACKAGE_IDENTITIES:
            family = package_family_name(name, publisher)
            if family is None:
                return None
            count = _packages_in_family(family)
            if count is None:
                return None
            found = found or count > 0
        return found
    except (OSError, AttributeError, ValueError):
        return None


def failure_message(result: dict[str, Any], *, turning_on: bool) -> str:
    from .i18n import t

    if turning_on:
        if str(result.get("hresult", "")).lower() == NEED_PIN_HRESULT:
            return t("settings.windowsPasskeys.needPin")
        if result.get("error") == "unsupported_build":
            return t("settings.windowsPasskeys.unsupported")
        return t("settings.windowsPasskeys.registerFailed")
    return t("settings.windowsPasskeys.unregisterFailed")


# -- metadata sync --------------------------------------------------------------------------------------------------
def snapshot_digest(snapshot: list[dict[str, str]]) -> str:
    canonical = json.dumps(snapshot, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


class MetadataSync:
    """Debounced ``--sync``: runs only while ``enabled()``, unlocked (``snapshot()`` not None) and changed.

    The digest of the last synced snapshot is kept in memory only. A failed sync keeps the old digest, so the next
    change or unlock tries again. The provider fetches its own (possibly later) list over the pipe, so the digest
    describes what this app last asked Windows to hold, not strictly what Windows holds; a change in between emits
    ``items.changed`` again and syncs once more.
    """

    def __init__(self, *, enabled: Callable[[], bool], snapshot: Callable[[], list[dict[str, str]] | None],
                 run: Callable[..., dict[str, Any]], delay: float = 2.0,
                 lock: Any = None) -> None:
        self._enabled = enabled
        self._snapshot = snapshot
        self._run = run
        self._delay = delay
        self._lock = lock if lock is not None else PROVIDER_LOCK
        self._state = threading.Lock()
        self._timer: threading.Timer | None = None
        self._digest: str | None = None
        self._clear_pending = False

    def schedule(self) -> None:
        if not self._safe_enabled():
            return
        with self._state:
            if self._timer is not None:
                self._timer.cancel()
            timer = threading.Timer(self._delay, self._fire)
            timer.daemon = True
            timer.name = "lgk-passkey-metadata-sync"
            self._timer = timer
            timer.start()

    def forget(self) -> None:
        with self._state:
            if self._timer is not None:
                self._timer.cancel()
                self._timer = None
            self._digest = None
            self._clear_pending = False

    @property
    def clear_pending(self) -> bool:
        """The last ``clear()`` failed and nothing (sync, toggle, unregister) has replaced it since."""
        with self._state:
            return self._clear_pending

    def clear(self) -> bool:
        """Empty Windows' metadata cache (``--clear-cache``); the provider stays registered. True on success.

        A failure is remembered (``clear_pending``) so the ticker can try again until it works.
        """
        self.forget()
        ok = False
        try:
            with self._lock:
                result = self._run("--clear-cache")
            ok = result.get("ok") is True
            if not ok:
                _log.info("Windows passkey metadata clear failed: %s", str(result.get("error", ""))[:40])
        except Exception:  # noqa: BLE001 - never breaks the app
            ok = False
        with self._state:
            self._clear_pending = not ok
        return ok

    def retry_clear(self, still_wanted: Callable[[], bool]) -> bool:
        """Run a failed ``clear()`` again while ``still_wanted()`` (under the provider lock). True when it ran."""
        if not self.clear_pending:
            return False
        with self._lock:
            if not self.clear_pending:
                return False
            try:
                wanted = still_wanted() is True
            except Exception:  # noqa: BLE001 - unknown: keep it pending, try on the next tick
                return False
            if not wanted:
                with self._state:
                    self._clear_pending = False
                return False
            self.clear()
            return True

    def flush(self) -> None:
        """Run a pending sync now (tests and shutdown)."""
        with self._state:
            timer, self._timer = self._timer, None
        if timer is not None:
            timer.cancel()
            self._fire()

    def on_event(self, name: str, _detail: dict[str, Any]) -> None:
        """``EventBus`` listener: item changes and profile switches."""
        if name in ("items.changed", "vault.state"):
            self.schedule()

    def _safe_enabled(self) -> bool:
        try:
            return self._enabled() is True
        except Exception:  # noqa: BLE001 - unknown means off
            return False

    def _fire(self) -> None:
        with self._state:
            if self._timer is not None and threading.current_thread() is self._timer:
                self._timer = None
        try:
            with self._lock:
                if not self._safe_enabled():
                    return
                snapshot = self._snapshot()
                if snapshot is None:
                    return  # locked: Windows keeps what it has
                digest = snapshot_digest(snapshot)
                with self._state:
                    if digest == self._digest:
                        return
                result = self._run("--sync")
                if result.get("ok") is True:
                    with self._state:
                        self._digest = digest
                else:
                    _log.info("Windows passkey metadata sync failed: %s", str(result.get("error", ""))[:40])
        except Exception:  # noqa: BLE001 - a sync never breaks the app
            _log.info("Windows passkey metadata sync failed", exc_info=True)


class ProviderSwitch:
    """Applies ``windows_passkey_provider`` changes on a worker thread and reports them as toasts.

    ``desired()`` is read again under the provider lock, so quick on/off/on clicks end in the last state.
    """

    def __init__(self, *, desired: Callable[[], bool], toast: Callable[[str, str], None],
                 switch_off: Callable[[], None], sync: MetadataSync,
                 run: Callable[..., dict[str, Any]] = run_provider,
                 open_settings: Callable[[], None] = open_windows_settings,
                 spawn: Callable[[Callable[[], None]], None] | None = None,
                 passkeys_on: Callable[[], bool] = lambda: True) -> None:
        self._desired = desired
        self._passkeys_on = passkeys_on
        self._toast = toast
        self._switch_off = switch_off
        self._sync = sync
        self._run = run
        self._open_settings = open_settings
        self._spawn = spawn or (lambda work: threading.Thread(target=work, name="lgk-passkey-provider",
                                                              daemon=True).start())
        self._applied: bool | None = None

    def changed(self) -> None:
        self._spawn(self.apply)

    @property
    def applied(self) -> bool | None:
        """What this app last registered (True), unregistered (False), or None before start-up decided."""
        with PROVIDER_LOCK:
            return self._applied

    def mark_applied(self, registered: bool) -> None:
        """What start-up found (so a later toggle to the same state does nothing)."""
        with PROVIDER_LOCK:
            self._applied = registered

    def passkeys_changed(self) -> None:
        """``passkeys_enabled`` changed: off clears the names from Windows (registration kept); on syncs in full."""
        def work() -> None:
            with PROVIDER_LOCK:
                if self._desired() is not True or self._applied is not True:
                    return
                if self._passkeys_on() is True:
                    self._sync.forget()
                    self._sync.schedule()
                else:
                    self._sync.clear()

        self._spawn(work)

    def apply(self) -> None:
        from .i18n import t

        with PROVIDER_LOCK:
            want = self._desired() is True
            if want == self._applied:
                return
            if want:
                result = enable(run=self._run, open_settings=self._open_settings)
                if result.get("ok") is True:
                    self._applied = True
                    self._sync.forget()
                    self._sync.schedule()
                    self._toast("info", t("settings.windowsPasskeys.enabled"))
                else:
                    self._applied = False
                    self._switch_off()
                    self._toast("error", failure_message(result, turning_on=True))
                return
            self._sync.forget()
            result = disable(run=self._run)
            self._applied = False
            if result.get("ok") is True:
                self._toast("info", t("settings.windowsPasskeys.disabled"))
            else:
                self._toast("error", failure_message(result, turning_on=False))


# -- app wiring -----------------------------------------------------------------------------------------------------
def attach(*, controller: Any, bus: Any, run_on_ui: Callable[..., Any], toast: Callable[[str, str], None],
           start: Callable[[Callable[[], None]], None] | None = None,
           run: Callable[..., dict[str, Any]] = run_provider,
           is_available: Callable[[], bool] = available) -> ProviderSwitch:
    """Wire the switch, the sync and the start-up clean-up into the running app; returns the switch.

    ``settings_changed("windows_passkey_provider")`` must call ``switch.changed()``. Locking does nothing here.
    """
    start = start or (lambda work: threading.Thread(target=work, name="lgk-passkey-provider-start",
                                                    daemon=True).start())

    def setting_on() -> bool:
        return getattr(controller.settings, "windows_passkey_provider", False) is True

    def sync_enabled() -> bool:
        # The app answers passkey_credentials_system only while passkeys are on too.
        return (setting_on() and getattr(controller.settings, "passkeys_enabled", False) is True
                and is_available())

    def snapshot() -> list[dict[str, str]] | None:
        def read() -> list[dict[str, str]] | None:
            from .duress import is_decoy

            if not controller.is_unlocked() or is_decoy(controller.session):
                return None  # a duress session never publishes its passkeys to Windows (sub-plan 08)
            return controller.session.item_service.passkey_metadata()

        try:
            return run_on_ui(read, timeout=10)
        except TimeoutError:
            return None

    def switch_off() -> None:
        import dataclasses

        def write() -> None:
            current = controller.settings
            if getattr(current, "windows_passkey_provider", False) is not True:
                return
            updated = dataclasses.replace(current, windows_passkey_provider=False)
            updated.save()
            controller.settings = updated

        try:
            run_on_ui(write, timeout=30)
        except (TimeoutError, OSError):
            _log.info("The Windows passkey switch could not be turned off")
            return
        bus.emit("settings.changed", {"key": "windows_passkey_provider"})

    sync = MetadataSync(enabled=sync_enabled, snapshot=snapshot, run=run)
    def passkeys_on() -> bool:
        return getattr(controller.settings, "passkeys_enabled", False) is True

    switch = ProviderSwitch(desired=setting_on, toast=toast, switch_off=switch_off, sync=sync, run=run,
                            passkeys_on=passkeys_on)
    def decoy_open() -> bool:
        from .duress import is_decoy

        session = getattr(controller, "session", None)
        return session is not None and is_decoy(session)

    def clear_for_decoy() -> None:
        if setting_on() and switch.applied is True:
            sync.clear()

    def on_unlock() -> None:
        if decoy_open():
            # A duress session: the real vault's names must leave Windows' picker (sub-plan 08). clear()
            # also forgets the digest, so the next real unlock syncs them back in full. ``switch.applied`` takes
            # PROVIDER_LOCK, which a running sync holds while it waits for the vault lock this unlock hook may hold
            # (page calls run under it): read it on the worker, never here (scan 3 suspicion 1, a 10 s stall).
            start(clear_for_decoy)
            return
        sync.schedule()

    controller.on_unlock.append(on_unlock)
    bus.listeners.append(sync.on_event)

    def at_start() -> None:
        with PROVIDER_LOCK:
            found = reconcile(setting_on(), run=run, is_available=is_available)
            if found == "registered":
                switch.mark_applied(True)
                if not passkeys_on():
                    sync.clear()  # passkeys off: Windows must not list the accounts
            elif found in ("not_registered", "unregistered"):
                switch.mark_applied(False)
                if found == "not_registered" and setting_on():
                    switch_off()  # reinstalled: never re-register without the user turning it on
        sync.schedule()

    start(at_start)

    def clear_still_wanted() -> bool:
        # Passkeys still off (or a duress session open) and the provider still registered by this app:
        # Windows must not list the accounts.
        return setting_on() and (not passkeys_on() or decoy_open()) and switch.applied is True

    def refresh_state() -> None:
        # Keeps the broker's view of Windows fresh while the setting is on (it ages out after MAX_AGE otherwise).
        if setting_on():
            REGISTRATION.refresh_later(run=run, is_available=is_available)
        # A failed --clear-cache (passkeys off) is retried on every tick until it works.
        sync.retry_clear(clear_still_wanted)

    _start_ticker(refresh_state)
    return switch
