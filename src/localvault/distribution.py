"""Distribution channel of the running build: direct download or Microsoft Store.

The same frozen executables ship in both the Inno Setup installer and the MSIX
package. What differs is decided at runtime:

* **Store build flag** - ``scripts/build_msix_package.ps1`` places
  :data:`STORE_MARKER_NAME` next to ``LocalGateKeys.exe`` in the package
  layout. MSIX package files are read-only and covered by the package
  signature, so the flag cannot be added to or removed from an installed
  package without breaking it.
* **Package identity** - a frozen build launched from an MSIX package (Store or
  a sideloaded test package) has a package family name. Package identity, not
  the flag, decides how Windows integration works (StartupTask instead of the
  Run key, an app execution alias for the native host), because those follow
  from how the OS runs the process.

The in-app updater is disabled whenever either is true: the Store (or, for a
sideloaded package, the next sideload) replaces the package; an installer
downloaded by the app could not update it.

Source runs never count as packaged, even under the Microsoft Store Python,
whose interpreter has a package identity of its own.
"""
from __future__ import annotations

import os
import re
import sys
from pathlib import Path

STORE_MARKER_NAME = "LocalGateKeys.store-build"
# Must match AppxManifest.xml.in: the alias Chromium launches, the
# Application Ids, and the StartupTask id.
NATIVE_HOST_ALIAS = "LocalGateKeysNativeHost.exe"
NATIVE_HOST_IMAGE = Path("NativeHost") / "LocalGateKeysNativeHost.exe"
CLI_ALIAS = "lgk.exe"
CLI_IMAGE = Path("cli") / "lgk.exe"
STARTUP_TASK_ID = "LocalGateKeysStartup"

CHANNEL_DIRECT = "direct"
CHANNEL_STORE = "store"
CHANNEL_SIDELOAD = "msix-sideload"

_APPMODEL_ERROR_NO_PACKAGE = 15700
_ERROR_INSUFFICIENT_BUFFER = 122


def _is_frozen() -> bool:
    return bool(getattr(sys, "frozen", False))


def _current_package_string(function_name: str) -> str | None:
    """Call ``GetCurrentPackageFamilyName``/``GetCurrentPackagePath``; ``None`` when unpackaged."""

    if os.name != "nt":
        return None
    try:
        import ctypes
        import ctypes.wintypes as wintypes

        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        function = getattr(kernel32, function_name)
        function.argtypes = [ctypes.POINTER(wintypes.UINT), wintypes.LPWSTR]
        function.restype = wintypes.LONG
        length = wintypes.UINT(0)
        result = function(ctypes.byref(length), None)
        if result == _APPMODEL_ERROR_NO_PACKAGE or result != _ERROR_INSUFFICIENT_BUFFER or not length.value:
            return None
        buffer = ctypes.create_unicode_buffer(length.value)
        if function(ctypes.byref(length), buffer) != 0:
            return None
        return buffer.value or None
    except (OSError, AttributeError, ValueError):
        return None


def package_family_name() -> str | None:
    """Package family name of this frozen build, or ``None`` when not packaged."""

    if not _is_frozen():
        return None
    return _current_package_string("GetCurrentPackageFamilyName")


def package_root() -> Path | None:
    """Install directory of the running package (versioned, read-only), or ``None``."""

    if not _is_frozen():
        return None
    value = _current_package_string("GetCurrentPackagePath")
    return Path(value) if value else None


def is_packaged() -> bool:
    return package_family_name() is not None


def store_marker_path() -> Path | None:
    if not _is_frozen():
        return None
    return Path(sys.executable).resolve().parent / STORE_MARKER_NAME


def is_store_build() -> bool:
    marker = store_marker_path()
    return marker is not None and marker.is_file()


def channel() -> str:
    if is_store_build():
        return CHANNEL_STORE
    if is_packaged():
        return CHANNEL_SIDELOAD
    return CHANNEL_DIRECT


def is_installer_build() -> bool:
    """The Inno Setup build: frozen, unpackaged, on Windows (never a source run)."""

    return os.name == "nt" and _is_frozen() and channel() == CHANNEL_DIRECT


def self_update_enabled() -> bool:
    """Whether the signed release-feed check and installer download may run."""

    return channel() == CHANNEL_DIRECT


def uses_startup_task() -> bool:
    """Packaged builds start with Windows through the manifest's StartupTask."""

    return is_packaged()


def native_host_alias_path() -> Path | None:
    """Stable, version-independent path browsers launch for a packaged native host.

    Windows creates ``%LOCALAPPDATA%\\Microsoft\\WindowsApps\\<family name>\\<alias>``
    for every ``windows.appExecutionAlias`` of an installed package. Unlike the
    package directory it does not change when the Store updates the app, and
    launching it gives the host the package identity (and the same
    unvirtualized data directory) as the agent.
    """

    family = package_family_name()
    if not family:
        return None
    local = os.environ.get("LOCALAPPDATA") or str(Path.home() / "AppData" / "Local")
    return Path(local) / "Microsoft" / "WindowsApps" / family / NATIVE_HOST_ALIAS


FIREFOX_HOST_LAUNCHER = "LocalGateKeysNativeHost.firefox.cmd"
_SAFE_PATH_PART = re.compile(r"[A-Za-z0-9._-]+")


def firefox_native_host_launcher_path() -> Path | None:
    """Batch file Firefox launches for a packaged host, next to its manifest.

    Firefox starts a host executable directly with explicit stdio handles; when
    that executable is the execution alias (a reparse point), the packaged host
    it starts never receives those handles and Firefox reports an unexpected
    error. Chromium goes through ``cmd.exe /c``, which works. Firefox runs a
    ``.cmd`` host through ``cmd.exe /s /c`` too, so the packaged Firefox
    manifest names this launcher, which starts the alias (keeping the package
    identity and its data directory). ``None`` when not packaged.
    """

    if package_family_name() is None:
        return None
    from .config import data_dir

    return data_dir() / FIREFOX_HOST_LAUNCHER


def firefox_native_host_launcher_script() -> str | None:
    """Exact content of the Firefox launcher, or ``None`` when not packaged.

    ASCII only: the alias is named through ``%LOCALAPPDATA%`` (expanded by
    cmd.exe as Unicode, never re-parsed), so user names with spaces, non-ASCII
    letters or ``%``/``&`` need no quoting tricks. The package family name and
    alias are checked to be plain path segments, so nothing in the file comes
    from outside this build. Delayed expansion is off so ``!`` stays literal.
    """

    family = package_family_name()
    if not family:
        return None
    if not (_SAFE_PATH_PART.fullmatch(family) and _SAFE_PATH_PART.fullmatch(NATIVE_HOST_ALIAS)):
        return None
    return ("@setlocal DisableDelayedExpansion\r\n"
            f'@"%LOCALAPPDATA%\\Microsoft\\WindowsApps\\{family}\\{NATIVE_HOST_ALIAS}" %*\r\n')


def _is_our_firefox_launcher(path: str) -> bool:
    launcher = firefox_native_host_launcher_path()
    script = firefox_native_host_launcher_script()
    if launcher is None or script is None or not _same_path(path, str(launcher)):
        return False
    try:
        return launcher.read_bytes() == script.encode("ascii")
    except OSError:
        return False


def packaged_native_host_image() -> Path | None:
    """The real native-host executable inside the running package."""

    root = package_root()
    return root / NATIVE_HOST_IMAGE if root else None


def _same_path(left: str, right: str) -> bool:
    return os.path.normcase(os.path.abspath(left)) == os.path.normcase(os.path.abspath(right))


def resolve_native_host_path(path: str) -> str:
    """Map this package's execution alias to the executable it launches.

    A process started through the alias reports the package executable as its
    image, and the alias itself is a reparse point that cannot be hashed, so
    the pipe pin and diagnostics compare against the resolved image. The
    Firefox launcher batch file (see :func:`firefox_native_host_launcher_path`)
    maps to the same image, but only while its content is exactly the launcher
    this build writes. Any other path, and every path in an unpackaged build,
    is returned unchanged.
    """

    if not path:
        return path
    alias = native_host_alias_path()
    if alias is None:
        return path
    if not _same_path(path, str(alias)) and not _is_our_firefox_launcher(path):
        return path
    image = packaged_native_host_image()
    return str(image) if image is not None else path
