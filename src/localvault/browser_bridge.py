from __future__ import annotations

"""Windows native-messaging registration for the packaged LocalGateKeys app.

This module is intentionally independent from the repository-only PowerShell
repair script.  The production installer and the in-app Repair bridge action
both call the same code, so a packaged installation can repair itself without
requiring source files or a virtual environment.
"""

import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

from . import distribution
from .config import (
    DEV_ID_DEVELOPER_INSTALL,
    DEV_ID_OPT_IN,
    EXTENSION_ID,
    NATIVE_HOST_NAME,
    ExtensionTrust,
    atomic_write_bytes,
    atomic_write_json,
    data_dir,
    extension_trust,
    install_config_path,
)
from .native_host import FIREFOX_EXTENSION_ID
from .version import BRIDGE_CONFIG_VERSION, RELEASE_ID
from .winpaths import current_user_sid, system32

# Chromium browsers share one manifest format (allowed_origins); Firefox uses
# allowed_extensions with the Gecko add-on id and its own registry root.
_BROWSER_REGISTRY_ROOTS = (
    r"Software\Google\Chrome\NativeMessagingHosts",
    r"Software\Microsoft\Edge\NativeMessagingHosts",
)
_FIREFOX_REGISTRY_ROOT = r"Software\Mozilla\NativeMessagingHosts"


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest().upper()


def _native_host_executable() -> Path:
    """Resolve the native host for packaged and repository executions."""

    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent / "NativeHost" / "LocalGateKeysNativeHost.exe"

    root = Path(__file__).resolve().parents[2]
    candidates = (
        root / ".venv" / "Scripts" / "localgatekeys-native-host.exe",
        root / ".venv" / "Scripts" / "LocalGateKeysNativeHost.exe",
        root / "dist-personal" / "LocalGateKeysNativeHost" / "LocalGateKeysNativeHost.exe",
    )
    for candidate in candidates:
        if candidate.is_file():
            return candidate.resolve()
    return candidates[0]


def _manifest_path() -> Path:
    return data_dir() / f"{NATIVE_HOST_NAME}.json"


def _firefox_manifest_path() -> Path:
    return data_dir() / f"{NATIVE_HOST_NAME}.firefox.json"


def _allowed_origins(extension_id: str = EXTENSION_ID, trust: ExtensionTrust | None = None) -> list[str]:
    """The IDs this build trusts (see ``config.extension_trust``), requested ID first.

    One manifest serves Chrome and Edge. Frozen builds list only the Chrome
    Web Store and Edge Add-ons IDs; the developer ID is added for source runs,
    after an explicit developer opt-in, or while a store ID is unassigned. An
    explicitly requested ID outside that list is kept only for source runs
    and the developer opt-in.
    """

    trust = trust or extension_trust()
    ids = list(trust.chromium_ids)
    if extension_id in ids:
        ids.remove(extension_id)
        ids.insert(0, extension_id)
    elif trust.developer_id_reason in (DEV_ID_DEVELOPER_INSTALL, DEV_ID_OPT_IN):
        ids.insert(0, extension_id)
    return [f"chrome-extension://{value}/" for value in ids]


def _manifest_payload(host_executable: Path, extension_id: str = EXTENSION_ID,
                      trust: ExtensionTrust | None = None) -> dict[str, Any]:
    return {
        "name": NATIVE_HOST_NAME,
        "description": "LocalGateKeys browser bridge",
        "path": str(host_executable),
        "type": "stdio",
        "allowed_origins": _allowed_origins(extension_id, trust),
    }


def _firefox_manifest_payload(host_executable: Path, firefox_id: str = FIREFOX_EXTENSION_ID) -> dict[str, Any]:
    return {
        "name": NATIVE_HOST_NAME,
        "description": "LocalGateKeys browser bridge",
        "path": str(host_executable),
        "type": "stdio",
        "allowed_extensions": [firefox_id],
    }


def _write_firefox_launcher() -> Path | None:
    """Write the packaged Firefox launcher batch file; ``None`` when not packaged."""

    launcher = distribution.firefox_native_host_launcher_path()
    script = distribution.firefox_native_host_launcher_script()
    if launcher is None or script is None:
        return None
    atomic_write_bytes(launcher, script.encode("ascii"))
    return launcher


def _secure_data_directory(path: Path) -> None:
    """Apply current-user-only DACLs when possible without requiring elevation.

    ``icacls.exe`` is launched from System32 by absolute path (a bare name
    would resolve through the app and current directories first) and the grant
    names the process token's SID, not the environment-derived user name.
    """

    if os.name != "nt":
        return
    sid = current_user_sid()
    if not sid:
        # Without a trustworthy SID, removing inheritance could lock the user
        # out; leave the inherited per-user profile ACL in place.
        return
    icacls = system32("icacls.exe")
    flags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
    try:
        subprocess.run(
            [icacls, str(path), "/grant:r", f"*{sid}:(OI)(CI)F"],  # noqa: S603 - fixed System32 path, no shell
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=30,
            creationflags=flags,
        )
        subprocess.run(
            [icacls, str(path), "/inheritance:r"],  # noqa: S603 - fixed System32 path, no shell
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=30,
            creationflags=flags,
        )
    except Exception:
        # Registration remains useful even if ACL tightening is unavailable.
        # Existing LocalGateKeys data-directory protections still apply.
        pass


def _register_manifest(manifest_path: Path, firefox_manifest_path: Path | None = None) -> None:
    import winreg

    targets = [(root, manifest_path) for root in _BROWSER_REGISTRY_ROOTS]
    if firefox_manifest_path is not None:
        targets.append((_FIREFOX_REGISTRY_ROOT, firefox_manifest_path))
    packaged = distribution.is_packaged()
    conflicts: list[str] = []
    for root, path in targets:
        key_path = f"{root}\\{NATIVE_HOST_NAME}"
        if packaged:
            current = _registered_value(winreg, key_path)
            if current is not None and _same_registry_path(current, str(path)):
                # The value is the same data-directory path in every build, so
                # a matching value (e.g. from an Inno Setup install) is final,
                # unless the package's view differs from the real HKCU.
                if _real_value_matches(key_path, path) is not False:
                    continue
            elif current is not None and _is_working_manifest(current):
                # Another working LocalGateKeys install owns the registration
                # (e.g. Inno Setup with its own data folder): never take it over.
                conflicts.append(root)
                continue
            # Missing or stale (manifest gone, not ours, or launcher gone):
            # write our own computed path, then check what the browsers see.
            _write_registry_value(winreg, key_path, path)
            if _real_value_matches(key_path, path) is False:
                # Older Windows 11 builds made this write private to the
                # package; write it from a process outside the package.
                _run_reg_outside_package("add", f"HKCU\\{key_path}", "/ve", "/t", "REG_SZ", "/d", str(path), "/f")
                if _real_value_matches(key_path, path) is False:
                    conflicts.append(root)
            continue
        _write_registry_value(winreg, key_path, path)
    if conflicts:
        raise OSError("The browser registration for LocalGateKeys points at a different manifest under "
                      + ", ".join(conflicts) + ". Remove the other LocalGateKeys installation, then start "
                      "LocalGateKeys again.")


def _registered_value(winreg: Any, key_path: str) -> str | None:
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path) as key:
            value = winreg.QueryValue(key, None)
    except FileNotFoundError:
        return None
    return str(value) if value else None


def _same_registry_path(left: str, right: str) -> bool:
    return os.path.normcase(os.path.abspath(left)) == os.path.normcase(os.path.abspath(right))


def _write_registry_value(winreg: Any, key_path: str, path: Path) -> None:
    with winreg.CreateKey(winreg.HKEY_CURRENT_USER, key_path) as key:
        winreg.SetValueEx(key, None, 0, winreg.REG_SZ, str(path))


def _is_working_manifest(value: str) -> bool:
    """True when ``value`` names a readable LocalGateKeys manifest whose launcher exists.

    The file is only read, never run; anything else makes the value stale.
    """

    try:
        manifest = Path(value)
        data = json.loads(manifest.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return False
    if not isinstance(data, dict) or data.get("name") != NATIVE_HOST_NAME:
        return False
    launcher = data.get("path")
    if not isinstance(launcher, str) or not launcher:
        return False
    launcher_path = Path(launcher)
    if not launcher_path.is_absolute():
        # Chrome resolves a relative path against the manifest's folder.
        launcher_path = manifest.parent / launcher_path
    # lexists: an app execution alias is a reparse point stat() cannot follow.
    return os.path.lexists(launcher_path)


def _real_value_matches(key_path: str, path: Path) -> bool | None:
    """Whether the real HKCU value (what browsers read) equals ``path``.

    Asked from a reg.exe outside the package, since this process may see a
    package-private copy. Exact match, case-insensitive; reg.exe's printed
    output is not parsed because it loses non-ASCII characters. ``None`` when
    the check could not run. No ``/ve``: combined with ``/f`` it ignores the
    search and always succeeds (measured); the key holds only this one value.
    """

    code = _run_reg_outside_package("query", f"HKCU\\{key_path}", "/f", str(path), "/d", "/e")
    if code is None or code not in (0, 1):
        return None
    return code == 0


_PROC_THREAD_ATTRIBUTE_DESKTOP_APP_POLICY = 0x00020012
# Measured on Windows 11 26300: the created process itself runs outside the
# package (it has no package identity), and so does everything it starts.
_DESKTOP_APP_BREAKAWAY_ENABLE_PROCESS_TREE = 0x01


def _run_reg_outside_package(*args: str) -> int | None:
    """Run System32 ``reg.exe`` outside the MSIX container; its exit code, or ``None``.

    Only the fixed native-messaging key paths and this app's own manifest
    paths are passed in. No shell is involved and no handles are inherited.
    """

    if os.name != "nt":
        return None
    try:
        import ctypes
        import ctypes.wintypes as wt

        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

        class STARTUPINFOW(ctypes.Structure):
            _fields_ = [("cb", wt.DWORD), ("lpReserved", wt.LPWSTR), ("lpDesktop", wt.LPWSTR),
                        ("lpTitle", wt.LPWSTR), ("dwX", wt.DWORD), ("dwY", wt.DWORD), ("dwXSize", wt.DWORD),
                        ("dwYSize", wt.DWORD), ("dwXCountChars", wt.DWORD), ("dwYCountChars", wt.DWORD),
                        ("dwFillAttribute", wt.DWORD), ("dwFlags", wt.DWORD), ("wShowWindow", wt.WORD),
                        ("cbReserved2", wt.WORD), ("lpReserved2", ctypes.c_void_p), ("hStdInput", wt.HANDLE),
                        ("hStdOutput", wt.HANDLE), ("hStdError", wt.HANDLE)]

        class STARTUPINFOEXW(ctypes.Structure):
            _fields_ = [("StartupInfo", STARTUPINFOW), ("lpAttributeList", ctypes.c_void_p)]

        class PROCESS_INFORMATION(ctypes.Structure):
            _fields_ = [("hProcess", wt.HANDLE), ("hThread", wt.HANDLE), ("dwProcessId", wt.DWORD),
                        ("dwThreadId", wt.DWORD)]

        init_list = kernel32.InitializeProcThreadAttributeList
        init_list.argtypes = [ctypes.c_void_p, wt.DWORD, wt.DWORD, ctypes.POINTER(ctypes.c_size_t)]
        update_list = kernel32.UpdateProcThreadAttribute
        update_list.argtypes = [ctypes.c_void_p, wt.DWORD, ctypes.c_size_t, ctypes.c_void_p, ctypes.c_size_t,
                                ctypes.c_void_p, ctypes.c_void_p]
        delete_list = kernel32.DeleteProcThreadAttributeList
        delete_list.argtypes = [ctypes.c_void_p]
        create = kernel32.CreateProcessW
        create.argtypes = [wt.LPCWSTR, wt.LPWSTR, ctypes.c_void_p, ctypes.c_void_p, wt.BOOL, wt.DWORD,
                           ctypes.c_void_p, wt.LPCWSTR, ctypes.c_void_p, ctypes.c_void_p]
        kernel32.WaitForSingleObject.argtypes = [wt.HANDLE, wt.DWORD]
        kernel32.GetExitCodeProcess.argtypes = [wt.HANDLE, ctypes.POINTER(wt.DWORD)]
        kernel32.TerminateProcess.argtypes = [wt.HANDLE, wt.UINT]
        kernel32.CloseHandle.argtypes = [wt.HANDLE]

        size = ctypes.c_size_t(0)
        init_list(None, 1, 0, ctypes.byref(size))
        attributes = ctypes.create_string_buffer(size.value)
        if not init_list(attributes, 1, 0, ctypes.byref(size)):
            return None
        try:
            policy = wt.DWORD(_DESKTOP_APP_BREAKAWAY_ENABLE_PROCESS_TREE)
            if not update_list(attributes, 0, _PROC_THREAD_ATTRIBUTE_DESKTOP_APP_POLICY, ctypes.byref(policy),
                               ctypes.sizeof(policy), None, None):
                return None
            startup = STARTUPINFOEXW()
            startup.StartupInfo.cb = ctypes.sizeof(STARTUPINFOEXW)
            startup.lpAttributeList = ctypes.cast(attributes, ctypes.c_void_p)
            info = PROCESS_INFORMATION()
            reg = system32("reg.exe")
            command_line = ctypes.create_unicode_buffer(subprocess.list2cmdline([reg, *args]))
            flags = 0x00080000 | getattr(subprocess, "CREATE_NO_WINDOW", 0x08000000)  # EXTENDED_STARTUPINFO_PRESENT
            if not create(reg, command_line, None, None, False, flags, None, None,
                          ctypes.byref(startup), ctypes.byref(info)):
                return None
        finally:
            delete_list(attributes)
        try:
            if kernel32.WaitForSingleObject(info.hProcess, 15000) != 0:
                kernel32.TerminateProcess(info.hProcess, 1)
                return None
            code = wt.DWORD()
            if not kernel32.GetExitCodeProcess(info.hProcess, ctypes.byref(code)):
                return None
            return int(code.value)
        finally:
            kernel32.CloseHandle(info.hThread)
            kernel32.CloseHandle(info.hProcess)
    except Exception:
        return None


def _unregister_manifest() -> None:
    import winreg

    for root in (*_BROWSER_REGISTRY_ROOTS, _FIREFOX_REGISTRY_ROOT):
        key_path = f"{root}\\{NATIVE_HOST_NAME}"
        try:
            winreg.DeleteKey(winreg.HKEY_CURRENT_USER, key_path)
        except FileNotFoundError:
            # Best-effort file/OS step: failure is harmless here, so it is ignored.
            pass


def _install_mode() -> str:
    if distribution.is_packaged():
        return "msix"
    return "installed" if getattr(sys, "frozen", False) else "repository"


def repair_browser_bridge(extension_id: str = EXTENSION_ID) -> Path:
    """Create the manifest, pin the host binary, and register Chrome/Edge."""

    if os.name != "nt":
        raise OSError("Browser bridge registration is available only on Windows")
    if len(extension_id) != 32 or any(ch < "a" or ch > "p" for ch in extension_id):
        raise ValueError("Invalid Chromium extension ID")

    host_executable = _native_host_executable()
    if not host_executable.is_file():
        raise FileNotFoundError(f"Native host executable is missing: {host_executable}")

    # Browsers launch a packaged host through its execution alias: the package
    # directory is versioned (it changes on every Store update) and is not a
    # path other programs should start directly. The pins below keep the real
    # executable, which is what the launched process reports as its image.
    launch_path = distribution.native_host_alias_path() or host_executable

    target_dir = data_dir()
    _secure_data_directory(target_dir)
    # Rewritten on every repair: the installer runs it on each install and
    # upgrade, and MSIX builds at every launch, so an older manifest that
    # still lists the developer ID is replaced with this build's list. The
    # native host checks its caller against the same list on its own.
    trust = extension_trust()
    manifest_path = _manifest_path()
    atomic_write_json(manifest_path, _manifest_payload(launch_path, extension_id, trust))
    # Firefox cannot start the alias directly (the packaged host would not get
    # its stdio pipes); it starts a fixed batch file that runs the alias.
    firefox_launch_path = _write_firefox_launcher() or launch_path
    firefox_manifest_path = _firefox_manifest_path()
    atomic_write_json(firefox_manifest_path, _firefox_manifest_payload(firefox_launch_path))

    config = {
        "version": BRIDGE_CONFIG_VERSION,
        "bridge_revision": RELEASE_ID,
        "product": "LocalGateKeys",
        "scope": "current_user",
        "mode": _install_mode(),
        "install_root": str(Path(sys.executable).resolve().parent if getattr(sys, "frozen", False) else Path(__file__).resolve().parents[2]),
        "allowed_extension_origins": _allowed_origins(extension_id, trust),
        "allowed_firefox_extensions": [FIREFOX_EXTENSION_ID],
        # Report why the developer extension ID is (still) trusted, and which
        # store listings have no assigned ID yet. Diagnostics only: the native
        # host never widens its list from this file.
        "developer_extension_id": trust.developer_id_reason,
        "unassigned_store_extension_ids": list(trust.missing_store_ids),
        "native_host_path": str(host_executable),
        "native_host_sha256": _sha256(host_executable),
    }
    if launch_path != host_executable:
        config["native_host_launch_path"] = str(launch_path)
    if firefox_launch_path != launch_path:
        config["firefox_native_host_launch_path"] = str(firefox_launch_path)
    if not getattr(sys, "frozen", False):
        # Development: the pipe gives the cli scope to this lgk.exe (frozen builds use <install dir>\cli\lgk.exe).
        config["cli_path"] = str(Path(__file__).resolve().parents[2] / "dist-personal" / "lgk" / "lgk.exe")
    atomic_write_json(install_config_path(), config)
    # Last, so a registration conflict (packaged builds raise) still leaves the
    # manifests and pins above consistent with each other.
    _register_manifest(manifest_path, firefox_manifest_path)
    return manifest_path


def unregister_browser_bridge() -> None:
    """Remove browser registration/bridge metadata without touching vault data."""

    if os.name != "nt":
        return
    _unregister_manifest()
    paths = [_manifest_path(), _firefox_manifest_path(), install_config_path()]
    launcher = distribution.firefox_native_host_launcher_path()
    if launcher is not None:
        paths.append(launcher)
    for path in paths:
        try:
            path.unlink()
        except FileNotFoundError:
            # Best-effort file/OS step: failure is harmless here, so it is ignored.
            pass


def ensure_packaged_registration() -> bool:
    """Register the bridge at launch of an MSIX build; no-op otherwise.

    An MSIX package runs no installer code, so there is no install-time
    ``--repair-browser-bridge``. Repairing on every launch also re-pins the
    host after a Store update moved the package to a new versioned directory.
    The data directory is excluded from AppData virtualization and new HKCU
    keys are written unvirtualized (see build-msix/AppxManifest.xml.in),
    so the browsers see both. Returns whether
    the registration completed.
    """

    if not distribution.is_packaged():
        return False
    try:
        repair_browser_bridge()
    except Exception:
        # Never block the app from starting; Connections can repair it later.
        return False
    return True
