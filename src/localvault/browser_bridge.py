from __future__ import annotations

"""Windows native-messaging registration for the packaged LocalGateKeys app.

This module is intentionally independent from the repository-only PowerShell
repair script.  The production installer and the in-app Repair bridge action
both call the same code, so a packaged installation can repair itself without
requiring source files or a virtual environment.
"""

import hashlib
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
            if current is not None:
                # Inside an MSIX package, changing an existing HKCU value is
                # copy-on-write into the package's private hive: the browser
                # would keep the real value and this process would see a
                # private one from then on. Never write over it. The value is
                # the same data-directory path in every build, so a matching
                # value (e.g. from an earlier Inno Setup install) is final.
                if not _same_registry_path(current, str(path)):
                    conflicts.append(root)
                continue
        with winreg.CreateKey(winreg.HKEY_CURRENT_USER, key_path) as key:
            winreg.SetValueEx(key, None, 0, winreg.REG_SZ, str(path))
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


def _unregister_manifest() -> None:
    import winreg

    for root in (*_BROWSER_REGISTRY_ROOTS, _FIREFOX_REGISTRY_ROOT):
        key_path = f"{root}\\{NATIVE_HOST_NAME}"
        try:
            winreg.DeleteKey(winreg.HKEY_CURRENT_USER, key_path)
        except FileNotFoundError:
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
    firefox_manifest_path = _firefox_manifest_path()
    atomic_write_json(firefox_manifest_path, _firefox_manifest_payload(launch_path))

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
    for path in (_manifest_path(), _firefox_manifest_path(), install_config_path()):
        try:
            path.unlink()
        except FileNotFoundError:
            pass


def ensure_packaged_registration() -> bool:
    """Register the bridge at launch of an MSIX build; no-op otherwise.

    An MSIX package runs no installer code, so there is no install-time
    ``--repair-browser-bridge``. Repairing on every launch also re-pins the
    host after a Store update moved the package to a new versioned directory.
    The data directory is excluded from AppData virtualization and new HKCU
    keys are written unvirtualized (see build-msix/AppxManifest.xml.in and
    docs/store/MSIX_FEASIBILITY.md), so the browsers see both. Returns whether
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
