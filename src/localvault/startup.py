from __future__ import annotations

import os
import shutil
import sys
from pathlib import Path

RUN_KEY = r"Software\Microsoft\Windows\CurrentVersion\Run"
VALUE_NAME = "LocalGateKeys"
# Prototype-era Run values. They launched console entry points, which flashed a
# black command window at sign-in, so they are always removed.
LEGACY_VALUE_NAMES = ("LocalVaultPrototype", "LocalVault")


def agent_executable() -> Path:
    candidate = shutil.which("localgatekeys-agent") or shutil.which("localvault-agent")
    if candidate:
        return Path(candidate).resolve()
    scripts_dir = Path(sys.executable).resolve().parent
    for name in ("localgatekeys-agent.exe", "localgatekeys-agent", "localvault-agent.exe", "localvault-agent"):
        path = scripts_dir / name
        if path.exists():
            return path
    return Path(sys.argv[0]).resolve()


def startup_command() -> str:
    if getattr(sys, "frozen", False):
        return f'"{Path(sys.executable).resolve()}" --background'

    # Console entry points and direct source launches both need pythonw: their
    # Python console otherwise appears before the application can hide it.
    pythonw = Path(sys.executable).resolve().with_name("pythonw.exe")
    if pythonw.exists():
        return f'"{pythonw}" -m localvault.agent --background'

    agent = agent_executable()
    return f'"{agent}" --background'


def _set_packaged_startup_task(enabled: bool) -> None:
    """MSIX builds: switch the manifest's StartupTask instead of the Run key."""

    from . import msix_startup
    from .distribution import STARTUP_TASK_ID

    if not enabled:
        msix_startup.disable(STARTUP_TASK_ID)
        return
    state = msix_startup.request_enable(STARTUP_TASK_ID)
    if state in msix_startup.ENABLED_STATES:
        return
    if state == msix_startup.DISABLED_BY_USER:
        raise OSError("Start with Windows was turned off for LocalGateKeys in Windows. Turn it back on "
                      "in Settings > Apps > Startup (or Task Manager > Startup apps).")
    if state == msix_startup.DISABLED_BY_POLICY:
        raise OSError("Start with Windows is turned off for LocalGateKeys by your organization's policy.")
    raise OSError("Windows did not enable starting LocalGateKeys at sign-in.")


def set_start_with_windows(enabled: bool) -> None:
    if os.name != "nt":
        return
    from .distribution import uses_startup_task

    if uses_startup_task():
        _set_packaged_startup_task(enabled)
        return
    import winreg

    with winreg.CreateKey(winreg.HKEY_CURRENT_USER, RUN_KEY) as key:
        for legacy in LEGACY_VALUE_NAMES:
            try:
                winreg.DeleteValue(key, legacy)
            except FileNotFoundError:
                pass
        if enabled:
            winreg.SetValueEx(key, VALUE_NAME, 0, winreg.REG_SZ, startup_command())
        else:
            try:
                winreg.DeleteValue(key, VALUE_NAME)
            except FileNotFoundError:
                pass


def sync_start_with_windows(enabled: bool) -> None:
    """Make the Run entry match the setting and the running build.

    Called at launch so an entry written by an older build (missing
    ``--background`` or pointing at a console launcher) is repaired.
    Packaged builds have no Run entry to repair, and re-enabling their
    StartupTask here could undo a choice the user made in Windows.
    """
    from .distribution import uses_startup_task

    if uses_startup_task():
        return
    try:
        set_start_with_windows(enabled)
    except OSError:
        pass


def is_start_with_windows_enabled() -> bool:
    if os.name != "nt":
        return False
    from .distribution import STARTUP_TASK_ID, uses_startup_task

    if uses_startup_task():
        from . import msix_startup

        try:
            return msix_startup.state(STARTUP_TASK_ID) in msix_startup.ENABLED_STATES
        except OSError:
            return False
    import winreg

    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, RUN_KEY) as key:
            value, _ = winreg.QueryValueEx(key, VALUE_NAME)
    except FileNotFoundError:
        return False
    return str(value).strip() == startup_command()
