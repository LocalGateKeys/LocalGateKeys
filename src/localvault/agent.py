"""LocalGateKeys entry point (``python -m localvault.agent``): one agent per Windows session, WebView2 UI.

Start with Windows, the installers and the packaged build all start this module. ``--background`` starts the
window hidden in the tray; the two browser-bridge flags repair or remove the native-messaging registration.
"""

from __future__ import annotations

import os
import sys

ERROR_ALREADY_EXISTS = 183
ALREADY_RUNNING = "LocalGateKeys is already running. Open it from the system tray."


def _acquire_windows_instance_mutex() -> int | None:
    """Return a held per-session mutex handle, or None when another agent exists."""

    if os.name != "nt":
        return 1
    import ctypes
    from ctypes import wintypes

    kernel32 = ctypes.windll.kernel32
    create_mutex = kernel32.CreateMutexW
    create_mutex.argtypes = [wintypes.LPVOID, wintypes.BOOL, wintypes.LPCWSTR]
    create_mutex.restype = wintypes.HANDLE
    close_handle = kernel32.CloseHandle
    close_handle.argtypes = [wintypes.HANDLE]
    close_handle.restype = wintypes.BOOL
    raw_handle = create_mutex(None, False, "Local\\LocalGateKeysPrototype.Agent")
    handle = int(raw_handle or 0)
    if not handle:
        raise OSError("Windows could not create the LocalGateKeys instance mutex")
    if int(kernel32.GetLastError()) == ERROR_ALREADY_EXISTS:
        close_handle(handle)
        return None
    return handle


def _release_windows_instance_mutex(handle: int | None) -> None:
    if os.name == "nt" and handle:
        import ctypes
        from ctypes import wintypes

        close_handle = ctypes.windll.kernel32.CloseHandle
        close_handle.argtypes = [wintypes.HANDLE]
        close_handle.restype = wintypes.BOOL
        close_handle(handle)


def _tell_already_running(background: bool) -> None:
    print(ALREADY_RUNNING, file=sys.stderr)
    if os.name == "nt" and not background:
        import ctypes

        ctypes.windll.user32.MessageBoxW(None, ALREADY_RUNNING, "LocalGateKeys", 0x40)  # MB_ICONINFORMATION


def _install_from_link(link: str) -> bool:
    """Confirm and install the licence in a ``localgatekeys://install-licence/`` link (Windows dialogs)."""
    from .licence_link import handle

    def ask(text: str) -> bool:
        if os.name != "nt":
            return False
        import ctypes

        mb_yesno, mb_iconquestion, mb_setforeground, idyes = 0x4, 0x20, 0x10000, 6
        return ctypes.windll.user32.MessageBoxW(
            None, text, "LocalGateKeys", mb_yesno | mb_iconquestion | mb_setforeground) == idyes

    def tell(text: str) -> None:
        print(text, file=sys.stderr)
        if os.name == "nt":
            import ctypes

            ctypes.windll.user32.MessageBoxW(None, text, "LocalGateKeys", 0x30 | 0x10000)  # MB_ICONWARNING

    return handle(link, ask, tell)


def sweep_open_copies(profile_dir: str) -> int:
    """``--sweep-open-copies``: after exit, delete decrypted copies once their apps close them.

    Only a folder inside the LocalGateKeys data folder is accepted; anything else is refused (exit 2).
    """
    from pathlib import Path

    from . import open_copy_watch
    from .config import data_dir

    try:
        target = Path(profile_dir).resolve()
        root = data_dir().resolve()
    except OSError:
        return 2
    if target == root or root not in target.parents:
        return 2
    return open_copy_watch.run_exit_sweeper(target)


def main() -> None:
    import argparse

    from .ui_assets import enable_dpi_awareness

    enable_dpi_awareness()
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--background", action="store_true")
    parser.add_argument("--repair-browser-bridge", action="store_true")
    parser.add_argument("--unregister-browser-bridge", action="store_true")
    parser.add_argument("--sweep-open-copies", default=None)
    parser.add_argument("--web-ui", action="store_true")  # accepted for old shortcuts; the WebView UI is the only UI
    args, _unknown = parser.parse_known_args()

    if args.sweep_open_copies:
        raise SystemExit(sweep_open_copies(args.sweep_open_copies))
    if args.repair_browser_bridge:
        from .browser_bridge import repair_browser_bridge

        repair_browser_bridge()
        return
    if args.unregister_browser_bridge:
        from .browser_bridge import unregister_browser_bridge

        unregister_browser_bridge()
        return

    from .licence_link import find_link

    link = find_link(_unknown)
    installed = False
    if link is not None:
        installed = _install_from_link(link)
    from . import share_open

    shared = share_open.find_share_file(_unknown)
    if shared is not None:
        share_open.note(shared)  # the running app (or this one, once unlocked) takes it
    mutex = _acquire_windows_instance_mutex()
    if mutex is None:
        if shared is not None:
            share_open.signal_running_app()
        elif link is None:
            _tell_already_running(args.background)
        elif installed:
            from .licence_link import signal_running_app

            signal_running_app()
        return
    try:
        from .web.main import run as run_web_ui

        run_web_ui()
    finally:
        _release_windows_instance_mutex(mutex)


if __name__ == "__main__":
    main()
