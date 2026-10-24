"""Personal native-host entry; self-check intentionally excludes camera/ML payloads."""
import importlib
import sys

# Must import in the frozen host (LocalGateKeysNativeHost.spec bundles these).
NATIVE_MODULES = (
    "localvault.native_host", "localvault.protocol", "localvault.pipe_transport",
    "localvault.bridge_status", "localvault.browser_ancestry", "localvault.config",
    "localvault.distribution", "localvault.signature", "localvault.process_hardening",
)
WINDOWS_MODULES = ("win32api", "win32crypt", "win32file", "win32pipe", "win32security", "pywintypes", "psutil")
# Must NOT be bundled: the browser starts this process for every message (audit 2026-10-24 L-10).
TRIMMED = ("tkinter", "_tkinter", "PIL", "ssl", "_ssl", "asyncio", "cv2", "numpy", "webview", "pystray", "win32ui")


def check_native_build(hardening=None) -> int:
    try:
        if hardening is not None:
            from localvault.process_hardening import check_hardened

            problem = check_hardened(hardening)
            if problem:
                raise RuntimeError(problem)
        for name in NATIVE_MODULES + (WINDOWS_MODULES if sys.platform == "win32" else ()):
            importlib.import_module(name)
        if getattr(sys, "frozen", False):
            bundled = []
            for name in TRIMMED:
                try:
                    importlib.import_module(name)
                except ImportError:
                    continue
                bundled.append(name)
            if bundled:
                raise RuntimeError(f"native host bundles modules it must not: {', '.join(bundled)}")
    except Exception as exc:
        stream = sys.stderr or sys.stdout
        if stream is not None:
            print(f"Native host build check failed: {type(exc).__name__}: {exc}", file=stream)
        return 1
    if sys.stdout is not None:
        print("LocalGateKeys native host build check passed")
    return 0


if __name__ == "__main__":
    # First: DLL search order and image-load policy before pywin32/psutil load.
    from localvault.process_hardening import harden_process

    _hardening = harden_process()
    if sys.argv[1:] == ["--check-build"]:
        raise SystemExit(check_native_build(_hardening))
    from localvault.native_host import _log, main

    if not _hardening.ok:
        _log(f"process_hardening_incomplete {_hardening.describe()}")
    main()
