"""lgk.exe entry: the command line client. Its self-check keeps the vault and crypto packages out of this build."""
import importlib
import sys

# Must import in the frozen client (LocalGateKeysCli.spec bundles these).
CLI_MODULES = (
    "localvault.cli", "localvault.cli.main", "localvault.cli.run", "localvault.cli.inject", "localvault.cli.mcp_server",
    "localvault.pipe_transport", "localvault.bridge_status", "localvault.config",
    "localvault.distribution", "localvault.signature", "localvault.process_hardening",
)
WINDOWS_MODULES = ("win32api", "win32crypt", "win32file", "win32pipe", "win32security", "pywintypes", "psutil")
# Must NOT be bundled: lgk only forwards requests to the running app, it never holds a vault.
TRIMMED = ("tkinter", "_tkinter", "PIL", "ssl", "_ssl", "asyncio", "cv2", "numpy", "webview", "pystray", "win32ui",
           "cryptography", "cffi", "argon2", "localvault.vault", "localvault.local_clients")


def check_cli_build(hardening=None) -> int:
    try:
        if hardening is not None:
            from localvault.process_hardening import check_hardened

            problem = check_hardened(hardening)
            if problem:
                raise RuntimeError(problem)
        for name in CLI_MODULES + (WINDOWS_MODULES if sys.platform == "win32" else ()):
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
                raise RuntimeError(f"lgk bundles modules it must not: {', '.join(bundled)}")
    except Exception as exc:
        stream = sys.stderr or sys.stdout
        if stream is not None:
            print(f"lgk build check failed: {type(exc).__name__}: {exc}", file=stream)
        return 1
    if sys.stdout is not None:
        print("lgk build check passed")
    return 0


if __name__ == "__main__":
    from localvault.process_hardening import harden_process

    _hardening = harden_process()
    if sys.argv[1:] == ["--check-build"]:
        raise SystemExit(check_cli_build(_hardening))
    from localvault.cli.main import main

    for _stream in (sys.stdout, sys.stderr):
        try:
            _stream.reconfigure(encoding="utf-8")  # the same encoding the output masking matches
        except (AttributeError, ValueError, OSError):
            pass
    raise SystemExit(main())
