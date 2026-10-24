"""Non-interactive packaging checks; never open a vault, camera or auth prompt."""
from __future__ import annotations

import importlib
import sys
from pathlib import Path

BUILD_FEATURE = "rgb-face-local-liveness-autosave-1"


def check(*, require_camera: bool = False, require_license_keys: bool = False) -> None:
    if require_license_keys:
        from . import licensing
        if not licensing.LICENSE_KEYS:
            raise RuntimeError("LICENSE_KEYS is empty: generate the licence key (scripts/issue_license.py keygen) before a release build")
    modules = (
        "argon2.low_level", "cryptography.hazmat.primitives.ciphers.aead",
        "localvault.auth_task", "localvault.hello_unlock",
        "localvault.windows_hello", "localvault.agent", "localvault.native_host",
        "localvault.web.main", "localvault.api.bridge",
    )
    for name in modules:
        importlib.import_module(name)
    if sys.platform == "win32":
        for name in (
            "win32api", "win32con", "win32gui", "win32security", "pywinauto",
            "pystray", "PIL.Image", "webview",
            # The window's renderer: importing it loads pythonnet and WinForms and resolves
            # every WebView2 runtime folder, exactly what the app does before the first
            # window; a payload trimmed too far fails here instead of at the user's start.
            "webview.platforms.edgechromium",
        ):
            importlib.import_module(name)
        from .windows_hello import WindowsHello
        WindowsHello()  # Resolve system DLL/functions only; no provider or key is opened.

    package = Path(__file__).resolve().parent
    if getattr(sys, "frozen", False):
        assets = Path(sys._MEIPASS) / "assets"
    else:
        assets = package.parents[1] / "assets"
    for asset in (assets / "icons" / "localgatekeys.ico", assets / "icons" / "app_48.png"):
        if not asset.is_file():
            raise RuntimeError(f"Missing required application asset: {asset.name}")
    if not (package / "assets").is_dir():
        raise RuntimeError("Missing localvault package assets")
    if not (package / "assets" / "ui" / "index.html").is_file():
        raise RuntimeError("Missing the LocalGateKeys window (webui build: npm run build in webui)")

    if require_camera:
        cv2 = importlib.import_module("cv2")
        importlib.import_module("numpy")
        if not hasattr(cv2, "FaceDetectorYN") and not hasattr(cv2, "FaceDetectorYN_create"):
            raise RuntimeError("The installed OpenCV package lacks YuNet face detection support")
        if not hasattr(cv2, "FaceRecognizerSF") and not hasattr(cv2, "FaceRecognizerSF_create"):
            raise RuntimeError("The installed OpenCV package lacks SFace recognition support")
        from .face_models import require_model_files
        require_model_files()


def main(*, require_camera: bool = False, require_license_keys: bool = False) -> int:
    try:
        check(require_camera=require_camera, require_license_keys=require_license_keys)
    except Exception as exc:
        stream = sys.stderr or sys.stdout
        if stream is not None:
            print(f"Build check failed: {type(exc).__name__}: {exc}", file=stream)
        return 1
    if sys.stdout is not None:
        suffix = "+camera" if require_camera else ""
        print(f"LocalGateKeys build check passed: {BUILD_FEATURE}{suffix}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(require_camera=True))
