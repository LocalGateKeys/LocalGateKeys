# -*- mode: python ; coding: utf-8 -*-
from pathlib import Path
import sys

from PyInstaller.utils.hooks import collect_submodules

ROOT = Path(SPECPATH).resolve()
sys.path.insert(0, str(ROOT / 'src'))
sys.path.insert(0, str(ROOT / 'build-personal'))
from lgk_version_info import version_info  # noqa: E402

hiddenimports = collect_submodules('localvault')
hiddenimports += ['cv2', 'numpy']

EXCLUDES = [
    'tkinter', '_tkinter',  # the WebView2 window replaced Tk
    # numpy's own test helper (its hook hidden-imports it; nothing at run time does).
    'numpy._core._multiarray_tests',
    # Pillow decoders the app never needs: every Image.open is PNG/JPEG/ICO,
    # and a plugin that is present is probed on untrusted profile photos.
    'PIL.AvifImagePlugin', 'PIL._avif', 'PIL.WebPImagePlugin', 'PIL._webp', 'PIL.ImageTk', 'PIL._imagingtk',
]
# Not excluded: pythonwin/win32ui (pywinauto.base_wrapper imports it at module
# level, and localvault.uia uses pywinauto).

# Collected files this x64 build never loads, matched on the destination path
# (lower case, forward slashes) and dropped after Analysis:
# - OpenCV's FFmpeg plugin: only file/URL capture and video writing use it;
#   the camera opens a device index through DirectShow/Media Foundation and QR
#   images decode through imgcodecs.
# - x86/arm64 copies: pywebview, its WebView2 SDK and clr_loader pick the
#   loader matching the (x64) process.
DROP_PAYLOAD = [
    'cv2/opencv_videoio_ffmpeg',
    'webview/lib/runtimes/win-x86/',
    'webview/lib/runtimes/win-arm64/',
    'webview/lib/webbrowserinterop.x86.dll',
    'clr_loader/ffi/dlls/x86/',
]


def _keep(entry) -> bool:
    dest = str(entry[0]).replace('\\', '/').lower()
    return not any(dest.startswith(prefix) for prefix in DROP_PAYLOAD)


a = Analysis(
    [str(ROOT / 'build-personal' / 'lgk_agent_entry.py')],
    pathex=[str(ROOT / 'src')],
    binaries=[],
    datas=[
        (str(ROOT / 'assets'), 'assets'),
        (str(ROOT / 'src' / 'localvault' / 'assets'), 'localvault/assets'),
        (str(ROOT / 'src' / 'localvault' / 'models'), 'localvault/models'),
    ],
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=EXCLUDES,
    # pystray is LGPL-3.0: ship it as plain .py files in _internal\pystray\
    # (not inside the executable's archive) so a user can replace it, as
    # THIRD-PARTY-NOTICES.txt explains (audit 2026-10-24 I-23).
    module_collection_mode={'pystray': 'py'},
    noarchive=False,
    optimize=0,
)
dropped = [entry[0] for entry in a.binaries + a.datas if not _keep(entry)]
a.binaries = [entry for entry in a.binaries if _keep(entry)]
a.datas = [entry for entry in a.datas if _keep(entry)]
print(f"LocalGateKeys.spec: dropped {len(dropped)} unused payload files: {sorted(dropped)}")
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name='LocalGateKeys',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=[str(ROOT / 'assets' / 'icons' / 'localgatekeys.ico')],
    manifest=str(ROOT / 'build-personal' / 'LocalGateKeys.manifest'),
    version=version_info(description='LocalGateKeys', original_filename='LocalGateKeys.exe'),
)
coll = COLLECT(
    exe,
    a.binaries,
    a.datas,
    strip=False,
    upx=False,
    upx_exclude=[],
    name='LocalGateKeys',
)
