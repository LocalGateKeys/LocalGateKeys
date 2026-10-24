# -*- mode: python ; coding: utf-8 -*-
from pathlib import Path
import sys

ROOT = Path(SPECPATH).resolve()
sys.path.insert(0, str(ROOT / 'src'))
sys.path.insert(0, str(ROOT / 'build-personal'))
from lgk_version_info import version_info  # noqa: E402

# The native host only forwards framed messages between the browser and the
# running app, and the browser starts it for every message. Bundle only what
# localvault.native_host reaches (its lazy imports included) plus the self-check
# in build-personal/lgk_native_entry.py; keep the GUI, camera/ML, Tk, Pillow,
# TLS and asyncio out of this security boundary (audit 2026-10-24 L-10).
NATIVE_MODULES = [
    'localvault', 'localvault.version', 'localvault.native_host', 'localvault.protocol',
    'localvault.pipe_transport', 'localvault.bridge_status', 'localvault.browser_ancestry',
    'localvault.config', 'localvault.distribution', 'localvault.signature', 'localvault.winpaths',
    'localvault.process_hardening',
]
hiddenimports = NATIVE_MODULES + [
    'win32api', 'win32con', 'win32crypt', 'win32file', 'win32pipe', 'win32security',
    'ntsecuritycon', 'pywintypes', 'psutil',
]
# Checked again at run time by `LocalGateKeysNativeHost.exe --check-build`.
EXCLUDES = [
    'cv2', 'numpy', 'localvault.face_models', 'localvault.app.face_capture', 'localvault.face_unlock',
    'localvault.face_ui', 'localvault.app', 'localvault.web', 'localvault.api', 'localvault.agent',
    'tkinter', '_tkinter', 'PIL', 'pystray', 'webview', 'pywinauto', 'comtypes',
    'ssl', '_ssl', 'asyncio', '_asyncio', 'sqlite3', '_sqlite3', 'unittest', 'pydoc', 'xmlrpc',
    'cryptography', 'argon2', 'cffi', 'pyotp', 'qrcode',
    'pythonwin', 'win32ui', 'win32uiole', 'dde',  # MFC-based; needs mfc140u.dll, unused here
]


a = Analysis(
    [str(ROOT / 'build-personal' / 'lgk_native_entry.py')],
    pathex=[str(ROOT / 'src')],
    binaries=[],
    # The browser never shows the native host, so no UI assets; the icon is
    # embedded in the exe below.
    datas=[],
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=EXCLUDES,
    noarchive=False,
    optimize=0,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name='LocalGateKeysNativeHost',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=[str(ROOT / 'assets' / 'icons' / 'localgatekeys.ico')],
    version=version_info(description='LocalGateKeys browser bridge', original_filename='LocalGateKeysNativeHost.exe'),
)
coll = COLLECT(
    exe,
    a.binaries,
    a.datas,
    strip=False,
    upx=False,
    upx_exclude=[],
    name='LocalGateKeysNativeHost',
)
