# -*- mode: python ; coding: utf-8 -*-
from pathlib import Path
import sys

ROOT = Path(SPECPATH).resolve()
sys.path.insert(0, str(ROOT / 'src'))
sys.path.insert(0, str(ROOT / 'build-personal'))
from lgk_version_info import version_info  # noqa: E402

# lgk.exe only forwards requests to the running app over its pipe. Same trimmed
# build as the native host (no cryptography, TLS, asyncio, GUI or camera/ML);
# the self-check is in build-personal/lgk_cli_entry.py.
CLI_MODULES = [
    'localvault', 'localvault.version', 'localvault.cli', 'localvault.cli.main', 'localvault.cli.run',
    'localvault.cli.inject', 'localvault.cli.mcp_server', 'localvault.pipe_transport', 'localvault.bridge_status',
    'localvault.browser_ancestry', 'localvault.config', 'localvault.distribution', 'localvault.signature',
    'localvault.winpaths', 'localvault.process_hardening',
]
hiddenimports = CLI_MODULES + [
    'win32api', 'win32con', 'win32crypt', 'win32file', 'win32pipe', 'win32security',
    'ntsecuritycon', 'pywintypes', 'psutil',
]
# Checked again at run time by `lgk.exe --check-build`.
EXCLUDES = [
    'cv2', 'numpy', 'localvault.vault', 'localvault.local_clients', 'localvault.native_host',
    'localvault.face_models', 'localvault.app.face_capture', 'localvault.face_unlock',
    'localvault.face_ui', 'localvault.app', 'localvault.web', 'localvault.api', 'localvault.agent',
    'tkinter', '_tkinter', 'PIL', 'pystray', 'webview', 'pywinauto', 'comtypes',
    'ssl', '_ssl', 'asyncio', '_asyncio', 'sqlite3', '_sqlite3', 'unittest', 'pydoc', 'xmlrpc',
    'cryptography', 'argon2', 'cffi', 'pyotp', 'qrcode',
    'pythonwin', 'win32ui', 'win32uiole', 'dde',  # MFC-based; needs mfc140u.dll, unused here
]


a = Analysis(
    [str(ROOT / 'build-personal' / 'lgk_cli_entry.py')],
    pathex=[str(ROOT / 'src')],
    binaries=[],
    # No assets; the icon is embedded in the exe below.
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
    name='lgk',
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
    version=version_info(description='LocalGateKeys command line', original_filename='lgk.exe'),
)
coll = COLLECT(
    exe,
    a.binaries,
    a.datas,
    strip=False,
    upx=False,
    upx_exclude=[],
    name='lgk',
)
