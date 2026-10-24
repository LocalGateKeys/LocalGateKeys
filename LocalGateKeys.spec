# -*- mode: python ; coding: utf-8 -*-
from pathlib import Path
import sys

from PyInstaller.utils.hooks import collect_submodules

ROOT = Path(SPECPATH).resolve()
sys.path.insert(0, str(ROOT / 'src'))

hiddenimports = collect_submodules('localvault')
hiddenimports += ['cv2', 'numpy']


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
    excludes=['tkinter', '_tkinter'],  # the WebView2 window replaced Tk
    # pystray is LGPL-3.0: ship it as plain .py files in _internal\pystray\
    # (not inside the executable's archive) so a user can replace it, as
    # THIRD-PARTY-NOTICES.txt explains (audit 2026-10-24 I-23).
    module_collection_mode={'pystray': 'py'},
    noarchive=False,
    optimize=0,
)
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
