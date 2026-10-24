"""Windows version resource for the frozen executables, from localvault.version.

Imported by LocalGateKeys.spec and LocalGateKeysNativeHost.spec (with src/ on
sys.path) and passed as EXE(version=...), so Explorer, Defender and the
browser's native-messaging diagnostics see the real product and version.
"""
from __future__ import annotations


def version_tuple(version: str) -> tuple[int, int, int, int]:
    parts = [int(part) for part in version.split(".")]
    if not 1 <= len(parts) <= 4 or any(not 0 <= part <= 0xFFFF for part in parts):
        raise ValueError(f"not a Windows file version: {version!r}")
    return tuple(parts + [0] * (4 - len(parts)))  # type: ignore[return-value]


def version_info(*, description: str, original_filename: str):
    from PyInstaller.utils.win32.versioninfo import (
        FixedFileInfo, StringFileInfo, StringStruct, StringTable, VarFileInfo, VarStruct, VSVersionInfo,
    )

    from localvault.version import APP_VERSION

    numbers = version_tuple(APP_VERSION)
    return VSVersionInfo(
        ffi=FixedFileInfo(
            filevers=numbers,
            prodvers=numbers,
            mask=0x3F,
            flags=0x0,
            OS=0x40004,  # VOS_NT_WINDOWS32
            fileType=0x1,  # VFT_APP
            subtype=0x0,
            date=(0, 0),
        ),
        kids=[
            StringFileInfo([
                StringTable("040904B0", [  # U.S. English, Unicode
                    StringStruct("CompanyName", "LocalGateKeys"),
                    StringStruct("FileDescription", description),
                    StringStruct("FileVersion", APP_VERSION),
                    StringStruct("InternalName", original_filename.rsplit(".", 1)[0]),
                    StringStruct("OriginalFilename", original_filename),
                    StringStruct("ProductName", "LocalGateKeys"),
                    StringStruct("ProductVersion", APP_VERSION),
                ]),
            ]),
            VarFileInfo([VarStruct("Translation", [0x0409, 1200])]),
        ],
    )
