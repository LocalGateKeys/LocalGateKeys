from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TEMPLATE = ROOT / "build-personal" / "LocalGateKeys-Personal.iss"
BUILD_SCRIPT = ROOT / "scripts" / "build_personal_installer.ps1"


def test_installer_template_has_no_machine_specific_paths() -> None:
    text = TEMPLATE.read_text(encoding="utf-8-sig")
    assert not re.search(r"[A-Za-z]:\\", text), "template must use paths relative to build-personal"
    for line in ("OutputDir=..\\dist-installer", 'Source: "..\\dist-personal\\LocalGateKeys\\*"',
                 'Source: "..\\browser-extension\\*"'):
        assert line in text


def test_build_writes_generated_script_beside_not_over_the_template() -> None:
    text = BUILD_SCRIPT.read_text(encoding="utf-8-sig")
    assert '"LocalGateKeys-Personal.generated.iss"' in text
    assert "$IsccArguments += $IssScript" in text


def test_build_takes_the_installer_version_from_the_app() -> None:
    # Windows shows AppVersion in Installed apps; the template's value is only a placeholder.
    template = TEMPLATE.read_text(encoding="utf-8-sig")
    assert re.search(r'^#define AppVersion "[^"]*"$', template, re.M)
    text = BUILD_SCRIPT.read_text(encoding="utf-8-sig")
    assert "from localvault.version import APP_VERSION" in text
    assert "#define AppVersion" in text


def test_installer_closes_the_tray_app_before_replacing_files() -> None:
    text = TEMPLATE.read_text(encoding="utf-8-sig")
    assert "function PrepareToInstall(" in text
    assert "function InitializeUninstall(" in text
    assert "taskkill.exe" in text
    assert "LocalGateKeysNativeHost.exe" in text
    # Only this user's processes are stopped.
    assert '"USERNAME eq \' + GetUserNameString' in text


def test_installer_only_installs_in_the_per_user_programs_folder() -> None:
    # A chosen folder under C:\ inherits "Authenticated Users: Modify" (another
    # account could replace the app or the native host the browser starts), and
    # [UninstallDelete] would wipe a chosen existing folder.
    text = TEMPLATE.read_text(encoding="utf-8-sig")
    setup = text.split("[Setup]", 1)[1].split("\n[", 1)[0]
    assert re.search(r"^DefaultDirName=\{localappdata\}\\Programs\\LocalGateKeys$", setup, re.M)
    assert re.search(r"^DisableDirPage=yes$", setup, re.M)
    assert re.search(r"^UsePreviousAppDir=no$", setup, re.M)
    code = text.split("[Code]", 1)[1]
    assert "ExpandConstant('{localappdata}\\Programs\\LocalGateKeys')" in code
    # /DIR= is refused up front, and the resolved {app} is checked before any file is written.
    init = code.split("function InitializeSetup(", 1)[1].split("\nend;", 1)[0]
    assert "{param:DIR|}" in init and "IsAllowedAppDir" in init and "Result := False" in init
    prepare = code.split("function PrepareToInstall(", 1)[1]
    assert prepare.index("IsAllowedAppDir(ExpandConstant('{app}'))") < prepare.index("StopLocalGateKeys")


def test_build_refuses_output_folders_other_accounts_can_write() -> None:
    text = BUILD_SCRIPT.read_text(encoding="utf-8-sig")
    assert "function Get-ForeignWriters(" in text
    assert "GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier])" in text
    for sid in ('"S-1-5-18"', '"S-1-5-32-544"'):
        assert sid in text
    # Checked before anything is generated or packaged there.
    check = text.index("Assert-PrivateBuildFolder $OutputBase")
    assert check < text.index('$BuildRoot = Join-Path $OutputBase "build-personal"')
    assert check < text.index("-m PyInstaller")


def _spec_list(text: str, name: str) -> list[str]:
    import ast

    for node in ast.parse(text).body:
        if isinstance(node, ast.Assign) and any(getattr(t, "id", None) == name for t in node.targets):
            return list(ast.literal_eval(node.value))
    raise AssertionError(f"{name} not found")


def test_both_executables_get_a_version_resource_from_the_app_version() -> None:
    import importlib.util

    for spec_name in ("LocalGateKeys.spec", "LocalGateKeysNativeHost.spec"):
        text = (ROOT / spec_name).read_text(encoding="utf-8")
        assert "from lgk_version_info import version_info" in text
        assert len(re.findall(r"^\s+version=version_info\(", text, re.M)) == 1, spec_name
    helper = importlib.util.spec_from_file_location("lgk_version_info", ROOT / "build-personal" / "lgk_version_info.py")
    module = importlib.util.module_from_spec(helper)
    helper.loader.exec_module(module)
    assert module.version_tuple("0.4.5") == (0, 4, 5, 0)
    for bad in ("1.x", "70000.0.0", "1.2.3.4.5"):
        try:
            module.version_tuple(bad)
        except ValueError:
            continue
        raise AssertionError(bad)
    from localvault.version import APP_VERSION

    info = module.version_info(description="LocalGateKeys", original_filename="LocalGateKeys.exe")
    assert info.ffi.fileVersionMS == (module.version_tuple(APP_VERSION)[0] << 16) | module.version_tuple(APP_VERSION)[1]
    assert f"StringStruct('FileVersion', '{APP_VERSION}')" in str(info)


def test_main_app_drops_unused_payload_but_keeps_what_runs() -> None:
    text = (ROOT / "LocalGateKeys.spec").read_text(encoding="utf-8")
    drop = _spec_list(text, "DROP_PAYLOAD")
    assert "cv2/opencv_videoio_ffmpeg" in drop
    assert not any("win-x64" in p or "amd64" in p or p.endswith("x64.dll") for p in drop)
    excludes = _spec_list(text, "EXCLUDES")
    assert "numpy._core._multiarray_tests" in excludes and "PIL._avif" in excludes
    # pywinauto imports win32ui at module level; PNG/JPEG/ICO decoders stay.
    assert not {"win32ui", "pythonwin", "PIL.PngImagePlugin", "PIL.JpegImagePlugin", "PIL.IcoImagePlugin"} & set(excludes)
    assert "excludes=EXCLUDES" in text and "a.binaries = [entry for entry in a.binaries if _keep(entry)]" in text
    native = _spec_list((ROOT / "LocalGateKeysNativeHost.spec").read_text(encoding="utf-8"), "EXCLUDES")
    assert "win32ui" in native
