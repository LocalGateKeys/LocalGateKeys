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
