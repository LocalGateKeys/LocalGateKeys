"""Build and release tooling fixes from docs/SECURITY_AUDIT_EXTENDED_2026-10-24.md.

L-10 native host trimmed and stale files removed on upgrade, I-9 no PFX
password on a command line and release builds from the lock, L-9 Python
floor, I-23 third-party notices shipped.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def read(relative: str) -> str:
    return (ROOT / relative).read_text(encoding="utf-8-sig")


def spec_list(text: str, name: str) -> list[str]:
    tree = ast.parse(text)
    for node in tree.body:
        if isinstance(node, ast.Assign) and any(getattr(t, "id", None) == name for t in node.targets):
            return list(ast.literal_eval(node.value))
    raise AssertionError(f"{name} not found")


def test_native_host_bundles_only_what_it_needs() -> None:
    spec = read("LocalGateKeysNativeHost.spec")
    assert "collect_submodules('localvault')" not in spec
    excludes = spec_list(spec, "EXCLUDES")
    for name in ("tkinter", "_tkinter", "PIL", "ssl", "_ssl", "asyncio", "cv2", "numpy", "webview", "pystray"):
        assert name in excludes, name
    modules = spec_list(spec, "NATIVE_MODULES")
    assert "localvault.native_host" in modules
    assert not any(m.startswith(("localvault.app", "localvault.web", "localvault.face")) for m in modules)
    assert "datas=[]" in spec


def test_native_host_imports_stay_inside_the_bundle() -> None:
    """Every localvault module the native host imports (lazily too) is bundled."""
    bundled = set(spec_list(read("LocalGateKeysNativeHost.spec"), "NATIVE_MODULES"))
    seen: set[str] = set()
    queue = ["localvault.native_host"]
    while queue:
        module = queue.pop()
        if module in seen:
            continue
        seen.add(module)
        path = ROOT / "src" / Path(*module.split(".")).with_suffix(".py")
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and node.level == 1 and node.module:
                queue.append(f"localvault.{node.module}")
    assert seen <= bundled, sorted(seen - bundled)


def test_native_entry_self_check_rejects_trimmed_modules() -> None:
    entry = read("build-personal/lgk_native_entry.py")
    assert "localvault.build_check" not in entry  # the full check imports the GUI stack
    trimmed = re.search(r"TRIMMED = \(([^)]*)\)", entry).group(1)
    for name in ("tkinter", "PIL", "ssl", "asyncio"):
        assert f'"{name}"' in trimmed


def test_installer_replaces_both_runtimes_and_ships_notices() -> None:
    iss = read("build-personal/LocalGateKeys-Personal.iss")
    install_delete = iss.split("[InstallDelete]", 1)[1].split("\n[", 1)[0]
    assert 'Type: filesandordirs; Name: "{app}\\_internal"' in install_delete
    assert 'Type: filesandordirs; Name: "{app}\\NativeHost\\_internal"' in install_delete
    assert 'Source: "..\\THIRD-PARTY-NOTICES.txt"; DestDir: "{app}"' in iss
    build = read("scripts/build_personal_installer.ps1")
    assert "'Source: \"..\\THIRD-PARTY-NOTICES.txt\"'" in build
    msix = read("scripts/build_msix_package.ps1")
    assert 'Join-Path $Layout "THIRD-PARTY-NOTICES.txt"' in msix


def test_pfx_password_never_reaches_a_command_line() -> None:
    build = read("scripts/build_personal_installer.ps1")
    assert '"/p"' not in build and "@(\"/f\"" not in build
    assert "PtrToStringBSTR" not in build  # the password is never made a plain string
    assert "Import-PfxCertificate" in build
    assert "Read-Host -AsSecureString" in build
    assert "-DeleteKey" in build  # the imported key is removed afterwards


def test_release_builds_use_the_lock_and_a_python_floor() -> None:
    build = read("scripts/build_personal_installer.ps1")
    assert '[string]$MinimumPythonVersion = "3.14.9"' in build
    assert "if ($Signing -or $Release)" in build
    assert "$InstallDependencies = [switch]::Present" in build
    assert "if ($Release) { throw $message }" in build


def test_third_party_notices_cover_the_runtime_lock() -> None:
    notices = read("THIRD-PARTY-NOTICES.txt")
    lock = read("requirements.lock.txt")
    for name in re.findall(r"^([A-Za-z0-9_.-]+)==", lock, flags=re.MULTILINE):
        assert re.search(rf"^  {re.escape(name)} \S+  ", notices, flags=re.MULTILINE), name
    assert "GNU LESSER GENERAL PUBLIC LICENSE" in notices
    assert "_internal\\pystray\\" in notices
    assert "Apache License" in notices
    assert "module_collection_mode={'pystray': 'py'}" in read("LocalGateKeys.spec")
