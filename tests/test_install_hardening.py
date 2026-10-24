from pathlib import Path


def test_windows_installer_is_current_user_only_and_pins_native_host() -> None:
    root = Path(__file__).resolve().parents[1]
    script = (root / "scripts" / "install_windows.ps1").read_text(encoding="utf-8")
    assert 'Join-Path $env:LOCALAPPDATA "Programs\\LocalGateKeys"' in script
    assert 'Join-Path $env:LOCALAPPDATA "LocalGateKeys"' in script
    assert "HKEY_LOCAL_MACHINE" not in script
    assert "HKLM:" not in script
    assert "HKCU:\\Software\\Google\\Chrome\\NativeMessagingHosts" in script
    assert "HKCU:\\Software\\Microsoft\\Edge\\NativeMessagingHosts" in script
    assert "icacls" in script
    assert "/inheritance:r" in script
    assert "native_host_sha256" in script
    assert "Get-FileHash -Algorithm SHA256" in script
    assert 'scope = "current_user"' in script


def test_uninstaller_preserves_vault_data_by_default() -> None:
    root = Path(__file__).resolve().parents[1]
    script = (root / "scripts" / "uninstall_windows.ps1").read_text(encoding="utf-8")
    assert "[switch]$RemoveData" in script
    assert 'Join-Path $env:LOCALAPPDATA "Programs\\LocalGateKeys"' in script
    assert 'Join-Path $env:LOCALAPPDATA "LocalGateKeys"' in script
    assert "if ($RemoveData)" in script
    assert "Encrypted profile data was preserved" in script


def test_rgb_camera_models_are_hash_pinned_and_packaged_only_with_agent() -> None:
    root = Path(__file__).resolve().parents[1]
    fetch = (root / "scripts" / "fetch_face_models.ps1").read_text(encoding="utf-8")
    model_code = (root / "src" / "localvault" / "face_models.py").read_text(encoding="utf-8")
    build = (root / "scripts" / "build_personal_installer.ps1").read_text(encoding="utf-8-sig")
    agent_spec = (root / "LocalGateKeys.spec").read_text(encoding="utf-8")
    native_spec = (root / "LocalGateKeysNativeHost.spec").read_text(encoding="utf-8")
    pyproject = (root / "pyproject.toml").read_text(encoding="utf-8")

    for digest in (
        "8f2383e4dd3cfbb4553ea8718107fc0423210dc964f9f4280604804ed2552fa4",
        "fb143eea07838aa532d1c95df5f69899974ea0140e1fba05e94204be13ed74ee",
    ):
        assert digest in model_code
        assert digest.upper() in fetch
    assert "fetch_face_models.ps1" in build
    assert "localvault/models" in agent_spec
    assert "'cv2', 'numpy'" in native_spec
    assert "localvault.app.face_capture" in native_spec
    assert "opencv-contrib-python>=4.13.0.92,<5" in pyproject
