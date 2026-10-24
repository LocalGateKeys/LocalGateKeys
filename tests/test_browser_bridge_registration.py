from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path

from localvault import browser_bridge
from localvault.config import EXTENSION_ID, NATIVE_HOST_NAME, chromium_extension_ids


def test_manifest_payload_matches_extension_and_host(tmp_path: Path) -> None:
    host = tmp_path / "LocalGateKeysNativeHost.exe"
    payload = browser_bridge._manifest_payload(host)
    assert payload == {
        "name": NATIVE_HOST_NAME,
        "description": "LocalGateKeys browser bridge",
        "path": str(host),
        "type": "stdio",
        # The dev ID first, then every store ID assigned so far.
        "allowed_origins": [f"chrome-extension://{value}/" for value in chromium_extension_ids()],
    }
    assert payload["allowed_origins"][0] == f"chrome-extension://{EXTENSION_ID}/"


def test_firefox_manifest_uses_allowed_extensions_with_the_gecko_id(tmp_path: Path) -> None:
    host = tmp_path / "LocalGateKeysNativeHost.exe"
    payload = browser_bridge._firefox_manifest_payload(host)
    assert payload == {
        "name": NATIVE_HOST_NAME,
        "description": "LocalGateKeys browser bridge",
        "path": str(host),
        "type": "stdio",
        "allowed_extensions": ["localgatekeys@localgatekeys.app"],
    }
    assert "allowed_origins" not in payload
    assert browser_bridge._FIREFOX_REGISTRY_ROOT == r"Software\Mozilla\NativeMessagingHosts"


def test_repair_registers_chromium_and_firefox_manifests(monkeypatch, tmp_path: Path) -> None:
    import sys

    created: list[tuple[str, str]] = []

    class Key:
        def __init__(self, path: str) -> None:
            self.path = path

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

    fake = type("winreg", (), {
        "HKEY_CURRENT_USER": "HKCU", "REG_SZ": 1,
        "CreateKey": staticmethod(lambda root, sub: Key(sub)),
        "SetValueEx": staticmethod(lambda key, name, reserved, kind, value: created.append((key.path, value))),
    })
    monkeypatch.setitem(sys.modules, "winreg", fake)
    chrome, firefox = tmp_path / "host.json", tmp_path / "host.firefox.json"
    browser_bridge._register_manifest(chrome, firefox)
    assert created == [
        (rf"Software\Google\Chrome\NativeMessagingHosts\{NATIVE_HOST_NAME}", str(chrome)),
        (rf"Software\Microsoft\Edge\NativeMessagingHosts\{NATIVE_HOST_NAME}", str(chrome)),
        (rf"Software\Mozilla\NativeMessagingHosts\{NATIVE_HOST_NAME}", str(firefox)),
    ]


def test_personal_installer_repairs_before_launch_and_unregisters_on_uninstall() -> None:
    root = Path(__file__).resolve().parents[1]
    text = (root / "build-personal" / "LocalGateKeys-Personal.iss").read_text(encoding="utf-8-sig")
    assert 'Parameters: "--repair-browser-bridge"' in text
    assert 'Flags: runhidden waituntilterminated' in text
    assert '[UninstallRun]' in text
    assert 'Parameters: "--unregister-browser-bridge"' in text


def test_packaged_agent_has_native_bridge_maintenance_cli() -> None:
    root = Path(__file__).resolve().parents[1]
    text = (root / "src" / "localvault" / "agent.py").read_text(encoding="utf-8")
    assert '"--repair-browser-bridge"' in text
    assert '"--unregister-browser-bridge"' in text
    assert "repair_browser_bridge()" in text
    assert "unregister_browser_bridge()" in text


def test_in_app_repair_does_not_depend_on_repository_powershell() -> None:
    root = Path(__file__).resolve().parents[1]
    repair_block = (root / "src" / "localvault" / "app" / "connections.py").read_text(encoding="utf-8")
    assert "from ..browser_bridge import repair_browser_bridge" in repair_block
    assert "repair_browser_bridge.ps1" not in repair_block
    assert "powershell.exe" not in repair_block


def test_extension_manifest_key_matches_expected_extension_id() -> None:
    root = Path(__file__).resolve().parents[1]
    manifest = json.loads((root / "browser-extension" / "manifest.json").read_text(encoding="utf-8"))
    public_key = base64.b64decode(manifest["key"])
    first_128_bits = hashlib.sha256(public_key).digest()[:16]
    derived_id = "".join(
        chr(ord("a") + (byte >> 4)) + chr(ord("a") + (byte & 0x0F))
        for byte in first_128_bits
    )
    assert derived_id == EXTENSION_ID
