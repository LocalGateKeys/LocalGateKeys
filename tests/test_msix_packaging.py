"""The MSIX manifest template, packaging helpers and Python constants agree."""
from __future__ import annotations

import importlib.util
import re
import xml.etree.ElementTree as ET
from pathlib import Path

import pytest

from localvault import distribution
from localvault.config import APP_DIR_NAME, NATIVE_HOST_NAME
from localvault.version import APP_VERSION

ROOT = Path(__file__).resolve().parents[1]
TEMPLATE = ROOT / "build-msix" / "AppxManifest.xml.in"
SCRIPT = ROOT / "scripts" / "build_msix_package.ps1"
NS = {
    "m": "http://schemas.microsoft.com/appx/manifest/foundation/windows10",
    "uap": "http://schemas.microsoft.com/appx/manifest/uap/windows10",
    "uap5": "http://schemas.microsoft.com/appx/manifest/uap/windows10/5",
    "uap10": "http://schemas.microsoft.com/appx/manifest/uap/windows10/10",
    "desktop": "http://schemas.microsoft.com/appx/manifest/desktop/windows10",
    "desktop6": "http://schemas.microsoft.com/appx/manifest/desktop/windows10/6",
    "rescap": "http://schemas.microsoft.com/appx/manifest/foundation/windows10/restrictedcapabilities",
    "virtualization": "http://schemas.microsoft.com/appx/manifest/virtualization/windows10",
}


def _load(name: str):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def manifest() -> ET.Element:
    text = TEMPLATE.read_text(encoding="utf-8")
    tokens = set(re.findall(r"@[A-Z_]+@", text))
    assert tokens == {"@IDENTITY_NAME@", "@PUBLISHER@", "@VERSION@", "@DISPLAY_NAME@", "@PUBLISHER_DISPLAY_NAME@"}
    for token in tokens:
        text = text.replace(token, "1.2.3.0" if token == "@VERSION@" else "CN=X" if token == "@PUBLISHER@" else "X")
    return ET.fromstring(text)  # noqa: S314 - the repository's own template, not untrusted input


def test_every_template_token_is_replaced_by_the_script() -> None:
    script = SCRIPT.read_text(encoding="utf-8")
    for token in re.findall(r"@[A-Z_]+@", TEMPLATE.read_text(encoding="utf-8")):
        assert f'"{token}"' in script


def test_native_host_alias_matches_the_runtime_constants(manifest) -> None:
    aliases = manifest.findall(".//uap5:ExecutionAlias", NS)
    assert [alias.get("Alias") for alias in aliases] == [distribution.NATIVE_HOST_ALIAS]
    extension = manifest.find(".//uap5:Extension[@Category='windows.appExecutionAlias']", NS)
    assert Path(extension.get("Executable").replace("\\", "/")) == Path(distribution.NATIVE_HOST_IMAGE.as_posix())


def test_startup_task_matches_and_starts_in_the_background(manifest) -> None:
    extension = manifest.find(".//desktop:Extension[@Category='windows.startupTask']", NS)
    assert extension.get(f"{{{NS['uap10']}}}Parameters") == "--background"
    task = extension.find("desktop:StartupTask", NS)
    assert task.get("TaskId") == distribution.STARTUP_TASK_ID
    assert task.get("Enabled") == "false"  # off until the user turns it on


def test_data_directory_and_bridge_keys_escape_virtualization(manifest) -> None:
    directories = [node.text for node in manifest.findall(".//virtualization:ExcludedDirectory", NS)]
    assert directories == [f"$(KnownFolder:LocalAppData)\\{APP_DIR_NAME}"]
    keys = {node.text for node in manifest.findall(".//virtualization:ExcludedKey", NS)}
    assert keys == {
        f"HKEY_CURRENT_USER\\Software\\Google\\Chrome\\NativeMessagingHosts\\{NATIVE_HOST_NAME}",
        f"HKEY_CURRENT_USER\\Software\\Microsoft\\Edge\\NativeMessagingHosts\\{NATIVE_HOST_NAME}",
        f"HKEY_CURRENT_USER\\Software\\Mozilla\\NativeMessagingHosts\\{NATIVE_HOST_NAME}",
    }
    # Measured on Windows 11: the desktop6 registry flag is what makes new
    # HKCU keys real; without it the ExcludedKeys list left every write private.
    flags = {node.tag.split("}")[1]: node.text for node in manifest.find("m:Properties", NS)
             if node.tag.startswith(f"{{{NS['desktop6']}}}")}
    assert flags == {"FileSystemWriteVirtualization": "disabled", "RegistryWriteVirtualization": "disabled"}
    capabilities = {node.get("Name") for node in manifest.findall(".//rescap:Capability", NS)}
    assert capabilities == {"runFullTrust", "unvirtualizedResources"}


def test_applications_are_full_trust_desktop_apps(manifest) -> None:
    applications = manifest.findall(".//m:Application", NS)
    # One Application only: a second, hidden one (AppListEntry="none") is a
    # "headless app" that Store ingestion rejects without a waiver.
    assert [app.get("Executable") for app in applications] == ["LocalGateKeys.exe"]
    assert not [node for node in manifest.iter() if node.get("AppListEntry")]
    alias_hosts = [ext.get("Executable") for ext in manifest.findall(".//uap5:Extension", NS)
                   if ext.get("Category") == "windows.appExecutionAlias"]
    assert alias_hosts == ["NativeHost\\LocalGateKeysNativeHost.exe"]
    for app in applications:
        assert app.get(f"{{{NS['uap10']}}}RuntimeBehavior") == "packagedClassicApp"
        assert app.get(f"{{{NS['uap10']}}}TrustLevel") == "mediumIL"
    assert manifest.find(".//m:DeviceCapability[@Name='webcam']", NS) is not None


def test_script_writes_the_store_flag_the_runtime_reads() -> None:
    script = SCRIPT.read_text(encoding="utf-8")
    assert f'"{distribution.STORE_MARKER_NAME}"' in script
    assert "APP_VERSION" in script and re.fullmatch(r"\d+\.\d+\.\d+", APP_VERSION)


def test_generated_logos_cover_every_manifest_reference(manifest, tmp_path) -> None:
    referenced = set()
    for node in manifest.iter():
        for attribute in ("Square150x150Logo", "Square44x44Logo", "Wide310x150Logo"):
            if node.get(attribute):
                referenced.add(node.get(attribute))
    referenced.add(manifest.find("m:Properties/m:Logo", NS).text)
    assets = _load("generate_msix_assets")
    plain = {path.name for path in assets.write_assets(tmp_path / "plain", qualified=False)}
    qualified = {path.name for path in assets.write_assets(tmp_path / "qualified", qualified=True)}
    for reference in referenced:
        folder, name = reference.split("\\")
        assert folder == "PackageAssets"
        stem = name.removesuffix(".png")
        assert name in plain
        assert f"{stem}.scale-200.png" in qualified

    from PIL import Image

    with Image.open(tmp_path / "qualified" / "Square150x150Logo.scale-200.png") as image:
        assert image.size == (300, 300)


def test_test_certificate_matches_the_test_publisher(tmp_path) -> None:
    from cryptography import x509
    from cryptography.x509.oid import ExtendedKeyUsageOID

    certificates = _load("msix_test_certificate")
    subject = "CN=LocalGateKeys Test Signing"
    assert f'Publisher = "{subject}"' in SCRIPT.read_text(encoding="utf-8")
    pfx, cer = certificates.create(tmp_path, subject, "pw")
    first = cer.read_bytes()
    certificate = x509.load_der_x509_certificate(first)
    assert certificate.subject.rfc4514_string() == subject
    usage = certificate.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
    assert ExtendedKeyUsageOID.CODE_SIGNING in usage
    assert not certificate.extensions.get_extension_for_class(x509.BasicConstraints).value.ca
    # Reused, not regenerated, while still valid.
    assert certificates.create(tmp_path, subject, "pw") == (pfx, cer)
    assert cer.read_bytes() == first
    with pytest.raises(ValueError):
        certificates.create(tmp_path / "other", "CN=A, O=B", "pw")
