"""The MSIX manifest template, packaging helpers and Python constants agree."""
from __future__ import annotations

import ast
import importlib.util
import json
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
    "com": "http://schemas.microsoft.com/appx/manifest/com/windows10",
}
PROVIDER_SRC = ROOT / "windows-passkey-provider" / "src" / "LocalGateKeys.PasskeyProvider"


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
    assert alias_hosts == ["NativeHost\\LocalGateKeysNativeHost.exe"]  # one alias block per Application
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


def test_install_licence_links_open_the_app(manifest) -> None:
    from localvault.licence_link import SCHEME

    protocol = manifest.find(".//uap:Extension[@Category='windows.protocol']/uap:Protocol", NS)
    assert protocol is not None and protocol.get("Name") == SCHEME


def test_msix_ships_no_lgk_cli(manifest) -> None:
    """MakeAppx allows one appExecutionAlias block per Application, used by the native host, so a Store package
    cannot put lgk on PATH: the CLI is dropped from the package for now (owner decision 2026-11-09)."""
    assert manifest.find(".//uap5:ExecutionAlias[@Alias='lgk.exe']", NS) is None
    script = SCRIPT.read_text(encoding="utf-8")
    assert "$CliLayout" not in script and "$CliDist" not in script and '"lgk.exe"' not in script
    from localvault import pipe_transport

    assert Path(*pipe_transport.CLI_RELATIVE_PATH) == distribution.CLI_IMAGE


def test_frozen_build_includes_lgk() -> None:
    builder = (ROOT / "scripts" / "build_personal_installer.ps1").read_text(encoding="utf-8")
    assert "LocalGateKeysCli.spec" in builder and 'Join-Path $DistRoot "lgk\\lgk.exe"' in builder


def test_cli_spec_excludes_cryptography() -> None:
    spec = (ROOT / "LocalGateKeysCli.spec").read_text(encoding="utf-8")
    excludes = ast.literal_eval(re.search(r"EXCLUDES = (\[.*?\n\])", spec, re.S).group(1))
    for name in ("cryptography", "cffi", "argon2", "ssl", "_ssl", "asyncio", "tkinter", "PIL",
                 "localvault.vault", "localvault.local_clients"):
        assert name in excludes
    modules = ast.literal_eval(re.search(r"CLI_MODULES = (\[.*?\])", spec, re.S).group(1))
    assert "localvault.cli.main" in modules and not [m for m in modules if "vault" in m.split(".")]
    assert "name='lgk'" in spec and "console=True" in spec
    entry = (ROOT / "build-personal" / "lgk_cli_entry.py").read_text(encoding="utf-8")
    assert "--check-build" in entry and '"cryptography"' in entry  # the run-time guard repeats the exclusion


def test_repair_writes_cli_path_in_development(tmp_path, monkeypatch) -> None:
    from localvault import browser_bridge, config

    host = tmp_path / "host.exe"
    host.write_bytes(b"MZ")
    monkeypatch.setenv("LOCALGATEKEYS_DATA_DIR", str(tmp_path / "data"))
    monkeypatch.setattr(browser_bridge, "_native_host_executable", lambda: host)
    monkeypatch.setattr(browser_bridge, "_secure_data_directory", lambda _path: None)
    monkeypatch.setattr(browser_bridge, "_register_manifest", lambda *_args: None)
    monkeypatch.setattr(distribution, "native_host_alias_path", lambda: None)
    monkeypatch.setattr(distribution, "is_packaged", lambda: False)
    browser_bridge.repair_browser_bridge()
    install = json.loads(config.install_config_path().read_text(encoding="utf-8"))
    assert install["cli_path"] == str(ROOT / "dist-personal" / "lgk" / "lgk.exe")


def test_manifest_declares_provider_com_server(manifest) -> None:
    """Windows activates the passkey provider through this COM class; the CLSID is the one the exe serves."""
    from localvault import pipe_transport

    text = TEMPLATE.read_text(encoding="utf-8")
    assert f'xmlns:com="{NS["com"]}"' in text
    assert "com" in re.search(r'IgnorableNamespaces="([^"]*)"', text).group(1).split()
    application = manifest.find(".//m:Application[@Id='LocalGateKeys']", NS)
    extensions = application.findall("m:Extensions/com:Extension", NS)
    assert [ext.get("Category") for ext in extensions] == ["windows.comServer"]
    servers = extensions[0].findall("com:ComServer/com:ExeServer", NS)
    assert len(servers) == 1
    server = servers[0]
    assert server.get("Executable") == "PasskeyProvider\\LocalGateKeysPasskeyProvider.exe"
    assert tuple(server.get("Executable").split("\\")) == pipe_transport.PROVIDER_RELATIVE_PATH
    cli = (PROVIDER_SRC / "Commands" / "Cli.cs").read_text(encoding="utf-8")
    assert 'public const string PluginActivated = "-PluginActivated";' in cli
    assert server.get("Arguments") == "-PluginActivated"
    assert server.get("DisplayName") == "LocalGateKeys passkeys"
    ids = (PROVIDER_SRC / "Provider" / "ProviderIds.cs").read_text(encoding="utf-8")
    clsid = re.search(r'Guid Clsid = new\("([0-9a-fA-F-]{36})"\)', ids).group(1)
    classes = [(node.get("Id").lower(), node.get("DisplayName")) for node in server.findall("com:Class", NS)]
    assert classes == [(clsid.lower(), "LocalGateKeys passkeys")]
    # Package-scoped only: the build never writes the class to the registry or registers the provider.
    script = SCRIPT.read_text(encoding="utf-8")
    assert "CLSID" not in script and "regsvr32" not in script.lower() and "--register" not in script
    assert "Add-AppxPackage" not in script


def test_only_one_application(manifest) -> None:
    """The COM server hangs off the main app; a second (hidden) Application is a headless app the Store rejects."""
    assert [app.get("Id") for app in manifest.findall(".//m:Application", NS)] == ["LocalGateKeys"]
    assert len(manifest.findall(".//com:Extension", NS)) == 1
    assert "runFullTrust" in {node.get("Name") for node in manifest.findall(".//rescap:Capability", NS)}


def test_script_publishes_and_copies_provider() -> None:
    script = SCRIPT.read_text(encoding="utf-8")
    assert '[string]$ProviderDist = "build\\passkey-provider"' in script
    # Missing (or -Build): publish the self-contained provider the way Task 4 does.
    publish = re.search(r"\$publishArgs = @\(([^)]*)\)", script).group(1)
    for part in ('"publish"', '"Release"', '"win-x64"', '"--self-contained"', '"true"', "$ProviderProject"):
        assert part in publish
    assert '"windows-passkey-provider\\src\\LocalGateKeys.PasskeyProvider\\LocalGateKeys.PasskeyProvider.csproj"' in script
    assert (PROVIDER_SRC / "LocalGateKeys.PasskeyProvider.csproj").is_file()
    # Copied next to the NativeHost copy, at the path the manifest declares, and required.
    assert '$ProviderExe = Join-Path $ProviderDist "LocalGateKeysPasskeyProvider.exe"' in script
    required = re.search(r"foreach \(\$required in ([^{]*)\)\s*\{", script).group(1)
    assert "$ProviderExe" in required
    assert '$ProviderLayout = Join-Path $Layout "PasskeyProvider"' in script
    assert '(Join-Path $ProviderDist "*") -Destination $ProviderLayout' in script
    pack = script.index('"makeappx pack"')
    assert script.index("$ProviderLayout") < pack
    # Same signer as LocalGateKeys.exe: sign with the app's certificate when one is given, and refuse a package
    # whose two executables differ (the app's pipe pin and the provider's server pin compare them).
    assert '[string]$CertificateThumbprint = ""' in script
    assert '@("sign", "/fd", "SHA256", "/td", "SHA256", "/tr", $TimestampUrl, "/sha1", $CertificateThumbprint' in script
    assert 'Get-SignerThumbprint (Join-Path $Layout "LocalGateKeys.exe")' in script
    assert "Get-SignerThumbprint $LayoutProviderExe" in script
    assert script.index("Assert-SameSigner") < pack


def test_provider_layout_has_no_runtime_injection_knobs() -> None:
    script = SCRIPT.read_text(encoding="utf-8")
    pack = script.index('"makeappx pack"')
    # createdump.exe is dropped with the symbols (DOTNET_DbgEnableMiniDump could dump the pipe token).
    drop = script.index('-Filter "createdump.exe" -File -Recurse | Remove-Item -Force')
    assert script.index('-Destination $ProviderLayout') < drop < pack
    # The packaged runtimeconfig must keep the startup hook and built-in COM interop off, or the build stops.
    check = script.index('$ProviderRuntimeConfig = Join-Path $ProviderLayout "LocalGateKeysPasskeyProvider.runtimeconfig.json"')
    assert check < pack
    for switch in ("System.StartupHookProvider.IsSupported", "System.Runtime.InteropServices.BuiltInComInterop.IsSupported"):
        assert f'"{switch}"' in script
    project = (PROVIDER_SRC / "LocalGateKeys.PasskeyProvider.csproj").read_text(encoding="utf-8")
    assert "<StartupHookSupport>false</StartupHookSupport>" in project
    assert "<BuiltInComInteropSupport>false</BuiltInComInteropSupport>" in project
    # Any Release build output on this machine carries the switches (dotnet test / publish write the same file).
    for config in PROVIDER_SRC.glob("bin/Release/*/*/LocalGateKeysPasskeyProvider.runtimeconfig.json"):
        properties = json.loads(config.read_text(encoding="utf-8"))["runtimeOptions"]["configProperties"]
        assert properties.get("System.StartupHookProvider.IsSupported") is False, config
        assert properties.get("System.Runtime.InteropServices.BuiltInComInterop.IsSupported") is False, config


def _provider_dist_guard() -> str:
    script = SCRIPT.read_text(encoding="utf-8")
    start = script.index("    if (Test-Path -LiteralPath $ProviderDist) {")
    end = script.index("        Remove-Item -LiteralPath $ProviderDist -Recurse -Force\n    }", start)
    return script[start:end + len("        Remove-Item -LiteralPath $ProviderDist -Recurse -Force\n    }")]


def test_provider_dist_is_only_wiped_when_empty_or_a_provider_publish(tmp_path) -> None:
    guard = _provider_dist_guard()
    assert "Refusing to delete -ProviderDist" in guard
    # The guard is the only Remove-Item of -ProviderDist.
    assert SCRIPT.read_text(encoding="utf-8").count("Remove-Item -LiteralPath $ProviderDist") == 1
    import os
    import shutil
    import subprocess

    shell = shutil.which("powershell.exe") if os.name == "nt" else None
    if not shell:
        pytest.skip("Windows PowerShell")

    def run(dist: Path) -> tuple[int, str]:
        body = ("$ErrorActionPreference = 'Stop'\n"
                f"$Root = '{tmp_path / 'repo'}'\n$OutputBase = $Root\n$ProviderDist = '{dist}'\n"
                '$ProviderExe = Join-Path $ProviderDist "LocalGateKeysPasskeyProvider.exe"\n' + guard + "\n")
        runner = tmp_path / "guard.ps1"
        runner.write_text(body, encoding="utf-8")
        done = subprocess.run([shell, "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", str(runner)],
                              capture_output=True, text=True, timeout=60)
        return done.returncode, done.stdout + done.stderr

    (tmp_path / "repo").mkdir()
    precious = tmp_path / "Documents"
    precious.mkdir()
    (precious / "taxes.xlsx").write_text("keep", encoding="utf-8")
    code, output = run(precious)
    assert code != 0 and "Refusing to delete" in output and (precious / "taxes.xlsx").is_file()
    # An unrelated folder that merely holds a file named like the provider is still not a publish.
    (precious / "LocalGateKeysPasskeyProvider.exe").write_bytes(b"MZ")
    code, _output = run(precious)
    assert code != 0 and (precious / "taxes.xlsx").is_file()
    # The repo root itself is never wiped.
    code, _output = run(tmp_path / "repo")
    assert code != 0 and (tmp_path / "repo").is_dir()
    # Empty, or a previous provider publish: wiped.
    empty = tmp_path / "empty"
    empty.mkdir()
    assert run(empty)[0] == 0 and not empty.exists()
    publish = tmp_path / "publish"
    publish.mkdir()
    for name in ("LocalGateKeysPasskeyProvider.exe", "LocalGateKeysPasskeyProvider.runtimeconfig.json", "coreclr.dll"):
        (publish / name).write_bytes(b"x")
    assert run(publish)[0] == 0 and not publish.exists()
