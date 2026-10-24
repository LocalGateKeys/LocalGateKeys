"""Store/MSIX build flag and packaged-app path logic (no GUI, no real package)."""
from __future__ import annotations

import json
import sys
import types
from pathlib import Path

import pytest

from localvault import browser_bridge, distribution, pipe_transport, startup, updates
from localvault.config import NATIVE_HOST_NAME

FAMILY = "LocalGateKeys.Test_qhrrfmay8q2xp"


def _frozen(monkeypatch: pytest.MonkeyPatch, install_dir: Path) -> Path:
    install_dir.mkdir(parents=True, exist_ok=True)
    executable = install_dir / "LocalGateKeys.exe"
    executable.touch()
    monkeypatch.setattr(sys, "frozen", True, raising=False)
    monkeypatch.setattr(sys, "executable", str(executable))
    return executable


def _packaged(monkeypatch: pytest.MonkeyPatch, package_dir: Path, local_appdata: Path) -> None:
    values = {"GetCurrentPackageFamilyName": FAMILY, "GetCurrentPackagePath": str(package_dir)}
    monkeypatch.setattr(distribution, "_current_package_string", values.get)
    monkeypatch.setenv("LOCALAPPDATA", str(local_appdata))


def _unpackaged(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(distribution, "_current_package_string", lambda _name: None)


# -- channel / build flag ---------------------------------------------------

def test_source_runs_are_direct_even_with_a_package_identity(monkeypatch) -> None:
    # The Microsoft Store Python has package identity of its own.
    monkeypatch.setattr(sys, "frozen", False, raising=False)
    monkeypatch.setattr(distribution, "_current_package_string", lambda _name: "PythonSoftwareFoundation.Python")
    assert distribution.package_family_name() is None
    assert distribution.channel() == distribution.CHANNEL_DIRECT
    assert distribution.self_update_enabled()
    assert not distribution.uses_startup_task()


def test_frozen_inno_build_is_direct(monkeypatch, tmp_path) -> None:
    _frozen(monkeypatch, tmp_path / "app")
    _unpackaged(monkeypatch)
    assert distribution.channel() == distribution.CHANNEL_DIRECT
    assert distribution.self_update_enabled()
    assert distribution.native_host_alias_path() is None


def test_store_marker_next_to_the_executable_is_the_store_flag(monkeypatch, tmp_path) -> None:
    executable = _frozen(monkeypatch, tmp_path / "pkg")
    _packaged(monkeypatch, executable.parent, tmp_path / "Local")
    assert distribution.channel() == distribution.CHANNEL_SIDELOAD
    (executable.parent / distribution.STORE_MARKER_NAME).write_text('{"channel": "store"}\n', encoding="utf-8")
    assert distribution.is_store_build()
    assert distribution.channel() == distribution.CHANNEL_STORE
    assert not distribution.self_update_enabled()


def test_sideloaded_package_without_marker_still_disables_self_update(monkeypatch, tmp_path) -> None:
    executable = _frozen(monkeypatch, tmp_path / "pkg")
    _packaged(monkeypatch, executable.parent, tmp_path / "Local")
    assert not distribution.is_store_build()
    assert distribution.channel() == distribution.CHANNEL_SIDELOAD
    assert not distribution.self_update_enabled()
    assert distribution.uses_startup_task()


def test_unpackaged_process_reports_no_package_identity() -> None:
    # The real kernel32 call: pytest's interpreter is not an MSIX package.
    assert distribution._current_package_string("GetCurrentPackageFamilyName") is None


# -- updater gate -------------------------------------------------------------

def test_store_build_never_configures_or_contacts_the_release_feed(monkeypatch, tmp_path) -> None:
    executable = _frozen(monkeypatch, tmp_path / "pkg")
    _packaged(monkeypatch, executable.parent, tmp_path / "Local")
    (executable.parent / distribution.STORE_MARKER_NAME).touch()

    def no_network(*_args, **_kwargs):
        raise AssertionError("a Store build must not fetch the release feed")

    assert updates.release_configuration() is None
    assert updates.check_for_updates(opener_factory=no_network) is None
    assert updates.managed_update_channel() == "Microsoft Store"


def test_direct_build_keeps_the_signed_update_check(monkeypatch, tmp_path) -> None:
    _frozen(monkeypatch, tmp_path / "app")
    _unpackaged(monkeypatch)
    assert updates.managed_update_channel() is None
    assert updates.release_configuration() is not None


# -- native host alias --------------------------------------------------------

def test_alias_path_is_version_independent_and_resolves_to_the_package_host(monkeypatch, tmp_path) -> None:
    package = tmp_path / "WindowsApps" / f"LocalGateKeys.Test_0.4.0.0_x64__{FAMILY.split('_')[1]}"
    _frozen(monkeypatch, package)
    _packaged(monkeypatch, package, tmp_path / "Local")
    alias = distribution.native_host_alias_path()
    assert alias == tmp_path / "Local" / "Microsoft" / "WindowsApps" / FAMILY / distribution.NATIVE_HOST_ALIAS
    image = package / "NativeHost" / "LocalGateKeysNativeHost.exe"
    assert distribution.resolve_native_host_path(str(alias)) == str(image)
    assert distribution.resolve_native_host_path(str(alias).upper()) == str(image)
    other = str(tmp_path / "Other" / "LocalGateKeysNativeHost.exe")
    assert distribution.resolve_native_host_path(other) == other


def test_resolver_is_identity_when_unpackaged(monkeypatch, tmp_path) -> None:
    _frozen(monkeypatch, tmp_path / "app")
    _unpackaged(monkeypatch)
    path = str(tmp_path / "Local" / "Microsoft" / "WindowsApps" / FAMILY / distribution.NATIVE_HOST_ALIAS)
    assert distribution.resolve_native_host_path(path) == path


def test_pipe_pin_sees_the_package_host_behind_the_registered_alias(monkeypatch, tmp_path) -> None:
    package = tmp_path / "pkg"
    _frozen(monkeypatch, package)
    _packaged(monkeypatch, package, tmp_path / "Local")
    alias = distribution.native_host_alias_path()
    manifest = tmp_path / "Local" / "LocalGateKeys" / f"{NATIVE_HOST_NAME}.json"
    manifest.parent.mkdir(parents=True)
    manifest.write_text(json.dumps({"name": NATIVE_HOST_NAME, "type": "stdio", "path": str(alias)}), encoding="utf-8")

    class Key:
        def __enter__(self):
            return self

        def __exit__(self, *_):
            return False

    fake = types.SimpleNamespace(HKEY_CURRENT_USER="HKCU", OpenKey=lambda *_a: Key(),
                                 QueryValue=lambda _key, _name: str(manifest))
    monkeypatch.setitem(sys.modules, "winreg", fake)
    monkeypatch.setattr(pipe_transport.os, "name", "nt")
    found = pipe_transport._registered_native_host_paths()
    assert found
    assert set(found.values()) == {str(package / "NativeHost" / "LocalGateKeysNativeHost.exe")}


def test_repair_writes_alias_into_manifests_and_real_image_into_pins(monkeypatch, tmp_path) -> None:
    package = tmp_path / "pkg"
    _frozen(monkeypatch, package)
    _packaged(monkeypatch, package, tmp_path / "Local")
    host = package / "NativeHost" / "LocalGateKeysNativeHost.exe"
    host.parent.mkdir(parents=True)
    host.write_bytes(b"host")
    data = tmp_path / "data"
    data.mkdir()
    monkeypatch.setenv("LOCALGATEKEYS_DATA_DIR", str(data))
    monkeypatch.setattr(browser_bridge.os, "name", "nt")
    monkeypatch.setattr(browser_bridge, "_secure_data_directory", lambda _path: None)
    registered: list[tuple[Path, Path | None]] = []
    monkeypatch.setattr(browser_bridge, "_register_manifest", lambda *paths: registered.append(paths))

    browser_bridge.repair_browser_bridge()

    alias = str(distribution.native_host_alias_path())
    assert json.loads((data / f"{NATIVE_HOST_NAME}.json").read_text(encoding="utf-8"))["path"] == alias
    assert json.loads((data / f"{NATIVE_HOST_NAME}.firefox.json").read_text(encoding="utf-8"))["path"] == alias
    config = json.loads((data / "install.json").read_text(encoding="utf-8"))
    assert config["mode"] == "msix"
    assert config["native_host_path"] == str(host)
    assert config["native_host_launch_path"] == alias
    assert registered


def _fake_registry(existing: dict[str, str]):
    writes: list[tuple[str, str]] = []

    class Key:
        def __init__(self, path: str) -> None:
            self.path = path

        def __enter__(self):
            return self

        def __exit__(self, *_):
            return False

    def open_key(_root, path):
        if path not in existing:
            raise FileNotFoundError(path)
        return Key(path)

    fake = types.SimpleNamespace(
        HKEY_CURRENT_USER="HKCU", REG_SZ=1,
        OpenKey=open_key, QueryValue=lambda key, _name: existing[key.path],
        CreateKey=lambda _root, path: Key(path),
        SetValueEx=lambda key, _name, _reserved, _kind, value: writes.append((key.path, value)),
    )
    return fake, writes


def test_packaged_registration_creates_missing_keys_but_never_overwrites(monkeypatch, tmp_path) -> None:
    _frozen(monkeypatch, tmp_path / "pkg")
    _packaged(monkeypatch, tmp_path / "pkg", tmp_path / "Local")
    chrome, firefox = tmp_path / "host.json", tmp_path / "host.firefox.json"
    chrome_key = rf"Software\Google\Chrome\NativeMessagingHosts\{NATIVE_HOST_NAME}"
    edge_key = rf"Software\Microsoft\Edge\NativeMessagingHosts\{NATIVE_HOST_NAME}"
    fake, writes = _fake_registry({chrome_key: str(chrome)})  # e.g. left by the Inno Setup build
    monkeypatch.setitem(sys.modules, "winreg", fake)

    browser_bridge._register_manifest(chrome, firefox)

    assert [path for path, _value in writes] == [edge_key, rf"Software\Mozilla\NativeMessagingHosts\{NATIVE_HOST_NAME}"]


def test_packaged_registration_reports_a_foreign_value_without_writing_it(monkeypatch, tmp_path) -> None:
    _frozen(monkeypatch, tmp_path / "pkg")
    _packaged(monkeypatch, tmp_path / "pkg", tmp_path / "Local")
    chrome_key = rf"Software\Google\Chrome\NativeMessagingHosts\{NATIVE_HOST_NAME}"
    fake, writes = _fake_registry({chrome_key: str(tmp_path / "elsewhere.json")})
    monkeypatch.setitem(sys.modules, "winreg", fake)

    with pytest.raises(OSError, match="Google"):
        browser_bridge._register_manifest(tmp_path / "host.json", tmp_path / "host.firefox.json")
    assert chrome_key not in [path for path, _value in writes]


def test_unpackaged_registration_still_overwrites(monkeypatch, tmp_path) -> None:
    _frozen(monkeypatch, tmp_path / "app")
    _unpackaged(monkeypatch)
    chrome_key = rf"Software\Google\Chrome\NativeMessagingHosts\{NATIVE_HOST_NAME}"
    fake, writes = _fake_registry({chrome_key: str(tmp_path / "old.json")})
    monkeypatch.setitem(sys.modules, "winreg", fake)
    browser_bridge._register_manifest(tmp_path / "host.json", None)
    assert (chrome_key, str(tmp_path / "host.json")) in writes


def test_launch_registration_runs_only_in_a_package(monkeypatch, tmp_path) -> None:
    calls: list[str] = []
    monkeypatch.setattr(browser_bridge, "repair_browser_bridge", lambda: calls.append("repair"))
    _frozen(monkeypatch, tmp_path / "app")
    _unpackaged(monkeypatch)
    assert browser_bridge.ensure_packaged_registration() is False
    _packaged(monkeypatch, tmp_path / "app", tmp_path / "Local")
    assert browser_bridge.ensure_packaged_registration() is True

    def broken() -> None:
        raise OSError("registry unavailable")

    monkeypatch.setattr(browser_bridge, "repair_browser_bridge", broken)
    assert browser_bridge.ensure_packaged_registration() is False
    assert calls == ["repair"]


# -- start with Windows ---------------------------------------------------------

class _FakeStartupTask:
    DISABLED, DISABLED_BY_USER, ENABLED, DISABLED_BY_POLICY, ENABLED_BY_POLICY = 0, 1, 2, 3, 4
    ENABLED_STATES = frozenset({2, 4})

    def __init__(self, enable_result: int) -> None:
        self.enable_result = enable_result
        self.calls: list[tuple[str, str]] = []

    def request_enable(self, task_id: str) -> int:
        self.calls.append(("enable", task_id))
        return self.enable_result

    def disable(self, task_id: str) -> int:
        self.calls.append(("disable", task_id))
        return 0

    def state(self, task_id: str) -> int:
        self.calls.append(("state", task_id))
        return self.enable_result


def _no_run_key(monkeypatch) -> None:
    def forbidden(*_args, **_kwargs):
        raise AssertionError("a packaged build must not touch the Run key")

    monkeypatch.setitem(sys.modules, "winreg", types.SimpleNamespace(CreateKey=forbidden, OpenKey=forbidden,
                                                                     HKEY_CURRENT_USER="HKCU"))


def test_packaged_start_with_windows_uses_the_startup_task(monkeypatch, tmp_path) -> None:
    _frozen(monkeypatch, tmp_path / "pkg")
    _packaged(monkeypatch, tmp_path / "pkg", tmp_path / "Local")
    monkeypatch.setattr(startup.os, "name", "nt")
    task = _FakeStartupTask(enable_result=2)
    monkeypatch.setitem(sys.modules, "localvault.msix_startup", task)
    import localvault

    monkeypatch.setattr(localvault, "msix_startup", task, raising=False)
    _no_run_key(monkeypatch)

    startup.set_start_with_windows(True)
    startup.set_start_with_windows(False)
    assert startup.is_start_with_windows_enabled()
    startup.sync_start_with_windows(True)  # no Run key to repair, task left alone
    assert task.calls == [("enable", distribution.STARTUP_TASK_ID), ("disable", distribution.STARTUP_TASK_ID),
                          ("state", distribution.STARTUP_TASK_ID)]


def test_startup_task_turned_off_by_the_user_is_reported(monkeypatch, tmp_path) -> None:
    _frozen(monkeypatch, tmp_path / "pkg")
    _packaged(monkeypatch, tmp_path / "pkg", tmp_path / "Local")
    monkeypatch.setattr(startup.os, "name", "nt")
    task = _FakeStartupTask(enable_result=1)
    monkeypatch.setitem(sys.modules, "localvault.msix_startup", task)
    import localvault

    monkeypatch.setattr(localvault, "msix_startup", task, raising=False)
    _no_run_key(monkeypatch)
    with pytest.raises(OSError, match="Startup"):
        startup.set_start_with_windows(True)
    assert not startup.is_start_with_windows_enabled()


@pytest.mark.skipif(sys.platform != "win32", reason="WinRT is Windows-only")
def test_startup_task_api_fails_cleanly_without_package_identity() -> None:
    from localvault import msix_startup

    with pytest.raises(OSError):
        msix_startup.state(distribution.STARTUP_TASK_ID)
