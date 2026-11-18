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
    launcher = data / distribution.FIREFOX_HOST_LAUNCHER
    assert json.loads((data / f"{NATIVE_HOST_NAME}.json").read_text(encoding="utf-8"))["path"] == alias
    # Firefox cannot start the alias directly: it gets the launcher batch file.
    assert json.loads((data / f"{NATIVE_HOST_NAME}.firefox.json").read_text(encoding="utf-8"))["path"] == str(launcher)
    assert launcher.read_bytes() == distribution.firefox_native_host_launcher_script().encode("ascii")
    config = json.loads((data / "install.json").read_text(encoding="utf-8"))
    assert config["mode"] == "msix"
    assert config["native_host_path"] == str(host)
    assert config["native_host_launch_path"] == alias
    assert config["firefox_native_host_launch_path"] == str(launcher)
    assert registered
    # The pin and diagnostics see the package host behind both launch paths.
    assert distribution.resolve_native_host_path(str(launcher)) == str(host)
    assert distribution.resolve_native_host_path(alias) == str(host)

    # Never touch the real HKCU from a test (this once deleted the developer's own browser registrations).
    unregistered: list[bool] = []
    monkeypatch.setattr(browser_bridge, "_unregister_manifest", lambda: unregistered.append(True))
    browser_bridge.unregister_browser_bridge()
    assert unregistered and not launcher.exists()


def test_firefox_launcher_runs_the_alias_through_localappdata(monkeypatch, tmp_path) -> None:
    _frozen(monkeypatch, tmp_path / "app")
    _unpackaged(monkeypatch)
    assert distribution.firefox_native_host_launcher_path() is None
    assert distribution.firefox_native_host_launcher_script() is None

    _packaged(monkeypatch, tmp_path / "pkg", tmp_path / "Local With Space & 100%")
    data = tmp_path / "data"
    monkeypatch.setenv("LOCALGATEKEYS_DATA_DIR", str(data))
    script = distribution.firefox_native_host_launcher_script()
    assert script == ("@setlocal DisableDelayedExpansion\r\n"
                      f'@"%LOCALAPPDATA%\\Microsoft\\WindowsApps\\{FAMILY}\\{distribution.NATIVE_HOST_ALIAS}" %*\r\n')
    # Nothing from the user's environment is written into the file.
    assert "Space" not in script and script.isascii()
    assert distribution.firefox_native_host_launcher_path() == data / distribution.FIREFOX_HOST_LAUNCHER


def test_firefox_launcher_with_unexpected_family_name_is_not_written(monkeypatch, tmp_path) -> None:
    _frozen(monkeypatch, tmp_path / "pkg")
    values = {"GetCurrentPackageFamilyName": 'Evil"&calc&_x', "GetCurrentPackagePath": str(tmp_path / "pkg")}
    monkeypatch.setattr(distribution, "_current_package_string", values.get)
    assert distribution.firefox_native_host_launcher_script() is None


def test_resolver_ignores_a_changed_firefox_launcher(monkeypatch, tmp_path) -> None:
    package = tmp_path / "pkg"
    _frozen(monkeypatch, package)
    _packaged(monkeypatch, package, tmp_path / "Local")
    data = tmp_path / "data"
    data.mkdir()
    monkeypatch.setenv("LOCALGATEKEYS_DATA_DIR", str(data))
    launcher = data / distribution.FIREFOX_HOST_LAUNCHER
    assert distribution.resolve_native_host_path(str(launcher)) == str(launcher)  # missing
    launcher.write_bytes(distribution.firefox_native_host_launcher_script().encode("ascii") + b"@calc\r\n")
    assert distribution.resolve_native_host_path(str(launcher)) == str(launcher)
    launcher.write_bytes(distribution.firefox_native_host_launcher_script().encode("ascii"))
    assert distribution.resolve_native_host_path(str(launcher)) == str(package / distribution.NATIVE_HOST_IMAGE)
    other = tmp_path / "elsewhere" / distribution.FIREFOX_HOST_LAUNCHER
    other.parent.mkdir()
    other.write_bytes(launcher.read_bytes())
    assert distribution.resolve_native_host_path(str(other)) == str(other)


def test_pipe_pin_accepts_alias_for_chromium_and_launcher_for_firefox(monkeypatch, tmp_path) -> None:
    package = tmp_path / "pkg"
    _frozen(monkeypatch, package)
    _packaged(monkeypatch, package, tmp_path / "Local")
    data = tmp_path / "data"
    data.mkdir()
    monkeypatch.setenv("LOCALGATEKEYS_DATA_DIR", str(data))
    launcher = data / distribution.FIREFOX_HOST_LAUNCHER
    launcher.write_bytes(distribution.firefox_native_host_launcher_script().encode("ascii"))
    chromium = data / f"{NATIVE_HOST_NAME}.json"
    firefox = data / f"{NATIVE_HOST_NAME}.firefox.json"
    for manifest, path in ((chromium, distribution.native_host_alias_path()), (firefox, launcher)):
        manifest.write_text(json.dumps({"name": NATIVE_HOST_NAME, "type": "stdio", "path": str(path)}),
                            encoding="utf-8")
    values = {
        rf"Software\Google\Chrome\NativeMessagingHosts\{NATIVE_HOST_NAME}": str(chromium),
        rf"Software\Microsoft\Edge\NativeMessagingHosts\{NATIVE_HOST_NAME}": str(chromium),
        rf"Software\Mozilla\NativeMessagingHosts\{NATIVE_HOST_NAME}": str(firefox),
    }
    fake, _writes = _fake_registry(values)
    monkeypatch.setitem(sys.modules, "winreg", fake)
    monkeypatch.setattr(pipe_transport.os, "name", "nt")
    found = pipe_transport._registered_native_host_paths()
    assert sorted(found) == ["Chrome", "Edge", "Firefox"]
    assert pipe_transport.ClientPinPolicy._registered_host(found) == str(package / distribution.NATIVE_HOST_IMAGE)


def _fake_outside(monkeypatch: pytest.MonkeyPatch, real: dict[str, str], *, add_works: bool = True) -> list[tuple]:
    """Stand-in for the out-of-package reg.exe: ``real`` is the hive browsers read."""

    calls: list[tuple] = []

    def run(*args: str) -> int | None:
        calls.append(args)
        key = args[1].removeprefix("HKCU\\")
        if args[0] == "query":
            return 0 if real.get(key, "").lower() == args[3].lower() else 1
        if args[0] == "add" and add_works:
            real[key] = args[6]
            return 0
        return 1

    monkeypatch.setattr(browser_bridge, "_run_reg_outside_package", run)
    return calls


def _fake_registry(existing: dict[str, str], real: dict[str, str] | None = None):
    """``existing`` is the package's view; writes also reach ``real`` when given."""

    writes: list[tuple[str, str]] = []

    def set_value(key, _name, _reserved, _kind, value):
        writes.append((key.path, value))
        existing[key.path] = value
        if real is not None:
            real[key.path] = value

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
        SetValueEx=set_value,
    )
    return fake, writes


CHROME_KEY = rf"Software\Google\Chrome\NativeMessagingHosts\{NATIVE_HOST_NAME}"
EDGE_KEY = rf"Software\Microsoft\Edge\NativeMessagingHosts\{NATIVE_HOST_NAME}"
FIREFOX_KEY = rf"Software\Mozilla\NativeMessagingHosts\{NATIVE_HOST_NAME}"


def _packaged_registry(monkeypatch, tmp_path, inside: dict[str, str], real: dict[str, str] | None = None, **kw):
    _frozen(monkeypatch, tmp_path / "pkg")
    _packaged(monkeypatch, tmp_path / "pkg", tmp_path / "Local")
    monkeypatch.setenv("LOCALGATEKEYS_DATA_DIR", str(tmp_path / "data"))
    real = dict(inside) if real is None else real
    fake, writes = _fake_registry(inside, real)
    monkeypatch.setitem(sys.modules, "winreg", fake)
    calls = _fake_outside(monkeypatch, real, **kw)
    return writes, real, calls


def _working_manifest(path: Path, launcher: Path | None = None) -> Path:
    launcher = launcher or path.with_name("LocalGateKeysNativeHost.exe")
    launcher.parent.mkdir(parents=True, exist_ok=True)
    launcher.touch()
    path.write_text(json.dumps({"name": NATIVE_HOST_NAME, "type": "stdio", "path": str(launcher)}), encoding="utf-8")
    return path


def test_packaged_registration_creates_missing_keys_and_keeps_a_matching_one(monkeypatch, tmp_path) -> None:
    chrome, firefox = tmp_path / "host.json", tmp_path / "host.firefox.json"
    writes, real, _calls = _packaged_registry(monkeypatch, tmp_path, {CHROME_KEY: str(chrome)})  # e.g. Inno Setup

    browser_bridge._register_manifest(chrome, firefox)

    assert [path for path, _value in writes] == [EDGE_KEY, FIREFOX_KEY]
    assert real == {CHROME_KEY: str(chrome), EDGE_KEY: str(chrome), FIREFOX_KEY: str(firefox)}


def test_packaged_registration_keeps_a_working_other_install(monkeypatch, tmp_path) -> None:
    other = _working_manifest(tmp_path / "Inno" / "host.json")
    writes, real, calls = _packaged_registry(monkeypatch, tmp_path, {CHROME_KEY: str(other)})

    with pytest.raises(OSError, match="Google"):
        browser_bridge._register_manifest(tmp_path / "host.json", tmp_path / "host.firefox.json")
    assert CHROME_KEY not in [path for path, _value in writes]
    assert real[CHROME_KEY] == str(other)
    assert not [args for args in calls if args[0] == "add"]


@pytest.mark.parametrize("kind", ["missing", "unreadable", "not_ours", "no_launcher"])
def test_packaged_registration_replaces_a_stale_value(monkeypatch, tmp_path, kind) -> None:
    stale = tmp_path / "old-data" / "com.localgatekeys.app.firefox.json"
    stale.parent.mkdir()
    if kind == "unreadable":
        stale.write_text("{not json", encoding="utf-8")
    elif kind == "not_ours":
        _working_manifest(stale)
        stale.write_text(json.dumps({"name": "org.other.host", "path": str(stale.with_name("LocalGateKeysNativeHost.exe"))}),
                         encoding="utf-8")
    elif kind == "no_launcher":
        stale.write_text(json.dumps({"name": NATIVE_HOST_NAME, "path": str(tmp_path / "gone" / "host.cmd")}),
                         encoding="utf-8")
    chrome, firefox = tmp_path / "host.json", tmp_path / "host.firefox.json"
    writes, real, calls = _packaged_registry(
        monkeypatch, tmp_path, {CHROME_KEY: str(chrome), EDGE_KEY: str(chrome), FIREFOX_KEY: str(stale)})

    browser_bridge._register_manifest(chrome, firefox)

    assert writes == [(FIREFOX_KEY, str(firefox))]
    assert real[FIREFOX_KEY] == str(firefox)
    # Checked from outside the package; no fallback write was needed.
    assert ("query", f"HKCU\\{FIREFOX_KEY}", "/f", str(firefox), "/d", "/e") in calls
    assert not [args for args in calls if args[0] == "add"]


def test_packaged_registration_rewrites_from_outside_when_the_write_stays_private(monkeypatch, tmp_path) -> None:
    chrome, firefox = tmp_path / "host.json", tmp_path / "host.firefox.json"
    real = {CHROME_KEY: str(chrome), EDGE_KEY: str(chrome), FIREFOX_KEY: str(tmp_path / "stale.json")}
    inside = dict(real)
    _frozen(monkeypatch, tmp_path / "pkg")
    _packaged(monkeypatch, tmp_path / "pkg", tmp_path / "Local")
    monkeypatch.setenv("LOCALGATEKEYS_DATA_DIR", str(tmp_path / "data"))
    fake, _writes = _fake_registry(inside)  # copy-on-write: only the package's view changes
    monkeypatch.setitem(sys.modules, "winreg", fake)
    calls = _fake_outside(monkeypatch, real)

    browser_bridge._register_manifest(chrome, firefox)

    assert ("add", f"HKCU\\{FIREFOX_KEY}", "/ve", "/t", "REG_SZ", "/d", str(firefox), "/f") in calls
    assert real[FIREFOX_KEY] == str(firefox)


def test_packaged_registration_reports_needs_repair_when_the_real_value_stays_wrong(monkeypatch, tmp_path) -> None:
    chrome, firefox = tmp_path / "host.json", tmp_path / "host.firefox.json"
    real = {CHROME_KEY: str(chrome), EDGE_KEY: str(chrome), FIREFOX_KEY: str(tmp_path / "stale.json")}
    _frozen(monkeypatch, tmp_path / "pkg")
    _packaged(monkeypatch, tmp_path / "pkg", tmp_path / "Local")
    monkeypatch.setenv("LOCALGATEKEYS_DATA_DIR", str(tmp_path / "data"))
    fake, _writes = _fake_registry(dict(real))
    monkeypatch.setitem(sys.modules, "winreg", fake)
    _fake_outside(monkeypatch, real, add_works=False)

    with pytest.raises(OSError, match="Mozilla"):
        browser_bridge._register_manifest(chrome, firefox)
    # The next start sees its own (private) value but still checks the real one.
    with pytest.raises(OSError, match="Mozilla"):
        browser_bridge._register_manifest(chrome, firefox)


def test_packaged_registration_trusts_its_own_view_when_the_outside_check_cannot_run(monkeypatch, tmp_path) -> None:
    chrome, firefox = tmp_path / "host.json", tmp_path / "host.firefox.json"
    writes, _real, _calls = _packaged_registry(monkeypatch, tmp_path, {FIREFOX_KEY: str(tmp_path / "stale.json")})
    monkeypatch.setattr(browser_bridge, "_run_reg_outside_package", lambda *_args: None)

    browser_bridge._register_manifest(chrome, firefox)

    assert (FIREFOX_KEY, str(firefox)) in writes


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
