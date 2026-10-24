import localvault.config as config
from localvault.config import EXTENSION_ORIGINS
from localvault.native_host import _verify_caller


def test_native_host_fails_closed_without_browser_origin() -> None:
    assert not _verify_caller(["localvault-native-host.exe"])


def test_native_host_accepts_only_configured_extension_origin() -> None:
    assert _verify_caller(["localvault-native-host.exe", EXTENSION_ORIGINS[0]])
    assert not _verify_caller(
        ["localvault-native-host.exe", "chrome-extension://aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/"]
    )


def test_native_host_accepts_firefox_manifest_and_extension_id_arguments() -> None:
    # Firefox: argv = [host, manifest path, extension id]
    assert _verify_caller(["host.exe", "C:/x/com.localgatekeys.app.firefox.json", "localgatekeys@localgatekeys.app"])
    assert not _verify_caller(["host.exe", "C:/x/manifest.json", "other@example.test"])
    assert not _verify_caller(["host.exe", "localgatekeys@localgatekeys.app"])


def test_native_host_does_not_trust_user_configured_origin(monkeypatch) -> None:
    monkeypatch.setattr(config, "install_config_path", lambda: "unused")
    monkeypatch.setattr(
        config,
        "read_json",
        lambda _path: {"allowed_extension_origins": ["chrome-extension://aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/"]},
    )
    assert not _verify_caller(
        ["localvault-native-host.exe", "chrome-extension://aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/"]
    )
