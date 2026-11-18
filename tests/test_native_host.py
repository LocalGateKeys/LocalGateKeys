import pytest

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


@pytest.mark.parametrize(("argv", "expected"), [
    (["h.exe", "mcp"], ["mcp"]),
    (["h.exe", "lgk", "mcp"], ["mcp"]),
    (["h.exe", "lgk", "read", "lgk://GitHub/password"], ["read", "lgk://GitHub/password"]),
    (["h.exe", "lgk"], []),
])
def test_native_host_cli_subcommands_run_lgk(monkeypatch, argv, expected) -> None:
    import localvault.native_host as host

    ran = []
    monkeypatch.setattr(host, "_run_cli", lambda args: ran.append(args) or 3)
    monkeypatch.setattr(host, "_configure_binary_stdio", lambda: (_ for _ in ()).throw(AssertionError("browser")))
    monkeypatch.setattr(host.sys, "argv", argv)
    with pytest.raises(SystemExit) as exc:
        host.main()
    assert exc.value.code == 3 and ran == [expected]


def test_native_host_browser_arguments_never_start_the_cli(monkeypatch) -> None:
    import localvault.native_host as host

    origin = sorted(EXTENSION_ORIGINS)[0] if EXTENSION_ORIGINS else "chrome-extension://x/"
    for argv in (["h.exe", origin], ["h.exe", origin, "--parent-window=0"], ["h.exe", "C:/m.json", "ext@id"],
                 ["h.exe", "mcp", "extra"], ["h.exe", "MCP"], ["h.exe", "LGK"], ["h.exe"]):
        assert host._cli_arguments(argv) is None
    # A browser launch still takes the native-messaging path, never the CLI.
    monkeypatch.setattr(host, "_run_cli", lambda args: (_ for _ in ()).throw(AssertionError("cli")))
    monkeypatch.setattr(host, "_configure_binary_stdio", lambda: None)
    monkeypatch.setattr(host, "_verify_caller", lambda argv: False)
    written = []
    monkeypatch.setattr(host, "_write_native_message", lambda stream, msg: written.append(msg))
    monkeypatch.setattr(host.sys, "argv", ["h.exe", "chrome-extension://bad/"])
    host.main()
    assert written == [{"ok": False, "error": "caller_not_allowed"}]


def test_native_host_cli_is_the_lgk_main(monkeypatch) -> None:
    import localvault.cli.main as cli_main
    import localvault.native_host as host

    seen = []
    monkeypatch.setattr(cli_main, "main", lambda args: seen.append(args) or 0)
    assert host._run_cli(["status"]) == 0 and seen == [["status"]]


def test_oversized_reply_becomes_a_small_error_not_a_protocol_error(monkeypatch, tmp_path):
    import io as _io
    import json as _json
    import struct as _struct

    from localvault import native_host as _nh

    monkeypatch.setenv("LOCALGATEKEYS_DATA_DIR", str(tmp_path))
    monkeypatch.setattr(_nh, "_log", lambda *a, **k: None)
    stream = _io.BytesIO()
    _nh._send_response(stream, {"ok": True, "blob": "x" * (_nh._MAX_NATIVE_MESSAGE + 10)})
    raw = stream.getvalue()
    (length,) = _struct.unpack("=I", raw[:4])
    reply = _json.loads(raw[4:4 + length])
    assert reply["error"] == "response_too_large"
