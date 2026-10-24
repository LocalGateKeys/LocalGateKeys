"""Store-assigned extension IDs reach the native-host manifest and caller check.

The Chrome Web Store and Edge Add-ons each assign their own extension ID; the
unpacked developer build keeps the ID derived from the manifest "key".  One
Chromium native-messaging manifest must allow all of them, and the native host
must accept each of them (and nothing else) as its caller.
"""

from __future__ import annotations

import io
import json
import struct
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

import localvault.config as config
from localvault import browser_bridge, native_host

CWS_ID = "abcdefghijklmnopabcdefghijklmnop"
EDGE_ID = "ponmlkjihgfedcbaponmlkjihgfedcba"
OTHER_ID = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"


@pytest.fixture
def store_ids(monkeypatch):
    """Simulate the placeholders being filled in after the listings exist."""

    monkeypatch.setattr(config, "CHROME_WEB_STORE_EXTENSION_ID", CWS_ID)
    monkeypatch.setattr(config, "EDGE_ADDONS_EXTENSION_ID", EDGE_ID)
    ids = config.chromium_extension_ids()
    monkeypatch.setattr(config, "CHROMIUM_EXTENSION_IDS", ids)
    monkeypatch.setattr(config, "EXTENSION_ORIGINS", config.extension_caller_origins(ids))
    # No install.json: only the package's built-in origins apply.
    monkeypatch.setattr(config, "read_json", lambda _path: {})
    return ids


def test_placeholders_are_unassigned_and_ignored_until_filled_in() -> None:
    # The Edge Add-ons ID is assigned; flip the Chrome assertion when its listing exists.
    assert config.CHROME_WEB_STORE_EXTENSION_ID == ""
    assert config.EDGE_ADDONS_EXTENSION_ID == "oclkjglnfefdmhddgicmbadaoehakbjj"
    assert config.CHROMIUM_EXTENSION_IDS == (config.EXTENSION_ID, config.EDGE_ADDONS_EXTENSION_ID)
    assert config.EXTENSION_ORIGINS == (
        f"chrome-extension://{config.EXTENSION_ID}/",
        f"extension://{config.EXTENSION_ID}/",
        f"chrome-extension://{config.EDGE_ADDONS_EXTENSION_ID}/",
        f"extension://{config.EDGE_ADDONS_EXTENSION_ID}/",
    )


def test_configured_store_ids_are_well_formed() -> None:
    for value in config.CHROMIUM_EXTENSION_IDS:
        assert len(value) == 32 and set(value) <= set("abcdefghijklmnop"), value


def test_store_ids_follow_the_dev_id_without_duplicates() -> None:
    assert config.chromium_extension_ids((CWS_ID, EDGE_ID)) == (config.EXTENSION_ID, CWS_ID, EDGE_ID)
    assert config.chromium_extension_ids(("", CWS_ID, CWS_ID)) == (config.EXTENSION_ID, CWS_ID)
    assert config.chromium_extension_ids((config.EXTENSION_ID,)) == (config.EXTENSION_ID,)


@pytest.mark.parametrize("bad", ["TODO", "x" * 32, CWS_ID.upper(), CWS_ID[:-1], CWS_ID + "a"])
def test_malformed_store_id_is_rejected_not_silently_allowed(bad: str) -> None:
    with pytest.raises(ValueError):
        config.chromium_extension_ids((bad,))


def test_native_host_manifest_allows_dev_and_store_origins(store_ids, tmp_path: Path) -> None:
    payload = browser_bridge._manifest_payload(tmp_path / "LocalGateKeysNativeHost.exe")
    assert payload["allowed_origins"] == [
        f"chrome-extension://{config.EXTENSION_ID}/",
        f"chrome-extension://{CWS_ID}/",
        f"chrome-extension://{EDGE_ID}/",
    ]


def test_explicit_extension_id_is_listed_first_once(store_ids) -> None:
    assert browser_bridge._allowed_origins(EDGE_ID) == [
        f"chrome-extension://{EDGE_ID}/",
        f"chrome-extension://{config.EXTENSION_ID}/",
        f"chrome-extension://{CWS_ID}/",
    ]


def test_native_host_accepts_every_listed_id_and_rejects_others(store_ids) -> None:
    for value in (config.EXTENSION_ID, CWS_ID, EDGE_ID):
        assert native_host._verify_caller(["host.exe", f"chrome-extension://{value}/"]), value
        assert native_host._verify_caller(["host.exe", f"extension://{value}/"]), value
    assert not native_host._verify_caller(["host.exe", f"chrome-extension://{OTHER_ID}/"])
    assert not native_host._verify_caller(["host.exe", f"chrome-extension://{CWS_ID}"])


def test_install_config_cannot_add_an_unlisted_store_id(store_ids, monkeypatch) -> None:
    monkeypatch.setattr(config, "read_json", lambda _path: {
        "allowed_extension_origins": [f"chrome-extension://{OTHER_ID}/", f"chrome-extension://{CWS_ID}/"],
    })
    assert native_host._verify_caller(["host.exe", f"chrome-extension://{CWS_ID}/"])
    assert not native_host._verify_caller(["host.exe", f"chrome-extension://{OTHER_ID}/"])


def _run_host(monkeypatch, argv: list[str], request: dict) -> list[dict]:
    body = json.dumps(request).encode()
    out = io.BytesIO()
    monkeypatch.setattr(sys, "argv", argv)
    monkeypatch.setattr(sys, "stdin", SimpleNamespace(buffer=io.BytesIO(struct.pack("=I", len(body)) + body)))
    monkeypatch.setattr(sys, "stdout", SimpleNamespace(buffer=out))
    native_host.main()
    data, replies = out.getvalue(), []
    while data:
        (length,) = struct.unpack("=I", data[:4])
        replies.append(json.loads(data[4:4 + length]))
        data = data[4 + length:]
    return replies


def test_store_caller_still_needs_a_verified_browser_parent(store_ids, monkeypatch, tmp_path: Path) -> None:
    """A listed store origin passes the argv check but never replaces the
    browser-ancestry check: only ``ping`` is relayed for an unverified parent."""

    monkeypatch.setenv("LOCALGATEKEYS_DATA_DIR", str(tmp_path))
    forwarded: list[str] = []
    monkeypatch.setattr(native_host, "_forward", lambda req: forwarded.append(req["action"]) or {"ok": True})
    argv = ["host.exe", f"chrome-extension://{CWS_ID}/"]

    monkeypatch.setattr(native_host, "_verify_browser_parent", lambda: False)
    replies = _run_host(monkeypatch, argv, {"action": "begin_browser", "origin": "https://example.test"})
    assert replies[0]["ok"] is False and replies[0]["stage"] == "peer"
    assert forwarded == []

    monkeypatch.setattr(native_host, "_verify_browser_parent", lambda: True)
    assert _run_host(monkeypatch, argv, {"action": "begin_browser"}) == [{"ok": True}]
    assert forwarded == ["begin_browser"]

    rejected = _run_host(monkeypatch, ["host.exe", f"chrome-extension://{OTHER_ID}/"], {"action": "ping"})
    assert rejected == [{"ok": False, "error": "caller_not_allowed"}]
    assert forwarded == ["begin_browser"]


def test_native_host_built_in_fallback_is_a_subset_of_the_config_origins() -> None:
    assert native_host._DEFAULT_ALLOWED_ORIGINS <= set(config.EXTENSION_ORIGINS)
