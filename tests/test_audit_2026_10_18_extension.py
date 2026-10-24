"""Audit 2026-10-18, M6: frozen (installer / MSIX / Store) builds trust only the
store-assigned extension IDs; the developer ID (derived from the public key
committed in browser-extension/manifest.json) only for source runs, an
explicit developer opt-in, or while a store ID is still a placeholder.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

import pytest

import localvault.config as config
from localvault import browser_bridge, distribution, native_host

CWS_ID = "abcdefghijklmnopabcdefghijklmnop"
EDGE_ID = "ponmlkjihgfedcbaponmlkjihgfedcba"
DEV = config.EXTENSION_ID


def _origin(value: str) -> str:
    return f"chrome-extension://{value}/"


@pytest.fixture
def data(monkeypatch, tmp_path: Path) -> Path:
    monkeypatch.setenv("LOCALGATEKEYS_DATA_DIR", str(tmp_path))
    return tmp_path


@pytest.fixture
def frozen(monkeypatch, data):
    monkeypatch.setattr(sys, "frozen", True, raising=False)
    return data


@pytest.fixture
def store_ids(monkeypatch):
    monkeypatch.setattr(config, "CHROME_WEB_STORE_EXTENSION_ID", CWS_ID)
    monkeypatch.setattr(config, "EDGE_ADDONS_EXTENSION_ID", EDGE_ID)


def test_frozen_build_with_store_ids_trusts_only_the_store_ids(frozen, store_ids) -> None:
    trust = config.extension_trust()
    assert trust.chromium_ids == (CWS_ID, EDGE_ID)
    assert trust.developer_id_reason is None
    assert trust.missing_store_ids == ()
    assert browser_bridge._allowed_origins() == [_origin(CWS_ID), _origin(EDGE_ID)]
    assert browser_bridge._manifest_payload(Path("host.exe"))["allowed_origins"] == [_origin(CWS_ID), _origin(EDGE_ID)]


def test_native_host_of_a_frozen_build_rejects_the_developer_id(frozen, store_ids, monkeypatch) -> None:
    # A user-writable install.json that still lists the dev ID changes nothing.
    monkeypatch.setattr(config, "read_json", lambda _path: {"allowed_extension_origins": [_origin(DEV)]})
    assert not native_host._verify_caller(["host.exe", _origin(DEV)])
    assert not native_host._verify_caller(["host.exe", f"extension://{DEV}/"])
    for value in (CWS_ID, EDGE_ID):
        assert native_host._verify_caller(["host.exe", _origin(value)])
        assert native_host._verify_caller(["host.exe", f"extension://{value}/"])


def test_developer_opt_in_file_restores_the_developer_id(frozen, store_ids) -> None:
    (frozen / config.DEVELOPER_EXTENSION_OPT_IN).write_text("", encoding="utf-8")
    trust = config.extension_trust()
    assert trust.developer_id_reason == config.DEV_ID_OPT_IN
    assert DEV in trust.chromium_ids
    assert native_host._verify_caller(["host.exe", _origin(DEV)])
    assert browser_bridge._allowed_origins()[0] == _origin(DEV)


def test_opt_in_must_be_a_file(frozen, store_ids) -> None:
    (frozen / config.DEVELOPER_EXTENSION_OPT_IN).mkdir()
    assert config.extension_trust().developer_id_reason is None


@pytest.mark.parametrize(("cws", "edge", "missing"), [
    ("", "", ("chrome_web_store", "edge_addons")),
    (CWS_ID, "", ("edge_addons",)),
    ("", EDGE_ID, ("chrome_web_store",)),
])
def test_unassigned_store_id_keeps_the_developer_id_and_reports_it(frozen, monkeypatch, cws, edge, missing) -> None:
    monkeypatch.setattr(config, "CHROME_WEB_STORE_EXTENSION_ID", cws)
    monkeypatch.setattr(config, "EDGE_ADDONS_EXTENSION_ID", edge)
    trust = config.extension_trust()
    assert trust.developer_id_reason == config.DEV_ID_STORE_ID_UNASSIGNED
    assert trust.missing_store_ids == missing
    assert trust.chromium_ids[0] == DEV
    assert native_host._verify_caller(["host.exe", _origin(DEV)])
    log = (frozen / "native-host.log").read_text(encoding="utf-8")
    assert "caller_developer_extension_id reason=store_id_unassigned" in log


def test_source_runs_always_trust_the_developer_id(data, store_ids, monkeypatch) -> None:
    monkeypatch.delattr(sys, "frozen", raising=False)
    trust = config.extension_trust()
    assert trust.developer_id_reason == config.DEV_ID_DEVELOPER_INSTALL
    assert trust.chromium_ids == (DEV, CWS_ID, EDGE_ID)
    assert native_host._verify_caller(["host.exe", _origin(DEV)])


def test_explicit_unknown_id_is_not_added_to_a_frozen_manifest(frozen, store_ids) -> None:
    other = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    assert browser_bridge._allowed_origins(other) == [_origin(CWS_ID), _origin(EDGE_ID)]
    (frozen / config.DEVELOPER_EXTENSION_OPT_IN).write_text("", encoding="utf-8")
    assert browser_bridge._allowed_origins(other)[0] == _origin(other)


def test_native_host_fails_closed_in_a_frozen_build_when_config_cannot_load(frozen, monkeypatch) -> None:
    monkeypatch.setattr(native_host, "_caller_trust", lambda: None)
    assert native_host._allowed_callers() == set()
    assert not native_host._verify_caller(["host.exe", _origin(DEV)])


def test_firefox_gecko_id_is_still_accepted(frozen, store_ids) -> None:
    # Firefox passes no signature state; the AMO-signed id is the gecko id.
    assert native_host._verify_caller(["host.exe", "C:/x/m.json", native_host.FIREFOX_EXTENSION_ID])


@pytest.mark.skipif(os.name != "nt", reason="registration is Windows-only")
def test_repair_on_upgrade_rewrites_a_manifest_that_lists_the_developer_id(frozen, store_ids, monkeypatch) -> None:
    host = frozen / "LocalGateKeysNativeHost.exe"
    host.write_bytes(b"MZ")
    monkeypatch.setattr(browser_bridge, "_native_host_executable", lambda: host)
    monkeypatch.setattr(browser_bridge, "_secure_data_directory", lambda _path: None)
    registered: list[Path] = []
    monkeypatch.setattr(browser_bridge, "_register_manifest", lambda path, _ff=None: registered.append(path))
    monkeypatch.setattr(distribution, "native_host_alias_path", lambda: None)
    monkeypatch.setattr(distribution, "is_packaged", lambda: True)
    # The manifest an older MSIX build left behind.
    old = frozen / f"{config.NATIVE_HOST_NAME}.json"
    old.write_text(json.dumps({"allowed_origins": [_origin(DEV), _origin(CWS_ID)]}), encoding="utf-8")

    assert browser_bridge.repair_browser_bridge() == old
    manifest = json.loads(old.read_text(encoding="utf-8"))
    assert manifest["allowed_origins"] == [_origin(CWS_ID), _origin(EDGE_ID)]
    install = json.loads(config.install_config_path().read_text(encoding="utf-8"))
    assert install["mode"] == "msix"
    assert install["allowed_extension_origins"] == [_origin(CWS_ID), _origin(EDGE_ID)]
    assert install["developer_extension_id"] is None
    assert install["unassigned_store_extension_ids"] == []
    assert registered == [old]


@pytest.mark.skipif(os.name != "nt", reason="registration is Windows-only")
def test_repair_with_placeholder_store_ids_reports_them(frozen, monkeypatch) -> None:
    monkeypatch.setattr(config, "CHROME_WEB_STORE_EXTENSION_ID", "")
    monkeypatch.setattr(config, "EDGE_ADDONS_EXTENSION_ID", "")
    host = frozen / "LocalGateKeysNativeHost.exe"
    host.write_bytes(b"MZ")
    monkeypatch.setattr(browser_bridge, "_native_host_executable", lambda: host)
    monkeypatch.setattr(browser_bridge, "_secure_data_directory", lambda _path: None)
    monkeypatch.setattr(browser_bridge, "_register_manifest", lambda *_args: None)
    monkeypatch.setattr(distribution, "native_host_alias_path", lambda: None)
    monkeypatch.setattr(distribution, "is_packaged", lambda: False)
    browser_bridge.repair_browser_bridge()
    install = json.loads(config.install_config_path().read_text(encoding="utf-8"))
    assert install["mode"] == "installed"
    assert install["allowed_extension_origins"] == [_origin(DEV)]
    assert install["developer_extension_id"] == config.DEV_ID_STORE_ID_UNASSIGNED
    assert install["unassigned_store_extension_ids"] == ["chrome_web_store", "edge_addons"]
