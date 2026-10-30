"""Browser extension localization: every key the code asks for exists in _locales/en."""

from __future__ import annotations

import json
import re
import shutil
import subprocess
import zipfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
EXT = ROOT / "browser-extension"
EN = EXT / "_locales" / "en" / "messages.json"
KEY = re.compile(r"^[A-Za-z0-9_]+$")


def _messages() -> dict:
    return json.loads(EN.read_text(encoding="utf-8"))


def _tr_keys(text: str) -> set[str]:
    return set(re.findall(r"""(?<![\w$.])tr\(\s*["']([A-Za-z0-9_]+)["']""", text))


def test_en_messages_exist_and_are_well_formed():
    msgs = _messages()
    assert msgs
    for key, entry in msgs.items():
        assert KEY.match(key), key
        assert isinstance(entry["message"], str) and entry["message"], key
        used = set(re.findall(r"\$([A-Za-z0-9_@]+)\$", entry["message"]))
        defined = {p.lower() for p in entry.get("placeholders", {})}
        assert {u.lower() for u in used} == defined, key
        for ph in entry.get("placeholders", {}).values():
            assert re.fullmatch(r"\$[1-9]", ph["content"]), key


def test_manifest_is_localized():
    manifest = json.loads((EXT / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["default_locale"] == "en"
    msgs = _messages()
    for field in ("name", "description"):
        value = manifest[field]
        assert value.startswith("__MSG_") and value.endswith("__"), field
        assert value[6:-2] in msgs


def test_popup_html_data_i18n_keys_exist():
    html = (EXT / "popup.html").read_text(encoding="utf-8")
    keys = set(re.findall(r'data-i18n(?:-[a-z-]+)?="([^"]+)"', html))
    assert keys
    assert keys <= set(_messages()), sorted(keys - set(_messages()))


@pytest.mark.parametrize("name", ["popup.js", "content.js", "login-safety.js", "background.js", "background-safari.js"])
def test_tr_keys_in_scripts_exist(name):
    keys = _tr_keys((EXT / name).read_text(encoding="utf-8"))
    assert keys, name
    assert keys <= set(_messages()), sorted(keys - set(_messages()))


def test_every_message_is_used():
    used: set[str] = set()
    for name in ("popup.js", "content.js", "login-safety.js", "background.js", "background-safari.js"):
        used |= _tr_keys((EXT / name).read_text(encoding="utf-8"))
    used |= set(re.findall(r'data-i18n(?:-[a-z-]+)?="([^"]+)"', (EXT / "popup.html").read_text(encoding="utf-8")))
    used |= {"ext_name", "ext_description", "ext_description_ios", "ext_description_macos"}
    assert set(_messages()) - used == set()


def test_tr_helper_falls_back_to_key():
    api = (EXT / "api.js").read_text(encoding="utf-8")
    assert "getMessage" in api and "|| key" in api


@pytest.mark.skipif(shutil.which("node") is None, reason="node not installed")
def test_store_package_ships_locales(tmp_path):
    subprocess.run(["node", str(EXT / "build-store-package.cjs"), str(tmp_path)], check=True, capture_output=True)
    zips = sorted(tmp_path.glob("*.zip"))
    assert len(zips) == 2
    for z in zips:
        with zipfile.ZipFile(z) as zf:
            assert "_locales/en/messages.json" in zf.namelist(), z.name
            assert json.loads(zf.read("_locales/en/messages.json")) == _messages()
