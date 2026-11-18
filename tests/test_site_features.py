"""The bundled site-features table (scripts/build_site_features.py) and its copies stay in step.

The apps read src/localvault/assets/site_features.json; Android packages a byte copy and the iPhone/Mac
targets list the file in ios/project.yml.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

from localvault import origin

ROOT = Path(__file__).resolve().parents[1]
ASSET = ROOT / "src" / "localvault" / "assets" / "site_features.json"
ANDROID_COPY = ROOT / "android" / "app" / "src" / "main" / "assets" / "site_features.json"
PROJECT = ROOT / "ios" / "project.yml"


def _data() -> dict:
    return json.loads(ASSET.read_text(encoding="utf-8"))


def test_format_header():
    data = _data()
    assert data["format"] == "localgatekeys-site-features"
    assert data["version"] == 1
    assert re.fullmatch(r"\d{4}-\d{2}-\d{2}", data["generated"])
    assert data["sources"]
    for source in data["sources"].values():
        assert source["licence"] and source["licenceUrl"].startswith("https://")


def test_keys_are_registrable_domains():
    keys = list(_data()["sites"])
    assert len(keys) > 500
    assert keys == sorted(keys)
    for key in keys:
        assert key == key.lower() and key.isascii(), key
        assert origin.base_domain(key) == key and "." in key, key


def test_values_sorted_subset():
    for key, value in _data()["sites"].items():
        assert value and value == sorted(set(value)) and set(value) <= {"passkey", "totp"}, key


def test_android_copy_matches():
    assert ANDROID_COPY.read_bytes() == ASSET.read_bytes(), "run: python scripts/build_site_features.py"


def test_ios_project_references_file():
    assert PROJECT.read_text(encoding="utf-8").count("site_features.json") == 2


def test_size_budget():
    assert ASSET.stat().st_size < 400_000
