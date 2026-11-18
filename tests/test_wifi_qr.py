from __future__ import annotations

import json
from pathlib import Path

import pytest

from localvault.item_schema import WIFI_SECURITY_TYPES
from localvault.wifi_qr import wifi_qr_text

CASES = json.loads((Path(__file__).parent / "vectors" / "wifi_qr" / "cases.json").read_text(encoding="utf-8"))


@pytest.mark.parametrize("case", CASES, ids=[c["name"] for c in CASES])
def test_vectors(case):
    assert wifi_qr_text(case["ssid"], case["password"], case["security"], case["hidden"]) == case["text"]


def test_vectors_cover_every_security_type():
    assert {c["security"] for c in CASES} == set(WIFI_SECURITY_TYPES)


def test_unknown_security_has_no_qr():
    assert wifi_qr_text("a", "b", "bogus", False) is None
