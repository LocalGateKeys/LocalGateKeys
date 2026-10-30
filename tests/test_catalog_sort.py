"""The app's vault list sort matches every case in the shared sort vectors."""
from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from localvault.app.catalog import sort_items, sort_title_key

VECTORS = json.loads((Path(__file__).parent / "vectors" / "vault_sort" / "cases.json").read_text(encoding="utf-8"))


def _items():
    return [SimpleNamespace(**{"created_at": None, "updated_at": None, **row}) for row in VECTORS["items"]]


@pytest.mark.parametrize("case", VECTORS["cases"], ids=lambda c: f"{c['option']}-{c['favorites_first']}")
def test_sort_matches_vectors(case):
    ordered = sort_items(_items(), case["option"], case["favorites_first"])
    assert [item.id for item in ordered] == case["expected"]


def test_title_key_folds_accents_width_and_case():
    assert sort_title_key("Éclair") == "eclair"
    assert sort_title_key("Ｚoom") == "zoom"
    assert sort_title_key("") == ""


def test_unknown_option_falls_back_to_title():
    ordered = sort_items(_items(), "bogus", False)
    assert [i.id for i in ordered] == next(c["expected"] for c in VECTORS["cases"]
                                           if c["option"] == "title_asc" and not c["favorites_first"])
