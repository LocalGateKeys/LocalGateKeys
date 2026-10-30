"""The shared vault sort rule: the committed vectors match the generator (other apps read the same file)."""
from __future__ import annotations

import importlib.util
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_sort_vectors_are_current():
    spec = importlib.util.spec_from_file_location("make_sort_vectors", ROOT / "scripts" / "make_sort_vectors.py")
    gen = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(gen)
    data = json.loads((ROOT / "tests" / "vectors" / "vault_sort" / "cases.json").read_text("utf-8"))
    assert data["items"] == gen.ITEMS
    for case in data["cases"]:
        assert gen.order(gen.ITEMS, case["option"], case["favorites_first"]) == case["expected"], case
