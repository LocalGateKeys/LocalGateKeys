"""``tests/vectors/sync/mac/licence_text.json`` is what ``scripts/gen_licence_text_vectors.py`` writes."""
from __future__ import annotations

import importlib.util
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
VECTOR = ROOT / "tests" / "vectors" / "sync" / "mac" / "licence_text.json"


def _generator():
    spec = importlib.util.spec_from_file_location("gen_licence_text_vectors", ROOT / "scripts" / "gen_licence_text_vectors.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_generator_reproduces_the_committed_file():
    assert _generator().build() == VECTOR.read_bytes()
