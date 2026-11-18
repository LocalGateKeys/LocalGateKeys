"""Lookalike-domain classifier (src/localvault/lookalike.py).

The vectors in tests/vectors/lookalike/cases.json are shared with
tests/extension/lookalike.test.cjs, so both runtimes must agree on each one.
They test ``match``, the shared algorithm; ``classify`` (the desktop shield)
narrows "related" (tests/test_lookalike_related.py).
"""

from __future__ import annotations

import json
import socket
from pathlib import Path

import pytest

from localvault import lookalike
from localvault.lookalike import Verdict, classify, match

ROOT = Path(__file__).resolve().parents[1]
VECTORS = json.loads((ROOT / "tests" / "vectors" / "lookalike" / "cases.json").read_text(encoding="utf-8"))
CASES = VECTORS["cases"]


def test_vectors_cover_every_kind() -> None:
    assert len(CASES) >= 40
    kinds = {case["kind"] for case in CASES}
    assert kinds == {"exact", "related", "lookalike", "unknown"}
    reasons = {case["reason"] for case in CASES if case["kind"] == "lookalike"}
    assert {"homoglyph", "mixed-script", "edit-distance"} <= reasons
    assert len({case["name"] for case in CASES}) == len(CASES)


@pytest.mark.parametrize("case", CASES, ids=[case["name"] for case in CASES])
def test_shared_vector(case: dict) -> None:
    verdict = match(case["origin"], case["saved"])
    assert isinstance(verdict, Verdict)
    assert (verdict.kind, verdict.matched, verdict.reason) == (case["kind"], case["matched"], case["reason"])


def test_crosscheck_corpus_is_current_and_agrees() -> None:
    """tests/vectors/lookalike/crosscheck.json (also run by the extension, Kotlin and Swift tests).

    ``pairs`` / ``lists`` are the shared algorithm (``match``); ``shield_pairs`` / ``shield_lists`` the phishing
    shield (``classify``). The builder imports both by name.
    """
    import importlib.util

    spec = importlib.util.spec_from_file_location("build_crosscheck", ROOT / "scripts" / "build_lookalike_crosscheck.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)  # type: ignore[union-attr]
    assert module.OUT.read_text(encoding="utf-8") == module.build(), "run scripts/build_lookalike_crosscheck.py"
    corpus = json.loads(module.OUT.read_text(encoding="utf-8"))
    assert len(corpus["pairs"]) >= 5000 and len(corpus["lists"]) == len(corpus["origins"])


def test_review_focus_cases() -> None:
    # Punycode origin decoding to a Cyrillic lookalike of a saved domain.
    assert classify("https://xn--pple-43d.com", ["https://apple.com"]).kind == "lookalike"
    # Subdomain of a saved site: related in the shared algorithm, not vouched for by the shield.
    assert match("https://accounts.example.com", ["https://example.com"]).kind == "related"
    assert classify("https://accounts.example.com", ["https://example.com"]).kind == "unknown"
    # A public-suffix host: another user's site is not related.
    assert classify("https://other.github.io", ["https://user.github.io"]).kind == "unknown"


def test_accepts_any_iterable_and_skips_non_strings() -> None:
    saved = (value for value in [None, 42, "https://example.com"])
    verdict = classify("https://example.com", saved)  # type: ignore[arg-type]
    assert verdict == Verdict("exact", "https://example.com", "same-origin")


def test_verdict_is_immutable() -> None:
    verdict = classify("https://example.com", [])
    with pytest.raises(AttributeError):
        verdict.kind = "exact"  # type: ignore[misc]


def test_never_touches_the_network(monkeypatch: pytest.MonkeyPatch) -> None:
    def refuse(*_args, **_kwargs):
        raise AssertionError("lookalike classification must not open a socket")

    monkeypatch.setattr(socket, "socket", refuse)
    monkeypatch.setattr(socket, "create_connection", refuse)
    monkeypatch.setattr(socket, "getaddrinfo", refuse)
    for case in CASES:
        classify(case["origin"], case["saved"])


def test_damerau_levenshtein() -> None:
    distance = lookalike._osa_distance
    assert distance("example", "example") == 0
    assert distance("example", "exmaple") == 1
    assert distance("example", "exmapel") == 2
    assert distance("example", "axumplo") == 3
    assert distance("", "abc") == 3


def test_psl_min_json_is_built_from_the_bundled_list() -> None:
    import importlib.util

    spec = importlib.util.spec_from_file_location("build_psl", ROOT / "scripts" / "build_psl.py")
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    current = (ROOT / "browser-extension" / "psl-min.json").read_text(encoding="utf-8")
    assert current == module.build(), "run scripts/build_psl.py"
    assert len(current.encode("utf-8")) < 160_000


def test_public_suffix_list_licence_is_in_the_notices() -> None:
    notices = (ROOT / "THIRD-PARTY-NOTICES.txt").read_text(encoding="utf-8")
    assert "Public Suffix List" in notices
    assert "Mozilla Public License Version 2.0" in notices
