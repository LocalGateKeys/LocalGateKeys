"""Audit 2026-11-10: the phishing shield's "Related site" is for the same host only.

``lookalike.match`` (the shared algorithm, vectors in tests/vectors/lookalike) calls any host on a saved
site's registrable domain "related".  ``lookalike.classify`` (what the broker answers the extension) keeps
"related" for the same host on another scheme or port and for a ``www.`` twin; another host on that domain
(``sites.google.com`` next to a saved ``accounts.google.com``, a domain that hosts other people's pages without
being on the Public Suffix List) gets the neutral ``unknown`` / ``same-site`` naming the saved origin.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from localvault.lookalike import Verdict, classify, match

ROOT = Path(__file__).resolve().parents[1]
CASES = json.loads((ROOT / "tests" / "vectors" / "lookalike" / "cases.json").read_text(encoding="utf-8"))["cases"]


def test_user_content_host_on_a_saved_domain_is_not_related() -> None:
    saved = ["https://accounts.google.com"]
    assert match("https://sites.google.com", saved).kind == "related"
    assert classify("https://sites.google.com", saved) == Verdict("unknown", "https://accounts.google.com",
                                                                  "same-site")


@pytest.mark.parametrize(("origin", "saved", "expected"), [
    ("https://accounts.google.com", ["https://accounts.google.com"], Verdict(
        "exact", "https://accounts.google.com", "same-origin")),
    ("http://accounts.google.com", ["https://accounts.google.com"], Verdict(
        "related", "https://accounts.google.com", "same-host")),
    ("https://accounts.google.com:8443", ["https://accounts.google.com"], Verdict(
        "related", "https://accounts.google.com", "same-host")),
    ("https://www.example.com", ["https://example.com"], Verdict("related", "https://example.com", "www-host")),
    ("https://example.com", ["https://www.example.com"], Verdict("related", "https://www.example.com", "www-host")),
    # A www twin only: www.accounts.example.com is not the same host as example.com.
    ("https://www.accounts.example.com", ["https://example.com"], Verdict("unknown", "https://example.com",
                                                                          "same-site")),
    ("https://login.example.com", ["https://example.com"], Verdict("unknown", "https://example.com", "same-site")),
    ("https://example.com", ["https://login.example.com"], Verdict("unknown", "https://login.example.com",
                                                                   "same-site")),
])
def test_shield_verdicts(origin: str, saved: list[str], expected: Verdict) -> None:
    assert classify(origin, saved) == expected


def test_a_closer_saved_host_still_wins() -> None:
    saved = ["https://example.com", "https://login.example.com"]
    assert classify("https://login.example.com", saved) == Verdict("exact", "https://login.example.com",
                                                                   "same-origin")
    saved = ["https://accounts.example.com", "https://example.com"]
    assert classify("https://www.example.com", saved) == Verdict("related", "https://example.com", "www-host")


def test_a_saved_domain_is_not_flagged_for_resembling_another_saved_site() -> None:
    # As in the shared algorithm, the same site outranks the lookalikes: the user saved a login on this domain.
    saved = ["https://example.net", "https://example.com"]
    assert classify("https://accounts.example.com", saved) == Verdict("unknown", "https://example.com", "same-site")


def test_mixed_script_subdomain_on_a_saved_domain_is_a_lookalike() -> None:
    page = "https://xn--ccounts-1fg.example.com"  # Cyrillic "а" + Latin "ccounts" on a saved domain
    assert classify(page, ["https://example.com"]) == Verdict("lookalike", None, "mixed-script")


@pytest.mark.parametrize("case", CASES, ids=[case["name"] for case in CASES])
def test_shield_differs_from_the_shared_algorithm_only_for_other_hosts_on_the_same_site(case: dict) -> None:
    shared = match(case["origin"], case["saved"])
    shield = classify(case["origin"], case["saved"])
    if shared.reason == "same-site":
        assert shield.kind in {"related", "unknown", "lookalike"}
        assert shield.kind != "related" or shield.reason == "www-host"
    else:
        assert shield == shared
