"""Shared health vectors (Windows, Swift and Kotlin read the same file) and the new health categories."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from localvault.app.health import FILTERS
from localvault.password_tools import vault_health
from localvault.shell.security_model import issues_for
from localvault.site_features import SiteFeatures

CASES = json.loads((Path(__file__).parent / "vectors" / "health" / "site_cases.json").read_text(encoding="utf-8"))


def _entries(case: dict) -> list[dict]:
    return [{"id": login["id"], "label": login["id"], "kind": "web", "password": "Xk9#mQ2$vLp7!zRt",
             "totp": "JBSWY3DPEHPK3PXP" if login["has_totp"] else "",
             "scope": {"urls": [{"url": url, "match": "exact_origin"} for url in login["urls"]]}}
            for login in case["logins"]]


@pytest.mark.parametrize("case", CASES, ids=[c["name"] for c in CASES])
def test_site_case(case: dict) -> None:
    health = vault_health(_entries(case), features=SiteFeatures(case["sites"]),
                          passkey_domains=frozenset(case["passkey_domains"]))
    for category, ids in case["expected"].items():
        assert health[f"{category}_ids"] == sorted(ids), category
        assert health[f"{category}_count"] == len(ids)


def test_without_features_no_2fa_and_passkey_are_empty() -> None:
    health = vault_health(_entries(CASES[3]))
    assert health["no_2fa_ids"] == [] and health["passkey_ids"] == []
    assert health["http_ids"] == ["a"]


def test_row_categories_list_new_categories() -> None:
    case = next(c for c in CASES if c["name"] == "mixed_logins")
    rows = {r["id"]: r["categories"] for r in
            vault_health(_entries(case), features=SiteFeatures(case["sites"]))["rows"]}
    assert "http" in rows["a"] and "no_2fa" in rows["a"] and "passkey" in rows["b"]


def test_issues_for_lists_http_and_passkey() -> None:
    health = {"rows": [{"id": "a", "label": "A"}, {"id": "b", "label": "B"}],
              "http_ids": ["a"], "passkey_ids": ["a", "b"]}
    issues = {i.key: i for i in issues_for(health, None)}
    assert issues["http"].count == 1 and issues["passkey"].count == 2
    assert issues["http"].action.kwargs == (("initial_filter", "http"),)
    assert issues["passkey"].action.kwargs == (("initial_filter", "passkey"),)


def test_filters_include_new_categories() -> None:
    keys = [key for _label, key in FILTERS]
    assert "http" in keys and "passkey" in keys
