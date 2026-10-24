"""Audit 2026-10-24 stream D: origin/URL canonicalisation and matching.

L-27 forbidden host code points, L-28 ``ValueError`` from the parsers, L-29
bracketed netlocs, I-13 ports in ``host`` mode, I-22 zone ids / IPv4-mapped
addresses / whitespace / trailing dots, M-4 plain-HTTP candidates.  The
shared table ``tests/vectors/origin/url_cases.json`` is also run by the
Kotlin (``OriginVectorsTest``) and Swift (``URLOriginVectorsTests``) cores.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from localvault.item_schema import (
    ItemSchemaError,
    migrate_web_scope,
    validate_bookmark_url,
    validate_web_urls,
)
from localvault.origin import (
    OriginError,
    base_domain,
    candidates_for,
    canonicalize_origin,
    host_of,
    match_rank,
    normalize_url,
    origin_of,
)
from localvault.shell.login_form import UrlRow, _url_error

VECTORS = json.loads((Path(__file__).parent / "vectors" / "origin" / "url_cases.json").read_text(encoding="utf-8"))
FUNCTIONS = {"canonicalize": canonicalize_origin, "normalize_url": normalize_url,
             "origin_of": origin_of, "host_of": host_of}


def _run(fn, value):
    try:
        return {"ok": fn(value)}
    except OriginError as exc:
        return {"error": str(exc)}


@pytest.mark.parametrize("case", VECTORS["cases"], ids=lambda c: ascii(c["input"]))
def test_shared_vector_functions(case) -> None:
    for name, fn in FUNCTIONS.items():
        assert _run(fn, case["input"]) == case[name], name


@pytest.mark.parametrize("case", VECTORS["match"], ids=lambda c: ascii(f"{c['rows']}->{c['candidate']}"))
def test_shared_vector_match_rank(case) -> None:
    rows = [{"url": url, "match": mode} for url, mode in case["rows"]]
    assert match_rank(rows, case["candidate"]) == case["rank"]


# -- L-27 -----------------------------------------------------------------------

@pytest.mark.parametrize("url", [
    "https://paypal.com\\.evil.com", "https://paypal.com%2f.evil.com", "https://a^b.com", "https://a|b.com",
    "https://a<b.com", "https://a>b.com", "https://a%62.com", "https://a\x7fb.com",
])
def test_forbidden_host_code_points_are_refused_everywhere(url: str) -> None:
    for fn in FUNCTIONS.values():
        with pytest.raises(OriginError, match="browsers do not allow"):
            fn(url)
    for mode in ("exact_origin", "host", "base_domain", "starts_with"):
        with pytest.raises(ItemSchemaError, match="^url is malformed"):
            validate_web_urls([{"url": url, "match": mode}])


def test_backslash_row_never_fills_on_the_real_host() -> None:
    entry = {"id": "x", "kind": "web", "scope": {"origin": "https://paypal.com",
                                                  "urls": [{"url": "https://paypal.com\\.evil.com",
                                                            "match": "base_domain"}]}}
    assert match_rank(entry["scope"]["urls"], "https://login.evil.com/") is None
    assert candidates_for([entry], "https://login.evil.com/") == []


def test_fullwidth_reverse_solidus_is_refused_after_idna_mapping() -> None:
    with pytest.raises(OriginError):
        canonicalize_origin("https://paypal.com＼.evil.com")


# -- L-28 -----------------------------------------------------------------------

@pytest.mark.parametrize("url", ["https://[::1", "https://[vzz]", "https://::1]", "https://[1:2:3:4:5:6:7:8:9]",
                                 "https://[127.0.0.1]", "https://evil.com[::1]", "https://[::1]x"])
def test_malformed_brackets_raise_origin_error_not_value_error(url: str) -> None:
    for fn in (*FUNCTIONS.values(), lambda u: base_domain(host_of(u))):
        with pytest.raises(OriginError):
            fn(url)
    assert match_rank([{"url": url, "match": "host"}], "https://[::1]/") is None
    assert match_rank([{"url": "https://[::1]", "match": "host"}], url) is None
    entry = {"id": "x", "kind": "web", "scope": {"origin": "https://example.com", "urls": [{"url": url, "match": "host"}]}}
    assert candidates_for([entry], url) == []
    with pytest.raises(ItemSchemaError):
        validate_web_urls([{"url": url, "match": "starts_with"}])
    with pytest.raises(ItemSchemaError):
        migrate_web_scope({"origin": url})


def test_login_form_shows_a_message_for_malformed_brackets() -> None:
    for url in ("https://[::1", "https://[vzz]", "[::1", "https://evil.com[::1]/x"):
        for mode in ("exact_origin", "host", "base_domain", "starts_with"):
            row, message = _url_error(UrlRow(url, mode))
            assert row is None and message, (url, mode)


def test_login_form_reports_forbidden_host_characters() -> None:
    row, message = _url_error(UrlRow("https://paypal.com\\.evil.com", "base_domain"))
    assert row is None and "browsers do not allow" in message


def test_bookmark_with_malformed_brackets_is_a_schema_error() -> None:
    with pytest.raises(ItemSchemaError, match="bookmark URL is malformed"):
        validate_bookmark_url("https://[::1")
    with pytest.raises(ItemSchemaError, match="bookmark URL is malformed"):
        validate_bookmark_url("https://evil.com[::1]/")


# -- I-13 -----------------------------------------------------------------------

def test_host_mode_compares_ports() -> None:
    rows = [{"url": "http://localhost:3000", "match": "host"}]
    assert match_rank(rows, "http://localhost:3000/x") == 1
    assert match_rank(rows, "https://localhost:3000/x") == 1
    assert match_rank(rows, "http://localhost:3001/x") is None
    assert match_rank(rows, "http://localhost/x") is None
    default = [{"url": "https://example.com/app", "match": "host"}]
    assert match_rank(default, "https://example.com:443/z") == 1
    assert match_rank(default, "https://example.com:8443/z") is None


# -- I-22 -----------------------------------------------------------------------

@pytest.mark.parametrize("url", ["https://[::1%25eth0]", "http://[fe80::1%25en0]:8080", "https://[::ffff:127.0.0.1]",
                                 "http://[::ffff:127.0.0.1]:8443", "https://[::ffff:7f00:1]"])
def test_zone_ids_and_ipv4_mapped_addresses_are_refused(url: str) -> None:
    for fn in FUNCTIONS.values():
        with pytest.raises(OriginError):
            fn(url)


@pytest.mark.parametrize("url", ["https://example.com ", "https://example.com\t", " https://example.com",
                                 "https://example.com\n", "https://example.com\x0b", "https://example.com:443\x00"])
def test_whitespace_and_controls_are_refused_at_either_end(url: str) -> None:
    for fn in FUNCTIONS.values():
        with pytest.raises(OriginError, match="whitespace or a control character"):
            fn(url)


def test_one_trailing_dot_is_dropped_more_are_refused() -> None:
    assert canonicalize_origin("https://example.com.") == "https://example.com"
    assert host_of("https://Example.COM.:8443/x") == "example.com"
    for url in ("https://example.com..", "https://example.com.../x", "https://.."):
        with pytest.raises(OriginError):
            normalize_url(url)


def test_ipv6_base_domain_is_the_address() -> None:
    assert base_domain("::1") == "::1"
    assert base_domain("2001:DB8::1") == "2001:db8::1"
    with pytest.raises(OriginError):
        base_domain("::1%eth0")
    assert match_rank([{"url": "https://[::1]", "match": "base_domain"}], "https://[::1]:8443/") == 2


# -- M-4 ------------------------------------------------------------------------

@pytest.mark.parametrize("mode", ["host", "base_domain", "starts_with", "exact_origin"])
def test_plain_http_candidate_on_a_public_host_never_matches(mode: str) -> None:
    rows = [{"url": "https://bank.example.com/", "match": mode}]
    assert match_rank(rows, "http://bank.example.com/") is None
    assert match_rank(rows, "http://bank.example.com:8080/") is None
    loopback = [{"url": "http://localhost:8080/", "match": mode}]
    assert match_rank(loopback, "http://localhost:8080/") is not None
