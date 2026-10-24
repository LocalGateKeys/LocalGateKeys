"""Tests that close gaps found by mutation testing of ``localvault.origin`` (2026-10-24)."""
from __future__ import annotations

import pytest

from localvault import origin
from localvault.origin import OriginError

FORBIDDEN = "character that browsers do not allow"


# --- _ascii_host: both host-character layers ----------------------------------------------


@pytest.mark.parametrize("value", ["https://a.com\\.evil.com", "https://a|b.com", "https://a<b>.com", "https://a^b.com"])
def test_ascii_host_with_forbidden_character_is_refused(value) -> None:
    for fn in (origin.canonicalize_origin, origin.origin_of, origin.normalize_url):
        with pytest.raises(OriginError, match=FORBIDDEN):
            fn(value)


@pytest.mark.parametrize("value", ["https://é|x.com", "https://é\\x.com", "https://é%x.com",
                                   "https://é^x.com", "https://é\x7f.com"])
def test_forbidden_character_is_refused_before_idna_runs(value) -> None:
    # The first layer names the forbidden character; without it UTS-46 would
    # refuse the host with a different, less precise error.
    with pytest.raises(OriginError, match=FORBIDDEN):
        origin.canonicalize_origin(value)
    with pytest.raises(OriginError, match=FORBIDDEN):
        origin.origin_of(value)


def test_fullwidth_backslash_is_refused() -> None:
    # U+FF3C FULLWIDTH REVERSE SOLIDUS maps onto "\" under UTS-46.
    for fn in (origin.canonicalize_origin, origin.origin_of):
        with pytest.raises(OriginError):
            fn("https://a.com＼.evil.com")


def test_idna_output_is_checked_again(monkeypatch) -> None:
    """The second layer: whatever the IDNA library returns is re-checked.

    The pinned ``idna`` refuses every forbidden code point itself; this pins the
    defence in depth against a more lenient library mapping e.g. U+FF3C onto "\\".
    """
    import idna

    monkeypatch.setattr(idna, "encode", lambda *_a, **_k: b"a.com\\.evil.com")
    with pytest.raises(OriginError, match=FORBIDDEN):
        origin.canonicalize_origin("https://a.com＼.evil.com")
    monkeypatch.setattr(idna, "encode", lambda *_a, **_k: b"a.com|evil.com")
    with pytest.raises(OriginError, match=FORBIDDEN):
        origin.origin_of("https://é.com")


# --- _urlsplit / _url_host -----------------------------------------------------------------


@pytest.mark.parametrize("value", ["https://ex℀ample.com", "https://a＃b.com", "https://a﹫b.com"])
def test_nfkc_netloc_error_is_an_origin_error(value) -> None:
    # urlsplit raises ValueError when the NFKC-normalised netloc gains / ? # @ or :.
    for fn in (origin.canonicalize_origin, origin.origin_of, origin.normalize_url):
        with pytest.raises(OriginError, match="malformed"):
            fn(value)
    assert origin.match_rank(["https://example.com"], value) is None


@pytest.mark.parametrize("value", ["https:///x", "https://", "https://:443/", "http:///"])
def test_missing_host_is_refused(value) -> None:
    with pytest.raises(OriginError, match="missing a host"):
        origin.origin_of(value)
    with pytest.raises(OriginError, match="missing a host"):
        origin.host_of(value)


@pytest.mark.parametrize("value", ["https://", "https://:8443"])
def test_origin_without_host_is_refused(value) -> None:
    with pytest.raises(OriginError, match="missing a host"):
        origin.canonicalize_origin(value)


# --- canonicalize_origin input guard ---------------------------------------------------------


@pytest.mark.parametrize("value", [None, 5, b"https://a.com", ["https://a.com"], ""])
def test_non_string_or_empty_origin_is_refused(value) -> None:
    with pytest.raises(OriginError, match="non-empty string shorter than 2049"):
        origin.canonicalize_origin(value)


def test_origin_over_2048_characters_is_refused() -> None:
    long_origin = "https://" + "a." * 1030 + "com"
    assert len(long_origin) > 2048
    origin.origin_of(long_origin)  # a valid origin otherwise (the URL limit is 4096)
    with pytest.raises(OriginError, match="shorter than 2049"):
        origin.canonicalize_origin(long_origin)


def test_origin_at_2048_characters_is_accepted() -> None:
    head = "https://" + "a." * 1016
    value = head + "b" * (2048 - len(head) - 4) + ".com"
    assert len(value) == 2048
    assert origin.canonicalize_origin(value) == value


# --- base_domain --------------------------------------------------------------------------


@pytest.mark.parametrize("host", ["1::2::3", "::g", "fe80:::1", "1:2:3:4:5:6:7:8:9"])
def test_base_domain_refuses_invalid_ipv6(host) -> None:
    with pytest.raises(OriginError, match="Invalid IPv6"):
        origin.base_domain(host)


def test_base_domain_keeps_valid_ipv6_lower_case() -> None:
    assert origin.base_domain("FE80::1") == "fe80::1"


# --- match rows ---------------------------------------------------------------------------


@pytest.mark.parametrize("rows", [[{"url": 5}], [None], [{"url": None, "match": "host"}], [b"https://a.com"],
                                  [{"match": "host"}]])
def test_non_string_url_row_raises_instead_of_silently_not_matching(rows) -> None:
    with pytest.raises(OriginError, match="malformed"):
        origin.match_rank(rows, "https://a.com/")


def test_starts_with_row_ending_in_slash_matches_any_continuation() -> None:
    rows = [{"url": "https://a.com/app/", "match": "starts_with"}]
    rank = origin.match_rank(rows, "https://a.com/app/page")
    assert rank is not None
    assert origin._starts_with("https://a.com/app/", "https://a.com/app/page") is True
    assert origin._starts_with("https://a.com/app/", "https://a.com/app/") is True
    # Without the trailing slash only a path or query boundary continues a prefix.
    assert origin._starts_with("https://a.com/app", "https://a.com/apple") is False
    assert origin._starts_with("https://a.com/app", "https://a.com/app/x") is True
    assert origin._starts_with("https://a.com/app", "https://a.com/app?x=1") is True
    assert origin.match_rank([{"url": "https://a.com/app", "match": "starts_with"}], "https://a.com/apple") is None


def test_row_matches_refuses_an_unknown_mode() -> None:
    with pytest.raises(OriginError, match="Unsupported"):
        origin._row_matches("https://a.com", "regex", "https://a.com")


# --- entry_urls -------------------------------------------------------------------------------


@pytest.mark.parametrize("scope", ["https://a.com", ["https://a.com"], 5, None, ("urls",)])
def test_entry_urls_with_non_mapping_scope_is_empty(scope) -> None:
    assert origin.entry_urls({"scope": scope}) == []
    assert origin.candidates_for([{"scope": scope}], "https://a.com/") == []


def test_entry_urls_of_non_mapping_entry_is_empty() -> None:
    assert origin.entry_urls(["scope"]) == []  # type: ignore[arg-type]
