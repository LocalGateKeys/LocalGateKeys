import pytest

from localvault.origin import OriginError, canonicalize_origin


def test_canonicalizes_default_ports_and_case() -> None:
    assert canonicalize_origin("https://EXAMPLE.com:443/") == "https://example.com"
    assert canonicalize_origin("http://localhost:80/") == "http://localhost"


def test_preserves_non_default_port() -> None:
    assert canonicalize_origin("https://example.com:8443") == "https://example.com:8443"


def test_rejects_paths_and_public_http() -> None:
    with pytest.raises(OriginError):
        canonicalize_origin("https://example.com/login")
    with pytest.raises(OriginError):
        canonicalize_origin("http://example.com")


def test_accepts_loopback_http_only() -> None:
    assert canonicalize_origin("http://127.0.0.1:8000") == "http://127.0.0.1:8000"
    assert canonicalize_origin("http://[::1]:8000") == "http://[::1]:8000"


# ---------------------------------------------------------------------------
# Multi-URL matching
# ---------------------------------------------------------------------------
from localvault.origin import (  # noqa: E402
    MATCH_MODES,
    base_domain,
    candidates_for,
    matches,
    normalize_url,
)


def test_match_modes_are_closed() -> None:
    assert MATCH_MODES == ("exact_origin", "host", "base_domain", "starts_with")


def test_normalize_url_lowercases_idna_and_drops_trailing_dot_and_default_port() -> None:
    assert normalize_url("HTTPS://Example.COM.:443/Login?x=1#frag") == "https://example.com/Login?x=1"
    assert normalize_url("https://bücher.example/") == "https://xn--bcher-kva.example/"
    assert normalize_url("https://XN--BCHER-KVA.example") == "https://xn--bcher-kva.example/"
    assert normalize_url("https://example.com:8443") == "https://example.com:8443/"
    with pytest.raises(OriginError):
        normalize_url("javascript:alert(1)")
    with pytest.raises(OriginError):
        normalize_url("https://user:pw@example.com/")


def test_base_domain_uses_embedded_public_suffix_list() -> None:
    assert base_domain("login.example.co.uk") == "example.co.uk"
    assert base_domain("example.co.uk") == "example.co.uk"
    assert base_domain("a.b.example.com") == "example.com"
    assert base_domain("user.github.io") == "user.github.io"
    assert base_domain("pages.user.github.io") == "user.github.io"
    assert base_domain("shop.example.com.au") == "example.com.au"
    assert base_domain("localhost") == "localhost"
    assert base_domain("co.uk") == "co.uk"
    assert base_domain("127.0.0.1") == "127.0.0.1"


def test_exact_origin_mode_compares_canonical_origin() -> None:
    entry = [{"url": "https://example.com", "match": "exact_origin"}]
    assert matches(entry, "https://EXAMPLE.com:443/login?next=/")
    assert matches(entry, "https://example.com.")
    assert not matches(entry, "https://example.com:8443/")
    assert not matches(entry, "https://login.example.com/")
    assert not matches(entry, "http://example.com/")
    assert not matches(entry, "https://evil-example.com/")


def test_host_mode_compares_hostname_and_port() -> None:
    # Host rows ignore scheme and path but compare the port (stream D,
    # 2026-10-24): another listener on the same host is another service.
    entry = [{"url": "https://example.com:8443/app", "match": "host"}]
    assert matches(entry, "https://example.com:8443/x")
    assert matches(entry, "https://Example.COM.:8443/")
    assert not matches(entry, "https://example.com/anything")
    assert not matches(entry, "https://Example.COM.:9000/")
    assert not matches(entry, "https://login.example.com/")
    assert not matches(entry, "https://evil-example.com/")


def test_base_domain_mode_matches_subdomains_but_not_lookalikes() -> None:
    entry = [{"url": "https://example.co.uk/", "match": "base_domain"}]
    assert matches(entry, "https://login.example.co.uk/signin")
    assert matches(entry, "https://example.co.uk")
    assert not matches(entry, "https://other.co.uk/")
    assert not matches(entry, "https://evil-example.co.uk/")
    assert not matches(entry, "https://example.co.uk.evil.test/")
    simple = [{"url": "https://example.com", "match": "base_domain"}]
    assert matches(simple, "https://accounts.example.com/")
    assert not matches(simple, "https://evil-example.com/")
    assert not matches(simple, "https://example.com.evil.test/")
    pages = [{"url": "https://alice.github.io", "match": "base_domain"}]
    assert not matches(pages, "https://bob.github.io/")


def test_starts_with_mode_compares_normalized_prefix_at_path_boundary() -> None:
    entry = [{"url": "https://example.com/app", "match": "starts_with"}]
    assert matches(entry, "https://EXAMPLE.com/app")
    assert matches(entry, "https://example.com/app/login")
    assert matches(entry, "https://example.com/app?x=1")
    assert not matches(entry, "https://example.com/application")
    assert not matches(entry, "https://example.com/other")
    assert not matches(entry, "https://example.com.evil.test/app")


def test_matches_accepts_mode_override_and_string_entries() -> None:
    assert matches(["https://example.com"], "https://example.com/login", mode="exact_origin")
    assert matches(["https://example.com"], "https://a.example.com/", mode="base_domain")
    assert not matches(["https://example.com"], "https://a.example.com/", mode="exact_origin")
    with pytest.raises(OriginError):
        matches(["https://example.com"], "https://example.com", mode="regex")
    with pytest.raises(OriginError):
        matches([{"url": "https://example.com", "match": "regex"}], "https://example.com")


def test_matches_fails_closed_on_malformed_candidate() -> None:
    assert not matches([{"url": "https://example.com", "match": "host"}], "not a url")
    assert not matches([{"url": "https://example.com", "match": "host"}], "")
    assert not matches([{"url": "https://example.com", "match": "host"}], None)  # type: ignore[arg-type]


def test_idn_punycode_normalization_matches_both_spellings() -> None:
    entry = [{"url": "https://bücher.example", "match": "exact_origin"}]
    assert matches(entry, "https://xn--bcher-kva.example/")
    assert matches([{"url": "https://xn--bcher-kva.example", "match": "host"}], "https://BÜCHER.example/x")


def test_candidates_for_ranks_exact_origin_first_then_host_base_domain_prefix() -> None:
    entries = [
        {"id": "base", "kind": "web", "updated_at": 5,
         "scope": {"origin": "https://example.com", "urls": [{"url": "https://example.com", "match": "base_domain"}]}},
        {"id": "exact", "kind": "web", "updated_at": 1,
         "scope": {"origin": "https://login.example.com"}},
        {"id": "host", "kind": "web", "updated_at": 9,
         "scope": {"origin": "https://login.example.com", "urls": [{"url": "https://login.example.com", "match": "host"}]}},
        {"id": "prefix", "kind": "web", "updated_at": 2,
         "scope": {"origin": "https://login.example.com", "urls": [{"url": "https://login.example.com/sso", "match": "starts_with"}]}},
        {"id": "other", "kind": "web", "updated_at": 3, "scope": {"origin": "https://evil-example.com"}},
        {"id": "desktop", "kind": "desktop", "scope": {"exe_path": "C:/x.exe"}},
    ]
    ranked = candidates_for(entries, "https://login.example.com/sso/start")
    assert [entry["id"] for entry in ranked] == ["exact", "host", "base", "prefix"]
    assert [entry["id"] for entry in candidates_for(entries, "https://evil-example.com/")] == ["other"]
    assert candidates_for(entries, "garbage") == []


# ---------------------------------------------------------------------------
# Public Suffix List (SEC-I12) and UTS-46 hosts (SEC-I11)
# ---------------------------------------------------------------------------
import localvault.origin as origin_module  # noqa: E402


@pytest.fixture
def psl_cache_reset():
    origin_module._reset_suffix_rules_cache()
    yield
    origin_module._reset_suffix_rules_cache()


def test_bundled_public_suffix_list_loads_all_sections(psl_cache_reset) -> None:
    rules = origin_module.suffix_rules()
    assert rules is not None and len(rules.normal) > 9000
    assert "co.uk" in rules.normal and "github.io" in rules.normal  # ICANN and PRIVATE
    assert origin_module.suffix_rules() is rules  # parsed once
    # Unicode rules are matched on their A-label form.
    assert "xn--55qx5d.cn" in rules.normal
    assert base_domain("shop.a.公司.cn") == "a.xn--55qx5d.cn"


def test_psl_wildcard_and_exception_rules(psl_cache_reset) -> None:
    # *.ck: every second-level label is itself a public suffix ...
    assert base_domain("shop.foo.ck") == "shop.foo.ck"
    assert base_domain("a.shop.foo.ck") == "shop.foo.ck"
    assert base_domain("foo.ck") == "foo.ck"
    # ... except !www.ck, whose registrable domain is www.ck itself.
    assert base_domain("www.ck") == "www.ck"
    assert base_domain("login.www.ck") == "www.ck"


def test_psl_algorithm_on_synthetic_rules() -> None:
    rules = origin_module.parse_suffix_rules([
        "// comment", "", "com", "*.platform.example", "!keep.platform.example", "deep.example.com  trailing",
        "bad*.rule", "ünï.example",
    ])
    suffix = origin_module.public_suffix
    assert suffix("a.b.com", rules) == "com"
    assert suffix("x.deep.example.com", rules) == "deep.example.com"
    assert suffix("t.zone.platform.example", rules) == "zone.platform.example"
    assert suffix("keep.platform.example", rules) == "platform.example"
    assert suffix("a.unknown", rules) == "unknown"  # default rule *
    assert origin_module._ascii_host("ünï.example") in rules.normal and not any("*" in rule for rule in rules.normal)


def test_local_rules_only_narrow_azure_static_sites(psl_cache_reset) -> None:
    assert base_domain("alice.z13.web.core.windows.net") == "alice.z13.web.core.windows.net"
    assert base_domain("mallory.z13.web.core.windows.net") == "mallory.z13.web.core.windows.net"


def test_missing_or_truncated_suffix_list_fails_closed_to_exact_host(psl_cache_reset, monkeypatch, tmp_path) -> None:
    monkeypatch.setattr(origin_module, "PUBLIC_SUFFIX_LIST_PATH", tmp_path / "missing.dat")
    assert origin_module.suffix_rules() is None
    assert base_domain("login.example.co.uk") == "login.example.co.uk"
    rows = [{"url": "https://example.com", "match": "base_domain"}]
    assert matches(rows, "https://example.com/")
    assert not matches(rows, "https://login.example.com/")
    origin_module._reset_suffix_rules_cache()
    truncated = tmp_path / "truncated.dat"
    truncated.write_text("com\nco.uk\n", encoding="utf-8")
    monkeypatch.setattr(origin_module, "PUBLIC_SUFFIX_LIST_PATH", truncated)
    assert origin_module.suffix_rules() is None and base_domain("a.example.com") == "a.example.com"


def test_unicode_hosts_use_uts46_nontransitional_like_browsers() -> None:
    assert canonicalize_origin("https://straße.de") == "https://xn--strae-oqa.de"
    assert canonicalize_origin("https://σοφος.gr") != canonicalize_origin("https://σοφοσ.gr")  # final sigma kept
    assert canonicalize_origin("https://faß.de") != canonicalize_origin("https://fass.de")
    assert canonicalize_origin("https://bücher。example") == "https://xn--bcher-kva.example"  # ideographic dot
    assert canonicalize_origin("https://strasse.de") == "https://strasse.de"
    with pytest.raises(OriginError):
        canonicalize_origin("https://a‍b.de")  # ZWJ outside a joining context


def test_ascii_hosts_are_unchanged_by_the_idna_switch() -> None:
    assert canonicalize_origin("https://XN--STRAE-OQA.de") == "https://xn--strae-oqa.de"
    assert canonicalize_origin("https://my_host.example") == "https://my_host.example"
    with pytest.raises(OriginError):
        canonicalize_origin("https://" + "a" * 64 + ".example")
