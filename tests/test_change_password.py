from __future__ import annotations

from localvault.change_password import change_url


def test_origin_gives_well_known_url() -> None:
    assert change_url({"origin": "https://shop.example.test/login"}) == (
        "https://shop.example.test/.well-known/change-password", "well-known")


def test_scope_urls_are_read() -> None:
    entry = {"scope": {"origin": "https://a.example.test", "urls": [{"url": "https://a.example.test"}]}}
    assert change_url(entry)[1] == "well-known"


def test_override_wins_for_subdomains() -> None:
    url, source = change_url({"origin": "https://accounts.google.com"})
    assert source == "site-features" and url.startswith("https://myaccount.google.com/")


def test_no_https_origin_falls_back_to_login_url() -> None:
    assert change_url({"origin": "", "url": "http://router.local/login"}) == (
        "http://router.local/login", "login-url")


def test_nothing_to_open_is_never_a_dead_link() -> None:
    assert change_url({"origin": None}) == ("", "login-url")
    assert change_url({"url": "javascript:alert(1)"}) == ("", "login-url")


def test_every_override_is_well_formed_https_with_a_source() -> None:
    import json
    from urllib.parse import urlsplit

    from localvault.change_password import CHANGE_URLS_PATH

    raw = json.loads(CHANGE_URLS_PATH.read_text(encoding="utf-8"))
    sites, sources = raw["sites"], raw["sources"]
    assert len(sites) >= 10
    for host, url in sites.items():
        assert host == host.lower() and "." in host and "/" not in host and ":" not in host
        parts = urlsplit(url)
        assert parts.scheme == "https" and parts.hostname and not parts.username and " " not in url, host
        assert not parts.port and "\\" not in url, host
        assert sources.get(host, "").strip(), f"{host} has no source note"
