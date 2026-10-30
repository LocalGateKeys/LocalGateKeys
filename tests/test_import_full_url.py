"""Imported logins keep the full page address (tester report 2026-10-29).

``https://www.abcdef.com/interface/login.aspx`` used to be saved as just
``https://www.abcdef.com``.  The importer now adds a ``starts_with`` row with
the full address after the ``exact_origin`` rows; matching must not change.
"""

from __future__ import annotations

from localvault.import_workflow import ImportedRecord, _web_rows
from localvault.item_schema import migrate_web_scope, validate_web_urls, web_page_address
from localvault.origin import match_rank


def _record(*urls: str) -> ImportedRecord:
    record = ImportedRecord.__new__(ImportedRecord)
    record.urls = list(urls)
    return record


def test_full_address_kept_after_exact_origin_row():
    origin, rows, other, upgraded = _web_rows(_record("https://www.abcdef.com/interface/login.aspx"))
    assert origin == "https://www.abcdef.com" and other == [] and not upgraded
    assert rows == [{"url": "https://www.abcdef.com", "match": "exact_origin"},
                    {"url": "https://www.abcdef.com/interface/login.aspx", "match": "starts_with"}]
    assert validate_web_urls(rows) == rows
    assert migrate_web_scope({"origin": origin, "urls": rows})["urls"] == rows


def test_bare_site_and_http_upgrade_rules_unchanged():
    _o, rows, _x, upgraded = _web_rows(_record("https://x.example.com/", "abc.example.com",
                                               "http://old.example.com/a?b=1#frag", "http://localhost:8080/p"))
    assert upgraded
    assert rows == [{"url": "https://x.example.com", "match": "exact_origin"},
                    {"url": "https://abc.example.com", "match": "exact_origin"},
                    {"url": "https://old.example.com", "match": "exact_origin"},
                    {"url": "http://localhost:8080", "match": "exact_origin"},
                    {"url": "https://old.example.com/a?b=1", "match": "starts_with"},
                    {"url": "http://localhost:8080/p", "match": "starts_with"}]


def test_matching_is_identical_to_exact_origin_only():
    _o, rows, _x, _u = _web_rows(_record("https://www.abcdef.com/interface/login.aspx"))
    exact = [row for row in rows if row["match"] == "exact_origin"]
    for page in ("https://www.abcdef.com/", "https://www.abcdef.com/interface/login.aspx?r=1",
                 "https://www.abcdef.com/other", "http://www.abcdef.com/interface/login.aspx",
                 "https://evil.abcdef.com/interface/login.aspx", "https://www.abcdef.com:8443/interface",
                 "https://www.abcdef.com.evil.test/interface/login.aspx"):
        assert match_rank(rows, page) == match_rank(exact, page), page


def test_page_address_is_shown_and_opened():
    scope = {"origin": "https://www.abcdef.com",
             "urls": [{"url": "https://www.abcdef.com", "match": "exact_origin"},
                      {"url": "https://www.abcdef.com/interface/login.aspx", "match": "starts_with"}]}
    assert web_page_address(scope) == "https://www.abcdef.com/interface/login.aspx"
    assert web_page_address({"origin": "https://a.example"}) == "https://a.example"
    # A page on another origin never replaces the login's own site.
    other = {"origin": "https://a.example", "urls": [{"url": "https://a.example", "match": "exact_origin"},
                                                     {"url": "https://b.example/x", "match": "starts_with"}]}
    assert web_page_address(other) == "https://a.example"
