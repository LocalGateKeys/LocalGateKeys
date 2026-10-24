"""Main-window search: tokenized matching, field prefixes, fuzzy fallback and ranking."""
from __future__ import annotations

from types import SimpleNamespace

from localvault.app.catalog import (
    SEARCH_PREFIXES,
    parse_search_query,
    rank_search_results,
    search_fields,
    search_rank,
)


def _summary(title, *, kind="web", username="", origin="", tags=(), updated_at=0, **extra):
    scope = {"origin": origin} if kind == "web" else ({"exe_path": extra.pop("exe", "")} if kind == "desktop" else None)
    return SimpleNamespace(id=title.lower().replace(" ", "-"), kind=kind, title=title, label=title,
                           username=username, scope=scope, tags=tuple(tags), favorite=False,
                           updated_at=updated_at, collection_ids=())


def _fields(summary, target=""):
    return search_fields(summary, target or (summary.scope or {}).get("origin", ""))


def test_parse_search_query_splits_tokens_and_recognises_field_prefixes() -> None:
    assert parse_search_query("  GitHub  work ") == [(None, "github"), (None, "work")]
    assert parse_search_query("tag:Work url:github.com type:Note user:alice") == [
        ("tags", "work"), ("url", "github.com"), ("kind", "note"), ("username", "alice"),
    ]
    # Unknown prefixes stay literal tokens; a bare prefix without a value is dropped.
    assert parse_search_query("foo:bar tag:") == [(None, "foo:bar")]
    assert set(SEARCH_PREFIXES) == {"tag", "url", "type", "user"}


def test_all_tokens_must_match_across_safe_fields_but_never_notes() -> None:
    row = _fields(_summary("GitHub", username="alice@example.test", origin="https://github.com", tags=("work",)))
    assert search_rank(row, parse_search_query("github alice")) is not None
    assert search_rank(row, parse_search_query("github work")) is not None
    assert search_rank(row, parse_search_query("github missing")) is None
    assert "notes" not in row


def test_field_prefixes_restrict_the_match_to_one_field() -> None:
    row = _fields(_summary("GitHub", username="alice", origin="https://github.com", tags=("work",)))
    assert search_rank(row, parse_search_query("tag:work")) is not None
    assert search_rank(row, parse_search_query("tag:github")) is None
    assert search_rank(row, parse_search_query("url:github.com")) is not None
    assert search_rank(row, parse_search_query("user:alice")) is not None
    assert search_rank(row, parse_search_query("user:bob")) is None
    assert search_rank(row, parse_search_query("type:web")) is not None
    assert search_rank(row, parse_search_query("type:website")) is not None  # display label
    assert search_rank(row, parse_search_query("type:note")) is None


def test_fuzzy_fallback_only_applies_when_no_exact_token_hit() -> None:
    row = _fields(_summary("Amazon", username="alice"))
    assert search_rank(row, parse_search_query("amazn")) == 3
    assert search_rank(row, parse_search_query("amazon")) == 0
    # Far-off tokens never match.
    assert search_rank(row, parse_search_query("zzzz")) is None
    # Prefixed tokens are exact-only.
    assert search_rank(row, parse_search_query("user:alcie")) is None


def test_ranking_prefers_exact_title_then_prefix_then_contains_then_fuzzy_then_recency() -> None:
    exact = _summary("Mail", kind="web", origin="https://mail.test", updated_at=10)
    prefix = _summary("Mailbox pro", kind="web", origin="https://box.test", updated_at=50)
    contains = _summary("Webmail", kind="web", origin="https://web.test", updated_at=90)
    fuzzy = _summary("Maul", kind="web", origin="https://maul.test", updated_at=99)
    recent = _summary("Mail", kind="desktop", exe="C:/mail.exe", updated_at=500)
    rows = [(summary, _fields(summary)) for summary in (fuzzy, contains, prefix, exact, recent)]

    ranked = rank_search_results(rows, "mail")

    assert [summary.id for summary in ranked] == [recent.id, exact.id, prefix.id, contains.id, fuzzy.id]


def test_typed_bookmarks_are_searchable_by_url_host() -> None:
    bookmark = _summary("Docs", kind="bookmark")
    row = search_fields(bookmark, "docs.example.org")
    assert search_rank(row, parse_search_query("example.org")) is not None
    assert search_rank(row, parse_search_query("url:docs.example")) is not None
    assert rank_search_results([(bookmark, row)], "nothing") == []
