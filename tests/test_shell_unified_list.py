"""Unified vault list: runtime kind labels, filter dropdown options, per-kind website column."""
from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

from localvault.app.catalog import (
    DISPLAY_KIND_LABELS,
    KIND_ORDER,
    filter_options,
    kind_label,
    matches_filter,
    row_target,
)
from localvault.item_schema import ITEM_KINDS

SOURCE_ROOT = Path(__file__).resolve().parents[1] / "src" / "localvault"


def _summary(kind, title="Item", *, favorite=False, collection_ids=(), scope=None, item_id=None):
    return SimpleNamespace(id=item_id or f"{kind}-{title}".lower(), kind=kind, title=title, label=title,
                           username="", tags=(), favorite=favorite, updated_at=0,
                           collection_ids=tuple(collection_ids), scope=scope)


def test_every_schema_kind_has_a_display_label_discovered_at_runtime() -> None:
    assert set(DISPLAY_KIND_LABELS) == set(ITEM_KINDS)
    assert kind_label("ssh_key") == "SSH key"
    assert kind_label("api_key") == "API key"
    assert kind_label("bank_account") == "Bank account"
    assert kind_label("web") == "Website login"
    assert kind_label("brand_new_kind") == "Brand new kind"
    assert KIND_ORDER[:2] == ("web", "desktop") and set(KIND_ORDER) == set(ITEM_KINDS)


def test_filter_options_list_favorites_kinds_present_collections_and_pinned_views() -> None:
    summaries = [_summary("web"), _summary("card"), _summary("card", "Second"), _summary("note")]
    collections = [{"id": "col-1", "name": "Family"}]
    views = [{"id": "view-1", "name": "Expiring", "pinned": True}, {"id": "view-2", "name": "Hidden", "pinned": False}]

    options = filter_options(summaries, collections, views)

    labels = [option.label for option in options]
    assert labels == ["All types", "Favorites", "Browser", "Note", "Payment card", "Collection: Family",
                      "View: Expiring"]
    by_label = {option.label: option for option in options}
    assert by_label["All types"].kind is None and by_label["All types"].key == "all"
    assert by_label["Favorites"].kind == "favorite"
    assert by_label["Browser"].kind == "web" and by_label["Browser"].key == "web"
    assert by_label["Payment card"].kind == "card"
    assert by_label["Collection: Family"].kind == "collection:col-1"
    assert by_label["View: Expiring"].kind == "view:view-1"


def test_matches_filter_handles_every_filter_token() -> None:
    favorite = _summary("note", favorite=True, collection_ids=("col-1",))
    plain = _summary("card")
    assert matches_filter(favorite, None, set()) and matches_filter(plain, None, set())
    assert matches_filter(favorite, "favorite", set()) and not matches_filter(plain, "favorite", set())
    assert matches_filter(plain, "card", set()) and not matches_filter(favorite, "card", set())
    assert matches_filter(favorite, "collection:col-1", set()) and not matches_filter(plain, "collection:col-1", set())
    assert matches_filter(favorite, "view:v", {favorite.id}) and not matches_filter(plain, "view:v", {favorite.id})


def test_row_target_shows_a_sensible_website_column_per_kind() -> None:
    assert row_target(_summary("web", scope={"origin": "https://github.com"})) == "https://github.com"
    assert row_target(_summary("desktop", scope={"exe_path": "C:/Apps/Mail/mail.exe"})) == "mail.exe"
    assert row_target(_summary("bookmark"), {"payload": {"url_present": True}}, bookmark_host="docs.example.org") == "docs.example.org"
    assert row_target(_summary("passkey"), {"payload": {"relying_party_id": "login.example"}}) == "login.example"
    assert row_target(_summary("api_key"), {"payload": {"service": "Stripe", "key_present": True}}) == "Stripe"
    assert row_target(_summary("wifi"), {"payload": {"ssid": "Home"}}) == "Home"
    assert row_target(_summary("card"), {"payload": {"brand": "visa", "cardholder": "A"}}) == "Visa"
    assert row_target(_summary("bank_account"), {"payload": {"bank": "Example Bank"}}) == "Example Bank"
    assert row_target(_summary("license"), {"payload": {"vendor": "Acme", "product": "Tool"}}) == "Acme · Tool"
    assert row_target(_summary("subscription"), {"payload": {"vendor": "Netflix"}}) == "Netflix"
    assert row_target(_summary("ssh_key"), {"payload": {"fingerprint": "SHA256:abc"}}) == "SHA256:abc"
    assert row_target(_summary("note"), {"payload": {"body_present": True}}) == ""
    # Protected values never leak through the column even if a projection carried them.
    assert "4111" not in row_target(_summary("card"), {"payload": {"number": "4111111111111111"}})


def test_matches_filter_attention_no2fa_and_expiring_read_flag_ids() -> None:
    item = _summary("web", item_id="a")
    for token in ("attention", "no2fa", "expiring"):
        assert matches_filter(item, token, set(), flag_ids={token: {"a"}})
        assert not matches_filter(item, token, set(), flag_ids={token: set()})
        assert not matches_filter(item, token, set(), flag_ids={})
        assert not matches_filter(item, token, set())
