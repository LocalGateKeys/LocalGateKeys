from types import SimpleNamespace as S

from localvault.app.catalog import matches_filter
from localvault.shell.nav import TOOLS_ENTRIES, build_nav


def _s(i, kind, fav=False):
    return S(id=str(i), kind=kind, favorite=fav, collection_ids=(), updated_at=i)


def test_groups_in_spec_order():
    groups = build_nav([_s(1, "web"), _s(2, "card")], [], [], unlocked=True)
    assert [g.name for g in groups] == ["Vault", "Types", "Collections & views", "Tools"]


def test_vault_group_counts():
    vault = build_nav([_s(1, "web", True), _s(2, "web")], [], [], unlocked=True)[0]
    assert [(e.label, e.token, e.count) for e in vault.entries] == [
        ("All items", None, 2), ("Favorites", "favorite", 1), ("Recently used", "recent", None)]


def test_types_only_present_kinds_in_kind_order():
    types = build_nav([_s(1, "card"), _s(2, "web"), _s(3, "web")], [], [], unlocked=True)[1]
    assert [(e.token, e.count) for e in types.entries] == [("web", 2), ("card", 1)]
    assert [e.label for e in types.entries] == ["Logins", "Cards"]


def test_collections_then_pinned_views():
    g = build_nav([], [{"id": "c1", "name": "Work"}],
                  [{"id": "v1", "name": "Expiring soon", "pinned": True},
                   {"id": "v2", "name": "x", "pinned": False},
                   {"id": "v3", "name": "y", "pinned": True, "disabled": True}],
                  unlocked=True)[2]
    assert [e.token for e in g.entries] == ["collection:c1", "view:v1"]


def test_tools_route_to_webview_pages():
    from pathlib import Path

    home = (Path(__file__).resolve().parents[1] / "webui/src/screens/Home.svelte").read_text(encoding="utf-8")
    assert [e.label for e in TOOLS_ENTRIES] == [
        "Security center", "Reminders", "Sync", "Devices & connections", "Licence", "Import & export",
        "Scan QR code", "Activity", "Trash"]
    assert all(e.action and e.token is None and (f"{e.action}:" in home or f"'{e.action}'" in home)
               for e in TOOLS_ENTRIES)


def test_locked_hides_counts_and_types():
    groups = build_nav([_s(1, "web")], [], [], unlocked=False)
    assert [g.name for g in groups] == ["Vault", "Tools"]
    assert all(e.count is None for e in groups[0].entries)


def test_recent_token_uses_flag_ids():
    s = _s(1, "web")
    assert matches_filter(s, "recent", set(), flag_ids={"recent": {"1"}})
    assert not matches_filter(s, "recent", set(), flag_ids={"recent": {"2"}})
    assert not matches_filter(s, "recent", set())
