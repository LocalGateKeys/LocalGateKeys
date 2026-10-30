"""Stage 2: the home service behind the WebView list, sidebar, chips, overview and status line."""
from __future__ import annotations

import json

import pytest

from localvault.app.controller import WebController
from localvault.app.home import HomeService
from localvault.profiles import ProfileManager
from localvault.settings import AppSettings

KDF = {"time_cost": 1, "memory_cost_kib": 8192, "parallelism": 1, "hash_len": 32}
MASTER = "correct horse battery"
SECRETS = ("pw-alpha-1234567", "pw-beta-1234567", "pw-gamma-1234567")


class Bus:
    def __init__(self):
        self.events = []

    def emit(self, name, detail):
        self.events.append((name, detail))


class Sched:
    def call_later(self, delay, fn):
        return fn

    def cancel(self, handle):
        pass


@pytest.fixture
def env(tmp_path, monkeypatch):
    monkeypatch.setattr("localvault.app.controller.clear_master_unlock_requirement", lambda _pid: None)
    # Unlimited (Pro): the fixture already fills the free plan's four items.
    monkeypatch.setattr("localvault.licensing.item_limit", lambda st=None: None)
    profiles = ProfileManager(tmp_path / "data")
    profiles.ensure_profile()
    controller = WebController(profiles=profiles, settings=AppSettings(auto_lock_seconds=300, idle_source="vault"),
                               bus=Bus(), scheduler=Sched(), create_kwargs={"kdf_overrides": KDF})
    controller.create(MASTER, MASTER)
    session = controller.session
    alpha = session.create_web_login(urls=[{"url": "https://alpha.test", "match": "exact_origin"}],
                                     username="ann", password=SECRETS[0], label="Alpha")
    session.create_web_login(urls=[{"url": "https://beta.test", "match": "exact_origin"}],
                             username="bob", password=SECRETS[1], label="Beta", favorite=True,
                             totp={"secret": "JBSWY3DPEHPK3PXP", "algorithm": "SHA1", "digits": 6, "period": 30})
    session.create_web_login(urls=[{"url": "https://gamma.test", "match": "exact_origin"}],
                             username="cy", password=SECRETS[2], label="Gamma")
    session.item_service.create_note("Router", "wifi codes inside")
    return HomeService(controller), controller, alpha


def test_items_sort_favorites_then_title(env):
    home, _controller, _alpha = env
    titles = [row["title"] for row in home.items(None, None, "")["items"]]
    assert titles == ["Beta", "Alpha", "Gamma", "Router"]


def test_items_sort_choice_is_applied_and_remembered(env, monkeypatch):
    home, controller, _alpha = env
    saved = []
    monkeypatch.setattr(controller.settings, "save", lambda *a, **k: saved.append(True), raising=False)
    state = home.set_sort("title_desc", False)
    assert state["option"] == "title_desc" and state["favorites_first"] is False
    assert [o["value"] for o in state["options"]] == ["title_asc", "title_desc", "modified_desc", "created_desc"]
    assert saved and controller.settings.list_sort == "title_desc"
    listed = home.items(None, None, "")
    assert [row["title"] for row in listed["items"]] == ["Router", "Gamma", "Beta", "Alpha"]
    assert listed["sort"]["option"] == "title_desc"
    home.set_sort("title_desc", True)
    assert [row["title"] for row in home.items(None, None, "")["items"]] == ["Beta", "Router", "Gamma", "Alpha"]
    # A typed search keeps relevance order whatever the sort.
    assert [row["title"] for row in home.items(None, None, "alpha")["items"]][0] == "Alpha"


def test_items_sort_rejects_unknown_choice(env):
    from localvault.api.result import ApiError

    home, _controller, _alpha = env
    with pytest.raises(ApiError):
        home.set_sort("size", True)
    with pytest.raises(ApiError):
        home.set_sort("title_asc", "yes")


def test_search_ranks_like_catalog(env):
    home, _controller, _alpha = env
    assert [r["title"] for r in home.items(None, None, "gam")["items"]] == ["Gamma"]
    assert [r["title"] for r in home.items(None, None, "user:bob")["items"]] == ["Beta"]


def test_filter_kind_favorite_and_note(env):
    home, _controller, _alpha = env
    assert [r["title"] for r in home.items("favorite", None, "")["items"]] == ["Beta"]
    assert [r["title"] for r in home.items("note", None, "")["items"]] == ["Router"]
    context = home.items("favorite", None, "")["context"]
    assert context == {"title": "Favorites", "text": "Items you marked as favorites in this profile."}


def test_chips_count_no2fa(env):
    home, _controller, _alpha = env
    result = home.items(None, None, "")
    assert result["chips"]["no2fa"] == 2
    assert {r["title"] for r in home.items(None, "no2fa", "")["items"]} == {"Alpha", "Gamma"}


def test_empty_states_query_vs_locked(env):
    home, controller, _alpha = env
    empty = home.items(None, None, "zzzz-nothing")["empty"]
    assert empty == {"title": "No matching items",
                     "text": "Try another name, username or tag, or clear your filters.",
                     "action": "Clear filters", "action_id": "clear_filters"}
    controller.lock()
    locked = home.items(None, None, "")
    assert locked["items"] == []
    assert locked["empty"] == {"title": "Vault locked", "text": "Unlock this profile to browse its items.",
                               "action": "Unlock vault", "action_id": "unlock"}


def test_rows_shape_and_no_secret(env):
    home, _controller, alpha = env
    rows = home.items(None, None, "")["items"]
    alpha_row = next(r for r in rows if r["title"] == "Alpha")
    assert alpha_row["ref"] == {"source": "credential", "id": alpha, "kind": "web"}
    assert alpha_row["username"] == "ann" and alpha_row["kind_label"] == "Website login"
    assert alpha_row["target"] == "https://alpha.test"
    assert alpha_row["origin"] == "https://alpha.test" and "letter" not in alpha_row
    note_row = next(r for r in rows if r["title"] == "Router")
    assert note_row["ref"]["source"] == "typed" and note_row["origin"] is None
    blob = json.dumps(rows)
    for secret in SECRETS:
        assert secret not in blob
    assert "wifi codes inside" not in blob


def test_nav_groups_and_counts(env):
    home, _controller, _alpha = env
    groups = {g["name"]: g["entries"] for g in home.nav()["groups"]}
    assert groups["Vault"][0] == {"label": "All items", "icon": "nav.allItems", "token": None, "count": 4, "action": None}
    assert {e["label"]: e["count"] for e in groups["Types"]} == {"Logins": 3, "Secure notes": 1}
    assert groups["Tools"][0]["action"] == "security_health_clicked"
    assert home.nav()["settings"] == {"label": "Settings", "action": "settings_clicked"}


def test_overview_health_label(env):
    home, _controller, _alpha = env
    overview = home.overview()
    assert overview["health"]["label"] in {"Good", "Fair", "Poor"}
    assert overview["health"]["no_2fa"] == 2
    assert overview["backup"]["count"] >= 0
    assert overview["reminders"] == []


def test_status_texts(env):
    home, controller, _alpha = env
    status = home.status()
    assert status["autolock"].startswith("Auto-lock in ")
    assert status["encrypted"] == "Local · Encrypted"
    assert status["clipboard"] == ""
    controller.lock()
    assert home.status()["autolock"] == "Locked"


def test_bookmark_host_is_cached_between_searches(env, monkeypatch):
    home, controller, _alpha = env
    controller.session.item_service.create_bookmark("Docs", "https://docs.example.test/page")
    from localvault.item_service import ItemService

    calls = []
    real = ItemService.get_item

    def counting(self, item_id, *, include_protected=False):
        if include_protected:
            calls.append(item_id)
        return real(self, item_id, include_protected=include_protected)

    monkeypatch.setattr(ItemService, "get_item", counting)
    first = home.items(None, None, "")
    assert any(r["target"] == "docs.example.test" for r in first["items"])
    home.items(None, None, "d")
    home.items(None, None, "do")
    assert len(calls) == 1


def test_quick_search_filters_kind_and_sorts_favorites_first(env):
    home, controller, _alpha = env
    result = home.quick_search("", "")
    assert [r["title"] for r in result["rows"]] == ["★ Beta", "Alpha", "Gamma", "Router"]
    assert result["profile"] == controller.profiles.active_profile().name
    assert [r["title"] for r in home.quick_search("", "note")["rows"]] == ["Router"]
    assert [r["title"] for r in home.quick_search("alp", "credentials")["rows"]] == ["Alpha"]
    row = home.quick_search("bet", "")["rows"][0]
    assert row["ref"]["source"] == "credential" and row["subtitle"] == "bob"
    assert SECRETS[1] not in repr(row)


def test_quick_search_rejects_unknown_kind_and_needs_unlock(env):
    home, controller, _alpha = env
    with pytest.raises(ValueError):
        home.quick_search("", "everything")
    controller.lock()
    assert home.quick_search("", "")["rows"] == []


def test_an_icon_captured_after_the_list_loaded_shows_up(env):
    home, controller, alpha = env
    first = next(r for r in home.items(None, None, "")["items"] if r["title"] == "Alpha")
    assert first["icon"] is None
    import io

    from PIL import Image
    raw = io.BytesIO()
    Image.new("RGBA", (16, 16), "green").save(raw, format="PNG")
    from localvault.site_icon import normalize_site_icon
    assert controller.session.set_entry_icon(alpha, normalize_site_icon(raw.getvalue()))
    again = next(r for r in home.items(None, None, "")["items"] if r["title"] == "Alpha")
    assert again["icon"] and again["icon"].startswith("data:image/png;base64,")


def test_desktop_rows_get_the_app_icon_from_the_provider(env):
    home, controller, _alpha = env
    controller.session.add_desktop(label="Example app", username="ann", password="pw-desktop-12345",
                                   exe_path=r"C:\Apps\example.exe", exe_sha256="a" * 64, window_title="Sign in",
                                   control_fingerprint=[{"index": 0, "control_type": "Edit", "is_password": True}],
                                   username_selector=None,
                                   password_selector={"automation_id": "pw", "class_name": "Edit", "name": "",
                                                      "control_type": "Edit", "framework_id": "Win32"},
                                   signer=None, binding_mode="strict")
    asked = []
    home.icons = type("P", (), {"desktop": lambda self, exe: asked.append(exe) or "data:image/png;base64,AA==",
                                "website": lambda self, origin: None})()
    row = next(r for r in home.items(None, None, "")["items"] if r["title"] == "Example app")
    assert row["icon"] == "data:image/png;base64,AA==" and asked == [r"C:\Apps\example.exe"]


def test_codes_lists_live_2fa_codes_without_secrets(env):
    home, controller, _alpha = env
    controller.session.create_web_login(urls=[{"url": "https://bank.test", "match": "exact_origin"}],
                                        username="dee", password="pw-bank-1234567", label="Bank",
                                        totp={"secret": "JBSWY3DPEHPK3PXP", "algorithm": "SHA1", "digits": 6, "period": 30},
                                        policy={"fill": "ask", "sign_in": False, "require_master_password": True,
                                                "save_prompts": True})
    codes = home.codes()["codes"]
    assert [(c["title"], c["username"]) for c in codes] == [("Bank", "dee"), ("Beta", "bob")]
    bank, beta = codes
    assert bank.get("hidden") is True and "code" not in bank
    assert beta["ref"]["source"] == "credential" and beta["origin"] == "https://beta.test"
    assert len(beta["code"]) == 7 and beta["code"][3] == " " and 0 < beta["remaining"] <= 30 and beta["period"] == 30
    assert "JBSWY3DPEHPK3PXP" not in json.dumps(codes)


def test_codes_empty_when_locked(env):
    home, controller, _alpha = env
    controller.lock()
    assert home.codes() == {"codes": []}


def _empty_home(tmp_path, monkeypatch, **settings_kwargs):
    monkeypatch.setattr("localvault.app.controller.clear_master_unlock_requirement", lambda _pid: None)
    profiles = ProfileManager(tmp_path / "data")
    profiles.ensure_profile()
    settings = AppSettings(auto_lock_seconds=300, idle_source="vault", **settings_kwargs)
    controller = WebController(profiles=profiles, settings=settings, bus=Bus(), scheduler=Sched(),
                               create_kwargs={"kdf_overrides": KDF})
    controller.create(MASTER, MASTER)
    return HomeService(controller), controller, settings


def test_import_card_on_empty_vault_until_first_item(tmp_path, monkeypatch):
    home, controller, _settings = _empty_home(tmp_path, monkeypatch)
    assert home.items(None, None, "")["import_card"] is True
    controller.session.item_service.create_note("First", "x")
    assert home.items(None, None, "")["import_card"] is False


def test_import_card_not_now_is_saved(tmp_path, monkeypatch):
    home, _controller, settings = _empty_home(tmp_path, monkeypatch)
    saved = []
    monkeypatch.setattr(settings, "save", lambda *a, **k: saved.append(True), raising=False)
    assert home.dismiss_import_card() == {"import_card": False}
    assert saved and settings.import_card_dismissed is True
    assert home.items(None, None, "")["import_card"] is False


def test_import_card_setting_round_trips(tmp_path):
    path = tmp_path / "settings.json"
    AppSettings(import_card_dismissed=True).save(path)
    assert AppSettings.load(path).import_card_dismissed is True
    assert AppSettings().import_card_dismissed is False


def test_import_card_not_shown_when_items_exist_or_locked(env):
    home, controller, _alpha = env
    assert home.items(None, None, "")["import_card"] is False
    controller.lock()
    assert home.items(None, None, "")["import_card"] is False
