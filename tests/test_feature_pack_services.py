"""Windows services of the 2026-11-15 feature pack: access rules, item history, travel mode, clean up."""
from __future__ import annotations

import json

import pytest

from localvault import access_policy, item_history, travel
from localvault.api.result import ApiError
from localvault.app.controller import WebController
from localvault.app.feature_pack import (
    AccessRulesService,
    HygieneService,
    ItemHistoryService,
    TravelService,
)
from localvault.app.home import HomeService
from localvault.app.login_editor import LoginEditorService
from localvault.app.login_extras import LoginExtrasService
from localvault.app.secrets import SecretService
from localvault.profiles import ProfileManager
from localvault.secret_text import SecretText
from localvault.settings import AppSettings

KDF = {"time_cost": 1, "memory_cost_kib": 8192, "parallelism": 1, "hash_len": 32}
MASTER = "correct horse battery"


class Bus:
    def __init__(self):
        self.events = []

    def emit(self, name, detail):
        self.events.append(name)


class Sched:
    def call_later(self, delay, fn):
        return fn

    def cancel(self, handle):
        pass


class FakeClipboard:
    timeout_seconds = 30

    def __init__(self):
        self.value, self.short = None, []

    def copy(self, text):
        self.value = text

    def copy_for(self, text, seconds):
        self.value = text
        self.short.append(seconds)

    def clear(self):
        self.value = None


class Port:
    def __init__(self):
        self.passwords, self.asked, self.answers, self.upgrades = [], [], [], 0

    def ask_password(self, title, message):
        self.asked.append(title)
        answer = self.passwords.pop(0) if self.passwords else None
        return None if answer is None else SecretText.from_str(answer)

    def confirm(self, title, message):
        self.asked.append(title)
        return self.answers.pop(0) if self.answers else True

    def notify(self, kind, title, message):
        self.asked.append(title)

    def show_upgrade(self, **kwargs):
        self.upgrades += 1


@pytest.fixture
def env(tmp_path, monkeypatch):
    monkeypatch.setattr("localvault.app.controller.clear_master_unlock_requirement", lambda _pid: None)
    profiles = ProfileManager(tmp_path / "data")
    profiles.ensure_profile()
    controller = WebController(profiles=profiles, settings=AppSettings(idle_source="vault"), bus=Bus(),
                               scheduler=Sched(), create_kwargs={"kdf_overrides": KDF})
    controller.create(MASTER, MASTER)
    controller.clipboard = FakeClipboard()
    session = controller.session
    alpha = session.create_web_login(urls=[{"url": "https://alpha.test", "match": "exact_origin"}], username="ann",
                                     password="pw-first-1234567", label="Alpha", tags=["Bank"])
    port = Port()
    editor = LoginEditorService(controller, port, generate=lambda: "Gen-Pass-123456!")
    extras = LoginExtrasService(controller, port, editor)
    return controller, port, extras, {"source": "credential", "id": alpha, "kind": "web"}


def _entry(controller, entry_id):
    return next(e for e in controller.session._require_payload()["entries"] if e["id"] == entry_id)


# ------------------------------------------------------------------------------------ access rules
def test_access_rules_round_trip_and_enforcement(env):
    controller, port, extras, ref = env
    access = AccessRulesService(controller, port, extras)
    view = access.get(ref)
    assert view["access"] == {"copy": "normal", "phones": "full", "expires": ""} and not view["unknown"]
    port.passwords = [MASTER]
    saved = access.save(ref, {"copy": "once", "expires": "2000-01-01"})
    assert saved["access"]["copy"] == "once" and saved["expired"] is True
    stored = _entry(controller, ref["id"])
    assert stored["scope"]["access"] == {"copy": "once", "expires": "2000-01-01"}
    # Expired: never filled, always the master password.
    enforced = access_policy.enforced_policy(stored)
    assert enforced["fill"] == "never" and enforced["require_master_password"] is True
    assert controller.session.item_service.find_web_candidates("https://alpha.test/login")  # still listed
    # Loosening works on the free plan.
    controller.session.pro_features = frozenset()
    port.passwords = [MASTER]
    loosened = access.save(ref, {"copy": "normal", "expires": None})
    assert loosened["access"] == {"copy": "normal", "phones": "full", "expires": ""}
    assert "access" not in _entry(controller, ref["id"])["scope"]


def test_access_rules_tightening_needs_pro(env):
    controller, port, extras, ref = env
    controller.session.pro_features = frozenset()
    access = AccessRulesService(controller, port, extras)
    with pytest.raises(ApiError) as refused:
        access.save(ref, {"phones": "view"})
    assert refused.value.code == "pro_required" and port.upgrades == 1
    with pytest.raises(ApiError) as strict:
        access.save(ref, {"reauth": True})
    assert strict.value.code == "pro_required"
    assert "access" not in _entry(controller, ref["id"])["scope"]


def test_unknown_access_value_is_strictest_and_kept_by_edits(env):
    controller, port, extras, ref = env
    session = controller.session
    session.set_entry_access(ref["id"], {"copy": "once", "biometric_only": True})
    entry = _entry(controller, ref["id"])
    assert access_policy.enforced_policy(entry)["fill"] == "never"
    assert AccessRulesService(controller, port, extras).get(ref)["unknown"] is True
    session.update_entry_fields(ref["id"], password="pw-next-1234567")
    assert _entry(controller, ref["id"])["scope"]["access"] == {"copy": "once", "biometric_only": True}


def test_copy_once_clears_fast_then_asks_again(env):
    controller, port, _extras, ref = env
    controller.session.set_entry_access(ref["id"], {"copy": "once"})
    secrets = SecretService(controller, port)
    port.passwords = [MASTER]
    result = secrets.copy(ref, "password")
    assert controller.clipboard.value == "pw-first-1234567" and controller.clipboard.short == [10]
    assert result["clear_after"] == 10
    port.asked.clear()
    port.passwords = [MASTER]
    secrets.copy(ref, "password")
    assert port.asked == ["Confirm it's you to copy again."]
    controller.lock()
    assert controller._copy_once_used == set()


# ------------------------------------------------------------------------------------ item history
def test_login_edits_are_captured_and_one_field_restores(env):
    controller, port, _extras, ref = env
    session = controller.session
    session.update_entry_fields(ref["id"], username="bob")
    service = ItemHistoryService(controller, port)
    rows = service.list(ref)["rows"]
    assert len(rows) == 1 and rows[0]["change_type"] == "update"
    fields = service.diff(ref, rows[0]["snapshot_id"])["fields"]
    assert {"field": "username", "before": "ann", "after": "bob", "secret": False, "restorable": True} in fields
    assert service.restore_field(ref, rows[0]["snapshot_id"], "username")["message"] == "username restored."
    assert _entry(controller, ref["id"])["username"] == "ann"
    assert sorted(r["change_type"] for r in service.list(ref)["rows"]) == ["restore", "update"]
    with pytest.raises(ApiError) as refused:
        service.restore_field(ref, rows[0]["snapshot_id"], "created_at")
    assert refused.value.code == "not_restorable"


def test_password_diff_is_masked_until_revealed(env):
    controller, port, _extras, ref = env
    controller.session.update_entry_fields(ref["id"], password="pw-second-1234567")
    service = ItemHistoryService(controller, port)
    row = service.list(ref)["rows"][0]
    masked = service.diff(ref, row["snapshot_id"])["fields"]
    assert "pw-first" not in json.dumps(masked)
    port.passwords = [MASTER]
    shown = service.diff(ref, row["snapshot_id"], reveal=True)["fields"]
    assert any(f["field"] == "password" and f["before"] == "pw-first-1234567" for f in shown)


def test_local_only_change_is_not_captured_and_free_limits_apply(env):
    controller, _port, _extras, ref = env
    session = controller.session
    session.pro_features = frozenset()
    entry = _entry(controller, ref["id"])
    entry["site_icon"] = "x"
    session.save()
    assert session.entry_history_rows(ref["id"]) == []
    for n in range(7):
        session.update_entry_fields(ref["id"], username=f"user{n}")
    assert len(session.entry_history_rows(ref["id"])) == item_history.FREE_LIMITS["max_versions"]


def test_typed_item_history_masks_card_number(env):
    controller, port, _extras, _ref = env
    items = controller.session.item_service
    card = items.create_card("Visa", number="4111111111111111", expiry="12/30")
    items.update_item(card, title="Visa 2")
    ref = {"source": "typed", "id": card, "kind": "card"}
    service = ItemHistoryService(controller, port)
    row = service.list(ref)["rows"][0]
    fields = service.diff(ref, row["snapshot_id"])["fields"]
    assert any(f["field"] == "title" and f["before"] == "Visa" for f in fields)
    service.restore_field(ref, row["snapshot_id"], "title")
    assert items.get_item(card)["title"] == "Visa"


# ------------------------------------------------------------------------------------- travel mode
def test_travel_mode_hides_and_needs_master_password_to_turn_off(env):
    controller, port, _extras, ref = env
    session = controller.session
    other = session.create_web_login(urls=[{"url": "https://beta.test", "match": "exact_origin"}], username="b",
                                     password="pw-beta-1234567", label="Beta")
    service = TravelService(controller, port)
    assert service.get()["available_tags"] == ["Bank"]
    result = service.save([], [" bank "])
    assert result["on"] is True and result["hidden_count"] == 1
    assert travel.hidden_id_set(session) == {ref["id"]}
    home = HomeService(controller)
    ids = json.dumps(home.items(None, None, "")["items"])
    assert ref["id"] not in ids and other in ids
    assert session.item_service.find_web_candidates("https://alpha.test/") == []
    port.passwords = [MASTER]
    off = service.off()
    assert off["on"] is False and port.asked[-1] == "Confirm it's you to show hidden items again."
    assert session.item_service.find_web_candidates("https://alpha.test/")


def test_travel_mode_needs_pro_to_turn_on(env):
    controller, port, _extras, _ref = env
    controller.session.pro_features = frozenset()
    with pytest.raises(ApiError) as refused:
        TravelService(controller, port).save([], ["Bank"])
    assert refused.value.code == "pro_required"


# ---------------------------------------------------------------------------------------- clean up
def test_hygiene_merge_and_bulk_undo(env):
    controller, port, _extras, ref = env
    session = controller.session
    twin = session.create_web_login(urls=[{"url": "https://alpha.test", "match": "exact_origin"}], username="ANN",
                                    password="pw-other-1234567", label="Alpha 2", tags=["Work"])
    service = HygieneService(controller, port)
    scan = service.scan()
    assert scan["summary"]["dupes"] == 2
    assert scan["groups"][0]["type"] == "same_account_other_password"
    other_ref = {"source": "credential", "id": twin}
    preview = service.merge_preview(ref, other_ref)["fields"]
    assert any(f["field"] == "tags" for f in preview)
    assert "pw-other" not in json.dumps(preview)
    service.merge(ref, other_ref)
    merged = _entry(controller, ref["id"])
    assert merged["tags"] == ["Bank", "Work"]
    assert merged["password_history"][0]["password"] == "pw-other-1234567"
    assert all(e["id"] != twin for e in session._require_payload()["entries"])
    assert "merge" in {r["change_type"] for r in session.entry_history_rows(ref["id"])}
    # Bulk delete (Pro) with Undo.
    beta = session.create_web_login(urls=[{"url": "https://beta.test", "match": "exact_origin"}], username="b",
                                    password="pw-beta-1234567", label="Beta")
    refs = [ref, {"source": "credential", "id": beta}]
    deleted = service.delete(refs)
    assert deleted["can_undo"] is True
    assert session._require_payload()["entries"] == []
    service.undo()
    assert {e["id"] for e in session._require_payload()["entries"]} == {ref["id"], beta}


def test_hygiene_bulk_needs_pro(env):
    controller, port, _extras, ref = env
    session = controller.session
    beta = session.create_web_login(urls=[{"url": "https://beta.test", "match": "exact_origin"}], username="b",
                                    password="pw-beta-1234567", label="Beta")
    session.pro_features = frozenset()
    service = HygieneService(controller, port)
    with pytest.raises(ApiError) as refused:
        service.delete([ref, {"source": "credential", "id": beta}])
    assert refused.value.code == "pro_required"
    deleted = service.delete([ref])
    assert deleted["can_undo"] is False


# ------------------------------------------------------------- security scan 2026-11-15 regressions
def test_travel_narrowing_needs_the_master_password(env):
    """W-M2: swapping or dropping a hidden tag shows items again, so it needs the same check as turning it off."""
    controller, port, _extras, ref = env
    service = TravelService(controller, port)
    service.save([], ["Bank"])
    assert port.asked == []
    service.save([], ["Bank", "Unused"])  # widening hides more: no prompt
    assert port.asked == []
    port.passwords = []  # the user cancels
    with pytest.raises(ApiError):
        service.save([], ["Unused"])
    assert travel.setting_of(controller.session)["tags"] == ["Bank", "Unused"]
    assert ref["id"] in travel.hidden_id_set(controller.session)
    assert port.asked == ["Confirm it's you to show hidden items again."]
    port.passwords = [MASTER]
    service.save([], ["Unused"])
    assert travel.setting_of(controller.session)["tags"] == ["Unused"]
    assert ref["id"] not in travel.hidden_id_set(controller.session)


def test_travel_narrowing_compares_settings_not_todays_items(env):
    """A hidden tag that no item has today still counts: dropping it is narrowing."""
    controller, port, _extras, _ref = env
    service = TravelService(controller, port)
    service.save([], ["Bank", "Nothing yet"])
    port.passwords = []
    with pytest.raises(ApiError):
        service.save([], ["Bank"])
    assert travel.setting_of(controller.session)["tags"] == ["Bank", "Nothing yet"]


def test_travel_save_checks_pro_before_asking(env):
    controller, port, _extras, _ref = env
    service = TravelService(controller, port)
    service.save([], ["Bank"])
    controller.session.pro_features = frozenset()
    with pytest.raises(ApiError) as refused:
        service.save([], ["Other"])
    assert refused.value.code == "pro_required" and port.asked == []


def _history_row_with(service, ref, field_prefix):
    for row in service.list(ref)["rows"]:
        fields = service.diff(ref, row["snapshot_id"])["fields"]
        if any(f["field"].startswith(field_prefix) for f in fields):
            return row, next(f["field"] for f in fields if f["field"].startswith(field_prefix))
    raise AssertionError("no history row changes " + field_prefix)


@pytest.mark.parametrize("change,prefix", [({"never_fill": True}, "policy"), ({"copy": "once"}, "scope")])
def test_restoring_a_looser_rule_from_history_needs_reauthentication(env, change, prefix):
    """W-M3: restoring an older policy / scope.access must not drop a rule without the owner check."""
    controller, port, extras, ref = env
    port.passwords = [MASTER]
    AccessRulesService(controller, port, extras).save(ref, change)
    before = access_policy.enforced_policy(_entry(controller, ref["id"]))
    service = ItemHistoryService(controller, port)
    row, field = _history_row_with(service, ref, prefix)
    controller.routine_reauth = (None, 0)  # the rules screen's confirmation grace has run out
    port.asked.clear()
    port.passwords = []  # cancelled
    with pytest.raises(ApiError):
        service.restore_field(ref, row["snapshot_id"], field)
    assert port.asked  # the user was asked
    assert access_policy.enforced_policy(_entry(controller, ref["id"])) == before
    port.passwords = [MASTER]
    service.restore_field(ref, row["snapshot_id"], field)
    entry = _entry(controller, ref["id"])
    assert access_policy.enforced_policy(entry)["fill"] == "click" and not entry["scope"].get("access")


def test_restoring_a_stricter_rule_needs_pro(env):
    controller, port, extras, ref = env
    port.passwords = [MASTER]
    AccessRulesService(controller, port, extras).save(ref, {"never_fill": True})
    port.passwords = [MASTER]
    AccessRulesService(controller, port, extras).save(ref, {"never_fill": False})
    service = ItemHistoryService(controller, port)
    newest, field = _history_row_with(service, ref, "policy")  # the version with fill never
    controller.session.pro_features = frozenset()
    with pytest.raises(ApiError) as refused:
        service.restore_field(ref, newest["snapshot_id"], field)
    assert refused.value.code == "pro_required"


def test_bulk_merge_undo_restores_a_keeper_merged_twice(env):
    """W-L3: the journal keeps the first before-state of a keeper merged more than once."""
    controller, port, _extras, ref = env
    session = controller.session
    for n, (user, tag) in enumerate((("ANN", "Work"), ("Ann", "Home"))):
        session.create_web_login(urls=[{"url": "https://alpha.test", "match": "exact_origin"}], username=user,
                                 password="pw-first-1234567", label=f"Alpha {n}", tags=[tag])
    service = HygieneService(controller, port)
    group = next(g for g in service.scan()["groups"] if g["type"] == "same_login")
    keeper_id = group["items"][0]["ref"]["id"]
    original = json.loads(json.dumps(_entry(controller, keeper_id)))
    assert service.merge_all()["count"] == 2
    assert len(_entry(controller, keeper_id)["tags"]) == 3
    service.undo()
    restored = _entry(controller, keeper_id)
    assert restored["tags"] == original["tags"]
    assert len(session._require_payload()["entries"]) == 3


# --------------------------------------------------------------------- final review 2026-11-15 (Windows)
def _grace(controller):
    """The recent-unlock grace that Windows Hello or a routine check leaves."""
    controller.routine_reauth = (controller.guard.stamp(), controller._clock() + 600)


def test_travel_hides_its_collections_and_refuses_their_operations(env):
    """M1: a hidden collection is absent from the sidebar, filters and collections page, and cannot be archived,
    deleted, renamed or have members moved until travel mode is off."""
    from localvault.app.workspace import CollectionsService
    from localvault.collections import TravelHiddenCollection

    controller, port, _extras, _ref = env
    session = controller.session
    bank = session.collections.create("Vault Docs")
    work = session.collections.create("Work Stuff")
    note = session.item_service.create_note("Statement", "acct 42", collection_ids=[bank])
    loose = session.item_service.create_note("Loose", "x")
    TravelService(controller, port).save([bank], [])
    home = HomeService(controller)
    assert "Vault Docs" not in json.dumps(home.nav()) and "Work Stuff" in json.dumps(home.nav())
    assert "Vault Docs" not in json.dumps(home.items(None, None, ""))
    pages = CollectionsService(controller, lambda: None)
    assert [c["id"] for c in pages.list()["collections"]] == [work]
    for action in (lambda: pages.archive(bank), lambda: pages.rename(bank, "Renamed")):
        with pytest.raises(ApiError):
            action()
    with pytest.raises(TravelHiddenCollection):
        session.collections.delete(bank)
    with pytest.raises(TravelHiddenCollection):
        session.collections.set_membership(loose, [bank])  # moving an item into it
    assert session.collections.members(bank) == []
    payload_note = next(i for i in session._require_typed_catalog()["items"] if i["id"] == note)
    assert payload_note["collection_ids"] == [bank] and note in travel.hidden_id_set(session)
    assert any(c["id"] == bank for c in session.collections.list())
    pages.rename(work, "Work Renamed")  # other collections still work
    port.passwords = [MASTER]
    TravelService(controller, port).off()
    pages.archive(bank)
    assert note not in travel.hidden_id_set(session)


def test_history_reveal_of_a_note_body_needs_the_master_password(env):
    """M2: the grace or Windows Hello is not enough to show a secure note's body in a history diff."""
    controller, port, _extras, _ref = env
    items = controller.session.item_service
    note = items.create_note("Diary", "old secret body")
    items.update_item(note, body="new secret body")
    ref = {"source": "typed", "id": note, "kind": "note"}
    service = ItemHistoryService(controller, port)
    row = service.list(ref)["rows"][0]
    _grace(controller)
    port.passwords = []  # cancelled
    with pytest.raises(ApiError):
        service.diff(ref, row["snapshot_id"], reveal=True)
    assert port.asked == ["Confirm to reveal this note"]  # asked although the grace was running; not "password"
    port.asked.clear()
    port.passwords = [MASTER]
    shown = service.diff(ref, row["snapshot_id"], reveal=True)["fields"]
    assert any(f["field"] == "payload.body" and f["before"] == "old secret body" for f in shown)
    # A card number follows the usual reveal rule: the grace is enough.
    card = items.create_card("Visa", number="4111111111111111", expiry="12/30")
    items.update_item(card, title="Visa 2")
    card_ref = {"source": "typed", "id": card, "kind": "card"}
    card_row = service.list(card_ref)["rows"][0]
    _grace(controller)
    port.asked.clear()
    service.diff(card_ref, card_row["snapshot_id"], reveal=True)
    assert port.asked == []


def test_history_diff_never_shows_passkey_key_material(env, monkeypatch):
    """M2: a passkey's private key is masked in a diff even when revealed."""
    controller, port, _extras, _ref = env
    current = {"id": "pk", "kind": "passkey", "payload": {"private_key": "NEW-KEY-MATERIAL", "rp_id": "x.test"}}
    old = {"id": "pk", "kind": "passkey", "payload": {"private_key": "OLD-KEY-MATERIAL", "rp_id": "x.test"}}
    monkeypatch.setattr("localvault.app.feature_pack._record", lambda _s, _r: ("item", current))
    service = ItemHistoryService(controller, port)
    monkeypatch.setattr(service, "_snapshot", lambda *_a: old)
    port.passwords = [MASTER]
    fields = service.diff({"source": "typed", "id": "pk"}, "s1", reveal=True)["fields"]
    assert "KEY-MATERIAL" not in json.dumps(fields)
    assert any(f["field"] == "payload.private_key" for f in fields)


def test_legacy_policy_controls_take_the_access_rules_checks(env):
    """M3: fill never -> click through the old policy save asks to confirm it's you; tightening there is Pro."""
    controller, port, extras, ref = env
    port.passwords = [MASTER]
    extras.policy_save(ref, {"fill": "never"})
    controller.routine_reauth = (None, 0)
    port.asked.clear()
    port.passwords = []  # cancelled
    with pytest.raises(ApiError):
        extras.policy_save(ref, {"fill": "click"})
    assert port.asked
    assert access_policy.normalized_policy(_entry(controller, ref["id"]).get("policy"))["fill"] == "never"
    port.asked.clear()
    extras.policy_save(ref, {"save_prompts": False})  # not an access rule: no prompt
    assert port.asked == []
    controller.session.pro_features = frozenset()
    with pytest.raises(ApiError) as refused:
        extras.policy_save(ref, {"require_master_password": True})
    assert refused.value.code == "pro_required"


def test_home_health_and_reminders_leave_out_travel_hidden_items(env):
    """L1 and L2."""
    import datetime

    from localvault.app.workspace import RemindersService

    controller, port, _extras, _ref = env
    session = controller.session
    session.create_web_login(urls=[{"url": "https://beta.test", "match": "exact_origin"}], username="b",
                             password="pw-first-1234567", label="Beta")
    passport = session.item_service.create_note("Passport Hidden", "x", tags=["Bank"])
    session.reminders.create(passport, datetime.date.today() + datetime.timedelta(days=5))
    assert HomeService(controller).overview()["health"]["reused"] == 2
    reminders = RemindersService(controller, lambda: None)
    assert [r["title"] for r in reminders.list()["rows"]] == ["Passport Hidden"]
    TravelService(controller, port).save([], ["Bank"])
    overview = HomeService(controller).overview()
    assert overview["health"]["reused"] == 0
    assert "Passport Hidden" not in json.dumps(overview)
    assert reminders.list()["rows"] == []


def test_copy_once_covers_history_copy_and_recovery_codes(env):
    """L4: after the one copy, an earlier password or a recovery code needs the master password too."""
    controller, port, extras, ref = env
    session = controller.session
    session.update_entry_fields(ref["id"], password="pw-second-1234567")
    extras.recovery_codes_save(ref, ["code-1", "code-2"])
    session.set_entry_access(ref["id"], {"copy": "once"})
    port.passwords = [MASTER]
    SecretService(controller, port).copy(ref, "password")
    port.passwords = [MASTER]
    row = extras.history(ref)["rows"][0]
    port.asked.clear()
    port.passwords = [MASTER]
    extras.history_copy(ref, row["index"], row["changed_at"])
    assert port.asked == ["Confirm it's you to copy again."]
    assert controller.clipboard.value == "pw-first-1234567" and controller.clipboard.short[-1] == 10
    port.asked.clear()
    port.passwords = [MASTER]
    extras.recovery_use_next(ref)
    assert port.asked[0] == "Confirm it's you to copy again."
    assert controller.clipboard.value == "code-1"


def test_item_endpoints_refuse_travel_hidden_ids(env):
    """L7: a stale selection or deep link cannot open a hidden item."""
    controller, port, extras, ref = env
    TravelService(controller, port).save([], ["Bank"])
    calls = [lambda: ItemHistoryService(controller, port).list(ref),
             lambda: AccessRulesService(controller, port, extras).get(ref),
             lambda: SecretService(controller, port).detail(ref),
             lambda: SecretService(controller, port).copy(ref, "username"),
             lambda: extras.policy(ref)]
    for call in calls:
        with pytest.raises(ApiError) as refused:
            call()
        assert refused.value.code == "not_found"
    assert port.asked == []


def test_a_failed_save_drops_its_history_label(env, monkeypatch):
    """L9: the label of a write that failed is not reused by the next save."""
    from localvault.vault import VaultError

    controller, _port, _extras, ref = env
    session = controller.session
    session.mark_history_change([ref["id"]], "sync")
    _entry(controller, ref["id"])["username"] = "from-sync"

    def broken(*_args, **_kwargs):
        raise OSError("disk full")

    monkeypatch.setattr("localvault.vault.atomic_write_json", broken)
    with pytest.raises(VaultError):
        session.save()
    monkeypatch.undo()
    session.update_entry_fields(ref["id"], username="bob")
    assert [r["change_type"] for r in session.entry_history_rows(ref["id"])] == ["update"]


def test_restore_field_does_not_hold_the_lock_while_asking(env):
    """L9: other history calls do not wait behind an open re-authentication dialog."""
    import threading

    controller, port, extras, ref = env
    port.passwords = [MASTER]
    AccessRulesService(controller, port, extras).save(ref, {"never_fill": True})
    service = ItemHistoryService(controller, port)
    row, field = _history_row_with(service, ref, "policy")
    controller.routine_reauth = (None, 0)
    free = []
    original = port.ask_password

    def probe():
        got = service._lock.acquire(blocking=False)
        if got:
            service._lock.release()
        free.append(got)

    def ask(title, message):
        thread = threading.Thread(target=probe)
        thread.start()
        thread.join()
        return original(title, message)

    port.ask_password = ask
    port.passwords = [MASTER]
    service.restore_field(ref, row["snapshot_id"], field)
    assert free == [True]
