"""Scan 2026-11-15 (Windows): travel mode in the browser and agent paths, the update dialog naming its target,
and the probe budget on the popup's site queries (W-M1, W-L1, W-L2, W-L5)."""
from __future__ import annotations

import json

import pytest

from localvault import travel
from localvault.app.agent_gate_service import _LockedSession
from localvault.vault import create_vault
from test_broker_item_limit import KDF, ORIGIN, _Broker
from test_phase2c_identity_broker import _Broker as _CardBroker

RFC_B32 = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"


@pytest.fixture
def session(tmp_path, monkeypatch):
    monkeypatch.setenv("LOCALGATEKEYS_DATA_DIR", str(tmp_path / "data"))
    return create_vault(tmp_path / "travel.json", "redacted-master", kdf_overrides=KDF)


def _travel_on(session, tag="Bank"):
    session._commit_prefs({travel.PREF_KEY: travel.clean_setting(True, [], [tag])})


@pytest.fixture
def confirms(monkeypatch):
    asked = []
    monkeypatch.setattr("broker_host.confirm", lambda *a: asked.append(a) or True)
    return asked


# ------------------------------------------------------------------ W-M1: travel-hidden items never reach a page
def test_totp_choices_and_release_leave_out_hidden_logins(session):
    shown = session.upsert_web(origin=ORIGIN, username="shown", password="pw-1")
    hidden = session.upsert_web(origin=ORIGIN, username="hidden", password="pw-2")
    session.set_details(shown, totp={"secret": RFC_B32})
    session.set_details(hidden, totp={"secret": RFC_B32}, tags=["Bank"])
    broker = _Broker(session)
    start = broker.request("begin_totp_browser", user_gesture=True)
    assert {c["entry_id"] for c in start["choices"]} == {shown, hidden}
    _travel_on(session)
    start = broker.request("begin_totp_browser", user_gesture=True)
    assert [c["entry_id"] for c in start["choices"]] == [shown]
    # Only the hidden login: nothing to offer at all.
    session.set_details(shown, tags=["Bank"])
    assert broker.request("begin_totp_browser", user_gesture=True) == {"ok": False, "error": "totp_not_found"}


def test_totp_release_of_a_login_hidden_after_the_grant_is_refused(session):
    entry = session.upsert_web(origin=ORIGIN, username="ada", password="pw-1")
    session.set_details(entry, totp={"secret": RFC_B32}, tags=["Bank"])
    broker = _Broker(session)
    start = broker.request("begin_totp_browser", user_gesture=True)
    _travel_on(session)  # turned on between the list and the release
    reply = broker.request("release_totp_browser", entry_id=entry, grant=start["grant"],
                           session_id=start["session_id"], gesture_nonce=start.get("gesture_nonce"))
    assert reply["ok"] is False and "code" not in json.dumps(reply)


def test_card_choices_and_release_leave_out_hidden_cards(tmp_path, monkeypatch):
    monkeypatch.setenv("LOCALGATEKEYS_DATA_DIR", str(tmp_path / "data"))
    session = create_vault(tmp_path / "card.json", "redacted-master", kdf_overrides=KDF)
    card = session.items.create_card("Visa", cardholder="Ada Example", number="4111111111111111",
                                     expiry="07/29", cvv="123", tags=["Bank"])
    broker = _CardBroker(session)
    start = broker.request("begin_card_browser", user_gesture=True)
    assert [c["entry_id"] for c in start["choices"]] == [card]
    monkeypatch.setattr("broker_host.confirm", lambda *a: True)
    approved = broker.request("approve_card_browser", user_gesture=True, entry_id=card, revision=1,
                              fields=["cc-number"], session_id=start["session_id"])
    assert approved["ok"]
    _travel_on(session)
    assert broker.request("begin_card_browser", user_gesture=True) == {"ok": False, "error": "card_not_found"}
    released = broker.request("release_card_browser", approval=approved["approval"], entry_id=card, revision=1,
                              fields=["cc-number"], gesture_nonce=approved["gesture_nonce"])
    assert released["ok"] is False and "4111111111111111" not in json.dumps(released)


def test_identity_choices_leave_out_hidden_identities(tmp_path, monkeypatch):
    monkeypatch.setenv("LOCALGATEKEYS_DATA_DIR", str(tmp_path / "data"))
    session = create_vault(tmp_path / "id.json", "redacted-master", kdf_overrides=KDF)
    session.items.create_identity("Personal", {"name": "Ada Example", "email": "ada@example.test"}, tags=["Bank"])
    broker = _CardBroker(session)
    before = broker.dispatch_remote({"action": "begin_identity_browser", "protocol": 2, "identity_protocol": 1,
                                     "extension_version": "0.3.3", "origin": ORIGIN, "user_gesture": True,
                                     "context": json.dumps([17, "document-redacted", ORIGIN, "operation-redacted"])})
    _travel_on(session)
    after = broker.dispatch_remote({"action": "begin_identity_browser", "protocol": 2, "identity_protocol": 1,
                                    "extension_version": "0.3.3", "origin": ORIGIN, "user_gesture": True,
                                    "context": json.dumps([17, "document-redacted", ORIGIN, "operation-redacted"])})
    assert before["ok"] and before["choices"]
    assert not after.get("choices")
    assert "Ada Example" not in json.dumps(after)


def test_passkey_records_and_metadata_leave_out_hidden_passkeys(session):
    session.items.create_passkey("Shown", relying_party_id="pk.test", credential_id="AQID", user_name="shown")
    session.items.create_passkey("Hidden", relying_party_id="pk.test", credential_id="BAUG", user_name="hidden",
                                 tags=["Bank"])
    assert len(session.items.passkey_records("pk.test")) == 2
    assert len(session.items.passkey_metadata()) == 2
    _travel_on(session)
    assert [r["title"] for r in session.items.passkey_records("pk.test")] == ["Shown"]
    assert [m["user_name"] for m in session.items.passkey_metadata()] == ["shown"]


# ------------------------------------------------------------------ W-L5: the agent gate's locked reader
class _Host:
    def run_on_ui(self, function, timeout=0):
        return function()


def test_agent_gate_reader_leaves_out_hidden_items(session):
    shown = session.upsert_web(origin=ORIGIN, username="shown", password="pw-1")
    hidden = session.upsert_web(origin=ORIGIN, username="hidden", password="pw-2")
    session.set_details(hidden, tags=["Bank"])
    note = session.items.create_note("Secret note", "body", tags=["Bank"])
    session.items.create_passkey("Hidden", relying_party_id="pk.test", credential_id="BAUG", tags=["Bank"])
    reader = _LockedSession(_Host(), session)
    assert reader.get_entry(hidden) is not None and reader.item(note) is not None
    _travel_on(session)
    assert reader.hidden_ids() >= {hidden, note}
    assert {str(s.id) for s in reader.summaries()} == {shown}
    assert reader.get_entry(hidden) is None and reader.get_entry(shown) is not None
    assert reader.item(note) is None
    assert note not in {str(i.get("id")) for i in reader.items()}
    assert reader.passkeys() == []

    from localvault.agent_gate import _hidden_ids

    assert _hidden_ids(reader) == reader.hidden_ids()
    assert _hidden_ids(session) == travel.hidden_id_set(session)


# ------------------------------------------------------------------ W-L1: the update dialog names the login
def test_update_dialog_names_the_login_chosen_by_entry_id(session, confirms):
    first = session.upsert_web(origin=ORIGIN, username="old-name", password="pw-old")
    session.upsert_web(origin=ORIGIN, username="other", password="pw-other")
    broker = _Broker(session)
    captured = broker.request("capture_browser", username="new-name", password="pw-new")
    reply = broker.request("save_pending_browser", pending_token=captured["pending_token"], entry_id=first,
                           user_gesture=True)
    assert reply["status"] == "updated"
    text = str(confirms[-1])
    assert "Its current username: old-name" in text
    assert "The username will change from old-name to new-name." in text


def test_update_dialog_names_the_login_for_a_changed_password(session, confirms):
    session.upsert_web(origin=ORIGIN, username="ada", password="pw-old")
    broker = _Broker(session)
    token = broker.request("capture_browser", username="ada", password="pw-new")["pending_token"]
    reply = broker.request("save_pending_browser", pending_token=token, user_gesture=True)
    assert reply["ok"] is True
    text = str(confirms[-1])
    assert "Login to update:" in text and "Its current username: ada" in text
    assert "will change" not in text


def test_target_lines_flatten_and_cap_the_title():
    from localvault.browser_broker import BrowserBroker

    lines = BrowserBroker._target_lines(("Bank\nFake: approve " + "x" * 300, "ada"), "ada")
    assert lines.count("\n") == 2 and "Bank Fake" in lines and len(lines) < 300
    assert BrowserBroker._target_lines(None, "ada") == ""


# ------------------------------------------------------------------ W-L2: popup site queries share the probe budget
@pytest.mark.parametrize("action", ["site_logins_browser", "passkey_hint_browser"])
def test_site_queries_are_probe_limited(session, action):
    session.upsert_web(origin=ORIGIN, username="ada", password="pw")
    broker = _Broker(session)
    replies = [broker.request(action) for _ in range(broker.PROBE_LIMIT_PER_ORIGIN + 3)]
    assert all(r["ok"] for r in replies[:broker.PROBE_LIMIT_PER_ORIGIN])
    assert replies[-1]["ok"] is False and replies[-1] == broker._probe_limited()


# ------------------------------------------------------------------ live test: change-password offer (no username)
def _password_only(broker):
    captured = broker.request("capture_browser", username="", password="pw-changed-1")
    assert captured["ok"] and captured["stored"] and captured["status"] == "update_only"
    pending = broker.request("pending_browser")
    assert pending["pending"] and pending["username"] == ""  # the page then offers this site's logins
    return captured["pending_token"]


def test_password_only_capture_updates_the_chosen_login_and_keeps_its_username(session, confirms):
    chosen = session.upsert_web(origin=ORIGIN, username="ada", password="pw-old")
    other = session.upsert_web(origin=ORIGIN, username="bob", password="pw-bob")
    broker = _Broker(session)
    token = _password_only(broker)
    logins = broker.request("site_logins_browser")
    assert {row["entry_id"] for row in logins["logins"]} == {chosen, other}
    # The extension sends the chosen login's username; a different one from the page is ignored.
    reply = broker.request("save_pending_browser", pending_token=token, entry_id=chosen, username="mallory",
                           user_gesture=True)
    assert reply == {"ok": True, "status": "updated", "entry_id": chosen}
    entry = session.get_entry(chosen)
    assert entry["username"] == "ada" and entry["password"] == "pw-changed-1"
    assert session.get_entry(other)["password"] == "pw-bob"
    assert "Its current username: ada" in str(confirms[-1]) and "will change" not in str(confirms[-1])
    assert len(session.find_web(ORIGIN)) == 2
    assert broker.request("pending_browser")["pending"] is False


@pytest.mark.parametrize("username", [None, "", "new-account"])
def test_password_only_capture_never_creates_a_login(session, confirms, username):
    broker = _Broker(session)
    token = _password_only(broker)
    extra = {} if username is None else {"username": username}
    reply = broker.request("save_pending_browser", pending_token=token, user_gesture=True, **extra)
    assert reply == {"ok": False, "error": "entry_required"}
    assert confirms == [] and session.find_web(ORIGIN) == []
    assert broker.request("pending_browser")["pending"] is True  # still there for a choice


def test_password_only_capture_refuses_another_sites_login(session, confirms):
    elsewhere = session.upsert_web(origin="https://other.test", username="ada", password="pw")
    broker = _Broker(session)
    token = _password_only(broker)
    reply = broker.request("save_pending_browser", pending_token=token, entry_id=elsewhere, user_gesture=True)
    assert reply == {"ok": False, "error": "entry_not_for_site"}
    assert confirms == [] and session.get_entry(elsewhere)["password"] == "pw"


def test_password_only_capture_expires_like_others(session):
    import time

    broker = _Broker(session)
    _password_only(broker)
    for item in broker._browser_pending_saves.values():
        item["created"] = time.monotonic() - 91
    assert broker.request("pending_browser") == {"ok": True, "pending": False}


# ------------------------------------------------------------------ step 3: "1 items" in the travel texts
@pytest.mark.parametrize("key", ["travel.on", "travel.exportLeftOut"])
def test_travel_counts_use_plural_forms_in_every_catalog(key):
    from localvault import i18n

    try:
        for code in sorted(i18n.SUPPORTED):
            value = i18n.catalog(code)[key]
            assert isinstance(value, dict) and "other" in value, (code, key)
            i18n.set_language(code)
            one, two = i18n.t(key, count=1), i18n.t(key, count=2)
            assert "1" in one and "2" in two and "{count}" not in one + two
            if code not in {"ja", "ko", "zh-Hans"}:
                assert one != two.replace("2", "1"), (code, key, one)  # a real singular form
        i18n.set_language("en")
        assert i18n.t("travel.on", count=1) == "Travel mode is on: 1 item hidden on this device."
        assert i18n.t("travel.exportLeftOut", count=1).startswith("1 hidden item was left out.")
        assert i18n.t("travel.on", count=3) == "Travel mode is on: 3 items hidden on this device."
    finally:
        i18n.set_language("en")
