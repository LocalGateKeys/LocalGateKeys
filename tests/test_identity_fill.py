from __future__ import annotations

import json
from types import SimpleNamespace

import pytest

from localvault.browser_broker import BrowserBroker
from localvault.identity_fill import (
    IdentityReleaseError,
    IdentityReleaseManager,
    normalize_selected_fields,
    validate_identity_context,
)
from localvault.item_schema import ItemSchemaError, validate_payload
from broker_host import BrokerHostBase as RuntimeActions
from localvault.session_guard import SessionGuard, StaleSession
from localvault.settings import AppSettings
from localvault.vault import create_vault

MASTER = "identity test master password"
KDF = {"time_cost": 1, "memory_cost_kib": 8192, "parallelism": 1, "hash_len": 32}


class Clock:
    def __init__(self) -> None:
        self.now = 100.0

    def tick(self, seconds: float) -> None:
        self.now += seconds


def _identity(guard: SessionGuard, clock: Clock) -> tuple[IdentityReleaseManager, str]:
    manager = IdentityReleaseManager(guard, monotonic=lambda: clock.now)
    guard.open(3600)
    token = manager.issue(
        identity_id="identity-1", revision=3, origin="https://example.test",
        context=json.dumps([8, "document-A", "https://example.test", "operation-1"]),
        fields=["name", "email"], ttl=30,
    )
    return manager, token


def test_identity_schema_is_closed_text_only() -> None:
    payload = validate_payload("identity", {
        "name": "Ada Example", "email": "ada@example.test", "address_line1": "1 Test Way",
    })
    assert payload["name"] == "Ada Example"
    with pytest.raises(ItemSchemaError):
        validate_payload("identity", {"password": "not-an-identity-field"})
    with pytest.raises(ItemSchemaError):
        validate_payload("identity", {"email": 123})
    with pytest.raises(ItemSchemaError):
        validate_payload("identity", {"name": "x" * 257})
    with pytest.raises(ItemSchemaError):
        validate_payload("identity", {"name": "Ada", "script": "<script>alert(1)</script>"})


def test_identity_service_revision_and_metadata_redaction(tmp_path) -> None:
    session = create_vault(tmp_path / "identity.json", MASTER, kdf_overrides=KDF)
    item_id = session.items.create_identity(
        "Personal", {"name": "Ada Example", "email": "ada@example.test", "phone": "+1 555 0100"}
    )
    assert session.items.search_metadata("ada@example.test") == []
    assert "ada@example.test" not in repr(session.items.metadata_summaries())
    view = session.items.identity_release_view(item_id)
    assert view["fields"]["email"] == "ada@example.test"
    assert session.items.update_identity(item_id, {"city": "London"}, expected_revision=1)
    with pytest.raises(Exception, match="revision conflict"):
        session.items.update_identity(item_id, {"city": "Paris"}, expected_revision=1)
    session.lock()


@pytest.mark.parametrize("bad", [
    {"origin": "https://evil.test"},
    {"context": json.dumps([9, "document-A", "https://example.test", "operation-1"])},
    {"context": json.dumps([8, "document-B", "https://example.test", "operation-1"])},
    {"identity_id": "identity-2"},
    {"revision": 4},
    {"fields": ["email"]},
])
def test_identity_release_denies_changed_scope_and_consumes_capability(bad) -> None:
    clock = Clock()
    guard = SessionGuard("profile-1", monotonic=lambda: clock.now, wall_clock=lambda: clock.now)
    manager, token = _identity(guard, clock)
    args = {
        "identity_id": "identity-1", "revision": 3, "origin": "https://example.test",
        "context": json.dumps([8, "document-A", "https://example.test", "operation-1"]),
        "fields": ["name", "email"], "identity": {"fields": {"name": "Ada", "email": "ada@example.test"}},
    }
    args.update(bad)
    with pytest.raises((IdentityReleaseError, StaleSession, ItemSchemaError)):
        manager.release(token, **args)
    with pytest.raises(IdentityReleaseError):
        manager.release(token, identity_id="identity-1", revision=3, origin="https://example.test",
                        context=json.dumps([8, "document-A", "https://example.test", "operation-1"]),
                        fields=["name", "email"],
                        identity={"fields": {"name": "Ada", "email": "ada@example.test"}})


def test_identity_release_is_selected_only_and_one_use() -> None:
    clock = Clock()
    guard = SessionGuard("profile-1", monotonic=lambda: clock.now, wall_clock=lambda: clock.now)
    manager, token = _identity(guard, clock)
    context = json.dumps([8, "document-A", "https://example.test", "operation-1"])
    values = manager.release(
        token, identity_id="identity-1", revision=3, origin="https://example.test", context=context,
        fields=["name", "email"], identity={"fields": {"name": "Ada", "email": "ada@example.test", "phone": "secret"}},
    )
    assert values == {"name": "Ada", "email": "ada@example.test"}
    with pytest.raises(IdentityReleaseError):
        manager.release(token, identity_id="identity-1", revision=3, origin="https://example.test",
                        context=context, fields=["name", "email"], identity={"fields": {"name": "Ada", "email": "ada@example.test"}})


def test_identity_release_expires_and_lock_invalidates() -> None:
    clock = Clock()
    guard = SessionGuard("profile-1", monotonic=lambda: clock.now, wall_clock=lambda: clock.now)
    manager, token = _identity(guard, clock)
    clock.tick(31)
    with pytest.raises(IdentityReleaseError):
        manager.release(token, identity_id="identity-1", revision=3, origin="https://example.test",
                        context=json.dumps([8, "document-A", "https://example.test", "operation-1"]),
                        fields=["name", "email"], identity={"fields": {"name": "Ada", "email": "ada@example.test"}})

    manager, token = _identity(guard, clock)
    guard.invalidate()
    with pytest.raises(IdentityReleaseError):
        manager.release(token, identity_id="identity-1", revision=3, origin="https://example.test",
                        context=json.dumps([8, "document-A", "https://example.test", "operation-1"]),
                        fields=["name", "email"], identity={"fields": {"name": "Ada", "email": "ada@example.test"}})


class IdentityBroker(RuntimeActions, BrowserBroker):
    def __init__(self, session) -> None:
        self.session = session
        self.guard = SessionGuard("profile-1")
        self.guard.open(3600)
        self.root = None
        self.settings = AppSettings(auto_lock_seconds=0)
        self.active_profile = SimpleNamespace(id="profile-1", name="Test profile", color="#12ABCD")
        self._remote_busy = False
        self.last_extension_seen = 0
        self.last_extension_version = ""
        self.last_secret_use = 0
        self._closing = False

    def ensure_unlocked(self):
        return self._session_available()

    def run_on_ui(self, function, timeout=0):
        return function()

    def _touch_secret(self):
        self.last_secret_use = 1

    def reauthenticate(self, *args):
        return True

    def request(self, action, *, origin="https://example.test", context=None, **kwargs):
        return self.dispatch_remote({
            "action": action, "protocol": 2, "identity_protocol": 1,
            "extension_version": "0.3.3", "origin": origin,
            "context": context or json.dumps([8, "document-A", origin, "operation-1"]), **kwargs,
        })


def test_broker_identity_review_returns_no_values_until_release(tmp_path, monkeypatch) -> None:
    session = create_vault(tmp_path / "identity.json", MASTER, kdf_overrides=KDF)
    item_id = session.items.create_identity("Personal", {"name": "Ada Example", "email": "ada@example.test", "phone": "secret-phone"})
    broker = IdentityBroker(session)
    start = broker.request("begin_identity_browser", user_gesture=True)
    assert start["ok"] and start["choices"][0]["entry_id"] == item_id
    assert "ada@example.test" not in json.dumps(start)
    monkeypatch.setattr("broker_host.confirm", lambda *args: True)
    approved = broker.request("approve_identity_browser", user_gesture=True, entry_id=item_id,
                              revision=start["choices"][0]["revision"], fields=["name", "email"],
                              session_id=start["session_id"])
    assert approved["ok"] and "ada@example.test" not in json.dumps(approved)
    released = broker.request("release_identity_browser", approval=approved["approval"], entry_id=item_id,
                              revision=approved["revision"], fields=["name", "email"])
    assert released["values"] == {"name": "Ada Example", "email": "ada@example.test"}
    assert "phone" not in released["values"]


def test_selected_field_normalization_rejects_credential_like_names() -> None:
    with pytest.raises(ItemSchemaError):
        normalize_selected_fields(["password"])


def test_identity_context_requires_browser_document_and_exact_origin() -> None:
    context = json.dumps([8, "document-A", "https://example.test", "operation-1"])
    parsed = validate_identity_context(context, "https://example.test")
    assert parsed.tab_id == 8
    assert parsed.document_id == "document-A"
    assert parsed.operation_id == "operation-1"
    with pytest.raises(ItemSchemaError):
        validate_identity_context(
            json.dumps([8, "document-A", "https://evil.test", "operation-1"]),
            "https://example.test",
        )
    with pytest.raises(ItemSchemaError):
        validate_identity_context("tab-8-document-A-operation-1", "https://example.test")


def test_identity_multifield_release_is_selected_only_and_redacted(tmp_path, monkeypatch) -> None:
    session = create_vault(tmp_path / "identity-multifield.json", MASTER, kdf_overrides=KDF)
    item_id = session.items.create_identity(
        "Personal",
        {"given_name": "Ada", "family_name": "Example", "email": "ada@example.test",
         "phone": "secret-phone", "postal_code": "NW1 6XE"},
    )
    broker = IdentityBroker(session)
    start = broker.request("begin_identity_browser", user_gesture=True)
    choice = start["choices"][0]
    assert set(choice["fields"]) == {"given_name", "family_name", "email", "phone", "postal_code"}
    assert "ada@example.test" not in json.dumps(start)
    monkeypatch.setattr("broker_host.confirm", lambda *args: True)
    approved = broker.request(
        "approve_identity_browser", user_gesture=True, entry_id=item_id,
        revision=choice["revision"], fields=["given_name", "family_name", "email"],
        session_id=start["session_id"],
    )
    assert approved["ok"]
    assert "values" not in approved and "ada@example.test" not in json.dumps(approved)
    released = broker.request(
        "release_identity_browser", approval=approved["approval"], entry_id=item_id,
        revision=approved["revision"], fields=["given_name", "family_name", "email"],
    )
    assert released["values"] == {"given_name": "Ada", "family_name": "Example", "email": "ada@example.test"}
    assert "secret-phone" not in json.dumps(released)


def test_identity_approval_cancel_and_replay_are_fail_closed(tmp_path, monkeypatch) -> None:
    session = create_vault(tmp_path / "identity-cancel.json", MASTER, kdf_overrides=KDF)
    item_id = session.items.create_identity("Personal", {"name": "Ada"})
    broker = IdentityBroker(session)
    start = broker.request("begin_identity_browser", user_gesture=True)
    revision = start["choices"][0]["revision"]
    monkeypatch.setattr("broker_host.confirm", lambda *args: False)
    cancelled = broker.request(
        "approve_identity_browser", user_gesture=True, entry_id=item_id,
        revision=revision, fields=["name"], session_id=start["session_id"],
    )
    assert cancelled == {"ok": False, "error": "user_cancelled"}

    monkeypatch.setattr("broker_host.confirm", lambda *args: True)
    approved = broker.request(
        "approve_identity_browser", user_gesture=True, entry_id=item_id,
        revision=revision, fields=["name"], session_id=start["session_id"],
    )
    assert broker.request(
        "cancel_identity_browser", approval=approved["approval"],
    ) == {"ok": True}
    released = broker.request(
        "release_identity_browser", approval=approved["approval"], entry_id=item_id,
        revision=revision, fields=["name"],
    )
    assert released["ok"] is False and "values" not in released


def test_identity_revision_lock_and_profile_changes_invalidate_release(tmp_path, monkeypatch) -> None:
    session = create_vault(tmp_path / "identity-stale.json", MASTER, kdf_overrides=KDF)
    item_id = session.items.create_identity("Personal", {"name": "Ada", "email": "ada@example.test"})
    broker = IdentityBroker(session)
    monkeypatch.setattr("broker_host.confirm", lambda *args: True)
    start = broker.request("begin_identity_browser", user_gesture=True)
    revision = start["choices"][0]["revision"]
    approved = broker.request(
        "approve_identity_browser", user_gesture=True, entry_id=item_id,
        revision=revision, fields=["email"], session_id=start["session_id"],
    )
    session.items.update_identity(item_id, {"city": "London"}, expected_revision=revision)
    stale = broker.request(
        "release_identity_browser", approval=approved["approval"], entry_id=item_id,
        revision=revision, fields=["email"],
    )
    assert stale["error"] == "session_changed" and "values" not in stale

    start = broker.request("begin_identity_browser", user_gesture=True)
    revision = start["choices"][0]["revision"]
    approved = broker.request(
        "approve_identity_browser", user_gesture=True, entry_id=item_id,
        revision=revision, fields=["email"], session_id=start["session_id"],
    )
    broker.guard.invalidate("profile-2")
    profile_stale = broker.request(
        "release_identity_browser", approval=approved["approval"], entry_id=item_id,
        revision=revision, fields=["email"],
    )
    assert profile_stale["error"] == "session_changed" and "values" not in profile_stale


def test_identity_actions_reject_context_origin_and_unknown_actions(tmp_path) -> None:
    session = create_vault(tmp_path / "identity-action.json", MASTER, kdf_overrides=KDF)
    session.items.create_identity("Personal", {"name": "Ada"})
    broker = IdentityBroker(session)
    bad_context = broker.dispatch_remote({
        "action": "begin_identity_browser", "protocol": 2, "identity_protocol": 1,
        "extension_version": "0.3.3", "origin": "https://example.test",
        "context": json.dumps([8, "document-A", "https://evil.test", "operation-1"]),
        "user_gesture": True,
    })
    assert bad_context["error"] == "invalid_request"
    unknown = broker.dispatch_remote({
        "action": "dump_identity_browser", "protocol": 2, "identity_protocol": 1,
        "extension_version": "0.3.3", "origin": "https://example.test",
        "context": json.dumps([8, "document-A", "https://example.test", "operation-1"]),
    })
    assert unknown["error"] == "unsupported_action"


# ---------------------------------------------------------------------------
# Card fill (autocomplete tokens; never the PIN)
# ---------------------------------------------------------------------------
from localvault.identity_fill import (  # noqa: E402
    CARD_FILL_PROTOCOL,
    CARD_FILL_TOKENS,
    CARD_PROTECTED_TOKENS,
    CardReleaseManager,
    card_fill_fields,
    card_fill_metadata,
    normalize_selected_card_fields,
    selected_card_values,
)

CARD_ITEM = {
    "id": "card-1", "kind": "card", "title": "Visa", "revision": 2,
    "payload": {"cardholder": "Ada Example", "number": "4111111111111111", "brand": "visa",
                "expiry": "07/29", "cvv": "123", "pin": "4321", "notes": "secret note"},
}


def test_card_fill_tokens_are_the_html_autocomplete_set_and_never_pin() -> None:
    assert CARD_FILL_TOKENS == ("cc-name", "cc-number", "cc-exp", "cc-exp-month", "cc-exp-year",
                                "cc-csc", "cc-type")
    assert CARD_FILL_PROTOCOL == 1
    assert CARD_PROTECTED_TOKENS == frozenset({"cc-number", "cc-csc"})
    fields = card_fill_fields(CARD_ITEM)
    assert fields == {"cc-name": "Ada Example", "cc-number": "4111111111111111", "cc-exp": "07/2029",
                      "cc-exp-month": "07", "cc-exp-year": "2029", "cc-csc": "123", "cc-type": "visa"}
    assert "4321" not in repr(fields) and "secret note" not in repr(fields)
    # A service ``card_fill_view`` (already token-keyed) is accepted as well.
    view = {"id": "card-1", "revision": 2, "fields": dict(fields)}
    assert card_fill_fields(view) == fields
    assert card_fill_fields({"payload": {}}) == {token: "" for token in CARD_FILL_TOKENS}
    with pytest.raises(ItemSchemaError):
        card_fill_fields("not a card")
    with pytest.raises(ItemSchemaError):
        card_fill_fields({"payload": {"number": 4111}})


def test_card_fill_metadata_has_per_field_approval_info_without_values() -> None:
    metadata = card_fill_metadata(CARD_ITEM)
    assert list(metadata) == list(CARD_FILL_TOKENS)
    assert metadata["cc-number"] == {"label": "Card number", "protected": True, "present": True}
    assert metadata["cc-csc"]["protected"] is True
    assert metadata["cc-name"] == {"label": "Cardholder name", "protected": False, "present": True}
    assert "pin" not in json.dumps(metadata) and "4111" not in json.dumps(metadata)
    assert "123" not in json.dumps(metadata)
    missing = card_fill_metadata({"payload": {"cardholder": "Ada"}})
    assert missing["cc-number"]["present"] is False and missing["cc-name"]["present"] is True


@pytest.mark.parametrize("bad", [["pin"], ["password"], ["cc-number", "cc-number"], [], "cc-number",
                                 ["cc-number", "name"], list(CARD_FILL_TOKENS) + ["cc-pin"]])
def test_card_selected_field_normalization_is_closed(bad) -> None:
    with pytest.raises(ItemSchemaError):
        normalize_selected_card_fields(bad)
    assert normalize_selected_card_fields(["cc-csc", "cc-number"]) == ("cc-csc", "cc-number")


def test_selected_card_values_release_only_the_selected_tokens() -> None:
    values = selected_card_values(CARD_ITEM, ["cc-name", "cc-exp-month", "cc-exp-year"])
    assert values == {"cc-name": "Ada Example", "cc-exp-month": "07", "cc-exp-year": "2029"}
    with pytest.raises(IdentityReleaseError):
        selected_card_values({"payload": {"cardholder": "Ada"}}, ["cc-number"])


def test_card_release_manager_mirrors_identity_capability_semantics() -> None:
    clock = Clock()
    guard = SessionGuard("profile-1", monotonic=lambda: clock.now, wall_clock=lambda: clock.now)
    guard.open(3600)
    manager = CardReleaseManager(guard, monotonic=lambda: clock.now)
    context = json.dumps([8, "document-A", "https://shop.test", "operation-1"])
    with pytest.raises(ItemSchemaError):
        manager.issue(identity_id="card-1", revision=2, origin="https://shop.test", context=context,
                      fields=["pin"])
    token = manager.issue(identity_id="card-1", revision=2, origin="https://shop.test", context=context,
                          fields=["cc-number", "cc-csc"], ttl=30)
    with pytest.raises(IdentityReleaseError):
        manager.release(token, identity_id="card-1", revision=2, origin="https://shop.test", context=context,
                        fields=["cc-number"], identity=CARD_ITEM)
    token = manager.issue(identity_id="card-1", revision=2, origin="https://shop.test", context=context,
                          fields=["cc-number", "cc-csc"], ttl=30)
    values = manager.release(token, identity_id="card-1", revision=2, origin="https://shop.test",
                             context=context, fields=["cc-number", "cc-csc"], identity=CARD_ITEM)
    assert values == {"cc-number": "4111111111111111", "cc-csc": "123"}
    with pytest.raises(IdentityReleaseError):
        manager.release(token, identity_id="card-1", revision=2, origin="https://shop.test",
                        context=context, fields=["cc-number", "cc-csc"], identity=CARD_ITEM)
    token = manager.issue(identity_id="card-1", revision=2, origin="https://shop.test", context=context,
                          fields=["cc-name"], ttl=30)
    clock.tick(31)
    with pytest.raises(IdentityReleaseError):
        manager.release(token, identity_id="card-1", revision=2, origin="https://shop.test",
                        context=context, fields=["cc-name"], identity=CARD_ITEM)
