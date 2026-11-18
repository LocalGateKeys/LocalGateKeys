"""Stage 3: typed items in the WebView UI — schema, detail, edit, save, reveal and copy."""
from __future__ import annotations

import json

import pytest

from localvault.api.result import ApiError
from localvault.app.controller import WebController
from localvault.app.typed import TypedService
from localvault.item_schema import ITEM_KINDS, PROTECTED_FIELDS_BY_KIND
from localvault.profiles import ProfileManager
from localvault.secret_text import SecretText
from localvault.settings import AppSettings

KDF = {"time_cost": 1, "memory_cost_kib": 8192, "parallelism": 1, "hash_len": 32}
MASTER = "correct horse battery"
CARD_NUMBER = "4111111111111111"


class Bus:
    def emit(self, name, detail):
        pass


class Sched:
    def call_later(self, delay, fn):
        return fn

    def cancel(self, handle):
        pass


class FakeClipboard:
    timeout_seconds = 30

    def __init__(self):
        self.value = None

    def copy(self, text):
        self.value = text

    def clear(self):
        self.value = None

    def remaining(self):
        return None


class Port:
    def __init__(self):
        self.passwords, self.asked, self.upgrades = [], [], []

    def ask_password(self, title, message):
        self.asked.append(title)
        answer = self.passwords.pop(0) if self.passwords else None
        return None if answer is None else SecretText.from_str(answer)

    def notify(self, kind, title, message):
        self.asked.append(f"{kind}:{title}")

    def confirm(self, title, message):
        return True

    def show_upgrade(self, *, limit, message, on_enter):
        self.upgrades.append(limit)


@pytest.fixture
def env(tmp_path, monkeypatch):
    monkeypatch.setattr("localvault.app.controller.clear_master_unlock_requirement", lambda _pid: None)
    profiles = ProfileManager(tmp_path / "data")
    profiles.ensure_profile()
    controller = WebController(profiles=profiles, settings=AppSettings(idle_source="vault"), bus=Bus(),
                               scheduler=Sched(), create_kwargs={"kdf_overrides": KDF})
    controller.create(MASTER, MASTER)
    controller.clipboard = FakeClipboard()
    port = Port()
    return TypedService(controller, port), controller, port


def _new(service, kind, title, values=None, protected=None):
    return service.save(None, kind, {"title": title, "tags": ["t"], "favorite": False,
                                     "values": values or {}, "protected": protected or {}, "clear": []})["ref"]


def test_schema_covers_every_typed_kind_and_protected_flags(env):
    service, _controller, _port = env
    schema = {k["kind"]: k for k in service.schema()["kinds"]}
    assert set(schema) == set(ITEM_KINDS) - {"web", "desktop"}
    for kind, protected in PROTECTED_FIELDS_BY_KIND.items():
        if kind in ("note", "bookmark", "identity"):
            continue
        flagged = {f["name"] for f in schema[kind]["fields"] if f["protected"]}
        assert flagged <= set(protected), kind
        assert flagged, kind
    card = {f["name"]: f for f in schema["card"]["fields"]}
    assert card["number"]["label"] == "Card number (Luhn-checked; brand is detected)"
    assert schema["card"]["note"].startswith("Card details are stored encrypted.")


def test_secret_kinds_never_return_protected_values(env):
    service, _controller, _port = env
    refs = {
        "card": _new(service, "card", "Visa", {"cardholder": "Ann", "expiry": "12/30"},
                     {"number": CARD_NUMBER, "cvv": "123", "pin": "4321"}),
        "api_key": _new(service, "api_key", "API", {"service": "svc"}, {"key": "KEY-SECRET-1", "secret": "SEC-2"}),
        "wifi": _new(service, "wifi", "Home", {"ssid": "home", "security": "wpa2"}, {"password": "wifi-pass-123"}),
        "license": _new(service, "license", "App", {"product": "App"}, {"license_value": "LIC-AAAA-BBBB"}),
    }
    blob = json.dumps([service.detail(r) for r in refs.values()] + [service.open_edit(r) for r in refs.values()])
    for secret in (CARD_NUMBER, "123", "4321", "KEY-SECRET-1", "SEC-2", "wifi-pass-123", "LIC-AAAA-BBBB"):
        assert f'"{secret}"' not in blob
    card = service.detail(refs["card"])
    number = next(f for f in card["fields"] if f["name"] == "number")
    assert number == {"name": "number", "label": "Card number",
                      "value": None, "protected": True, "present": True}


def test_update_keeps_protected_values_not_given_and_clears_on_request(env):
    service, controller, _port = env
    ref = _new(service, "api_key", "API", {"service": "svc"}, {"key": "KEY-1", "secret": "SEC-1"})
    edit = service.open_edit(ref)
    assert edit["protected_present"] == {"key": True, "secret": True}
    service.save(ref, "api_key", {"title": "API 2", "tags": [], "favorite": True, "values": {"service": "svc2"},
                                  "protected": {}, "clear": ["secret"], "revision": edit["revision"]})
    item = controller.session.item_service.get_item(ref["id"], include_protected=True)
    assert item["payload"]["key"] == "KEY-1" and not item["payload"].get("secret")
    assert item["title"] == "API 2" and item["favorite"] is True


def test_revision_conflict_is_changed(env):
    service, controller, _port = env
    ref = _new(service, "wifi", "Home", {"ssid": "home", "security": "wpa2"}, {"password": "wifi-pass-123"})
    edit = service.open_edit(ref)
    controller.session.item_service.update_typed_item(ref["id"], title="Elsewhere")
    with pytest.raises(ApiError) as changed:
        service.save(ref, "wifi", {"title": "Mine", "tags": [], "favorite": False, "values": {"ssid": "home"},
                                   "protected": {}, "clear": [], "revision": edit["revision"]})
    assert changed.value.code == "changed"


def test_invalid_card_number_uses_vault_message(env):
    service, _controller, _port = env
    with pytest.raises(ApiError) as invalid:
        _new(service, "card", "Bad", {}, {"number": "4111111111111112"})
    assert invalid.value.code == "invalid" and "checksum" in invalid.value.message


def test_bookmark_values_shown_and_note_body_hidden(env):
    service, _controller, _port = env
    note = _new(service, "note", "Router", {"body": "wifi codes inside"})
    bookmark = _new(service, "bookmark", "Docs", {"url": "https://docs.test/", "notes": "n"})
    body = next(f for f in service.detail(note)["fields"] if f["name"] == "body")
    assert body == {"name": "body", "label": "Note body", "value": None, "protected": True, "present": True}
    assert "wifi codes" not in json.dumps(service.detail(note))
    assert {f["name"]: f["value"] for f in service.detail(bookmark)["fields"]}["url"] == "https://docs.test/"


def test_note_body_reveal_copy_and_edit_need_the_master_password(env):
    service, controller, port = env
    note = _new(service, "note", "Router", {"body": "wifi codes inside"})
    for action in (lambda: service.reveal(note, "body"), lambda: service.copy(note, "body"),
                   lambda: service.open_edit(note)):
        with pytest.raises(ApiError) as cancelled:
            action()
        assert cancelled.value.code == "cancelled"
    port.passwords = ["wrong password"]
    with pytest.raises(ApiError) as wrong:
        service.reveal(note, "body")
    assert wrong.value.code == "not_authorized"
    port.passwords = [MASTER, MASTER, MASTER]
    assert service.reveal(note, "body")["value"] == "wifi codes inside"
    service.copy(note, "body")
    assert controller.clipboard.value == "wifi codes inside"
    assert service.open_edit(note)["values"]["body"] == "wifi codes inside"


def test_reveal_and_copy_need_reauth(env):
    service, controller, port = env
    ref = _new(service, "card", "Visa", {}, {"number": CARD_NUMBER})
    with pytest.raises(ApiError):
        service.reveal(ref, "number")
    assert port.asked[-1] == "Confirm to reveal number"
    port.passwords = [MASTER]
    assert service.reveal(ref, "number") == {"value": CARD_NUMBER, "mask_after": 30}
    assert service.copy(ref, "number")["message"].startswith("Number copied.")  # inside the 120 s grace
    assert controller.clipboard.value == CARD_NUMBER


def test_license_reveal_needs_reauth_too(env):
    service, _controller, port = env
    ref = _new(service, "license", "App", {"product": "App"}, {"license_value": "LIC-AAAA-BBBB"})
    port.passwords = [MASTER]
    assert service.reveal(ref, "license_value")["value"] == "LIC-AAAA-BBBB"
    assert port.asked == ["Confirm to reveal license_value"]


def test_item_limit_calls_upgrade(env):
    service, controller, port = env
    controller.session.item_limit = 0
    with pytest.raises(ApiError) as full:
        _new(service, "note", "x", {"body": "y"})
    assert full.value.code == "item_limit" and port.upgrades == [0]


def _wifi(service, security, **extra):
    return _new(service, "wifi", "Home", {"ssid": "my;net", "security": security, **extra}, {"password": "wifi-pass-123"})


def test_wifi_qr_returns_png(env):
    import base64

    service, _controller, port = env
    ref = _wifi(service, "wpa2")
    port.passwords = [MASTER]
    result = service.wifi_qr(ref)
    assert result["ssid"] == "my;net"
    assert result["png_data_url"].startswith("data:image/png;base64,")
    assert base64.b64decode(result["png_data_url"].split(",", 1)[1]).startswith(b"\x89PNG")
    assert "wifi-pass-123" not in json.dumps(result)


def test_wifi_qr_enterprise_not_supported(env):
    service, _controller, port = env
    ref = _wifi(service, "wpa2-enterprise")
    with pytest.raises(ApiError) as err:
        service.wifi_qr(ref)
    assert err.value.code == "not_supported"
    assert port.asked == []  # nothing released, so no prompt


def test_wifi_qr_respects_strict_reveal(env):
    service, _controller, port = env
    ref = _wifi(service, "wpa2")
    with pytest.raises(ApiError):  # no master password given: the same gate as revealing the password
        service.wifi_qr(ref)
    assert port.asked[-1] == "Confirm to reveal password"
    note = _new(service, "note", "n", {"body": "x"})
    with pytest.raises(ApiError):
        service.wifi_qr(note)


def test_wifi_qr_defaults_to_wpa2_when_security_missing(env):
    service, _controller, port = env
    ref = _new(service, "wifi", "Home", {"ssid": "home"}, {"password": "wifi-pass-123"})
    with pytest.raises(ApiError):  # still behind the reveal gate
        service.wifi_qr(ref)
    port.passwords = [MASTER]
    assert service.wifi_qr(ref)["png_data_url"].startswith("data:image/png;base64,")


def _jwt(exp=None):
    import base64

    def part(obj):
        return base64.urlsafe_b64encode(json.dumps(obj).encode()).rstrip(b"=").decode()
    claims = {"iss": "https://idp.example", "sub": "svc-1", "aud": ["a", "b"], "iat": 1_700_000_000}
    if exp is not None:
        claims["exp"] = exp
    return f"{part({'alg': 'HS256', 'typ': 'JWT'})}.{part(claims)}.c2ln"


def test_typed_detail_token_only_after_reveal(env):
    service, _controller, port = env
    token = _jwt(exp=1_800_000_000)
    ref = _new(service, "api_key", "API", {"service": "svc"}, {"key": token, "secret": "plain-secret"})
    assert token not in json.dumps(service.detail(ref)) and "token" not in service.detail(ref)
    with pytest.raises(ApiError):
        service.reveal(ref, "key")
    assert port.asked[-1] == "Confirm to reveal key"
    port.passwords = [MASTER]
    revealed = service.reveal(ref, "key")
    assert revealed["value"] == token
    block = revealed["token"]
    assert (block["alg"], block["typ"], block["iss"], block["sub"], block["aud"]) == (
        "HS256", "JWT", "https://idp.example", "svc-1", ["a", "b"])
    assert block["expired"] is False and block["set_expiry_date"] != "" and len(block["exp"]) == 16
    # A value that is not a JWT, and a copy, carry no token.
    port.passwords = [MASTER]
    assert "token" not in service.reveal(ref, "secret")
    assert "token" not in service.copy(ref, "key")


def test_token_ignored_for_other_kinds(env):
    service, _controller, port = env
    ref = _new(service, "license", "L", {"product": "p"}, {"license_value": _jwt(exp=1_800_000_000)})
    port.passwords = [MASTER]
    assert "token" not in service.reveal(ref, "license_value")


def test_set_expiry_from_token(env):
    service, controller, port = env
    ref = _new(service, "api_key", "API", {"service": "svc"}, {"key": _jwt(exp=4_000_000_000)})
    port.passwords = [MASTER]
    date = service.reveal(ref, "key")["token"]["set_expiry_date"]
    assert len(date) == 10 and date[:4] in ("2095", "2096")
    edit = service.open_edit(ref)
    service.save(ref, "api_key", {"title": "API", "tags": [], "favorite": False,
                                  "values": {**edit["values"], "expires": date}, "protected": {}, "clear": [],
                                  "revision": edit["revision"]})
    item = controller.session.item_service.get_item(ref["id"], include_protected=True)
    assert item["payload"]["expires"] == date and item["payload"]["key"].count(".") == 2
    # Once the item has an expiry the action is no longer offered.
    port.passwords = [MASTER]
    assert service.reveal(ref, "key")["token"]["set_expiry_date"] == ""


def test_reveal_survives_dates_the_platform_cannot_format(env, monkeypatch):
    service, _controller, port = env
    token = _jwt(exp=1_800_000_000)
    ref = _new(service, "api_key", "API", {"service": "svc"}, {"key": token})
    port.passwords = [MASTER]

    class Broken:
        @staticmethod
        def fromtimestamp(_stamp):
            raise OSError("year out of range")

    monkeypatch.setattr("localvault.app.typed.datetime", Broken)
    result = service.reveal(ref, "key")
    assert result["value"] == token
    assert result["token"]["exp"] == "" and result["token"]["set_expiry_date"] == ""

