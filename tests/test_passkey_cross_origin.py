"""Passkey sign-in inside another site's frame (known limitation 4).

The extension's service worker reads the top-level origin from the browser's frame tree and sends it as
``top_origin`` (with ``publickey_get_allowed`` once the frame's permissions policy allows
``publickey-credentials-get``), bound into a five-element context. Only ``get`` may carry it. The rpId is
still checked against the frame's own origin, clientDataJSON carries ``crossOrigin: true`` and ``topOrigin``,
and the dialog names both sites. Same-origin and top-level requests keep today's bytes.
"""
from __future__ import annotations

import hashlib
import json
import threading
import time
from types import SimpleNamespace

import pytest
from broker_host import BrokerHostBase as RuntimeActions
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from localvault import i18n
from localvault.browser_broker import BrowserBroker
from localvault.passkey_dialog import dialog_text
from localvault.passkeys import b64u_decode, b64u_encode, client_data_json
from localvault.session_guard import SessionGuard
from localvault.settings import AppSettings
from localvault.vault import create_vault
from localvault.web.ui_port import WebUiPort

KDF = {"time_cost": 1, "memory_cost_kib": 8192, "parallelism": 1, "hash_len": 32}
FRAME = "https://pay.example.test"
TOP = "https://shop.example"
OTHER_TOP = "https://news.example"
ACCOUNT = {"id": "item-1", "title": "Example (ada)", "user_name": "ada"}


def _context(origin: str, top: str | None = None, operation: str = "pk-op-1") -> str:
    value = [17, "document-redacted", origin, operation] + ([top] if top is not None else [])
    return json.dumps(value, separators=(",", ":"))


class _Broker(RuntimeActions, BrowserBroker):
    def __init__(self, session) -> None:
        self.session = session
        self.guard = SessionGuard("redacted-profile")
        self.guard.open(3600)
        self.root = None
        self.settings = AppSettings(auto_lock_seconds=0)
        self.active_profile = SimpleNamespace(id="redacted-profile", name="Redacted", color="#123456")
        self._remote_busy = False
        self.last_extension_seen = 0.0
        self.last_extension_version = ""
        self.last_secret_use = 0.0
        self._closing = False
        self.prompts: list[dict] = []
        self.answer: tuple[str, str | None] = ("approve", None)

    def run_on_ui(self, function, timeout=0):
        return function()

    def refresh_entries(self):
        return None

    def _touch_secret(self):
        self.last_secret_use = 1.0

    def _passkey_schedule(self, delay):  # no timer threads in tests
        return None

    def passkey_prompt(self, mode, *, origin, rp_id, accounts, excluded, **extra):
        self.prompts.append({"mode": mode, "origin": origin, "rp_id": rp_id, "accounts": accounts,
                             "excluded": excluded, **extra})
        if mode == "create":
            return ("approve", None)
        return ("approve", accounts[0]["id"]) if self.answer == ("approve", None) else self.answer

    def reauthenticate(self, title, lease, *, allow_hello=False, fresh=False):
        return True

    def request(self, action: str, *, origin: str = FRAME, context: str | None = None, **payload):
        return self.dispatch_remote({
            "action": action, "protocol": 2, "passkey_protocol": 1, "extension_version": "0.4.0",
            "origin": origin, "context": context if context is not None else _context(origin),
            "user_activation": True, **payload,
        })


def _broker(tmp_path) -> _Broker:
    return _Broker(create_vault(tmp_path / "pk.json", "passkey cross-origin master", kdf_overrides=KDF))


def _create_options(rp_id: str = "example.test"):
    return {"rp": {"id": rp_id, "name": "Example"},
            "user": {"id": b64u_encode(b"user-1"), "name": "ada", "displayName": "Ada"},
            "challenge": b64u_encode(b"c" * 32), "pubKeyCredParams": [{"type": "public-key", "alg": -7}]}


def _get_options(rp_id: str = "example.test"):
    return {"rpId": rp_id, "challenge": b64u_encode(b"g" * 32), "userVerification": "discouraged"}


def _register(broker: _Broker, origin: str = FRAME) -> dict:
    reply = broker.request("passkey_create_browser", origin=origin, options=_create_options())
    assert reply["ok"] is True, reply
    broker.prompts.clear()
    return reply["credential"]


def _cross_get(broker: _Broker, *, top: str = TOP, **overrides):
    payload = {"options": _get_options(), "top_origin": top, "publickey_get_allowed": True,
               "context": _context(FRAME, top)}
    payload.update(overrides)
    return broker.request("passkey_get_browser", **payload)


# -- clientDataJSON ---------------------------------------------------------------------------------------------

def test_client_data_json_cross_origin_exact_bytes() -> None:
    # WebAuthn L3 5.8.1.1: type, challenge, origin, crossOrigin, then topOrigin (only when cross-origin).
    assert client_data_json("webauthn.get", b"\x01" * 16, FRAME, top_origin=TOP) == (
        b'{"type":"webauthn.get","challenge":"AQEBAQEBAQEBAQEBAQEBAQ",'
        b'"origin":"https://pay.example.test","crossOrigin":true,"topOrigin":"https://shop.example"}')


def test_client_data_json_same_origin_bytes_unchanged() -> None:
    expected = (b'{"type":"webauthn.get","challenge":"AQEBAQEBAQEBAQEBAQEBAQ",'
                b'"origin":"https://example.com","crossOrigin":false}')
    assert client_data_json("webauthn.get", b"\x01" * 16, "https://example.com") == expected
    assert client_data_json("webauthn.get", b"\x01" * 16, "https://example.com", top_origin=None) == expected


@pytest.mark.parametrize("top", ["https://shop.example/path", "shop.example", "http://shop.example", "", "null",
                                 "https://SHOP.example"])
def test_client_data_json_refuses_a_top_origin_that_is_not_canonical(top) -> None:
    with pytest.raises(ValueError):
        client_data_json("webauthn.get", b"\x01" * 16, FRAME, top_origin=top)


def test_client_data_json_never_marks_a_create_cross_origin() -> None:
    with pytest.raises(ValueError):
        client_data_json("webauthn.create", b"\x01" * 16, FRAME, top_origin=TOP)


# -- broker --------------------------------------------------------------------------------------------------------

def test_cross_origin_get_signs_with_cross_origin_client_data(tmp_path) -> None:
    broker = _broker(tmp_path)
    created = _register(broker)
    reply = _cross_get(broker)
    assert reply["ok"] is True, reply
    assert broker.prompts[0]["mode"] == "get"
    assert broker.prompts[0]["origin"] == FRAME
    assert broker.prompts[0]["top_origin"] == TOP
    assertion = reply["credential"]
    client = b64u_decode(assertion["client_data_json"], max_bytes=4096)
    assert client == (b'{"type":"webauthn.get","challenge":"' + b64u_encode(b"g" * 32).encode()
                      + b'","origin":"https://pay.example.test","crossOrigin":true,"topOrigin":"https://shop.example"}')
    auth_data = b64u_decode(assertion["authenticator_data"], max_bytes=4096)
    assert auth_data[:32] == hashlib.sha256(b"example.test").digest(), "rpId hash of the frame's rpId"
    public_key = serialization.load_der_public_key(b64u_decode(created["public_key_spki"], max_bytes=4096))
    public_key.verify(b64u_decode(assertion["signature"], max_bytes=128),
                      auth_data + hashlib.sha256(client).digest(), ec.ECDSA(hashes.SHA256()))


def test_same_origin_get_keeps_todays_bytes_and_prompt(tmp_path) -> None:
    broker = _broker(tmp_path)
    _register(broker)
    reply = broker.request("passkey_get_browser", options=_get_options())
    assert reply["ok"] is True, reply
    assert "top_origin" not in broker.prompts[0], "the prompt call is unchanged for same-origin requests"
    client = b64u_decode(reply["credential"]["client_data_json"], max_bytes=4096)
    assert client == (b'{"type":"webauthn.get","challenge":"' + b64u_encode(b"g" * 32).encode()
                      + b'","origin":"https://pay.example.test","crossOrigin":false}')


def test_cross_origin_get_without_the_permission_flag_falls_back_unprompted(tmp_path) -> None:
    broker = _broker(tmp_path)
    _register(broker)
    for flag in (None, False, "true", 1):
        payload = {} if flag is None else {"publickey_get_allowed": flag}
        reply = broker.request("passkey_get_browser", options=_get_options(), top_origin=TOP,
                               context=_context(FRAME, TOP), **payload)
        assert reply == {"ok": False, "error": "fallback"}, flag
    assert broker.prompts == []


def test_a_top_origin_not_bound_into_the_context_is_refused(tmp_path) -> None:
    broker = _broker(tmp_path)
    _register(broker)
    cases = [
        {"context": _context(FRAME)},                              # four elements: no top site bound
        {"context": _context(FRAME, OTHER_TOP)},                   # bound to another top site
        {"top_origin": None, "context": _context(FRAME, TOP)},     # five elements without a top origin
        {"top_origin": "https://shop.example/", "context": _context(FRAME, "https://shop.example/")},
        {"top_origin": "null", "context": _context(FRAME, "null")},
        {"top_origin": 7, "context": _context(FRAME, TOP)},
    ]
    for case in cases:
        if case.get("top_origin", TOP) is None:
            reply = broker.request("passkey_get_browser", options=_get_options(), publickey_get_allowed=True,
                                   context=case["context"])
        else:
            reply = _cross_get(broker, **case)
        assert reply["ok"] is False and reply["error"] == "invalid_request", case
    assert broker.prompts == []


def test_only_get_may_come_from_a_cross_origin_frame(tmp_path) -> None:
    broker = _broker(tmp_path)
    for action, extra in (("passkey_create_browser", {"options": _create_options()}),
                          ("passkey_confirm_browser", {}), ("passkey_discard_browser", {})):
        reply = broker.request(action, top_origin=TOP, publickey_get_allowed=True, context=_context(FRAME, TOP),
                               **extra)
        assert reply["ok"] is False and reply["error"] == "invalid_request", action
    assert broker.prompts == []
    assert broker.session.item_service.passkey_records("example.test") == []


def test_rp_id_is_checked_against_the_frame_not_the_top_site(tmp_path) -> None:
    broker = _broker(tmp_path)
    # The rpId is a registrable suffix of the top site, not of the frame: refused before any prompt.
    top = "https://www.shop.example"
    reply = _cross_get(broker, top=top, context=_context(FRAME, top), options=_get_options(rp_id="shop.example"))
    assert reply == {"ok": False, "error": "security_error"}
    assert broker.prompts == []


def test_two_top_sites_give_two_contexts(tmp_path) -> None:
    broker = _broker(tmp_path)
    _register(broker)
    first = _cross_get(broker, top=TOP)
    second = _cross_get(broker, top=OTHER_TOP, context=_context(FRAME, OTHER_TOP))
    assert first["ok"] is True and second["ok"] is True
    assert [p["top_origin"] for p in broker.prompts] == [TOP, OTHER_TOP]
    assert _context(FRAME, TOP) != _context(FRAME, OTHER_TOP)
    tops = [json.loads(b64u_decode(r["credential"]["client_data_json"], max_bytes=4096))["topOrigin"]
            for r in (first, second)]
    assert tops == [TOP, OTHER_TOP]


# -- dialog --------------------------------------------------------------------------------------------------------

def test_dialog_names_the_frame_site_and_the_top_site() -> None:
    previous = i18n.current()
    try:
        i18n.set_language("en")
        text = dialog_text("get", origin=FRAME, rp_id="example.test", profile_name="Work", accounts=[ACCOUNT],
                           excluded=False, top_origin=TOP)
    finally:
        i18n.set_language(previous)
    lines = text["body"].split("\n")
    assert f"Page: {FRAME}" in lines
    assert f"{FRAME} is shown inside {TOP}, the site in the address bar." in lines
    same = dialog_text("get", origin=FRAME, rp_id="example.test", profile_name="Work", accounts=[ACCOUNT],
                       excluded=False)
    assert TOP not in same["body"] and "shown inside" not in same["body"]
    assert same["body"] == dialog_text("get", origin=FRAME, rp_id="example.test", profile_name="Work",
                                       accounts=[ACCOUNT], excluded=False, top_origin=None)["body"]


def test_every_catalog_translates_the_shown_inside_line() -> None:
    english = i18n._load("en")["passkeyModal.shownInside"]
    for code in (*i18n.SUPPORTED, i18n.PSEUDO):
        value = json.loads((i18n.CATALOG_DIR / f"{code}.json").read_text(encoding="utf-8"))["passkeyModal.shownInside"]
        assert "{page}" in value and "{top}" in value, code
        assert "\n" not in value, code
        if code != "en":
            assert value != english, f"{code} is an English copy"


def test_dialog_text_in_another_language_names_both_sites() -> None:
    previous = i18n.current()
    try:
        i18n.set_language("de")
        text = dialog_text("get", origin=FRAME, rp_id="example.test", profile_name="Work", accounts=[ACCOUNT],
                           excluded=False, top_origin=TOP)
    finally:
        i18n.set_language(previous)
    line = next(line for line in text["body"].split("\n") if TOP in line)
    assert FRAME in line


def test_web_ui_port_shows_the_shown_inside_line() -> None:
    class Bus:
        def __init__(self) -> None:
            self.events: list[tuple[str, dict]] = []

        def emit(self, name, detail):
            self.events.append((name, detail))

    bus = Bus()
    port = WebUiPort(bus, timeout=5)
    box: dict = {}
    thread = threading.Thread(target=lambda: box.setdefault("v", port.ask_passkey(
        "get", origin=FRAME, rp_id="example.test", profile_name="P", accounts=[{"id": "i1"}], excluded=False,
        top_origin=TOP)))
    thread.start()
    deadline = time.monotonic() + 2
    while not bus.events and time.monotonic() < deadline:
        time.sleep(0.005)
    name, request = bus.events[-1]
    assert name == "modal.request" and request["kind"] == "passkey"
    assert TOP in request["text"]["body"] and FRAME in request["text"]["body"]
    port.answer(request["id"], {"choice": "cancel"})
    thread.join(2)
    assert box["v"] == ("cancel", None)


# -- review 2026-11-13 ---------------------------------------------------------------------------------------------

def test_an_agent_grant_is_never_used_by_a_framed_copy_of_the_site(tmp_path) -> None:
    broker = _broker(tmp_path)
    _register(broker)
    asked = []
    broker._agent_passkey_grant = lambda origin, candidates: asked.append(origin)  # type: ignore[method-assign]
    assert _cross_get(broker)["ok"] is True
    assert asked == [], "a grant approved for the site is not spent under another top site"
    broker.prompts.clear()
    assert broker.request("passkey_get_browser", options=_get_options())["ok"] is True
    assert asked == [FRAME], "the site's own page still uses it"


def test_a_dismissed_framed_get_cools_down_only_that_pairing(tmp_path) -> None:
    broker = _broker(tmp_path)
    _register(broker)
    broker.answer = ("cancel", None)
    assert _cross_get(broker) == {"ok": False, "error": "user_cancelled"}
    broker.answer = ("approve", None)
    broker.prompts.clear()
    assert _cross_get(broker) == {"ok": False, "error": "fallback"}, "the same pairing cools down"
    assert broker.prompts == []
    assert _cross_get(broker, top=OTHER_TOP)["ok"] is True, "another top site is not affected"
    assert broker.request("passkey_get_browser", options=_get_options())["ok"] is True, (
        "a page of the site itself is not affected")
