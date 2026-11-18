"""Write the shared feature-pack vectors (docs/superpowers/specs/2026-11-15-feature-pack-contract.md).

    .venv/Scripts/python.exe scripts/make_feature_pack_vectors.py [--check]

Inputs and expected results are written by hand below.  The script only computes what cannot be
typed by hand (row padding to exact byte sizes, digests, the Ed25519 signature, Python's normal
form) and refuses to write when the Python implementation disagrees with a hand-written result.
``tests/test_feature_pack_vectors.py`` runs it with ``--check`` (byte-for-byte).
"""
from __future__ import annotations

import base64
import copy
import json
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from localvault import access_policy, hygiene, import_undo, item_history, privacy_proof, travel  # noqa: E402
from localvault.sync.vault_bridge import normal_form  # noqa: E402
from localvault.updates import canonical_json  # noqa: E402

OUT = ROOT / "tests" / "vectors"
T0 = 1790000000  # same anchor as tests/vectors/sync
DAY = 86400


def dump(value: Any) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False) + "\n").encode("utf-8")


def sid(n: int) -> str:
    return f"00000000-0000-4000-8000-{n:012d}"


def uid(n: int) -> str:
    return f"10000000-0000-4000-8000-{n:012d}"


def col(n: int) -> str:
    return f"c0000000-0000-4000-8000-{n:012d}"


# --- history ---------------------------------------------------------------------------------

def _row(n: int, item: str, created_at: int, size: int | None = None) -> dict[str, Any]:
    row = {"snapshot_id": sid(n), "item_id": item, "ns": "entry", "created_at": created_at,
           "change_type": "update",
           "record": {"id": item, "kind": "web", "label": "Example", "username": "u", "password": "p",
                      "scope": {"origin": "https://example.com"}, "notes": ""}}
    if size is not None:
        pad = size - len(canonical_json(row))
        assert pad >= 0
        row["record"]["notes"] = "x" * pad
        assert len(canonical_json(row)) == size
    return row


def history_prune() -> dict[str, Any]:
    a, b, x = uid(1), uid(2), uid(3)
    big = {"max_versions": 30, "max_age_days": 365, "max_bytes": 1_000_000}
    cases = [
        {"name": "age cut: older than max_age_days dropped, exactly at the cut kept",
         "now": T0, "limits": {"max_versions": 5, "max_age_days": 30, "max_bytes": 1_000_000},
         "rows": [_row(1, a, T0 - 30 * DAY - 1), _row(2, a, T0 - 30 * DAY), _row(3, a, T0 - DAY)],
         "expected_ids": [sid(2), sid(3)]},
        {"name": "per-item cap with equal created_at: tie broken by snapshot_id ascending",
         "now": T0, "limits": {"max_versions": 2, "max_age_days": 30, "max_bytes": 1_000_000},
         "rows": [_row(13, a, T0 - 100), _row(11, a, T0 - 100), _row(12, a, T0 - 100), _row(14, b, T0 - 500)],
         "expected_ids": [sid(11), sid(12), sid(14)]},
        {"name": "byte cap drops the globally oldest rows across items (each row is 600 bytes)",
         "now": T0, "limits": {"max_versions": 5, "max_age_days": 30, "max_bytes": 2048},
         "rows": [_row(21, a, T0 - 10, 600), _row(22, b, T0 - 20, 600), _row(23, b, T0 - 30, 600),
                  _row(24, a, T0 - 40, 600), _row(25, b, T0 - 50, 600)],
         "expected_ids": [sid(21), sid(22), sid(23)]},
    ]
    same = [_row(30 + n, x, T0 - n * DAY) for n in range(1, 9)] + [_row(40, x, T0 - 100 * DAY)]
    cases.append({"name": "Free limits on 9 versions (8 recent, 1 at 100 days)", "now": T0,
                  "limits": dict(item_history.FREE_LIMITS, max_bytes=8 * 1024 * 1024), "rows": same,
                  "expected_ids": [sid(31), sid(32), sid(33), sid(34), sid(35)]})
    cases.append({"name": "Pro limits on the same rows", "now": T0,
                  "limits": dict(item_history.PRO_LIMITS, max_bytes=8 * 1024 * 1024), "rows": copy.deepcopy(same),
                  "expected_ids": [sid(n) for n in range(31, 39)] + [sid(40)]})
    for case in cases:
        got = [r["snapshot_id"] for r in item_history.prune(case["rows"], case["now"], case["limits"])]
        assert got == case["expected_ids"], (case["name"], got)
    del big
    return {"cases": cases}


def _login(**extra: Any) -> dict[str, Any]:
    rec = {"id": uid(100), "kind": "web", "label": "Example", "username": "alice@example.com",
           "password": "correct-horse-1", "scope": {"origin": "https://example.com"},
           "created_at": T0 - 1000, "updated_at": T0 - 500}
    rec.update(extra)
    return rec


def _card(number: str, **extra: Any) -> dict[str, Any]:
    payload = {"cardholder": "A Person", "number": number, "brand": "visa", "last4": number[-4:],
               "expiry": "12/27", "cvv": "123", "pin": "", "billing_address_id": "", "notes": "",
               "template_id": ""}
    payload.update(extra.pop("payload", {}))
    rec = {"id": uid(200), "kind": "card", "title": "Visa", "created_at": T0 - 1000, "updated_at": T0 - 500,
           "revision": 3, "favorite": False, "tags": [], "collection_ids": [], "payload": payload}
    rec.update(extra)
    return rec


def history_diff() -> dict[str, Any]:
    p = "[protected]"
    cases = [
        {"name": "login password and tag change, password masked", "kind": "web", "reveal": False,
         "before": _login(tags=["Work"]), "after": _login(password="new-pass-2", tags=["Work", "Bank"], updated_at=T0),
         "expected": [{"field": "password", "before": p, "after": p, "secret": True},
                      {"field": "tags", "before": ["Work"], "after": ["Work", "Bank"], "secret": False}]},
        {"name": "same change revealed", "kind": "web", "reveal": True,
         "before": _login(tags=["Work"]), "after": _login(password="new-pass-2", tags=["Work", "Bank"], updated_at=T0),
         "expected": [{"field": "password", "before": "correct-horse-1", "after": "new-pass-2", "secret": True},
                      {"field": "tags", "before": ["Work"], "after": ["Work", "Bank"], "secret": False}]},
        {"name": "card number masked, last4 shown", "kind": "card", "reveal": False,
         "before": _card("4111111111111111"), "after": _card("5555555555554444", payload={"brand": "mastercard"}),
         "expected": [{"field": "payload.brand", "before": "visa", "after": "mastercard", "secret": False},
                      {"field": "payload.last4", "before": "1111", "after": "4444", "secret": False},
                      {"field": "payload.number", "before": p, "after": p, "secret": True}]},
        {"name": "a list (custom_fields) is one field", "kind": "web", "reveal": True,
         "before": _login(custom_fields=[{"name": "PIN", "value": "1234", "hidden": True}]),
         "after": _login(custom_fields=[{"name": "PIN", "value": "1234", "hidden": True},
                                        {"name": "Branch", "value": "Main", "hidden": False}]),
         "expected": [{"field": "custom_fields", "before": [{"hidden": True, "name": "PIN", "value": "1234"}],
                       "after": [{"hidden": True, "name": "PIN", "value": "1234"},
                                 {"hidden": False, "name": "Branch", "value": "Main"}], "secret": True}]},
        {"name": "ignored paths only: no difference", "kind": "web", "reveal": False,
         "before": _login(policy={"fill": "click", "sign_in": "inherit"}, site_icon="AAAA", revision=1,
                          password_history=[], scope={"origin": "https://example.com", "browser_approvals": {"x": 1}}),
         "after": _login(policy={"fill": "click", "sign_in": "never"}, site_icon="BBBB", revision=2, updated_at=T0,
                         password_history=[{"password": "old", "changed_at": T0}],
                         scope={"origin": "https://example.com", "browser_approvals": {"x": 2}}),
         "expected": []},
        {"name": "field added and removed: the missing side is null (also when secret)", "kind": "web",
         "reveal": False, "before": _login(favorite=True), "after": _login(notes="call first"),
         "expected": [{"field": "favorite", "before": True, "after": None, "secret": False},
                      {"field": "notes", "before": None, "after": p, "secret": True}]},
        {"name": "non-ASCII paths sort by code point (not UTF-16 units)", "kind": "web", "reveal": False,
         "before": _login(),
         "after": _login(scope={"origin": "https://example.com", "\U0001d49c": 1, "\ufb00": 2, "école": 3,
                                "zeta": 4, "Zed": 5}),
         "expected": [{"field": "scope.Zed", "before": None, "after": 5, "secret": False},
                      {"field": "scope.zeta", "before": None, "after": 4, "secret": False},
                      {"field": "scope.école", "before": None, "after": 3, "secret": False},
                      {"field": "scope.\ufb00", "before": None, "after": 2, "secret": False},
                      {"field": "scope.\U0001d49c", "before": None, "after": 1, "secret": False}]},
        {"name": "identity: every payload field is secret except template_id", "kind": "identity",
         "reveal": False,
         "before": {"id": uid(300), "kind": "identity", "title": "Me", "payload": {"first_name": "Ann", "template_id": "a"}},
         "after": {"id": uid(300), "kind": "identity", "title": "Me", "payload": {"first_name": "Anna", "template_id": "b"}},
         "expected": [{"field": "payload.first_name", "before": p, "after": p, "secret": True},
                      {"field": "payload.template_id", "before": "a", "after": "b", "secret": False}]},
    ]
    for case in cases:
        got = item_history.diff(case["before"], case["after"], case["kind"], reveal=case["reveal"])
        assert got == case["expected"], (case["name"], got)
    return {"cases": cases}


def history_restore() -> dict[str, Any]:
    old_rows = [{"password": f"older-{n}", "changed_at": T0 - n * DAY} for n in range(1, 6)]
    urls_now = [{"url": "https://example.com", "match": "exact_origin"},
                {"url": "https://login.example.com", "match": "exact_origin"}]
    urls_then = [{"url": "https://example.com", "match": "exact_origin"}]
    cases = [
        {"name": "restore username", "path": "username", "now": T0,
         "current": _login(username="new@example.com"), "snapshot": _login(username="alice@example.com"),
         "expected": _login(username="alice@example.com", updated_at=T0)},
        {"name": "restore password pushes the current one (write cap 5)", "path": "password", "now": T0,
         "current": _login(password="current-pass", password_history=old_rows),
         "snapshot": _login(password="restored-pass"),
         "expected": _login(password="restored-pass", updated_at=T0,
                            password_history=[{"password": "current-pass", "changed_at": T0}, *old_rows[:4]])},
        {"name": "restore the scope.urls list as a whole", "path": "scope.urls", "now": T0,
         "current": _login(scope={"origin": "https://example.com", "urls": urls_now}),
         "snapshot": _login(scope={"origin": "https://example.com", "urls": urls_then}),
         "expected": _login(scope={"origin": "https://example.com", "urls": urls_then}, updated_at=T0)},
        {"name": "created_at is not restorable", "path": "created_at", "now": T0,
         "current": _login(), "snapshot": _login(created_at=T0 - 9000), "error": "not_restorable"},
        {"name": "a snapshot value this device's normaliser rejects (Luhn)", "path": "payload.number", "now": T0,
         "current": _card("4111111111111111"), "snapshot": _card("4111111111111112"),
         "error": "invalid_on_this_device"},
    ]
    for case in cases:
        try:
            got = item_history.restore_field(case["current"], case["snapshot"], case["path"], case["now"])
        except item_history.RestoreError as exc:
            assert case.get("error") == exc.code, (case["name"], exc.code)
        else:
            assert "error" not in case and got == case["expected"], (case["name"], got)
    return {"cases": cases}


# --- travel ----------------------------------------------------------------------------------

def travel_visible() -> dict[str, Any]:
    c1, c2, unknown = col(1), col(2), col(9)

    def item(n: int, kind: str, tags: list[str] = (), collections: list[str] = ()) -> dict[str, Any]:
        return {"id": uid(400 + n), "kind": kind, "tags": list(tags), "collections": list(collections)}

    def on(cols: list[str] = (), tags: list[str] = ()) -> dict[str, Any]:
        return {"on": True, "collections": list(cols), "tags": list(tags), "since": T0}

    cases = [
        {"name": "off hides nothing", "setting": {"on": False, "collections": [c1], "tags": ["Bank"], "since": T0},
         "items": [item(1, "web", ["Bank"]), item(2, "card", [], [c1])], "expected_hidden": []},
        {"name": "login hidden by tag with different case and spaces", "setting": on(tags=["Bank"]),
         "items": [item(3, "web", ["  bANK "]), item(4, "web", ["Banking"])], "expected_hidden": [uid(403)]},
        {"name": "typed item hidden by collection", "setting": on(cols=[c1]),
         "items": [item(5, "note", [], [c1]), item(6, "note", [], [c2])], "expected_hidden": [uid(405)]},
        {"name": "a login row listing a collection is not hidden by it", "setting": on(cols=[c1]),
         "items": [item(7, "web", [], [c1]), item(8, "desktop", [], [c1])], "expected_hidden": []},
        {"name": "unknown collection id is ignored", "setting": on(cols=[unknown, c2]),
         "items": [item(9, "card", [], [c1]), item(10, "card", [], [c2])], "expected_hidden": [uid(410)]},
        {"name": "setting tags that are duplicates after fold", "setting": on(tags=["Work", " work"]),
         "items": [item(11, "web", ["WORK"]), item(12, "api_key", ["Home"])], "expected_hidden": [uid(411)]},
        {"name": "item in two collections, one hidden", "setting": on(cols=[c2]),
         "items": [item(13, "passkey", [], [c1, c2])], "expected_hidden": [uid(413)]},
    ]
    for case in cases:
        assert travel.hidden_ids(case["items"], case["setting"]) == case["expected_hidden"], case["name"]
    return {"cases": cases}


# --- hygiene ---------------------------------------------------------------------------------

def _web(n: int, origin: str, username: str, password: str = "pw-1", updated: int = T0 - 100, **extra: Any) -> dict:
    rec = {"id": uid(500 + n), "kind": "web", "label": f"Login {n}", "username": username, "password": password,
           "scope": {"origin": origin}, "created_at": T0 - 1000, "updated_at": updated}
    rec.update(extra)
    return rec


def _item(n: int, kind: str, title: str, payload: dict, updated: int = T0 - 100, **extra: Any) -> dict:
    rec = {"id": uid(600 + n), "kind": kind, "title": title, "created_at": T0 - 1000, "updated_at": updated,
           "revision": 1, "favorite": False, "tags": [], "collection_ids": [], "payload": payload}
    rec.update(extra)
    return rec


def hygiene_duplicates() -> dict[str, Any]:
    today = "2026-11-15"
    cases = [
        {"name": "same login: usernames differ only in case and spaces (newest first)",
         "records": [_web(1, "https://example.com", "Alice@Example.com", updated=T0 - 50),
                     _web(2, "https://example.com", " alice@example.com", updated=T0 - 10)],
         "expected": [{"type": "same_login", "ids": [uid(502), uid(501)]}]},
        {"name": "same account, different passwords",
         "records": [_web(3, "https://example.com", "bob", "pw-a"), _web(4, "https://example.com", "BOB", "pw-b")],
         "expected": [{"type": "same_account_other_password", "ids": [uid(503), uid(504)]}]},
        {"name": "www. and apex are the same site",
         "records": [_web(5, "https://www.example.com", "carol"), _web(6, "https://example.com", "carol")],
         "expected": [{"type": "same_site", "ids": [uid(505), uid(506)]}]},
        {"name": "example.co.uk subdomains share a site; other.co.uk does not",
         "records": [_web(7, "https://a.example.co.uk", "dan"), _web(8, "https://b.example.co.uk", "dan"),
                     _web(9, "https://other.co.uk", "dan")],
         "expected": [{"type": "same_site", "ids": [uid(507), uid(508)]}]},
        {"name": "github.io users are different sites",
         "records": [_web(10, "https://alice.github.io", "erin"), _web(11, "https://bob.github.io", "erin")],
         "expected": []},
        {"name": "http and https of one host are the same site",
         "records": [_web(12, "http://example.org", "fay"), _web(13, "https://example.org", "fay")],
         "expected": [{"type": "same_site", "ids": [uid(512), uid(513)]}]},
        {"name": "empty usernames never match as same site (same origin and password still is the same login)",
         "records": [_web(14, "https://www.example.net", ""), _web(15, "https://example.net", ""),
                     _web(16, "https://example.net", "")],
         "expected": [{"type": "same_login", "ids": [uid(515), uid(516)]}]},
        {"name": "passkeys by relying party (folded) and credential id",
         "records": [_item(1, "passkey", "Example", {"relying_party_id": "Example.com", "credential_id": "Y3JlZA"}),
                     _item(2, "passkey", "Example 2", {"relying_party_id": "example.com", "credential_id": "Y3JlZA"}),
                     _item(3, "passkey", "Example", {"relying_party_id": "example.com", "credential_id": "b3RoZXI"})],
         "expected": [{"type": "same_item", "ids": [uid(601), uid(602)]}]},
        {"name": "cards by number",
         "records": [_item(4, "card", "Visa", {"number": "4111111111111111", "notes": "a"}),
                     _item(5, "card", "Old visa", {"number": "4111111111111111", "notes": "b"}, updated=T0 - 5),
                     _item(6, "card", "Empty", {"number": ""}), _item(7, "card", "Empty 2", {"number": ""})],
         "expected": [{"type": "same_item", "ids": [uid(605), uid(604)]}]},
        {"name": "typed item equal except notes and title case",
         "records": [_item(8, "wifi", "Home WiFi", {"ssid": "home", "password": "pw", "notes": "router"}),
                     _item(9, "wifi", "home wifi ", {"ssid": "home", "password": "pw", "notes": ""}),
                     _item(10, "wifi", "Home WiFi", {"ssid": "home", "password": "other", "notes": ""})],
         "expected": [{"type": "same_item", "ids": [uid(608), uid(609)]}]},
        {"name": "desktop logins are skipped",
         "records": [{"id": uid(700), "kind": "desktop", "label": "App", "username": "u", "password": "p",
                      "scope": {"exe_path": "C:\\app.exe"}, "updated_at": T0 - 3 * 365 * DAY},
                     {"id": uid(701), "kind": "desktop", "label": "App", "username": "u", "password": "p",
                      "scope": {"exe_path": "C:\\app.exe"}, "updated_at": T0 - 3 * 365 * DAY}],
         "expected": []},
        {"name": "not changed in 2 years: strictly older than 730 days",
         "records": [_web(17, "https://one.example", "g", updated=T0 - 730 * DAY - 1),
                     _web(18, "https://two.example", "h", updated=T0 - 730 * DAY)],
         "expected": [{"type": "not_changed_2y", "ids": [uid(517)]}]},
    ]
    for case in cases:
        case["now"] = T0
        case["today"] = today
        got = hygiene.findings(case["records"], case["now"], case["today"])
        assert got == case["expected"], (case["name"], got)
    return {"cases": cases}


def hygiene_expired() -> dict[str, Any]:
    card = _item(20, "card", "Visa", {"number": "4111111111111111", "expiry": "12/26"})
    cases = [
        {"name": "card 12/26 is not expired on 2026-12-31", "today": "2026-12-31", "records": [card],
         "expected_ids": []},
        {"name": "card 12/26 is expired on 2027-01-01", "today": "2027-01-01", "records": [card],
         "expected_ids": [uid(620)]},
        {"name": "a 4-digit year (11/2026) reads as 2026-11", "today": "2026-12-01",
         "records": [_item(21, "card", "MC", {"number": "5555555555554444", "expiry": "11/2026"})],
         "expected_ids": [uid(621)]},
        {"name": "licence, API key (YYYYMMDD), week date skipped, inactive subscription skipped",
         "today": "2026-11-15",
         "records": [_item(22, "license", "Tool", {"expiration_date": "2026-11-14"}, updated=T0 - 1),
                     _item(23, "license", "Tool 2", {"expiration_date": "2026-11-15"}),
                     _item(24, "api_key", "Key", {"expires": "20261114"}, updated=T0 - 2),
                     _item(25, "warranty", "TV", {"expiration_date": "2026-W46-1"}),
                     _item(26, "subscription", "Old", {"expiration_date": "2020-01-01", "active": False}),
                     _item(27, "subscription", "Live", {"expiration_date": "2020-01-01", "active": True}, updated=T0 - 3),
                     _item(28, "purchase", "Phone", {"expiration_date": ""})],
         "expected_ids": [uid(622), uid(624), uid(627)]},
    ]
    for case in cases:
        case["now"] = T0
        got = [f["ids"] for f in hygiene.findings(case["records"], case["now"], case["today"]) if f["type"] == "expired"]
        assert (got[0] if got else []) == case["expected_ids"], (case["name"], got)
    return {"cases": cases}


def hygiene_merge() -> dict[str, Any]:
    hist = [{"password": f"old-{n}", "changed_at": T0 - n * DAY} for n in range(1, 6)]
    keeper = _web(30, "https://example.com", "ann", "keeper-pass", updated=T0 - 10, tags=["Work", "bank"],
                  password_history=hist, notes="Keeper notes", favorite=False,
                  recovery_codes=["a1", "b2"], custom_fields=[{"name": "PIN", "value": "1", "hidden": True}],
                  scope={"origin": "https://example.com", "urls": [{"url": "https://example.com", "match": "exact_origin"},
                                                                    {"url": "https://www.example.com", "match": "exact_origin"}],
                         "access": {"copy": "once"}},
                  policy={"fill": "click", "sign_in": "inherit", "require_master_password": False, "save_prompts": True})
    other = _web(31, "https://example.com", "ANN", "other-pass", updated=T0 - 20, tags=["work ", "Shopping"],
                 notes="Other notes", favorite=True, recovery_codes=["b2", "c3"],
                 totp={"secret": "JBSWY3DPEHPK3PXP", "algorithm": "SHA1", "digits": 6, "period": 30},
                 custom_fields=[{"name": "PIN", "value": "1", "hidden": True}, {"name": "Q", "value": "x", "hidden": False}],
                 scope={"origin": "https://example.com", "urls": [{"url": "https://www.example.com", "match": "exact_origin"},
                                                                   {"url": "https://m.example.com", "match": "exact_origin"}],
                        "access": {"phones": "view", "expires": "2027-03-31", "biometric_only": True}},
                 policy={"fill": "never", "require_master_password": True})
    expected = copy.deepcopy(keeper)
    expected.update(
        tags=["Work", "bank", "Shopping"], updated_at=T0, favorite=True, notes="Keeper notes\n\nOther notes",
        password_history=[{"password": "other-pass", "changed_at": T0}, *hist[:4]],
        recovery_codes=["a1", "b2", "c3"],
        custom_fields=[{"name": "PIN", "value": "1", "hidden": True}, {"name": "Q", "value": "x", "hidden": False}],
        totp=copy.deepcopy(other["totp"]),
        policy={"fill": "never", "sign_in": "inherit", "require_master_password": True, "save_prompts": True})
    expected["scope"] = {"origin": "https://example.com",
                         "urls": [{"url": "https://example.com", "match": "exact_origin"},
                                  {"url": "https://www.example.com", "match": "exact_origin"},
                                  {"url": "https://m.example.com", "match": "exact_origin"}],
                         "access": {"copy": "once", "phones": "view", "expires": "2027-03-31", "biometric_only": True}}
    card_keeper = _item(40, "card", "Visa", {"number": "4111111111111111", "notes": ""}, tags=["Cards"],
                        collection_ids=[col(1)])
    card_other = _item(41, "card", "Visa old", {"number": "4111111111111111", "notes": "PIN in safe"},
                       tags=["cards", "Travel"], collection_ids=[col(2), col(1)], favorite=True)
    card_expected = copy.deepcopy(card_keeper)
    card_expected.update(tags=["Cards", "Travel"], collection_ids=[col(1), col(2)], favorite=True, updated_at=T0,
                         payload={"number": "4111111111111111", "notes": "PIN in safe"})
    site_keeper = _web(36, "https://example.com", "dan", updated=T0 - 10)
    site_other = _web(37, "https://www.example.com", "Dan", updated=T0 - 20)
    site_expected = copy.deepcopy(site_keeper)
    site_expected.update(updated_at=T0, scope={"origin": "https://example.com", "urls": [
        {"url": "https://example.com", "match": "exact_origin"},
        {"url": "https://www.example.com", "match": "exact_origin"}]})
    rows_keeper = _web(50, "https://shop.example", "fay")
    rows_other = _web(51, "https://shop.example", "fay", scope={"origin": "https://shop.example", "urls": [
        {"url": "https://shop.example", "match": "exact_origin"},
        {"url": "https://shop.example", "match": "host"},
        {"url": "https://shop.example/login", "match": "starts_with"}]})
    rows_expected = copy.deepcopy(rows_keeper)
    rows_expected.update(updated_at=T0, scope={"origin": "https://shop.example", "urls": [
        {"url": "https://shop.example", "match": "exact_origin"},
        {"url": "https://shop.example", "match": "host"},
        {"url": "https://shop.example/login", "match": "starts_with"}]})
    cases = [
        {"name": "login merge: history at cap 5, tags folded, urls and lists unioned, notes appended, stricter rules",
         "keeper": keeper, "other": other, "now": T0, "expected": expected},
        {"name": "card merge: tags, notes and collections only", "keeper": card_keeper, "other": card_other,
         "now": T0, "expected": card_expected},
        {"name": "notes over 20 000 characters refuse", "now": T0,
         "keeper": _web(32, "https://example.com", "b", notes="k" * 15000),
         "other": _web(33, "https://example.com", "b", notes="o" * 5000), "error": "notes_too_long"},
        {"name": "more than 20 tags refuse", "now": T0,
         "keeper": _web(34, "https://example.com", "c", tags=[f"k{n}" for n in range(15)]),
         "other": _web(35, "https://example.com", "c", tags=[f"o{n}" for n in range(6)]), "error": "too_many_tags"},
        {"name": "same_site: legacy origins only, the other's origin becomes a url row (keeper's first)", "now": T0,
         "keeper": site_keeper, "other": site_other, "expected": site_expected},
        {"name": "same origin, no urls on either side: scope unchanged", "now": T0,
         "keeper": _web(38, "https://example.com", "e"), "other": _web(39, "https://example.com", "e", "pw-1"),
         "expected": dict(_web(38, "https://example.com", "e"), updated_at=T0)},
        {"name": "other's urls rows deduplicated by (url, match), legacy keeper gains its origin row first",
         "now": T0, "keeper": rows_keeper, "other": rows_other, "expected": rows_expected},
        {"name": "more than 20 url rows refuse", "now": T0,
         "keeper": _web(52, "https://a.example", "g", scope={"origin": "https://a.example", "urls": [
             {"url": f"https://a{n}.example", "match": "exact_origin"} for n in range(12)]}),
         "other": _web(53, "https://b.example", "g", scope={"origin": "https://b.example", "urls": [
             {"url": f"https://b{n}.example", "match": "exact_origin"} for n in range(9)]}),
         "error": "too_many_values"},
    ]
    for case in cases:
        try:
            got = hygiene.merge(case["keeper"], case["other"], case["now"])
        except hygiene.MergeRefused as exc:
            assert case.get("error") == exc.code, (case["name"], exc.code)
        else:
            assert "error" not in case and got == case["expected"], (case["name"], got)
    return {"cases": cases}


# --- access ----------------------------------------------------------------------------------

def access_effective() -> dict[str, Any]:
    def rec(access: Any = None, policy: dict | None = None) -> dict[str, Any]:
        scope: dict[str, Any] = {"origin": "https://bank.example"}
        if access is not None:
            scope["access"] = access
        out: dict[str, Any] = {"id": uid(800), "kind": "web", "label": "Bank", "username": "u", "password": "p",
                               "scope": scope}
        if policy is not None:
            out["policy"] = policy
        return out

    def exp(reauth=False, autofill=True, copy_once=False, phone_view=False, expired=False) -> dict[str, bool]:
        return {"reauth": reauth, "autofill": autofill, "copy_once": copy_once, "phone_view": phone_view,
                "expired": expired}

    all_on = exp(True, False, True, True, False)
    today = "2026-11-15"
    cases = [
        ("no access", rec(), "phone", exp()),
        ("copy once", rec({"copy": "once"}), "computer", exp(copy_once=True)),
        ("view only on phones, on a phone", rec({"phones": "view"}), "phone", exp(autofill=False, phone_view=True)),
        ("view only on phones, on a computer", rec({"phones": "view"}), "computer", exp(phone_view=True)),
        ("expires tomorrow", rec({"expires": "2026-11-16"}), "computer", exp()),
        ("expires today", rec({"expires": "2026-11-15"}), "computer", exp(reauth=True, autofill=False, expired=True)),
        ("expired yesterday", rec({"expires": "2026-11-14"}), "phone", exp(reauth=True, autofill=False, expired=True)),
        ("unknown copy value is once", rec({"copy": "twice"}), "computer", exp(copy_once=True)),
        ("unknown key: every rule on", rec({"copy": "normal", "biometric_only": True}), "computer", all_on),
        ("malformed date is expired now", rec({"expires": "2027-02-30"}), "computer",
         exp(reauth=True, autofill=False, expired=True)),
        ("YYYYMMDD is not accepted here", rec({"expires": "20271231"}), "computer",
         exp(reauth=True, autofill=False, expired=True)),
        ("access not an object: every rule on", rec("x"), "phone", all_on),
        ("empty access object is no rule", rec({}), "phone", exp()),
        ("strict policy and phone view on a computer", rec({"phones": "view"}, {"require_master_password": True}),
         "computer", exp(reauth=True, phone_view=True)),
        ("fill never", rec(None, {"fill": "never"}), "computer", exp(autofill=False)),
    ]
    out = []
    for name, record, device, expected in cases:
        assert access_policy.effective(record, device, today) == expected, name
        out.append({"name": name, "record": record, "device_class": device, "today": today, "expected": expected})
    return {"cases": out}


def access_preserve() -> dict[str, Any]:
    entry = {"id": uid(801), "kind": "web", "label": "Bänk ✓", "username": "zoë", "password": "p@ss",
             "scope": {"origin": "https://bank.example",
                       "access": {"copy": "once", "expires": "2027-03-31", "biometric_only": "Ünïcødé ✓ 日本",
                                  "nested": {"z": [1, 2], "a": None}},
                       "ai_agents": True, "browser_approvals": {"x": 1}},
             "site_icon": "iVBORw0KGgo=", "created_at": T0 - 100, "updated_at": T0, "tags": ["Bank"]}
    normal = normal_form("entry", entry)
    assert canonical_json(normal["scope"]["access"]) == canonical_json(entry["scope"]["access"])
    return {"cases": [{"name": "scope.access with an unknown key and non-ASCII text survives the sync normaliser",
                       "input_entry": entry, "expected_normal_form": normal}]}


def access_stricter() -> dict[str, Any]:
    cases = [
        ("two expiry dates: the earlier wins", {"expires": "2027-03-31"}, {"expires": "2026-12-01"},
         {"expires": "2026-12-01"}),
        ("one side absent", None, {"phones": "view"}, {"phones": "view"}),
        ("both absent", None, None, None),
        ("per key the stricter value", {"copy": "once", "phones": "full"}, {"copy": "normal", "phones": "view"},
         {"copy": "once", "phones": "view"}),
        ("unknown key kept", {"copy": "once"}, {"biometric_only": True}, {"copy": "once", "biometric_only": True}),
        ("unknown value kept (it reads as the strict one)", {"copy": "normal"}, {"copy": "twice"}, {"copy": "twice"}),
        ("malformed date wins (it reads as expired)", {"expires": "2026-01-01"}, {"expires": "soon"},
         {"expires": "soon"}),
        ("access that is not an object wins", {"copy": "once"}, "x", "x"),
        ("empty objects give nothing", {}, {}, None),
    ]
    out = []
    for name, a, b, expected in cases:
        assert access_policy.stricter_access(a, b) == expected, name
        out.append({"name": name, "a": a, "b": b, "expected": expected})
    return {"cases": out}


# --- privacy proof ---------------------------------------------------------------------------

def _device_a() -> dict[str, Any]:
    ids = json.loads((OUT / "sync" / "identities.json").read_text(encoding="utf-8"))
    return ids["devices"]["A"]


def proof_document() -> dict[str, Any]:
    return {
        "format": "lgk-privacy-proof", "version": 2, "generated_at": "2026-11-15T10:00:00Z",
        "app": {"platform": "windows", "version": "0.5.0"},
        "facts": {"sync": "folder", "devices": 2, "shares": 0, "items": 120, "breach_checks": False,
                  "strict_offline": True, "update_check": True},
        "claims": ["connections_listed", "no_item_content_sent"],
        "network": {"available": True, "since": "2026-11-01T08:00:00Z",
                    "entries": [{"purpose": "update_check", "host": "example.invalid", "result": "ok",
                                 "at": "2026-11-14T09:30:00Z"}],
                    "counts": {"website_icon": 14, "lan_sync": 30}},
        "signature": None,
    }


def privacy_files() -> dict[str, bytes]:
    from cryptography.hazmat.primitives.asymmetric import ed25519

    device = _device_a()
    private = base64.b64decode(device["private"]["signing_private"])
    doc = proof_document()
    signed = privacy_proof.sign(doc, private, device["device_id"])
    public = base64.b64decode(device["signing_public_b64"])
    assert signed["signature"]["public_key"] == device["signing_public_b64"]
    fp = privacy_proof.fingerprint(public)
    assert privacy_proof.verify_document(signed) == {"result": "valid", "device_id": device["device_id"],
                                                     "fingerprint": fp, "reason": ""}
    unsigned_doc = {k: v for k, v in doc.items() if k != "signature"}
    signed_body = copy.deepcopy(signed)
    del signed_body["signature"]["value"]
    files = {
        "signed.json": dump({
            "device": "A (tests/vectors/sync/identities.json)", "device_id": device["device_id"],
            "unsigned_document": unsigned_doc,
            "signed_body": signed_body,
            "signed_bytes_hex": privacy_proof.signed_bytes(signed).hex(),
            "signature": signed["signature"], "fingerprint": fp,
            "signed_document": signed, "expected_result": "valid"}),
        "unsigned.json": dump({"document": doc, "expected_result": "unsigned"}),
    }
    assert privacy_proof.signed_bytes(signed) == privacy_proof.SIGN_PREFIX + canonical_json(signed_body)
    key = ed25519.Ed25519PrivateKey.from_private_bytes(private)

    def resign(document: dict[str, Any], prefix: bytes = privacy_proof.SIGN_PREFIX, cover_key: bool = True,
               device_id: str = device["device_id"]) -> dict[str, Any]:
        body = {k: copy.deepcopy(v) for k, v in document.items() if k != "signature"}
        meta = {"alg": "Ed25519", "device_id": device_id, "public_key": device["signing_public_b64"]}
        message = prefix + canonical_json(dict(body, signature=meta) if cover_key else body)
        return dict(body, signature=dict(meta, value=base64.b64encode(key.sign(message)).decode("ascii")))

    tampered = copy.deepcopy(signed)
    tampered["facts"]["items"] = 121
    wrong_prefix = resign(doc, b"")
    extra = copy.deepcopy(doc)
    extra["note"] = "added"
    extra = resign(extra)
    v1 = copy.deepcopy(doc)
    v1["version"] = 1
    v1 = resign(v1, b"localgatekeys|privacy-proof|v1|", cover_key=False)
    v3 = copy.deepcopy(doc)
    v3["version"] = 3
    v3 = resign(v3)
    device_changed = copy.deepcopy(signed)
    device_changed["signature"]["device_id"] = "ffffffff-ffff-4fff-8fff-ffffffffffff"
    key_fields_unsigned = resign(doc, cover_key=False)
    text = json.dumps(signed, indent=2, sort_keys=True, ensure_ascii=False)
    duplicate = text.replace('"version": 2', '"version": 2,\n  "version": 2', 1) + "\n"
    assert duplicate.count('"version": 2') == 2
    rejected = {"tampered_fact.json": dump(tampered), "wrong_prefix.json": dump(wrong_prefix),
                "duplicate_key.json": duplicate.encode("utf-8"), "extra_top_key.json": dump(extra),
                "version_1.json": dump(v1), "version_3.json": dump(v3),
                "device_id_changed.json": dump(device_changed),
                "key_fields_unsigned.json": dump(key_fields_unsigned)}
    for name, data in rejected.items():
        assert privacy_proof.verify_bytes(data)["result"] == "invalid", name
        files["rejected/" + name] = data
    return files


# --- import undo -----------------------------------------------------------------------------

def import_undo_vector() -> dict[str, Any]:
    pre = _web(40, "https://keep.example", "pre")
    r1_before = _web(41, "https://r1.example", "r1", "before-1", updated=T0 - 900)
    r2_before = _web(42, "https://r2.example", "r2", "before-2", updated=T0 - 900)
    before = [pre, r1_before, r2_before]
    c1 = _web(43, "https://c1.example", "c1", "imported-1", updated=T0 - 60)
    c2 = _web(44, "https://c2.example", "c2", "imported-2", updated=T0 - 60)
    r1_after = _web(41, "https://r1.example", "r1", "imported-r1", updated=T0 - 60)
    r2_after = _web(42, "https://r2.example", "r2", "imported-r2", updated=T0 - 60)
    after = [pre, r1_after, r2_after, c1, c2]
    journal = {"import_id": "20000000-0000-4000-8000-000000000001", "at": T0 - 60, "source": "bitwarden",
               "created": {c1["id"]: import_undo.digest(c1), c2["id"]: import_undo.digest(c2)},
               "replaced": {r1_after["id"]: {"before": r1_before, "after": import_undo.digest(r1_after)},
                            r2_after["id"]: {"before": r2_before, "after": import_undo.digest(r2_after)}}}
    c2_edited = copy.deepcopy(c2)
    c2_edited.update(password="edited-after-import", updated_at=T0 - 30)
    r2_edited = copy.deepcopy(r2_after)
    r2_edited.update(label="Renamed", updated_at=T0 - 30)
    current = [pre, r1_after, r2_edited, c1, c2_edited]
    r1_restored = copy.deepcopy(r1_before)
    r1_restored["updated_at"] = T0
    expected_after = [pre, r1_restored, r2_edited, c2_edited]
    result = import_undo.plan(journal, current, T0)
    assert result["records"] == expected_after
    assert result["kept"] == sorted([c2["id"], r2_after["id"]])
    assert result["trashed"] == [c1["id"]] and result["restored"] == [r1_after["id"]]
    return {"cases": [{
        "name": "created untouched (to Recently deleted), created then edited (kept), replaced untouched "
                "(restored), replaced then edited (kept)",
        "now": T0, "before_records": before, "after_records": after, "journal": journal,
        "current_records": current, "expected_after_undo": expected_after,
        "expected_trashed_ids": [c1["id"]], "expected_restored_ids": [r1_after["id"]],
        "expected_kept_ids": sorted([c2["id"], r2_after["id"]])}]}


READMES = {
    "history/README.md": """# Item history vectors (contract section 1)

Generated by `scripts/make_feature_pack_vectors.py` (hand-written inputs and results; rows are padded
to exact byte sizes). `tests/test_feature_pack_vectors.py` checks Python against them byte for byte.

- `prune.json`: `prune(rows, now, limits)`; `expected_ids` are the kept `snapshot_id`s **in input
  order**. Row size = UTF-8 length of `canon(row)`.
- `diff.json`: `diff(before, after, kind)` with `reveal`. A secret value shows as `"[protected]"`
  unless `reveal`; a missing side stays `null` (so an added or removed secret is visible as such).
  Values compare by `canon`. Paths sort by Unicode code point (compare scalars, not UTF-16 units).
- `restore_field.json`: `restore_field(current, snapshot, path, now)`; `expected` is the record as
  written (before any normaliser output), or `error`. The password push uses the existing push rule
  (only when the current password is non-empty and differs).
""",
    "travel/README.md": """# Travel mode vectors (contract section 2)

`visible.json`: `hidden_ids(items, setting)` = `expected_hidden`, in input order. Items are neutral
rows `{id, kind, tags, collections}`; logins (`web`, `desktop`) are never hidden by a collection.
""",
    "hygiene/README.md": """# Clean-up sweep vectors (contract section 3)

- `duplicates.json`: `findings(records, now, today)` = `expected` (all finding types). Types come in
  the order `same_login, same_account_other_password, same_site, same_item, not_changed_2y,
  expired`; groups of one type are ordered by their id lists; ids inside a group by `updated_at`
  desc, then id. An empty username can still be a `same_login` (same origin and password); it never
  makes a `same_site`.
- `expired.json`: the ids of the `expired` finding.
- `merge.json`: `merge(keeper, other, now)` = `expected`, or `error`. When the keeper has no notes the
  other's notes are taken as they are (no leading blank line). Fields neither side has stay absent.
  Web logins: `scope.urls` = the keeper's URL rows then the other's, deduplicated by `(url, match)`
  (rows = `scope.urls`, or `[{url: scope.origin, match: "exact_origin"}]` when there are none);
  `scope.origin` stays the keeper's; when nothing is added `scope` is left as the keeper had it.
""",
    "access/README.md": """# Access rule vectors (contract section 4)

- `effective.json`: `effective(record, device_class, today)`.
- `preserve.json`: the full Python sync normal form is given; other cores compare `scope.access` of
  their own normal form with it by `canon` (other fields may differ by core).
- `stricter.json`: `stricter(a, b)`; `null` means absent. Non-default values are kept as written
  (an unknown value such as `"twice"` stays, because it reads as the strict one); unknown keys are
  kept; a value that is not an object wins as is.
""",
    "privacy_proof/README.md": """# Privacy proof vectors (contract section 5, version 2)

Generated with Python's Ed25519 (deterministic) and device A of `tests/vectors/sync/identities.json`
(TEST ONLY keys). Signed bytes = UTF-8 `localgatekeys|privacy-proof|v2|` + `canon(D)`, where D is the
whole document with only `signature.value` removed (so `signature.alg`, `device_id` and `public_key`
are signed). Fingerprint = first 8 bytes of SHA-256 of the raw public key, hex.

- `signed.json`: `unsigned_document`, `signed_body` (D), `signed_bytes_hex`, `signature`,
  `fingerprint`, and the full `signed_document` (verifies `valid`).
- `unsigned.json`: `document` with `signature: null` verifies `unsigned`.
- `rejected/*.json`: raw proof files; each verifies `invalid`: tampered fact, signed without the
  prefix, duplicate key, extra top-level key, a version-1 file signed with the version-1 rule,
  version 3, `device_id` changed after signing, and signed bytes that leave out `signature`
  (the version-1 rule with the v2 prefix).
""",
    "import/report/README.md": """# Import undo vectors (contract section 6.1)

`undo.json`: undo the journal against `current_records` at `now`. `digest(record)` = lower-hex
SHA-256 of `canon(record)`. `expected_after_undo` lists live records in `current_records` order
(a restored record gets `updated_at = now`); trashed ids move to Recently deleted.
""",
}


def build() -> dict[str, bytes]:
    files = {
        "history/prune.json": dump(history_prune()),
        "history/diff.json": dump(history_diff()),
        "history/restore_field.json": dump(history_restore()),
        "travel/visible.json": dump(travel_visible()),
        "hygiene/duplicates.json": dump(hygiene_duplicates()),
        "hygiene/expired.json": dump(hygiene_expired()),
        "hygiene/merge.json": dump(hygiene_merge()),
        "access/effective.json": dump(access_effective()),
        "access/preserve.json": dump(access_preserve()),
        "access/stricter.json": dump(access_stricter()),
        "import/report/undo.json": dump(import_undo_vector()),
    }
    files.update({f"privacy_proof/{name}": data for name, data in privacy_files().items()})
    files.update({name: text.encode("utf-8") for name, text in READMES.items()})
    return files


def main(argv: list[str]) -> int:
    files = build()
    if "--check" in argv:
        bad = [name for name, data in files.items() if (OUT / name).read_bytes() != data]
        if bad:
            print("Out of date:", ", ".join(bad))
            return 1
        return 0
    for name, data in files.items():
        path = OUT / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
    print(f"Wrote {len(files)} files under {OUT}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
