"""Write tests/vectors/share/v1.json: run from the repo root with ``python tests/vectors/share/generate.py``.

LGKCore (Swift) and lgk-core (Kotlin) read the same file:

- every ``opens`` package must open with ``code`` at ``now`` to exactly ``item``, must re-seal byte for byte
  from ``item``/``sender``/``now``/``id``/``salt``/``nonce``, and (``phone_saves``) must pass the receiver's
  normal form so it can be saved. Every ``item`` is in the stored shape the spec defines, made by the desktop's
  own validators (``vault._validate_legacy_payload`` for logins, ``item_schema.validate_item`` for typed items).
- every ``legacy`` package holds the display shape early builds sent (top-level ``urls`` / ``fields``):
  a receiver converts it to ``stored`` (``share.stored_form``) and saves it.
"""
from __future__ import annotations

import base64
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "src"))

from localvault.item_schema import validate_item  # noqa: E402
from localvault.share import _LOCAL_ONLY, LIFETIME, seal, stored_form  # noqa: E402
from localvault.vault import _validate_legacy_payload  # noqa: E402

NOW = 1_800_000_000
CODE = "maple river onion seven lamp quote"
T = 1_799_990_000


def _login(entry: dict) -> dict:
    checked = _validate_legacy_payload({"version": 1, "entries": [entry], "trash": []}, strict_origins=True)
    return {k: v for k, v in checked["entries"][0].items() if k not in _LOCAL_ONLY}


def _typed(kind: str, item_id: str, title: str, payload: dict) -> dict:
    checked = validate_item({"id": item_id, "kind": kind, "title": title, "created_at": T, "updated_at": T,
                             "tags": [], "payload": payload})
    return {k: v for k, v in checked.items() if k not in _LOCAL_ONLY}


WIFI = _typed("wifi", "2b0d6c1e-6d35-4d55-9a0e-1c1f1c0a7a11", "Home Wi-Fi",
              {"ssid": "Home", "password": "correct-horse-staple", "security": "WPA2"})
LOGIN = _login({"kind": "web", "id": "6f8a9a52-4d0b-4b87-8f3c-0a4f9d7b2c10", "label": "Alpha", "username": "ann",
                "password": "pw-alpha-1234567",
                "scope": {"origin": "https://alpha.test",
                          "urls": [{"url": "https://alpha.test", "match": "exact_origin"},
                                   {"url": "https://login.alpha.test/sso", "match": "starts_with"},
                                   {"url": "https://alpha-cdn.test", "match": "host"}]},
                "notes": "shared", "tags": ["work"], "created_at": 1_799_000_000, "updated_at": 1_799_000_000})
CARD = _typed("card", "7c1d2e3f-4a5b-4c6d-8e7f-8091a2b3c4d5", "Visa",
              {"cardholder": "Ann Example", "number": "4111111111111111", "expiry": "12/30", "cvv": "123"})
NOTE = _typed("note", "8d2e3f40-5b6c-4d7e-8f80-91a2b3c4d5e6", "Door code", {"body": "4711\nback door"})
IDENTITY = _typed("identity", "9e3f4051-6c7d-4e8f-9091-a2b3c4d5e6f7", "Ann",
                  {"given_name": "Ann", "family_name": "Example", "email": "ann@example.test", "city": "Athens"})
DESKTOP = _login({"kind": "desktop", "id": "a04f5162-7d8e-4f90-a1a2-b3c4d5e6f708", "label": "Tool",
                  "username": "ann", "password": "pw-desktop-12345",
                  "scope": {"exe_path": "C:\\Program Files\\Tool\\tool.exe"},
                  "created_at": T, "updated_at": T})

LEGACY_LOGIN = {"kind": "web", "id": "b15f6273-8e9f-4a01-b2b3-c4d5e6f70819", "title": "Beta", "username": "bob",
                "password": "pw-beta-1234567890",
                "urls": [{"url": "https://beta.test/login", "match": "starts_with"},
                         {"url": "https://www.beta.test", "match": "host"}],
                "notes": "", "tags": [], "created_at": T, "updated_at": T}
LEGACY_WIFI = {"kind": "wifi", "id": "c2607384-9fa0-4b12-83c4-d5e6f708192a", "label": "Cabin",
               "fields": {"ssid": "Cabin", "password": "pine-cone-lake", "security": "WPA2"},
               "tags": [], "created_at": T, "updated_at": T}


def _case(name: str, item: dict, package_id: str, salt_byte: int, nonce_byte: int, sender: str, **extra) -> dict:
    salt, nonce = bytes([salt_byte]) * 16, bytes([nonce_byte]) * 12
    data = seal(item, CODE, sender=sender, now=NOW, package_id=package_id, salt=salt, nonce=nonce)
    return {"name": name, "code": CODE, "sender": sender, "now": NOW, "id": package_id,
            "salt": base64.b64encode(salt).decode(), "nonce": base64.b64encode(nonce).decode(),
            "item": item, "package": data.decode("utf-8"), **extra}


def main() -> None:
    cases = [
        _case("wifi", WIFI, "0c7e4f0a-9c55-4c6b-8a7e-3c2b1a0f9e01", 1, 2, "Alex's iPhone", phone_saves=True),
        _case("login", LOGIN, "5d1e2f3a-4b5c-4d6e-8f70-819203a4b5c6", 3, 4, "Desk PC", phone_saves=True),
        _case("card", CARD, "1a2b3c4d-5e6f-4a7b-8c9d-0e1f2a3b4c5d", 5, 6, "Pixel 9", phone_saves=True),
        _case("note", NOTE, "2b3c4d5e-6f7a-4b8c-9d0e-1f2a3b4c5d6e", 7, 8, "Mac", phone_saves=True),
        _case("identity", IDENTITY, "3c4d5e6f-7a8b-4c9d-8e1f-2a3b4c5d6e7f", 9, 10, "Desk PC", phone_saves=True),
        # Windows only: phones refuse it with "can't be saved on this device".
        _case("desktop login", DESKTOP, "4d5e6f7a-8b9c-4d0e-9f2a-3b4c5d6e7f80", 11, 12, "Desk PC", phone_saves=False),
    ]
    legacy = [
        _case("legacy login", LEGACY_LOGIN, "5e6f7a8b-9c0d-4e1f-8a3b-4c5d6e7f8091", 13, 14, "Old Pixel",
              stored=stored_form(LEGACY_LOGIN)),
        _case("legacy wifi", LEGACY_WIFI, "6f7a8b9c-0d1e-4f2a-9b4c-5d6e7f8091a2", 15, 16, "Old iPhone",
              stored=stored_form(LEGACY_WIFI)),
    ]
    base = cases[0]["package"]
    envelope = json.loads(base)
    tampered = dict(envelope)
    tampered["sender"] = "Mallory"
    flipped = dict(envelope)
    raw = bytearray(base64.b64decode(flipped["ciphertext"]))
    raw[0] ^= 1
    flipped["ciphertext"] = base64.b64encode(bytes(raw)).decode()
    weak = dict(envelope)
    weak["kdf"] = {**envelope["kdf"], "memory_cost_kib": 8}
    dumps = lambda v: json.dumps(v, sort_keys=True, separators=(",", ":"), ensure_ascii=False)  # noqa: E731
    refused = [
        {"name": "wrong code", "package": base, "code": "maple river onion seven lamp quick", "now": NOW,
         "reason": "wrong-code"},
        {"name": "expired", "package": base, "code": CODE, "now": NOW + LIFETIME, "reason": "expired"},
        {"name": "sender changed", "package": dumps(tampered), "code": CODE, "now": NOW, "reason": "wrong-code"},
        {"name": "ciphertext flipped", "package": dumps(flipped), "code": CODE, "now": NOW, "reason": "wrong-code"},
        {"name": "date in the future", "package": base, "code": CODE, "now": NOW - 3600, "reason": "malformed"},
        {"name": "not six words", "package": base, "code": "maple river", "now": NOW, "reason": "bad-code"},
        {"name": "newer version", "package": base.replace('"version":1', '"version":2'), "code": CODE, "now": NOW,
         "reason": "unsupported"},
        {"name": "weaker kdf", "package": dumps(weak), "code": CODE, "now": NOW, "reason": "malformed"},
    ]
    out = {"format": "localgatekeys-share", "version": 1, "spec": "docs/formats/LGKSHARE_V1.md",
           "opens": cases, "legacy": legacy, "refused": refused}
    path = Path(__file__).with_name("v1.json")
    path.write_text(json.dumps(out, indent=2, ensure_ascii=False) + "\n", encoding="utf-8", newline="\n")


if __name__ == "__main__":
    main()
