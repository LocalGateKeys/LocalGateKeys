"""UX plan workstream 9: the ``.lgkshare`` v1 format core against the shared vectors."""
from __future__ import annotations

import base64
import json
from pathlib import Path

import pytest

from localvault import share

VECTORS = json.loads((Path(__file__).parent / "vectors" / "share" / "v1.json").read_text(encoding="utf-8"))


@pytest.mark.parametrize("case", VECTORS["opens"], ids=lambda c: c["name"])
def test_vector_opens_and_reseals_byte_for_byte(case):
    data = case["package"].encode("utf-8")
    opened = share.open_package(data, case["code"], now=case["now"])
    assert opened["item"] == case["item"] and opened["sender"] == case["sender"] and opened["id"] == case["id"]
    assert opened["expires_at"] == case["now"] + share.LIFETIME
    again = share.seal(case["item"], case["code"], sender=case["sender"], now=case["now"], package_id=case["id"],
                       salt=base64.b64decode(case["salt"]), nonce=base64.b64decode(case["nonce"]))
    assert again == data


@pytest.mark.parametrize("case", VECTORS["refused"], ids=lambda c: c["name"])
def test_vector_refusals(case):
    with pytest.raises(share.ShareError) as refused:
        share.open_package(case["package"].encode("utf-8"), case["code"], now=case["now"])
    assert refused.value.reason == case["reason"]


def test_header_is_readable_without_the_code_and_holds_no_secret():
    case = VECTORS["opens"][0]
    header = share.read_header(case["package"].encode("utf-8"))
    assert header["sender"] == "Alex's iPhone" and header["id"] == case["id"]
    assert "correct-horse" not in case["package"] and "Home Wi-Fi" not in case["package"]


def test_open_once_per_device_and_code_spelling():
    case = VECTORS["opens"][0]
    data = case["package"].encode("utf-8")
    with pytest.raises(share.ShareError) as again:
        share.open_package(data, case["code"], now=case["now"], opened={case["id"]})
    assert again.value.reason == "already-opened"
    assert share.open_package(data, "Maple · River · Onion · Seven · Lamp · Quote", now=case["now"])["id"] == case["id"]


def test_fresh_code_and_qr_round_trip():
    code = share.generate_code()
    assert len(code.split()) == 6 and share.normalize_code(code) == code
    assert share.code_from_qr_text(share.code_qr_text(code)) == code
    data = share.seal({"kind": "note", "title": "n", "fields": {"text": "x"}}, code, sender="PC", now=100)
    assert share.fits_qr(data)
    assert share.open_package(data, code, now=200)["item"]["title"] == "n"


def test_passkeys_attachments_and_local_fields_never_travel():
    code = share.generate_code()
    with pytest.raises(share.ShareError):
        share.seal({"kind": "passkey", "title": "p"}, code, sender="PC", now=1)
    with pytest.raises(share.ShareError):
        share.seal({"kind": "web", "attachments": [{"id": "a"}]}, code, sender="PC", now=1)
    data = share.seal({"kind": "web", "label": "A", "policy": {"fill": "auto"}, "password_history": [{}]}, code,
                      sender="PC", now=1)
    assert share.open_package(data, code, now=2)["item"] == {"kind": "web", "label": "A"}
