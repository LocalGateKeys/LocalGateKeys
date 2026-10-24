"""Cross-language check: a licence signed by the Cloudflare Worker (JS) verifies in Python.

The vector files are written by tests/license-issuer.test.cjs with a TEST ONLY key.
"""

from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path

import pytest

from localvault import licensing

VECTORS = Path(__file__).parent / "vectors" / "license"


def _load():
    bundle = json.loads((VECTORS / "worker-issued.lgklicense").read_text(encoding="utf-8"))
    public = (VECTORS / "worker-public-key.txt").read_text(encoding="utf-8").strip()
    key_id = hashlib.sha256(base64.b64decode(public)).digest()[:8].hex()
    return bundle, public, key_id


def test_worker_issued_licence_verifies():
    bundle, public, key_id = _load()
    assert bundle["signature"]["key_id"] == key_id
    lic = licensing.verify_bundle(bundle, keys={key_id: public})
    assert lic.name == "Zoë Müller 山田"
    assert lic.updates_until.isoformat() == "9999-12-31"


def test_worker_issued_paste_form_round_trips():
    bundle, public, key_id = _load()
    parsed = licensing.verify_bundle(
        licensing.parse_license_text(licensing.encode_paste(bundle)), keys={key_id: public}
    )
    assert parsed.license_id == bundle["license"]["license_id"]


def test_tampered_worker_licence_is_rejected():
    bundle, public, key_id = _load()
    bundle["license"]["name"] = "Someone Else"
    with pytest.raises(licensing.LicenseError):
        licensing.verify_bundle(bundle, keys={key_id: public})
