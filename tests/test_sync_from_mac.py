"""The desktop reads the keyrings and the folder group the Mac's LGKCore wrote (tests/vectors/sync/mac/from_mac).

Written by ``LGK_WRITE_FROM_MAC=1 swift test --filter GroupCreateTests`` in ios/LGKCore, from the
randomness in ``mac/keyring_write.json`` (``scripts/gen_mac_sync_vectors.py``).  ``folder`` is a group
the Mac created end to end (production Argon2id) and ran once in.  The desktop's own public functions
must accept everything: structure (including the Mac-signed member proofs), the sync password, the
MAC, the names, a desktop device joining, and the Mac's signed view.
"""

from __future__ import annotations

import base64
import json
from pathlib import Path

import pytest

from localvault.sync import keyring as kr
from localvault.sync.group import GroupKey, decode_view, verify_view_signature
from localvault.sync.pairing import DeviceIdentity
from localvault.updates import canonical_json

ROOT = Path(__file__).resolve().parents[1]
VECTORS = ROOT / "tests" / "vectors" / "sync"
FROM_MAC = VECTORS / "mac" / "from_mac"
SYNC_DIR = FROM_MAC / "folder" / "LocalGateKeys Sync"

pytestmark = pytest.mark.skipif(
    not FROM_MAC.is_dir(),
    reason="tests/vectors/sync/mac/from_mac is absent; run LGK_WRITE_FROM_MAC=1 swift test in ios/LGKCore",
)


def _vector() -> dict:
    return json.loads((VECTORS / "mac" / "keyring_write.json").read_text(encoding="utf-8"))


def _identity(name: str) -> DeviceIdentity:
    devices = json.loads((VECTORS / "identities.json").read_text(encoding="utf-8"))["devices"]
    return DeviceIdentity.from_protected_dict(devices[name]["private"])


def _read(path: Path) -> dict:
    raw = path.read_bytes()
    ring = kr.parse_keyring(raw)
    kr.verify_keyring_structure(ring)  # checks the Mac's Ed25519 member proofs
    assert canonical_json(ring) == raw  # written as canonical JSON
    return ring


def test_mac_created_keyring_opens_with_the_password_and_takes_a_desktop_member():
    v = _vector()
    ring = _read(FROM_MAC / "keyring_created.lgkkeys")
    gk = GroupKey(v["group_id"], 1, bytes.fromhex(v["create"]["group_key_hex"]))
    a = _identity("A")
    assert kr.accept_keyring(ring, gk, a) == gk
    assert kr.member_names(ring, gk) == {a.device_id: v["name"]}
    assert kr.member_signing_keys(ring) == {a.device_id: v["create"]["keyring"]["members"][0]["signing_public"]}
    # identical to the desktop's own create_group output except the hedged proof and the MAC over it
    expected = dict(v["create"]["keyring"])
    for r in (ring, expected):
        r["members"][0] = {**r["members"][0], "signing_proof": None}
        r["mac"] = None
    assert ring == expected
    ring = _read(FROM_MAC / "keyring_created.lgkkeys")
    joined, key = kr.join_with_password(ring, v["password"], _identity("B"), "Laptop (Windows)")
    assert key == gk
    kr.verify_keyring_structure(joined)


def test_mac_first_keyring_of_an_existing_group():
    v = _vector()
    ring = _read(FROM_MAC / "keyring_existing.lgkkeys")
    ex = v["existing"]
    gk = GroupKey(ex["group_id"], ex["epoch"], bytes.fromhex(ex["group_key_hex"]))
    assert ring["prev_mac"] is None
    assert kr.accept_keyring(ring, gk, _identity("A")) == gk
    attached = kr.attach_with_password(ring, v["password"], _identity("B"), "Laptop (Windows)", gk)
    assert {m["device_id"] for m in attached["members"]} == {_identity("A").device_id, _identity("B").device_id}


def test_mac_folder_group_joins_and_its_view_verifies():
    v = _vector()
    ring = _read(SYNC_DIR / "keyring.lgkkeys")
    assert ring["epoch"] == 1 and ring["prev_mac"] is None and len(ring["members"]) == 1
    mac_id = ring["members"][0]["device_id"]
    joined, gk = kr.join_with_password(ring, v["password"], _identity("B"), "Laptop (Windows)")
    assert kr.member_names(ring, gk) == {mac_id: v["name"]}
    raw = (SYNC_DIR / "devices" / f"{mac_id}.lgksync").read_bytes()
    view = decode_view(gk, raw, expected_device_id=mac_id)
    assert view.header["counter"] == 1
    signer = verify_view_signature((SYNC_DIR / "signatures" / f"{mac_id}.lgksig").read_bytes(), raw, view.header)
    assert signer == base64.b64decode(kr.member_signing_keys(ring)[mac_id])
    assert sorted(p.name for p in SYNC_DIR.iterdir()) == ["devices", "keyring.lgkkeys", "signatures"]
