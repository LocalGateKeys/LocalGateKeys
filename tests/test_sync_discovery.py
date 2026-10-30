"""Bonjour discovery tags (``sync/discovery.py``) against ``tests/vectors/sync/discovery.json``."""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
from pathlib import Path

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from localvault.sync import discovery
from localvault.sync.group import GroupKey

VECTORS = json.loads((Path(__file__).parent / "vectors" / "sync" / "discovery.json").read_text("utf-8"))


def _gk() -> GroupKey:
    return GroupKey(VECTORS["group_id"], VECTORS["epoch"], base64.b64decode(VECTORS["group_key_b64"]))


def test_discovery_key_and_tags_match_an_independent_computation():
    gk = _gk()
    key = HKDF(algorithm=hashes.SHA256(), length=32, salt=gk.group_id.encode(),
               info=b"localgatekeys|sync|discover|v1|1").derive(gk.key)
    assert base64.b64encode(key).decode() == VECTORS["discovery_key_b64"]
    for case in VECTORS["tags"]:
        mac = hmac.new(key, f"{VECTORS['host_device_id']}|{case['day']}".encode(), hashlib.sha256).digest()
        assert base64.b32encode(mac[:10]).decode().rstrip("=").lower() == case["tag"]
        assert discovery.tag(gk, VECTORS["host_device_id"], case["day"]) == case["tag"]


def test_window_is_today_and_yesterday_utc():
    gk, host, now = _gk(), VECTORS["host_device_id"], VECTORS["window"]["now"]
    accepted = discovery.accepted_tags(gk, host, now)
    assert sorted(accepted) == VECTORS["window"]["accepted"]
    assert discovery.tag(gk, host, discovery.utc_day(now)) in accepted
    assert discovery.tag(gk, host, discovery.utc_day(now - 2 * 86400)) not in accepted
    assert discovery.txt_record(gk, host, now) == VECTORS["txt"]


def test_tag_depends_on_host_epoch_and_key():
    gk, host, day = _gk(), VECTORS["host_device_id"], "2026-10-29"
    base = discovery.tag(gk, host, day)
    assert len(base) == 16 and base.isalnum() and base == base.lower()
    assert discovery.tag(gk, host + "x", day) != base
    assert discovery.tag(GroupKey(gk.group_id, 2, gk.key), host, day) != base
    assert discovery.tag(GroupKey(gk.group_id, 1, bytes(32)), host, day) != base


def test_instance_name_is_neutral():
    assert discovery.instance_name("3f9a") == VECTORS["instance_name_example"]
    name = discovery.instance_name()
    assert name.startswith("LocalGateKeys-") and len(name) == len("LocalGateKeys-") + 4
    assert discovery.SERVICE_TYPE == VECTORS["service_type"]
