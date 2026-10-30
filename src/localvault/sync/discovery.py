"""Finding a sync host on the local network after its address changed (Bonjour / mDNS).

A host announces ``_lgksync._tcp`` with a neutral instance name and a TXT record
``{"v": "1", "t": <tag>}``.  The tag lets group members recognise their host without the
announcement naming it; it changes every UTC day, so it cannot be used to follow a PC from
network to network.  Identity is still the pinned keys checked by the session hello: the
tag only says where to dial.

Format rules (version 1, pinned by ``tests/vectors/sync/discovery.json``)
-----------------------------------------------------------------------
* ``discovery_key = HKDF(SHA256, length=32, salt=group_id utf-8,
  info=b"localgatekeys|sync|discover|v1|" + str(epoch) ascii)`` over the group key.
* ``tag = base32(HMAC-SHA256(discovery_key, host_device_id utf-8 + b"|" + day ascii)[:10])``,
  lowercase, no padding (16 characters).  ``day`` is the UTC date ``YYYY-MM-DD``.
* A client accepts the tags for today and yesterday (UTC), so a clock a few hours off still
  matches.
* The instance name is ``LocalGateKeys-`` and four random lowercase hex digits per app start.
"""
from __future__ import annotations

import base64
import hmac
import hashlib
import secrets
import time

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from .group import GroupKey

SERVICE_TYPE = "_lgksync._tcp"
TXT_VERSION = "1"
DISCOVER_INFO = b"localgatekeys|sync|discover|v1|"
_TAG_BYTES = 10
_DAY = 86400


def discovery_key(group_key: GroupKey) -> bytes:
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=group_key.group_id.encode("utf-8"),
        info=DISCOVER_INFO + str(group_key.epoch).encode("ascii"),
    ).derive(group_key.key)


def utc_day(now: float) -> str:
    return time.strftime("%Y-%m-%d", time.gmtime(int(now)))


def tag(group_key: GroupKey, host_device_id: str, day: str) -> str:
    mac = hmac.new(discovery_key(group_key), host_device_id.encode("utf-8") + b"|" + day.encode("ascii"),
                   hashlib.sha256).digest()
    return base64.b32encode(mac[:_TAG_BYTES]).decode("ascii").rstrip("=").lower()


def accepted_tags(group_key: GroupKey, host_device_id: str, now: float) -> frozenset[str]:
    """The tags a client accepts for *host_device_id* at *now*: today's and yesterday's (UTC)."""
    return frozenset(tag(group_key, host_device_id, utc_day(now - back)) for back in (0, _DAY))


def txt_record(group_key: GroupKey, host_device_id: str, now: float) -> dict[str, str]:
    return {"v": TXT_VERSION, "t": tag(group_key, host_device_id, utc_day(now))}


def instance_name(token: str | None = None) -> str:
    return "LocalGateKeys-" + (token if token is not None else secrets.token_hex(2))
