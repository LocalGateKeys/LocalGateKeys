"""Generate the Mac host-side Wi-Fi pairing vectors in ``tests/vectors/sync/mac``.

Test-only.  ``pairing.create_pairing_offer`` runs unmodified; only its randomness is replaced
by a fixed byte stream, consumed in the order the Swift ``PairingOffer.create`` reads it:

1. 16 bytes for the offer id (uuid4: version and variant bits forced, as ``uuid.uuid4``),
2. 32 bytes for the transcript nonce,
3. 32 bytes for the pairing secret,
4. 4 bytes at a time for the 8-digit code: a big-endian unsigned integer, resampled while it is
   >= 4_200_000_000 (the largest multiple of 10**8 below 2**32), then taken modulo 10**8.

The inviter is device A of ``tests/vectors/sync/identities.json``.

``keyring_write.json`` pins the keyring writers (``keyring.create_group``,
``create_for_existing_group``, ``join_with_password`` and ``rotate`` run unmodified with ``_rand``
from the same kind of stream).  Each case lists its ``random_reads_hex`` in the order Swift draws
them, and ``argon2`` maps ``password|salt_b64`` to the production Argon2id key, so Swift can
inject the KDF and stay fast.

Usage::

    python scripts/gen_mac_sync_vectors.py [OUT_DIR]      # default: tests/vectors/sync/mac
"""

# ruff: noqa: S101, S105

from __future__ import annotations

import base64
import hashlib
import json
import sys
import uuid
from pathlib import Path
from unittest import mock

from localvault.sync import keyring as kr
from localvault.sync import pairing
from localvault.sync.group import GroupKey
from localvault.sync.pairing import (
    DeviceIdentity,
    create_pairing_offer,
    offer_qr_payload,
    parse_qr_payload,
)

ROOT = Path(__file__).resolve().parent.parent
GROUP_ID = "5b0c7d3e-9a41-4f6b-8c2d-3e1a7f905b64"
CODE_LIMIT = (2**32 // 10**8) * 10**8


def stream(label: str, count: int) -> bytes:
    out = b""
    i = 0
    while len(out) < count:
        out += hashlib.sha256(f"mac-host|{label}|{i}".encode()).digest()
        i += 1
    return out[:count]


class Source:
    def __init__(self, data: bytes) -> None:
        self.data, self.pos, self.reads = data, 0, []

    def take(self, n: int) -> bytes:
        chunk = self.data[self.pos:self.pos + n]
        assert len(chunk) == n, "stream exhausted"
        self.pos += n
        self.reads.append(chunk.hex())
        return chunk

    def uuid4(self) -> uuid.UUID:
        return uuid.UUID(bytes=self.take(16), version=4)

    def randbelow(self, n: int) -> int:
        assert n == 10**8
        while True:
            value = int.from_bytes(self.take(4), "big")
            if value < CODE_LIMIT:
                return value % n


def identity(who: str) -> DeviceIdentity:
    devices = json.loads((ROOT / "tests/vectors/sync/identities.json").read_text())["devices"]
    return DeviceIdentity.from_protected_dict(devices[who]["private"])


def identity_a() -> DeviceIdentity:
    return identity("A")


KEYRING_GROUP_ID = "7c2e9b41-3d5a-4f80-9e16-b0a4c8d2f357"
EXISTING_GROUP_ID = "0d4f8a26-5b13-4c7e-a9f2-61e3b7c50d98"
PASSWORD = "correct horse battery staple 42"
NEW_PASSWORD = "violet tram sundial 1987 pebble"
MAC_NAME = "Mac de Ilías"
NOW = 1790001000


def keyring_doc() -> dict:
    argon: dict[str, str] = {}

    def remember(password: str, ring: dict) -> None:
        salt = ring["kdf"]["salt"]
        key = kr._argon2(password, base64.b64decode(salt), kr._PRODUCTION_KDF)
        argon[f"{password}|{salt}"] = key.hex()

    a, b = identity("A"), identity("B")
    src = Source(stream("keyring-create", 32 + 16 + 12 + 32 + 12 + 12))
    created, gk = kr.create_group(PASSWORD, a, MAC_NAME, _rand=src.take, _now=NOW, _group_id=KEYRING_GROUP_ID)
    remember(PASSWORD, created)
    create = {"random_reads_hex": src.reads, "keyring": created, "group_key_hex": gk.key.hex()}

    src = Source(stream("keyring-join", 32 + 12 + 12))
    joined, _ = kr.join_with_password(created, PASSWORD, b, "Laptop (Windows)", _rand=src.take, _now=NOW + 60)
    join = {"random_reads_hex": src.reads, "keyring": joined}

    def rotated(label: str, remove: list[str]) -> dict:
        members = len(joined["members"]) - len(remove)
        src = Source(stream(label, 32 + 16 + 12 + members * (32 + 12 + 12)))
        ring, new = kr.rotate(joined, gk, a, NEW_PASSWORD, remove=remove, _rand=src.take)
        remember(NEW_PASSWORD, ring)
        return {"remove": remove, "random_reads_hex": src.reads, "keyring": ring, "group_key_hex": new.key.hex()}

    # the reuse check derives the new password with the current salt
    remember(NEW_PASSWORD, joined)
    remove_member = rotated("keyring-remove", [b.device_id])
    change_password = rotated("keyring-change-password", [])

    existing_key = GroupKey(EXISTING_GROUP_ID, 3, stream("keyring-existing-key", 32))
    src = Source(stream("keyring-existing", 16 + 12 + 32 + 12 + 12))
    existing = kr.create_for_existing_group(existing_key, PASSWORD, a, MAC_NAME, _rand=src.take, _now=NOW)
    remember(PASSWORD, existing)
    return {
        "description": "Keyrings written by localvault.sync.keyring with fixed randomness (see "
                       "scripts/gen_mac_sync_vectors.py). Device A creates the group as the Mac, B joins, "
                       "A then removes B (remove_member) or keeps it (change_password).",
        "group_id": KEYRING_GROUP_ID, "password": PASSWORD, "new_password": NEW_PASSWORD,
        "name": MAC_NAME, "now": NOW, "creator": "A", "joiner": "B",
        "create": create, "join": join, "remove_member": remove_member, "change_password": change_password,
        "existing": {"group_id": EXISTING_GROUP_ID, "epoch": 3, "group_key_hex": existing_key.key.hex(),
                     "random_reads_hex": src.reads, "keyring": existing},
        "argon2": argon,
    }


def case(name: str, data: bytes, host: str, port: int, now: int) -> dict:
    src = Source(data)
    with mock.patch.object(pairing.uuid, "uuid4", src.uuid4), \
            mock.patch.object(pairing.secrets, "token_bytes", src.take), \
            mock.patch.object(pairing.secrets, "randbelow", src.randbelow):
        offer = create_pairing_offer(identity_a(), GROUP_ID, host, port, now=now)
    qr = offer_qr_payload(offer)
    assert parse_qr_payload(qr) == offer.bundle_dict()
    assert offer.expires_at == now + pairing.PAIRING_TTL_SECONDS
    return {
        "name": name, "now": now, "endpoint": {"host": host, "port": port}, "group_id": GROUP_ID,
        "inviter": "A", "random_reads_hex": src.reads, "offer_bundle": offer.bundle_dict(), "qr_payload": qr,
    }


def main() -> None:
    out = Path(sys.argv[1]) if len(sys.argv) > 1 else ROOT / "tests/vectors/sync/mac"
    out.mkdir(parents=True, exist_ok=True)
    plain = stream("plain", 84)
    # The first code read is 0xffffffff (over the limit), so the code needs a second read.
    resample = stream("resample", 80) + b"\xff\xff\xff\xff" + stream("resample-code", 4)
    doc = {
        "description": "Host-side pairing offers made by pairing.create_pairing_offer with fixed "
                       "randomness (see scripts/gen_mac_sync_vectors.py for the read order). "
                       "random_reads_hex lists every read in order.",
        "cases": [
            case("plain", plain, "192.168.1.20", 47821, 1790000000),
            case("code_resampled", resample, "10.0.0.5", 47821, 1790000500),
        ],
    }
    (out / "host_offer.json").write_text(json.dumps(doc, indent=2, sort_keys=True) + "\n")
    print(out / "host_offer.json")
    (out / "keyring_write.json").write_text(json.dumps(keyring_doc(), indent=2, sort_keys=True,
                                                       ensure_ascii=False) + "\n", encoding="utf-8")
    print(out / "keyring_write.json")


if __name__ == "__main__":
    main()
