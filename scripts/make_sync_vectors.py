"""Generate the deterministic desktop <-> iOS sync test vectors in ``tests/vectors/sync``.

Everything here is test-only.  Every key, salt, nonce and id is derived from fixed labels,
and the production formats run unmodified: the only difference from a real run is that the
random bytes come from the keyword-only ``_rand`` / ``nonce_source`` / ``_eph_seed`` hooks
(the keyring uses the PRODUCTION Argon2id parameters, 128 MiB x 4 passes x 4 lanes).

Usage::

    python scripts/make_sync_vectors.py [OUT_DIR]      # default: tests/vectors/sync

``tests/test_sync_vectors.py`` regenerates into a temporary directory and compares every
file byte for byte with the committed copies.
"""

# ruff: noqa: S101, S105  (generator self-checks use assert; the passwords are published test vectors)

from __future__ import annotations

import base64
import hashlib
import ipaddress
import json
import sys
import unicodedata
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ed25519, x25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from localvault import licensing, passkeys
from localvault.item_schema import ItemSchemaError, validate_passkey_fields
from localvault.origin import OriginError
from localvault.sync import keyring as kr
from localvault.sync import engine as sync_engine
from localvault.sync.engine import EngineError, ItemState, conflict_copy_id, implausible_vv, merge
from localvault.sync.folder_transport import MAX_COUNTER_JUMP, MAX_FILE_COUNTER, counter_verdict
from localvault.sync.group import MAGIC, SIG_LABEL, GroupKey, SyncFormatError, encode_view, sign_view, verify_view_signature
from localvault.sync.lan_address import LAN_NETWORKS, is_lan_address
from localvault.sync.lan_sync import (
    CHUNK_BYTES,
    ERROR_REASONS,
    _view_message,
    encode_message,
    parse_message,
    split_view,
)
from localvault.sync.pairing import (
    DeviceIdentity,
    PairedDevice,
    PairingOffer,
    PairingSession,
    build_enrollment_request,
    offer_qr_payload,
    open_enrollment_reply,
    parse_qr_payload,
    seal_enrollment_reply,
)
from localvault.sync.transport import SecureChannel, create_session_hello, version_refusal
from localvault.sync.vault_bridge import CONFLICT_SUFFIX, _license_wrapper, _wrapper, normal_form
from localvault.totp import TotpError
from localvault.updates import canonical_json
from localvault.vault import VaultError

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_OUT = ROOT / "tests" / "vectors" / "sync"

# --- fixed scenario constants ------------------------------------------------------------------

T0 = 1790000000  # 2026-09-21T13:33:20Z; every timestamp below is T0 + an offset
PASSWORD_1 = "correct horse battery staple 42"
PASSWORD_2 = "violet tram sundial 1987 pebble"
GROUP_ID = "5b0c7d3e-9a41-4f6b-8c2d-3e1a7f905b64"

DEVICE_IDS = {
    "A": "a1111111-0000-4000-8000-00000000000a",
    "B": "b2222222-0000-4000-8000-00000000000b",
    "C": "c3333333-0000-4000-8000-00000000000c",
}
EXISTING_GROUP_ID = "e6a1c2d4-7b30-4c58-9f12-0a8d5b3c6e71"  # the group of the existing-group keyrings
PASSWORD_UNICODE = "caf\u00e9 sync password 42"  # NFC; its NFD form is derived
DEVICE_NAMES = {"A": "Desk PC (Windows)", "B": "Laptop (Windows)", "C": "Old Tablet"}

# item ids
LOGIN_EDITED = "11111111-aaaa-4000-8000-000000000001"  # edited concurrently by A and B
NOTE = "22222222-aaaa-4000-8000-000000000002"  # typed note
DESKTOP = "33333333-aaaa-4000-8000-000000000003"  # desktop entry
LOGIN_DELETED = "44444444-aaaa-4000-8000-000000000004"  # deleted by C
BOOKMARK = "55555555-aaaa-4000-8000-000000000005"  # edited by B while C deleted it
NOTE_UNICODE = "66666666-aaaa-4000-8000-000000000006"  # B only; non-ASCII canonical JSON
LOGIN_TIE = "77777777-aaaa-4000-8000-000000000007"  # A and B edit with EQUAL updated_at (hash tie-break)

# Written by the three devices in this order; (counter, written_at offset).
VIEW_HEADERS = {"A": (7, 900), "B": (4, 880), "C": (3, 860)}

GENERATED_FILES = tuple(sorted((
    "README.md",
    "canonical_json.json",
    "devices/A.lgksync",
    "devices/B.lgksync",
    "devices/C.lgksync",
    "expected.json",
    "expected_merge.json",
    "hardening_cases.json",
    "identities.json",
    "keyring_attach.json",
    "keyring_epoch1.json",
    "keyring_epoch1_ab.json",
    "keyring_epoch2.json",
    "keyring_existing_epoch1.json",
    "keyring_existing_epoch3.json",
    "keyring_v1_epoch1.json",
    "lan/enroll_reply.bin",
    "lan/enroll_reply_no_endpoint.bin",
    "lan/enroll_request.bin",
    "lan/enroll_request_no_endpoint.bin",
    "lan/expected_lan.json",
    "lan/frame_initiator.bin",
    "lan/frame_responder.bin",
    "lan/hello_initiator.bin",
    "lan/hello_responder.bin",
    "lan/lan_ranges.json",
    "lan/messages.json",
    "lan/messages/01_request_view_0.bin",
    "lan/messages/01_response_ack_0.bin",
    "lan/messages/02_request_view_1.bin",
    "lan/messages/02_response_view_0.bin",
    "lan/messages/03_request_next_1.bin",
    "lan/messages/03_response_view_1.bin",
    "lan/qr_payload.txt",
    "lan/session.json",
    "normalise/entries.json",
    "license_state.json",
    "normalise/items.json",
    "passkeys/assertion.json",
    "passkeys/records.json",
    "passkeys/registration.json",
    "schema_cases.json",
    "signatures/A.lgksig",
)))


class DetRand:
    """Deterministic byte stream: sha256(label | counter) blocks.  Used as ``os.urandom``."""

    def __init__(self, label: str) -> None:
        self._label = b"lgk-sync-vectors|rand|" + label.encode("ascii")
        self._counter = 0

    def __call__(self, size: int) -> bytes:
        out = b""
        while len(out) < size:
            out += hashlib.sha256(self._label + b"|" + self._counter.to_bytes(4, "big")).digest()
            self._counter += 1
        return out[:size]


def seed(label: str) -> bytes:
    return hashlib.sha256(b"lgk-sync-vectors|seed|" + label.encode("ascii")).digest()


def b64(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def dumps(value: Any) -> bytes:
    """Readable, stable JSON for the descriptive files (keys sorted, 2 spaces, LF, final newline)."""
    return (json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False) + "\n").encode("utf-8")


# --- identities --------------------------------------------------------------------------------


def make_identity(name: str) -> DeviceIdentity:
    return DeviceIdentity(
        DEVICE_IDS[name],
        ed25519.Ed25519PrivateKey.from_private_bytes(seed(f"identity|{name}|signing")),
        x25519.X25519PrivateKey.from_private_bytes(seed(f"identity|{name}|exchange")),
    )


def identities_json(identities: dict[str, DeviceIdentity]) -> bytes:
    devices = {}
    for name, ident in identities.items():
        devices[name] = {
            "device_id": ident.device_id,
            "name": DEVICE_NAMES[name],
            "private": ident.protected_dict(),
            "signing_public_b64": b64(ident.signing_public_key),
            "exchange_public_b64": b64(ident.exchange_public_key),
            "fingerprint_sha256_of_signing_public": ident.fingerprint,
        }
    return dumps(
        {
            "WARNING": "TEST ONLY. These private keys are published in the repository on purpose. "
            "Never use them for a real device or vault.",
            "devices": devices,
        }
    )


# --- keyrings ----------------------------------------------------------------------------------


def build_keyrings(identities: dict[str, DeviceIdentity]) -> dict[str, Any]:
    """Create epoch 1 (A creates, B then C join by password), then rotate to epoch 2 without C.

    Runs the real keyring functions with the PRODUCTION KDF; ``recorded`` captures every
    Argon2id output so ``expected.json`` can publish the password-wrap keys.
    """
    rand = DetRand("keyring")
    recorded: dict[tuple[str, str], bytes] = {}
    real = kr._argon2

    def recording(password: str, salt: bytes, profile: tuple[int, int, int]) -> bytes:
        key = real(password, salt, profile)
        recorded[(password, salt.hex())] = key
        return key

    kr._argon2 = recording
    try:
        ring_a, gk1 = kr.create_group(
            PASSWORD_1, identities["A"], DEVICE_NAMES["A"], _rand=rand, _now=T0, _group_id=GROUP_ID
        )
        ring_ab, _ = kr.join_with_password(
            ring_a, PASSWORD_1, identities["B"], DEVICE_NAMES["B"], _rand=rand, _now=T0 + 60
        )
        ring1, _ = kr.join_with_password(
            ring_ab, PASSWORD_1, identities["C"], DEVICE_NAMES["C"], _rand=rand, _now=T0 + 120
        )
        ring2, gk2 = kr.rotate(ring1, gk1, identities["A"], PASSWORD_2, remove=[DEVICE_IDS["C"]], _rand=rand)
    finally:
        kr._argon2 = real
    salts = {1: ring1["kdf"]["salt"], 2: ring2["kdf"]["salt"]}
    pw_keys = {
        1: recorded[(PASSWORD_1, base64.b64decode(salts[1]).hex())],
        2: recorded[(PASSWORD_2, base64.b64decode(salts[2]).hex())],
    }
    return {"ring_ab": ring_ab, "ring1": ring1, "ring2": ring2, "gk": {1: gk1, 2: gk2}, "pw_keys": pw_keys}


def format1_keyring(ring: dict[str, Any], gk: GroupKey) -> dict[str, Any]:
    """*ring* as format 1 (no member signing keys), MAC recomputed under *gk*: what an older app wrote."""
    body = {k: v for k, v in ring.items() if k != "mac"}
    body["format"] = 1
    body["members"] = [{k: v for k, v in m.items() if k not in ("signing_public", "signing_proof")}
                       for m in ring["members"]]
    return kr._finish(body, gk, None, ring["prev_mac"])


def expected_json(built: dict[str, Any], existing: dict[str, Any], unicode_pw: dict[str, Any]) -> bytes:
    epochs = {}
    for epoch in (1, 2):
        gk: GroupKey = built["gk"][epoch]
        epochs[str(epoch)] = {
            "group_key_hex": gk.key.hex(),
            "record_key_hex": gk.record_key().hex(),
            "file_key_hex": gk.file_key().hex(),
            "keyring_mac_key_hex": kr._mac_key(gk.key, gk.group_id, gk.epoch).hex(),
            "password_wrap_key_hex": built["pw_keys"][epoch].hex(),
            "member_name_key_hex": kr._name_key(gk).hex(),
            "member_names": kr.member_names(built[f"ring{epoch}"], gk),
            "member_signing_keys": kr.member_signing_keys(built[f"ring{epoch}"]),
        }
    return dumps(
        {
            "group_id": GROUP_ID,
            "password_epoch1": PASSWORD_1,
            "password_epoch2": PASSWORD_2,
            "kdf": {"name": "argon2id", "memory_kib": 131072, "iterations": 4, "parallelism": 4},
            "epochs": epochs,
            "existing_group": existing,
            "unicode_password": unicode_pw,
            "view_magic_hex": MAGIC.hex(),
            "note": "password_wrap_key_hex is the raw 32-byte Argon2id output for that epoch's "
            "password and the salt in the matching keyring (epoch 1: keyring_epoch1*.json, "
            "epoch 2: keyring_epoch2.json). member_names are the decrypted name_ct values of that "
            "epoch's keyring (keyring_epoch1.json / keyring_epoch2.json), keyed by device id.",
        }
    )


# --- fixture records ---------------------------------------------------------------------------


def web_login(item_id, label, origin, username, password, created, updated, **extra):
    record = {
        "id": item_id,
        "kind": "web",
        "label": label,
        "username": username,
        "password": password,
        "scope": {"origin": origin},
        "created_at": T0 + created,
        "updated_at": T0 + updated,
        "favorite": False,
        "tags": [],
        "policy": {"fill": "click", "require_master_password": False, "save_prompts": True},
    }
    record.update(extra)
    return record


def typed_item(item_id, kind, title, payload, created, updated, *, tags=(), favorite=False):
    return {
        "id": item_id,
        "kind": kind,
        "title": title,
        "created_at": T0 + created,
        "updated_at": T0 + updated,
        "revision": 1,
        "favorite": favorite,
        "tags": list(tags),
        "collection_ids": [],
        "payload": payload,
    }


def wrapped(ns: str, record: dict) -> dict:
    """The bridge's wrapper for *record* (validated and normalised by the bridge itself)."""
    return _wrapper(ns, record)


def fixtures() -> dict[str, dict[str, dict]]:
    """Wrapper content per device and item id (``None`` marks a tombstone, see ``views``)."""
    login_base = dict(
        origin="https://accounts.example.com",
        label="Example account",
        username="sample.user@example.com",
        created=-86400,
    )
    login_a = web_login(
        LOGIN_EDITED,
        login_base["label"],
        login_base["origin"],
        login_base["username"],
        "Maple-Orbit-7731",
        login_base["created"],
        500,
        tags=["personal"],
        notes="Password rotated from the desk PC.",
        password_history=[{"password": "hunter2-sample-only", "changed_at": T0 - 3600}],
        totp={"secret": "JBSWY3DPEHPK3PXP", "digits": 6, "period": 30, "algorithm": "SHA1"},
    )
    login_b = web_login(
        LOGIN_EDITED,
        "Example account (work)",
        login_base["origin"],
        "work.user@example.com",
        "hunter2-sample-only",
        login_base["created"],
        400,
        tags=["work"],
        notes="Renamed from the laptop.",
        recovery_codes=["7Q4K-2M9X", "B8T1-5ZHP"],
    )
    login_base_rec = web_login(
        LOGIN_EDITED,
        login_base["label"],
        login_base["origin"],
        login_base["username"],
        "hunter2-sample-only",
        login_base["created"],
        -3600,
    )
    doomed = web_login(
        LOGIN_DELETED, "Old forum", "https://forum.example.org", "forum_sample", "forum-pass-sample",
        -172800, -172800, notes="Account closed; C removes this entry.",
    )
    desktop = {
        "id": DESKTOP,
        "kind": "desktop",
        "label": "Sample Mail Client",
        "username": "desk.user",
        "password": "desk-pass-sample",
        "scope": {
            "exe_path": "C:/Program Files/SampleMail/samplemail.exe",
            "exe_sha256": "ab" * 32,
            "window_title": "SampleMail - Sign in",
            "control_fingerprint": [
                {"control_type": "Edit", "name": "Username", "automation_id": "txtUser"},
                {"control_type": "Edit", "name": "Password", "automation_id": "txtPass"},
            ],
            "username_selector": {"automation_id": "txtUser"},
            "password_selector": {"automation_id": "txtPass"},
            "binding_mode": "strict",
        },
        "created_at": T0 - 7200,
        "updated_at": T0 - 7200,
        "favorite": False,
        "tags": [],
        "policy": {"fill": "click", "require_master_password": False, "save_prompts": True},
    }
    note = typed_item(
        NOTE,
        "note",
        "Wi-Fi at the cabin",
        {
            "body": "Router sits behind the pantry door.\nReset button: hold 10 s.",
            "fields": [
                {"name": "SSID", "value": "CabinNet-5G", "hidden": False},
                {"name": "Passphrase", "value": "pine-cone-lantern-88", "hidden": True},
            ],
            "template_id": None,
        },
        -43200,
        -43200,
        tags=["home"],
        favorite=True,
    )
    bookmark_base = typed_item(
        BOOKMARK, "bookmark", "Bank help page",
        {"url": "https://www.example.net/help", "notes": "Opening hours.", "template_id": None},
        -86400, -86400,
    )
    bookmark_b = typed_item(
        BOOKMARK, "bookmark", "Bank help page",
        {"url": "https://www.example.net/help/contact", "notes": "Opening hours and phone.", "template_id": None},
        -86400, 450,
    )
    note_unicode = typed_item(
        NOTE_UNICODE,
        "note",
        'Z\u00fcrich trip \u2708 "caf\u00e9" back\\slash',
        {
            "body": "Gr\u00fc\u00dfe aus Z\u00fcrich \U0001f511\n\tTab, \"quotes\", back\\slash, slash/ok, \u00e9\u4e2d\u6587",
            "fields": [{"name": "Hotel", "value": "H\u00f4tel du Lac", "hidden": False}],
            "template_id": None,
        },
        300,
        300,
        tags=["travel"],
    )
    # Equal updated_at: the engine ranks by sha256 of the canonical item. The custom field row
    # carries canonical-JSON edge cases: keys that sort differently by code point and by UTF-16
    # ("ｚ" U+FF5A vs "\U0001f511" U+1F511), and floats/ints with fixed Python repr output.
    tie_extras = [
        {
            "a": "ascii",
            "é": "e-acute",
            "ｚ": "fullwidth z",
            "\U0001f511": "key emoji",
            "f_0_1": 0.1,
            "f_1e-07": 1e-07,
            "f_1e+16": 1e16,
            "f_100": 100.0,
            "f_neg_zero": -0.0,
            "i_2p62": 2**62,
        }
    ]
    tie_base = dict(
        origin="https://café.example.com", username="user@café.example.com", created=-5000,
    )
    login_tie_base = web_login(
        LOGIN_TIE, "Café Zürich", tie_base["origin"], tie_base["username"],
        "base-pass-sample", tie_base["created"], -2000,
    )
    login_tie_a = web_login(
        LOGIN_TIE, "Café Zürich ☕", tie_base["origin"], tie_base["username"],
        "tie-pass-from-A", tie_base["created"], 600,
        notes="Änderung auf dem Desktop — 中文", custom_fields=tie_extras,
    )
    login_tie_b = web_login(
        LOGIN_TIE, "Café Zürich \U0001f511", tie_base["origin"], tie_base["username"],
        "tie-pass-from-B", tie_base["created"], 600,
        notes="Changement sur l'ordinateur portable — café", custom_fields=tie_extras,
    )
    return {
        "login_tie_base": wrapped("entry", login_tie_base),
        "login_tie_a": wrapped("entry", login_tie_a),
        "login_tie_b": wrapped("entry", login_tie_b),
        "login_a": wrapped("entry", login_a),
        "login_b": wrapped("entry", login_b),
        "login_base": wrapped("entry", login_base_rec),
        "doomed": wrapped("entry", doomed),
        "desktop": wrapped("entry", desktop),
        "note": wrapped("item", note),
        "bookmark_base": wrapped("item", bookmark_base),
        "bookmark_b": wrapped("item", bookmark_b),
        "note_unicode": wrapped("item", note_unicode),
    }


def device_states() -> dict[str, list[ItemState]]:
    """The engine states each device publishes at epoch 1.

    Version vectors are what the vault bridge would hold: A created everything except the desktop
    entry and the unicode note (B did), then A and B edited the login concurrently, B edited the
    bookmark, and C deleted the old login and the bookmark.
    """
    f = fixtures()

    def live(item_id, vv, wrapper):
        return ItemState(item_id, vv, False, None, wrapper)

    def tomb(item_id, vv, at):
        return ItemState(item_id, vv, True, T0 + at, None)

    a, b, c = DEVICE_IDS["A"], DEVICE_IDS["B"], DEVICE_IDS["C"]
    return {
        "A": [
            live(LOGIN_EDITED, {a: 2}, f["login_a"]),
            live(NOTE, {a: 1}, f["note"]),
            live(DESKTOP, {b: 1}, f["desktop"]),
            live(LOGIN_DELETED, {a: 1}, f["doomed"]),
            live(BOOKMARK, {a: 1}, f["bookmark_base"]),
            live(LOGIN_TIE, {a: 2}, f["login_tie_a"]),
        ],
        "B": [
            live(LOGIN_EDITED, {a: 1, b: 1}, f["login_b"]),
            live(NOTE, {a: 1}, f["note"]),
            live(DESKTOP, {b: 1}, f["desktop"]),
            live(LOGIN_DELETED, {a: 1}, f["doomed"]),
            live(BOOKMARK, {a: 1, b: 1}, f["bookmark_b"]),
            live(NOTE_UNICODE, {b: 1}, f["note_unicode"]),
            live(LOGIN_TIE, {a: 1, b: 1}, f["login_tie_b"]),
        ],
        "C": [
            live(LOGIN_EDITED, {a: 1}, f["login_base"]),
            live(NOTE, {a: 1}, f["note"]),
            live(DESKTOP, {b: 1}, f["desktop"]),
            tomb(LOGIN_DELETED, {a: 1, c: 1}, 300),
            tomb(BOOKMARK, {a: 1, c: 1}, 350),
            live(LOGIN_TIE, {a: 1}, f["login_tie_base"]),
        ],
    }


def encode_devices(gk1: GroupKey, states: dict[str, list[ItemState]]) -> dict[str, bytes]:
    out = {}
    for name in DEVICES:
        counter, written = VIEW_HEADERS[name]
        out[name] = encode_view(
            gk1,
            DEVICE_IDS[name],
            counter,
            states[name],
            T0 + written,
            nonce_source=DetRand(f"view|{name}"),
        )
    return out


DEVICES = ("A", "B", "C")


# --- merge expectations --------------------------------------------------------------------------


def dump_states(states) -> list[dict]:
    return [
        {
            "id": s.item_id,
            "vv": s.vv,
            "deleted": s.deleted,
            "deleted_at": s.deleted_at,
            "item": s.item,
            # sha256 hex of canonical_json(item) (see keyring.py "Canonical JSON"); null for tombstones
            "canonical_sha256": None if s.item is None else hashlib.sha256(canonical_json(s.item)).hexdigest(),
        }
        for s in sorted(states, key=lambda s: s.item_id)
    ]


def fold(order, views) -> tuple[dict[str, ItemState], list[dict]]:
    """Merge the device views in *order*: the first is local, each later one is merged into it."""
    local = {s.item_id: s for s in views[order[0]]}
    steps = []
    for name in order[1:]:
        outcome = merge(local, views[name])
        steps.append(
            {
                "local": "+".join(order[: len(steps) + 1]),
                "remote": name,
                "upserts": sorted(s.item_id for s in outcome.upserts),
                "deletes": sorted(s.item_id for s in outcome.deletes),
                "copies": sorted(s.item_id for s in outcome.copies),
                "conflicts": sorted(loc.item_id for loc, _remote in outcome.conflicts),
            }
        )
        for state in (*outcome.upserts, *outcome.deletes, *outcome.copies):
            local[state.item_id] = state
    return local, steps


def bridge_stored_form(local: dict[str, ItemState]) -> tuple[list[dict], list[dict]]:
    """What ``vault_bridge.apply`` stores for the engine result.

    Only conflict copies differ: the bridge sets the record id to the copy id and appends
    ``CONFLICT_SUFFIX`` to the entry ``label`` (typed items: ``title``), then re-normalises.
    """
    originals = {s.item_id for s in local.values() if "id" not in (s.item or {})}
    stored = []
    copy_info: list[dict[str, Any]] = []
    for state in sorted(local.values(), key=lambda s: s.item_id):
        if state.deleted or state.item_id in originals:
            stored.append(state)
            continue
        wrapper = json.loads(canonical_json(state.item))
        original_id = wrapper["record"]["id"]
        wrapper.pop("id")
        record = wrapper["record"]
        record["id"] = state.item_id
        key = "label" if wrapper["ns"] == "entry" else "title"
        record[key] = record[key] + CONFLICT_SUFFIX
        normalised = _wrapper(wrapper["ns"], record)
        stored.append(ItemState(state.item_id, state.vv, False, None, normalised))
        loser = json.loads(canonical_json(state.item))
        loser.pop("id")
        digest = hashlib.sha256(canonical_json(loser)).hexdigest()
        assert conflict_copy_id(original_id, digest) == state.item_id
        copy_info.append(
            {
                "copy_id": state.item_id,
                "original_id": original_id,
                "content_digest": digest,
                "loser_wrapper": loser,
            }
        )
    return dump_states(stored), copy_info


def expected_merge_json(views: dict[str, list[ItemState]]) -> bytes:
    orders = [("A", "B", "C"), ("C", "B", "A")]
    results = {}
    for order in orders:
        local, steps = fold(order, views)
        results["".join(order)] = (local, steps)
    final_a = results["ABC"][0]
    final_c = results["CBA"][0]
    assert dump_states(final_a.values()) == dump_states(final_c.values()), "merge must not depend on order"
    stored, copy_info = bridge_stored_form(final_a)
    return dumps(
        {
            "description": "Final state after merging the three device files in any order "
            "(see README.md). engine_states is the engine result (what merge returns, applied to "
            "the local map). bridge_stored_states is the same set as the vault bridge stores it: "
            "identical except that the conflict copy has no top-level 'id', its record id is the "
            "copy id and its label carries the ' (sync conflict)' suffix.",
            "conflict_suffix": CONFLICT_SUFFIX,
            "engine_states": dump_states(final_a.values()),
            "bridge_stored_states": stored,
            "conflict_copies": copy_info,
            "fold_steps": {
                "ABC": results["ABC"][1],
                "CBA": results["CBA"][1],
            },
            "notes": {
                LOGIN_EDITED: "concurrent edit by A and B: A has the larger updated_at and keeps the "
                "id with the merged vector; B's version becomes the conflict copy.",
                NOTE: "unchanged everywhere.",
                DESKTOP: "unchanged everywhere.",
                LOGIN_DELETED: "C's tombstone dominates A's and B's live copies: deleted.",
                BOOKMARK: "B edited while C deleted: concurrent edit vs delete keeps the live item "
                "with the merged vector; the tombstone is not applied.",
                NOTE_UNICODE: "only B has it; exercises non-ASCII canonical JSON.",
                LOGIN_TIE: "concurrent edit with EQUAL updated_at (T0+600): the larger sha256 of the "
                "canonical item wins (digest tie-break); the other becomes a conflict copy. The "
                "custom field row holds keys a, é, U+FF5A, U+1F511 (code point order, not "
                "UTF-16) and the floats 0.1, 1e-07, 1e+16, 100.0, -0.0 plus the int 2**62.",
            },
        }
    )


# --- LAN files ----------------------------------------------------------------------------------


def lan_files(identities: dict[str, DeviceIdentity], gk1: GroupKey) -> dict[str, bytes]:
    rand = DetRand("lan")
    inviter, invitee = identities["A"], identities["B"]
    offer = PairingOffer(
        offer_id="d4e5f6a7-0b1c-4d2e-8f30-415263748596",
        group_id=GROUP_ID,
        endpoint_host="192.168.1.20",
        endpoint_port=48201,
        inviter_device_id=inviter.device_id,
        inviter_signing_public=inviter.signing_public_key,
        inviter_exchange_public=inviter.exchange_public_key,
        certificate_fingerprint=inviter.fingerprint,
        expires_at=T0 + 120,  # an int: whole seconds (pairing.py format rules)
        transcript_nonce=rand(32),
        pairing_secret=rand(32),
        code="04817352",
    )
    qr = offer_qr_payload(offer)
    parsed = parse_qr_payload(qr)
    now = T0 + 30
    from localvault.sync import pairing as pr

    def pub(seed_bytes: bytes) -> bytes:
        return pr._public_bytes(x25519.X25519PrivateKey.from_private_bytes(seed_bytes).public_key())

    def exchange(seed_bytes: bytes, peer_public: bytes) -> bytes:
        return x25519.X25519PrivateKey.from_private_bytes(seed_bytes).exchange(
            x25519.X25519PublicKey.from_public_bytes(peer_public)
        )

    def enroll(endpoint, name):
        """One request + reply round; returns (request, reply, expected-dict fragment)."""
        req_eph, req_nonce = rand(32), rand(12)
        request = build_enrollment_request(
            offer, invitee, endpoint=endpoint, name=name, now=now, _eph_seed=req_eph, _nonce=req_nonce
        )
        _peer, verified = PairingSession(offer).accept_enrollment(inviter, request, now=now)
        assert verified.name == name
        rep_eph, rep_nonce = rand(32), rand(12)
        reply = seal_enrollment_reply(
            inviter, offer, verified, GROUP_ID, gk1.epoch, gk1.key, _eph_seed=rep_eph, _nonce=rep_nonce
        )
        group_id, epoch, key = open_enrollment_reply(offer, invitee, reply, endpoint=endpoint, name=name)
        assert (group_id, epoch, key) == (GROUP_ID, gk1.epoch, gk1.key)
        # the verification code, recomputed from the documented recipe
        digest = hashlib.sha256(b"localgatekeys|sync|enroll-verify|v2|" + verified.transcript).digest()
        code = f"{int.from_bytes(digest[:4], 'big') % 10**6:06d}"
        assert code == verified.code == pr.verification_code(verified.transcript)

        bound = hashlib.sha256(verified.transcript).digest()
        offer_id = offer.offer_id.encode("ascii")
        # request: recompute the HKDF key and decrypt independently of pairing's helpers
        req_key = pr._hkdf(exchange(req_eph, offer.inviter_exchange_public), offer.transcript_nonce,
                           pr._REQUEST_INFO + offer_id)
        outer = json.loads(request[len(pr.ENROLL_REQUEST_MAGIC):])
        req_aad = pr._canonical({"offer_id": outer["offer_id"], "eph": outer["eph"]})
        req_plain = AESGCM(req_key).decrypt(base64.b64decode(outer["nonce"]), base64.b64decode(outer["ct"]), req_aad)
        # reply
        rep_key = pr._hkdf(exchange(rep_eph, invitee.exchange_public_key), bound, pr._REPLY_INFO + offer_id)
        outer = json.loads(reply[len(pr.ENROLL_REPLY_MAGIC):])
        rep_header = pr._canonical({"eph": outer["eph"], "nonce": outer["nonce"]})
        rep_plain = AESGCM(rep_key).decrypt(
            base64.b64decode(outer["nonce"]), base64.b64decode(outer["ct"]), rep_header + bound
        )
        return request, reply, {
            "request": {
                "device_id": verified.device_id,
                "name": name,
                "verification_code": code,
                "invitee_endpoint": None if endpoint is None else {"host": endpoint[0], "port": endpoint[1]},
                "endpoint_list": None if endpoint is None else [endpoint[0], endpoint[1]],
                "transcript": verified.transcript.decode("ascii"),
                "transcript_sha256_hex": bound.hex(),
                "ephemeral_private_hex": req_eph.hex(),
                "ephemeral_public_b64": b64(pub(req_eph)),
                "nonce_b64": b64(req_nonce),
                "hkdf_key_hex": req_key.hex(),
                "aad": req_aad.decode("ascii"),
                "plaintext": req_plain.decode("ascii"),
            },
            "reply": {
                "group_id": group_id,
                "epoch": epoch,
                "key_hex": key.hex(),
                "key_b64": b64(key),
                "ephemeral_private_hex": rep_eph.hex(),
                "ephemeral_public_b64": b64(pub(rep_eph)),
                "nonce_b64": b64(rep_nonce),
                "hkdf_key_hex": rep_key.hex(),
                "aad_hex": (rep_header + bound).hex(),
                "plaintext": rep_plain.decode("ascii"),
            },
        }

    request, reply, with_endpoint = enroll(("192.168.1.31", 48202), DEVICE_NAMES["B"])
    # a non-ASCII name: the canonical JSON escapes it (\u2019, \u00e9) in the body and the transcript
    request2, reply2, without_endpoint = enroll(None, "Ilias\u2019s iPhone \u00e9")
    expected = {
        "description": "QR enrollment (version 2: device name, verification code, Accept step) of device B "
        "by device A at epoch 1 (see README.md). Top-level request/reply: B announces its listening "
        "endpoint; request_no_endpoint/reply_no_endpoint: B announces none (invitee_endpoint is null in "
        "the body and the transcript) and a non-ASCII name.",
        "now": now,
        "qr_payload": qr,
        "offer_bundle": parsed,
        **with_endpoint,
        "request_no_endpoint": without_endpoint["request"],
        "reply_no_endpoint": without_endpoint["reply"],
        "framing": {
            "request_magic": "LGKENROLL1\\n",
            "request_magic_hex": pr.ENROLL_REQUEST_MAGIC.hex(),
            "reply_magic": "LGKENROLLOK1\\n",
            "reply_magic_hex": pr.ENROLL_REPLY_MAGIC.hex(),
            "refused_magic": "LGKENROLLNO1\\n",
            "refused_magic_hex": pr.ENROLL_REFUSED_MAGIC.hex(),
            "refusals_hex": {reason: pr.enrollment_refusal(reason).hex() for reason in sorted(pr.REFUSAL_REASONS)},
            "json": "pairing._canonical: sorted keys, compact, ensure_ascii=True (differs from "
            "the sealed-view canonical JSON, which keeps non-ASCII literally)",
        },
    }
    return {
        "lan/qr_payload.txt": qr.encode("ascii"),
        "lan/enroll_request.bin": request,
        "lan/enroll_reply.bin": reply,
        "lan/enroll_request_no_endpoint.bin": request2,
        "lan/enroll_reply_no_endpoint.bin": reply2,
        "lan/expected_lan.json": dumps(expected),
    }


# --- LAN session, frames and messages -----------------------------------------------------------

#: The LAN view the 2-chunk exchange carries is CHUNK_BYTES + at least this many bytes.
VIEW_EXTRA_BYTES = 1000
#: Filler items in each LAN view: FILLER_FIXED items with FILLER_PAD notes characters, plus one
#: last item whose notes length is the smallest that makes the encoded view reach the target size.
FILLER_FIXED = 19
FILLER_PAD = 20000

def filler_view(gk: GroupKey, name: str) -> tuple[bytes, dict[str, Any]]:
    """A real ``encode_view`` output of deterministic filler login states, just over one chunk.

    The size is the smallest the encoding reaches that is at least ``CHUNK_BYTES + VIEW_EXTRA_BYTES``
    (sizes move in steps of 4 bytes because of base64, so the exact target may be skipped).
    """
    device_id = DEVICE_IDS[name]
    counter, written = VIEW_HEADERS[name]
    target = CHUNK_BYTES + VIEW_EXTRA_BYTES
    prefix = name.lower()

    def build(last_pad: int) -> bytes:
        rand = DetRand(f"lan|filler|{name}")
        states = []
        for index, pad in enumerate([FILLER_PAD] * FILLER_FIXED + [last_pad]):
            item_id = f"f{prefix}{index:06d}-aaaa-4000-8000-{index:012d}"
            notes = rand((pad + 1) // 2).hex()[:pad]
            record = web_login(item_id, f"Filler {name}{index}", "https://filler.example.com",
                               "filler.user", "filler-password", 0, 10, notes=notes)
            states.append(ItemState(item_id, {device_id: 1}, False, None, wrapped("entry", record)))
        return encode_view(gk, device_id, counter, states, T0 + written,
                           nonce_source=DetRand(f"lan|filler-nonce|{name}"))

    low, high = 0, FILLER_PAD
    assert len(build(high)) >= target
    while low < high:
        mid = (low + high) // 2
        if len(build(mid)) >= target:
            high = mid
        else:
            low = mid + 1
    raw = build(low)
    assert len(raw) >= target and (low == 0 or len(build(low - 1)) < target)
    return raw, {
        "device": name,
        "device_id": device_id,
        "header_counter": counter,
        "written_at": T0 + written,
        "items": FILLER_FIXED + 1,
        "notes_characters_per_fixed_item": FILLER_PAD,
        "notes_characters_last_item": low,
        "size": len(raw),
        "sha256": hashlib.sha256(raw).hexdigest(),
    }


def paired(identity: DeviceIdentity) -> PairedDevice:
    """The trust record a peer pins for *identity* (the enrollment signature is not part of a session)."""
    return PairedDevice(identity.device_id, GROUP_ID, identity.signing_public_key,
                        identity.exchange_public_key, identity.fingerprint, float(T0 + 30), bytes(64))


class LanSession:
    """One LAN connection: *initiator* and the other device, fixed session id, hello nonces and
    ephemeral keys (protocol version 2).

    The desktop opens one connection per request/response (``sync_with`` makes a new connection,
    hello pair, session id and key for every chunk request), so every frame counter here is 1.
    """

    def __init__(self, label: str, identities: dict[str, DeviceIdentity], *, initiator: str = "A",
                 counters: tuple[int, int] = (1, 1)) -> None:
        self.label = label
        self.initiator_name = initiator
        self.responder_name = "B" if initiator == "A" else "A"
        self.session_id = seed(f"lan|{label}|session-id")[:16]
        self.a, self.b = identities[self.initiator_name], identities[self.responder_name]
        self.counters = counters
        self.eph = {role: seed(f"lan|{label}|ephemeral|{role}") for role in ("initiator", "responder")}
        self.hello_a = create_session_hello(self.a, GROUP_ID, self.session_id, counter=counters[0],
                                            _nonce=seed(f"lan|{label}|hello-nonce|initiator"),
                                            _ephemeral=self.eph["initiator"])
        self.hello_b = create_session_hello(self.b, GROUP_ID, self.session_id, counter=counters[1],
                                            _nonce=seed(f"lan|{label}|hello-nonce|responder"),
                                            _ephemeral=self.eph["responder"])
        self.initiator = SecureChannel.from_paired_identities(
            self.a, paired(self.b), group_id=GROUP_ID, session_id=self.session_id, role="initiator",
            local_hello=self.hello_a, remote_hello=self.hello_b)
        self.responder = SecureChannel.from_paired_identities(
            self.b, paired(self.a), group_id=GROUP_ID, session_id=self.session_id, role="responder",
            local_hello=self.hello_b, remote_hello=self.hello_a)
        # The key again, derived here from the documented recipe and not from transport.py.
        ordered = sorted((self.hello_a.to_bytes(), self.hello_b.to_bytes()))
        self.transcript = b"".join(ordered)
        self.sorted_first = "initiator" if ordered[0] == self.hello_a.to_bytes() else "responder"
        self.shared = self.a.exchange_key.exchange(
            x25519.X25519PublicKey.from_public_bytes(self.b.exchange_public_key))
        self.ephemeral_shared = x25519.X25519PrivateKey.from_private_bytes(self.eph["initiator"]).exchange(
            x25519.X25519PublicKey.from_public_bytes(self.hello_b.ephemeral_public))
        assert self.ephemeral_shared == x25519.X25519PrivateKey.from_private_bytes(self.eph["responder"]).exchange(
            x25519.X25519PublicKey.from_public_bytes(self.hello_a.ephemeral_public))
        self.salt = hashlib.sha256(b"localgatekeys|sync|session-salt|v2|" + self.transcript).digest()
        self.info = b"localgatekeys|sync|session-key|v2|" + self.session_id
        self.ikm = self.ephemeral_shared + self.shared
        self.key = HKDF(algorithm=hashes.SHA256(), length=32, salt=self.salt, info=self.info).derive(self.ikm)
        assert self.key == self.initiator._key == self.responder._key
        # both ephemeral secrets were used up by the two derivations
        assert self.hello_a.ephemeral_secret.used and self.hello_b.ephemeral_secret.used
        self.prefix = {role: hashlib.sha256(self.key + b"send|" + role.encode()).digest()[:4]
                       for role in ("initiator", "responder")}
        assert self.prefix["initiator"] == self.initiator._send_prefix
        assert self.prefix["responder"] == self.responder._send_prefix

    def hello_json(self) -> dict[str, Any]:
        def one(hello, name, role):
            return {
                "device": name,
                "counter": hello.counter,
                "text": hello.to_bytes().decode("ascii"),
                "signing_input_hex": hello.signing_bytes().hex(),
                "nonce_hex": hello.nonce.hex(),
                "ephemeral_private_hex": self.eph[role].hex(),
                "ephemeral_public_hex": hello.ephemeral_public.hex(),
            }
        return {"initiator": one(self.hello_a, self.initiator_name, "initiator"),
                "responder": one(self.hello_b, self.responder_name, "responder")}

    def key_json(self) -> dict[str, Any]:
        return {
            "initiator_device": self.initiator_name,
            "responder_device": self.responder_name,
            "session_id": self.session_id.hex(),
            "hello": self.hello_json(),
            "transcript_sorted_hex": self.transcript.hex(),
            "sorted_first": self.sorted_first,
            "shared_secret_hex": self.shared.hex(),
            "ephemeral_shared_secret_hex": self.ephemeral_shared.hex(),
            "ikm_hex": self.ikm.hex(),
            "salt": self.salt.hex(),
            "info_hex": self.info.hex(),
            "key": self.key.hex(),
            "prefix_initiator": self.prefix["initiator"].hex(),
            "prefix_responder": self.prefix["responder"].hex(),
        }

    def seal(self, role: str, plaintext: bytes) -> tuple[dict[str, Any], bytes]:
        """Seal *plaintext* on the channel of *role*; returns (frame description, frame bytes).

        The nonce, the AAD and the decryption are recomputed here from the documented rules.
        """
        sender, receiver = (
            (self.initiator, self.responder) if role == "initiator" else (self.responder, self.initiator))
        frame = sender.seal(plaintext)
        assert int.from_bytes(frame[:4], "big") == len(frame) - 4
        outer = json.loads(frame[4:])
        counter = outer["counter"]
        assert counter == 1, "one request and one response per connection"
        nonce = self.prefix[role] + counter.to_bytes(8, "big")
        metadata = {"version": 2, "session_id": b64(self.session_id), "counter": counter, "nonce": b64(nonce)}
        aad = json.dumps(metadata, ensure_ascii=True, separators=(",", ":"), sort_keys=True).encode("ascii")
        assert {k: v for k, v in outer.items() if k != "ciphertext"} == metadata
        assert AESGCM(self.key).decrypt(nonce, base64.b64decode(outer["ciphertext"]), aad) == plaintext
        assert receiver.open(frame) == plaintext
        return {
            "sender": role,
            "counter": counter,
            "nonce": nonce.hex(),
            "aad": aad.decode("ascii"),
            "plaintext_size": len(plaintext),
            "plaintext_sha256": hashlib.sha256(plaintext).hexdigest(),
            "frame_size": len(frame),
            "frame_sha256": hashlib.sha256(frame).hexdigest(),
        }, frame

    def round_trip(self, request: bytes, response: bytes) -> tuple[dict[str, Any], bytes, dict[str, Any], bytes]:
        """The one request and one response of this connection."""
        req, req_frame = self.seal("initiator", request)
        resp, resp_frame = self.seal("responder", response)
        return req, req_frame, resp, resp_frame


#: The documented LAN address table (``tests/test_sync_lan_address.py`` runs it too): address text and
#: whether ``is_lan_address`` accepts it.  An IPv6 zone id (``%eth0``, ``%1``) is never accepted.
LAN_RANGE_CASES: tuple[tuple[str, bool], ...] = (
    ("10.1.2.3", True), ("172.31.255.255", True), ("172.32.0.1", False), ("192.168.1.20", True),
    ("169.254.9.9", True), ("127.0.0.1", True), ("100.64.0.1", False), ("192.0.2.1", False),
    ("8.8.8.8", False), ("0.0.0.0", False), ("224.0.0.1", False), ("::1", True), ("fe80::1", True),  # noqa: S104
    ("fd12:3456::1", True), ("2001:db8::1", False), ("::ffff:192.168.1.1", False), ("::", False),
    ("fe80::1%eth0", False), ("fe80::1%1", False),
)


def legacy_hello(identities: dict[str, DeviceIdentity]) -> dict[str, Any]:
    """A signed version-1 hello of B (no ephemeral key): a version-2 responder must refuse it with
    ``version_refusal`` and may verify the signature only to report that B needs an update."""
    b = identities["B"]
    unsigned = {"version": 1, "session_id": b64(seed("lan|legacy|session-id")[:16]), "group_id": GROUP_ID,
                "device_id": b.device_id, "signing_public": b64(b.signing_public_key),
                "exchange_public": b64(b.exchange_public_key), "nonce": b64(seed("lan|legacy|nonce")),
                "counter": 5}
    canonical = json.dumps(unsigned, ensure_ascii=True, separators=(",", ":"), sort_keys=True).encode("ascii")
    signature = b.sign(b"localgatekeys|sync|session-hello|v1|" + canonical)
    text = json.dumps({**unsigned, "signature": b64(signature)}, ensure_ascii=True, separators=(",", ":"),
                      sort_keys=True)
    return {"device": "B", "text": text}


def prefixed(payload: bytes) -> bytes:
    return len(payload).to_bytes(4, "big") + payload


#: Inline the plaintext in messages.json only below this size.
INLINE_LIMIT = 4096


def lan_session_files(identities: dict[str, DeviceIdentity], gk1: GroupKey) -> tuple[dict[str, bytes], dict[str, Any]]:
    files: dict[str, bytes] = {}

    # session.json: three connections whose transcript order differs (see README). Each has the one
    # request and one response of a real connection: a `next` for a transfer the responder never
    # started, answered with the `bad-chunk` error.
    def refused_next(label: str) -> tuple[bytes, bytes]:
        transfer = seed(f"lan|{label}|transfer").hex()[:32]
        return (encode_message({"type": "next", "transfer": transfer, "seq": 1}),
                encode_message({"type": "error", "reason": "bad-chunk"}))

    variants = [
        ("a-initiates", "A", (1, 1)),
        ("b-initiates", "B", (1, 1)),
        ("counters-9-10", "A", (9, 10)),
    ]
    sessions = []
    for name, initiator, counters in variants:
        session = LanSession(name, identities, initiator=initiator, counters=counters)
        request, response = refused_next(name)
        req, req_frame, resp, resp_frame = session.round_trip(request, response)
        for entry, text in ((req, request), (resp, response)):
            entry["plaintext"] = text.decode("ascii")
        entry = {"name": name, **session.key_json(),
                 "request": {**req, "frame_hex": req_frame.hex()},
                 "response": {**resp, "frame_hex": resp_frame.hex()}}
        sessions.append(entry)
        if name == "a-initiates":
            assert session.sorted_first == "initiator"
            files["lan/hello_initiator.bin"] = prefixed(session.hello_a.to_bytes())
            files["lan/hello_responder.bin"] = prefixed(session.hello_b.to_bytes())
            files["lan/frame_initiator.bin"] = req_frame
            files["lan/frame_responder.bin"] = resp_frame
        else:
            # initiator-then-responder order would give a different key here
            assert session.sorted_first == "responder"
        if name == "counters-9-10":
            assert session.hello_a.to_bytes() > session.hello_b.to_bytes() and counters[0] < counters[1]
    files["lan/session.json"] = dumps({
        "description": "Three LAN connections (protocol version 2, ephemeral keys) of A and B (group id and "
        "identities as in identities.json), each "
        "with its one sealed request and one sealed response, both with frame counter 1. The first has A "
        "as initiator and both hello counters 1, the second B as initiator, the third hello counters 9 "
        "(initiator A) and 10 (responder B), where bytewise order (counter 10 before counter 9) "
        "disagrees with numeric order and with initiator-first order. lan/hello_*.bin and lan/frame_*.bin "
        "are the first connection. Every .bin file and every frame_hex INCLUDES the 4-byte big-endian "
        "length prefix (README.md).",
        "group_id": GROUP_ID,
        "version_refusal": version_refusal().decode("ascii"),
        "legacy_hello": legacy_hello(identities),
        "sessions": sessions,
    })

    # messages: the 2-chunk exchange, one connection per request/response
    raw_a, info_a = filler_view(gk1, "A")
    raw_b, info_b = filler_view(gk1, "B")
    parts_a, parts_b = split_view(raw_a), split_view(raw_b)
    assert len(parts_a) == len(parts_b) == 2 and len(parts_a[0]) == len(parts_b[0]) == CHUNK_BYTES
    transfer_a = seed("lan|messages|transfer|initiator").hex()[:32]
    transfer_b = seed("lan|messages|transfer|responder").hex()[:32]
    flow = [
        (_view_message(gk1, transfer_a, 0, parts_a, len(raw_a)), {"type": "ack", "transfer": transfer_a, "seq": 0}),
        (_view_message(gk1, transfer_a, 1, parts_a, len(raw_a)), _view_message(gk1, transfer_b, 0, parts_b, len(raw_b))),
        ({"type": "next", "transfer": transfer_b, "seq": 1}, _view_message(gk1, transfer_b, 1, parts_b, len(raw_b))),
    ]
    connections = []
    for number, (request, response) in enumerate(flow, start=1):
        session = LanSession(f"messages-{number}", identities)
        plains = (encode_message(request), encode_message(response))
        for plain, message in zip(plains, (request, response), strict=True):
            assert parse_message(plain) == message
        req, req_frame, resp, resp_frame = session.round_trip(*plains)
        entries = {}
        for role, desc, frame, message, plain in (
                ("request", req, req_frame, request, plains[0]), ("response", resp, resp_frame, response, plains[1])):
            name = f"messages/{number:02d}_{role}_{message['type']}_{message['seq']}.bin"
            files[f"lan/{name}"] = frame
            entry = {"type": message["type"], "seq": message["seq"], "transfer": message["transfer"],
                     "file": name, **desc}
            if len(plain) < INLINE_LIMIT:
                entry["plaintext"] = plain.decode("ascii")
            entries[role] = entry
        connections.append({"connection": number, **session.key_json(), **entries})
    # every reason a responder can send; the sealed example of an error is session.json "response"
    errors = [{"reason": reason, "plaintext": encode_message({"type": "error", "reason": reason}).decode("ascii")}
              for reason in ERROR_REASONS]
    for error in errors:
        assert parse_message(error["plaintext"].encode("ascii"))["reason"] == error["reason"]
    files["lan/messages.json"] = dumps({
        "description": "A 2-chunk view exchange between A (initiator, view of A) and B (responder, view of B). "
        "The protocol is one request and one response per connection, so each of the three connections has "
        "its own hello pair, session id and key, and every frame has counter 1. Each sealed frame is its "
        "own .bin file under lan/messages/ (with the 4-byte length prefix); the plaintext is inline only "
        "when it is under 4096 bytes, otherwise check plaintext_size and plaintext_sha256. errors lists the "
        "plaintext of one error message per reason; lan/session.json holds a sealed error frame.",
        "group_id": GROUP_ID,
        "epoch": gk1.epoch,
        "chunk_bytes": CHUNK_BYTES,
        "views": {
            "initiator": {**info_a, "transfer": transfer_a, "total": 2, "chunk_sizes": [len(p) for p in parts_a]},
            "responder": {**info_b, "transfer": transfer_b, "total": 2, "chunk_sizes": [len(p) for p in parts_b]},
        },
        "connections": connections,
        "errors": errors,
    })

    cases = LAN_RANGE_CASES
    for text, ok in cases:
        assert is_lan_address(ipaddress.ip_address(text)) is ok
    files["lan/lan_ranges.json"] = dumps({
        "description": "The explicit LAN address ranges (lan_address.LAN_NETWORKS) and the "
        "test_lan_address_table cases with the expected result of is_lan_address. An IPv4-mapped IPv6 "
        "address is never accepted, nor is an IPv6 address with a zone id.",
        "networks": [str(n) for n in LAN_NETWORKS],
        "cases": [{"address": text, "lan": ok} for text, ok in cases],
    })
    facts = {"size_a": info_a["size"], "size_b": info_b["size"], "chunk_1_a": info_a["size"] - CHUNK_BYTES,
             "chunk_1_b": info_b["size"] - CHUNK_BYTES, "last_a": info_a["notes_characters_last_item"],
             "last_b": info_b["notes_characters_last_item"]}
    return files, facts


# --- normalisation vectors -------------------------------------------------------------------------

NORM_ID = "88888888-aaaa-4000-8000-000000000008"


def _entry_base(**over: Any) -> dict:
    """A complete valid web login; each case varies one field of it."""
    rec = web_login(
        NORM_ID, "Norm login", "https://example.com", "norm.user", "norm-pass-sample", -100, -50,
    )
    rec.update(over)
    return rec


def _entry_with_scope(**scope: Any) -> dict:
    return _entry_base(scope=scope)


def _desktop_base(**scope: Any) -> dict:
    base_scope = {
        "exe_path": "C:/Program Files/SampleMail/samplemail.exe",
        "exe_sha256": "ab" * 32,
        "window_title": "SampleMail - Sign in",
        "control_fingerprint": [{"control_type": "Edit", "name": "Username", "automation_id": "txtUser"}],
        "username_selector": {"automation_id": "txtUser"},
        "password_selector": {"automation_id": "txtPass"},
        "binding_mode": "strict",
    }
    base_scope.update(scope)
    return _entry_base(scope=base_scope, kind="desktop", label="Norm desktop")


def _norm_cases_entries() -> list[tuple[str, dict]]:
    cases: list[tuple[str, dict]] = []

    def add(name: str, record: dict) -> None:
        cases.append((name, record))

    add("plain_web_login", _entry_base())
    # origins
    for name, origin in (
        ("origin_upper_case_scheme_and_host", "HTTPS://Example.COM"),
        ("origin_default_https_port", "https://example.com:443"),
        ("origin_trailing_dot", "https://example.com."),
        ("origin_ipv6_upper_case_with_port", "https://[2001:DB8::1]:8443"),
        ("origin_localhost_http_with_port", "http://localhost:8080"),
        ("origin_plain_http_rejected", "http://example.com"),
        ("origin_idna_umlaut", "https://b\u00fccher.example"),
        ("origin_idna_sharp_s_non_transitional", "https://fa\u00df.de"),
        ("origin_idna_japanese", "https://\u4f8b\u3048.\u30c6\u30b9\u30c8"),
        ("origin_with_path_rejected", "https://example.com/login"),
    ):
        add(name, _entry_with_scope(origin=origin))
    # scope.urls
    add("urls_bare_string_row", _entry_with_scope(origin="https://example.com", urls=["https://app.example.com"]))
    add("urls_each_match_mode", _entry_with_scope(origin="https://example.com", urls=[
        {"url": "https://a.example.com", "match": "exact_origin"},
        {"url": "https://b.example.com", "match": "host"},
        {"url": "https://c.example.com", "match": "base_domain"},
        {"url": "https://d.example.com", "match": "starts_with"},
    ]))
    add("urls_duplicate_row_dropped", _entry_with_scope(origin="https://example.com", urls=[
        "https://app.example.com", {"url": "HTTPS://App.Example.com", "match": "host"},
        {"url": "https://app.example.com", "match": "host"},
    ]))
    add("urls_bad_match_mode", _entry_with_scope(origin="https://example.com", urls=[
        {"url": "https://a.example.com", "match": "regex"},
    ]))
    # TOTP
    add("totp_minimal", _entry_base(totp={"secret": "JBSWY3DPEHPK3PXP"}))
    add("totp_all_fields", _entry_base(totp={
        "secret": "jbswy3dpehpk3pxp", "digits": 8, "period": 60, "algorithm": "SHA256",
        "issuer": "Example", "account": "norm.user",
    }))
    add("totp_digits_7", _entry_base(totp={"secret": "JBSWY3DPEHPK3PXP", "digits": 7}))
    add("totp_period_15", _entry_base(totp={"secret": "JBSWY3DPEHPK3PXP", "period": 15}))
    add("totp_period_120", _entry_base(totp={"secret": "JBSWY3DPEHPK3PXP", "period": 120}))
    add("totp_extra_scalar_key", _entry_base(totp={"secret": "JBSWY3DPEHPK3PXP", "note": "kept"}))
    for name, totp in (
        ("totp_digits_5_rejected", {"secret": "JBSWY3DPEHPK3PXP", "digits": 5}),
        ("totp_digits_9_rejected", {"secret": "JBSWY3DPEHPK3PXP", "digits": 9}),
        ("totp_digits_as_text_rejected", {"secret": "JBSWY3DPEHPK3PXP", "digits": "6"}),
        ("totp_digits_as_bool_rejected", {"secret": "JBSWY3DPEHPK3PXP", "digits": True}),
        ("totp_period_14_rejected", {"secret": "JBSWY3DPEHPK3PXP", "period": 14}),
        ("totp_period_121_rejected", {"secret": "JBSWY3DPEHPK3PXP", "period": 121}),
        ("totp_algorithm_not_text_rejected", {"secret": "JBSWY3DPEHPK3PXP", "algorithm": 5}),
        ("totp_secret_not_text_rejected", {"secret": 5}),
        ("totp_algorithm_unknown_name_kept", {"secret": "JBSWY3DPEHPK3PXP", "algorithm": "MD5"}),
        ("totp_empty_secret_kept", {"secret": ""}),
        ("totp_without_secret_kept", {"digits": 6}),
        ("totp_secret_not_base32_kept", {"secret": "!!!!"}),
    ):
        add(name, _entry_base(totp=totp))
    add("totp_secret_with_spaces_and_padding", _entry_base(totp={"secret": "JBSW Y3DP EHPK 3PXP===="}))
    # custom fields
    add("custom_fields_name_value_hidden", _entry_base(custom_fields=[
        {"name": "Security answer", "value": "blue", "hidden": True},
        {"name": "Branch", "value": "Zurich", "hidden": False},
    ]))
    add("custom_fields_int_float_null", _entry_base(custom_fields=[
        {"name": "n", "value": 3, "ratio": 0.5, "whole": 100.0, "nothing": None, "flag": True},
    ]))
    add("custom_fields_16_keys", _entry_base(custom_fields=[{f"k{i:02d}": i for i in range(16)}]))
    add("custom_fields_17_keys_rejected", _entry_base(custom_fields=[{f"k{i:02d}": i for i in range(17)}]))
    add("custom_fields_nested_value_rejected", _entry_base(custom_fields=[{"name": "x", "value": {"a": 1}}]))
    # policy
    base_no_policy = _entry_base()
    del base_no_policy["policy"]
    add("policy_missing", base_no_policy)
    add("policy_full_dict", _entry_base(policy={"fill": "click", "require_master_password": True, "save_prompts": False}))
    add("policy_unknown_key", _entry_base(policy={"fill": "click", "require_master_password": False,
                                                  "save_prompts": True, "surprise": 1}))
    add("policy_fill_auto", _entry_base(policy={"fill": "auto", "require_master_password": False, "save_prompts": True}))
    add("policy_fill_unknown_value", _entry_base(policy={"fill": "sometimes"}))
    add("policy_is_a_list", _entry_base(policy=["fill", "click"]))
    # tags, history, misc
    add("tags_plain", _entry_base(tags=["work", "Work", "bank"]))
    add("tags_too_long_rejected", _entry_base(tags=["x" * 41]))
    add("password_history_changed_at", _entry_base(password_history=[
        {"password": "old-1", "changed_at": T0 - 100},
    ]))
    add("password_history_replaced_at", _entry_base(password_history=[
        {"password": "old-1", "replaced_at": T0 - 100},
    ]))
    add("password_history_both_times_prefers_changed_at", _entry_base(password_history=[
        {"password": "old-1", "changed_at": T0 - 100, "replaced_at": T0 - 200},
    ]))
    add("recovery_codes_and_notes", _entry_base(notes="n", recovery_codes=["AAAA-1111"]))
    add("unknown_top_level_field_rejected", _entry_base(surprise="x"))
    add("float_timestamp_rejected", _entry_base(updated_at=1.5))
    # desktop entries
    add("desktop_plain", _desktop_base())
    add("desktop_exe_sha256_upper_case", _desktop_base(exe_sha256="AB" * 32))
    add("desktop_exe_sha256_lower_case", _desktop_base(exe_sha256="cd" * 32))
    add("desktop_bad_exe_sha256", _desktop_base(exe_sha256="zz"))
    return cases


def _norm_cases_items() -> list[tuple[str, dict]]:
    cases: list[tuple[str, dict]] = []

    def item(kind: str, payload: dict, **over: Any) -> dict:
        rec = {
            "id": NORM_ID, "kind": kind, "title": f"Norm {kind}",
            "created_at": T0 - 100, "updated_at": T0 - 50, "payload": payload,
        }
        rec.update(over)
        return rec

    cases.append(("note_minimal", item("note", {})))
    cases.append(("note_full", item("note", {"body": "hello", "fields": [
        {"name": "a", "value": "b", "hidden": False}], "template_id": None},
        favorite=True, tags=["home"], revision=7, collection_ids=[])))
    cases.append(("note_already_normal", item("note", {
        "body": "hello", "fields": [{"hidden": False, "name": "a", "value": "b"}], "template_id": None,
    }, favorite=False, tags=["home"])))
    cases.append(("card_minimal", item("card", {})))
    cases.append(("identity_minimal", item("identity", {})))
    cases.append(("identity_populated", item("identity", {
        "name": "Ann Lee", "given_name": "Ann", "middle_name": "", "family_name": "Lee",
        "organization": "", "company": "Example Ltd", "job_title": "", "email": "ann@example.com",
        "phone": "", "address": "", "address_line1": "1 Main Street", "address_line2": "",
        "city": "Zurich", "state": "", "postal_code": "8001", "country": "CH",
        "website": "https://example.com",
    })))
    cases.append(("identity_template_id_null", item("identity", {"template_id": None})))
    cases.append(("identity_unknown_field_rejected", item("identity", {"first_name": "Ann"})))
    cases.append(("bookmark_minimal", item("bookmark", {"url": "https://www.example.net/help"})))
    cases.append(("bookmark_without_url_rejected", item("bookmark", {})))
    cases.append(("tags_case_fold_dedup", item("note", {}, tags=["Work", "work", "WORK", "Home"])))
    cases.append(("id_upper_case_uuid", item("note", {}, id=NORM_ID.upper())))
    cases.append(("local_only_fields_stripped", item(
        "license", {"license_value": "AAAA-BBBB", "document_ids": ["99999999-aaaa-4000-8000-000000000009"]},
        revision=3, collection_ids=["99999999-aaaa-4000-8000-00000000000a"])))
    # Kinds the phone creates and edits since it gained every synced typed kind (all but `document`).
    cases.append(("bookmark_full", item("bookmark", {"url": "http://[2001:db8::1]:8080/a?b#c", "notes": "n",
                                                     "template_id": None})))
    cases.append(("bookmark_ftp_rejected", item("bookmark", {"url": "ftp://example.com/"})))
    cases.append(("bookmark_credentials_rejected", item("bookmark", {"url": "https://me@example.com/"})))
    cases.append(("bookmark_space_rejected", item("bookmark", {"url": "https://example.com/a b"})))
    cases.append(("bookmark_no_host_rejected", item("bookmark", {"url": "https:///path"})))
    cases.append(("license_minimal", item("license", {})))
    cases.append(("license_full", item("license", {
        "license_value": "AAAA-BBBB", "product": "Editor", "vendor": "Acme", "purchase_date": "2024-02-29",
        "expiration_date": "2025-02-28", "notes": "seat 1", "template_id": None})))
    cases.append(("license_week_date", item("license", {"purchase_date": "2024W01", "expiration_date": "2024-W01-3"})))
    cases.append(("license_expiry_before_purchase_rejected", item("license", {
        "purchase_date": "2025-01-02", "expiration_date": "2025-01-01"})))
    cases.append(("license_bad_date_rejected", item("license", {"purchase_date": "2023-02-29"})))
    cases.append(("license_duplicate_document_ids_rejected", item("license", {"document_ids": [
        "99999999-aaaa-4000-8000-000000000009", "99999999-AAAA-4000-8000-000000000009"]})))
    for kind in ("purchase", "warranty", "subscription"):
        cases.append((f"{kind}_minimal", item(kind, {})))
    cases.append(("purchase_full", item("purchase", {
        "product": "Laptop", "vendor": "Shop", "provider": "", "purchase_date": "2024-05-01",
        "expiration_date": "2026-05-01", "renewal_date": "", "amount_minor": 129999, "currency": "chf",
        "notes": "", "active": False})))
    cases.append(("subscription_negative_amount", item("subscription", {"amount_minor": -500, "currency": "EUR",
                                                                        "renewal_date": "2025-06-01"})))
    cases.append(("purchase_currency_without_amount_rejected", item("purchase", {"currency": "EUR"})))
    cases.append(("purchase_amount_without_currency_rejected", item("purchase", {"amount_minor": 5})))
    cases.append(("purchase_float_amount_rejected", item("purchase", {"amount_minor": 5.0, "currency": "EUR"})))
    cases.append(("purchase_bool_amount_rejected", item("purchase", {"amount_minor": True, "currency": "EUR"})))
    cases.append(("purchase_huge_amount_rejected", item("purchase", {"amount_minor": 10**15 + 1, "currency": "EUR"})))
    cases.append(("purchase_bad_currency_rejected", item("purchase", {"amount_minor": 1, "currency": "E1R"})))
    cases.append(("warranty_renewal_before_purchase_rejected", item("warranty", {
        "purchase_date": "2024-05-01", "renewal_date": "2024-04-30"})))
    cases.append(("subscription_active_not_bool_rejected", item("subscription", {"active": 1})))
    cases.append(("bank_account_minimal", item("bank_account", {})))
    cases.append(("bank_account_iban", item("bank_account", {
        "bank": "Bank", "account_holder": "Ann Lee", "account_number": " ch93 0076 2011 6238 5295 7 ",
        "routing": " ubswchzh80a ", "pin": "1234", "notes": ""})))
    cases.append(("bank_account_other_number", item("bank_account", {"account_number": "12-345-678",
                                                                     "routing": "021000021"})))
    cases.append(("bank_account_iban_checksum_rejected", item("bank_account", {
        "account_number": "CH9400762011623852957"})))
    cases.append(("bank_account_number_format_recomputed", item("bank_account", {
        "account_number": "12345678", "number_format": "iban"})))
    cases.append(("bank_account_bad_routing_rejected", item("bank_account", {"routing": "UBS WCH"})))
    cases.append(("bank_account_short_pin_rejected", item("bank_account", {"pin": "12"})))
    cases.append(("ssh_key_minimal", item("ssh_key", {})))
    cases.append(("ssh_key_openssh", item("ssh_key", {
        "private_key": "  -----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaA==\n-----END OPENSSH PRIVATE KEY-----\n",
        "public_key": "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl ann@laptop",
        "passphrase": "pw", "fingerprint": "ignored", "key_format": "putty"})))
    cases.append(("ssh_key_encrypted_rsa", item("ssh_key", {
        "private_key": "-----BEGIN RSA PRIVATE KEY-----\nProc-Type: 4,ENCRYPTED\nDEK-Info: AES-128-CBC,00\n\nAA==\n"
                       "-----END RSA PRIVATE KEY-----"})))
    cases.append(("ssh_key_unknown_format_user_fingerprint", item("ssh_key", {
        "private_key": "not a key", "public_key": "-----BEGIN PUBLIC KEY-----", "fingerprint": "  MD5:aa:bb  "})))
    cases.append(("ssh_key_bad_base64_rejected", item("ssh_key", {"public_key": "ssh-rsa AAA*"})))
    cases.append(("ssh_key_missing_padding_rejected", item("ssh_key", {"public_key": "ssh-rsa QQ"})))
    cases.append(("api_key_minimal", item("api_key", {})))
    cases.append(("api_key_full", item("api_key", {"service": "Cloud", "key": "k", "secret": "s",
                                                   "expires": "20261231", "notes": "x"})))
    cases.append(("api_key_bad_expiry_rejected", item("api_key", {"expires": "2026-13-01"})))
    cases.append(("wifi_minimal", item("wifi", {})))
    cases.append(("wifi_full", item("wifi", {"ssid": "Home", "password": "secret", "security": " WPA3 ",
                                             "hidden": True})))
    cases.append(("wifi_blank_security_defaults", item("wifi", {"security": "  "})))
    cases.append(("wifi_unknown_security_rejected", item("wifi", {"security": "wpa4"})))
    cases.append(("wifi_hidden_not_bool_rejected", item("wifi", {"hidden": "yes"})))
    cases.append(("wifi_long_ssid_rejected", item("wifi", {"ssid": "x" * 33})))
    cases.append(("collection_id_not_a_uuid_rejected", item("note", {}, collection_ids=["c1"])))
    cases.append(("unknown_kind_rejected", item("spaceship", {})))
    cases.append(("float_timestamp_rejected", item("note", {}, updated_at=1.5)))
    return cases


def _norm_error_reason(exc: BaseException) -> str:
    # The desktop has no stable error codes: every rejection is the one contract reason.
    return "rejected"


def _norm_file(ns: str, cases: list[tuple[str, dict]]) -> bytes:
    rows = []
    names = set()
    for name, record in cases:
        assert name not in names, name
        names.add(name)
        # Round trip through JSON so int/float and key differences count, as on the wire.
        wire = json.loads(json.dumps(record))
        try:
            output = normal_form(ns, wire)
            error = None
            detail = None
        except (VaultError, ItemSchemaError, TotpError, OriginError) as exc:
            output = None
            error = _norm_error_reason(exc)
            detail = str(exc)
        normal = None if output is None else json.loads(json.dumps(output))
        rows.append({
            "name": name, "ns": ns, "input": wire, "output": normal, "error": error,
            "already_normal": normal is not None and canonical_json(wire) == canonical_json(normal),
        })
        if detail is not None:
            rows[-1]["detail"] = detail
    return dumps({"cases": rows})


def normalise_files() -> dict[str, bytes]:
    return {
        "normalise/entries.json": _norm_file("entry", _norm_cases_entries()),
        "normalise/items.json": _norm_file("item", _norm_cases_items()),
    }



# --- existing-group keyrings (P4) and the NFC / NFD password pair ---------------------------------


def build_existing_keyrings(identities: dict[str, DeviceIdentity]) -> dict[str, Any]:
    """First keyrings of a group the device already holds a key for, and B attaching to epoch 1.

    Same real functions and PRODUCTION KDF as ``build_keyrings``: A creates an epoch-1 and an
    epoch-3 keyring for two fixed group keys, then B attaches to the epoch-1 one.
    """
    rand = DetRand("keyring-existing")
    recorded: dict[tuple[str, str], bytes] = {}
    real = kr._argon2

    def recording(password: str, salt: bytes, profile: tuple[int, int, int]) -> bytes:
        key = real(password, salt, profile)
        recorded[(password, salt.hex())] = key
        return key

    gk1 = GroupKey(EXISTING_GROUP_ID, 1, seed("existing-group|key|1"))
    gk3 = GroupKey(EXISTING_GROUP_ID, 3, seed("existing-group|key|3"))
    kr._argon2 = recording
    try:
        ring1 = kr.create_for_existing_group(
            gk1, PASSWORD_1, identities["A"], DEVICE_NAMES["A"], _rand=rand, _now=T0 + 300
        )
        ring3 = kr.create_for_existing_group(
            gk3, PASSWORD_2, identities["A"], DEVICE_NAMES["A"], _rand=rand, _now=T0 + 360
        )
        attach = kr.attach_with_password(
            ring1, PASSWORD_1, identities["B"], DEVICE_NAMES["B"], gk1, _rand=rand, _now=T0 + 420
        )
    finally:
        kr._argon2 = real
    passwords = {1: PASSWORD_1, 3: PASSWORD_2}
    rings = {1: ring1, 3: ring3}
    pw_keys = {
        e: recorded[(passwords[e], base64.b64decode(rings[e]["kdf"]["salt"]).hex())] for e in (1, 3)
    }
    return {"ring1": ring1, "ring3": ring3, "attach": attach, "gk": {1: gk1, 3: gk3},
            "pw_keys": pw_keys, "passwords": passwords}


def existing_expected(built: dict[str, Any]) -> dict[str, Any]:
    epochs = {}
    for epoch in (1, 3):
        gk: GroupKey = built["gk"][epoch]
        epochs[str(epoch)] = {
            "group_key_hex": gk.key.hex(),
            "record_key_hex": gk.record_key().hex(),
            "file_key_hex": gk.file_key().hex(),
            "keyring_mac_key_hex": kr._mac_key(gk.key, gk.group_id, gk.epoch).hex(),
            "password": built["passwords"][epoch],
            "password_wrap_key_hex": built["pw_keys"][epoch].hex(),
            "member_name_key_hex": kr._name_key(gk).hex(),
            "member_names": kr.member_names(built[f"ring{epoch}"], gk),
        }
    return {
        "group_id": EXISTING_GROUP_ID,
        "epochs": epochs,
        "attach": {
            "password": PASSWORD_1,
            "password_wrap_key_hex": built["pw_keys"][1].hex(),
            "member_names": kr.member_names(built["attach"], built["gk"][1]),
            "note": "keyring_attach.json is keyring_existing_epoch1.json with device B added by "
            "attach_with_password (trusted key = the epoch-1 group key above, B keeps its own identity).",
        },
        "note": "keyring_existing_epoch1.json and keyring_existing_epoch3.json are the first keyring "
        "of a group the creating device (A) already held a key for (create_for_existing_group): "
        "prev_mac is null at every epoch, the epoch is the one of the supplied key.",
    }


def unicode_password() -> dict[str, Any]:
    """Argon2id of the same password text in NFC and NFD form: the password is NOT normalised."""
    nfc = unicodedata.normalize("NFC", PASSWORD_UNICODE)
    nfd = unicodedata.normalize("NFD", PASSWORD_UNICODE)
    assert nfc != nfd
    salt = seed("unicode-password|salt")[:16]
    out_nfc = kr._argon2(nfc, salt, kr._PRODUCTION_KDF)
    out_nfd = kr._argon2(nfd, salt, kr._PRODUCTION_KDF)
    assert out_nfc != out_nfd
    return {
        "password_nfc": nfc,
        "password_nfd": nfd,
        "password_nfc_utf8_hex": nfc.encode("utf-8").hex(),
        "password_nfd_utf8_hex": nfd.encode("utf-8").hex(),
        "kdf": {"name": "argon2id", "memory_kib": 131072, "iterations": 4, "parallelism": 4},
        "salt_hex": salt.hex(),
        "argon2id_nfc_hex": out_nfc.hex(),
        "argon2id_nfd_hex": out_nfd.hex(),
        "note": "The two passwords look the same but differ in UTF-8 bytes; the sync password is used "
        "exactly as typed, so the two outputs differ and must stay different.",
    }


# --- canonical JSON known answers -----------------------------------------------------------------

#: JSON texts whose canonical bytes are published, in both dialects.
CANONICAL_VALUES = (
    '"\\u2028"', '"\\u2029"', '"\\u007f"', '"\\u0000"', '"\\u001f"',
    '"\\/"', '"\\\\/"',
    '"\\ud83d\\udd11"', '"\U0001f511"',
    '"caf\\u00e9"', '"cafe\\u0301"',
    '"a\\"b\\\\c\\n\\t\\b\\f\\r"',
    "1e15", "1e16", "0.1", "-0.0", "1e-07", "1.5", "100.0",
    "9007199254740992", "9223372036854775807", "-9223372036854775807",
    '{"b":[1e15,{"z":null,"a":true}],"a":"\\u2028\\ud83d\\udd11"}',
)

#: (text, reason, rejected_by).  Each decoder is asserted in tests/test_sync_vectors.py.
CANONICAL_REJECTED = (
    ('{"n":9223372036854775808}',
     "2**63 does not fit the signed 64-bit item integer range; the item engine (ItemState) rejects "
     "it, although a plain JSON parser and the canonical encoder accept it",
     ["engine_item_state"]),
    ('{"x":NaN}',
     "NaN is not JSON; the canonical encoder (allow_nan=False), the item engine and the strict parsers reject it",
     ["canonical_encoder", "engine_item_state", "strict_parser"]),
    ('{"x":Infinity}',
     "Infinity is not JSON; the canonical encoder (allow_nan=False), the item engine and the strict parsers reject it",
     ["canonical_encoder", "engine_item_state", "strict_parser"]),
    ('{"a":1,"a":2}',
     "a duplicate object key; the strict parsers reject it (a lenient parser keeps the last value)",
     ["strict_parser"]),
    ('{"s":"\\ud800"}',
     "a lone surrogate has no UTF-8 form; the canonical encoder and the item engine (ItemState) "
     "reject it; the strict parsers accept the escape text",
     ["canonical_encoder", "engine_item_state"]),
)


def canonical_json_file() -> bytes:
    utf8 = []
    ascii_ = []
    for text in CANONICAL_VALUES:
        value = json.loads(text)
        utf8.append({"value_json": text, "canonical_hex": canonical_json(value).hex()})
        encoded = json.dumps(value, ensure_ascii=True, separators=(",", ":"), sort_keys=True)
        ascii_.append({"value_json": text, "canonical_hex": encoded.encode("ascii").hex()})
    rejected = []
    for text, reason, by in CANONICAL_REJECTED:
        _assert_rejected(text, by)
        rejected.append({"text": text, "reason": reason, "rejected_by": by})
    return dumps({
        "utf8": utf8,
        "ascii": ascii_,
        "rejected": rejected,
        "note": "utf8 = localvault.updates.canonical_json (views, keyrings): sorted keys, no whitespace, "
        "ensure_ascii=False, allow_nan=False. ascii = json.dumps(sort_keys=True, separators=(',', ':'), "
        "ensure_ascii=True) (pairing, transport, LAN). value_json is the JSON text to parse; "
        "canonical_hex the hex of the output bytes. Floats use Python repr (1e15 -> "
        "1000000000000000.0, 1e16 -> 1e+16).",
    })


def _assert_rejected(text: str, by: list[str]) -> None:
    """The generator refuses to publish a rejection claim the real decoders do not back."""
    def rejects(decoder: str) -> bool:
        try:
            if decoder == "strict_parser":
                kr.parse_keyring(text.encode("utf-8"))
            elif decoder == "canonical_encoder":
                canonical_json(json.loads(text))
            else:
                ItemState("x", {"A": 1}, False, None, json.loads(text))
        except (kr.KeyringError, ValueError, EngineError):
            return True
        return False

    for decoder in ("engine_item_state", "canonical_encoder", "strict_parser"):
        assert rejects(decoder) is (decoder in by), (text, decoder)


# --- licence state -------------------------------------------------------------------------------


def _signed_license(private: ed25519.Ed25519PrivateKey, **over: Any) -> dict[str, Any]:
    """A licence bundle signed by *private* (key id derived from its public key)."""
    key_id = hashlib.sha256(private.public_key().public_bytes_raw()).digest()[:8].hex()
    lic = {
        "format": 1,
        "license_id": "lic-vector-0001",
        "edition": "pro",
        "name": "Ada Lovelace",
        "email": "ada@example.com",
        "issued_at": "2026-09-21",
        "updates_until": "2027-09-21",
        **over,
    }
    return {
        "license": lic,
        "signature": {
            "alg": "Ed25519",
            "key_id": key_id,
            "signature": b64(private.sign(canonical_json(lic))),
        },
    }


def license_cases(private: ed25519.Ed25519PrivateKey, bundle: dict[str, Any]) -> list[dict[str, Any]]:
    """Licence states and what the desktop bridge does with each when only the TEST key is known."""
    cases: list[dict[str, Any]] = []

    def add(name: str, wrapper: dict[str, Any], expect: str, *, state_id: str | None = None,
            copy: bool = False) -> None:
        sid = state_id or licensing.sync_state_id(wrapper["record"]["license"]["license_id"])
        cases.append({"name": name, "state_id": sid, "copy": copy, "wrapper": wrapper, "expect": expect})

    def fork(value: Any) -> Any:
        return json.loads(json.dumps(value))

    wrapper = _license_wrapper(bundle)
    sid = licensing.sync_state_id(bundle["license"]["license_id"])
    add("valid", wrapper, "accepted")
    tampered = fork(bundle)
    tampered["license"]["name"] = "Someone Else"
    add("bad_signature", _license_wrapper(tampered), "bad-remote")
    add("id_mismatch", wrapper, "bad-remote", state_id=licensing.sync_state_id("lic-vector-9999"))
    other = ed25519.Ed25519PrivateKey.from_private_bytes(seed("licence-other-key"))
    add("unknown_key_id", _license_wrapper(_signed_license(other, license_id="lic-vector-0002")), "update-needed")
    malformed = fork(bundle)
    malformed["signature"]["key_id"] = "not-a-key-id"
    add("malformed_key_id", _license_wrapper(malformed), "bad-remote")
    bad_alg = fork(bundle)
    bad_alg["signature"]["alg"] = "Ed448"
    add("unknown_alg", _license_wrapper(bad_alg), "update-needed")
    add("format_2_signed", _license_wrapper(_signed_license(private, license_id="lic-vector-0003", format=2)),
        "update-needed")
    add("format_2_unsigned", _license_wrapper({**fork(bundle), "license": {**bundle["license"], "format": 2}}),
        "bad-remote")
    add("updated_at_1", {**fork(wrapper), "updated_at": 1}, "bad-remote")
    add("top_level_id", {**fork(wrapper), "id": sid}, "bad-remote")
    add("schema_2", {**fork(wrapper), "schema": 2}, "update-needed")
    entry = web_login(sid, "Not a licence", "https://lic.example.com", "u@example.com", "pw", -3600, -1800)
    add("entry_under_lic_prefix", wrapped("entry", entry), "bad-remote", state_id=sid)
    copy_id = conflict_copy_id(sid, hashlib.sha256(canonical_json(wrapper)).hexdigest())
    add("conflict_copy", {**fork(wrapper), "id": copy_id}, "dropped", state_id=copy_id, copy=True)
    return cases


def license_state_file() -> bytes:
    """A licence signed with the vectors' own TEST licence key and its sync state (ruling R1)."""
    private = ed25519.Ed25519PrivateKey.from_private_bytes(seed("licence-test-key"))
    raw_public = private.public_key().public_bytes_raw()
    key_id = hashlib.sha256(raw_public).digest()[:8].hex()
    bundle = _signed_license(private)
    public_b64 = b64(raw_public)
    verified = licensing.verify_bundle(bundle, keys={key_id: public_b64})
    wrapper = _license_wrapper(bundle)
    return dumps({
        "WARNING": "TEST ONLY. This signing key exists only for these vectors; the production licence "
        "keys never verify it, and it never verifies a production licence.",
        "key_id": key_id,
        "public_key_b64": public_b64,
        "license": {
            "license_id": verified.license_id, "edition": verified.edition, "name": verified.name,
            "email": verified.email, "issued_at": verified.issued_at.isoformat(),
            "updates_until": verified.updates_until.isoformat(),
        },
        "bundle": bundle,
        "state_id": licensing.sync_state_id(verified.license_id),
        "wrapper": wrapper,
        "wrapper_canonical_hex": canonical_json(wrapper).hex(),
        "cases": license_cases(private, bundle),
        "note": "Verify bundle with keys = {key_id: public_key_b64}; key_id is the first 8 bytes of "
        "sha256(raw public key) in hex; the signature covers canonical_json(bundle.license). state_id "
        "is 'lic:' + the first 32 hex digits of sha256(license_id). A licence travels as the wrapper "
        "{ns: license, schema: 1, updated_at: 0, record: bundle}. cases: each wrapper is a remote state "
        "under state_id (a conflict copy of the engine when copy is true), applied with only this TEST key "
        "known; expect is accepted (stored and republished), dropped (no write, no report), update-needed "
        "or bad-remote (that state is skipped and reported).",
    })


# --- wrapper schema cases ------------------------------------------------------------------------


def schema_cases_file() -> bytes:
    """Wrappers at several ``schema`` values and what a reader does with each."""
    entry = web_login(
        "99999999-aaaa-4000-8000-000000000009", "Schema sample", "https://schema.example.com",
        "schema.user@example.com", "schema-pass-sample", -3600, -1800,
    )
    note = typed_item("99999999-aaaa-4000-8000-00000000000a", "note", "Schema note",
                      {"body": "Sample text.", "fields": [], "template_id": None},
                      -3600, -1800)
    cases = []

    def add(name: str, base: dict, expect: str, *, schema: Any = ..., drop: bool = False,
            extra: dict | None = None) -> None:
        wrapper = json.loads(json.dumps(base))
        if drop:
            del wrapper["schema"]
        elif schema is not ...:
            wrapper["schema"] = schema
        wrapper.update(extra or {})
        cases.append({"name": name, "item_id": base["record"]["id"], "wrapper": wrapper, "expect": expect})

    entry_w = wrapped("entry", entry)
    item_w = wrapped("item", note)
    add("entry_schema_1", entry_w, "accepted")
    add("item_schema_1", item_w, "accepted")
    add("entry_schema_2", entry_w, "update-needed", schema=2)
    add("item_schema_2", item_w, "update-needed", schema=2)
    add("entry_schema_99", entry_w, "update-needed", schema=99)
    add("entry_schema_2_extra_wrapper_key", entry_w, "update-needed", schema=2, extra={"signed_by": "future"})
    add("entry_schema_1_extra_wrapper_key", entry_w, "bad-remote", extra={"signed_by": "future"})
    add("entry_schema_true_extra_wrapper_key", entry_w, "bad-remote", schema=True, extra={"signed_by": "future"})
    add("entry_schema_missing", entry_w, "bad-remote", drop=True)
    add("entry_schema_0", entry_w, "bad-remote", schema=0)
    add("entry_schema_negative", entry_w, "bad-remote", schema=-1)
    add("entry_schema_string_1", entry_w, "bad-remote", schema="1")
    add("entry_schema_float_1", entry_w, "bad-remote", schema=1.0)
    add("entry_schema_true", entry_w, "bad-remote", schema=True)
    add("entry_schema_null", entry_w, "bad-remote", schema=None)
    return dumps({
        "cases": cases,
        "note": "Each wrapper is an item state's body. expect is what the desktop reader does: accepted "
        "(applied), update-needed (this item is kept as it is here, reported, everything else "
        "syncs) or bad-remote (this item is skipped and reported as damaged). schema must be a JSON "
        "integer; true, 1.0 and '1' are not. The schema is checked first (an integer above 1 is "
        "update-needed whatever else the wrapper holds), then the exact key set, then the rest.",
    })


# --- README --------------------------------------------------------------------------------------

README = """\
# Sync test vectors (desktop <-> iOS contract)

Generated by `scripts/make_sync_vectors.py`; `tests/test_sync_vectors.py` regenerates them and
requires byte-for-byte equality, so they only change when a format changes on purpose. The iOS
app must decode, decrypt, verify and merge exactly these files. EVERY KEY HERE IS TEST ONLY.

Fixed facts: group id `{group}`; `T0 = {t0}` (all times are `T0 + n`); devices A, B, C are the
Windows desk PC, a Windows laptop and an old tablet (see `identities.json`). Format rules live in
the docstrings of `src/localvault/sync/{{group,keyring,engine,pairing}}.py`. The password is used exactly as typed (UTF-8, no Unicode normalisation); key derivation is Argon2id version 1.3.

## Files

| File | What it is | How an iOS test uses it |
| --- | --- | --- |
| `identities.json` | Private and public keys of A, B, C (Ed25519 signing, X25519 exchange, raw base64). | Build `DeviceIdentity` values; the iOS test device can act as any of them. |
| `keyring_epoch1_ab.json` | Keyring after A created the group and B joined by password (2 members). | Optional: join as C with the password and check structure (output differs, joins are randomised). |
| `keyring_epoch1.json` | Epoch-1 keyring: A created it, B and C joined by password. Exact bytes of `keyring.lgkkeys` (canonical JSON, no trailing newline). | Parse, re-canonicalise, verify `mac`; open the password wrap with `correct horse battery staple 42` (Argon2id 128 MiB / 4 passes / 4 lanes, production parameters) and each device wrap with its identity. All three give `expected.json` epoch-1 group key. Decrypt every member's `name_ct` (key `member_name_key_hex`, AAD bound to group, epoch and device id) and compare with `member_names`. Keyring format 2: every member lists its Ed25519 view-signing key `signing_public` and `signing_proof`, its signature over `localgatekeys|sync|keyring-member|v2|` + group id + `|` + device id + `|` + `exchange_public` (base64 text) + `|` + `signing_public` (base64 text); verify each proof and compare the keys with `member_signing_keys`. |
| `keyring_v1_epoch1.json` | `keyring_epoch1.json` written in format 1 (members without `signing_public` / `signing_proof`, `mac` recomputed): what an older app wrote. Byte-identical to the epoch-1 keyring of the format-1 vectors. | Must still be read and accepted (same group key, names and wraps); `member_signing_keys` is empty; a join or attach writes it back as format 2 with null signing fields for the existing members. |
| `keyring_epoch2.json` | A rotated to `violet tram sundial 1987 pebble` and removed C. Members: A, B. | `accept_keyring` from trusted epoch 1 + A's or B's identity must return the epoch-2 key (checks `prev_mac` and `mac`). C must get `not-member`; epoch 2 trusted against epoch 1 keyring must give `rollback`. Names were re-encrypted under the epoch-2 name key (`member_names` of epoch 2). |
| `expected.json` | Group id, both passwords, group keys, record/file keys, keyring MAC keys, member-name keys, the decrypted member names and the raw Argon2id outputs (hex). | Compare every derived key. The Argon2id outputs let a failing KDF be told from a failing unwrap. |
| `devices/A.lgksync`, `B`, `C` | Sealed device views at epoch 1 (`LGKSYNC1` format), headers: A counter 7, B counter 4, C counter 3. | Decode with the epoch-1 group key and `expected_device_id` = the device id. |
| `expected_merge.json` | Final item set after merging A+B+C in ANY order. | Merge the decoded states in all 6 orders (first = local, then merge each other file into it and apply upserts, deletes and copies) and compare `engine_states`. Then check the stored form (below). |
| `lan/qr_payload.txt` | The QR text (`lgk-pair:` + unpadded base64url of the canonical offer bundle), no trailing newline. | `parse_qr_payload` equivalent must give `lan/expected_lan.json` `offer_bundle`. |
| `lan/enroll_request.bin` | B's enrollment request to A, exact wire bytes (`LGKENROLL1\\n` + canonical JSON). Body version 2: it carries B's `name`, which is also `invitee_name` in the transcript. | Verify as A (inviter) at `now` from `expected_lan.json`; the decrypted transcript must equal `request.transcript`, and both devices must compute `request.verification_code` from it (first 4 bytes of SHA-256(`localgatekeys|sync|enroll-verify|v2|` + transcript), big-endian, mod 10^6, 6 digits). |
| `lan/enroll_reply.bin` | A's reply (`LGKENROLLOK1\\n` + canonical JSON), the epoch-1 group key sealed to B and signed by A. | `open_enrollment_reply` as B must return group id, epoch 1 and the epoch-1 key. |
| `lan/enroll_request_no_endpoint.bin`, `lan/enroll_reply_no_endpoint.bin` | The same enrollment where B announces no listening endpoint (`invitee_endpoint` null) and a non-ASCII name (escaped as `\\u2019` and `\\u00e9` by the ASCII canonical JSON). | As above; `expected_lan.json` `request_no_endpoint` / `reply_no_endpoint`. `framing.refusals_hex` has the refusal of every reason, including `declined` (Decline or no Accept within 60 s) and `update-needed` (a version-1 body). |
| `lan/expected_lan.json` | Decoded fields and intermediate values: ephemeral keys, nonces, transcript and its hash, both HKDF keys, the AADs, the decrypted request and reply body plaintexts, and the magics as text and hex. | Compare each value. |
| `lan/session.json` | Three LAN connections of A and B (A initiates; B initiates; hello counters 9 and 10), each with both signed hello texts, their signing inputs (hex), the X25519 shared secret, the sorted transcript (hex) and which hello sorts first, `salt`, HKDF `info`, the session `key`, `prefix_initiator`, `prefix_responder`, and the one sealed request and one sealed response (`counter` 1, `nonce`, `aad`, `plaintext`, `frame_hex`). | Verify both hellos against the pinned identities of `identities.json`, re-derive `key` independently (the transcript order is by bytes), then decrypt the frames. |
| `lan/hello_initiator.bin`, `lan/hello_responder.bin` | The two hello frames of the first connection as they go on the wire: the 4-byte length prefix plus the canonical hello JSON. | Strip the prefix, parse strictly, check the signature and that `exchange_public` is the pinned one. |
| `lan/frame_initiator.bin`, `lan/frame_responder.bin` | The sealed request and response of the first connection, WITH the 4-byte length prefix. | Decrypt with that session's `key`; the result is the `plaintext` of the frame entry. |
| `lan/messages.json` | Metadata of the 2-chunk view exchange: three connections (own hellos, session id and key each), the sealed frames as files, sizes and hashes, both views, and the plaintext of one error message per reason. | Seal the plaintexts yourself and compare with the `.bin` files; open the frames; reassemble both views from the chunks and decode them with the epoch-1 group key. |
| `lan/messages/*.bin` | The six sealed frames of that exchange, WITH the 4-byte length prefix. | As above. |
| `lan/lan_ranges.json` | The LAN address ranges and the `test_lan_address_table` cases with the expected result. | Apply the same rule to every case. |
| `canonical_json.json` | Known answers for canonical JSON in both dialects (`utf8`, `ascii`) plus `rejected` inputs, each naming the decoder that refuses it (see "Canonical JSON known answers"). | Parse each `value_json`, canonicalise, compare the hex; expect a rejection from the named decoder for every `rejected` text. |
| `keyring_existing_epoch1.json`, `keyring_existing_epoch3.json` | First keyring of a group the creating device (A) already held a key for, at epoch 1 and at epoch 3 (group `{existing}`, two fixed group keys in `expected.json` `existing_group`). `prev_mac` is null at both epochs. | Verify structure and `mac`; open the password wrap with the password in `existing_group`; `accept_keyring` with the matching trusted key and A's identity returns that key. |
| `keyring_attach.json` | `keyring_existing_epoch1.json` after B attached with the same password (two members, trusted key = the epoch-1 key). | Same checks as above for both A and B; the password wrap, salt and A's entry are unchanged. |
| `license_state.json` | A licence signed with a TEST licence key (key id and public key included), its sync state id and its wrapper, plus `cases`: remote licence states (bad signature, id mismatch, unknown and malformed key id, unknown alg, format 2, `updated_at` 1, a conflict copy and more) with the expected outcome. | Verify the bundle with `keys = {{key_id: public_key_b64}}`, recompute `state_id`, compare the wrapper and its canonical bytes, then run your licence reader on every case with only that key known. |
| `schema_cases.json` | Wrappers at `schema` 1, 2, 99, missing, 0, negative, "1", 1.0, true and null, and with an extra wrapper field at schema 1, 2 and true, each with the expected outcome. | Run your wrapper reader on every `wrapper`: `accepted`, `update-needed` or `bad-remote`. |
| `normalise/entries.json`, `normalise/items.json` | Input/output tables of the desktop's record normaliser, one per namespace (see "Normalisation tables"). | Run your normaliser on each `input` and compare with `output`, or expect a rejection. |
| `signatures/A.lgksig` | A's signature file for `devices/A.lgksync` (format: "View signature" block of `group.py`), signed with A's identity. | `verify_view_signature` with the decoded header of `devices/A.lgksync` returns A's `signing_public_b64`; re-signing gives the same bytes (Ed25519 is deterministic). |
| `hardening_cases.json` | Audit 2026-10-24 bounds: `constants`; `vv` cases (`remote`, `local`, `known` -> `implausible_vv` result or null); `counters` cases (`counter`, `last` or null -> `counter_verdict` result or null); `signatures` cases (signature file text for `devices/A.lgksync` -> `valid`, `sig-malformed`, `sig-stale` or `sig-mismatch`). | Run your own rule on every case and compare. |

The offer's `expires_at` is a plain JSON integer (`1790000120`, whole Unix seconds). It is embedded
in the MAC'd and signed enrollment transcript, so floats are rejected everywhere (a float would
re-serialise differently on the scanner). The byte-level rules for every `lan/*` file are the
"Format rules" block at the top of `src/localvault/sync/pairing.py`.

Pairing JSON (`lan/*`) uses `ensure_ascii=True` canonical JSON; sealed views and keyrings use
`localvault.updates.canonical_json` (`ensure_ascii=False`). Both are "sorted keys, compact".

## The device-file scenario (epoch 1)

* `{login}`: web login edited concurrently: A (vector `A:2`, `updated_at` T0+500, new password) and
  B (vector `A:1,B:1`, `updated_at` T0+400, renamed, different notes). C still has the base version
  (`A:1`). A wins (larger `updated_at`) and keeps the id; B's version becomes a conflict copy.
* `{note}`: typed note with custom fields (identical in all files).
* `{desktop}`: desktop entry with a full binding (created by B).
* `{deleted}`: login deleted by C (tombstone `A:1,C:1`, `deleted_at` T0+300) while A and B still
  hold it live: the tombstone wins.
* `{bookmark}`: typed bookmark edited by B (`A:1,B:1`) while C deleted it (`A:1,C:1`, T0+350):
  concurrent edit vs delete keeps the live item with the merged vector `A:1,B:1,C:1`.
* `{unicode}`: note only B has, with non-ASCII text, quotes, backslash and a tab/newline.
* `{tie}`: login edited by A and B with EQUAL `updated_at` (T0+600), so the winner is decided by the
  larger sha256 of the canonical item. Non-ASCII label/notes, and a custom-field row whose keys
  (`a`, U+00E9, U+FF5A, U+1F511) sort by code point rather than UTF-16, with the floats 0.1, 1e-07,
  1e+16, 100.0, -0.0 and the int 2**62 (Python `repr` formatting, see `keyring.py` "Canonical JSON").

## LAN session, frames and messages

**Length prefix.** Every frame `.bin` file here (`lan/hello_*.bin`, `lan/frame_*.bin`, `lan/messages/*.bin`)
and every `frame_hex` includes the 4-byte big-endian length prefix, exactly as the bytes travel on the
socket (a frame payload is at most 1 MiB). The enrollment `.bin` files (`lan/enroll_*.bin`) do NOT include
it: they are the payload only, and a transport adds the same prefix when it sends them.

**One request, one response per connection.** The initiator opens a TCP connection, sends its hello and
picks the 16-byte `session_id`. The responder checks the hello and replies with its own hello carrying
the SAME `session_id` (the initiator rejects a different one). Both derive the session key. The initiator
sends one sealed request, the responder answers with one sealed response and closes. Every chunk of a
view is its own request on its own connection with its own hello pair, `session_id` and key, so every
frame counter is 1. The desktop never sends two frames in one direction of a connection.
`lan/session.json` holds three such connections; `lan/messages.json` holds three more (the exchange below).

**Hello (protocol version 2).** A hello is canonical ASCII JSON (sorted keys, compact) with exactly the
fields `version` (2), `session_id` (16 bytes, base64), `group_id`, `device_id`, `signing_public` (32 bytes),
`exchange_public` (32 bytes), `ephemeral_public` (32 bytes: a fresh X25519 public key for this connection
only), `nonce` (32 bytes, base64), `counter` and `signature` (64 bytes, base64). Parse strictly: exactly
that field set, duplicate keys rejected, base64 canonical (what you re-encode must equal what you read),
exact lengths, `counter` a JSON integer from 0 to 2^63 - 1, and at most 1 MiB - 256 bytes. The signing
input is the ASCII text `localgatekeys|sync|session-hello|v2|` followed by the canonical JSON of the hello
without `signature`. A receiver checks that the group, device id, signing key, its fingerprint (lowercase
hex SHA-256 of the raw 32-byte Ed25519 public key) and `exchange_public` are exactly the pinned ones (the
pinned exchange key, not the one in the hello), that `ephemeral_public` is not all zero and not the
exchange key, then the Ed25519 signature. `version` must be the JSON integer 2: `true`, `2.0` and `"2"`
are refused, and so is a hello with a missing or an extra field.

**Other versions: no downgrade.** A first frame that is a signed hello with another integer `version`
(version 1 had no `ephemeral_public` and the label `...|session-hello|v1|`) is never used for a key. The
responder answers with the plain frame `{{"refused":"version","version":2}}` (`session.json`
`version_refusal`) and closes; a version-1 hello whose signature verifies under the pinned key only marks
that device as "needs an update" (`session.json` `legacy_hello` is B's). An initiator that reads such a
refusal instead of a hello stops and reports that one side needs an update (the announced version is
lower: the peer; higher: this device). It never retries with another version.

**Hello counter.** Each device raises its hello counter for every connection it starts or accepts. Both
sides enforce it: the responder rejects a hello whose counter is not above the last one it accepted from
that peer, and the initiator does the same with the responder's hello; this is the replay protection on
LAN. A device must persist its counter before the hello leaves it and never reuse a value, also across
restarts and a clock set backwards: the desktop refuses a hello whose counter is not above the last one
it accepted from that device, whichever side sent it.
`session.json` `counters-9-10` shows hellos with different counters.

**Session key.** `shared` (`shared_secret_hex`) = X25519 of one side's exchange private key and the other
side's exchange public key; `ephemeral_shared` (`ephemeral_shared_secret_hex`) = X25519 of one side's
ephemeral private key (`hello.*.ephemeral_private_hex`, published here for testing only) and the other
hello's `ephemeral_public`. An all-zero result of either is refused. Each ephemeral private key is used
for exactly one derivation and then erased. `transcript` = both hellos, each as the canonical re-serialisation of the parsed hello (what
`to_bytes` returns; not the bytes as received, though for a canonical sender they are equal), sorted
bytewise as byte strings and concatenated with no separator. The order is by bytes, never by role or by
counter: `session.json` `b-initiates` (A's hello sorts first although A is the responder) and `counters-9-10`
(the text `"counter":10` sorts before `"counter":9`, so the responder's hello comes first although
the initiator's counter is the smaller number) have `sorted_first` = `responder`. `salt` = SHA-256 of `localgatekeys|sync|session-salt|v2|`
followed by `transcript`. `key` = HKDF-SHA256, 32 bytes, that `salt`, `info` =
`localgatekeys|sync|session-key|v2|` followed by the 16 raw session id bytes, applied to `ikm` =
`ephemeral_shared` followed by `shared` (64 bytes, `ikm_hex`). The static part still binds the session
to the pinned exchange keys; the ephemeral part means a later leak of both exchange private keys does
not open recorded sessions.

**Frames.** The nonce is a 4-byte direction prefix plus the 8-byte big-endian counter. The prefix is the
first 4 bytes of SHA-256 of `key`, then `send|`, then the sender's role (`initiator` or `responder`).
The AAD is the canonical ASCII JSON of `version` (2), `session_id` (base64), `counter` and `nonce`
(base64). The frame payload is the canonical JSON of those four fields plus `ciphertext` (base64 of
AES-256-GCM output with the 16-byte tag at the end). A message plaintext is at most 1 MiB - 256 bytes.
Parse a frame payload as strictly as a hello: exactly the fields `ciphertext`, `counter`, `nonce`,
`session_id` and `version`, duplicate keys rejected, `version` the JSON integer 2 (not `true` or `2.0`).
A receiver rejects a counter that is not above the last one it accepted on that connection.

**Messages.** A message is canonical ASCII JSON of one of `view`, `ack`, `next` or `error` (field lists
in the docstring of `src/localvault/sync/lan_sync.py`). The `transfer` field is 32 lowercase hex
characters, chosen by the sender of the view. A view is sent in chunks of exactly `{chunk}` raw bytes
(the last chunk is what is left); `view` carries the standard base64 of chunk `seq`. The exchange in
`lan/messages.json` is three connections: (1) `view` seq 0 from A, answered with `ack` seq 0; (2) `view`
seq 1 from A (the last chunk), answered with seq 0 of B's own view; (3) `next` seq 1 for B's transfer,
answered with `view` seq 1 of B. Each sealed frame is a file under `lan/messages/` named
`NN_request|response_type_seq.bin`; `messages.json` lists, for each, the type, seq, transfer, counter,
nonce, AAD, plaintext and frame sizes and SHA-256 values, and the plaintext itself only when it is under
4096 bytes (the view chunks are not; decrypt the `.bin` and compare the hash). The `errors` list has the
plaintext of one `error` message per reason a responder can send: `bad-chunk`, `bad-message`, `bad-view`,
`device-mismatch`, `epoch-behind`, `group-mismatch`, `local-data`, `not-joined`, `peer-epoch-behind`,
`rejoin-required`, `revoked`, `too-large`, `unknown-peer` (`lan_sync.ERROR_REASONS`). A sealed error
frame is in `lan/session.json` (`bad-chunk`, the answer to a `next` for an unknown transfer).

**The filler views.** Each view in `lan/messages.json` is a real `encode_view` output (epoch-1 group
key, the device's header from the table above, its own filler states). The states are {items} web
logins, one version-vector entry each: {fixed} items whose `notes` field is {pad} lowercase hex
characters taken from a fixed-label SHA-256 stream, and one last item whose `notes` length is the
smallest number of characters that makes the encoded view at least {chunk} + 1000 bytes (sizes move
in steps of 4 bytes, so the exact target 525288 is not reached). The result: A's view is {size_a}
bytes (chunk 0 is {chunk} bytes, chunk 1 is {chunk_1_a} bytes; last item notes {last_a} characters),
B's view is {size_b} bytes (chunk 1 is {chunk_1_b} bytes; last item notes {last_b} characters). The
sha256 and sizes of both are in `lan/messages.json` `views`.

**The LAN view header counter is informational.** It carries the stored own counter unchanged, is not monotonic on LAN and is never checked; only the folder transport enforces counters.

**Address ranges.** `lan/lan_ranges.json` lists `LAN_NETWORKS` (10.0.0.0/8, 172.16.0.0/12,
192.168.0.0/16, 169.254.0.0/16, 127.0.0.0/8, ::1/128, fe80::/10, fc00::/7) and the table cases. An
IPv4-mapped IPv6 address is never accepted, and the unspecified addresses `0.0.0.0` and `::` are not
LAN addresses either (no listed network contains them). An IPv6 address with a zone id (`fe80::1%eth0`,
`fe80::1%1`) is refused too: the zone names an interface of the writing device, so it never appears in
a pairing QR or an endpoint.

## Item wrapper

Every item state is a wrapper `{{"ns", "schema", "updated_at", "record"}}` (a conflict copy in engine
form also has a top-level `"id"`). `schema` is the integer `1`; it must be a JSON integer (not a
boolean, string or float) and at least 1. A reader that sees a larger `schema` keeps its own copy of
that item, reports `update-needed`, and syncs the rest. A missing, non-integer or smaller-than-1
`schema`, or an unknown field at schema 1, is `bad-remote`: that one item is skipped and reported.
The check order is fixed: first the schema (a JSON integer above 1 is `update-needed`, whatever other
fields the wrapper holds, because a newer schema may add wrapper fields), then the exact key set, then
everything else. `schema_cases.json` `entry_schema_2_extra_wrapper_key` is `update-needed`, while the
same extra field at schema 1 or with `schema` `true` is `bad-remote`.

## Canonical JSON known answers

`canonical_json.json` lists the same JSON texts in both dialects. `utf8` is `localvault.updates.canonical_json`
(sealed views, keyrings, licence signatures): sorted keys, no whitespace, `ensure_ascii=False`, `allow_nan=False`.
`ascii` is the pairing, transport and LAN form: `ensure_ascii=True`. Notable points: U+2028, U+2029 and U+007F
stay raw in `utf8` and become `\\uXXXX` in `ascii`; control characters below U+0020 are always escaped; `\\/`
in the input is just `/`; an astral character such as U+1F511 is raw UTF-8 in `utf8` and a surrogate pair in
`ascii`; floats use the shortest round-trip form of Python (`1e15` is `1000000000000000.0`, `1e16` is `1e+16`,
`-0.0` and `1e-07` keep their sign and exponent); integers up to `2**63 - 1` are printed in full.
`rejected` lists inputs that must not be accepted, and `rejected_by` names where each is refused:
`engine_item_state` (an integer outside the signed 64-bit range cannot be part of an item), `canonical_encoder`
(NaN, Infinity and a lone surrogate cannot be encoded; the item engine refuses NaN and Infinity too) and `strict_parser` (NaN, Infinity and duplicate keys
are refused when reading a keyring or message).

## Existing-group keyrings, passwords and licences

A device that already holds a group key (for example from Wi-Fi enrollment) writes its first keyring with
the same body as a new group, but for the given group id, epoch and key; that is why an epoch-3 keyring can
have `prev_mac` null. Attaching a second device keeps the password wrap and everything else and adds one member
and one device wrap. The password is never Unicode-normalised: `expected.json` `unicode_password` shows the same
text in NFC and NFD form giving different Argon2id outputs. `license_state.json` is signed with a key that exists
only for these vectors; a production build does not know it, so check it with an explicit key set.

## Licence states

A Pro licence travels as an item state so that every device of a group becomes Pro.

* The id prefix `lic:` is reserved for licences. The state id is `lic:` followed by the first 32 lowercase
  hex digits of SHA-256 of the UTF-8 `license_id`. An entry or typed item under a `lic:` id, or a
  licence state under any other id, is `bad-remote`.
* The wrapper is `{{"ns": "license", "schema": 1, "updated_at": 0, "record": <signed bundle>}}`.
  `updated_at` must be the integer 0, and a licence state never has a top-level `id`; anything else is
  `bad-remote`. The wrapper rules of the section above apply first (`schema` 2 is `update-needed`).
* Verification, with the licence keys the build knows: a well-formed but unknown `key_id` (16 lowercase
  hex digits), an unknown `alg`, or a bundle correctly signed by a known key whose `format` is above 1 is
  `update-needed`. A bad signature, a state id that does not match the licence id, a malformed `key_id`
  or any other shape problem is `bad-remote`.
* Licences are only ever added. A tombstone never deletes one: a device that publishes the licence
  republishes it above the tombstone. The same state id with different bytes is `bad-remote`, and an
  engine conflict copy of a licence is dropped without a write or a report.
* A revoked licence is dropped without a write. Licences never count toward the free item limit. A
  device keeps at most 16 received licences.
* A received licence is stored apart from the items and republished by the receiver in its own views,
  so it reaches devices that never saw the sender. A desktop where the user removed the licence (removal
  pending) publishes no licence at all until one is installed again.

`license_state.json` `cases` lists remote licence states with the outcome when only the TEST key is
known: `accepted` (stored and republished), `dropped` (no write, no report), `update-needed` or
`bad-remote` (that state is skipped and reported). `copy` true means the state arrives as an engine
conflict copy.

## Conflict copy: engine form vs stored form

The engine's copy state carries the loser's wrapper plus a top-level `"id"` equal to the copy id
and an unchanged `label`. The vault bridge then stores it with the record id set to the copy id and
the label suffixed with `" (sync conflict)"` (typed items: `title`), without the top-level `id`.
`expected_merge.json` has both: `engine_states` (what `merge` returns) and `bridge_stored_states`
(what the vault holds and republishes). `conflict_copies` lists, per copy, the copy id, the original
id, the loser wrapper and the sha256 digest that `conflict_copy_id` hashes. The copy keeps the
loser's version vector in both forms. Every state also carries `canonical_sha256`, the SHA-256 of
`canonical_json(item)` (null for tombstones), so a canonical-JSON difference shows up as a digest
mismatch before any merge runs.

Suffix and truncation: the bridge appends `" (sync conflict)"` (16 characters) to an entry `label`
(limit 512) or typed-item `title` (limit 512). Text that already ends with the suffix is left
alone; otherwise the text is first cut to `limit - 16` characters and then suffixed, so the result
never exceeds the limit. Lengths count Unicode code points (Python `len`), not UTF-16 units or
grapheme clusters.

## Normalisation tables

`normalise/entries.json` (namespace `entry`: web logins and desktop entries) and `normalise/items.json`
(namespace `item`: typed items) are `{{"cases": [...]}}`; each case is `{{"name", "ns", "input", "output",
"error", "already_normal"}}`. `output` is what `vault_bridge.normal_form(ns, input)` returns today (the
record as synced: canonical, with the local-only fields removed); the generator computes it, nobody
types it. `input` is a record built around a valid base in which the case varies one field (a few cases drop a
field on purpose, such as a missing `policy` or a minimal typed-item payload). Both are plain JSON,
so `int` and `float` differ (`100.0` stays a float, `true` is not `1`).

* `already_normal` is true when the canonical JSON text of `input` equals that of `output`, a flag for
  the iOS writer: an input with `already_normal` true must come back unchanged; one with false must
  change to `output`.
* `error` is null, or the single code `"rejected"`: the desktop refused the input, `output` is null
  and `already_normal` is false. A rejected case also has `detail`, the desktop message text, for a
  human reading a failure; it is not part of the contract and tests must not assert it.
* Recorded as the desktop does it today, including results that look odd: a `policy` that is a list
  is replaced by the default policy; an unknown `policy.fill` (and `"auto"`) becomes `"never"`; unknown
  policy keys are dropped; entry `tags` keep their case and duplicates, typed-item `tags` are case-folded and
  de-duplicated (first spelling wins); a `password_history` row `replaced_at` becomes `changed_at`;
  `exe_sha256` is upper-cased; origins are lower-cased, lose a default port and a trailing dot, and
  non-ASCII hosts become IDNA (UTS 46, non-transitional: `faß.de` keeps its sharp s as `xn--fa-hia.de`).
  A `scope.urls` bare string becomes `{{"url", "match": "exact_origin"}}`, and duplicate rows are dropped.

## Passkey vectors

`passkeys/*.json` pin the WebAuthn software authenticator (`src/localvault/passkeys.py`) for the iOS
credential-provider extension. Every key is derived from a fixed label (SHA-256 to a P-256 scalar),
every credential id from a fixed label; ECDSA signatures are randomised, so no signature is stored.

* `passkeys/assertion.json`: list of `{{rp_id, user_verified, private_key_b64u, client_data_hash_hex,
  authenticator_data_hex, public_key_x_hex, public_key_y_hex}}`. `private_key_b64u` is the unpadded
  base64url PKCS#8 DER P-256 key as stored in the item. The iOS test builds `authenticatorData`
  (SHA-256(rpId) + flags + `00000000`; flags UP|BE|BS, +UV when `user_verified`), compares it with
  `authenticator_data_hex`, signs `authenticatorData || clientDataHash` (DER ECDSA-SHA256) and
  verifies the signature with the public key `(x, y)`.
* `passkeys/registration.json`: list of `{{rp_id, credential_id_hex, private_key_b64u,
  authenticator_data_hex, cose_key_hex, attestation_object_hex}}` (UV set, AT set, AAGUID
  `b7d2a6f0-1c4e-4a5b-9e3d-5a1f7c2e8d41`). The iOS test rebuilds the COSE key from the private key,
  the authenticator data and the CBOR attestation object (`fmt` `none`, empty `attStmt`, `authData`)
  and compares each with the hex.
* `passkeys/records.json`: list of `{{name, input, valid, usable, normalised?}}`. `input` is a stored
  passkey payload; `valid` is whether `validate_passkey_fields` accepts it, `normalised` its result
  (only when valid: rp id casefolded, `discoverable` defaulting to true); `usable` is
  `passkeys.usable_record(input)` (ES256, a P-256 PKCS#8 key and a non-empty credential id).

## Regenerating

`python scripts/make_sync_vectors.py` (10 Argon2id evaluations at production cost). Randomness
comes from fixed-label SHA-256 streams injected through the `_rand` / `nonce_source` / `_eph_seed`
hooks; production code never passes them.

`from_ios/` is not produced by this script: the iOS core writes it (`LGK_WRITE_FROM_IOS=1 swift test`
in `ios/LGKCore`) and `tests/test_sync_from_ios.py` checks that the desktop accepts it.
`from_android/` is the same for the Android core (`LGK_WRITE_FROM_ANDROID=1 android/gradlew -p android
:lgk-core:test --tests "*FromAndroidTest*"`), checked by `tests/test_sync_from_android.py`.
"""


# --- passkeys ----------------------------------------------------------------------------------


def _pk_key(label: str) -> ec.EllipticCurvePrivateKey:
    scalar = int.from_bytes(hashlib.sha256(b"lgk-sync-vectors|passkey|" + label.encode("ascii")).digest(), "big")
    n = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
    return ec.derive_private_key(scalar % (n - 1) + 1, ec.SECP256R1())


def _pk_private_b64u(key: ec.EllipticCurvePrivateKey) -> str:
    return passkeys.b64u_encode(key.private_bytes(
        serialization.Encoding.DER, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))


def _pk_credential_id(label: str) -> bytes:
    digest = hashlib.sha256(b"lgk-sync-vectors|passkey-cred|" + label.encode("ascii")).digest()
    return digest[: passkeys.CREDENTIAL_ID_BYTES]


_PK_SCENARIOS = (
    ("alpha", "example.com", True),
    ("beta", "login.example.org", False),
    ("gamma", "accounts.example.co.uk", True),
)


def passkey_assertion_file() -> bytes:
    rows = []
    for label, rp_id, uv in _PK_SCENARIOS:
        key = _pk_key(label)
        numbers = key.public_key().public_numbers()
        rows.append({
            "rp_id": rp_id,
            "user_verified": uv,
            "private_key_b64u": _pk_private_b64u(key),
            "client_data_hash_hex": hashlib.sha256(b"lgk-sync-vectors|client-data|" + label.encode("ascii")).hexdigest(),
            "authenticator_data_hex": passkeys.authenticator_data(rp_id, user_verified=uv).hex(),
            "public_key_x_hex": numbers.x.to_bytes(32, "big").hex(),
            "public_key_y_hex": numbers.y.to_bytes(32, "big").hex(),
        })
    return dumps(rows)


def passkey_registration_file() -> bytes:
    rows = []
    for label, rp_id, _uv in _PK_SCENARIOS:
        key = _pk_key(label)
        credential_id = _pk_credential_id(label)
        cose = passkeys.cose_es256_public_key(key.public_key())
        auth_data = passkeys.authenticator_data(rp_id, user_verified=True, attested=(credential_id, cose))
        attestation = passkeys.cbor_encode({"fmt": "none", "attStmt": {}, "authData": auth_data})
        rows.append({
            "rp_id": rp_id,
            "credential_id_hex": credential_id.hex(),
            "private_key_b64u": _pk_private_b64u(key),
            "authenticator_data_hex": auth_data.hex(),
            "cose_key_hex": cose.hex(),
            "attestation_object_hex": attestation.hex(),
        })
    return dumps(rows)


def passkey_records_file() -> bytes:
    good = {
        "relying_party_id": "example.com",
        "rp_name": "Example",
        "user_handle": passkeys.b64u_encode(b"user-handle-1"),
        "user_name": "ada",
        "user_display_name": "Ada Lovelace",
        "credential_id": passkeys.b64u_encode(_pk_credential_id("alpha")),
        "private_key": _pk_private_b64u(_pk_key("alpha")),
        "algorithm": "ES256",
        "created": "2026-09-21",
        "discoverable": True,
    }
    cases = [
        ("desktop-made", good),
        ("rs256-import", {**good, "algorithm": "RS256", "private_key": "MIIEvQIBADANBgkqhkiG9w0BAQEFAASC"}),
        ("garbage-key", {**good, "private_key": "bm90LWEta2V5"}),
        ("uppercase-rp-id", {**good, "relying_party_id": "Example.COM"}),
        ("missing-discoverable", {k: v for k, v in good.items() if k != "discoverable"}),
        ("bad-b64url-credential-id", {**good, "credential_id": "not base64url!"}),
    ]
    rows = []
    for name, record in cases:
        row: dict[str, Any] = {"name": name, "input": record}
        try:
            row["normalised"] = validate_passkey_fields(record)
            row["valid"] = True
        except ItemSchemaError:
            row["valid"] = False
        row["usable"] = passkeys.usable_record(record)
        rows.append(row)
    assert [r["valid"] for r in rows] == [True, True, True, True, True, False], rows
    assert [r["usable"] for r in rows] == [True, False, False, True, True, False], rows
    return dumps(rows)


def passkey_files() -> dict[str, bytes]:
    return {
        "passkeys/assertion.json": passkey_assertion_file(),
        "passkeys/registration.json": passkey_registration_file(),
        "passkeys/records.json": passkey_records_file(),
    }


def readme(facts: dict[str, Any]) -> bytes:
    text = README.format(
        **facts, chunk=CHUNK_BYTES, items=FILLER_FIXED + 1, fixed=FILLER_FIXED, pad=FILLER_PAD,
        group=GROUP_ID, existing=EXISTING_GROUP_ID, t0=T0, login=LOGIN_EDITED, note=NOTE, desktop=DESKTOP,
        deleted=LOGIN_DELETED, bookmark=BOOKMARK, unicode=NOTE_UNICODE, tie=LOGIN_TIE,
    )
    return text.encode("utf-8")


# --- driver ------------------------------------------------------------------------------------


def hardening_cases(identities: dict[str, DeviceIdentity], view_a: bytes) -> tuple[bytes, bytes]:
    """``signatures/A.lgksig`` and ``hardening_cases.json`` (audit 2026-10-24 M-6/M-7)."""
    a, b = identities["A"], identities["B"]
    sig = sign_view(view_a, a.signing_key)
    header = json.loads(view_a[len(MAGIC):view_a.index(b"\n", len(MAGIC))])
    doc = json.loads(sig)
    body = {k: v for k, v in doc.items() if k != "sig"}

    def signed(fields: dict, key=a.signing_key) -> str:
        fields = {**fields, "signing_public": b64(key.public_key().public_bytes_raw())}
        return canonical_json({**fields, "sig": b64(key.sign(SIG_LABEL + canonical_json(fields)))}).decode("utf-8")

    sig_cases = [
        ("valid", sig.decode("utf-8")),
        ("signed by another device (valid; the reader checks the key)", signed(body, b.signing_key)),
        ("next counter", signed({**body, "counter": header["counter"] + 1})),
        ("other epoch", signed({**body, "epoch": header["epoch"] + 1})),
        ("other device", signed({**body, "device_id": DEVICE_IDS["B"]})),
        ("other file hash", signed({**body, "view_sha256": "0" * 64})),
        ("signature of other bytes", canonical_json({**doc, "sig": b64(a.signing_key.sign(b"other"))}).decode()),
        ("signing_public swapped", canonical_json({**doc, "signing_public": b64(b.signing_public_key)}).decode()),
        ("extra field", canonical_json({**doc, "x": 1}).decode()),
        ("missing sig", canonical_json(body).decode()),
        ("format 2", signed({**body, "format": 2})),
        ("format true", canonical_json({**doc, "format": True}).decode()),
        ("counter as string", canonical_json({**doc, "counter": str(header["counter"])}).decode()),
        ("uppercase hash", canonical_json({**doc, "view_sha256": body["view_sha256"].upper()}).decode()),
        ("short key", canonical_json({**doc, "signing_public": b64(b"\x01" * 31)}).decode()),
        ("unpadded sig", canonical_json({**doc, "sig": doc["sig"].rstrip("=")}).decode()),
        ("not canonical (space)", json.dumps(doc, sort_keys=True)),
        ("duplicate key", sig.decode("utf-8")[:-1] + ',"format":1}'),
        ("not JSON", "LGKSIG"),
        ("too large", canonical_json({**doc, "pad": "x" * 4096}).decode()),
    ]
    signatures = []
    for name, text in sig_cases:
        try:
            verify_view_signature(text.encode("utf-8"), view_a, header)
            expected = "valid"
        except SyncFormatError as exc:
            expected = exc.reason
        signatures.append({"name": name, "signature": text, "expected": expected})

    big, unknown, step = sync_engine.MAX_VV_COUNTER, sync_engine.MAX_UNKNOWN_VV_COUNTER, sync_engine.MAX_VV_STEP
    known = ["A", "B"]
    vv_inputs = [
        ({"A": 3, "B": 1}, {"A": 2}, known),
        ({"A": big}, None, known),
        ({"A": big + 1}, None, known),
        ({"A": 2**53 - 1, "B": 2**53 - 1}, None, known),
        ({"A": 2**53 - 1}, {"A": 2**53 - 1}, known),
        ({"A": big + 1}, {"A": big}, known),
        ({"A": big + step}, {"A": big}, known),
        ({"A": big + step + 1}, {"A": big}, known),
        ({"Z": unknown}, None, known),
        ({"Z": unknown + 1}, None, known),
        ({"Z": unknown + 1}, {"Z": 1}, known),
        ({"Z": big}, {"Z": 1}, known),
        ({"Z": big + 1}, {"Z": 1}, known),
        ({"A": 1}, {"A": 9}, []),
        ({f"d{i:03}": 1 for i in range(sync_engine.MAX_VV_KEYS)}, None, []),
        ({f"d{i:03}": 1 for i in range(sync_engine.MAX_VV_KEYS + 1)}, None, []),
    ]
    vv = [{"remote": r, "local": loc, "known": k, "expected": implausible_vv(r, loc, set(k))}
          for r, loc, k in vv_inputs]
    counter_inputs = [(1, None), (MAX_FILE_COUNTER, None), (MAX_FILE_COUNTER + 1, None), (2**53 - 1, None),
                      (5, 5), (4, 5), (5 + MAX_COUNTER_JUMP, 5), (6 + MAX_COUNTER_JUMP, 5),
                      (MAX_FILE_COUNTER + 10, MAX_FILE_COUNTER), (2**53 - 1, 7)]
    counters = [{"counter": c, "last": last, "expected": counter_verdict(c, last)} for c, last in counter_inputs]
    cases = {
        "constants": {
            "MAX_VV_COUNTER": big, "MAX_UNKNOWN_VV_COUNTER": unknown, "MAX_VV_STEP": step,
            "MAX_VV_KEYS": sync_engine.MAX_VV_KEYS, "MAX_FILE_COUNTER": MAX_FILE_COUNTER,
            "MAX_COUNTER_JUMP": MAX_COUNTER_JUMP, "SIG_LABEL": SIG_LABEL.decode("ascii"),
        },
        "vv": vv,
        "counters": counters,
        "signatures": signatures,
    }
    return sig, dumps(cases)


def generate(out: Path) -> None:
    """Write every vector file under *out* (created if missing)."""
    out = Path(out)
    identities = {name: make_identity(name) for name in DEVICES}
    built = build_keyrings(identities)
    existing = build_existing_keyrings(identities)
    gk1: GroupKey = built["gk"][1]
    states = device_states()
    devices = encode_devices(gk1, states)

    lan_session, lan_facts = lan_session_files(identities, gk1)
    files: dict[str, bytes] = {
        "README.md": readme(lan_facts),
        "identities.json": identities_json(identities),
        "keyring_epoch1_ab.json": canonical_json(built["ring_ab"]),
        "keyring_epoch1.json": canonical_json(built["ring1"]),
        "keyring_epoch2.json": canonical_json(built["ring2"]),
        "keyring_existing_epoch1.json": canonical_json(existing["ring1"]),
        "keyring_existing_epoch3.json": canonical_json(existing["ring3"]),
        "keyring_v1_epoch1.json": canonical_json(format1_keyring(built["ring1"], gk1)),
        "keyring_attach.json": canonical_json(existing["attach"]),
        "expected.json": expected_json(built, existing_expected(existing), unicode_password()),
        "canonical_json.json": canonical_json_file(),
        "license_state.json": license_state_file(),
        "schema_cases.json": schema_cases_file(),
        "expected_merge.json": expected_merge_json(states),
    }
    for name, raw in devices.items():
        files[f"devices/{name}.lgksync"] = raw
    files["signatures/A.lgksig"], files["hardening_cases.json"] = hardening_cases(identities, devices["A"])
    files.update(lan_files(identities, gk1))
    files.update(lan_session)
    files.update(normalise_files())
    files.update(passkey_files())

    assert tuple(sorted(files)) == GENERATED_FILES, sorted(files)
    for rel, data in files.items():
        path = out / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)


def main(argv: list[str]) -> int:
    out = Path(argv[1]) if len(argv) > 1 else DEFAULT_OUT
    generate(out)
    print(f"wrote {len(GENERATED_FILES)} files to {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
