"""Generate the signed sync removal notice vectors in ``tests/vectors/sync/removal``.

Test-only.  Every key is a published TEST key: devices A, B and C of
``tests/vectors/sync/identities.json`` plus a stranger D whose seed is derived from a fixed label.
Ed25519 is deterministic and every time is fixed (``T0 = 1790000000``), so the output never depends
on the clock or on randomness.

The group is the one of ``tests/vectors/sync``: the trusted keyring is ``keyring_epoch1.json``
(A, B, C, format 2, every member with ``signing_public``), the folder keyring after the removal is
``keyring_epoch2.json`` (A rotated and removed C).  The removed device is C; its watch is derived
from the epoch-1 keyring with ``removal.watch_from_state``.

Every expected result is what ``removal.verify_notice`` / ``removal.load_watch`` returns; each case
also states the result it is meant to show, and generation fails if Python disagrees.

Usage::

    python scripts/gen_removal_vectors.py [OUT_DIR]      # default: tests/vectors/sync/removal
"""

# ruff: noqa: S101

from __future__ import annotations

import base64
import hashlib
import json
import sys
import tempfile
from pathlib import Path
from types import SimpleNamespace
from typing import Any

from cryptography.hazmat.primitives.asymmetric import ed25519

from localvault.sync import keyring as kr
from localvault.sync import removal
from localvault.updates import canonical_json

ROOT = Path(__file__).resolve().parent.parent
SYNC_VEC = ROOT / "tests" / "vectors" / "sync"
OUT = SYNC_VEC / "removal"

T0 = 1790000000
ISSUED_AT = T0 + 600
GROUP_ID = "5b0c7d3e-9a41-4f6b-8c2d-3e1a7f905b64"
OTHER_GROUP = "e6a1c2d4-7b30-4c58-9f12-0a8d5b3c6e71"
STRANGER_ID = "d4444444-0000-4000-8000-00000000000d"
STRANGER_SEED = hashlib.sha256(b"localgatekeys|test|removal-vectors|stranger").digest()
INSTALL_ID = "c3333333-install-0000-4000-8000-0000000000c1"
FOLDER = "C:\\Users\\Alex\\OneDrive"
# Group order of Ed25519 (the signature's S must be below it).
L = 2**252 + 27742317777372353535851937790883648493
WARNING = "TEST ONLY. Every private key here is published on purpose. Never use one for a real device or vault."


def b64(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def dump(value: Any) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True, ensure_ascii=True) + "\n").encode("ascii")


_B64_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"


def flip_padding_bit(text: str) -> str:
    """*text* (padded base64) with the lowest bit of its last data character flipped: an unused padding bit."""
    data = text.rstrip("=")
    last = _B64_ALPHABET[_B64_ALPHABET.index(data[-1]) ^ 1]
    out = data[:-1] + last + text[len(data):]
    assert out != text and base64.b64decode(out) == base64.b64decode(text)
    return out


def text_or_none(raw: bytes) -> str | None:
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        return None


# --- fixed inputs ------------------------------------------------------------------------------------

def identities() -> dict[str, dict[str, Any]]:
    devices = json.loads((SYNC_VEC / "identities.json").read_text(encoding="utf-8"))["devices"]
    out: dict[str, dict[str, Any]] = {}
    for name in ("A", "B", "C"):
        d = devices[name]
        seed = base64.b64decode(d["private"]["signing_private"])
        out[name] = {"device_id": d["device_id"], "seed": seed}
    out["D"] = {"device_id": STRANGER_ID, "seed": STRANGER_SEED}
    for d in out.values():
        d["key"] = ed25519.Ed25519PrivateKey.from_private_bytes(d["seed"])
        d["public_b64"] = b64(d["key"].public_key().public_bytes_raw())
    assert out["A"]["public_b64"] == devices["A"]["signing_public_b64"]
    return out


def keyrings(ids: dict[str, dict[str, Any]]) -> dict[str, dict[str, Any]]:
    """name -> {"raw": bytes, "source", "synthetic"}; synthetic rings are edited copies (MAC invalid)."""
    e1 = (SYNC_VEC / "keyring_epoch1.json").read_bytes()
    e2 = (SYNC_VEC / "keyring_epoch2.json").read_bytes()
    v1 = (SYNC_VEC / "keyring_v1_epoch1.json").read_bytes()
    ring1, ring2 = kr.parse_keyring(e1), kr.parse_keyring(e2)
    c_entry = next(m for m in ring1["members"] if m["device_id"] == ids["C"]["device_id"])

    def edit(**changes: Any) -> bytes:
        return canonical_json({**ring2, **changes})

    rings = {
        "trusted_epoch1": (e1, "tests/vectors/sync/keyring_epoch1.json", False),
        "trusted_epoch1_format1": (v1, "tests/vectors/sync/keyring_v1_epoch1.json", False),
        "folder_epoch2": (e2, "tests/vectors/sync/keyring_epoch2.json", False),
        "synthetic_epoch3_without_c": (edit(epoch=3), "keyring_epoch2.json with epoch 3", True),
        "synthetic_epoch2_lists_c": (
            edit(members=sorted([*ring2["members"], c_entry], key=lambda m: m["device_id"])),
            "keyring_epoch2.json with C's epoch-1 member entry added", True),
        "synthetic_other_group": (edit(group_id=OTHER_GROUP), "keyring_epoch2.json with another group_id", True),
        "synthetic_members_not_list": (edit(members={}), "keyring_epoch2.json with members = {}", True),
        "synthetic_epoch_float": (e2.replace(b'"epoch":2,', b'"epoch":2.0,'), "epoch written as 2.0", True),
        "synthetic_epoch_string": (edit(epoch="2"), 'epoch written as "2"', True),
        "synthetic_group_invalid_id": (edit(group_id="not a valid id"), "group_id with spaces", True),
        "synthetic_member_bad_ids": (
            edit(members=[*ring2["members"], {"device_id": []}, {"device_id": 7}, "junk"]),
            "keyring_epoch2.json plus members that are not objects with a text device_id (ignored)", True),
        "synthetic_duplicate_key": (e2[:-1] + b',"epoch":3}', "keyring_epoch2.json with a second epoch key", True),
        "synthetic_not_json": (b"not json", "not JSON", True),
        "synthetic_array": (b"[]", "a JSON array", True),
        "synthetic_empty": (b"", "zero bytes", True),
    }
    assert rings["synthetic_epoch_float"][0] != e2
    return {n: {"raw": raw, "source": src, "synthetic": syn} for n, (raw, src, syn) in rings.items()}


def watches(ids: dict[str, dict[str, Any]], rings: dict[str, dict[str, Any]]) -> dict[str, removal.Watch]:
    c = ids["C"]["device_id"]

    def derive(ring: str, unacked: tuple[str, ...] = ()) -> removal.Watch:
        state = SimpleNamespace(keyring=rings[ring]["raw"], install_id=INSTALL_ID, group_id=GROUP_ID,
                                device_id=c, epoch=1, unacked_members=unacked)
        watch = removal.watch_from_state(state, FOLDER)
        assert watch is not None
        return watch

    trusted = derive("trusted_epoch1")
    assert set(trusted.signers) == {ids["A"]["device_id"], ids["B"]["device_id"]}

    def with_a_key(value: str) -> removal.Watch:
        return removal.Watch(trusted.group_id, trusted.device_id, trusted.epoch, trusted.install_id, trusted.folder,
                             {**trusted.signers, ids["A"]["device_id"]: value})

    a_raw = base64.b64decode(ids["A"]["public_b64"])
    noncanonical = flip_padding_bit(b64(a_raw))
    return {
        "trusted_c": trusted,
        "trusted_c_format1": derive("trusted_epoch1_format1"),
        "trusted_c_b_unconfirmed": derive("trusted_epoch1", (ids["B"]["device_id"],)),
        "bad_key_not_base64": with_a_key("not base64!"),
        "bad_key_31_bytes": with_a_key(b64(a_raw[:31])),
        "bad_key_noncanonical_base64": with_a_key(noncanonical),
    }


# --- notices -----------------------------------------------------------------------------------------

def body(ids: dict[str, dict[str, Any]], **changes: Any) -> dict[str, Any]:
    out = {"format": 1, "group_id": GROUP_ID, "device_id": ids["C"]["device_id"], "epoch": 2,
           "signer": ids["A"]["device_id"], "issued_at": ISSUED_AT}
    out.update(changes)
    return out


def signed(key: ed25519.Ed25519PrivateKey, b: dict[str, Any], *, label: bytes = removal.NOTICE_LABEL) -> dict:
    """*b* plus ``sig`` over ``label + canonical_json(b)`` (bodies make_notice would refuse are allowed)."""
    return {**b, "sig": b64(key.sign(label + canonical_json(b)))}


def notice_cases(ids: dict[str, dict[str, Any]]) -> list[dict[str, Any]]:
    a, b_, c, d = (ids[n]["key"] for n in "ABCD")
    A, B, C, D = (ids[n]["device_id"] for n in "ABCD")
    good = signed(a, body(ids))
    good_raw = canonical_json(good)
    assert good_raw == removal.make_notice(a, group_id=GROUP_ID, device_id=C, epoch=2, signer=A, now=ISSUED_AT)
    sig = base64.b64decode(good["sig"])

    def raw(doc: dict) -> bytes:
        return canonical_json(doc)

    def with_sig(s: bytes) -> bytes:
        return raw({**good, "sig": b64(s)})

    def unsorted_spaced() -> bytes:
        return json.dumps(dict(reversed(list(good.items()))), indent=1).encode("ascii")

    def padded(total: int) -> bytes:
        return good_raw[:-1] + b" " * (total - len(good_raw)) + b"}"

    s_int = int.from_bytes(sig[32:], "little")
    malleated = sig[:32] + (s_int + L).to_bytes(32, "little")
    flipped = bytearray(sig)
    flipped[0] ^= 1
    sig_b64 = good["sig"]
    sig_noncanonical = flip_padding_bit(sig_b64)

    def rawtext(text: str) -> bytes:
        return text.encode("utf-8")

    good_text = good_raw.decode("ascii")
    ok, kr_ = None, "keyring"
    # (name, description, notice bytes, watch, folder keyring, expected reason or None)
    cases: list[tuple[str, str, bytes, str, str, str | None]] = [
        ("valid", "A's notice that C was removed at epoch 2 (exact writer output).",
         good_raw, "trusted_c", "folder_epoch2", ok),
        ("valid-signed-by-other-member", "B, also a trusted member with a signing key, signs it.",
         raw(signed(b_, body(ids, signer=B))), "trusted_c", "folder_epoch2", ok),
        ("valid-folder-keyring-later-epoch", "Folder keyring at epoch 3 (> notice epoch 2) without C.",
         good_raw, "trusted_c", "synthetic_epoch3_without_c", ok),
        ("valid-folder-keyring-ignores-bad-members",
         "Members that are not objects with a text device_id are ignored (C is not listed).",
         good_raw, "trusted_c", "synthetic_member_bad_ids", ok),
        ("valid-noncanonical-layout",
         "Keys in reverse order with whitespace: accepted; the signature covers the canonical re-serialisation.",
         unsorted_spaced(), "trusted_c", "folder_epoch2", ok),
        ("valid-trailing-newline", "Writer output plus one LF.", good_raw + b"\n", "trusted_c", "folder_epoch2", ok),
        ("valid-escaped-id", "group_id with its first character written as \\u0035 (decodes to the same id).",
         good_raw.replace(b'"group_id":"5', b'"group_id":"\\u0035'), "trusted_c", "folder_epoch2", ok),
        ("valid-exactly-max-size", "Padded with spaces to exactly MAX_NOTICE_BYTES (4096).",
         padded(removal.MAX_NOTICE_BYTES), "trusted_c", "folder_epoch2", ok),
        ("valid-issued-at-zero", "issued_at is not checked against any clock (0).",
         raw(signed(a, body(ids, issued_at=0))), "trusted_c", "folder_epoch2", ok),
        ("valid-issued-at-max", "issued_at = 2^53 - 1 (far future) is accepted: no clock check.",
         raw(signed(a, body(ids, issued_at=2**53 - 1))), "trusted_c", "folder_epoch2", ok),
        # not-for-this-device
        ("wrong-device", "Names B, not C.", raw(signed(a, body(ids, device_id=B))), "trusted_c", "folder_epoch2",
         "not-for-this-device"),
        ("wrong-group", "Names another group.", raw(signed(a, body(ids, group_id=OTHER_GROUP))), "trusted_c",
         "folder_epoch2", "not-for-this-device"),
        # stale
        ("epoch-equal-trusted", "Epoch 1 = the trusted epoch.", raw(signed(a, body(ids, epoch=1))), "trusted_c",
         "folder_epoch2", "stale"),
        ("epoch-below-trusted", "Epoch 0.", raw(signed(a, body(ids, epoch=0))), "trusted_c", "folder_epoch2",
         "stale"),
        ("signer-is-the-device", "C signs its own removal (checked before the signer lookup).",
         raw(signed(c, body(ids, signer=C))), "trusted_c", "folder_epoch2", "stale"),
        # unknown-signer
        ("signer-not-a-member", "Stranger D (not in the trusted keyring) signs.",
         raw(signed(d, body(ids, signer=D))), "trusted_c", "folder_epoch2", "unknown-signer"),
        ("signer-without-signing-key", "Watch from the format-1 keyring: no member has a signing key.",
         good_raw, "trusted_c_format1", "folder_epoch2", "unknown-signer"),
        ("signer-unconfirmed", "Watch where B was an unconfirmed member: B is not a signer.",
         raw(signed(b_, body(ids, signer=B))), "trusted_c_b_unconfirmed", "folder_epoch2", "unknown-signer"),
        # bad-signature
        ("signed-by-other-key", "Claims signer A but signed with B's key.",
         raw(signed(b_, body(ids))), "trusted_c", "folder_epoch2", "bad-signature"),
        ("signed-by-stranger-as-a", "Claims signer A but signed with D's key.",
         raw(signed(d, body(ids))), "trusted_c", "folder_epoch2", "bad-signature"),
        ("tampered-issued-at", "issued_at changed after signing.", raw({**good, "issued_at": ISSUED_AT + 1}),
         "trusted_c", "folder_epoch2", "bad-signature"),
        ("tampered-epoch", "Epoch raised to 3 after signing.", raw({**good, "epoch": 3}),
         "trusted_c", "synthetic_epoch3_without_c", "bad-signature"),
        ("signature-bit-flipped", "First signature byte XOR 1.", with_sig(bytes(flipped)), "trusted_c",
         "folder_epoch2", "bad-signature"),
        ("signature-s-plus-l", "S replaced by S + L (malleated, non-canonical S must be rejected).",
         with_sig(malleated), "trusted_c", "folder_epoch2", "bad-signature"),
        ("signature-zero", "64 zero bytes.", with_sig(bytes(64)), "trusted_c", "folder_epoch2", "bad-signature"),
        ("signed-without-label", "Signature over canonical_json(body) only, without NOTICE_LABEL.",
         raw(signed(a, body(ids), label=b"")), "trusted_c", "folder_epoch2", "bad-signature"),
        # bad-key (the watch's signer key is checked only when that signer is used)
        ("watch-key-not-base64", "The watch's key for A is not base64.", good_raw, "bad_key_not_base64",
         "folder_epoch2", "bad-key"),
        ("watch-key-31-bytes", "The watch's key for A decodes to 31 bytes.", good_raw, "bad_key_31_bytes",
         "folder_epoch2", "bad-key"),
        ("watch-key-noncanonical-base64", "The watch's key for A has a nonzero padding bit.", good_raw,
         "bad_key_noncanonical_base64", "folder_epoch2", "bad-key"),
        # keyring corroboration (only after the signature verified)
        ("folder-keyring-still-epoch1", "The folder still holds the trusted epoch-1 keyring (lists C, epoch 1 < 2).",
         good_raw, "trusted_c", "trusted_epoch1", kr_),
        ("folder-keyring-lists-device", "Folder keyring at epoch 2 that still lists C.", good_raw, "trusted_c",
         "synthetic_epoch2_lists_c", kr_),
        ("folder-keyring-older-than-notice", "Notice at epoch 3, folder keyring at epoch 2.",
         raw(signed(a, body(ids, epoch=3))), "trusted_c", "folder_epoch2", kr_),
        ("folder-keyring-other-group", "Folder keyring of another group.", good_raw, "trusted_c",
         "synthetic_other_group", kr_),
        ("folder-keyring-members-not-list", "members is an object.", good_raw, "trusted_c",
         "synthetic_members_not_list", kr_),
        ("folder-keyring-epoch-float", "Keyring epoch 2.0.", good_raw, "trusted_c", "synthetic_epoch_float", kr_),
        ("folder-keyring-epoch-string", 'Keyring epoch "2".', good_raw, "trusted_c", "synthetic_epoch_string", kr_),
        ("folder-keyring-group-invalid", "Keyring group_id is not a valid id.", good_raw, "trusted_c",
         "synthetic_group_invalid_id", kr_),
        ("folder-keyring-duplicate-key", "Keyring with a duplicate key.", good_raw, "trusted_c",
         "synthetic_duplicate_key", kr_),
        ("folder-keyring-not-json", "Keyring is not JSON.", good_raw, "trusted_c", "synthetic_not_json", kr_),
        ("folder-keyring-array", "Keyring is a JSON array.", good_raw, "trusted_c", "synthetic_array", kr_),
        ("folder-keyring-empty", "Keyring is empty.", good_raw, "trusted_c", "synthetic_empty", kr_),
    ]
    bad = "bad-notice"
    malformed: list[tuple[str, str, bytes]] = [
        ("oversized", "MAX_NOTICE_BYTES + 1 (otherwise valid, padded with spaces).",
         padded(removal.MAX_NOTICE_BYTES + 1)),
        ("empty", "Zero bytes.", b""),
        ("not-json", "Not JSON.", b"removed"),
        ("array", "A JSON array.", b"[]"),
        ("extra-field", "An extra field (signed with it).", raw(signed(a, {**body(ids), "reason": "lost"}))),
        ("missing-issued-at", "No issued_at (signed without it).",
         raw(signed(a, {k: v for k, v in body(ids).items() if k != "issued_at"}))),
        ("missing-sig", "No sig.", raw(body(ids))),
        ("duplicate-key", "epoch appears twice.", good_raw[:-1] + b',"epoch":2}'),
        ("format-2", "format 2 (signed).", raw(signed(a, body(ids, format=2)))),
        ("format-true", "format true.", raw({**good, "format": True})),
        ("format-float", "format 1.0.", rawtext(good_text.replace('"format":1', '"format":1.0'))),
        ("format-string", 'format "1".', raw({**good, "format": "1"})),
        ("epoch-string", 'epoch "2".', raw({**good, "epoch": "2"})),
        ("epoch-float", "epoch 2.0.", rawtext(good_text.replace('"epoch":2', '"epoch":2.0'))),
        ("epoch-exponent", "epoch 2e0.", rawtext(good_text.replace('"epoch":2', '"epoch":2e0'))),
        ("epoch-negative", "epoch -1.", raw({**good, "epoch": -1})),
        ("epoch-true", "epoch true.", raw({**good, "epoch": True})),
        ("epoch-2-pow-53", "epoch 2^53 (above 2^53 - 1).", raw({**good, "epoch": 2**53})),
        ("epoch-2-pow-64", "epoch 2^64.", raw({**good, "epoch": 2**64})),
        ("epoch-null", "epoch null.", raw({**good, "epoch": None})),
        ("issued-at-negative", "issued_at -1.", raw({**good, "issued_at": -1})),
        ("issued-at-nan", "issued_at NaN.", rawtext(good_text.replace(f'"issued_at":{ISSUED_AT}', '"issued_at":NaN'))),
        ("device-id-path", "device_id with a slash.", raw({**good, "device_id": "c3333333/../x"})),
        ("device-id-empty", "device_id empty.", raw({**good, "device_id": ""})),
        ("device-id-129-chars", "device_id of 129 characters.", raw({**good, "device_id": "c" * 129})),
        ("device-id-non-ascii", "device_id with a non-ASCII letter.", raw({**good, "device_id": "c3333333-\u00e9"})),
        ("signer-number", "signer is a number.", raw({**good, "signer": 1})),
        ("sig-null", "sig null.", raw({**good, "sig": None})),
        ("sig-bad-chars", "sig with a character outside base64.", raw({**good, "sig": "!" + sig_b64[1:]})),
        ("sig-url-safe", "sig in the URL-safe alphabet.",
         raw({**good, "sig": base64.urlsafe_b64encode(sig).decode()}) if "+" in sig_b64 or "/" in sig_b64 else
         raw({**good, "sig": "-" + sig_b64[1:]})),
        ("sig-no-padding", "sig without its == padding.", raw({**good, "sig": sig_b64.rstrip("=")})),
        ("sig-noncanonical-base64", "sig with a nonzero padding bit (decodes to the same 64 bytes).",
         raw({**good, "sig": sig_noncanonical})),
        ("sig-trailing-newline", "sig text ends with \\n.", raw({**good, "sig": sig_b64 + "\n"})),
        ("sig-63-bytes", "sig of 63 bytes.", with_sig(sig[:63])),
        ("sig-65-bytes", "sig of 65 bytes.", with_sig(sig + b"\0")),
        ("invalid-utf8", "A 0xFF byte inside a string.", good_raw.replace(b'"signer":"', b'"signer":"\xff')),
        ("utf8-bom", "Writer output preceded by a UTF-8 BOM.", b"\xef\xbb\xbf" + good_raw),
        ("trailing-garbage", "Writer output followed by x.", good_raw + b"x"),
        ("two-objects", "Writer output twice.", good_raw + good_raw),
    ]
    out = []
    for name, desc, notice, watch, ring, reason in cases:
        out.append({"name": name, "description": desc, "notice": notice, "watch": watch, "folder_keyring": ring,
                    "intended": reason})
    for name, desc, notice in malformed:
        out.append({"name": name, "description": desc, "notice": notice, "watch": "trusted_c",
                    "folder_keyring": "folder_epoch2", "intended": bad})
    return out


def run_verify(notice: bytes, watch: removal.Watch, ring: bytes) -> dict[str, Any]:
    try:
        n = removal.verify_notice(notice, watch, ring)
    except removal.RemovalError as exc:
        return {"accept": False, "reason": exc.reason, "notice": None}
    return {"accept": True, "reason": None,
            "notice": {"group_id": n.group_id, "device_id": n.device_id, "epoch": n.epoch, "signer": n.signer,
                       "issued_at": n.issued_at}}


def watch_doc(w: removal.Watch) -> dict[str, Any]:
    return w.to_dict()


def build_notices(ids, rings, ws) -> dict[str, Any]:
    cases = []
    for case in notice_cases(ids):
        result = run_verify(case["notice"], ws[case["watch"]], rings[case["folder_keyring"]]["raw"])
        assert result["reason"] == case["intended"], (case["name"], result)
        cases.append({"name": case["name"], "description": case["description"],
                      "notice_b64": b64(case["notice"]), "notice_text": text_or_none(case["notice"]),
                      "watch": case["watch"], "folder_keyring": case["folder_keyring"], "expected": result})
    names = [c["name"] for c in cases]
    assert len(names) == len(set(names))
    ring_docs = {}
    for name, r in rings.items():
        ring_docs[name] = {"b64": b64(r["raw"]), "source": r["source"], "synthetic": r["synthetic"]}
    return {
        "WARNING": WARNING,
        "about": ("verify_notice(notice bytes, watch, folder keyring bytes) for every case. The removed device is C, "
                  "trusted epoch 1. 'expected.reason' is the RemovalError reason, null when accepted. See "
                  "tests/vectors/sync/README.md 'Removal notices'."),
        "constants": {"notice_format": removal.NOTICE_FORMAT, "notice_label": removal.NOTICE_LABEL.decode("ascii"),
                      "max_notice_bytes": removal.MAX_NOTICE_BYTES, "max_keyring_bytes": kr.MAX_KEYRING_BYTES,
                      "max_int": 2**53 - 1, "removed_dir": removal.REMOVED_DIR_NAME,
                      "notice_suffix": removal.NOTICE_SUFFIX, "group_id": GROUP_ID, "t0": T0},
        "identities": {n: {"device_id": d["device_id"], "signing_private_seed_b64": b64(d["seed"]),
                           "signing_public_b64": d["public_b64"]} for n, d in ids.items()},
        "keyrings": ring_docs,
        "watches": {n: watch_doc(w) for n, w in ws.items()},
        "cases": cases,
    }


def build_writer(ids) -> dict[str, Any]:
    specs = [
        ("A", "C", 2, ISSUED_AT, "A removes C: epoch 1 -> 2 (the notice of notices.json case 'valid')."),
        ("B", "C", 7, T0 + 86400, "B removes C at epoch 7."),
        ("A", "B", 2, 0, "A removes B at epoch 2, issued_at 0."),
    ]
    cases = []
    for signer, removed, epoch, issued, desc in specs:
        key = ids[signer]["key"]
        b = body(ids, device_id=ids[removed]["device_id"], epoch=epoch, signer=ids[signer]["device_id"],
                 issued_at=issued)
        notice = removal.make_notice(key, group_id=GROUP_ID, device_id=b["device_id"], epoch=epoch,
                                     signer=b["signer"], now=issued)
        message = removal.NOTICE_LABEL + canonical_json(b)
        sig = key.sign(message)
        assert notice == canonical_json({**b, "sig": b64(sig)})
        cases.append({
            "description": desc, "signer": signer,
            "inputs": {"group_id": GROUP_ID, "device_id": b["device_id"], "epoch": epoch, "signer": b["signer"],
                       "issued_at": issued, "signing_private_seed_b64": b64(ids[signer]["seed"])},
            "path": f"LocalGateKeys Sync/{removal.REMOVED_DIR_NAME}/{removal.notice_name(b['device_id'])}",
            "body_canonical": canonical_json(b).decode("ascii"),
            "signed_message_hex": message.hex(),
            "sig_b64": b64(sig),
            "notice_text": notice.decode("ascii"),
            "notice_sha256": hashlib.sha256(notice).hexdigest(),
        })
    refusals = []
    for desc, kw in (
        ("signer is the removed device", {"device_id": ids["A"]["device_id"]}),
        ("epoch negative", {"epoch": -1}),
        ("epoch 2^53", {"epoch": 2**53}),
        ("issued_at negative", {"now": -1}),
        ("device id with a slash", {"device_id": "c3333333/x"}),
        ("group id empty", {"group_id": ""}),
    ):
        args = {"group_id": GROUP_ID, "device_id": ids["C"]["device_id"], "epoch": 2,
                "signer": ids["A"]["device_id"], "now": ISSUED_AT, **kw}
        try:
            removal.make_notice(ids["A"]["key"], **args)
        except removal.RemovalError as exc:
            reason = exc.reason
        else:
            raise AssertionError(desc)
        inputs = {("issued_at" if k == "now" else k): v for k, v in args.items()}
        refusals.append({"description": desc, "inputs": inputs, "error": reason})
    return {
        "WARNING": WARNING,
        "about": ("removal.make_notice output for fixed removals: canonical JSON (sorted keys, no whitespace, "
                  "no trailing newline) of the body plus sig. Writers must produce these bytes exactly. "
                  "'refusals': inputs the writer must refuse (Python raises RemovalError('bad-notice'))."),
        "cases": cases,
        "refusals": refusals,
    }


def build_watch(ids, rings, ws) -> dict[str, Any]:
    trusted = ws["trusted_c"]
    trusted_bytes = canonical_json(trusted.to_dict())
    A, B, C = (ids[n]["device_id"] for n in "ABC")
    derive = []
    for name, ring, unacked in (("all-confirmed", "trusted_epoch1", []),
                                ("b-unconfirmed", "trusted_epoch1", [B]),
                                ("format-1-keyring", "trusted_epoch1_format1", [])):
        state = SimpleNamespace(keyring=rings[ring]["raw"], install_id=INSTALL_ID, group_id=GROUP_ID,
                                device_id=C, epoch=1, unacked_members=tuple(unacked))
        w = removal.watch_from_state(state, FOLDER)
        derive.append({"name": name, "state": {"group_id": GROUP_ID, "device_id": C, "epoch": 1,
                                               "install_id": INSTALL_ID, "keyring": ring,
                                               "unacked_members": unacked},
                       "folder": FOLDER, "watch_text": canonical_json(w.to_dict()).decode("ascii")})

    def parse_case(name: str, desc: str, raw: bytes) -> dict[str, Any]:
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "vault.sync-watch.json"
            p.write_bytes(raw)
            w = removal.load_watch(p)
        return {"name": name, "description": desc, "b64": b64(raw), "text": text_or_none(raw),
                "expected": None if w is None else w.to_dict()}

    doc = trusted.to_dict()
    text = trusted_bytes.decode("ascii")

    def edited(**changes: Any) -> bytes:
        return canonical_json({**doc, **changes})

    parse = [
        parse_case("valid", "The watch C writes after a folder run at trusted epoch 1.", trusted_bytes),
        parse_case("valid-spaced", "Same content, indented and unsorted.",
                   json.dumps(dict(reversed(list(doc.items()))), indent=2).encode("ascii")),
        parse_case("valid-no-signers", "signers empty.", edited(signers={})),
        parse_case("valid-non-ascii-folder", "A folder with a non-ASCII letter: written as raw UTF-8 (not escaped).",
                   edited(folder="C:\\Users\\Zo\u00eb\\OneDrive")),
        parse_case("valid-key-not-base64", "Signer values are not checked here (verify_notice gives bad-key).",
                   edited(signers={A: "not base64!"})),
        parse_case("valid-exactly-max-size", "Padded with spaces to MAX_WATCH_BYTES.",
                   trusted_bytes[:-1] + b" " * (removal.MAX_WATCH_BYTES - len(trusted_bytes)) + b"}"),
        parse_case("oversized", "MAX_WATCH_BYTES + 1.",
                   trusted_bytes[:-1] + b" " * (removal.MAX_WATCH_BYTES - len(trusted_bytes) + 1) + b"}"),
        parse_case("empty", "Zero bytes.", b""),
        parse_case("not-json", "Not JSON.", b"watch"),
        parse_case("array", "A JSON array.", b"[]"),
        parse_case("extra-field", "An extra field.", edited(note="x")),
        parse_case("missing-folder", "No folder.", canonical_json({k: v for k, v in doc.items() if k != "folder"})),
        parse_case("duplicate-key", "epoch twice.", trusted_bytes[:-1] + b',"epoch":1}'),
        parse_case("version-2", "version 2.", edited(version=2)),
        parse_case("version-true", "version true.", edited(version=True)),
        parse_case("version-float", "version 1.0.", text.replace('"version":1', '"version":1.0').encode("ascii")),
        parse_case("epoch-negative", "epoch -1.", edited(epoch=-1)),
        parse_case("epoch-float", "epoch 1.0.", text.replace('"epoch":1', '"epoch":1.0').encode("ascii")),
        parse_case("epoch-2-pow-53", "epoch 2^53.", edited(epoch=2**53)),
        parse_case("group-invalid", "group_id not a valid id.", edited(group_id="a b")),
        parse_case("device-invalid", "device_id empty.", edited(device_id="")),
        parse_case("install-empty", "install_id empty.", edited(install_id="")),
        parse_case("install-number", "install_id a number.", edited(install_id=1)),
        parse_case("folder-empty", "folder empty.", edited(folder="")),
        parse_case("signers-list", "signers is a list.", edited(signers=[])),
        parse_case("signer-id-invalid", "A signer id with a space.", edited(signers={"a b": "x"})),
        parse_case("signer-key-number", "A signer value that is a number.", edited(signers={A: 1})),
        parse_case("nan", "epoch NaN.", text.replace('"epoch":1', '"epoch":NaN').encode("ascii")),
        parse_case("invalid-utf8", "A 0xFF byte in folder.", trusted_bytes.replace(b'"folder":"', b'"folder":"\xff')),
        parse_case("utf8-bom", "Preceded by a UTF-8 BOM.", b"\xef\xbb\xbf" + trusted_bytes),
    ]

    def mk(signers: dict[str, str], *, device: str = C, group: str = GROUP_ID, epoch: int = 1) -> removal.Watch:
        return removal.Watch(group, device, epoch, INSTALL_ID, FOLDER, signers)

    a_key, b_key, d_key = (ids[n]["public_b64"] for n in "ABD")
    pin_specs = [
        ("no-old-watch", None, mk({A: a_key, B: b_key})),
        ("key-changed-keeps-old", mk({A: a_key, B: b_key}), mk({A: d_key, B: b_key}, epoch=2)),
        ("new-member-added", mk({A: a_key}), mk({A: a_key, B: b_key}, epoch=2)),
        ("member-gone-dropped", mk({A: a_key, B: b_key}), mk({A: a_key}, epoch=2)),
        ("other-device-not-pinned", mk({A: a_key}, device=B), mk({A: d_key})),
        ("other-group-not-pinned", mk({A: a_key}, group=OTHER_GROUP), mk({A: d_key})),
    ]
    pinned = [{"name": n, "old": None if old is None else old.to_dict(), "fresh": fresh.to_dict(),
               "expected": removal.pinned(fresh, old).to_dict()} for n, old, fresh in pin_specs]
    return {
        "WARNING": WARNING,
        "about": ("Watch file <vault stem>.sync-watch.json next to the vault: canonical JSON of the trusted sync "
                  "state. 'parse': bytes -> load_watch result (null = not valid). 'derive': watch_from_state. "
                  "'pinned': removal.pinned(fresh, old). Keyring names refer to notices.json 'keyrings'."),
        "constants": {"watch_version": removal.WATCH_VERSION, "watch_suffix": removal.WATCH_SUFFIX,
                      "max_watch_bytes": removal.MAX_WATCH_BYTES},
        "paths": [{"vault": v, "watch": str(Path(removal.watch_path(Path(v))).name)}
                  for v in ("vault.json", "Family.vault.json", "vault")],
        "example": {"watch_text": text, "parsed": doc},
        "derive": derive,
        "parse": parse,
        "pinned": pinned,
    }


def build() -> dict[str, bytes]:
    ids = identities()
    rings = keyrings(ids)
    ws = watches(ids, rings)
    return {
        "notices.json": dump(build_notices(ids, rings, ws)),
        "writer.json": dump(build_writer(ids)),
        "watch.json": dump(build_watch(ids, rings, ws)),
    }


def main(argv: list[str]) -> int:
    out = Path(argv[1]) if len(argv) > 1 else OUT
    out.mkdir(parents=True, exist_ok=True)
    for name, data in build().items():
        (out / name).write_bytes(data)
        print(f"wrote {out / name} ({len(data)} bytes)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
