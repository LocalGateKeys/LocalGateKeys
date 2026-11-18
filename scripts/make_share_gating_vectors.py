"""Write ``tests/vectors/share/collections/gating.json``: share v2 (keyring format 3) vectors.

Spec: ``docs/superpowers/specs/2026-11-12-collections-crypto-gating.md``.  Every expected value comes from
the desktop code (``localvault.sync.keyring``, ``group``); only randomness is fixed (same streams and
identities as ``scripts/make_share_collection_vectors.py``).  lgk-core (Kotlin) and LGKCore (Swift) must
write the same bytes from ``random_reads_hex`` and refuse the negatives with the same reason.

* ``create``: A shares a collection as share v2 (``C`` wrapped to A).
* ``join_b``: B joins with the password (pending: no content wrap).  ``approve_b``: A wraps ``C`` to B.
* ``join_c``: C joins after that (pending).  ``remove_b``: A removes B and the pending C (rotation, new ``C``).
* ``view``: A's view sealed with ``C``; it does not open with ``G``.
* ``upgrade``: a share v1 keyring (A, approved B, pending C) upgraded to share v2 with the same password.
* ``open``: per keyring, the content key each device opens (null: not approved).
* ``negative``: keyrings a device must refuse when it adopts them; ``open_negative``: keyrings whose
  content wrap opens to a key other than the committed one.  The ``removed_member_forks_*``,
  ``*_swapped`` and ``fork_downgraded_*`` cases (audit 2026-11-12 F-01) check that the owner signature
  binds ``kdf``, ``password_wrap``, the approved members' ``device_wraps`` and ``prev_mac``.
* ``approve_c``: A also approves C (the stored keyring of the fork cases); ``positive``: the genuine
  epoch-2 keyrings those cases forge, which C adopts (``new_key_hex``).

Usage (from the repo root, PYTHONPATH=src)::

    python scripts/make_share_gating_vectors.py [OUT_DIR]
"""

# ruff: noqa: S101, S105

from __future__ import annotations

import base64
import copy
import hashlib
import importlib.util
import json
import sys
import uuid
from pathlib import Path

from localvault.sync import group as grp
from localvault.sync import keyring as kr
from localvault.sync.engine import ItemState

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "tests/vectors/share/collections"


def _base():
    spec = importlib.util.spec_from_file_location("make_share_collection_vectors",
                                                  ROOT / "scripts/make_share_collection_vectors.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


BASE = _base()
COLLECTION_ID, NAME, MODE = BASE.COLLECTION_ID, BASE.NAME, BASE.MODE
PASSWORD, NEW_PASSWORD, NOW = BASE.PASSWORD, BASE.NEW_PASSWORD, BASE.NOW
Source, identity, adopt, remac, b64 = BASE.Source, BASE.identity, BASE.adopt, BASE.remac, BASE.b64

WRAP = 32 + 12  # ephemeral X25519 key + nonce
MEMBER = WRAP + 12  # device wrap + name nonce


def gating_doc() -> dict:
    a, b, c = identity("A"), identity("B"), identity("C")
    who = {"A": a, "B": b, "C": c}
    argon: dict[str, str] = {}

    def remember(password: str, ring: dict) -> None:
        salt = ring["kdf"]["salt"]
        argon[f"{password}|{salt}"] = kr._argon2(password, base64.b64decode(salt), kr._PRODUCTION_KDF).hex()

    def opened(ring: dict) -> dict:
        out = {}
        for name, ident in who.items():
            if ident.device_id in {m["device_id"] for m in ring["members"]}:
                ck = kr.open_content_key(ring, ident)
                out[name] = None if ck is None else ck.key.hex()
        return out

    spec = {"kind": "share", "collection_id": COLLECTION_ID, "name": NAME, "shared_mode": MODE}
    src = Source("gating-create", 16 + 32 + 16 + 12 + MEMBER + 12 + 32 + WRAP)
    group_id = str(uuid.UUID(bytes=src.take(16), version=4))
    created, gk1 = kr.create_group(PASSWORD, a, "Owner phone", _rand=src.take, _now=NOW, _group_id=group_id,
                                   metadata=spec)
    src.done()
    remember(PASSWORD, created)
    ck1 = kr.open_content_key(created, a)
    create = {"random_reads_hex": src.reads, "keyring": created, "group_key_hex": gk1.key.hex(),
              "content_key_hex": ck1.key.hex()}
    pinned = {k: created["metadata"][k] for k in ("collection_id", "owner", "owner_key", "shared_mode")}

    src = Source("gating-join-b", MEMBER)
    joined_b, _ = kr.join_with_password(created, PASSWORD, b, "Bea", _rand=src.take, _now=NOW + 60)
    src.done()
    join_b = {"random_reads_hex": src.reads, "keyring": joined_b}

    src = Source("gating-approve-b", WRAP)
    approved_b = kr.owner_approve_members(joined_b, gk1, a, approve=[b.device_id], _rand=src.take)
    src.done()
    assert kr.open_content_key(approved_b, b) == ck1
    approve_b = {"approve": [b.device_id], "random_reads_hex": src.reads, "keyring": approved_b}

    src = Source("gating-join-c", MEMBER)
    joined_c, _ = kr.join_with_password(approved_b, PASSWORD, c, "Cy", _rand=src.take, _now=NOW + 120)
    src.done()
    join_c = {"random_reads_hex": src.reads, "keyring": joined_c}

    remember(NEW_PASSWORD, joined_c)  # the reuse check derives the new password with the current salt
    src = Source("gating-remove-b", 32 + 16 + 12 + MEMBER + 12 + 32 + WRAP)
    rotated, gk2 = kr.rotate(joined_c, gk1, a, NEW_PASSWORD, remove=[b.device_id, c.device_id], _rand=src.take)
    src.done()
    remember(NEW_PASSWORD, rotated)
    ck2 = kr.open_content_key(rotated, a)
    assert ck2.key != ck1.key
    remove_b = {"remove": [b.device_id, c.device_id], "random_reads_hex": src.reads, "keyring": rotated,
                "group_key_hex": gk2.key.hex(), "content_key_hex": ck2.key.hex()}

    # A's view of one note, sealed with C: it never opens with G.
    state = ItemState("7c1d2e3f-4a5b-4c6d-8e7f-9a0b1c2d3e4f", {a.device_id: 1}, False, None,
                      {"ns": "item", "schema": 1, "updated_at": NOW,
                       "record": {"id": "7c1d2e3f-4a5b-4c6d-8e7f-9a0b1c2d3e4f", "kind": "note", "title": "Wifi",
                                  "payload": {"body": "family wifi"}, "collection_ids": [COLLECTION_ID],
                                  "updated_at": NOW}})
    src = Source("gating-view", 24)
    raw = grp.encode_view(ck1, a.device_id, 1, [state], NOW, nonce_source=src.take)
    src.done()
    assert grp.decode_view(ck1, raw, expected_device_id=a.device_id).states == (state,)
    try:
        grp.decode_view(gk1, raw, expected_device_id=a.device_id)
    except grp.SyncFormatError as exc:
        group_key_reason = exc.reason
    else:
        raise AssertionError("the group key must not open a share v2 view")
    view = {"device": "A", "nonce_reads_hex": src.reads, "view_b64": b64(raw),
            "view_sha256": hashlib.sha256(raw).hexdigest(), "group_key_reason": group_key_reason,
            "states": [{"id": state.item_id, "vv": state.vv, "deleted": False, "deleted_at": None,
                        "item": state.item}]}

    # Share v1 (A owner, B approved, C pending) upgraded to share v2 with the same password.
    src = Source("gating-v1", 16 + 32 + 16 + 12 + MEMBER + 12 + 2 * MEMBER)
    v1_group = str(uuid.UUID(bytes=src.take(16), version=4))
    v1, v1_gk = kr.create_group(PASSWORD, a, "Owner phone", _rand=src.take, _now=NOW, _group_id=v1_group,
                                metadata=spec, share_format=2)
    remember(PASSWORD, v1)
    v1, _ = kr.join_with_password(v1, PASSWORD, b, "Bea", _rand=src.take, _now=NOW + 60)
    v1 = kr.owner_approve_members(v1, v1_gk, a, approve=[b.device_id])
    v1, _ = kr.join_with_password(v1, PASSWORD, c, "Cy", _rand=src.take, _now=NOW + 120)
    src.done()
    src = Source("gating-upgrade", 32 + 16 + 12 + 3 * MEMBER + 12 + 32 + 2 * WRAP)
    upgraded, up_gk = kr.upgrade_share_keyring(v1, v1_gk, a, PASSWORD, _rand=src.take)
    src.done()
    remember(PASSWORD, upgraded)
    assert kr.accept_keyring(upgraded, v1_gk, c) == up_gk and kr.open_content_key(upgraded, c) is None
    upgrade = {"stored": v1, "stored_group_key_hex": v1_gk.key.hex(), "password": PASSWORD,
               "random_reads_hex": src.reads, "keyring": upgraded, "group_key_hex": up_gk.key.hex(),
               "content_key_hex": kr.open_content_key(upgraded, a).key.hex(),
               "approved": sorted(kr.approved_members(upgraded))}

    negative = []

    def case(name: str, device: str, stored: dict, candidate: dict, trusted: grp.GroupKey, why: str) -> None:
        got = adopt(stored, candidate, trusted, who[device], pinned)
        assert got == why, (name, got, why)
        negative.append({"name": name, "device": device, "stored": stored, "candidate": candidate,
                         "trusted_epoch": trusted.epoch, "trusted_key_hex": trusted.key.hex(), "reason": why})

    # Pending B approves itself (owner_sig members) without a content wrap: re-MACed with G.
    forged = copy.deepcopy(joined_b)
    forged["owner_sig"]["members"] = sorted([a.device_id, b.device_id])
    case("pending_self_approval", "A", joined_b, remac(copy.deepcopy(forged), gk1), gk1, "bad-content")
    # ... and with a wrap of a key it picked: the owner signature does not cover it.
    src = Source("gating-forged-wrap", WRAP)
    forged["content"]["wraps"][b.device_id] = kr._wrap_content(grp.GroupKey(group_id, 1, bytes(32)), b.device_id,
                                                               b64(b.exchange_public_key), src.take)
    case("pending_adds_own_content_wrap", "A", joined_b, remac(copy.deepcopy(forged), gk1), gk1, "bad-owner-sig")
    # Approved B replays the creation signature and content block (owner only): un-approves itself.
    replay = copy.deepcopy(approved_b)
    replay["owner_sig"], replay["content"] = copy.deepcopy(created["owner_sig"]), copy.deepcopy(created["content"])
    case("replayed_creation_content", "A", approved_b, remac(replay, gk1), gk1, "tampered")
    # Format checks.
    case("newer_format", "B", approved_b, {**approved_b, "format": 4}, gk1, "newer-format")
    no_content = {k: v for k, v in approved_b.items() if k != "content"}
    case("format3_without_content", "B", approved_b, no_content, gk1, "bad-fields")
    case("format2_with_content", "B", approved_b, {**approved_b, "format": 2}, gk1, "bad-fields")

    # Audit 2026-11-12 F-01: the owner signature binds G (approved members' device wraps, password wrap,
    # kdf, prev_mac).  A approves C too, then removes B; C is offline.  B still holds G of epoch 1 and
    # forges epoch 2 for C: the owner's genuine epoch-2 signature, content and roster, with wraps of a key
    # it picked, its own password wrap and salt, a chain MAC from the old key and a MAC under its key.
    src = Source("gating-approve-c", WRAP)
    approved_c = kr.owner_approve_members(joined_c, gk1, a, approve=[c.device_id], _rand=src.take)
    src.done()
    approve_c = {"approve": [c.device_id], "random_reads_hex": src.reads, "keyring": approved_c}
    src = Source("gating-fork-remove-b", 32 + 16 + 12 + 2 * MEMBER + 12 + 32 + 2 * WRAP)
    fork_rotated, fork_gk2 = kr.rotate(approved_c, gk1, a, NEW_PASSWORD, remove=[b.device_id], _rand=src.take)
    src.done()
    remember(NEW_PASSWORD, fork_rotated)
    assert adopt(approved_c, fork_rotated, gk1, c, pinned) == fork_gk2.key.hex()
    src = Source("gating-pending-remove-b", 32 + 16 + 12 + 2 * MEMBER + 12 + 32 + WRAP)
    pending_rotated, pending_gk2 = kr.rotate(joined_c, gk1, a, NEW_PASSWORD, remove=[b.device_id], _rand=src.take)
    src.done()
    remember(NEW_PASSWORD, pending_rotated)
    assert adopt(joined_c, pending_rotated, gk1, c, pinned) == pending_gk2.key.hex()
    positive = [
        {"name": "approved_member_adopts_removal", "device": "C", "stored": approved_c, "candidate": fork_rotated,
         "trusted_epoch": 1, "trusted_key_hex": gk1.key.hex(), "new_epoch": 2, "new_key_hex": fork_gk2.key.hex()},
        {"name": "pending_member_adopts_removal", "device": "C", "stored": joined_c, "candidate": pending_rotated,
         "trusted_epoch": 1, "trusted_key_hex": gk1.key.hex(), "new_epoch": 2,
         "new_key_hex": pending_gk2.key.hex()},
    ]

    def fork(genuine: dict, label: str) -> tuple[dict, grp.GroupKey]:
        """B's forged epoch 2 and its key: every G-bound field replaced, the owner's signature reused."""
        src = Source(label, 32 + 16 + 12 + 2 * WRAP)
        g_star = grp.GroupKey(group_id, 2, src.take(32))
        salt = src.take(16)
        forged = copy.deepcopy(genuine)
        forged["kdf"]["salt"] = b64(salt)
        forged["password_wrap"] = kr._wrap_password(g_star, "attacker chosen password 99!", salt,
                                                    kr._PRODUCTION_KDF, src.take)
        by_id = {m["device_id"]: m for m in forged["members"]}
        for d in sorted(by_id):
            forged["device_wraps"][d] = kr._wrap_device(g_star, d, base64.b64decode(by_id[d]["exchange_public"]),
                                                        src.take)
        src.done()
        # prev_mac = the chain MAC from the old G (B knows it), mac under the forged key.
        return kr._finish(forged, g_star, gk1), g_star

    forged_fork, g_star = fork(fork_rotated, "gating-fork-forge")
    case("removed_member_forks_next_epoch", "C", approved_c, forged_fork, gk1, "bad-owner-sig")
    case("removed_member_forks_next_epoch_for_pending", "C", joined_c,
         fork(pending_rotated, "gating-fork-forge-pending")[0], gk1, "bad-owner-sig")
    # Each G-bound field changed alone (re-MACed with the genuine new key, so only the signature catches it).
    for name, change in (
        ("kdf_salt_swapped", lambda r: r["kdf"].update(salt=b64(bytes(16)))),
        ("password_wrap_swapped", lambda r: r["password_wrap"].update(nonce=b64(bytes(12)))),
        ("approved_device_wrap_swapped", lambda r: r["device_wraps"].update({c.device_id: r["device_wraps"][a.device_id]})),
        ("prev_mac_swapped", lambda r: r.update(prev_mac=b64(bytes(32)))),
    ):
        changed = copy.deepcopy(fork_rotated)
        change(changed)
        case(name, "C", approved_c, remac(changed, fork_gk2), gk1, "bad-owner-sig")
    # Downgrades of the fork: share v1 (format 2, whose owner message does not bind G) needs an owner v1
    # signature the owner never made; a personal keyring (no share fields) loses the pinned owner.
    as_v1 = {k: v for k, v in forged_fork.items() if k != "content"}
    as_v1["format"] = 2
    case("fork_downgraded_to_share_v1", "C", approved_c, remac(as_v1, g_star), gk1, "bad-owner-sig")
    as_personal = {k: v for k, v in forged_fork.items() if k not in ("content", "metadata", "owner_sig")}
    as_personal["format"] = 2
    case("fork_downgraded_to_personal", "C", approved_c, remac(as_personal, g_star), gk1, "tampered")

    # A keyring the owner signed with a commitment that is not the wrapped key: opening refuses it.
    bad = copy.deepcopy(approved_b)
    bad["content"]["commit"] = b64(bytes(32))
    approved = bad["owner_sig"]["members"]
    body = {k: v for k, v in bad.items() if k not in ("mac", "owner_sig")}
    bad["owner_sig"] = {"members": approved, "sig": b64(a.signing_key.sign(kr._owner_message(body, approved)))}
    bad = remac(bad, gk1)
    kr.verify_keyring_structure(bad)
    try:
        kr.open_content_key(bad, b)
    except kr.KeyringError as exc:
        assert exc.reason == "content-key"
    else:
        raise AssertionError("a wrong commitment must be refused")
    open_negative = [{"name": "commit_mismatch", "device": "B", "keyring": bad, "reason": "content-key"}]

    return {
        "description": "Share v2 keyrings (format 3) written by localvault.sync.keyring with fixed randomness "
                       "(scripts/make_share_gating_vectors.py). A owns the share, B and C join.",
        "spec": "docs/superpowers/specs/2026-11-12-collections-crypto-gating.md",
        "group_id": group_id, "collection_id": COLLECTION_ID, "name": NAME, "shared_mode": MODE,
        "password": PASSWORD, "new_password": NEW_PASSWORD, "now": NOW,
        "owner": "A", "names": {"A": "Owner phone", "B": "Bea", "C": "Cy"}, "pinned": pinned,
        "create": create, "join_b": join_b, "approve_b": approve_b, "join_c": join_c, "remove_b": remove_b,
        "view": view, "upgrade": upgrade,
        "open": {"create": opened(created), "join_b": opened(joined_b), "approve_b": opened(approved_b),
                 "join_c": opened(joined_c), "remove_b": opened(rotated), "upgrade": opened(upgraded)},
        "approve_c": approve_c,
        "negative": negative, "positive": positive, "open_negative": open_negative, "argon2": argon,
    }


def generate(out: Path) -> list[Path]:
    out.mkdir(parents=True, exist_ok=True)
    path = out / "gating.json"
    path.write_bytes((json.dumps(gating_doc(), indent=2, sort_keys=True, ensure_ascii=False) + "\n").encode("utf-8"))
    return [path]


def main() -> None:
    for path in generate(Path(sys.argv[1]) if len(sys.argv) > 1 else OUT):
        print(path)


if __name__ == "__main__":
    main()
