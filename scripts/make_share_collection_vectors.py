"""Write the shared-collection vectors in ``tests/vectors/share/collections`` (sub-plan 07 Task 5).

Every expected value comes from the real desktop code (``localvault.sync.keyring``,
``share_group``, ``vault_bridge``, ``removal``, ``group``, ``lan_sync``); only randomness is fixed.
LGKCore (Swift) and lgk-core (Kotlin) must read, verify and write the same bytes.

* ``keyring.json``: owner A shares a collection (``create``), B joins (``join_b``), A approves B
  (``approve_b``), C joins after that (``join_c``), A removes B (``remove_b``: rotation + notice).
  Each writer case lists ``random_reads_hex`` in the order the writers draw (as
  ``tests/vectors/sync/mac/keyring_write.json``); ``argon2`` maps ``password|salt`` to the production
  Argon2id key so the phones can inject the KDF.  ``negative`` lists keyrings a device must refuse
  when it adopts them (``reason`` is what the desktop says).
* ``view.json``: a share view (what a share group publishes from a mixed vault) and incoming share
  records with the verdict ``apply`` gives them.
* ``states.json``: personal collection states (``col:``/``cm:``/``csl:``) with their wrappers and
  digests, plus malformed ones (refused as ``bad-remote``).
* ``capability.json``: a signed ``.lgkcol`` file (view counter 1) and a ``.lgkcap`` (counter 0)
  of the same device, and the LAN ``features`` messages.
* ``folder.json`` and ``folder/a/`` (Task 5n): device A's personal sync folder (keyring, signed view with
  collections, memberships and a share link, capability files) and what a joining device B must end with.
  ``folder/from_android/`` and ``folder/from_ios/`` are B's files written by the phone cores (not by this script).

Usage (from the repo root, PYTHONPATH=src)::

    python scripts/make_share_collection_vectors.py [OUT_DIR]
"""

# ruff: noqa: S101, S105

from __future__ import annotations

import base64
import copy
import hashlib
import json
import sys
import uuid
from pathlib import Path

from localvault.sync import group as grp
from localvault.sync import keyring as kr
from localvault.sync import lan_sync, removal, share_group, vault_bridge
from localvault.sync.engine import ItemState
from localvault.sync.pairing import DeviceIdentity

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "tests/vectors/share/collections"

COLLECTION_ID = "3f2a6c1e-8b4d-4e7a-9c05-d1e2f3a4b5c6"
OTHER_COLLECTION_ID = "9a8b7c6d-5e4f-4a3b-8c2d-1e0f9a8b7c6d"
NAME = "Family Ünïcode"
MODE = "read"
PASSWORD = "maple river onion seven lamp quote"
NEW_PASSWORD = "violet tram sundial 1987 pebble"
NOW = 1_800_000_000


def stream(label: str, count: int) -> bytes:
    out = b""
    i = 0
    while len(out) < count:
        out += hashlib.sha256(f"share-collections|{label}|{i}".encode()).digest()
        i += 1
    return out[:count]


class Source:
    """A fixed byte stream that records every read (hex) in order."""

    def __init__(self, label: str, count: int) -> None:
        self.data, self.pos, self.reads = stream(label, count), 0, []

    def take(self, n: int) -> bytes:
        chunk = self.data[self.pos:self.pos + n]
        assert len(chunk) == n, "stream exhausted"
        self.pos += n
        self.reads.append(chunk.hex())
        return chunk

    def done(self) -> None:
        assert self.pos == len(self.data), f"{len(self.data) - self.pos} bytes left"


def identity(who: str) -> DeviceIdentity:
    devices = json.loads((ROOT / "tests/vectors/sync/identities.json").read_text(encoding="utf-8"))["devices"]
    return DeviceIdentity.from_protected_dict(devices[who]["private"])


def canon(value: object) -> bytes:
    return grp.canonical_json(value)


def b64(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def adopt(stored: dict, candidate: dict, trusted: grp.GroupKey, me: DeviceIdentity, pinned: dict) -> str:
    """``share_group.adopt_keyring`` without a vault: the new key's hex, or the refusal reason.

    Same steps in the same order: accept (structure incl. owner signature, MAC, chain), the pinned
    owner/owner_key/collection/mode, same-epoch growth, this device still listed.
    """
    try:
        gk = kr.accept_keyring(candidate, trusted, me)
        meta = kr.keyring_metadata(candidate)
        if meta is None or any(meta[k] != pinned[k] for k in share_group._PINNED):
            return "tampered"
        if gk.epoch == trusted.epoch:
            share_group._check_same_epoch_growth(stored, candidate)
        if me.device_id not in {m["device_id"] for m in candidate["members"]}:
            return "removed"
    except kr.KeyringError as exc:
        return exc.reason
    return gk.key.hex()


def remac(ring: dict, gk: grp.GroupKey) -> dict:
    """What any member holding G can do: rewrite the keyring and recompute its MAC."""
    return kr._finish(ring, gk, None, ring["prev_mac"])


def keyring_doc() -> dict:
    a, b, c = identity("A"), identity("B"), identity("C")
    argon: dict[str, str] = {}

    def remember(password: str, ring: dict) -> None:
        salt = ring["kdf"]["salt"]
        argon[f"{password}|{salt}"] = kr._argon2(password, base64.b64decode(salt), kr._PRODUCTION_KDF).hex()

    spec = {"kind": "share", "collection_id": COLLECTION_ID, "name": NAME, "shared_mode": MODE}
    src = Source("create", 16 + 32 + 16 + 12 + 32 + 12 + 12 + 12)
    group_id = str(uuid.UUID(bytes=src.take(16), version=4))
    created, gk1 = kr.create_group(PASSWORD, a, "Owner phone", _rand=src.take, _now=NOW, _group_id=group_id,
                                   metadata=spec, share_format=2)
    src.done()
    remember(PASSWORD, created)
    assert kr.share_name(created, gk1) == NAME
    create = {"random_reads_hex": src.reads, "keyring": created, "group_key_hex": gk1.key.hex(),
              "approved": sorted(kr.approved_members(created))}
    pinned = {k: created["metadata"][k] for k in share_group._PINNED}

    src = Source("join-b", 32 + 12 + 12)
    joined_b, _ = kr.join_with_password(created, PASSWORD, b, "Bea", _rand=src.take, _now=NOW + 60)
    src.done()
    join_b = {"random_reads_hex": src.reads, "keyring": joined_b, "approved": sorted(kr.approved_members(joined_b))}

    approved_b = kr.owner_approve_members(joined_b, gk1, a, approve=[b.device_id])
    approve_b = {"approve": [b.device_id], "keyring": approved_b,
                 "approved": sorted(kr.approved_members(approved_b))}

    src = Source("join-c", 32 + 12 + 12)
    joined_c, _ = kr.join_with_password(approved_b, PASSWORD, c, "Cy", _rand=src.take, _now=NOW + 120)
    src.done()
    join_c = {"random_reads_hex": src.reads, "keyring": joined_c, "approved": sorted(kr.approved_members(joined_c))}

    remember(NEW_PASSWORD, joined_c)  # the reuse check derives the new password with the current salt
    # As share_group.remove_member: B and the unapproved C go; A stays the only member.
    src = Source("remove-b", 32 + 16 + 12 + (32 + 12 + 12) + 12)
    rotated, gk2 = kr.rotate(joined_c, gk1, a, NEW_PASSWORD, remove=[b.device_id, c.device_id], _rand=src.take)
    src.done()
    remember(NEW_PASSWORD, rotated)
    notice = removal.make_notice(a.signing_key, group_id=group_id, device_id=b.device_id, epoch=gk2.epoch,
                                 signer=a.device_id, now=NOW + 300)
    assert kr.share_name(rotated, gk2) == NAME
    remove_b = {"remove": [b.device_id, c.device_id], "random_reads_hex": src.reads, "keyring": rotated,
                "group_key_hex": gk2.key.hex(), "approved": sorted(kr.approved_members(rotated)),
                "notice": notice.decode("ascii"), "notice_issued_at": NOW + 300,
                "watch_signers": {a.device_id: b64(a.signing_public_key)}}

    # The member watch accepts the owner's notice; a notice signed by B for C is not the owner's.
    watch_b = removal.Watch(group_id, b.device_id, 1, "", ".", {a.device_id: b64(a.signing_public_key)})
    assert removal.verify_notice(notice, watch_b, canon(rotated)).signer == a.device_id
    forged_notice = removal.make_notice(b.signing_key, group_id=group_id, device_id=c.device_id, epoch=2,
                                        signer=b.device_id, now=NOW + 300)
    watch_c = removal.Watch(group_id, c.device_id, 1, "", ".", {a.device_id: b64(a.signing_public_key)})
    try:
        removal.verify_notice(forged_notice, watch_c, canon(rotated))
    except removal.RemovalError as exc:
        forged_reason = exc.reason
    else:
        raise AssertionError("a member's notice must be refused")

    negative = []

    def case(name: str, who: str, stored: dict, candidate: dict, trusted: grp.GroupKey, why: str) -> None:
        me = {"A": a, "B": b, "C": c}[who]
        got = adopt(stored, candidate, trusted, me, pinned)
        assert got == why, (name, got, why)
        negative.append({"name": name, "device": who, "stored": stored, "candidate": candidate,
                         "trusted_epoch": trusted.epoch, "trusted_key_hex": trusted.key.hex(), "reason": why})

    # A member (B) rotates the share keyring itself: it cannot sign as the owner.
    src_forge = Source("forged-rotation", 32 + 16 + 12 + 3 * (32 + 12 + 12) + 12)
    gk_forge = grp.GroupKey(group_id, 2, src_forge.take(32))
    names = kr.member_names(joined_c, gk1)
    body = kr._fresh_body(gk_forge, NEW_PASSWORD, [
        {"device_id": m["device_id"], "name": names[m["device_id"]], "exchange_public": m["exchange_public"],
         "signing_public": m["signing_public"], "signing_proof": m["signing_proof"], "added_at": m["added_at"]}
        for m in joined_c["members"]], kr._PRODUCTION_KDF, src_forge.take)
    body["metadata"] = {**joined_c["metadata"],
                        "name_ct": kr._seal_share_name(gk_forge, COLLECTION_ID, NAME, src_forge.take)}
    sig = b.signing_key.sign(kr._owner_message(body, sorted(m["device_id"] for m in body["members"])))
    body["owner_sig"] = {"members": sorted(m["device_id"] for m in body["members"]), "sig": b64(sig)}
    forged_rotation = kr._finish(body, gk_forge, gk1)
    case("member_rotation_signed_by_member", "C", joined_c, forged_rotation, gk1, "bad-owner-sig")

    # B makes itself the owner (metadata rewritten, signed with its own key): pinned facts change.
    claim = copy.deepcopy(joined_c)
    claim["metadata"]["owner"] = b.device_id
    claim["metadata"]["owner_key"] = b64(b.signing_public_key)
    claim = {k: v for k, v in claim.items() if k not in ("mac", "owner_sig")}
    approved = sorted(m["device_id"] for m in claim["members"])
    claim["owner_sig"] = {"members": approved, "sig": b64(b.signing_key.sign(kr._owner_message(claim, approved)))}
    claim = remac(claim, gk1)
    case("member_claims_ownership", "C", joined_c, claim, gk1, "tampered")

    # Same epoch: B drops C (still pending, so A's signature over [A, B] stays valid) and re-MACs.
    dropped = copy.deepcopy(joined_c)
    dropped["members"] = [m for m in dropped["members"] if m["device_id"] != c.device_id]
    dropped["device_wraps"] = {d: w for d, w in dropped["device_wraps"].items() if d != c.device_id}
    dropped = remac(dropped, gk1)
    case("same_epoch_drop", "A", joined_c, dropped, gk1, "tampered")

    # The owner key in the metadata is not the owner's listed signing key.
    wrong = copy.deepcopy(approved_b)
    wrong["metadata"]["owner_key"] = b64(b.signing_public_key)
    wrong = remac(wrong, gk1)
    case("wrong_owner_key", "B", approved_b, wrong, gk1, "bad-owner")

    # B replays the owner's creation signature (approving only A) over the approved keyring.
    replay = copy.deepcopy(approved_b)
    replay["owner_sig"] = copy.deepcopy(created["owner_sig"])
    replay = remac(replay, gk1)
    case("replayed_older_owner_signature", "A", approved_b, replay, gk1, "tampered")

    # A same-epoch keyring whose owner signature does not verify at all.
    bad_sig = copy.deepcopy(approved_b)
    bad_sig["owner_sig"]["sig"] = b64(bytes(64))
    bad_sig = remac(bad_sig, gk1)
    case("owner_signature_garbage", "B", approved_b, bad_sig, gk1, "bad-owner-sig")

    # Positive adoptions (same rules, accepted).
    positive = []
    for name, who, stored, candidate, trusted, new in (
        ("member_adopts_approval", "B", joined_b, approved_b, gk1, gk1),
        ("owner_adopts_join", "A", approved_b, joined_c, gk1, gk1),
        ("member_adopts_rotation", "A", joined_c, rotated, gk1, gk2),
    ):
        me = {"A": a, "B": b, "C": c}[who]
        got = adopt(stored, candidate, trusted, me, pinned)
        assert got == new.key.hex(), (name, got)
        positive.append({"name": name, "device": who, "stored": stored, "candidate": candidate,
                         "trusted_epoch": trusted.epoch, "trusted_key_hex": trusted.key.hex(),
                         "new_epoch": new.epoch, "new_key_hex": new.key.hex()})
    # B was removed: the rotation no longer wraps a key for it (accept refuses before "removed").
    assert adopt(joined_c, rotated, gk1, b, pinned) == "not-member"

    return {
        "description": "Share keyrings written by localvault.sync.keyring with fixed randomness "
                       "(scripts/make_share_collection_vectors.py). A owns the share, B and C join.",
        "group_id": group_id, "collection_id": COLLECTION_ID, "name": NAME, "shared_mode": MODE,
        "password": PASSWORD, "new_password": NEW_PASSWORD, "now": NOW,
        "owner": "A", "names": {"A": "Owner phone", "B": "Bea", "C": "Cy"},
        "pinned": pinned,
        "create": create, "join_b": join_b, "approve_b": approve_b, "join_c": join_c, "remove_b": remove_b,
        "forged_notice": {"notice": forged_notice.decode("ascii"), "device": "C", "reason": forged_reason},
        "negative": negative, "positive": positive, "argon2": argon,
    }


def _item(item_id: str, kind: str, title: str, payload: dict, **extra: object) -> dict:
    return {"id": item_id, "kind": kind, "title": title, "created_at": NOW - 500, "updated_at": NOW - 100,
            "revision": 3, "favorite": False, "tags": [], "collection_ids": [], "payload": payload, **extra}


def view_doc() -> dict:
    scope = vault_bridge._Scope(COLLECTION_ID, False)
    note = _item("11111111-1111-4111-8111-111111111111", "note", "Wi-Fi at grandma's",
                 {"body": "router in the hall", "fields": [], "template_id": None},
                 tags=["home"], favorite=True, collection_ids=[OTHER_COLLECTION_ID, COLLECTION_ID])
    card = _item("22222222-2222-4222-8222-222222222222", "license", "Family office licence",
                 {"license_value": "ABCD-EFGH", "product": "Office", "vendor": "Vendor", "purchase_date": "",
                  "expiration_date": "", "notes": "", "template_id": None,
                  "document_ids": ["55555555-5555-4555-8555-555555555555"]}, collection_ids=[COLLECTION_ID])
    personal = _item("33333333-3333-4333-8333-333333333333", "note", "Private", {"body": "mine", "fields": [], "template_id": None})
    other = _item("44444444-4444-4444-8444-444444444444", "note", "Elsewhere", {"body": "x", "fields": [], "template_id": None},
                  collection_ids=[OTHER_COLLECTION_ID])
    document = _item("55555555-5555-4555-8555-555555555555", "document", "Passport scan",
                     {"attachment_id": "66666666-6666-4666-8666-666666666666", "description": "",
                      "template_id": None},
                     collection_ids=[COLLECTION_ID])
    vault_items = [note, card, personal, other, document]
    shared = []
    for record in vault_items:
        ids = record.get("collection_ids") or []
        if COLLECTION_ID not in ids or record["kind"] in vault_bridge.UNSYNCED_ITEM_KINDS:
            continue
        wrapper = vault_bridge._wrapper("item", record, scope)
        shared.append({"id": record["id"], "wrapper": wrapper, "digest": vault_bridge.wrapper_digest(wrapper)})

    def incoming(name: str, wrapper: dict) -> dict:
        state = ItemState(wrapper["record"].get("id", "x"), {"b2222222-0000-4000-8000-00000000000b": 1}, False,
                          None, wrapper)
        try:
            vault_bridge._unwrap_remote(state, scope)
            verdict = "ok"
        except vault_bridge.BridgeError as exc:
            verdict = exc.reason or "bad-remote"
        return {"name": name, "id": state.item_id, "wrapper": wrapper, "verdict": verdict}

    good = copy.deepcopy(shared[0]["wrapper"])
    claims_two = copy.deepcopy(good)
    claims_two["record"]["collection_ids"] = [COLLECTION_ID, OTHER_COLLECTION_ID]
    claims_other = copy.deepcopy(good)
    claims_other["record"]["collection_ids"] = [OTHER_COLLECTION_ID]
    untagged = copy.deepcopy(good)
    del untagged["record"]["collection_ids"]
    login = {"ns": "entry", "schema": 1, "updated_at": NOW - 100, "record": {
        "id": "77777777-7777-4777-8777-777777777777", "kind": "web", "label": "Bank", "username": "u",
        "password": "p", "scope": {"origins": ["https://bank.example"], "match_mode": "exact_origin"},
        "created_at": NOW - 500, "updated_at": NOW - 100, "favorite": False, "tags": [], "notes": "",
        "totp": None, "recovery_codes": [], "custom_fields": [], "policy": {}, "password_history": []}}
    doc_wrapper = {"ns": "item", "schema": 1, "updated_at": NOW - 100,
                   "record": {**{k: v for k, v in document.items() if k not in ("revision", "tags", "favorite")},
                              "collection_ids": [COLLECTION_ID]}}
    with_tags = copy.deepcopy(good)
    with_tags["record"]["tags"] = ["peer tag"]
    with_tags["record"]["favorite"] = True
    cases = [
        incoming("shared_note", good),
        incoming("shared_licence", copy.deepcopy(shared[1]["wrapper"])),
        incoming("peer_tags_and_favourite_are_dropped_not_refused", with_tags),
        incoming("claims_two_collections", claims_two),
        incoming("claims_another_collection", claims_other),
        incoming("claims_no_collection", untagged),
        incoming("login", login),
        incoming("document", doc_wrapper),
    ]
    return {
        "description": "A share view of collection_id from a mixed vault (vault_bridge._wrapper with a share "
                       "scope) and incoming share records (vault_bridge._unwrap_remote with that scope).",
        "collection_id": COLLECTION_ID, "vault_items": vault_items, "shared": shared, "incoming": cases,
        "share_local_only_item_fields": list(vault_bridge.SHARE_LOCAL_ONLY_ITEM_FIELDS),
        "local_only_item_payload_fields": list(vault_bridge.LOCAL_ONLY_ITEM_PAYLOAD_FIELDS),
    }


def states_doc() -> dict:
    catalog = vault_bridge._catalog_record({"id": COLLECTION_ID, "name": "Family", "description": "Shared at home",
                                            "created_at": NOW - 900, "updated_at": NOW - 800, "revision": 4,
                                            "starter": False})
    membership = vault_bridge._membership_record("11111111-1111-4111-8111-111111111111",
                                                 [OTHER_COLLECTION_ID, COLLECTION_ID])
    link = vault_bridge._link_record(COLLECTION_ID, {"mode": "read", "role": "member"})
    valid = []
    for sid, record in ((vault_bridge.CATALOG_ID_PREFIX + COLLECTION_ID, catalog),
                        (vault_bridge.MEMBERSHIP_ID_PREFIX + membership["item_id"], membership),
                        (vault_bridge.LINK_ID_PREFIX + COLLECTION_ID, link)):
        checked = vault_bridge._check_collection_record(sid, record)
        wrapper = vault_bridge._collection_wrapper(checked)
        state = ItemState(sid, {"a1111111-0000-4000-8000-00000000000a": 1}, False, None, wrapper)
        assert vault_bridge._unwrap(state, is_copy=False) == ("collection", checked)
        valid.append({"id": sid, "wrapper": wrapper, "digest": vault_bridge.wrapper_digest(wrapper)})

    cat_id = vault_bridge.CATALOG_ID_PREFIX + COLLECTION_ID
    mem_id = vault_bridge.MEMBERSHIP_ID_PREFIX + membership["item_id"]
    link_id = vault_bridge.LINK_ID_PREFIX + COLLECTION_ID
    bad_records = {
        "catalog_extra_field": (cat_id, {**catalog, "revision": 4}),
        "catalog_shared_group_id": (cat_id, {**catalog, "shared_group_id": "g"}),
        "catalog_name_outer_space": (cat_id, {**catalog, "name": " Family"}),
        "catalog_name_empty": (cat_id, {**catalog, "name": ""}),
        "catalog_name_too_long": (cat_id, {**catalog, "name": "x" * 101}),
        "catalog_description_too_long": (cat_id, {**catalog, "description": "d" * 501}),
        "catalog_nul": (cat_id, {**catalog, "description": "a\u0000b"}),
        "catalog_updated_before_created": (cat_id, {**catalog, "updated_at": NOW - 1000}),
        "catalog_uppercase_uuid": ("col:" + COLLECTION_ID.upper(), {**catalog, "collection_id": COLLECTION_ID.upper()}),
        "catalog_id_mismatch": ("col:" + OTHER_COLLECTION_ID, catalog),
        "catalog_bool_time": (cat_id, {**catalog, "created_at": True}),
        "membership_unsorted": (mem_id, {**membership, "collection_ids": [OTHER_COLLECTION_ID, COLLECTION_ID]}),
        "membership_duplicate": (mem_id, {**membership, "collection_ids": [COLLECTION_ID, COLLECTION_ID]}),
        "membership_empty": (mem_id, {**membership, "collection_ids": []}),
        "membership_too_many": (mem_id, {**membership, "collection_ids": sorted(
            str(uuid.UUID(int=i, version=4)) for i in range(21))}),
        "membership_item_mismatch": ("cm:22222222-2222-4222-8222-222222222222", membership),
        "membership_bad_uuid": (mem_id, {**membership, "collection_ids": ["not-a-uuid"]}),
        "link_bad_mode": (link_id, {**link, "mode": "write"}),
        "link_bad_role": (link_id, {**link, "role": "admin"}),
        "link_extra_group_id": (link_id, {**link, "group_id": "g"}),
        "unknown_kind": (cat_id, {**catalog, "kind": "folder"}),
        "plain_id": ("11111111-1111-4111-8111-111111111111", catalog),
    }
    malformed = []
    for name, (sid, record) in bad_records.items():
        wrapper = {"ns": "collection", "schema": 1, "updated_at": vault_bridge._rank_updated_at(record),
                   "record": record}
        state = ItemState(sid, {"a1111111-0000-4000-8000-00000000000a": 1}, False, None, wrapper)
        reason = vault_bridge.check_remote_state(state)
        assert reason == "bad-remote", (name, reason)
        malformed.append({"name": name, "id": sid, "wrapper": wrapper, "verdict": reason})
    # A rank that does not match the record is refused too.
    wrong_rank = copy.deepcopy(valid[0]["wrapper"])
    wrong_rank["updated_at"] = 5
    state = ItemState(cat_id, {"a1111111-0000-4000-8000-00000000000a": 1}, False, None, wrong_rank)
    assert vault_bridge.check_remote_state(state) == "bad-remote"
    malformed.append({"name": "wrong_rank", "id": cat_id, "wrapper": wrong_rank, "verdict": "bad-remote"})
    return {
        "description": "Personal collection states (vault_bridge 'Personal collections'): valid wrappers with "
                       "their digests (sha256 of canonical JSON), and malformed ones check_remote_state refuses.",
        "prefixes": {"catalog": vault_bridge.CATALOG_ID_PREFIX, "membership": vault_bridge.MEMBERSHIP_ID_PREFIX,
                     "link": vault_bridge.LINK_ID_PREFIX},
        "valid": valid, "malformed": malformed,
    }


_DROP = object()


def capability_doc() -> dict:
    a = identity("A")
    gk = grp.GroupKey("7c2e9b41-3d5a-4f80-9e16-b0a4c8d2f357", 3, stream("capability-key", 32))
    nonces = Source("capability-nonces", 12 * 4)
    col = grp.encode_view(gk, a.device_id, 1, (), NOW, nonce_source=nonces.take)
    cap = grp.encode_view(gk, a.device_id, 0, (), NOW, nonce_source=nonces.take)
    col_sig, cap_sig = grp.sign_view(col, a.signing_key), grp.sign_view(cap, a.signing_key)
    for raw, sig in ((col, col_sig), (cap, cap_sig)):
        view = grp.decode_view(gk, raw, max_records=0)
        assert grp.verify_view_signature(sig, raw, view.header) == a.signing_public_key

    def message(name: str, raw: bytes) -> dict:
        try:
            msg = lan_sync.parse_message(raw)
            verdict = "ok" if msg["type"] == "features" else "other"
        except lan_sync.LanSyncError as exc:
            verdict = exc.reason
        return {"name": name, "raw": raw.decode("utf-8"), "verdict": verdict}

    ours = canon({"type": "features", "features": list(lan_sync.FEATURES)})
    messages = [
        message("ours", ours),
        message("empty_list", canon({"type": "features", "features": []})),
        message("unknown_feature_is_fine", canon({"type": "features", "features": ["collections", "later"]})),
        message("not_a_list", canon({"type": "features", "features": "collections"})),
        message("empty_name", canon({"type": "features", "features": [""]})),
        message("name_too_long", canon({"type": "features", "features": ["x" * 33]})),
        message("too_many", canon({"type": "features", "features": [f"f{i}" for i in range(17)]})),
        message("extra_field", canon({"type": "features", "features": [], "seq": 0})),
        message("number_in_list", canon({"type": "features", "features": [1]})),
    ]
    return {
        "description": "Folder capability files of device A (tests/vectors/sync/identities.json) under group_key: "
                       ".lgkcol is a signed zero-record format-1 view with counter 1, .lgkcap the same with "
                       "counter 0 (a copy of one never counts as the other). Then LAN features messages "
                       "(lan_sync.parse_message: ok / bad-message).",
        "device": "A", "group_id": gk.group_id, "epoch": gk.epoch, "group_key_hex": gk.key.hex(), "written_at": NOW,
        "lgkcol": {"file_b64": b64(col), "sig_b64": b64(col_sig), "counter": 1},
        "lgkcap": {"file_b64": b64(cap), "sig_b64": b64(cap_sig), "counter": 0},
        "suffixes": {"collections": ".lgkcol", "collections_sig": ".lgkcol.lgksig"},
        "features": list(lan_sync.FEATURES), "features_message": ours.decode("ascii"),
        "max_features": lan_sync.MAX_FEATURES, "messages": messages,
    }


FOLDER_PASSWORD = "harbour lantern quiet 2468 thistle"
FOLDER_NOW = NOW + 1000
WORK_ID = OTHER_COLLECTION_ID
N_BOTH = "11111111-1111-4111-8111-111111111111"
N_LICENCE = "22222222-2222-4222-8222-222222222222"
N_PRIVATE = "33333333-3333-4333-8333-333333333333"
N_DESK = "88888888-8888-4888-8888-888888888888"
#: Where the files of ``folder/a`` live in a cloud folder (folder_transport.SYNC_DIR_NAME).
SYNC_DIR = "LocalGateKeys Sync"


def folder_vault() -> dict:
    """Device A's vault content: two collections (Family is shared from A, see keyring.json ``create``), four
    typed items, three of them in collections.  Rows and items are exactly what the vault stores."""
    collections = [
        {"id": COLLECTION_ID, "name": NAME, "description": "Shared at home", "created_at": NOW - 900,
         "updated_at": NOW - 800, "revision": 4, "starter": False},
        {"id": WORK_ID, "name": "Work", "description": "", "created_at": NOW - 700, "updated_at": NOW - 700,
         "revision": 1, "starter": False},
    ]
    items = [
        _item(N_BOTH, "note", "Wi-Fi at grandma's", {"body": "router in the hall", "fields": [], "template_id": None},
              tags=["home"], favorite=True, collection_ids=[COLLECTION_ID, WORK_ID]),
        _item(N_LICENCE, "license", "Family office licence",
              {"license_value": "ABCD-EFGH", "product": "Office", "vendor": "Vendor", "purchase_date": "",
               "expiration_date": "", "notes": "", "template_id": None}, collection_ids=[COLLECTION_ID]),
        _item(N_PRIVATE, "note", "Private", {"body": "mine", "fields": [], "template_id": None}),
        _item(N_DESK, "note", "Desk drawer", {"body": "keys", "fields": [], "template_id": None},
              collection_ids=[WORK_ID]),
    ]
    return {"collections": collections, "items": items,
            "links": {COLLECTION_ID: {"mode": MODE, "role": "owner"}}}


def folder_states(vault: dict, device_id: str) -> list[ItemState]:
    """A's personal view of *vault* as ``vault_bridge.local_view(collections=True)`` publishes it the first time
    (every state at version 1 of A).  tests/test_share_collection_vectors.py checks it against the real call."""
    vv = {device_id: 1}
    states = [ItemState(r["id"], vv, False, None, vault_bridge._wrapper("item", r)) for r in vault["items"]]
    records = [(vault_bridge.CATALOG_ID_PREFIX + row["id"], vault_bridge._catalog_record(row))
               for row in vault["collections"]]
    records += [(vault_bridge.MEMBERSHIP_ID_PREFIX + r["id"], vault_bridge._membership_record(r["id"], r["collection_ids"]))
                for r in vault["items"] if r["collection_ids"]]
    records += [(vault_bridge.LINK_ID_PREFIX + cid, vault_bridge._link_record(cid, link))
                for cid, link in vault["links"].items()]
    for sid, record in records:
        wrapper = vault_bridge._collection_wrapper(vault_bridge._check_collection_record(sid, record))
        states.append(ItemState(sid, vv, False, None, wrapper))
    return sorted(states, key=lambda s: s.item_id)


def _state_json(s: ItemState) -> dict:
    return {"id": s.item_id, "vv": dict(s.vv), "deleted": s.deleted, "deleted_at": s.deleted_at, "item": s.item,
            "digest": vault_bridge.wrapper_digest(s.item) if s.item is not None else None}


def keyring_group_id() -> str:
    """The share group id of keyring.json ``create`` (its first 16 random bytes)."""
    return str(uuid.UUID(bytes=Source("create", 16).take(16), version=4))


def folder_doc() -> tuple[dict, dict[str, bytes]]:
    """Device A's personal sync folder (as A's first run writes it, randomness fixed) and what device B must hold
    after it joins with the password and runs over a copy of it."""
    a = identity("A")
    src = Source("folder-create", 16 + 32 + 16 + 12 + 32 + 12 + 12)
    group_id = str(uuid.UUID(bytes=src.take(16), version=4))
    ring, gk = kr.create_group(FOLDER_PASSWORD, a, "PC A", _rand=src.take, _now=NOW, _group_id=group_id)
    src.done()
    salt = ring["kdf"]["salt"]
    argon = {f"{FOLDER_PASSWORD}|{salt}": kr._argon2(FOLDER_PASSWORD, base64.b64decode(salt),
                                                     kr._PRODUCTION_KDF).hex()}
    vault = folder_vault()
    states = folder_states(vault, a.device_id)
    nonces = Source("folder-nonces", 12 * (len(states) + 1 + 2))
    view = grp.encode_view(gk, a.device_id, 1, states, FOLDER_NOW, nonce_source=nonces.take)
    col = grp.encode_view(gk, a.device_id, 1, (), FOLDER_NOW, nonce_source=nonces.take)
    cap = grp.encode_view(gk, a.device_id, 0, (), FOLDER_NOW, nonce_source=nonces.take)
    nonces.done()
    assert grp.decode_view(gk, view, expected_device_id=a.device_id).states == tuple(states)
    files = {
        "keyring.lgkkeys": canon(ring),
        f"devices/{a.device_id}.lgksync": view,
        f"signatures/{a.device_id}.lgksig": grp.sign_view(view, a.signing_key),
        f"attachments/{a.device_id}.lgkcol": col,
        f"attachments/{a.device_id}.lgkcol.lgksig": grp.sign_view(col, a.signing_key),
        f"attachments/{a.device_id}.lgkcap": cap,
        f"attachments/{a.device_id}.lgkcap.lgksig": grp.sign_view(cap, a.signing_key),
    }
    catalog = {r["id"]: {"name": r["name"], "description": r["description"]} for r in vault["collections"]}
    memberships = {r["id"]: sorted(r["collection_ids"]) for r in vault["items"] if r["collection_ids"]}
    doc = {
        "description": "Device A's personal sync folder: folder/a holds the files under 'LocalGateKeys Sync' as A's "
                       "first run writes them (localvault.sync code, fixed randomness): a personal group with A "
                       "alone, A's signed view (counter 1, format 1) with two collections, three memberships and "
                       "the share link of Family (A owns that share: keyring.json 'create'), and A's signed .lgkcol "
                       "and .lgkcap files.  Device B joins with 'password' ('argon2' gives the Argon2id output) and "
                       "runs; it must then hold 'expected_b' and publish 'a_states' unchanged, so A reads B's view "
                       "back to the same state.  Kotlin writes its B files to folder/from_android, Swift to "
                       "folder/from_ios (DetRand(b_run.rand), clocks join_at and run_at); "
                       "tests/test_share_collection_vectors.py runs the desktop's B and A over each.",
        "sync_dir": SYNC_DIR, "files": sorted(files),
        "password": FOLDER_PASSWORD, "argon2": argon, "group_id": group_id, "epoch": gk.epoch,
        "group_key_hex": gk.key.hex(), "device_a": a.device_id, "device_a_name": "PC A", "written_at": FOLDER_NOW,
        "a_vault": vault, "a_share_group_id": keyring_group_id(),
        "a_states": [_state_json(s) for s in states],
        "expected_b": {"catalog": catalog, "memberships": memberships, "links": vault["links"],
                       "items": sorted(r["id"] for r in vault["items"])},
        "b_run": {"device_name": "Phone B", "rand": "5n|folder-b", "join_at": FOLDER_NOW + 60,
                  "run_at": FOLDER_NOW + 120},
    }
    return doc, files


def write(out: Path, name: str, doc: dict) -> None:
    data = (json.dumps(doc, indent=2, sort_keys=True, ensure_ascii=False) + "\n").encode("utf-8")
    (out / name).write_bytes(data)


def generate(out: Path) -> list[Path]:
    """Write every vector; returns the written paths (the JSON files, then folder/a)."""
    out.mkdir(parents=True, exist_ok=True)
    folder, files = folder_doc()
    docs = {"keyring.json": keyring_doc(), "view.json": view_doc(), "states.json": states_doc(),
            "capability.json": capability_doc(), "folder.json": folder}
    for name, doc in docs.items():
        write(out, name, doc)
    written = [out / n for n in docs]
    for rel, data in files.items():
        path = out / "folder" / "a" / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        written.append(path)
    return written


def main() -> None:
    out = Path(sys.argv[1]) if len(sys.argv) > 1 else OUT
    for path in generate(out):
        print(path)


if __name__ == "__main__":
    main()
