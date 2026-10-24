"""The desktop reads the files the Android Kotlin core wrote (tests/vectors/sync/from_android).

Written by ``LGK_WRITE_FROM_ANDROID=1 android/gradlew -p android :lgk-core:test --tests "*FromAndroidTest*"``.
The phone joined the A/B/C group with the epoch-1 password, merged A/B/C, created one web login and one
passkey and edited one note.  Here the desktop's own public functions must accept the keyring, decode the
device file and merge it with no errors.
"""

from __future__ import annotations

import json
from pathlib import Path

from localvault.sync import keyring as kr
from localvault.sync.engine import ItemState, merge
from localvault.sync.group import GroupKey, decode_view
from localvault.sync.pairing import DeviceIdentity
from localvault.sync.vault_bridge import normal_form
from localvault.updates import canonical_json

ROOT = Path(__file__).resolve().parents[1]
VECTORS = ROOT / "tests" / "vectors" / "sync"
FROM_ANDROID = VECTORS / "from_android"
ANDROID_DEVICE_ID = "7086dd0d-47e4-4d5c-864a-d61f6196ab85"
NEW_WEB_LOGIN = "f1050000-0000-4000-8000-000000000201"
EDITED_NOTE = "22222222-aaaa-4000-8000-000000000002"
NEW_PASSKEY = "f1050000-0000-4000-8000-000000000202"


def _json(name: str) -> dict:
    return json.loads((VECTORS / name).read_text(encoding="utf-8"))


def _group_key(epoch: int) -> GroupKey:
    expected = _json("expected.json")
    entry = expected["epochs"][str(epoch)]
    return GroupKey(expected["group_id"], epoch, bytes.fromhex(entry["group_key_hex"]))


def _identity(name: str) -> DeviceIdentity:
    return DeviceIdentity.from_protected_dict(_json("identities.json")["devices"][name]["private"])


def _android_view():
    raw = (FROM_ANDROID / "devices" / f"{ANDROID_DEVICE_ID}.lgksync").read_bytes()
    return decode_view(_group_key(1), raw, expected_device_id=ANDROID_DEVICE_ID)


def test_vectors_exist_and_hold_exactly_one_device_file():
    assert (FROM_ANDROID / "keyring.lgkkeys").is_file()
    assert [p.name for p in (FROM_ANDROID / "devices").iterdir()] == [f"{ANDROID_DEVICE_ID}.lgksync"]


def test_desktop_accepts_the_android_keyring_with_the_epoch1_key():
    ring = kr.parse_keyring((FROM_ANDROID / "keyring.lgkkeys").read_bytes())
    kr.verify_keyring_structure(ring)
    gk1 = _group_key(1)
    assert ring["group_id"] == gk1.group_id
    assert ring["epoch"] == 1
    # an existing member (A) accepts it as the same epoch-1 key
    assert kr.accept_keyring(ring, gk1, _identity("A")) == gk1
    assert ANDROID_DEVICE_ID in [m["device_id"] for m in ring["members"]]


def test_desktop_decodes_the_android_device_file():
    view = _android_view()
    assert view.header["device_id"] == ANDROID_DEVICE_ID
    assert view.header["counter"] == 2
    ids = {s.item_id for s in view.states}
    assert {NEW_WEB_LOGIN, NEW_PASSKEY, EDITED_NOTE} <= ids
    for item_id in (NEW_WEB_LOGIN, NEW_PASSKEY, EDITED_NOTE):
        state = next(s for s in view.states if s.item_id == item_id)
        assert not state.deleted and state.vv[ANDROID_DEVICE_ID] == 1, item_id


def test_android_file_merges_into_abc_without_errors_and_only_touches_phone_edits():
    expected = _json("expected_merge.json")
    # the phone republishes what it did not edit in the stored (bridge) form, as the desktop does
    local = {
        row["id"]: ItemState(row["id"], row["vv"], row["deleted"], row["deleted_at"], row["item"])
        for row in expected["bridge_stored_states"]
    }
    before = dict(local)

    out = merge(local, _android_view().states)
    assert not out.conflicts
    assert not out.copies
    assert not out.deletes
    assert {s.item_id for s in out.upserts} == {NEW_WEB_LOGIN, NEW_PASSKEY, EDITED_NOTE}
    for state in out.upserts:
        local[state.item_id] = state
    # everything the phone merely republished is unchanged on the desktop
    for item_id, state in before.items():
        if item_id != EDITED_NOTE:
            assert local[item_id] == state, item_id
    assert local[EDITED_NOTE].item["record"]["title"] == "Edited on Android"
    # a second pass is idempotent
    again = merge(local, _android_view().states)
    assert not (again.upserts or again.deletes or again.copies or again.conflicts)


def test_every_android_written_live_record_is_its_own_normal_form():
    checked = 0
    for state in _android_view().states:
        if state.deleted:
            continue
        item = state.item
        assert item["ns"] in ("entry", "item"), (state.item_id, item["ns"])
        record = item["record"]
        assert canonical_json(normal_form(item["ns"], record)) == canonical_json(item["record"]), state.item_id
        checked += 1
    assert checked >= 3


def test_android_web_login_is_normalised():
    state = next(s for s in _android_view().states if s.item_id == NEW_WEB_LOGIN)
    assert state.item["ns"] == "entry"
    record = state.item["record"]
    assert record["kind"] == "web"
    assert record["label"] == "Créé sur Android"
    assert record["scope"]["origin"] == "https://example.org"  # case and default port normalised


def test_android_passkey_record_validates_and_is_usable():
    from localvault.item_schema import validate_passkey_fields
    from localvault.passkeys import usable_record

    state = next(s for s in _android_view().states if s.item_id == NEW_PASSKEY)
    assert not state.deleted and ANDROID_DEVICE_ID in state.vv
    assert state.item["ns"] == "item"
    record = state.item["record"]
    assert record["kind"] == "passkey"
    assert record["title"] == "Passkeys Example (android.user)"
    payload = record["payload"]
    assert validate_passkey_fields(payload) == payload
    assert usable_record(payload)
    assert payload["relying_party_id"] == "passkeys.example"
    assert payload["algorithm"] == "ES256"
    assert payload["discoverable"] is True
    assert payload["created"] == "2026-10-23"
    assert "=" not in payload["credential_id"] and "=" not in payload["private_key"]
