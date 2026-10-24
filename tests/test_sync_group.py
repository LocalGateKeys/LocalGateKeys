"""Tests for sync group keys and sealed views (format pinned for iOS)."""

from __future__ import annotations

import base64
import json
import uuid

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from localvault.sync import group as g
from localvault.sync.engine import EngineError, ItemState
from localvault.updates import canonical_json

KEY = bytes(range(32))


def gk(epoch: int = 1, group_id: str = "grp-1", key: bytes = KEY) -> g.GroupKey:
    return g.GroupKey(group_id, epoch, key)


def live(i: str = "a", vv: dict | None = None, **item) -> ItemState:
    body = {"id": i, "updated_at": 5, "title": "T\u00e9st", **item}
    return ItemState(i, vv or {"d1": 1}, False, None, body)


def tomb(i: str = "t") -> ItemState:
    return ItemState(i, {"d1": 2}, True, 1700000000, None)


def counter_nonces():
    state = {"n": 0}

    def src(n: int) -> bytes:
        state["n"] += 1
        return bytes([state["n"]]) * n

    return src


def reason_of(fn, *args, **kwargs) -> str:
    with pytest.raises(g.SyncFormatError) as e:
        fn(*args, **kwargs)
    return e.value.reason


def test_round_trip():
    states = [live("b"), tomb("a"), live("c", {"d1": 1, "d2": 3})]
    raw = g.encode_view(gk(), "dev", 7, states, 1700000001)
    view = g.decode_view(gk(), raw)
    assert view.header == {
        "format": 1,
        "group_id": "grp-1",
        "device_id": "dev",
        "epoch": 1,
        "counter": 7,
        "written_at": 1700000001,
    }
    assert view.states == tuple(sorted(states, key=lambda s: s.item_id))
    assert raw.startswith(g.MAGIC)


def _aad(item_id, vv, deleted, deleted_at, epoch=1):
    return canonical_json(
        {
            "label": "lgk-sync-item-v1",
            "id": item_id,
            "vv": vv,
            "deleted": deleted,
            "deleted_at": deleted_at,
            "epoch": epoch,
        }
    )


def test_tombstone_is_authenticated_empty_plaintext():
    sealed = g.seal_item(gk(), tomb())
    assert set(sealed) == {"id", "vv", "deleted", "deleted_at", "ct"}
    raw = base64.b64decode(sealed["ct"])
    assert len(raw) == 12 + 16  # nonce + tag over empty plaintext
    aad = _aad("t", {"d1": 2}, True, 1700000000)
    assert AESGCM(gk().record_key()).decrypt(raw[:12], raw[12:], aad) == b""
    assert g.open_item(gk(), sealed) == tomb()
    s = g.seal_item(gk(), live())
    assert set(s) == {"id", "vv", "deleted", "deleted_at", "ct"} and s["ct"]


def test_forged_or_downgraded_tombstone_rejected():
    k = gk()
    t = g.seal_item(k, tomb())
    assert reason_of(g.open_item, k, {**t, "ct": ""}) == "empty-ct"
    good = g.seal_item(k, live())
    forged = {**good, "deleted": True, "deleted_at": 5}
    assert reason_of(g.open_item, k, forged) == "auth-failed"
    assert reason_of(g.open_item, k, {**t, "deleted_at": 1}) == "auth-failed"
    assert reason_of(g.open_item, k, {**t, "vv": {"d1": 9}}) == "auth-failed"
    assert reason_of(g.open_item, k, {**t, "id": "u"}) == "auth-failed"
    assert reason_of(g.open_item, k, {**t, "deleted": False, "deleted_at": None}) == "auth-failed"
    nonce = bytes(12)
    aad = _aad("t", {"d1": 2}, True, 1700000000)
    ct = nonce + AESGCM(k.record_key()).encrypt(nonce, b"x", aad)
    assert reason_of(g.open_item, k, {**t, "ct": base64.b64encode(ct).decode()}) == "bad-item"
    assert reason_of(g.open_item, gk(epoch=2), t) == "auth-failed"


def test_non_ascii_and_surrogate_identifiers_rejected():
    k = gk()
    good = g.seal_item(k, live())
    tb = g.seal_item(k, tomb())
    for bad_id in ["\ud800", "caf\u00e9", "a b", "a|b", "a/b", "x" * 129, "a\n"]:
        assert reason_of(g.open_item, k, {**good, "id": bad_id}) == "invalid-state"
        assert reason_of(g.open_item, k, {**good, "vv": {bad_id: 1}}) == "invalid-state"
        assert reason_of(g.open_item, k, {**tb, "id": bad_id}) == "invalid-state"
        with pytest.raises(EngineError):
            ItemState(bad_id, {}, True, None, None)
        with pytest.raises(EngineError):
            ItemState("ok", {bad_id: 1}, True, None, None)
        assert reason_of(g.GroupKey, bad_id, 1, KEY) == "bad-group-key"
        assert reason_of(g.encode_view, k, bad_id, 1, [], 1) == "bad-header"
    assert reason_of(g.open_item, k, {**good, "ct": "\ud800"}) == "bad-ct"
    ItemState("a.B_c:d-1", {"dev.1": 1}, True, None, None)
    ItemState(str(uuid.uuid4()), {str(uuid.uuid4()): 1}, True, None, None)
    raw = g.MAGIC + b'{"counter":1,"device_id":"d\\ud800"}\n' + bytes(40)
    assert reason_of(g.decode_view, k, raw) == "bad-header"
    assert reason_of(g.decode_view, k, g.MAGIC + b"\xff\xfe\n" + bytes(40)) == "bad-header"
    hdr = {**HDR, "group_id": "\ud800"}
    raw = g.MAGIC + json.dumps(hdr, sort_keys=True).encode("ascii") + b"\n" + bytes(40)
    assert reason_of(g.decode_view, k, raw) == "bad-header"
    sealed = g.seal_item(k, live())
    hb = canonical_json(HDR)
    text = json.dumps([{**sealed, "id": "\ud800"}]).encode("ascii")
    enc = AESGCM(k.file_key()).encrypt(bytes(12), text, hb)
    assert reason_of(g.decode_view, k, g.MAGIC + hb + b"\n" + bytes(12) + enc) == "invalid-state"


def test_open_item_rejections():
    k = gk()
    good = g.seal_item(k, live())

    def bad(**ch):
        return reason_of(g.open_item, k, {**good, **ch})

    assert reason_of(g.open_item, k, {**good, "x": 1}) == "bad-fields"
    missing = dict(good)
    del missing["ct"]
    assert reason_of(g.open_item, k, missing) == "bad-fields"
    assert reason_of(g.open_item, k, []) == "bad-fields"
    assert bad(ct="") == "empty-ct"
    assert bad(ct="!!!notb64") == "bad-ct"
    assert bad(ct=base64.b64encode(b"short").decode()) == "bad-ct"
    assert bad(id="other") == "auth-failed"
    assert bad(vv={"d1": 2}) == "auth-failed"
    assert bad(deleted_at=7) == "invalid-state"
    assert bad(id=5) == "bad-fields"
    assert bad(vv={"d|x": 1}) == "invalid-state"
    assert bad(deleted_at=True) == "bad-fields"
    assert bad(ct=5) == "bad-fields"
    assert bad(deleted=True) == "auth-failed"
    raw = bytearray(base64.b64decode(good["ct"]))
    raw[-1] ^= 1
    assert bad(ct=base64.b64encode(bytes(raw)).decode()) == "auth-failed"
    assert reason_of(g.open_item, gk(epoch=2), good) == "auth-failed"
    assert reason_of(g.open_item, gk(key=bytes(32)), good) == "auth-failed"


def test_open_item_non_dict_plaintext():
    k = gk()
    good = g.seal_item(k, live())
    aad = _aad(good["id"], good["vv"], False, None)
    nonce = bytes(12)
    ct = nonce + AESGCM(k.record_key()).encrypt(nonce, b"[1]", aad)
    assert reason_of(g.open_item, k, {**good, "ct": base64.b64encode(ct).decode()}) == "bad-item"


def test_tamper_header_fails():
    raw = g.encode_view(gk(), "dev", 1, [live()], 10)
    old = b'"counter":1'
    i = raw.index(old)
    tampered = raw[:i] + b'"counter":2' + raw[i + len(old):]
    assert reason_of(g.decode_view, gk(), tampered) == "auth-failed"
    flipped = bytearray(raw)
    flipped[-1] ^= 1
    assert reason_of(g.decode_view, gk(), bytes(flipped)) == "auth-failed"


def test_wrong_epoch_fails():
    raw = g.encode_view(gk(epoch=1), "dev", 1, [live()], 10)
    assert reason_of(g.decode_view, gk(epoch=2), raw) == "epoch-mismatch"
    assert reason_of(g.decode_view, gk(group_id="other"), raw) == "group-mismatch"
    assert reason_of(g.decode_view, gk(key=bytes(32)), raw) == "auth-failed"


def test_bounds():
    raw = g.encode_view(gk(), "dev", 1, [live("a"), live("b")], 10)
    assert reason_of(g.decode_view, gk(), raw, max_bytes=len(raw) - 1) == "too-large"
    g.decode_view(gk(), raw, max_bytes=len(raw))
    assert reason_of(g.decode_view, gk(), raw, max_records=1) == "too-many-records"
    g.decode_view(gk(), raw, max_records=2)
    assert (
        reason_of(g.encode_view, gk(), "dev", 1, [live("a"), live("b")], 10, max_records=1)
        == "too-many-records"
    )


def _file(header: dict, payload: object, header_bytes: bytes | None = None) -> bytes:
    hb = header_bytes if header_bytes is not None else canonical_json(header)
    nonce = bytes(12)
    body = AESGCM(gk().file_key()).encrypt(nonce, canonical_json(payload), hb)
    return g.MAGIC + hb + b"\n" + nonce + body


HDR = {"format": 1, "group_id": "grp-1", "device_id": "dev", "epoch": 1, "counter": 1, "written_at": 1}


def test_view_rejections():
    k = gk()
    good_raw = g.encode_view(k, "dev", 1, [live()], 1)
    sealed = g.seal_item(k, live())

    def rs(raw: bytes) -> str:
        return reason_of(g.decode_view, k, raw)

    assert rs(b"BADMAGIC\n" + good_raw[9:]) == "bad-magic"
    assert rs(b"") == "bad-magic"
    assert rs(g.MAGIC + b"no newline") == "bad-header"
    assert rs(g.MAGIC + b"{not json\n" + bytes(40)) == "bad-header"
    assert rs(g.MAGIC + b"[1]\n" + bytes(40)) == "bad-header"
    assert rs(_file({**HDR, "extra": 1}, [])) == "bad-header"
    assert rs(_file({n: v for n, v in HDR.items() if n != "counter"}, [])) == "bad-header"
    assert rs(_file({**HDR, "format": 2}, [])) == "bad-header"
    assert rs(_file({**HDR, "counter": True}, [])) == "bad-header"
    assert rs(_file({**HDR, "counter": -1}, [])) == "bad-header"
    assert rs(_file({**HDR, "counter": 2**53}, [])) == "bad-header"
    assert rs(_file({**HDR, "written_at": 1.5}, [])) == "bad-header"
    assert rs(_file({**HDR, "device_id": ""}, [])) == "bad-header"
    assert rs(_file({**HDR, "device_id": "x" * 129}, [])) == "bad-header"
    assert rs(_file({**HDR, "group_id": "x" * 129}, [])) == "bad-header"
    pretty = json.dumps(HDR, sort_keys=True).encode()
    assert rs(_file(HDR, [], header_bytes=pretty)) == "header-noncanonical"
    assert rs(g.MAGIC + canonical_json(HDR) + b"\n" + bytes(10)) == "bad-payload"
    assert rs(_file(HDR, {"a": 1})) == "bad-payload"
    assert rs(_file(HDR, [1])) == "bad-payload"
    assert rs(_file(HDR, [sealed, sealed])) == "duplicate-id"
    assert rs(_file(HDR, [{**sealed, "ct": ""}])) == "empty-ct"
    assert rs(_file({**HDR, "device_id": "a|b"}, [])) == "bad-header"
    hb = canonical_json(HDR)
    n = bytes(12)
    junk = g.MAGIC + hb + b"\n" + n + AESGCM(k.file_key()).encrypt(n, b"\xff\xfe", hb)
    assert rs(junk) == "bad-payload"


def test_nonce_injection_for_vectors():
    a = g.encode_view(gk(), "dev", 1, [live()], 10, nonce_source=counter_nonces())
    b = g.encode_view(gk(), "dev", 1, [live()], 10, nonce_source=counter_nonces())
    assert a == b
    c = g.encode_view(gk(), "dev", 1, [live()], 10)
    d = g.encode_view(gk(), "dev", 1, [live()], 10)
    assert c != d
    with pytest.raises(g.SyncFormatError):
        g.encode_view(gk(), "dev", 1, [live()], 10, nonce_source=lambda n: b"\x00" * (n - 1))
    with pytest.raises(g.SyncFormatError):
        g.seal_item(gk(), live(), nonce_source=lambda n: "x" * n)


def test_encode_rejects_duplicates_and_bad_header_values():
    assert reason_of(g.encode_view, gk(), "dev", 1, [live("a"), live("a")], 1) == "duplicate-id"
    assert reason_of(g.encode_view, gk(), "", 1, [], 1) == "bad-header"
    assert reason_of(g.encode_view, gk(), "dev", -1, [], 1) == "bad-header"


def test_group_key_validation():
    cases = [
        ("", 1, KEY), ("a" * 129, 1, KEY), ("a\x00", 1, KEY), (5, 1, KEY),
        ("a", 0, KEY), ("a", True, KEY), ("a", 1.0, KEY),
        ("a", 1, b"short"), ("a", 1, "x" * 32), ("a", 1, bytearray(32)),
    ]
    for args in cases:
        assert reason_of(g.GroupKey, *args) == "bad-group-key"
    assert "key=" not in repr(gk())
    assert "\\x01" not in repr(gk())


def test_derived_keys_distinct_and_bound_to_epoch_and_group():
    a = gk()
    assert a.record_key() != a.file_key()
    assert len(a.record_key()) == 32
    assert gk(epoch=2).record_key() != a.record_key()
    assert gk(group_id="z").file_key() != a.file_key()


def test_hkdf_derivation():
    rec = HKDF(hashes.SHA256(), 32, b"grp-1", b"localgatekeys|sync|folder-record|v1|3").derive(KEY)
    assert gk(epoch=3).record_key() == rec
    fil = HKDF(hashes.SHA256(), 32, b"grp-1", b"localgatekeys|sync|folder-file|v1|3").derive(KEY)
    assert gk(epoch=3).file_key() == fil


def test_expected_device_id():
    raw = g.encode_view(gk(), "dev", 1, [live()], 1)
    assert g.decode_view(gk(), raw, expected_device_id="dev").header["device_id"] == "dev"
    assert reason_of(g.decode_view, gk(), raw, expected_device_id="other") == "device-mismatch"
    g.decode_view(gk(), raw)


def test_constant_nonce_source_rejected():
    const = lambda n: b"\x07" * n  # noqa: E731
    assert reason_of(g.encode_view, gk(), "dev", 1, [live("a"), live("b")], 1, nonce_source=const) == "nonce-reuse"
    assert reason_of(g.encode_view, gk(), "dev", 1, [live()], 1, nonce_source=const) == "nonce-reuse"
    assert reason_of(g.encode_view, gk(), "dev", 1, [tomb()], 1, nonce_source=const) == "nonce-reuse"


def test_record_id_must_match_sealed_id():
    k = gk()
    wrapper = {"ns": "n", "updated_at": 1, "record": {"id": "zzz", "title": "x"}}
    st = ItemState("a", {"d1": 1}, False, None, wrapper)
    assert reason_of(g.open_item, k, g.seal_item(k, st)) == "id-mismatch"
    ok = ItemState("a", {"d1": 1}, False, None, {**wrapper, "record": {"id": "a"}})
    assert g.open_item(k, g.seal_item(k, ok)) == ok
    no_id = ItemState("a", {"d1": 1}, False, None, {**wrapper, "record": {"title": "x"}})
    assert g.open_item(k, g.seal_item(k, no_id)) == no_id
    assert g.open_item(k, g.seal_item(k, live())).item["id"] == "a"


def test_duplicate_json_keys_rejected():
    k = gk()
    good = g.seal_item(k, live())
    nonce = bytes(12)
    aad = _aad(good["id"], good["vv"], False, None)
    ct = nonce + AESGCM(k.record_key()).encrypt(nonce, b'{"a":1,"a":2}', aad)
    assert reason_of(g.open_item, k, {**good, "ct": base64.b64encode(ct).decode()}) == "bad-item"
    hb = canonical_json(HDR)
    dup_header = hb[:-1] + b',"epoch":1}'
    assert reason_of(g.decode_view, k, g.MAGIC + dup_header + b"\n" + bytes(40)) == "bad-header"
    dup_text = json.dumps([good]).replace('"id"', '"id": "a", "id"', 1).encode()
    enc = AESGCM(k.file_key()).encrypt(nonce, dup_text, hb)
    assert reason_of(g.decode_view, k, g.MAGIC + hb + b"\n" + nonce + enc) == "bad-payload"


KAT_HEX = (
    "4c474b53594e43310a7b22636f756e746572223a332c226465766963655f"
    "6964223a226465762d61222c2265706f6368223a322c22666f726d617422"
    "3a312c2267726f75705f6964223a2267726f75702d31222c227772697474"
    "656e5f6174223a313730303030303030307d0a0202020202020202020202"
    "0296544e4522608fa19b6ebbad5cf97706630724c9580bd272dee60b52d7"
    "6ea707277c82e10108842fdbffceacf379f5a65de11ffcd38b173fc64307"
    "678ef972dcd01bd7d932dbc0391b96bc0ddcd42044de9f076e86395b781e"
    "d33e324b8c311f7650c663db27ed6afe9b081f8b364cd35d94a4aac47b5f"
    "425f233516c345524f7d9d1e7330f9ed54eaa327f2dc976802c43793f8bc"
    "1b96d0b65586c56bdc1e6c6c68b7221961230dc239f75ab3dd378b05ed22"
    "7366cc7c7fb8ca9529"
)


def test_known_answer_view_bytes():
    state = ItemState("item-1", {"dev-a": 2}, False, None, {"id": "item-1", "title": "x", "updated_at": 9})
    raw = g.encode_view(
        g.GroupKey("group-1", 2, KEY), "dev-a", 3, [state], 1700000000, nonce_source=counter_nonces()
    )
    assert raw.hex() == KAT_HEX


def test_engine_conflict_copy_round_trips():
    from localvault.sync.engine import merge

    def wrap(text: str, at: int) -> dict:
        return {"ns": "entry", "updated_at": at, "record": {"id": "a", "title": text}}

    local = {"a": ItemState("a", {"d1": 1}, False, None, wrap("one", 1))}
    remote = [ItemState("a", {"d2": 1}, False, None, wrap("two", 2))]
    outcome = merge(local, remote)
    assert len(outcome.copies) == 1
    copy = outcome.copies[0]
    assert copy.item["id"] == copy.item_id != copy.item["record"]["id"]
    k = gk()
    assert g.open_item(k, g.seal_item(k, copy)) == copy
    raw = g.encode_view(k, "dev", 1, [copy, *outcome.upserts], 1)
    assert set(s.item_id for s in g.decode_view(k, raw).states) == {copy.item_id, "a"}
    # a mismatching top-level id is still rejected
    bad = ItemState("b", {"d1": 1}, False, None, {**copy.item, "id": "zzz"})
    assert reason_of(g.open_item, k, g.seal_item(k, bad)) == "id-mismatch"


KAT_TOMB_CT = "CQkJCQkJCQkJCQkJqk1+AX96zUK9C99Fkjw1Gw=="
KAT_TOMB_HEX = (
    "4c474b53594e43310a7b22636f756e746572223a342c226465766963655f"
    "6964223a226465762d61222c2265706f6368223a322c22666f726d617422"
    "3a312c2267726f75705f6964223a2267726f75702d31222c227772697474"
    "656e5f6174223a313730303030303230307d0a0202020202020202020202"
    "0296544e4522608fa19b6ebbad5cf97706630724c9580bd272b2e4325bf7"
    "43ba1203598b967c17a834c7f7d3d3b960a2f74cae6bde83ae151bf94269"
    "6599ea30dec871fdce188edb174eac8d37c6b97611b6ff6704dd50003c6a"
    "a803010adf412c6d63f37edc44fc75aac1084195784dc24edde7b298291f"
    "135e6a615fc40b0d0a65841ce8f1406ca23c4e3ce4b324767f49f3ae"
)


def test_known_answer_tombstone_view_bytes():
    k = g.GroupKey("group-1", 2, KEY)
    t = ItemState("item-2", {"dev-a": 3, "dev-b": 1}, True, 1700000123, None)
    sealed = g.seal_item(k, t, nonce_source=lambda n: b"\x09" * n)
    assert sealed["ct"] == KAT_TOMB_CT
    raw = g.encode_view(k, "dev-a", 4, [t], 1700000200, nonce_source=counter_nonces())
    assert raw.hex() == KAT_TOMB_HEX
    assert g.decode_view(k, raw).states == (t,)
