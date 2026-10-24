"""Tests for the LGKMBAK1 phone backup reader and writer."""

from __future__ import annotations

import base64
import json

import pytest
from argon2.low_level import Type
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from localvault import phone_backup
from localvault.phone_backup import PhoneBackupError
from localvault.sync.engine import ItemState
from localvault.updates import canonical_json

FAST = {"name": "argon2id", "time_cost": 1, "memory_cost_kib": 8192, "parallelism": 1}


def _states():
    return (ItemState("a1", {"phone": 2}, False, None,
                      {"ns": "entry", "schema": 1, "updated_at": 5, "record": {"id": "a1", "label": "x"}}),
            ItemState("b2", {"phone": 1}, True, 7, None))


def _blob(**kw):
    args = dict(password="pw ü", device_id="phone", platform="android", app_version="1.0.0",
                created_at=1790000000, pro_hint=False, kdf=FAST)
    args.update(kw)
    return phone_backup.write_phone_backup(_states(), **args)


def _reason(data, password="pw ü"):
    with pytest.raises(PhoneBackupError) as info:
        phone_backup.read_phone_backup(data, password)
    return info.value


def _no_argon(monkeypatch):
    def boom(*a, **k):
        raise AssertionError("Argon2 must not run")
    monkeypatch.setattr(phone_backup, "_derive", boom)


def _envelope(mutate_header=None):
    env = json.loads(_blob())
    if mutate_header:
        mutate_header(env["header"])
    return canonical_json(env)


def _forge(payload, password="pw ü", header_edit=None):
    """Encrypt a hand-built payload with the module's own key derivation."""
    header = json.loads(_blob())["header"]
    if header_edit:
        header_edit(header)
    salt = base64.b64decode(header["salt"])
    nonce = base64.b64decode(header["nonce"])
    key = phone_backup._derive(password, salt, header["kdf"])
    ct = AESGCM(key).encrypt(nonce, canonical_json(payload), canonical_json(header))
    return canonical_json({"ciphertext": base64.b64encode(ct).decode(), "header": header})


def _good_payload(states):
    return {"app_version": "1.0.0", "device_id": "phone", "pro_hint": False, "states": states, "version": 1}


def _st(i, deleted=False):
    return {"deleted": deleted, "deleted_at": 1 if deleted else None, "id": i,
            "item": None if deleted else {"a": 1}, "vv": {"phone": 1}}


def test_round_trip_keeps_states_header_and_hint():
    b = phone_backup.read_phone_backup(_blob(pro_hint=True), "pw ü")
    assert b.states == _states() and b.device_id == "phone" and b.app_version == "1.0.0"
    assert b.pro_hint is True and b.header.platform == "android" and b.header.created_at == 1790000000


def test_new_files_use_production_kdf_by_default(monkeypatch):
    seen = {}

    def fake(**kw):
        seen.update(kw)
        return b"k" * 32

    monkeypatch.setattr(phone_backup, "hash_secret_raw", fake)
    blob = _blob(kdf=None)
    assert (seen["time_cost"], seen["memory_cost"], seen["parallelism"], seen["hash_len"]) == (4, 131072, 4, 32)
    assert seen["type"] == Type.ID and seen["version"] == 19
    assert json.loads(blob)["header"]["kdf"] == phone_backup.KDF


def test_inspect_needs_no_password(monkeypatch):
    blob = _blob()
    _no_argon(monkeypatch)
    assert phone_backup.inspect_phone_backup(blob).platform == "android"


def test_wrong_password_and_flipped_byte_give_the_same_reason():
    blob = _blob()
    env = json.loads(blob)
    ct = bytearray(base64.b64decode(env["ciphertext"]))
    ct[3] ^= 1
    flipped = dict(env, ciphertext=base64.b64encode(bytes(ct)).decode())
    edited = json.loads(blob)
    edited["header"]["created_at"] += 1
    for data, pw in ((blob, "other"), (canonical_json(flipped), "pw ü"), (canonical_json(edited), "pw ü")):
        exc = _reason(data, pw)
        assert exc.reason == "wrong-password-or-damaged"
        assert str(exc) == phone_backup.WRONG_PASSWORD == "Wrong password, or the file is damaged."


def test_garbage_and_truncated_files_are_not_backups(monkeypatch):
    blob = _blob()
    extra = _envelope(lambda h: h.update(extra=1))
    wrong_fmt = _envelope(lambda h: h.update(format="LGKMBAK2"))
    bad_platform = _envelope(lambda h: h.update(platform="windows"))
    list_platform = _envelope(lambda h: h.update(platform=[1]))
    obj_platform = _envelope(lambda h: h.update(platform={"a": 1}))
    salt_text = json.loads(blob)["header"]["salt"]
    assert salt_text.endswith("==")
    # same 16 bytes would end "...Q=="; flip the last data char so the padding bits are non-zero
    alt = "B" if salt_text[-3] != "B" else "C"
    loose_salt = _envelope(lambda h: h.update(salt=salt_text[:-3] + alt + "=="))
    bad_salt = _envelope(lambda h: h.update(salt=base64.b64encode(b"x" * 15).decode()))
    dup = blob.replace(b'"version":1', b'"version":1,"version":1', 1)
    nan = blob.replace(b'"created_at":1790000000', b'"created_at":NaN')
    _no_argon(monkeypatch)
    for data in (b"", b"{", b"PK\x03\x04", blob[:40], b"[]", b"\xff{}", list_platform, obj_platform, loose_salt, extra, wrong_fmt, bad_platform, bad_salt, dup, nan):
        assert _reason(data).reason == "not-a-backup"
    with pytest.raises(PhoneBackupError):
        phone_backup.inspect_phone_backup(b"{")


def test_version_and_kdf_rules(monkeypatch):
    v2 = _envelope(lambda h: h.update(version=2))
    v_str = _envelope(lambda h: h.update(version="2"))
    v_bool = _envelope(lambda h: h.update(version=True))
    kdf_edits = ({"time_cost": 11}, {"time_cost": 0}, {"memory_cost_kib": 4096},
                 {"memory_cost_kib": 512 * 1024 + 1}, {"parallelism": 17}, {"name": "scrypt"})
    forged = [_envelope(lambda h, e=edit: h["kdf"].update(e)) for edit in kdf_edits]
    _no_argon(monkeypatch)
    assert _reason(v2).reason == "unsupported-version"
    assert _reason(v_str).reason == "not-a-backup"
    assert _reason(v_bool).reason == "not-a-backup"
    for data, edit in zip(forged, kdf_edits):
        assert _reason(data).reason == "bad-kdf", edit


def test_payload_rules():
    bad = {
        "unsorted": [_st("b"), _st("a")],
        "duplicate": [_st("a"), _st("a")],
        "deleted with item": [dict(_st("a", True), item={"a": 1})],
        "too many": [_st(f"i{n:05d}") for n in range(20001)],
    }
    for name, states in bad.items():
        assert _reason(_forge(_good_payload(states))).reason == "bad-payload", name
    assert _reason(_forge(dict(_good_payload([]), version=2))).reason == "bad-payload"
    assert _reason(_forge(dict(_good_payload([]), extra=1))).reason == "bad-payload"
    assert _reason(_forge(dict(_good_payload([]), app_version=""))).reason == "bad-payload"
    assert phone_backup.read_phone_backup(_forge(_good_payload([_st("a"), _st("b")])), "pw ü").states[0].item_id == "a"


def test_too_large_is_rejected_before_parsing():
    assert _reason(b"x" * (phone_backup.MAX_FILE_BYTES + 1)).reason == "too-large"


def test_output_is_canonical_and_deterministic_with_fixed_salt_and_nonce():
    a = _blob(_salt=b"s" * 16, _nonce=b"n" * 12)
    b = _blob(_salt=b"s" * 16, _nonce=b"n" * 12)
    assert a == b and a == canonical_json(json.loads(a)) and not a.endswith(b"\n")


def test_writer_refuses_out_of_bounds_kdf():
    with pytest.raises(PhoneBackupError) as info:
        _blob(kdf=dict(FAST, time_cost=99))
    assert info.value.reason == "bad-kdf"


def test_app_version_must_be_printable_ascii_up_to_32():
    for bad in ("1.0\u00e9", "x" * 33, "", "a\tb"):
        assert _reason(_forge(dict(_good_payload([]), app_version=bad))).reason == "bad-payload", bad
        with pytest.raises(PhoneBackupError) as info:
            _blob(app_version=bad)
        assert info.value.reason == "bad-payload"
    assert phone_backup.read_phone_backup(_blob(app_version="x" * 32), "pw ü").app_version == "x" * 32


def test_zero_vv_counter_is_rejected_and_read_write_is_byte_identical():
    zero = dict(_st("a"), vv={"phone": 0})
    assert _reason(_forge(_good_payload([zero]))).reason == "bad-payload"
    blob = _blob(_salt=b"s" * 16, _nonce=b"n" * 12)
    b = phone_backup.read_phone_backup(blob, "pw ü")
    again = phone_backup.write_phone_backup(
        b.states, password="pw ü", device_id=b.device_id, platform=b.header.platform,
        app_version=b.app_version, created_at=b.header.created_at, pro_hint=b.pro_hint,
        kdf=b.header.kdf, _salt=b.header.salt, _nonce=b.header.nonce)
    assert again == blob


def test_integers_beyond_64_bits_are_refused(monkeypatch):
    huge = 2**70
    cases = (_envelope(lambda h: h.update(version=huge)),
             _envelope(lambda h: h["kdf"].update(time_cost=huge)),
             _envelope(lambda h: h.update(created_at=huge)))
    _no_argon(monkeypatch)
    for data in cases:
        assert _reason(data).reason == "not-a-backup"
    monkeypatch.undo()
    item = _st("a")
    item["item"] = {"n": huge}
    assert _reason(_forge(_good_payload([item]))).reason == "bad-payload"
    ok = _st("b")
    ok["item"] = {"n": 2**63 - 1, "m": -(2**63 - 1)}
    assert phone_backup.read_phone_backup(_forge(_good_payload([ok])), "pw ü").states[0].item == ok["item"]


def _forge_plain(plain: bytes, password="pw ü"):
    """Encrypt hand-built plaintext bytes (which canonical_json could not produce) like _forge."""
    header = json.loads(_blob())["header"]
    salt = base64.b64decode(header["salt"])
    nonce = base64.b64decode(header["nonce"])
    key = phone_backup._derive(password, salt, header["kdf"])
    ct = AESGCM(key).encrypt(nonce, plain, canonical_json(header))
    return canonical_json({"ciphertext": base64.b64encode(ct).decode(), "header": header})


def test_non_finite_floats_are_refused(monkeypatch):
    # 1e400 overflows to inf in Python's json: refused like the phones do, before any version/kdf check.
    text = _blob().decode("utf-8")
    cases = {
        "time_cost": text.replace('"time_cost":1', '"time_cost":1e400'),
        "version": text.replace('"version":1', '"version":1e400'),
        "created_at": text.replace('"created_at":1790000000', '"created_at":-1e400'),
    }
    calls = []
    monkeypatch.setattr(phone_backup, "hash_secret_raw", lambda *a, **k: calls.append(1) or b"\0" * 32)
    for name, data in cases.items():
        assert data != text, name
        assert _reason(data.encode("utf-8")).reason == "not-a-backup", name
        with pytest.raises(PhoneBackupError) as info:
            phone_backup.inspect_phone_backup(data.encode("utf-8"))
        assert info.value.reason == "not-a-backup", name
    assert calls == []
    monkeypatch.undo()
    item = _st("a")
    item["item"] = {"n": 0}
    plain = canonical_json(_good_payload([item])).decode("utf-8")
    assert _reason(_forge_plain(plain.replace('"n":0', '"n":1e400').encode())).reason == "bad-payload"
    assert _reason(_forge_plain(plain.replace('"version":1', '"version":-1e400').encode())).reason == "bad-payload"
    # A finite float in an item still reads back.
    ok = plain.replace('"n":0', '"n":1.5e300').encode()
    assert phone_backup.read_phone_backup(_forge_plain(ok), "pw ü").states[0].item == {"n": 1.5e300}
