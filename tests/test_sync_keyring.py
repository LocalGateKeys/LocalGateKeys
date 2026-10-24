"""Tests for the password- and device-wrapped sync keyring (format pinned for iOS)."""

from __future__ import annotations

import base64
import copy
import dataclasses
import os

import pytest

from localvault.sync import keyring as kr
from localvault.sync.group import GroupKey
from localvault.sync.pairing import DeviceIdentity
from localvault.updates import canonical_json

CHEAP = (1024, 1, 1)
PW = "correct horse battery staple 7!"
PW2 = "another very long passphrase 42?"
PW3 = "yet another long phrase 99#"


def ident(name: str | None = None) -> DeviceIdentity:
    return DeviceIdentity.generate(name)


def make(pw: str = PW):
    a = ident()
    ring, gk = kr.create_group(pw, a, "A", _kdf_override=CHEAP)
    return a, ring, gk


def join(ring, pw=PW, name="X"):
    dev = ident()
    new, gk = kr.join_with_password(ring, pw, dev, name, _kdf_override=CHEAP)
    return dev, new, gk


def b64(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def flip(value: str) -> str:
    raw = bytearray(base64.b64decode(value))
    raw[0] ^= 1
    return b64(bytes(raw))


def accept(ring, trusted, dev):
    return kr.accept_keyring(ring, trusted, dev, _kdf_override=CHEAP)


def structure(ring):
    kr.verify_keyring_structure(ring, _kdf_override=CHEAP)


def rotate(ring, trusted, dev, pw=PW2, **kw):
    return kr.rotate(ring, trusted, dev, pw, _kdf_override=CHEAP, **kw)


def reason(fn, *args, **kw):
    with pytest.raises(kr.KeyringError) as e:
        fn(*args, **kw)
    return e.value.reason


def test_production_constants():
    assert (kr.KDF_MEMORY_KIB, kr.KDF_ITERATIONS, kr.KDF_PARALLELISM) == (131072, 4, 4)
    assert kr.KDF_SALT_LEN == 16
    assert kr.MAX_MEMBERS == 16


def test_production_kdf_round_trip():
    a = ident()
    ring, gk = kr.create_group(PW, a, "A")
    kdf = ring["kdf"]
    assert (kdf["name"], kdf["memory_kib"], kdf["iterations"], kdf["parallelism"]) == ("argon2id", 131072, 4, 4)
    kr.verify_keyring_structure(ring)
    assert kr.accept_keyring(ring, gk, a) == gk
    _, gk2 = kr.join_with_password(ring, PW, ident(), "B")
    assert gk2.key == gk.key
    with pytest.raises(kr.KeyringError):
        kr.verify_keyring_structure(make()[1])  # cheap-profile keyring rejected in production mode


def test_create_shape():
    a, ring, gk = make()
    assert set(ring) == {"format", "group_id", "epoch", "kdf", "password_wrap", "device_wraps",
                         "members", "prev_mac", "mac"}
    assert ring["format"] == 1 and ring["epoch"] == 1 and gk.epoch == 1 and ring["prev_mac"] is None
    assert set(ring["members"][0]) == {"device_id", "name_ct", "exchange_public", "added_at"}
    assert set(ring["device_wraps"][a.device_id]) == {"eph", "nonce", "ct"}
    assert len(base64.b64decode(ring["kdf"]["salt"])) == 16
    structure(ring)
    assert accept(ring, gk, a) == gk
    assert gk.key.hex() not in repr(gk)


def test_weak_password_rejected_before_kdf():
    a = ident()
    for pw in ("short1!A", "aaaaaaaaaaaaaaaa", "password1234", "123456789012"):
        with pytest.raises(kr.WeakSyncPassword):
            kr.create_group(pw, a, "A", _kdf_override=CHEAP)

    def boom(*_a, **_k):
        raise AssertionError("KDF ran")

    orig = kr._argon2
    kr._argon2 = boom
    try:
        with pytest.raises(kr.WeakSyncPassword):
            kr.create_group("short", a, "A", _kdf_override=CHEAP)
    finally:
        kr._argon2 = orig
    a, ring, gk = make()
    kr._argon2 = boom
    try:
        with pytest.raises(kr.WeakSyncPassword):
            kr.rotate(ring, gk, a, "weak", _kdf_override=CHEAP)
    finally:
        kr._argon2 = orig


def test_join_with_password():
    a, ring, gk = make()
    b, ring2, gk2 = join(ring)
    assert gk2 == gk
    structure(ring2)
    assert [m["device_id"] for m in ring2["members"]] == [a.device_id, b.device_id]
    assert set(ring2["device_wraps"]) == {a.device_id, b.device_id}
    assert ring2["epoch"] == 1 and ring2["password_wrap"] == ring["password_wrap"]
    # both devices accept the joined keyring under their trusted key
    assert accept(ring2, gk, a) == gk
    assert accept(ring2, gk2, b) == gk


def test_join_wrong_password():
    _, ring, _ = make()
    assert reason(kr.join_with_password, ring, PW2, ident(), "B", _kdf_override=CHEAP) == "password"
    with pytest.raises(kr.KeyringError) as e:
        kr.join_with_password(ring, PW2, ident(), "B", _kdf_override=CHEAP)
    assert PW2 not in repr(e.value) and PW not in repr(e.value)


def test_join_twice_and_limit():
    a, ring, _ = make()
    assert reason(kr.join_with_password, ring, PW, a, "A", _kdf_override=CHEAP) == "already-member"
    for i in range(15):
        _, ring, _ = join(ring, name=f"M{i}")
    assert len(ring["members"]) == 16
    structure(ring)
    assert reason(kr.join_with_password, ring, PW, ident(), "17th", _kdf_override=CHEAP) == "too-many-members"
    forged = copy.deepcopy(ring)
    forged["members"].append(copy.deepcopy(forged["members"][0]))
    forged["members"][-1]["device_id"] = "extra"
    forged["device_wraps"]["extra"] = copy.deepcopy(forged["device_wraps"][a.device_id])
    assert reason(structure, forged) == "too-many-members"


def test_join_requires_valid_mac():
    # a keyring with a good password wrap but a bad MAC (tampered/forged body) cannot be joined
    a, ring, _ = make()
    t = copy.deepcopy(ring)
    t["members"][0]["name_ct"] = flip(t["members"][0]["name_ct"])
    assert reason(kr.join_with_password, t, PW, ident(), "B", _kdf_override=CHEAP) == "tampered"


def test_join_keeps_prev_mac_after_rotation():
    a, ring, gk = make()
    b, ring, gk = join(ring)
    ring2, gk2 = rotate(ring, gk, a)
    prev = ring2["prev_mac"]
    assert prev is not None
    _, joined, _ = join(ring2, PW2)
    assert joined["prev_mac"] == prev and joined["epoch"] == 2
    assert accept(joined, gk2, a) == gk2


def test_mac_definition_matches_spec():
    import hashlib
    import hmac as _hmac

    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF

    a, ring, gk = make()
    key = HKDF(hashes.SHA256(), 32, ring["group_id"].encode(), b"localgatekeys|sync|keyring-mac|v1|1").derive(gk.key)
    body = {k: v for k, v in ring.items() if k != "mac"}
    expect = _hmac.new(key, canonical_json(body), hashlib.sha256).digest()
    assert base64.b64decode(ring["mac"]) == expect


def test_rotate_removes_member_and_changes_password():
    a, ring, gk = make()
    b, ring, _ = join(ring)
    c, ring, _ = join(ring)
    new, gk2 = rotate(ring, gk, a, PW2, remove=[b.device_id])
    structure(new)
    assert new["epoch"] == 2 and gk2.epoch == 2 and gk2.key != gk.key
    assert new["kdf"]["salt"] != ring["kdf"]["salt"]
    assert [m["device_id"] for m in new["members"]] == [a.device_id, c.device_id]
    assert set(new["device_wraps"]) == {a.device_id, c.device_id}
    # remaining devices (at epoch 1) follow the chain; the acting device already trusts gk2
    assert accept(new, gk, c) == gk2
    assert accept(new, gk, a) == gk2
    assert accept(new, gk2, a) == gk2
    assert reason(accept, new, gk, b) == "not-member"
    # new password opens the new epoch, the old one does not
    _, gk3 = kr.join_with_password(new, PW2, ident(), "D", _kdf_override=CHEAP)
    assert gk3 == gk2
    assert reason(kr.join_with_password, new, PW, ident(), "E", _kdf_override=CHEAP) == "password"


def test_rotate_password_only():
    a, ring, gk = make()
    new, gk2 = rotate(ring, gk, a, PW2)
    assert gk2.epoch == 2 and len(new["members"]) == 1


def test_rotate_rules():
    a, ring, gk = make()
    b, ring, _ = join(ring)
    assert reason(rotate, ring, gk, a, PW2, remove=[a.device_id]) == "cannot-remove-self"
    assert reason(rotate, ring, gk, a, PW2, remove=["ghost"]) == "not-member"
    assert reason(rotate, ring, gk, ident(), PW2) == "not-member"
    wrong = GroupKey(gk.group_id, gk.epoch, bytes(32))
    assert reason(rotate, ring, wrong, a, PW2) == "tampered"
    with pytest.raises(kr.WeakSyncPassword):
        rotate(ring, gk, a, "weak")
    # an epoch+1 keyring is accepted but must be adopted before rotating again
    new, gk2 = rotate(ring, gk, a, PW2)
    assert reason(rotate, new, gk, b, PW3) == "stale-trust"


def test_attack_foreign_group_rejected():
    a, ring, gk = make()
    mallory = ident()
    foreign, _ = kr.create_group(PW, mallory, "M", _kdf_override=CHEAP)
    assert reason(accept, foreign, gk, a) == "group-mismatch"


def test_attack_g_substitution_same_group_id():
    # attacker reuses the group id, wraps own G to A and self-MACs
    a, ring, gk = make()
    mallory = ident()
    evil = GroupKey(gk.group_id, 1, os.urandom(32))
    members = [kr._new_member(a, "A"), kr._new_member(mallory, "M")]
    forged = kr._finish(kr._fresh_body(evil, PW, members, CHEAP), evil, None)
    structure(forged)
    assert reason(accept, forged, gk, a) == "tampered"
    # also a forged epoch+1 chain without knowing G fails on prev_mac
    evil2 = GroupKey(gk.group_id, 2, os.urandom(32))
    forged2 = kr._finish(kr._fresh_body(evil2, PW, members, CHEAP), evil2, GroupKey(gk.group_id, 1, os.urandom(32)))
    assert reason(accept, forged2, gk, a) == "tampered"


def test_attack_member_injection_without_password():
    a, ring, gk = make()
    mallory = ident()
    t = copy.deepcopy(ring)
    guess = GroupKey(gk.group_id, 1, os.urandom(32))  # without G the name is sealed under a guessed key
    t["members"].append(kr._member_entry(guess, kr._new_member(mallory, "M"))[0])
    t["device_wraps"][mallory.device_id] = copy.deepcopy(t["device_wraps"][a.device_id])
    structure(t)
    assert reason(accept, t, gk, a) == "tampered"
    # even an attacker who knows the password cannot forge the MAC without G: wrong-key MAC
    t2 = kr._finish({k: v for k, v in t.items() if k not in ("mac", "prev_mac")},
                    GroupKey(gk.group_id, 1, os.urandom(32)), None)
    assert reason(accept, t2, gk, a) == "tampered"


def test_attack_removed_member_forges_next_epoch():
    a, ring, gk = make()
    b, ring, gk_b = join(ring)
    c, ring, _ = join(ring)
    genuine, gk2 = rotate(ring, gk, a, PW2, remove=[b.device_id])
    # b knows the old G and old password; builds an epoch 2 keyring that chains correctly
    evil = GroupKey(gk.group_id, 2, os.urandom(32))
    members = [kr._new_member(b, "B"), kr._new_member(c, "C"), kr._new_member(a, "A")]
    forged = kr._finish(kr._fresh_body(evil, PW, members, CHEAP), evil, gk_b)
    structure(forged)
    # devices already at the genuine epoch 2 reject it
    assert reason(accept, forged, gk2, a) == "tampered"
    assert reason(accept, forged, gk2, c) == "tampered"
    # and the genuine keyring is still accepted
    assert accept(genuine, gk2, a) == gk2


def test_rollback_rejected():
    a, ring, gk = make()
    new, gk2 = rotate(ring, gk, a, PW2)
    assert reason(accept, ring, gk2, a) == "rollback"


def test_missed_rotation_rejected():
    a, ring, gk = make()
    r2, gk2 = rotate(ring, gk, a, PW2)
    r3, gk3 = rotate(r2, gk2, a, PW3)
    assert reason(accept, r3, gk, a) == "missed-rotation"
    assert accept(r3, gk2, a) == gk3


def test_tampering_same_epoch_reported_tampered():
    a, ring, gk = make()
    b, ring, _ = join(ring)
    paths = [
        ("group_id",), ("kdf", "salt"), ("password_wrap", "ct"), ("password_wrap", "nonce"),
        ("members", 0, "added_at"), ("members", 0, "name_ct"), ("members", 0, "exchange_public"),
        ("members", 1, "exchange_public"),
    ]
    for path in paths:
        t = copy.deepcopy(ring)
        node = t
        for p in path[:-1]:
            node = node[p]
        old = node[path[-1]]
        if isinstance(old, int):
            node[path[-1]] = old + 1
        elif path[-1] == "group_id":
            node[path[-1]] = old + "x"
        else:
            node[path[-1]] = flip(old)
        r = reason(accept, t, gk, a)
        assert r in ("tampered", "group-mismatch"), (path, r)
        if path != ("group_id",):
            assert r == "tampered", path
    for dev in (a, b):
        t = copy.deepcopy(ring)
        for fld in ("eph", "nonce", "ct"):
            t["device_wraps"][dev.device_id][fld] = flip(t["device_wraps"][dev.device_id][fld])
        assert reason(accept, t, gk, a) == "tampered"
    t = copy.deepcopy(ring)
    t["mac"] = flip(t["mac"])
    assert reason(accept, t, gk, a) == "tampered"
    t = copy.deepcopy(ring)
    t["members"].reverse()
    assert reason(accept, t, gk, a) == "tampered"


def test_wrap_aad_binds_epoch():
    a, ring, gk = make()
    new, gk2 = rotate(ring, gk, a, PW2)
    t = copy.deepcopy(new)
    t["epoch"] = 3
    assert reason(accept, t, gk, a) == "missed-rotation"
    t = copy.deepcopy(new)
    t["device_wraps"][a.device_id] = ring["device_wraps"][a.device_id]
    assert reason(accept, t, gk, a) in ("tampered", "device-wrap")


def test_wrap_member_mismatch():
    a, ring, gk = make()
    extra = copy.deepcopy(ring)
    extra["device_wraps"]["ghost"] = copy.deepcopy(ring["device_wraps"][a.device_id])
    assert reason(structure, extra) == "wrap-mismatch"
    b, ring2, _ = join(ring)
    missing = copy.deepcopy(ring2)
    del missing["device_wraps"][b.device_id]
    assert reason(structure, missing) == "wrap-mismatch"


def test_non_ascii_device_id_rejected():
    a, ring, gk = make()
    # pairing.DeviceIdentity.generate refuses such ids now; build one directly to test the keyring check.
    bad = dataclasses.replace(DeviceIdentity.generate(), device_id="dévice-1")
    assert reason(kr.join_with_password, ring, PW, bad, "B", _kdf_override=CHEAP) == "bad-device-id"
    assert reason(kr.create_group, PW, bad, "B", _kdf_override=CHEAP) == "bad-device-id"
    t = copy.deepcopy(ring)
    t["members"][0]["device_id"] = "dév"
    t["device_wraps"] = {"dév": t["device_wraps"][a.device_id]}
    assert reason(structure, t) == "bad-device-id"


def test_names():
    a = ident()
    for bad in ("", "x" * 65, "é" * 33, "bad\ud800", 5):
        assert reason(kr.create_group, PW, a, bad, _kdf_override=CHEAP) == "bad-name"
    kr.create_group(PW, a, "é" * 32, _kdf_override=CHEAP)
    _, ring, _ = make()
    for bad in ("", "x" * 65, 5):
        assert reason(kr.join_with_password, ring, PW, ident(), bad, _kdf_override=CHEAP) == "bad-name"


def test_structure_fields_and_types():
    a, ring, gk = make()
    cases = [
        lambda t: t.update(extra=1),
        lambda t: t.pop("epoch"),
        lambda t: t.pop("mac"),
        lambda t: t.update(signature="x"),
        lambda t: t.update(format=2),
        lambda t: t.update(format=True),
        lambda t: t.update(epoch=0),
        lambda t: t.update(epoch=1.0),
        lambda t: t.update(epoch=True),
        lambda t: t.update(group_id="gé"),
        lambda t: t.update(prev_mac=b64(bytes(32))),
        lambda t: t.update(mac="x"),
        lambda t: t["kdf"].update(extra=1),
        lambda t: t["kdf"].update(name="scrypt"),
        lambda t: t["kdf"].update(iterations=True),
        lambda t: t["kdf"].update(memory_kib=8),
        lambda t: t["kdf"].update(salt=b64(b"x" * 15)),
        lambda t: t["password_wrap"].update(extra="x"),
        lambda t: t["password_wrap"].update(nonce=b64(b"x" * 11)),
        lambda t: t["password_wrap"].update(ct="not base64!"),
        lambda t: t["password_wrap"].update(ct=t["password_wrap"]["ct"] + "\n"),
        lambda t: t["members"][0].update(extra=1),
        lambda t: t["members"][0].update(signing_public=b64(bytes(32))),
        lambda t: t["members"][0].update(name_ct=5),
        lambda t: t["members"][0].update(name="Desk"),
        lambda t: t["members"][0].update(added_at="1"),
        lambda t: t["device_wraps"][a.device_id].update(extra="x"),
        lambda t: t.update(members=[]),
        lambda t: t.update(device_wraps=[]),
        lambda t: t["members"].append(copy.deepcopy(t["members"][0])),
    ]
    for fn in cases:
        t = copy.deepcopy(ring)
        fn(t)
        with pytest.raises(kr.KeyringError):
            structure(t)
    with pytest.raises(kr.KeyringError):
        structure("nope")
    r2, _ = rotate(ring, gk, a)
    r2["prev_mac"] = None
    structure(r2)  # null prev_mac is allowed at any epoch (a first keyring for an existing group)
    r2["prev_mac"] = "x"
    assert reason(structure, r2) == "bad-base64"


def test_parse_keyring():
    _, ring, _ = make()
    assert kr.parse_keyring(canonical_json(ring)) == ring
    bad_inputs = (b'{"format":1,"format":1}', b"[]", b"\xff", b"{", b"NaN", b'{"a":NaN}',
                  b'{"a":1e999}', b'{"a":-1e999}', b" " * (256 * 1024 + 1))
    for bad in bad_inputs:
        with pytest.raises(kr.KeyringError):
            kr.parse_keyring(bad)
    with pytest.raises(kr.KeyringError):
        kr.parse_keyring("str")  # type: ignore[arg-type]


def test_no_signature_api_left():
    for name in ("remove_member", "change_password", "verify_keyring", "unwrap_for_device"):
        assert not hasattr(kr, name)


def test_lagging_device_accepts_keyring_after_later_join():
    a, ring, gk = make()
    c, ring, _ = join(ring)
    rotated, gk2 = rotate(ring, gk, a, PW2)
    # c missed the rotation; d joins at epoch 2 (rewrites members, wraps, mac; keeps prev_mac)
    c_member = {"device_id": c.device_id}
    assert c_member["device_id"] in {m["device_id"] for m in rotated["members"]}
    d, joined, _ = join(rotated, PW2)
    assert joined["prev_mac"] == rotated["prev_mac"]
    assert accept(joined, gk, c) == gk2
    assert accept(joined, gk2, d) == gk2
    # a forged prev_mac is tampered
    forged = copy.deepcopy(joined)
    forged["prev_mac"] = flip(forged["prev_mac"])
    assert reason(accept, forged, gk, c) == "tampered"


def test_swapping_prev_mac_same_epoch_is_tampered():
    a, ring, gk = make()
    new, gk2 = rotate(ring, gk, a, PW2)
    t = copy.deepcopy(new)
    t["prev_mac"] = flip(t["prev_mac"])
    assert reason(accept, t, gk2, a) == "tampered"


def test_rotate_rejects_password_reuse():
    a, ring, gk = make()
    assert reason(rotate, ring, gk, a, PW) == "password-reused"
    new, gk2 = rotate(ring, gk, a, PW2)
    assert reason(rotate, new, gk2, a, PW2) == "password-reused"
    assert rotate(new, gk2, a, PW)[1].epoch == 3


KAT_NAME = "Pièce ☃ \x01\x1f \"q\" \\ / \n\t"
KAT_CANONICAL = (
    b'{"device_wraps":{"dev.1":{"ct":"BgYGBgYGBgYGBgYGBgYGBgYGBgYGBgYGBgYGBgYGBgYGBgYGBgYGBgYGBgYGBgYG",'
    b'"eph":"BAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQ=","nonce":"BQUFBQUFBQUFBQUF"}},"epoch":2,'
    b'"format":1,"group_id":"grp-kat:1","kdf":{"iterations":4,"memory_kib":131072,"name":"argon2id",'
    b'"parallelism":4,"salt":"AQEBAQEBAQEBAQEBAQEBAQ=="},"members":[{"added_at":1700000000,'
    b'"device_id":"dev.1","exchange_public":"BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc=",'
    b'"name_ct":"CQkJCQkJCQkJCQkJXe8qgz+I4AHzQC7sO2xRZO/tVo0EVB2n/20VcV+kLFT0K7DXBMXN4Q=="}],'
    b'"password_wrap":{"ct":"AwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMD",'
    b'"nonce":"AgICAgICAgICAgIC"},"prev_mac":"CAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg="}'
)
#: KAT_NAME sealed for "dev.1" at epoch 2 of the KAT key with the nonce 09 x 12.
KAT_NAME_CT = "CQkJCQkJCQkJCQkJXe8qgz+I4AHzQC7sO2xRZO/tVo0EVB2n/20VcV+kLFT0K7DXBMXN4Q=="
KAT_NAME_KEY = "7cfea35c29ef45e741124b90e1d51d99bde92c36cf37e887459b845c497fca35"
KAT_MAC = "28a5e9281795f2684bd9d7ec7ba17192482f99c2162cde23000888f75ce0e121"
KAT_CHAIN = "01d873ef51c359bf2c7c3c5aa700960df0477650efbc946d684377e0467b1e9e"


def test_known_answer_canonical_body_and_mac():
    def f(n, x):
        return b64(bytes([x]) * n)

    gk = GroupKey("grp-kat:1", 2, bytes(range(32)))
    assert kr._name_key(gk).hex() == KAT_NAME_KEY
    assert kr._seal_name(gk, "dev.1", KAT_NAME, lambda n: bytes([9]) * n) == KAT_NAME_CT
    # canonical JSON string escaping (the name used to be stored in clear and pinned this)
    assert canonical_json({"name": KAT_NAME}) == (
        b'{"name":"Pi\xc3\xa8ce \xe2\x98\x83 \\u0001\\u001f \\"q\\" \\\\ / \\n\\t"}')
    body = {
        "format": 1, "group_id": "grp-kat:1", "epoch": 2,
        "kdf": {"name": "argon2id", "salt": f(16, 1), "memory_kib": 131072, "iterations": 4, "parallelism": 4},
        "password_wrap": {"nonce": f(12, 2), "ct": f(48, 3)},
        "device_wraps": {"dev.1": {"eph": f(32, 4), "nonce": f(12, 5), "ct": f(48, 6)}},
        "members": [{"device_id": "dev.1", "name_ct": KAT_NAME_CT, "exchange_public": f(32, 7),
                     "added_at": 1700000000}],
        "prev_mac": f(32, 8),
    }
    assert canonical_json(body) == KAT_CANONICAL
    assert kr.member_names(body, gk) == {"dev.1": KAT_NAME}
    assert kr._mac(gk.key, gk.group_id, 2, body).hex() == KAT_MAC
    old = GroupKey("grp-kat:1", 1, bytes(range(32, 64)))
    assert kr._chain_mac(old, gk).hex() == KAT_CHAIN


# --- encrypted member names --------------------------------------------------------------------


def test_member_names_encrypted_and_readable():
    a = ident()
    ring, gk = kr.create_group(PW, a, "Desk", _kdf_override=CHEAP)
    b = ident()
    ring, _ = kr.join_with_password(ring, PW, b, "Laptop", _kdf_override=CHEAP)
    for m in ring["members"]:
        assert set(m) == {"device_id", "name_ct", "exchange_public", "added_at"}
        assert "Desk" not in m["name_ct"] and "Laptop" not in m["name_ct"]
    assert b"Desk" not in canonical_json(ring) and b"Laptop" not in canonical_json(ring)
    assert kr.member_names(ring, gk) == {a.device_id: "Desk", b.device_id: "Laptop"}
    assert kr.DEFAULT_DEVICE_NAME_PC == "Windows PC"


def test_name_ct_bound_to_device_and_epoch():
    a, ring, gk = make()
    b, ring, _ = join(ring, name="B")
    t = copy.deepcopy(ring)
    t["members"][0]["name_ct"], t["members"][1]["name_ct"] = ring["members"][1]["name_ct"], ring["members"][0]["name_ct"]
    assert kr.member_names(t, gk) == {a.device_id: None, b.device_id: None}
    assert reason(accept, t, gk, a) == "tampered"


def test_name_ct_matches_spec():
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF

    a, ring, gk = make()
    raw = base64.b64decode(ring["members"][0]["name_ct"])
    key = HKDF(hashes.SHA256(), 32, ring["group_id"].encode(), b"localgatekeys|sync|member-name|v1|1").derive(gk.key)
    aad = b"lgk-keyring-member-name-v1|" + ring["group_id"].encode() + b"|1|" + a.device_id.encode()
    assert AESGCM(key).decrypt(raw[:12], raw[12:], aad) == b"A"
    assert len(raw) == 12 + 1 + 16


def test_rotation_reencrypts_names():
    a = ident()
    ring, gk = kr.create_group(PW, a, "Desk \u00e9", _kdf_override=CHEAP)
    b = ident()
    ring, _ = kr.join_with_password(ring, PW, b, "Laptop", _kdf_override=CHEAP)
    new, gk2 = rotate(ring, gk, a)
    assert kr.member_names(new, gk2) == {a.device_id: "Desk \u00e9", b.device_id: "Laptop"}
    assert kr.member_names(new, gk) == {a.device_id: None, b.device_id: None}
    assert new["members"][0]["name_ct"] != ring["members"][0]["name_ct"]
    assert [m["added_at"] for m in new["members"]] == [m["added_at"] for m in ring["members"]]
    # a G holder wrote an unreadable name (valid MAC): rotation re-seals it as "Unnamed device"
    t = copy.deepcopy(ring)
    t["members"][1]["name_ct"] = ring["members"][0]["name_ct"]
    t = kr._finish(t, gk, None, t["prev_mac"])
    assert accept(t, gk, a) == gk
    assert kr.member_names(t, gk)[b.device_id] is None
    new, gk2 = rotate(t, gk, a)
    assert kr.member_names(new, gk2) == {a.device_id: "Desk é", b.device_id: kr.UNNAMED_DEVICE}


def test_name_ct_length_checked():
    a, ring, gk = make()
    for size in (28, 93):
        t = copy.deepcopy(ring)
        t["members"][0]["name_ct"] = b64(bytes(size))
        assert reason(structure, t) == "bad-name"
    for size in (29, 92):
        t = copy.deepcopy(ring)
        t["members"][0]["name_ct"] = b64(bytes(size))
        structure(t)
    t = copy.deepcopy(ring)
    t["members"][0]["name_ct"] = "not base64!"
    with pytest.raises(kr.KeyringError):
        structure(t)
    assert len(base64.b64decode(kr.create_group(PW, a, "x" * 64, _kdf_override=CHEAP)[0]["members"][0]["name_ct"])) == 92


# --- a first keyring for an existing (Wi-Fi) group, and attaching to it ----------------------------


def _lan_gk(epoch: int = 1) -> GroupKey:
    return GroupKey("lan-group-1", epoch, os.urandom(32))


def first_ring(gk, dev, pw=PW, name="A"):
    return kr.create_for_existing_group(gk, pw, dev, name, _kdf_override=CHEAP)


def attach(ring, dev, stored, pw=PW, name="B"):
    return kr.attach_with_password(ring, pw, dev, name, stored, _kdf_override=CHEAP)


@pytest.mark.parametrize("epoch", [1, 3])
def test_first_keyring_for_existing_group_epoch1_and_3(epoch):
    a = ident()
    gk = _lan_gk(epoch)
    ring = first_ring(gk, a)
    structure(ring)
    assert ring["group_id"] == gk.group_id and ring["epoch"] == epoch and ring["prev_mac"] is None
    assert accept(ring, gk, a) == gk
    assert kr.member_names(ring, gk) == {a.device_id: "A"}
    # the password opens the same G: a join works like on any keyring
    dev, joined, gk2 = join(ring)
    assert gk2 == gk and accept(joined, gk, a) == gk and joined["prev_mac"] is None
    # a rotation from it chains normally
    rotated, new_gk = rotate(ring, gk, a)
    assert new_gk.epoch == epoch + 1 and rotated["prev_mac"] is not None
    assert accept(rotated, gk, a) == new_gk


def test_first_keyring_checks_inputs():
    a = ident()
    with pytest.raises(kr.WeakSyncPassword):
        first_ring(_lan_gk(), a, pw="short")
    assert reason(first_ring, _lan_gk(), a, name="") == "bad-name"
    assert reason(first_ring, ("g", 1, os.urandom(32)), a) == "bad-group-key"  # not a GroupKey


def test_epoch_plus_one_still_needs_prev_mac():
    a = ident()
    gk = _lan_gk(1)
    ring = first_ring(gk, a)
    # a G holder (or anyone with the next key) builds an epoch-2 keyring without a chain
    forged = first_ring(GroupKey(gk.group_id, 2, os.urandom(32)), a)
    assert forged["prev_mac"] is None
    assert reason(accept, forged, gk, a) == "tampered"
    assert accept(ring, gk, a) == gk


def test_attach_adds_member_and_keeps_identity():
    a, b = ident(), ident()
    gk = _lan_gk(2)
    ring = first_ring(gk, a)
    out = attach(ring, b, gk)
    assert isinstance(out, dict)
    assert [m["device_id"] for m in out["members"]] == [a.device_id, b.device_id]
    assert out["prev_mac"] is None and out["epoch"] == 2
    assert accept(out, gk, a) == gk and accept(out, gk, b) == gk
    assert kr.open_with_device_wrap(out, b, _kdf_override=CHEAP) == gk
    assert kr.member_names(out, gk) == {a.device_id: "A", b.device_id: "B"}


def test_attach_refuses_different_group_key():
    a, b = ident(), ident()
    gk = _lan_gk()
    ring = first_ring(GroupKey(gk.group_id, gk.epoch, os.urandom(32)), a)  # same id, another G
    assert reason(attach, ring, b, gk) == "different-group-key"
    other = first_ring(GroupKey("other-group", gk.epoch, gk.key), a)  # same G under another id
    assert reason(attach, other, b, gk) == "different-group-key"


def test_attach_reasons():
    a, b = ident(), ident()
    gk = _lan_gk(2)
    ring = first_ring(gk, a)
    assert reason(attach, ring, b, gk, pw=PW2) == "password"
    assert reason(attach, ring, b, GroupKey(gk.group_id, 1, gk.key)) == "epoch-mismatch"
    assert reason(attach, ring, ident(a.device_id), gk) == "already-member"  # same id, other key
    t = copy.deepcopy(ring)
    t["members"][0]["added_at"] += 1  # body changed without the MAC
    assert reason(attach, t, b, gk) == "tampered"
    assert reason(attach, ring, b, gk, name="") == "bad-name"


def test_attach_is_idempotent_for_the_same_device():
    a, b = ident(), ident()
    gk = _lan_gk(2)
    once = attach(first_ring(gk, a), b, gk)
    assert attach(once, b, gk) is once  # an attach that wrote but did not finish: retry succeeds, no rewrite
    assert attach(once, a, gk) is once
    assert reason(attach, once, b, gk, pw=PW2) == "password"  # the password is still checked
    assert reason(attach, once, ident(b.device_id), gk) == "already-member"
    # listed with its own key, but its wrap opens another key (a G holder rewrote it): already-member
    t = copy.deepcopy(once)
    t["device_wraps"][b.device_id] = kr._wrap_device(GroupKey(gk.group_id, gk.epoch, os.urandom(32)),
                                                     b.device_id, b.exchange_public_key)
    t = kr._finish(t, gk, None, t["prev_mac"])
    assert reason(attach, t, b, gk) == "already-member"
