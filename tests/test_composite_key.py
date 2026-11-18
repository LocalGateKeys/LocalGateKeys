"""Composite key v1 (docs/formats/COMPOSITE_KEY_V1.md): the shared vectors in tests/vectors/composite_key.

The vectors are the cross-platform contract (Windows vault v4, Apple MasterKeyFile v2, Android
AppPasswordWrap v2).  The generator must reproduce every committed file byte for byte.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import importlib.util
import json
import struct
import sys
from pathlib import Path
from unittest import mock

import pytest
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from localvault import composite_key, keyfile, secret_text, vault
from localvault.composite_key import FactorMismatch, FactorSpec

ROOT = Path(__file__).resolve().parents[1]
VEC = ROOT / "tests" / "vectors" / "composite_key"
SCRIPT = ROOT / "scripts" / "make_composite_vectors.py"
CASES = json.loads((VEC / "cases.json").read_text(encoding="utf-8"))
ARGON_OUT = bytes.fromhex(CASES["argon"]["output_hex"])
BY_NAME = {case["name"]: case for case in CASES["cases"]}
GENERIC = [case for case in CASES["cases"] if "combine_hex" in case]
KEYFILES = {row["name"]: row for row in CASES["keyfiles"]}


def _load_generator():
    spec = importlib.util.spec_from_file_location("make_composite_vectors", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    sys.modules["make_composite_vectors"] = module
    spec.loader.exec_module(module)
    return module


def _specs(case):
    return [FactorSpec.from_json(item) for item in case["factors"]]


def _secret(source: str) -> bytes:
    if source == "yubikey":
        return bytes.fromhex(CASES["yubikey"]["secret_hex"])
    return bytes.fromhex(KEYFILES[source]["key_hex"])


def test_case_names():
    assert [case["name"] for case in CASES["cases"]] == [
        "no_factors", "keyfile_xml_v2", "keyfile_xml_v1", "keyfile_raw32", "keyfile_hex64", "keyfile_arbitrary",
        "yubikey_only", "keyfile_and_yubikey", "windows_v4_header", "apple_masterkeyfile_v2",
        "android_apppassword_v2",
    ]


def test_argon_input():
    argon = CASES["argon"]
    out = secret_text.argon2id_raw(bytearray(argon["password"].encode()), bytes.fromhex(argon["salt_hex"]),
                                   time_cost=argon["time_cost"], memory_cost=argon["memory_cost_kib"],
                                   parallelism=argon["parallelism"], hash_len=argon["hash_len"])
    assert out.hex() == argon["output_hex"]


@pytest.mark.parametrize("case", GENERIC, ids=lambda case: case["name"])
def test_combine_vectors(case):
    specs = _specs(case)
    secrets = [bytes.fromhex(value) for value in case["secrets_hex"]]
    key = composite_key.combine(ARGON_OUT, specs, secrets)
    assert bytes(key).hex() == case["combine_hex"]
    if specs:
        assert composite_key.info(specs).decode("ascii") == case["info"]
    wrap = case["wrap"]
    data_key = AESGCM(bytes(key)).decrypt(bytes.fromhex(wrap["nonce_hex"]), bytes.fromhex(wrap["ciphertext_hex"]),
                                          bytes.fromhex(wrap["aad_hex"]))
    assert data_key.hex() == CASES["data_key_hex"]


@pytest.mark.parametrize("name", ["keyfile_xml_v2", "keyfile_xml_v1", "keyfile_raw32", "keyfile_hex64",
                                  "keyfile_arbitrary"])
def test_keyfile_cases_use_the_key_file_key(name):
    case = BY_NAME[name]
    data = (VEC / KEYFILES[name]["file"]).read_bytes()
    assert case["secrets_hex"] == [keyfile.key_from_bytes(data).hex()]


def test_empty_factors_identity():
    argon_out = bytearray(ARGON_OUT)
    assert composite_key.combine(argon_out, [], []) is argon_out
    assert BY_NAME["no_factors"]["combine_hex"] == ARGON_OUT.hex()


def test_factor_check_vectors():
    for row in CASES["keyfiles"]:
        assert composite_key.factor_check(bytes.fromhex(row["key_hex"])) == row["check"]
    yubikey = CASES["yubikey"]
    assert composite_key.factor_check(bytes.fromhex(yubikey["secret_hex"])) == yubikey["check"]
    for case in GENERIC:
        for spec, secret in zip(_specs(case), case["secrets_hex"], strict=True):
            assert composite_key.factor_check(bytes.fromhex(secret)) == spec.check
    secret = bytes(range(32))
    expected = hmac.new(secret, b"localgatekeys|factor-check|v1", hashlib.sha256).digest()[:8].hex()
    assert composite_key.factor_check(secret) == expected


def test_yubikey_vector():
    yubikey = CASES["yubikey"]
    padded = composite_key.pad_challenge(bytes.fromhex(yubikey["challenge_hex"]))
    assert padded.hex() == yubikey["padded_challenge_hex"]
    response = hmac.new(yubikey["hmac_secret"].encode(), bytes.fromhex(yubikey["hmac_message_hex"]),
                        hashlib.sha1).digest()
    assert response.hex() == yubikey["response_hex"]
    assert composite_key.yubikey_secret(response).hex() == yubikey["secret_hex"]
    with pytest.raises(ValueError):
        composite_key.yubikey_secret(response[:19])


def test_pad_challenge_vector():
    for row in CASES["pad_challenge"]:
        challenge = bytes.fromhex(row["challenge_hex"])
        padded = composite_key.pad_challenge(challenge)
        assert padded.hex() == row["padded_hex"]
        assert len(padded) == 64 and padded[32:] == b"\x20" * 32 and padded[:32] == challenge
    with pytest.raises(ValueError):
        composite_key.pad_challenge(b"\x00" * 31)


def test_verify_accepts_right_secrets():
    case = BY_NAME["keyfile_and_yubikey"]
    composite_key.verify(_specs(case), [bytes.fromhex(value) for value in case["secrets_hex"]])
    composite_key.verify([], [])


def test_verify_mismatch_names_the_kind():
    case = BY_NAME["keyfile_and_yubikey"]
    keyfile_secret, yubikey_secret = (bytes.fromhex(value) for value in case["secrets_hex"])
    with pytest.raises(FactorMismatch) as caught:
        composite_key.verify(_specs(case), [b"\x01" * 32, yubikey_secret])
    assert caught.value.kind == "keyfile"
    with pytest.raises(FactorMismatch) as caught:
        composite_key.verify(_specs(case), [keyfile_secret, b"\x01" * 32])
    assert caught.value.kind == "yubikey-hmac"


def test_verify_mismatch_raises_before_kdf():
    case = BY_NAME["keyfile_and_yubikey"]
    _, yubikey_secret = (bytes.fromhex(value) for value in case["secrets_hex"])
    kdf = json.loads((VEC / "windows_v4_vault.json").read_bytes())["kdf"]
    with mock.patch.object(secret_text, "argon2id_raw", side_effect=AssertionError("Argon2 ran")) as argon:
        with pytest.raises(FactorMismatch):
            composite_key.derive_wrapping_key(lambda: vault._derive_key("pw", kdf), _specs(case),
                                              [b"\x02" * 32, yubikey_secret])
    argon.assert_not_called()


def test_derive_wrapping_key_matches_combine():
    case = BY_NAME["keyfile_and_yubikey"]
    secrets = [bytes.fromhex(value) for value in case["secrets_hex"]]
    out = composite_key.derive_wrapping_key(lambda: bytearray(ARGON_OUT), _specs(case), secrets)
    assert out.hex() == case["combine_hex"]
    plain = bytearray(ARGON_OUT)
    assert composite_key.derive_wrapping_key(lambda: plain, [], []) is plain


def test_combine_rejects_bad_inputs():
    case = BY_NAME["keyfile_and_yubikey"]
    specs = _specs(case)
    secrets = [bytes.fromhex(value) for value in case["secrets_hex"]]
    with pytest.raises(ValueError):
        composite_key.combine(ARGON_OUT, specs, secrets[:1])
    with pytest.raises(ValueError):
        composite_key.combine(ARGON_OUT, specs, [secrets[0], secrets[1][:31]])
    with pytest.raises(ValueError):
        composite_key.combine(ARGON_OUT, list(reversed(specs)), list(reversed(secrets)))
    with pytest.raises(ValueError):
        composite_key.combine(ARGON_OUT, [specs[0], specs[0]], [secrets[0], secrets[0]])
    with pytest.raises(ValueError):
        composite_key.combine(ARGON_OUT[:16], specs, secrets)


@pytest.mark.parametrize("bad", [
    {"kind": "password", "check": "00" * 8},
    {"kind": "keyfile", "check": "00" * 7},
    {"kind": "keyfile", "check": "AA" * 8},
    {"kind": "keyfile", "check": "00" * 8, "slot": 2},
    {"kind": "keyfile", "check": "00" * 8, "extra": 1},
    {"kind": "yubikey-hmac", "check": "00" * 8, "slot": 2},
    {"kind": "yubikey-hmac", "check": "00" * 8, "slot": 3, "challenge": "00" * 32},
    {"kind": "yubikey-hmac", "check": "00" * 8, "slot": True, "challenge": "00" * 32},
    {"kind": "yubikey-hmac", "check": "00" * 8, "slot": 2, "challenge": "00" * 31},
    {"kind": "yubikey-hmac", "check": "00" * 8, "slot": 2, "challenge": "0G" * 32},
])
def test_factor_spec_rejects_malformed(bad):
    with pytest.raises(ValueError):
        FactorSpec.from_json(bad)


def test_factor_spec_to_json_drops_none():
    spec = FactorSpec("keyfile", "00" * 8)
    assert spec.to_json() == {"kind": "keyfile", "check": "00" * 8}
    assert composite_key.info([spec]) == b'[{"check":"0000000000000000","kind":"keyfile"}]'


def test_windows_v4_vector_decrypts():
    case = BY_NAME["windows_v4_header"]
    header = json.loads((VEC / case["file"]).read_bytes())
    assert header["version"] == 4 and header["format"] == "localgatekeys-vault-v4"
    password_wrapper = header["wrappers"]["password"]
    specs = [FactorSpec.from_json(item) for item in password_wrapper["factors"]]
    secrets = [_secret(source) for source in case["secret_sources"]]
    composite_key.verify(specs, secrets)
    argon_out = vault._derive_key(case["password"], header["kdf"])
    assert argon_out.hex() == case["argon_out_hex"]
    kek = composite_key.combine(argon_out, specs, secrets)
    assert bytes(kek).hex() == case["kek_hex"]
    identity = {"version": 3, "format": "localgatekeys-vault-v3", "catalog": header["catalog"],
                "catalog_version": header["catalog_version"], "vault_id": header["vault_id"],
                "key_generation": header["key_generation"]}
    aad = b"localgatekeys|vault-key-wrapper|v3|" + vault._canonical_json(
        dict(identity, wrapper="password", metadata={"kdf": header["kdf"], "factors": password_wrapper["factors"]}))
    assert base64.b64encode(aad).decode() == case["wrapper_aad_b64"]
    data_key = AESGCM(bytes(kek)).decrypt(base64.b64decode(password_wrapper["nonce"]),
                                          base64.b64decode(password_wrapper["ciphertext"]), aad)
    assert data_key.hex() == case["data_key_hex"]
    # The catalog and the recovery wrapper use the same AAD a v3 header with these fields gets.
    v3_twin = dict(header, version=3, format="localgatekeys-vault-v3")
    catalog = AESGCM(data_key).decrypt(base64.b64decode(header["cipher"]["nonce"]),
                                       base64.b64decode(header["cipher"]["ciphertext"]), vault._aad(v3_twin))
    assert json.loads(catalog) == case["payload"]
    recovery = header["wrappers"]["recovery"]
    entropy = vault.entropy_from_phrase(case["recovery_phrase"])
    assert entropy.hex() == case["recovery_entropy_hex"]
    rkey = vault._recovery_key(entropy, base64.b64decode(recovery["salt"]))
    metadata = {"kind": recovery["kind"], "salt": recovery["salt"]}
    assert AESGCM(bytes(rkey)).decrypt(base64.b64decode(recovery["nonce"]), base64.b64decode(recovery["ciphertext"]),
                                       vault._wrapper_aad(v3_twin, "recovery", metadata)) == data_key


def test_apple_masterkeyfile_v2_vector():
    case = BY_NAME["apple_masterkeyfile_v2"]
    document = json.loads((VEC / case["file"]).read_bytes())
    assert document["version"] == 2
    specs = [FactorSpec.from_json(item) for item in document["factors"]]
    assert specs[0].slot == 1
    padded = composite_key.pad_challenge(bytes.fromhex(specs[0].challenge))
    assert padded.hex() == case["yubikey"]["padded_challenge_hex"]
    secret = composite_key.yubikey_secret(bytes.fromhex(case["yubikey"]["response_hex"]))
    kdf = document["kdf"]
    aad = (f"localgatekeys|mac-master|v2|t={kdf['time_cost']}|m={kdf['memory_kib']}|p={kdf['parallelism']}"
           f"|salt={document['salt']}|factors=").encode() + composite_key.info(specs)
    assert aad.hex() == case["aad_hex"]
    argon_out = secret_text.argon2id_raw(bytearray(case["password"].encode()), base64.b64decode(document["salt"]),
                                         time_cost=kdf["time_cost"], memory_cost=kdf["memory_kib"],
                                         parallelism=kdf["parallelism"], hash_len=32)
    key = composite_key.combine(argon_out, specs, [secret])
    assert bytes(key).hex() == case["key_hex"]
    local_key = AESGCM(bytes(key)).decrypt(base64.b64decode(document["nonce"]),
                                           base64.b64decode(document["sealed_key"]), aad)
    assert local_key.hex() == case["local_key_hex"]


def test_android_apppassword_v2_vector():
    case = BY_NAME["android_apppassword_v2"]
    record = (VEC / case["file"]).read_bytes()
    assert record.hex() == case["hex"] and len(record) == case["size"]
    assert record[:6] == b"LGKAPW" and record[6] == 2
    memory_kib = struct.unpack(">I", record[7:11])[0]
    iterations, parallelism = record[11], record[12]
    length = struct.unpack(">H", record[13:15])[0]
    factors = record[15:15 + length]
    specs = [FactorSpec.from_json(item) for item in json.loads(factors)]
    assert composite_key.info(specs) == factors  # stored canonical
    assert len(record) == 167 + length
    body = record[15 + length:]
    pw_salt, pw_nonce, pw_sealed = body[:16], body[16:28], body[28:76]
    rec_salt, rec_nonce, rec_sealed = body[76:92], body[92:104], body[104:152]
    secrets = [_secret(source) for source in case["secret_sources"]]
    argon_out = secret_text.argon2id_raw(bytearray(case["password"].encode()), pw_salt, time_cost=iterations,
                                         memory_cost=memory_kib, parallelism=parallelism, hash_len=32)
    key = composite_key.combine(argon_out, specs, secrets)
    assert bytes(key).hex() == case["key_hex"]
    password_aad = record[:15 + length] + b"|password"
    assert password_aad.hex() == case["password_aad_hex"]
    assert AESGCM(bytes(key)).decrypt(pw_nonce, pw_sealed, password_aad).hex() == case["local_key_hex"]
    # The recovery wrapper keeps its v1 AAD, so adding a factor never needs the phrase.
    recovery_aad = b"LGKAPW\x01" + record[7:13] + b"|recovery"
    assert recovery_aad.hex() == case["recovery_aad_hex"]
    entropy = vault.entropy_from_phrase(case["recovery_phrase"])
    rkey = vault._recovery_key(entropy, rec_salt)
    assert AESGCM(bytes(rkey)).decrypt(rec_nonce, rec_sealed, recovery_aad).hex() == case["local_key_hex"]


def test_generator_reproduces_committed_vectors(tmp_path: Path):
    generator = _load_generator()
    generator.write(tmp_path)
    produced = sorted(p.relative_to(tmp_path).as_posix() for p in tmp_path.rglob("*") if p.is_file())
    committed = sorted(p.relative_to(VEC).as_posix() for p in VEC.rglob("*") if p.is_file())
    assert produced == committed
    for name in produced:
        assert (tmp_path / name).read_bytes() == (VEC / name).read_bytes(), name


FORMAT_CASES = ["windows_v4_header", "apple_masterkeyfile_v2", "android_apppassword_v2"]
TAMPERED = [(name, row) for name in FORMAT_CASES for row in BY_NAME[name]["tampered"]]


def _password_wrapper(name: str) -> tuple[bytes, bytes]:
    """``(nonce, sealed)`` of the password wrapper in a format vector."""
    case = BY_NAME[name]
    if name == "windows_v4_header":
        wrapper = json.loads((VEC / case["file"]).read_bytes())["wrappers"]["password"]
        return base64.b64decode(wrapper["nonce"]), base64.b64decode(wrapper["ciphertext"])
    if name == "apple_masterkeyfile_v2":
        document = json.loads((VEC / case["file"]).read_bytes())
        return base64.b64decode(document["nonce"]), base64.b64decode(document["sealed_key"])
    record = (VEC / case["file"]).read_bytes()
    length = struct.unpack(">H", record[13:15])[0]
    body = record[15 + length:]
    return body[16:28], body[28:76]


def test_every_format_has_the_three_tampered_rows():
    for name in FORMAT_CASES:
        assert [row["name"] for row in BY_NAME[name]["tampered"]] == [
            "factors_removed", "slot_changed", "challenge_changed"]


@pytest.mark.parametrize(("name", "row"), TAMPERED, ids=lambda value: value if isinstance(value, str) else value["name"])
def test_tampered_factor_list_fails_unwrap(name, row):
    case = BY_NAME[name]
    specs = [FactorSpec.from_json(item) for item in row["factors"]]
    if not specs:
        secrets = []
    elif name == "apple_masterkeyfile_v2":  # its own YubiKey challenge and secret
        secrets = [bytes.fromhex(case["yubikey"]["secret_hex"])]
    else:
        secrets = [_secret(source) for source in case["secret_sources"]]
    # The row's key is what an attacker derives from the edited list with the real secrets.
    key = composite_key.combine(bytes.fromhex(case["argon_out_hex"]), specs, secrets)
    assert bytes(key).hex() == row["key_hex"]
    if specs:
        assert composite_key.info(specs) in bytes.fromhex(row["aad_hex"])
        assert specs != _specs(case)
    nonce, sealed = _password_wrapper(name)
    with pytest.raises(InvalidTag):
        AESGCM(bytes.fromhex(row["key_hex"])).decrypt(nonce, sealed, bytes.fromhex(row["aad_hex"]))


def test_windows_v4_with_factors_removed_is_refused_by_the_v3_reader(tmp_path: Path):
    row = BY_NAME["windows_v4_header"]["tampered"][0]
    header = json.loads((VEC / row["file"]).read_bytes())
    assert header["version"] == 3 and "factors" not in header["wrappers"]["password"]
    target = tmp_path / "vault.json"
    target.write_bytes((VEC / row["file"]).read_bytes())
    with pytest.raises(vault.InvalidMasterPassword):
        vault.unlock_vault(target, BY_NAME["windows_v4_header"]["password"])
    assert target.read_bytes() == (VEC / row["file"]).read_bytes()


def test_new_challenge_is_32_random_bytes():
    first, second = composite_key.new_challenge(), composite_key.new_challenge()
    assert len(first) == 32 and first != second
    assert first[-1] not in composite_key.CHALLENGE_REDRAW_BYTES


@pytest.mark.parametrize("last", [0x00, 0x20])
def test_new_challenge_redraws_a_strippable_last_byte(last):
    draws = iter([b"\x11" * 31 + bytes([last]), b"\x22" * 31 + bytes([last]), b"\x33" * 32])
    with mock.patch.object(composite_key.os, "urandom", side_effect=lambda size: next(draws)) as urandom:
        assert composite_key.new_challenge() == b"\x33" * 32
    assert urandom.call_count == 3


def test_vector_challenges_would_not_be_redrawn():
    for case in CASES["cases"]:
        for item in case["factors"]:
            if item["kind"] == "yubikey-hmac":
                assert bytes.fromhex(item["challenge"])[-1] not in composite_key.CHALLENGE_REDRAW_BYTES
