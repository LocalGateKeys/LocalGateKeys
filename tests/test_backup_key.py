"""``localvault.backup_key``: the scheduled-backup key pair, record and reset authority.

Design: docs/design/backup-public-key-2026-10-31.md sections 3.2, 3.3, 3.4 (wrap only) and 3.6.  The committed
vectors (tests/vectors/backup/v3) are checked here against independent reference code (a pure-Python RFC 7748
ladder, HKDF from ``hmac``, Argon2id straight from ``argon2-cffi``, AES-GCM and HMAC from the libraries), so a
mistake in the module cannot hide inside its own vectors.  ``test_backup_v3_vectors.py`` regenerates them.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
from pathlib import Path

import pytest
from argon2.low_level import Type, hash_secret_raw
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from localvault import backup_key as bk
from localvault.backup import BACKUP_KDF, BackupError
from localvault.secret_text import SecretText

VEC = Path(__file__).resolve().parent / "vectors" / "backup" / "v3"
KEY = json.loads((VEC / "key.json").read_text(encoding="utf-8"))
WRAP = json.loads((VEC / "wrap.json").read_text(encoding="utf-8"))
RECORD = json.loads((VEC / "record.json").read_text(encoding="utf-8"))
AUTHORITY = json.loads((VEC / "authority.json").read_text(encoding="utf-8"))
CHEAP = {"time_cost": 1, "memory_cost_kib": 8192, "parallelism": 1}


# --------------------------------------------------------------------------- independent reference code
P = 2**255 - 19


def _ref_x25519(k: bytes, u: bytes) -> bytes:
    """RFC 7748 section 5 Montgomery ladder (clamps, masks the top bit of u)."""
    scalar = bytearray(k)
    scalar[0] &= 248
    scalar[31] &= 127
    scalar[31] |= 64
    n = int.from_bytes(scalar, "little")
    x1 = int.from_bytes(u, "little") & ((1 << 255) - 1)
    x2, z2, x3, z3, swap = 1, 0, x1, 1, 0
    for t in reversed(range(255)):
        bit = (n >> t) & 1
        swap ^= bit
        if swap:
            x2, x3, z2, z3 = x3, x2, z3, z2
        swap = bit
        a, b = (x2 + z2) % P, (x2 - z2) % P
        aa, bb = a * a % P, b * b % P
        e = (aa - bb) % P
        c, d = (x3 + z3) % P, (x3 - z3) % P
        da, cb = d * a % P, c * b % P
        x3, z3 = (da + cb) ** 2 % P, x1 * (da - cb) ** 2 % P
        x2, z2 = aa * bb % P, e * (aa + 121665 * e) % P
    if swap:
        x2, z2 = x3, z3
    return (x2 * pow(z2, P - 2, P) % P).to_bytes(32, "little")


BASE = (9).to_bytes(32, "little")


def _ref_hkdf(ikm: bytes, salt: bytes, info: bytes, length: int = 32) -> bytes:
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()
    out, block, counter = b"", b"", 1
    while len(out) < length:
        block = hmac.new(prk, block + info + bytes([counter]), hashlib.sha256).digest()
        out += block
        counter += 1
    return out[:length]


def _ref_canon(value) -> bytes:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode("utf-8")


def test_reference_ladder_matches_rfc7748_section_6_1() -> None:
    alice = bytes.fromhex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
    bob = bytes.fromhex("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb")
    alice_pk = "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"
    bob_pk = "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f"
    shared = "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742"
    assert _ref_x25519(alice, BASE).hex() == alice_pk == bk.x25519_public(alice).hex()
    assert _ref_x25519(bob, BASE).hex() == bob_pk == bk.x25519_public(bob).hex()
    assert _ref_x25519(alice, bytes.fromhex(bob_pk)).hex() == shared
    assert bytes(bk._shared_secret(bob, bytes.fromhex(alice_pk))).hex() == shared


def test_reference_hkdf_matches_rfc5869_case_1() -> None:
    okm = _ref_hkdf(b"\x0b" * 22, bytes(range(13)), bytes(range(0xF0, 0xFA)), 42)
    assert okm.hex() == ("3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
                         "34007208d5b887185865")


# --------------------------------------------------------------------------- 3.2 against the vectors
@pytest.mark.parametrize("case", KEY["cases"], ids=[c["name"] for c in KEY["cases"]])
def test_key_vectors_match_the_reference(case: dict) -> None:
    password = case["password"]
    assert password.encode("utf-8").hex() == case["password_utf8_hex"]
    assert len(password) == case["password_characters"]
    kdf = case["kdf"]
    seed = hash_secret_raw(secret=password.encode("utf-8"), salt=base64.b64decode(kdf["salt"]),
                           time_cost=kdf["time_cost"], memory_cost=kdf["memory_cost_kib"],
                           parallelism=kdf["parallelism"], hash_len=32, type=Type.ID, version=0x13)
    assert seed.hex() == case["seed"]
    sk_raw = _ref_hkdf(seed, bytes(32), b"localgatekeys|backup-key|x25519|v1")
    assert sk_raw.hex() == case["sk_raw"]
    sk = bytearray(sk_raw)
    sk[0] &= 0xF8
    sk[31] = (sk[31] & 0x7F) | 0x40
    assert sk.hex() == case["sk"]
    assert _ref_x25519(bytes(sk), BASE).hex() == case["pk"]
    assert base64.b64encode(bytes.fromhex(case["pk"])).decode() == case["pk_b64"]
    assert hashlib.sha256(b"localgatekeys|backup-key-id|v1|" + bytes.fromhex(case["pk"])).hexdigest()[:32] == case["key_id"]
    key = bk.derive_backup_key(password, kdf)
    assert (bytes(key.private_key).hex(), key.public_key.hex(), key.key_id) == (case["sk"], case["pk"], case["key_id"])
    assert key.kdf == kdf
    key.wipe()
    assert key.private_key == bytearray(32)


def test_key_vectors_cover_the_design_cases() -> None:
    by_name = {c["name"]: c for c in KEY["cases"]}
    assert by_name["ascii"]["kdf"]["memory_cost_kib"] == 262144 and by_name["ascii"]["kdf"]["time_cost"] == 3
    assert all(c["kdf"]["memory_cost_kib"] == 8192 for n, c in by_name.items() if n != "ascii")
    assert by_name["composed"]["password"] == "fixture café password 2026"
    assert by_name["decomposed"]["password"] == "fixture café password 2026"
    assert by_name["composed"]["key_id"] != by_name["decomposed"]["key_id"]   # no Unicode normalisation
    assert by_name["max_length"]["password_characters"] == 4096


def test_secret_text_password_gives_the_same_key() -> None:
    case = KEY["cases"][1]
    secret = SecretText.from_str(case["password"])
    key = bk.derive_backup_key(secret, case["kdf"])
    assert key.key_id == case["key_id"]


@pytest.mark.parametrize("row", KEY["rejected_passwords"] + KEY["rejected_kdf"],
                         ids=[r["name"] for r in KEY["rejected_passwords"] + KEY["rejected_kdf"]])
def test_rejected_key_inputs(row: dict) -> None:
    password = row.get("password", KEY["cases"][1]["password"])
    with pytest.raises(BackupError) as caught:
        bk.derive_backup_key(password, row["kdf"])
    assert str(caught.value) == row["error"]


def test_new_kdf_uses_backup_kdf_and_a_fresh_salt() -> None:
    a, b = bk.new_kdf(), bk.new_kdf()
    assert {k: a[k] for k in ("name", "time_cost", "memory_cost_kib", "parallelism")} == BACKUP_KDF
    assert set(a) == bk.KDF_FIELDS and len(base64.b64decode(a["salt"])) == 16 and a["salt"] != b["salt"]
    with pytest.raises(BackupError):
        bk.new_kdf(salt=bytes(15))
    with pytest.raises(BackupError):
        bk.new_kdf(parameters={"time_cost": 11})


# --------------------------------------------------------------------------- 3.4 against the vectors
def test_wrap_vector_matches_the_reference() -> None:
    w = WRAP
    sk, pk, esk, epk = (bytes.fromhex(w[k]) for k in ("sk", "pk", "esk", "epk"))
    clamped = bytearray(bytes.fromhex(w["esk_random"]))
    clamped[0] &= 0xF8
    clamped[31] = (clamped[31] & 0x7F) | 0x40
    assert bytes(clamped) == esk
    assert _ref_x25519(esk, BASE) == epk
    assert _ref_x25519(sk, BASE) == pk
    ss = _ref_x25519(esk, pk)
    assert ss == _ref_x25519(sk, epk) and ss.hex() == w["ss"]
    assert (epk + pk).hex() == w["kek_salt"]
    kek = _ref_hkdf(ss, epk + pk, b"localgatekeys|backup-wrap|v1")
    assert kek.hex() == w["kek"]
    aad = b"localgatekeys|backup-recipient|v1|" + _ref_canon({"header": w["core"], "recipient": w["recipient_body"]})
    assert aad.hex() == w["wrap_aad"] == bk.wrap_aad(w["core"], w["recipient_body"]).hex()
    wrapped = bytes.fromhex(w["wrapped"])
    assert len(wrapped) == 48 and base64.b64encode(wrapped).decode() == w["wrapped_b64"]
    assert AESGCM(kek).decrypt(bytes(12), wrapped, aad).hex() == w["dk"]
    assert AESGCM(kek).encrypt(bytes(12), bytes.fromhex(w["dk"]), aad) == wrapped
    assert w["recipient_body"]["ephemeral_public_key"] == base64.b64encode(epk).decode()
    key_case = next(c for c in KEY["cases"] if c["name"] == w["key_case"])
    assert (key_case["sk"], key_case["pk"], key_case["password"]) == (w["sk"], w["pk"], w["password"])


def test_module_reproduces_the_wrap() -> None:
    w = WRAP
    ephemeral = bk.new_ephemeral_key(bytes.fromhex(w["esk_random"]))
    assert (bytes(ephemeral.secret).hex(), ephemeral.public.hex()) == (w["esk"], w["epk"])
    aad = bytes.fromhex(w["wrap_aad"])
    assert bk.wrap_data_key(bytes.fromhex(w["dk"]), bytes.fromhex(w["pk"]), ephemeral, aad).hex() == w["wrapped"]
    assert bk.unwrap_data_key(bytes.fromhex(w["sk"]), ephemeral.public, bytes.fromhex(w["wrapped"]), aad).hex() == w["dk"]
    assert bk.unwrap_with_password(w["password"], kdf=w["recipient_body"]["kdf"],
                                   expected_key_id=w["recipient_body"]["key_id"], ephemeral_public=ephemeral.public,
                                   wrapped=bytes.fromhex(w["wrapped"]), aad=aad).hex() == w["dk"]


@pytest.mark.parametrize("row", WRAP["wrap_to_low_order_pk"], ids=lambda r: r["pk"][:8])
def test_wrap_refuses_low_order_public_keys(row: dict) -> None:
    assert _ref_x25519(bytes.fromhex(WRAP["esk"]), bytes.fromhex(row["pk"])) == bytes(32)
    with pytest.raises(BackupError) as caught:
        bk.wrap_data_key(bytes(32), bytes.fromhex(row["pk"]), bk.new_ephemeral_key(), b"aad")
    assert str(caught.value) == row["error"] == bk.INVALID_PUBLIC_KEY_MESSAGE


def test_every_unwrap_rejection_has_the_one_message() -> None:
    assert {r["error"] for r in WRAP["unwrap_rejected"]} == {"Wrong backup password or modified full backup"}
    assert len(WRAP["unwrap_rejected"]) == 9


def test_key_id_mismatch_makes_no_gcm_attempt(monkeypatch: pytest.MonkeyPatch) -> None:
    def fail(*_args, **_kwargs):
        raise AssertionError("unwrap attempted after a key id mismatch")

    monkeypatch.setattr(bk, "unwrap_data_key", fail)
    with pytest.raises(bk.WrongBackupPasswordError):
        bk.unwrap_with_password("second fixture backup password", kdf=WRAP["recipient_body"]["kdf"],
                                expected_key_id=WRAP["recipient_body"]["key_id"], ephemeral_public=bytes(32),
                                wrapped=bytes(48), aad=b"")


def test_random_round_trip_and_wipes() -> None:
    kdf = bk.new_kdf(parameters=CHEAP)
    key = bk.derive_backup_key("a round trip password", kdf)
    ephemeral = bk.new_ephemeral_key()
    dk = bytes(range(32))
    aad = bk.wrap_aad({"version": 3}, {"ephemeral_public_key": base64.b64encode(ephemeral.public).decode()})
    wrapped = bk.wrap_data_key(dk, key.public_key, ephemeral, aad)
    assert bytes(bk.unwrap_data_key(key.private_key, ephemeral.public, wrapped, aad)) == dk
    ephemeral.wipe()
    assert ephemeral.secret == bytearray(32)
    with pytest.raises(BackupError):
        bk.wrap_aad({"recipient": {}}, {})
    with pytest.raises(BackupError):
        bk.wrap_aad({}, {"wrapped_key": ""})
    with pytest.raises(BackupError):
        bk.wrap_data_key(bytes(31), key.public_key, bk.new_ephemeral_key(), aad)


# --------------------------------------------------------------------------- 3.6 against the vectors
def _ref_verify_wrapper(snapshot: dict, entropy: bytes) -> bool:
    key = _ref_hkdf(entropy, base64.b64decode(snapshot["salt"]), b"localgatekeys|recovery-key|v1")
    try:
        AESGCM(key).decrypt(base64.b64decode(snapshot["nonce"]), base64.b64decode(snapshot["ciphertext"]),
                            base64.b64decode(snapshot["aad"]))
    except Exception:  # noqa: BLE001
        return False
    return True


def test_windows_authority_vectors() -> None:
    w = AUTHORITY["windows"]
    from localvault.vault import entropy_from_phrase
    assert entropy_from_phrase(w["old_phrase"]).hex() == w["old_entropy"]
    assert entropy_from_phrase(w["new_phrase"]).hex() == w["new_entropy"]
    for check in w["checks"]:
        entropy = bytes.fromhex(w[check["phrase"].replace("phrase", "entropy")])
        snapshot = w[check["snapshot"]]
        assert snapshot["kind"] == "recovery-wrapper-v1"
        assert _ref_verify_wrapper(snapshot, entropy) is check["accepted"]
        assert bk.verify_authority(snapshot, entropy, AUTHORITY["record_key_id"]) is check["accepted"]
    assert base64.b64decode(w["old_snapshot"]["aad"]).startswith(b"localgatekeys|")


def test_mac_authority_vectors() -> None:
    m = AUTHORITY["mac"]
    from localvault.vault import entropy_from_phrase
    assert entropy_from_phrase(m["phrase"]).hex() == m["entropy"]
    key = _ref_hkdf(bytes.fromhex(m["entropy"]), bytes.fromhex(m["salt"]), b"localgatekeys|recovery-key|v1")
    assert key.hex() == m["phrase_key"]
    mac = hmac.new(key, b"localgatekeys|backup-reset-authority|v1|" + AUTHORITY["record_key_id"].encode(),
                   hashlib.sha256).digest()
    assert m["authority"] == {"kind": "recovery-key-mac-v1", "salt": base64.b64encode(bytes.fromhex(m["salt"])).decode(),
                              "mac": base64.b64encode(mac).decode()}
    for check in m["checks"]:
        entropy = bytes.fromhex(m["entropy"] if check["phrase"] == "phrase" else m["other_entropy"])
        assert bk.verify_authority(m["authority"], entropy, check["key_id"]) is check["accepted"]


@pytest.mark.parametrize("row", AUTHORITY["rejected"], ids=[r["name"] for r in AUTHORITY["rejected"]])
def test_rejected_authorities(row: dict) -> None:
    with pytest.raises(bk.DamagedAuthorityError) as caught:
        bk.validate_authority(row["authority"])
    assert str(caught.value) == row["error"]


def test_capture_wrapper_authority_edges() -> None:
    assert bk.capture_wrapper_authority({"version": 3, "wrappers": {}}) is None
    assert bk.capture_wrapper_authority({"version": 2, "wrappers": {"recovery": {}}}) is None
    with pytest.raises(bk.DamagedAuthorityError):
        bk.capture_wrapper_authority({"version": 3, "wrappers": {"recovery": {"kind": "bip39-english-24",
                                                                             "salt": "x"}}})


def test_capture_from_a_live_vault_matches_its_phrase(tmp_path: Path) -> None:
    from localvault.vault import _read_vault_header, create_vault, entropy_from_phrase
    path = tmp_path / "vault.json"
    session = create_vault(path, "a fixture master password", kdf_overrides=CHEAP)
    try:
        assert bk.capture_wrapper_authority(_read_vault_header(path)[0]) is None
        phrase = session.create_recovery_phrase("a fixture master password")
    finally:
        session.lock()
    snapshot = bk.capture_wrapper_authority(_read_vault_header(path)[0])
    assert bk.verify_authority(snapshot, entropy_from_phrase(phrase), "0" * 32) is True
    assert bk.verify_authority(snapshot, bytes(32), "0" * 32) is False


# --------------------------------------------------------------------------- 3.3 against the vectors
@pytest.mark.parametrize("name", sorted(RECORD["records"]))
def test_record_vectors(name: str) -> None:
    row = RECORD["records"][name]
    record = row["record"]
    assert _ref_canon(record).decode() == row["canonical"] == bk.encode_record(record).decode()
    assert bk.validate_record(record) == record
    assert row["inputs"]["now"] == record["set_at"]
    key = bk.derive_backup_key(row["inputs"]["password"], row["inputs"]["kdf"])
    assert key.key_id == record["key_id"] and base64.b64encode(key.public_key).decode() == record["public_key"]
    assert bk.record_public_key(record) == key.public_key
    assert (record["reset_at"] is not None) == (record["set_by"] == "reset")


def test_record_history_rules() -> None:
    records = {n: r["record"] for n, r in RECORD["records"].items()}
    assert records["set"]["history"] == [] and records["migrated"]["history"] == []
    assert records["changed"]["history"] == [{"key_id": records["set"]["key_id"], "set_at": records["set"]["set_at"],
                                              "set_by": "set", "replaced_at": records["changed"]["set_at"]}]
    assert records["reset"]["history"][1:] == records["changed"]["history"]
    assert records["reset"]["history"][0]["key_id"] == records["changed"]["key_id"]
    full = records["changed_history_full"]["history"]
    assert len(full) == 16 and full[1:] == RECORD["previous_history"][:15]
    assert records["reset"]["reset_authority"]["kind"] == "recovery-key-mac-v1"
    assert records["set"]["reset_authority"] == AUTHORITY["windows"]["old_snapshot"]


@pytest.mark.parametrize("row", RECORD["rejected"], ids=[r["name"] for r in RECORD["rejected"]])
def test_rejected_records(row: dict) -> None:
    with pytest.raises(bk.DamagedRecordError) as caught:
        bk.validate_record(row["record"])
    assert str(caught.value) == row["error"]


@pytest.mark.parametrize("row", RECORD["password_proofs"], ids=lambda r: f"{r['record']}-{r['matches']}")
def test_password_proofs(row: dict) -> None:
    assert bk.password_matches(RECORD["records"][row["record"]]["record"], row["password"]) is row["matches"]


def test_password_proof_of_a_short_password_is_false() -> None:
    assert bk.password_matches(RECORD["records"]["set"]["record"], "short") is False


def test_build_record_refusals() -> None:
    kdf = bk.new_kdf(parameters=CHEAP)
    key = bk.derive_backup_key("a record fixture password", kdf)
    previous = RECORD["records"]["set"]["record"]
    with pytest.raises(BackupError):
        bk.build_record(key, now=1, set_by="changed", reset_authority=None)
    with pytest.raises(BackupError):
        bk.build_record(key, now=1, set_by="set", reset_authority=None, previous=previous)
    with pytest.raises(BackupError):
        bk.build_record(key, now=1, set_by="removed", reset_authority=None)
    for now in (-1, 1.5, True, 2**53):
        with pytest.raises(BackupError):
            bk.build_record(key, now=now, set_by="set", reset_authority=None)
    with pytest.raises(bk.DamagedRecordError):
        bk.build_record(key, now=1, set_by="changed", reset_authority=None, previous=dict(previous, v=2))
    with pytest.raises(BackupError):
        bk.build_record(key, now=1, set_by="set", reset_authority={"kind": "other"})
    forged = bk.BackupKey(private_key=bytearray(key.private_key), public_key=bytes(32), key_id=key.key_id, kdf=kdf)
    with pytest.raises(BackupError):
        bk.build_record(forged, now=1, set_by="set", reset_authority=None)


def test_validate_record_returns_an_independent_copy() -> None:
    record = RECORD["records"]["changed"]["record"]
    copy = bk.validate_record(record)
    copy["history"][0]["set_by"] = "x"
    copy["kdf"]["time_cost"] = 9
    assert record["history"][0]["set_by"] == "set" and record["kdf"]["time_cost"] == 1


def test_module_reads_no_clock() -> None:
    source = Path(bk.__file__).read_text(encoding="utf-8")
    for needle in ("import time", "from time", "import datetime", "from datetime", "date.today", ".now("):
        assert needle not in source, needle


# --------------------------------------------------------------------------- owner decision Q2 (strict reset)
STRICT = AUTHORITY["strict_reset"]


@pytest.mark.parametrize("case", STRICT["cases"], ids=[c["name"] for c in STRICT["cases"]])
def test_strict_reset_cases(case: dict) -> None:
    record = STRICT["records"][case["record"]]
    entropy = bytes.fromhex(STRICT["entropies"][case["entropy"]])
    current = STRICT["currents"][case["current"]]
    assert bk.verify_reset_phrase(record, entropy, current) is case["accepted"]
    # The rule, spelled out with the low-level verifier.
    expected = (record["reset_authority"] is not None and current is not None
                and current["kind"] == record["reset_authority"]["kind"]
                and bk.verify_authority(record["reset_authority"], entropy, record["key_id"])
                and bk.verify_authority(current, entropy, record["key_id"]))
    assert expected is case["accepted"]


def test_strict_reset_covers_the_owner_rule() -> None:
    by_name = {c["name"]: c["accepted"] for c in STRICT["cases"]}
    assert by_name["windows, replaced phrase (bound, no longer current)"] is False
    assert by_name["mac, replaced phrase (bound, no longer current)"] is False
    assert by_name["windows, after re-bind: current phrase"] is True
    assert by_name["mac, after re-bind: current phrase"] is True


def test_rebind_changes_only_the_authority() -> None:
    for name, source in (("set_rebound", "set"), ("reset_rebound", "reset")):
        rebound, original = STRICT["records"][name], STRICT["records"][source]
        assert {k: v for k, v in rebound.items() if k != "reset_authority"} == {
            k: v for k, v in original.items() if k != "reset_authority"}
        assert rebound["reset_authority"] != original["reset_authority"]
        assert STRICT["rebound_canonical"][name] == _ref_canon(rebound).decode()
    row = RECORD["records"]["set"]
    again = bk.rebind_record(row["record"], row["inputs"]["password"], AUTHORITY["windows"]["new_snapshot"])
    assert again == STRICT["records"]["set_rebound"]
    assert bk.rebind_record(row["record"], row["inputs"]["password"], None)["reset_authority"] is None


def test_rebind_needs_the_current_backup_password() -> None:
    refusal = STRICT["rebind_with_wrong_password"]
    with pytest.raises(bk.NotCurrentPasswordError) as caught:
        bk.rebind_record(STRICT["records"][refusal["record"]], refusal["password"], AUTHORITY["windows"]["new_snapshot"])
    assert str(caught.value) == refusal["error"] == "That is not the current backup password."
