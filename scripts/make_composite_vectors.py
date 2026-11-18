"""Generate the deterministic composite-key test vectors in ``tests/vectors/composite_key``.

Everything here is test-only.  Passwords, salts, nonces, keys, key files and the YubiKey HMAC
secret are fixed; the cheapest Argon2id parameters every reader accepts keep the derivation fast.
The rules are spelled out here from ``docs/formats/COMPOSITE_KEY_V1.md`` (they are the contract
under test) and cross-checked against ``localvault.composite_key`` / ``localvault.keyfile`` /
``localvault.vault`` before anything is written:

* factor secret: ``keyfile`` = the KeePass key-file key; ``yubikey-hmac`` = SHA-256 of the 20-byte
  HMAC-SHA1 response to the stored 32-byte challenge, padded to 64 bytes as KeePassXC pads;
* ``check`` = hex of the first 8 bytes of HMAC-SHA256(secret, "localgatekeys|factor-check|v1");
* wrapping key = HKDF-SHA256(ikm = Argon2id output || secrets..., salt = "localgatekeys|composite|v1",
  info = canonical JSON of the factor list, length 32); no factors = the Argon2id output itself;
* the three formats that carry factors: Windows vault v4, Apple ``MasterKeyFile`` v2 and Android
  ``AppPasswordWrap`` v2 (built here byte for byte).

Usage::

    python scripts/make_composite_vectors.py [OUT_DIR]      # default: tests/vectors/composite_key

``tests/test_composite_key.py`` regenerates into a temporary directory and compares every file
byte for byte with the committed copies.
"""

# ruff: noqa: S101, S105, S324  (generator self-checks use assert; published test passwords; SHA-1 is HMAC-SHA1)

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import struct
import sys
from pathlib import Path
from typing import Any

from argon2.low_level import Type, hash_secret_raw
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_OUT = ROOT / "tests" / "vectors" / "composite_key"

COMPOSITE_SALT = b"localgatekeys|composite|v1"
CHECK_INFO = b"localgatekeys|factor-check|v1"

PASSWORD = "correct horse battery staple 42"
ARGON = {"time_cost": 1, "memory_cost_kib": 8192, "parallelism": 1, "hash_len": 32}


def fixed(label: str, size: int) -> bytes:
    """Deterministic test bytes: the first ``size`` bytes of SHA-256(label) (size <= 32)."""
    assert size <= 32
    return hashlib.sha256(label.encode("ascii")).digest()[:size]


ARGON_SALT = fixed("lgk-composite-v1-salt", 16)
DATA_KEY = fixed("lgk-composite-v1-data-key", 32)
WRAP_NONCE = fixed("lgk-composite-v1-wrap-nonce", 12)

YUBIKEY_HMAC_SECRET = b"vector-hmac-secret"
CHALLENGE = fixed("lgk-composite-v1-challenge", 32)
#: ``new_challenge`` redraws a challenge ending in one of these bytes (variable-mode stripping).
CHALLENGE_REDRAW_BYTES = (0x00, 0x20)
# A second padding vector whose last byte equals the pad value (0x20): the key strips it too.
# It documents the edge case only: new_challenge() never produces such a challenge.
CHALLENGE_TRAILING_PAD = fixed("lgk-composite-v1-challenge-b", 31) + b"\x20"

# Key-file fixtures: the key each one must yield is known here independently of the reader.
KEY_XML_V2 = fixed("lgk-composite-v1-keyfile-xml-v2", 32)
KEY_XML_V1 = fixed("lgk-composite-v1-keyfile-xml-v1", 32)
KEY_RAW32 = fixed("lgk-composite-v1-keyfile-raw32", 32)
KEY_HEX64 = fixed("lgk-composite-v1-keyfile-hex64", 32)
ARBITRARY = b"Any file works as a key file: its SHA-256 is the key.\n"

# Windows vault v4 (same fixed-field style as scripts/make_vault_vectors.py).
WIN_KDF = {"name": "argon2id", "time_cost": 1, "memory_cost_kib": 8192, "parallelism": 1, "hash_len": 32,
           "salt": base64.b64encode(fixed("lgk-composite-v1-win-salt", 16)).decode("ascii")}
WIN_DATA_KEY = fixed("lgk-composite-v1-win-data-key", 32)
WIN_WRAPPER_NONCE = fixed("lgk-composite-v1-win-wrapper-nonce", 12)
WIN_CATALOG_NONCE = fixed("lgk-composite-v1-win-catalog-nonce", 12)
WIN_RECOVERY_SALT = fixed("lgk-composite-v1-win-recovery-salt", 16)
WIN_RECOVERY_NONCE = fixed("lgk-composite-v1-win-recovery-nonce", 12)
WIN_RECOVERY_ENTROPY = fixed("lgk-composite-v1-win-recovery-entropy", 32)
WIN_VAULT_ID = hashlib.sha256(b"lgk-composite-v1-win-vault-id").hexdigest()[:32]
WIN_GENERATION = 3
CREATED_AT = 1790000000
AAD_PREFIX_V3 = b"localgatekeys|vault|v3|"
WRAPPER_AAD_PREFIX = b"localgatekeys|vault-key-wrapper|v3|"
RECOVERY_KEY_INFO = b"localgatekeys|recovery-key|v1"
RECOVERY_WRAPPER_KIND = "bip39-english-24"
# Every AAD of a v4 vault uses the v3 identity, literally (COMPOSITE_KEY_V1.md, "Windows vault v4").
V3_IDENTITY_VERSION = 3
V3_IDENTITY_FORMAT = "localgatekeys-vault-v3"

# Apple MasterKeyFile v2.
APPLE_SALT = fixed("lgk-composite-v1-apple-salt", 16)
APPLE_NONCE = fixed("lgk-composite-v1-apple-nonce", 12)
APPLE_LOCAL_KEY = fixed("lgk-composite-v1-apple-local-key", 32)
APPLE_KDF = {"time_cost": 1, "memory_kib": 8192, "parallelism": 1}
APPLE_YUBIKEY_SLOT = 1

# Android AppPasswordWrap v2.
ANDROID_MAGIC = b"LGKAPW"
ANDROID_LOCAL_KEY = fixed("lgk-composite-v1-android-local-key", 32)
ANDROID_PW_SALT = fixed("lgk-composite-v1-android-pw-salt", 16)
ANDROID_PW_NONCE = fixed("lgk-composite-v1-android-pw-nonce", 12)
ANDROID_REC_SALT = fixed("lgk-composite-v1-android-rec-salt", 16)
ANDROID_REC_NONCE = fixed("lgk-composite-v1-android-rec-nonce", 12)
ANDROID_REC_ENTROPY = fixed("lgk-composite-v1-android-rec-entropy", 32)
ANDROID_PARAMS = (8192, 1, 1)  # memory KiB, iterations, parallelism

KEYFILE_DIR = "keyfiles"


# --------------------------------------------------------------------------- primitives
def b64(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def canonical(value: Any) -> bytes:
    """Canonical JSON: sorted keys, no whitespace, ASCII escapes."""
    return json.dumps(value, separators=(",", ":"), sort_keys=True).encode("utf-8")


def dumps(value: Any) -> bytes:
    """Readable, stable JSON for the descriptive file (keys sorted, 2 spaces, LF, final newline)."""
    return (json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False) + "\n").encode("utf-8")


def argon2id(password: str, salt: bytes) -> bytes:
    return hash_secret_raw(password.encode("utf-8"), salt, time_cost=ARGON["time_cost"],
                           memory_cost=ARGON["memory_cost_kib"], parallelism=ARGON["parallelism"],
                           hash_len=ARGON["hash_len"], type=Type.ID, version=19)


def factor_check(secret: bytes) -> str:
    return hmac.new(secret, CHECK_INFO, hashlib.sha256).digest()[:8].hex()


def pad_challenge(challenge: bytes) -> bytes:
    """KeePassXC: append (64 - len) bytes of value (64 - len)."""
    assert len(challenge) == 32
    return challenge + bytes([64 - len(challenge)]) * (64 - len(challenge))


def yubikey_variable_message(padded: bytes) -> bytes:
    """What a YubiKey slot in variable-input mode HMACs: the 64 bytes minus the trailing run of the last byte."""
    end = len(padded)
    while end > 0 and padded[end - 1] == padded[-1]:
        end -= 1
    return padded[:end]


def yubikey_response(padded: bytes, hmac_secret: bytes = YUBIKEY_HMAC_SECRET) -> bytes:
    return hmac.new(hmac_secret, yubikey_variable_message(padded), hashlib.sha1).digest()


def yubikey_secret(response: bytes) -> bytes:
    assert len(response) == 20
    return hashlib.sha256(response).digest()


def keyfile_spec(secret: bytes) -> dict[str, Any]:
    return {"check": factor_check(secret), "kind": "keyfile"}


def yubikey_spec(secret: bytes, slot: int, challenge: bytes) -> dict[str, Any]:
    return {"challenge": challenge.hex(), "check": factor_check(secret), "kind": "yubikey-hmac", "slot": slot}


def combine(argon_out: bytes, specs: list[dict[str, Any]], secrets: list[bytes]) -> bytes:
    if not specs:
        return argon_out
    assert len(specs) == len(secrets) and all(len(s) == 32 for s in secrets)
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=COMPOSITE_SALT,
                info=canonical(specs)).derive(argon_out + b"".join(secrets))


# --------------------------------------------------------------------------- key files
def keepass_xml_v2(key: bytes) -> bytes:
    """KeePass/KeePassXC XML 2.0 layout: Hash = first 4 bytes of SHA-256, upper-case hex in 8-char groups."""
    hex_key = key.hex().upper()
    groups = [hex_key[i:i + 8] for i in range(0, len(hex_key), 8)]
    lines = [" ".join(groups[i:i + 4]) for i in range(0, len(groups), 4)]
    data = "".join(f"\n            {line}" for line in lines)
    return (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        "<KeyFile>\n"
        "    <Meta>\n"
        "        <Version>2.0</Version>\n"
        "    </Meta>\n"
        "    <Key>\n"
        f'        <Data Hash="{hashlib.sha256(key).digest()[:4].hex().upper()}">{data}\n'
        "        </Data>\n"
        "    </Key>\n"
        "</KeyFile>\n"
    ).encode()


def keepass_xml_v1(payload: bytes) -> bytes:
    return (
        '<?xml version="1.0" encoding="utf-8"?>\n'
        "<KeyFile>\n\t<Meta>\n\t\t<Version>1.00</Version>\n\t</Meta>\n"
        f"\t<Key>\n\t\t<Data>{b64(payload)}</Data>\n\t</Key>\n</KeyFile>\n"
    ).encode()


def keyfiles() -> list[tuple[str, str, bytes, bytes, str]]:
    """``(name, file name, file bytes, expected key, rule)`` for every accepted key file."""
    hex_upper = KEY_HEX64.hex().upper().encode("ascii")
    not_hex = b"g" * 64
    return [
        ("keyfile_xml_v2", "xml_v2.keyx", keepass_xml_v2(KEY_XML_V2), KEY_XML_V2, "xml-2.0"),
        ("keyfile_xml_v1", "xml_v1.key", keepass_xml_v1(KEY_XML_V1), KEY_XML_V1, "xml-1.0"),
        ("keyfile_raw32", "raw32.key", KEY_RAW32, KEY_RAW32, "raw-32"),
        ("keyfile_hex64", "hex64.key", hex_upper, KEY_HEX64, "hex-64"),
        ("keyfile_hex64_newline", "hex64_newline.key", hex_upper + b"\n",
         hashlib.sha256(hex_upper + b"\n").digest(), "sha256"),
        ("keyfile_64_not_hex", "not_hex64.key", not_hex, hashlib.sha256(not_hex).digest(), "sha256"),
        ("keyfile_arbitrary", "arbitrary.txt", ARBITRARY, hashlib.sha256(ARBITRARY).digest(), "sha256"),
    ]


def keyfile_rejects() -> list[tuple[str, str, bytes, str]]:
    """``(name, file name, file bytes, reason)``: each must be refused as a factor."""
    bad_hash = keepass_xml_v2(KEY_XML_V2).replace(
        hashlib.sha256(KEY_XML_V2).digest()[:4].hex().upper().encode("ascii"), b"00000000")
    assert bad_hash != keepass_xml_v2(KEY_XML_V2)
    doctype = (b'<?xml version="1.0" encoding="utf-8"?><!DOCTYPE KeyFile [<!ENTITY k "QUJD">]>'
               b"<KeyFile><Meta><Version>1.00</Version></Meta><Key><Data>&k;</Data></Key></KeyFile>\n")
    return [
        ("xml_v2_bad_hash", "reject_xml_v2_bad_hash.keyx", bad_hash, "XML 2.0 Hash does not match the data"),
        ("xml_v1_short", "reject_xml_v1_short.key", keepass_xml_v1(b"sixteen byte key"),
         "XML data is not 32 bytes (a factor key must be 32 bytes)"),
        ("xml_doctype", "reject_xml_doctype.key", doctype, "XML with a DOCTYPE is refused"),
        ("xml_no_data", "reject_xml_no_data.key",
         b"<KeyFile><Meta><Version>2.0</Version></Meta><Key></Key></KeyFile>\n", "XML without Key/Data"),
    ]


# --------------------------------------------------------------------------- tampering
TAMPERED_CHALLENGE = fixed("lgk-composite-v1-tampered-challenge", 32)


def tampered_rows(specs: list[dict[str, Any]], secrets: list[bytes], argon_out: bytes, aad_for: Any,
                  nonce: bytes, ciphertext: bytes) -> list[dict[str, Any]]:
    """Edits an attacker could make to the stored factor list; every one must fail the password unwrap.

    ``aad_for(list)`` is the format's password-wrapper AAD for that list; ``aad_for([])`` is the
    no-factor (v3 / v1) reading.  The attacker keeps the real secrets and recomputes info and AAD.
    """
    yubikey = next(index for index, spec in enumerate(specs) if spec["kind"] == "yubikey-hmac")

    def edited(**changes: Any) -> list[dict[str, Any]]:
        out = [dict(spec) for spec in specs]
        out[yubikey].update(changes)
        return out

    slot = specs[yubikey]["slot"]
    other_slot = 1 if slot == 2 else 2
    edits = [
        ("factors_removed", "factor list removed; key = plain Argon2id output, no-factor AAD", [], []),
        ("slot_changed", f"YubiKey slot {slot} -> {other_slot}; info and AAD recomputed",
         edited(slot=other_slot), secrets),
        ("challenge_changed", "YubiKey challenge replaced; info and AAD recomputed, same secrets",
         edited(challenge=TAMPERED_CHALLENGE.hex()), secrets),
    ]
    rows = []
    for name, description, factors, row_secrets in edits:
        key = combine(argon_out, factors, row_secrets)
        aad = aad_for(factors)
        try:
            AESGCM(key).decrypt(nonce, ciphertext, aad)
        except InvalidTag:
            pass
        else:
            raise AssertionError(f"tampered row {name} opened")
        rows.append({"name": name, "description": description, "factors": factors, "key_hex": key.hex(),
                     "aad_hex": aad.hex(), "expect": "unwrap-fails"})
    return rows


# --------------------------------------------------------------------------- formats
def windows_v4(specs: list[dict[str, Any]], secrets: list[bytes]) -> tuple[bytes, dict[str, Any], bytes]:
    """A full v4 ``vault.json`` and its descriptive record."""
    from localvault import vault  # noqa: PLC0415 - script cross-check only

    header: dict[str, Any] = {
        "version": 4,
        "format": "localgatekeys-vault-v4",
        "catalog": "localgatekeys-catalog",
        "catalog_version": 2,
        "vault_id": WIN_VAULT_ID,
        "generation": WIN_GENERATION,
        "key_generation": 1,
        "kdf": WIN_KDF,
    }
    identity = {"version": V3_IDENTITY_VERSION, "format": V3_IDENTITY_FORMAT, "catalog": header["catalog"],
                "catalog_version": header["catalog_version"], "vault_id": WIN_VAULT_ID,
                "key_generation": header["key_generation"]}
    def password_aad(factors: list[dict[str, Any]]) -> bytes:
        metadata: dict[str, Any] = {"kdf": WIN_KDF, "factors": factors} if factors else {"kdf": WIN_KDF}
        return WRAPPER_AAD_PREFIX + canonical(dict(identity, wrapper="password", metadata=metadata))

    wrapper_aad = password_aad(specs)
    recovery_metadata = {"kind": RECOVERY_WRAPPER_KIND, "salt": b64(WIN_RECOVERY_SALT)}
    recovery_aad = WRAPPER_AAD_PREFIX + canonical(dict(identity, wrapper="recovery", metadata=recovery_metadata))
    catalog_aad = AAD_PREFIX_V3 + canonical(dict(identity, generation=WIN_GENERATION,
                                                 cipher={"name": "aes-256-gcm"}))
    argon_out = hash_secret_raw(PASSWORD.encode("utf-8"), base64.b64decode(WIN_KDF["salt"]), time_cost=1,
                                memory_cost=8192, parallelism=1, hash_len=32, type=Type.ID, version=19)
    assert bytes(vault._derive_key(PASSWORD, WIN_KDF)) == argon_out
    kek = combine(argon_out, specs, secrets)
    recovery_key = HKDF(algorithm=hashes.SHA256(), length=32, salt=WIN_RECOVERY_SALT,
                        info=RECOVERY_KEY_INFO).derive(WIN_RECOVERY_ENTROPY)
    assert bytes(vault._recovery_key(WIN_RECOVERY_ENTROPY, WIN_RECOVERY_SALT)) == recovery_key
    payload = windows_payload()
    header["wrappers"] = {
        "password": {"nonce": b64(WIN_WRAPPER_NONCE), "factors": specs,
                     "ciphertext": b64(AESGCM(kek).encrypt(WIN_WRAPPER_NONCE, WIN_DATA_KEY, wrapper_aad))},
        "recovery": {**recovery_metadata, "nonce": b64(WIN_RECOVERY_NONCE),
                     "ciphertext": b64(AESGCM(recovery_key).encrypt(WIN_RECOVERY_NONCE, WIN_DATA_KEY, recovery_aad))},
    }
    header["cipher"] = {"name": "aes-256-gcm", "nonce": b64(WIN_CATALOG_NONCE),
                        "ciphertext": b64(AESGCM(WIN_DATA_KEY).encrypt(WIN_CATALOG_NONCE, canonical(payload),
                                                                       catalog_aad))}
    # The constant v3 identity is what today's reader computes for a v3 header with the same fields.
    v3_twin = dict(header, version=3, format=V3_IDENTITY_FORMAT)
    assert vault._aad(v3_twin) == catalog_aad
    assert vault._wrapper_aad(v3_twin, "recovery", recovery_metadata) == recovery_aad
    assert vault._wrapper_aad(v3_twin, "password", {"kdf": WIN_KDF}) == password_aad([])
    tampered = tampered_rows(specs, secrets, argon_out, password_aad, WIN_WRAPPER_NONCE,
                             base64.b64decode(header["wrappers"]["password"]["ciphertext"]))
    # The same edit as a file: factors dropped and written back as a v3 vault.
    no_factors = json.loads(json.dumps(v3_twin))
    del no_factors["wrappers"]["password"]["factors"]
    tampered[0]["file"] = "windows_v4_tampered_no_factors.json"
    record = {
        "file": "windows_v4_vault.json",
        "password": PASSWORD,
        "argon_out_hex": argon_out.hex(),
        "kek_hex": kek.hex(),
        "data_key_hex": WIN_DATA_KEY.hex(),
        "wrapper_aad_b64": b64(wrapper_aad),
        "recovery_aad_b64": b64(recovery_aad),
        "catalog_aad_b64": b64(catalog_aad),
        "recovery_entropy_hex": WIN_RECOVERY_ENTROPY.hex(),
        "recovery_phrase": vault.phrase_from_entropy(WIN_RECOVERY_ENTROPY),
        "payload": payload,
        "tampered": tampered,
    }
    return canonical(header), record, canonical(no_factors)


def windows_payload() -> dict[str, Any]:
    return {
        "version": 2, "catalog": "localgatekeys-catalog", "created_at": CREATED_AT, "updated_at": CREATED_AT,
        "generation": WIN_GENERATION, "entries": [], "items": [], "collections": [], "templates": [],
        "events": [], "attachments": [], "reminders": [], "history": [], "relationships": [],
        "smart_views": [], "ocr_derivatives": [], "sync_protocol_state": {"next_counter": 1, "item_revisions": {}},
        "sync_receipts": [],
    }


def apple_v2(specs: list[dict[str, Any]], secrets: list[bytes]) -> tuple[bytes, dict[str, Any]]:
    salt_text = b64(APPLE_SALT)
    params = (f"t={APPLE_KDF['time_cost']}|m={APPLE_KDF['memory_kib']}|p={APPLE_KDF['parallelism']}"
              f"|salt={salt_text}")

    def aad_for(factors: list[dict[str, Any]]) -> bytes:
        if not factors:  # the v1 reading
            return f"localgatekeys|mac-master|v1|{params}".encode("ascii")
        return f"localgatekeys|mac-master|v2|{params}|factors=".encode("ascii") + canonical(factors)

    aad = aad_for(specs)
    argon_out = hash_secret_raw(PASSWORD.encode("utf-8"), APPLE_SALT, time_cost=APPLE_KDF["time_cost"],
                                memory_cost=APPLE_KDF["memory_kib"], parallelism=APPLE_KDF["parallelism"],
                                hash_len=32, type=Type.ID, version=19)
    key = combine(argon_out, specs, secrets)
    document = {
        "version": 2,
        "kdf": APPLE_KDF,
        "salt": salt_text,
        "nonce": b64(APPLE_NONCE),
        "sealed_key": b64(AESGCM(key).encrypt(APPLE_NONCE, APPLE_LOCAL_KEY, aad)),
        "factors": specs,
    }
    record = {"file": "apple_masterkeyfile_v2.json", "password": PASSWORD, "argon_out_hex": argon_out.hex(),
              "key_hex": key.hex(), "aad_hex": aad.hex(), "local_key_hex": APPLE_LOCAL_KEY.hex(),
              "tampered": tampered_rows(specs, secrets, argon_out, aad_for, APPLE_NONCE,
                                        base64.b64decode(document["sealed_key"]))}
    return canonical(document), record


def android_header_v1(memory_kib: int, iterations: int, parallelism: int) -> bytes:
    return ANDROID_MAGIC + bytes([1]) + struct.pack(">I", memory_kib) + bytes([iterations, parallelism])


def android_v2(specs: list[dict[str, Any]], secrets: list[bytes]) -> tuple[bytes, dict[str, Any]]:
    from localvault import vault  # noqa: PLC0415 - script cross-check only

    memory_kib, iterations, parallelism = ANDROID_PARAMS
    factors = canonical(specs)
    assert 1 <= len(factors) <= 1024
    header = (ANDROID_MAGIC + bytes([2]) + struct.pack(">I", memory_kib) + bytes([iterations, parallelism])
              + struct.pack(">H", len(factors)) + factors)
    password_aad = header + b"|password"

    def aad_for(factors_list: list[dict[str, Any]]) -> bytes:
        if not factors_list:  # the v1 reading
            return android_header_v1(memory_kib, iterations, parallelism) + b"|password"
        body = canonical(factors_list)
        return (ANDROID_MAGIC + bytes([2]) + struct.pack(">I", memory_kib) + bytes([iterations, parallelism])
                + struct.pack(">H", len(body)) + body + b"|password")

    assert aad_for(specs) == password_aad
    recovery_aad = android_header_v1(memory_kib, iterations, parallelism) + b"|recovery"
    argon_out = hash_secret_raw(PASSWORD.encode("utf-8"), ANDROID_PW_SALT, time_cost=iterations,
                                memory_cost=memory_kib, parallelism=parallelism, hash_len=32, type=Type.ID,
                                version=19)
    key = combine(argon_out, specs, secrets)
    recovery_key = HKDF(algorithm=hashes.SHA256(), length=32, salt=ANDROID_REC_SALT,
                        info=RECOVERY_KEY_INFO).derive(ANDROID_REC_ENTROPY)
    pw_sealed = AESGCM(key).encrypt(ANDROID_PW_NONCE, ANDROID_LOCAL_KEY, password_aad)
    record_bytes = (header + ANDROID_PW_SALT + ANDROID_PW_NONCE + pw_sealed
                    + ANDROID_REC_SALT + ANDROID_REC_NONCE
                    + AESGCM(recovery_key).encrypt(ANDROID_REC_NONCE, ANDROID_LOCAL_KEY, recovery_aad))
    assert len(record_bytes) == 167 + len(factors)
    record = {"file": "android_apppassword_v2.bin", "size": len(record_bytes), "hex": record_bytes.hex(),
              "password": PASSWORD, "argon_out_hex": argon_out.hex(), "key_hex": key.hex(),
              "password_aad_hex": password_aad.hex(), "recovery_aad_hex": recovery_aad.hex(),
              "local_key_hex": ANDROID_LOCAL_KEY.hex(), "recovery_entropy_hex": ANDROID_REC_ENTROPY.hex(),
              "recovery_phrase": vault.phrase_from_entropy(ANDROID_REC_ENTROPY),
              "tampered": tampered_rows(specs, secrets, argon_out, aad_for, ANDROID_PW_NONCE, pw_sealed)}
    return record_bytes, record


# --------------------------------------------------------------------------- build
def generic_case(name: str, argon_out: bytes, specs: list[dict[str, Any]], secrets: list[bytes]) -> dict[str, Any]:
    key = combine(argon_out, specs, secrets)
    return {
        "name": name,
        "factors": specs,
        "secrets_hex": [secret.hex() for secret in secrets],
        "info": canonical(specs).decode("ascii") if specs else None,
        "combine_hex": key.hex(),
        "wrap": {"nonce_hex": WRAP_NONCE.hex(), "aad_hex": "",
                 "ciphertext_hex": AESGCM(key).encrypt(WRAP_NONCE, DATA_KEY, b"").hex()},
    }


def build() -> dict[str, bytes]:
    files: dict[str, bytes] = {}
    argon_out = argon2id(PASSWORD, ARGON_SALT)

    accepted = keyfiles()
    keys: dict[str, bytes] = {}
    keyfile_rows = []
    for name, file_name, data, key, rule in accepted:
        files[f"{KEYFILE_DIR}/{file_name}"] = data
        keys[name] = key
        keyfile_rows.append({"name": name, "file": f"{KEYFILE_DIR}/{file_name}", "rule": rule,
                             "key_hex": key.hex(), "check": factor_check(key)})
    reject_rows = []
    for name, file_name, data, reason in keyfile_rejects():
        files[f"{KEYFILE_DIR}/{file_name}"] = data
        reject_rows.append({"name": name, "file": f"{KEYFILE_DIR}/{file_name}", "reason": reason})

    padded = pad_challenge(CHALLENGE)
    assert CHALLENGE[-1] not in CHALLENGE_REDRAW_BYTES, "new_challenge() would redraw this challenge"
    response = yubikey_response(padded)
    yk_secret = yubikey_secret(response)
    yk_spec = yubikey_spec(yk_secret, 2, CHALLENGE)

    cases = [generic_case("no_factors", argon_out, [], [])]
    for name in ("keyfile_xml_v2", "keyfile_xml_v1", "keyfile_raw32", "keyfile_hex64", "keyfile_arbitrary"):
        cases.append(generic_case(name, argon_out, [keyfile_spec(keys[name])], [keys[name]]))
    cases.append(generic_case("yubikey_only", argon_out, [yk_spec], [yk_secret]))
    cases.append(generic_case("keyfile_and_yubikey", argon_out,
                              [keyfile_spec(keys["keyfile_xml_v2"]), yk_spec],
                              [keys["keyfile_xml_v2"], yk_secret]))

    win_specs = [keyfile_spec(keys["keyfile_xml_v2"]), yk_spec]
    win_file, win_record, win_tampered = windows_v4(win_specs, [keys["keyfile_xml_v2"], yk_secret])
    files[win_record["file"]] = win_file
    files[win_record["tampered"][0]["file"]] = win_tampered
    cases.append({"name": "windows_v4_header", "factors": win_specs,
                  "secret_sources": ["keyfile_xml_v2", "yubikey"], **win_record})

    apple_challenge = fixed("lgk-composite-v1-apple-challenge", 32)
    apple_padded = pad_challenge(apple_challenge)
    assert apple_challenge[-1] not in CHALLENGE_REDRAW_BYTES
    apple_response = yubikey_response(apple_padded)
    apple_secret = yubikey_secret(apple_response)
    apple_specs = [yubikey_spec(apple_secret, APPLE_YUBIKEY_SLOT, apple_challenge)]
    apple_file, apple_record = apple_v2(apple_specs, [apple_secret])
    files[apple_record["file"]] = apple_file
    cases.append({"name": "apple_masterkeyfile_v2", "factors": apple_specs,
                  "secret_sources": ["yubikey"],
                  "yubikey": {"padded_challenge_hex": apple_padded.hex(), "response_hex": apple_response.hex(),
                              "secret_hex": apple_secret.hex()},
                  **apple_record})

    android_specs = [keyfile_spec(keys["keyfile_xml_v1"]), yk_spec]
    android_file, android_record = android_v2(android_specs, [keys["keyfile_xml_v1"], yk_secret])
    files[android_record["file"]] = android_file
    cases.append({"name": "android_apppassword_v2", "factors": android_specs,
                  "secret_sources": ["keyfile_xml_v1", "yubikey"], **android_record})

    trailing = pad_challenge(CHALLENGE_TRAILING_PAD)
    files["cases.json"] = dumps({
        "format": "localgatekeys-composite-key-vectors",
        "version": 1,
        "spec": "docs/formats/COMPOSITE_KEY_V1.md",
        "composite_salt": COMPOSITE_SALT.decode("ascii"),
        "check_info": CHECK_INFO.decode("ascii"),
        "argon": {"password": PASSWORD, "salt_hex": ARGON_SALT.hex(), **ARGON, "output_hex": argon_out.hex()},
        "data_key_hex": DATA_KEY.hex(),
        "yubikey": {
            "hmac_secret": YUBIKEY_HMAC_SECRET.decode("ascii"),
            "slot": 2,
            "challenge_hex": CHALLENGE.hex(),
            "padded_challenge_hex": padded.hex(),
            "hmac_message_hex": yubikey_variable_message(padded).hex(),
            "response_hex": response.hex(),
            "secret_hex": yk_secret.hex(),
            "check": yk_spec["check"],
        },
        "pad_challenge": [
            {"challenge_hex": CHALLENGE.hex(), "padded_hex": padded.hex(),
             "hmac_message_hex": yubikey_variable_message(padded).hex()},
            {"challenge_hex": CHALLENGE_TRAILING_PAD.hex(), "padded_hex": trailing.hex(),
             "hmac_message_hex": yubikey_variable_message(trailing).hex()},
        ],
        "keyfiles": keyfile_rows,
        "keyfile_rejects": reject_rows,
        "cases": cases,
    })
    cross_check(files, argon_out, keys)
    return files


def cross_check(files: dict[str, bytes], argon_out: bytes, keys: dict[str, bytes]) -> None:
    """The reader must agree with every value spelled out above before anything is written."""
    from localvault import composite_key, keyfile  # noqa: PLC0415 - script cross-check only

    for name, _file_name, data, key, _rule in keyfiles():
        assert keyfile.key_from_bytes(data) == key, name
    for name, _file, data, _reason in keyfile_rejects():
        try:
            keyfile.key_from_bytes(data)
        except keyfile.KeyFileError:
            continue
        raise AssertionError(f"{name} must be refused")
    assert composite_key.pad_challenge(CHALLENGE) == pad_challenge(CHALLENGE)
    assert composite_key.CHALLENGE_REDRAW_BYTES == CHALLENGE_REDRAW_BYTES
    vectors = json.loads(files["cases.json"])
    for case in vectors["cases"]:
        specs = [composite_key.FactorSpec.from_json(item) for item in case["factors"]]
        assert [spec.to_json() for spec in specs] == case["factors"], case["name"]
        if "combine_hex" in case:
            secrets = [bytes.fromhex(value) for value in case["secrets_hex"]]
            assert bytes(composite_key.combine(argon_out, specs, secrets)).hex() == case["combine_hex"]
            for spec, secret in zip(specs, secrets, strict=True):
                assert composite_key.factor_check(secret) == spec.check
    assert composite_key.factor_check(keys["keyfile_xml_v2"]) == factor_check(keys["keyfile_xml_v2"])
    assert keyfile.keepass_xml_v2(KEY_XML_V2) == keepass_xml_v2(KEY_XML_V2)


def write(out: Path) -> int:
    files = build()
    for name, data in files.items():
        target = out / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
    return len(files)


def main(argv: list[str]) -> int:
    out = Path(argv[1]) if len(argv) > 1 else DEFAULT_OUT
    print(f"wrote {write(out)} files to {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
