"""SSH key parsing and signing core (vectors in tests/vectors/ssh are test-only, published)."""
from __future__ import annotations

import base64
import json
import struct
from pathlib import Path

import pytest
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

from localvault import ssh_keys
from localvault.item_schema import validate_ssh_key_fields
from localvault.ssh_keys import SshKeyError, generate_ed25519, load_private_key

VECTORS = Path(__file__).parent / "vectors" / "ssh"
EXPECTED = json.loads((VECTORS / "expected.json").read_text(encoding="utf-8"))
PASS = EXPECTED["passphrase"]
DATA = base64.b64decode(EXPECTED["sign_data_b64"])
NAMES = sorted(EXPECTED["keys"])


def _key(name: str, encrypted: bool = False):
    text = (VECTORS / f"{name}{'_enc' if encrypted else ''}.key").read_text(encoding="ascii")
    return load_private_key(text, PASS if encrypted else None)


def _split(blob: bytes) -> list[bytes]:
    parts, pos = [], 0
    while pos < len(blob):
        (n,) = struct.unpack_from(">I", blob, pos)
        parts.append(blob[pos + 4:pos + 4 + n])
        pos += 4 + n
    return parts


def _public(key):
    """Public key object rebuilt from the key's own SSH public blob."""
    fields = _split(key.public_blob)
    if key.key_type == "ssh-ed25519":
        return ed25519.Ed25519PublicKey.from_public_bytes(fields[1])
    if key.key_type == "ssh-rsa":
        return rsa.RSAPublicNumbers(int.from_bytes(fields[1], "big"), int.from_bytes(fields[2], "big")).public_key()
    curve = ec.SECP256R1() if key.key_type.endswith("p256") else ec.SECP384R1()
    return ec.EllipticCurvePublicKey.from_encoded_point(curve, fields[2])


@pytest.mark.parametrize("name", NAMES)
@pytest.mark.parametrize("encrypted", [False, True])
def test_load_each_vector_key(name, encrypted):
    key = _key(name, encrypted)
    want = EXPECTED["keys"][name]
    assert key.key_type == want["key_type"]
    assert key.public_line("test-only " + name) == want["public_line"]
    pub_file = (VECTORS / f"{name}.pub").read_text(encoding="ascii").strip()
    assert key.public_line("test-only " + name) == pub_file


@pytest.mark.parametrize("name", NAMES)
def test_fingerprint_matches_ssh_keygen_format(name):
    fp = _key(name).fingerprint()
    assert fp == EXPECTED["keys"][name]["fingerprint"]  # values also confirmed with ssh-keygen -lf
    assert fp.startswith("SHA256:") and "=" not in fp


@pytest.mark.parametrize("name", NAMES)
def test_encrypted_needs_passphrase(name):
    text = (VECTORS / f"{name}_enc.key").read_text(encoding="ascii")
    for missing in (None, ""):
        with pytest.raises(SshKeyError) as exc:
            load_private_key(text, missing)
        assert exc.value.code == "needs_passphrase"


def test_bad_passphrase():
    text = (VECTORS / "ed25519_enc.key").read_text(encoding="ascii")
    with pytest.raises(SshKeyError) as exc:
        load_private_key(text, "wrong")
    assert exc.value.code == "bad_passphrase"


def test_putty_unsupported():
    with pytest.raises(SshKeyError) as exc:
        load_private_key((VECTORS / "putty.ppk").read_text(encoding="ascii"), None)
    assert exc.value.code == "unsupported_format"


def test_sk_key_unsupported():
    with pytest.raises(SshKeyError) as exc:
        load_private_key((VECTORS / "sk_ed25519.key").read_text(encoding="ascii"), None)
    assert exc.value.code == "unsupported_format"


def test_garbage_unsupported():
    junk = "-----BEGIN OPENSSH PRIVATE KEY-----\n!!!\n-----END OPENSSH PRIVATE KEY-----"
    for text in ("", "hello", junk):
        with pytest.raises(SshKeyError) as exc:
            load_private_key(text, None)
        assert exc.value.code == "unsupported_format"


def test_ed25519_signature_bytes_match_vector():
    sig = _key("ed25519").sign(DATA, 0)
    assert sig == base64.b64decode(EXPECTED["keys"]["ed25519"]["signature_blob_b64"])
    alg, raw = _split(sig)
    assert alg == b"ssh-ed25519" and len(raw) == 64
    _public(_key("ed25519")).verify(raw, DATA)


@pytest.mark.parametrize("name,hash_cls", [("ecdsa256", hashes.SHA256), ("ecdsa384", hashes.SHA384)])
def test_ecdsa_signature_verifies(name, hash_cls):
    key = _key(name)
    alg, inner = _split(key.sign(DATA, 0))
    assert alg == key.key_type.encode()
    r_bytes, s_bytes = _split(inner)
    for part in (r_bytes, s_bytes):
        assert part[0] < 0x80  # mpint is non-negative: a set high bit needs a 0x00 prefix
    r, s = int.from_bytes(r_bytes, "big"), int.from_bytes(s_bytes, "big")
    _public(key).verify(encode_dss_signature(r, s), DATA, ec.ECDSA(hash_cls()))
    with pytest.raises(InvalidSignature):
        _public(key).verify(encode_dss_signature(r, s), DATA + b"x", ec.ECDSA(hash_cls()))


@pytest.mark.parametrize("flags,alg,hash_cls", [
    (2, b"rsa-sha2-256", hashes.SHA256),
    (4, b"rsa-sha2-512", hashes.SHA512),
    (6, b"rsa-sha2-512", hashes.SHA512),
])
def test_rsa_sha256_and_sha512_verify(flags, alg, hash_cls):
    key = _key("rsa3072")
    got_alg, sig = _split(key.sign(DATA, flags))
    assert got_alg == alg
    _public(key).verify(sig, DATA, padding.PKCS1v15(), hash_cls())


def test_rsa_flags_zero_refused():
    with pytest.raises(SshKeyError) as exc:
        _key("rsa3072").sign(DATA, 0)
    assert exc.value.code == "sha1_refused"


def test_generate_ed25519_roundtrip():
    pem, line = generate_ed25519("me@host")
    assert pem.startswith("-----BEGIN OPENSSH PRIVATE KEY-----")
    key = load_private_key(pem, None)
    assert key.public_line("me@host") == line
    assert line.startswith("ssh-ed25519 ") and line.endswith(" me@host")
    _public(key).verify(_split(key.sign(DATA, 0))[1], DATA)
    assert generate_ed25519("x")[0] != pem


def test_pem_formats_load():
    private = rsa.generate_private_key(65537, 2048)
    for fmt in (serialization.PrivateFormat.TraditionalOpenSSL, serialization.PrivateFormat.PKCS8):
        pem = private.private_bytes(serialization.Encoding.PEM, fmt, serialization.NoEncryption()).decode()
        assert load_private_key(pem, None).key_type == "ssh-rsa"
    enc = private.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                serialization.BestAvailableEncryption(b"pw")).decode()
    with pytest.raises(SshKeyError) as exc:
        load_private_key(enc, None)
    assert exc.value.code == "needs_passphrase"
    assert load_private_key(enc, "pw").key_type == "ssh-rsa"


def test_mpint_encoding():
    assert ssh_keys.ssh_mpint(0) == b"\x00\x00\x00\x00"
    assert ssh_keys.ssh_mpint(0x80) == b"\x00\x00\x00\x02\x00\x80"
    assert ssh_keys.ssh_mpint(0x7F) == b"\x00\x00\x00\x01\x7f"


def test_schema_derives_missing_public_key():
    key_text = (VECTORS / "ed25519.key").read_text(encoding="ascii")
    out = validate_ssh_key_fields({"private_key": key_text})
    assert out["public_key"].startswith("ssh-ed25519 ")
    assert out["fingerprint"] == EXPECTED["keys"]["ed25519"]["fingerprint"]
    # An existing public key is never replaced; unparsable or locked keys stay blank.
    kept = validate_ssh_key_fields({"private_key": key_text, "public_key": "ssh-ed25519 AAAA mine"})
    assert kept["public_key"] == "ssh-ed25519 AAAA mine"
    enc = (VECTORS / "ed25519_enc.key").read_text(encoding="ascii")
    assert validate_ssh_key_fields({"private_key": enc})["public_key"] == ""
    assert validate_ssh_key_fields({"private_key": enc, "passphrase": PASS})["public_key"].startswith("ssh-ed25519 ")
    assert validate_ssh_key_fields({"private_key": "junk"})["public_key"] == ""


def test_passphrase_ignored_for_unencrypted_keys():
    text = (VECTORS / "ed25519.key").read_text(encoding="ascii")
    assert load_private_key(text, "unused").fingerprint() == EXPECTED["keys"]["ed25519"]["fingerprint"]
    pem = rsa.generate_private_key(65537, 2048).private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    ).decode()
    assert load_private_key(pem, "unused").key_type == "ssh-rsa"


def test_bcrypt_pbkdf_vectors_match_bcrypt_kdf():
    """The Mac's bcrypt_pbkdf (encrypted OpenSSH keys) is checked against these; they must stay bcrypt.kdf output."""
    bcrypt = pytest.importorskip("bcrypt")
    cases = json.loads((VECTORS / "bcrypt_pbkdf.json").read_text(encoding="utf-8"))["cases"]
    assert any(c["rounds"] == 16 and c["length"] == 48 for c in cases)  # OpenSSH's default: AES-256 key + IV
    for case in cases:
        key = bcrypt.kdf(case["password"].encode("utf-8"), bytes.fromhex(case["salt_hex"]), case["length"],
                         case["rounds"], ignore_few_rounds=True)
        assert key.hex() == case["key_hex"], case["name"]
