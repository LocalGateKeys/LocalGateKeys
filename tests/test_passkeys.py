"""WebAuthn software authenticator core: rpId rules, encodings and a relying-party round trip."""
from __future__ import annotations

import hashlib
import json
import struct

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from localvault.passkeys import (
    AAGUID,
    PasskeyError,
    authenticator_data,
    b64u_decode,
    b64u_encode,
    cbor_encode,
    client_data_json,
    create_credential,
    get_assertion,
    parse_create_options,
    parse_get_options,
    usable_record,
    validate_rp_id,
)

ORIGIN = "https://login.example.com"


def _b64(data: bytes) -> str:
    return b64u_encode(data)


def _create_raw(**overrides):
    raw = {
        "rp": {"id": "example.com", "name": "Example"},
        "user": {"id": _b64(b"user-0001"), "name": "ada@example.com", "displayName": "Ada"},
        "challenge": _b64(b"c" * 32),
        "pubKeyCredParams": [{"type": "public-key", "alg": -8}, {"type": "public-key", "alg": -7}],
        "authenticatorSelection": {"userVerification": "preferred"},
        "extensions": {"credProps": True},
    }
    raw.update(overrides)
    return raw


def _cbor_decode(data: bytes, offset: int = 0):
    """Just enough CBOR to read what the authenticator emits."""
    initial = data[offset]
    major, info = initial >> 5, initial & 0x1F
    offset += 1
    if info < 24:
        value = info
    elif info == 24:
        value = data[offset]; offset += 1
    elif info == 25:
        value = struct.unpack(">H", data[offset:offset + 2])[0]; offset += 2
    elif info == 26:
        value = struct.unpack(">I", data[offset:offset + 4])[0]; offset += 4
    else:
        raise AssertionError("unexpected CBOR length")
    if major == 0:
        return value, offset
    if major == 1:
        return -1 - value, offset
    if major == 2:
        return data[offset:offset + value], offset + value
    if major == 3:
        return data[offset:offset + value].decode("utf-8"), offset + value
    if major == 4:
        items = []
        for _ in range(value):
            item, offset = _cbor_decode(data, offset)
            items.append(item)
        return items, offset
    if major == 5:
        result = {}
        for _ in range(value):
            key, offset = _cbor_decode(data, offset)
            result[key], offset = _cbor_decode(data, offset)
        return result, offset
    if major == 7 and info in (20, 21):
        return info == 21, offset
    raise AssertionError("unexpected CBOR major type")


@pytest.mark.parametrize("origin,rp,expected", [
    ("https://login.example.com", "example.com", "example.com"),
    ("https://login.example.com", None, "login.example.com"),
    ("http://localhost:8080", None, "localhost"),
    ("http://localhost:8080", "localhost", "localhost"),
    ("https://EXAMPLE.com", "Example.COM", "example.com"),
])
def test_rp_id_accepted(origin, rp, expected) -> None:
    assert validate_rp_id(origin, rp) == expected


@pytest.mark.parametrize("origin,rp", [
    ("https://a.example.co.uk", "co.uk"),
    ("https://example.com", "evil.com"),
    ("https://example.com", "ample.com"),
    ("https://127.0.0.1", None),
    ("http://example.com", None),
    ("https://example.com", "sub.example.com"),
    ("https://example.com", "com"),
    ("https://example.com", ""),
])
def test_rp_id_rejected(origin, rp) -> None:
    with pytest.raises(PasskeyError) as error:
        validate_rp_id(origin, rp)
    assert error.value.code == "security_error"


def test_cbor_known_vectors() -> None:  # RFC 8949 Appendix A
    assert cbor_encode(0) == b"\x00"
    assert cbor_encode(-1) == b"\x20"
    assert cbor_encode(24) == b"\x18\x18"
    assert cbor_encode(-7) == b"\x26"
    assert cbor_encode(1000) == b"\x19\x03\xe8"
    assert cbor_encode(b"\x01\x02") == b"\x42\x01\x02"
    assert cbor_encode("a") == b"\x61a"
    assert cbor_encode({1: 2}) == b"\xa1\x01\x02"
    assert cbor_encode([]) == b"\x80"
    assert cbor_encode(True) == b"\xf5"


def test_client_data_json_exact_bytes() -> None:
    assert client_data_json("webauthn.get", b"\x01" * 16, "https://example.com") == (
        b'{"type":"webauthn.get","challenge":"AQEBAQEBAQEBAQEBAQEBAQ",'
        b'"origin":"https://example.com","crossOrigin":false}')


def test_authenticator_data_flags_and_zero_counter() -> None:
    data = authenticator_data("example.com", user_verified=False)
    assert len(data) == 37
    assert data[:32] == hashlib.sha256(b"example.com").digest()
    assert data[32] == 0x19
    assert data[33:37] == b"\0\0\0\0"
    assert authenticator_data("example.com", user_verified=True)[32] == 0x1D


def test_register_then_assert_round_trip_verifies_like_a_relying_party() -> None:
    opts = parse_create_options(ORIGIN, _create_raw())
    fields, response = create_credential(ORIGIN, opts, user_verified=True)

    assert fields["title"] == "Example (ada@example.com)"
    assert fields["relying_party_id"] == "example.com"
    assert fields["algorithm"] == "ES256"
    assert fields["user_handle"] == _b64(b"user-0001")
    assert fields["user_display_name"] == "Ada"
    assert response["credential_id"] == fields["credential_id"]
    assert response["public_key_algorithm"] == -7
    assert response["transports"] == ["internal"]
    assert response["cred_props_rk"] is True

    client_data = json.loads(b64u_decode(response["client_data_json"], max_bytes=4096))
    assert client_data == {"type": "webauthn.create", "challenge": _b64(b"c" * 32),
                           "origin": ORIGIN, "crossOrigin": False}

    attestation, _ = _cbor_decode(b64u_decode(response["attestation_object"], max_bytes=4096))
    assert attestation["fmt"] == "none" and attestation["attStmt"] == {}
    auth_data = attestation["authData"]
    assert auth_data == b64u_decode(response["authenticator_data"], max_bytes=4096)
    assert auth_data[:32] == hashlib.sha256(b"example.com").digest()
    assert auth_data[32] == 0x5D  # UP | UV | BE | BS | AT
    assert auth_data[37:53] == AAGUID
    cred_len = struct.unpack(">H", auth_data[53:55])[0]
    credential_id = auth_data[55:55 + cred_len]
    assert cred_len == 16 and credential_id == b64u_decode(fields["credential_id"], max_bytes=64)
    cose, end = _cbor_decode(auth_data, 55 + cred_len)
    assert end == len(auth_data)
    assert cose[1] == 2 and cose[3] == -7 and cose[-1] == 1

    public_key = serialization.load_der_public_key(b64u_decode(response["public_key_spki"], max_bytes=4096))
    numbers = public_key.public_numbers()
    assert cose[-2] == numbers.x.to_bytes(32, "big") and cose[-3] == numbers.y.to_bytes(32, "big")

    record = {**fields, "id": "item-1"}
    assert usable_record(record)
    get_opts = parse_get_options(ORIGIN, {
        "rpId": "example.com", "challenge": _b64(b"g" * 32),
        "allowCredentials": [{"type": "public-key", "id": fields["credential_id"]}],
        "userVerification": "discouraged",
    })
    assertion = get_assertion(ORIGIN, get_opts, record, user_verified=False)
    assert assertion["credential_id"] == fields["credential_id"]
    assert assertion["user_handle"] == fields["user_handle"]
    signed_auth = b64u_decode(assertion["authenticator_data"], max_bytes=4096)
    assert signed_auth[32] == 0x19
    client = b64u_decode(assertion["client_data_json"], max_bytes=4096)
    assert json.loads(client)["type"] == "webauthn.get"
    public_key.verify(b64u_decode(assertion["signature"], max_bytes=128),
                      signed_auth + hashlib.sha256(client).digest(), ec.ECDSA(hashes.SHA256()))


def test_create_title_falls_back_to_rp_id_without_names() -> None:
    raw = _create_raw(rp={"id": "example.com"}, user={"id": _b64(b"u"), "name": "", "displayName": ""})
    fields, _ = create_credential(ORIGIN, parse_create_options(ORIGIN, raw), user_verified=False)
    assert fields["title"] == "example.com"


def test_create_without_es256_falls_back() -> None:
    with pytest.raises(PasskeyError) as error:
        parse_create_options(ORIGIN, _create_raw(pubKeyCredParams=[{"type": "public-key", "alg": -257}]))
    assert error.value.code == "fallback"


@pytest.mark.parametrize("override", [
    {"challenge": _b64(b"c" * 8)},
    {"challenge": "not base64url!"},
    {"user": {"id": _b64(b"u" * 65), "name": "a", "displayName": "a"}},
    {"user": {"id": "", "name": "a", "displayName": "a"}},
    {"excludeCredentials": [{"type": "public-key", "id": _b64(b"x")}] * 65},
    {"rp": "example.com"},
])
def test_oversized_or_malformed_create_options_fall_back(override) -> None:
    with pytest.raises(PasskeyError) as error:
        parse_create_options(ORIGIN, _create_raw(**override))
    assert error.value.code == "fallback"


def test_malformed_get_options_fall_back_and_bad_rp_is_security_error() -> None:
    with pytest.raises(PasskeyError) as error:
        parse_get_options(ORIGIN, {"challenge": _b64(b"g" * 32),
                                   "allowCredentials": [{"type": "public-key", "id": "!"}]})
    assert error.value.code == "fallback"
    with pytest.raises(PasskeyError) as error:
        parse_get_options(ORIGIN, {"rpId": "evil.com", "challenge": _b64(b"g" * 32)})
    assert error.value.code == "security_error"
    opts = parse_get_options(ORIGIN, {"challenge": _b64(b"g" * 32)})
    assert opts.rp_id == "login.example.com" and opts.allow_ids == () and opts.user_verification == "preferred"


def test_create_options_parse_exclusions_and_user_verification() -> None:
    opts = parse_create_options(ORIGIN, _create_raw(
        excludeCredentials=[{"type": "public-key", "id": _b64(b"old")}],
        authenticatorSelection={"userVerification": "discouraged"}))
    assert opts.exclude_ids == (b"old",)
    assert opts.user_verification == "discouraged"
    assert opts.cred_props is True
    assert opts.user_id == b"user-0001"


def test_usable_record_requires_es256_and_p256_pkcs8() -> None:
    def pkcs8(curve) -> str:
        key = ec.generate_private_key(curve)
        return b64u_encode(key.private_bytes(serialization.Encoding.DER, serialization.PrivateFormat.PKCS8,
                                             serialization.NoEncryption()))
    base = {"credential_id": _b64(b"id"), "algorithm": "ES256", "private_key": pkcs8(ec.SECP256R1())}
    assert usable_record(base)
    assert not usable_record({**base, "algorithm": "RS256"})
    assert not usable_record({**base, "private_key": "garbage"})
    assert not usable_record({**base, "private_key": pkcs8(ec.SECP384R1())})
    assert not usable_record({**base, "credential_id": ""})


def test_page_supplied_names_cannot_add_lines_or_bidi_controls() -> None:
    raw = _create_raw(rp={"id": "example.com", "name": "Ex\u202eample\r\nSite: paypal.com"},
                      user={"id": _b64(b"u1"), "name": "alice\n\nSite: paypal.com", "displayName": "A\tB\u2028C"})
    opts = parse_create_options(ORIGIN, raw)
    for value in (opts.rp_name, opts.user_name, opts.user_display_name):
        assert not any(ch in value for ch in "\r\n\t\u2028\u202e")
    assert opts.user_name == "alice Site: paypal.com"
    assert opts.rp_name == "Example Site: paypal.com"
    assert opts.user_display_name == "A B C"
