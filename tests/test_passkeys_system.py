"""CTAP2 client-data-hash signing path for the Windows passkey provider (sub-plan 04, Task 2)."""
from __future__ import annotations

import hashlib

import pytest
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from localvault.passkeys import (
    AAGUID,
    CLIENT_DATA_HASH_BYTES,
    FLAG_AT,
    PasskeyError,
    SystemGetOptions,
    authenticator_data,
    b64u_decode,
    b64u_encode,
    cbor_encode,
    client_data_json,
    cose_es256_public_key,
    create_credential,
    create_credential_from_hash,
    get_assertion,
    get_assertion_from_hash,
    parse_create_options,
    parse_get_options,
    parse_system_create,
    parse_system_get,
    usable_record,
    validate_rp_id_syntax,
)

# A fixed P-256 PKCS#8 test key, generated once with `cryptography` and pasted here. Test only.
TEST_KEY_PKCS8 = (
    "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgnOl_MFGpZygh62CPZ7wHaghm6m-9Pz519-9gZry25CihRANCAATEi_P1"
    "xhVG46WDKhrs3dNI6g316yVKYp9hq_iqVECTqV8lvARj_24ZBytNpdw9R1GW0I4lMXvtKA7n303npDyK"
)
CREDENTIAL_ID = bytes(range(100, 116))
RP_ID_HASH_EXAMPLE_COM = "a379a6f6eeafb9a55e378c118034e2751e682fab9f2d30ab13d2125586ce1947"


def _record(**overrides):
    record = {
        "title": "Example (ada@example.com)",
        "relying_party_id": "example.com",
        "rp_name": "Example",
        "user_handle": b64u_encode(b"user-0001"),
        "user_name": "ada@example.com",
        "user_display_name": "Ada",
        "credential_id": b64u_encode(CREDENTIAL_ID),
        "private_key": TEST_KEY_PKCS8,
        "algorithm": "ES256",
        "created": "2026-11-08",
        "discoverable": True,
    }
    record.update(overrides)
    return record


def _public_key(record) -> ec.EllipticCurvePublicKey:
    key = serialization.load_der_private_key(b64u_decode(record["private_key"], max_bytes=4096), password=None)
    return key.public_key()


def _verifies(public_key, signature: bytes, message: bytes) -> bool:
    try:
        public_key.verify(signature, message, ec.ECDSA(hashes.SHA256()))
    except InvalidSignature:
        return False
    return True


def _create_raw(**overrides):
    raw = {
        "action": "passkey_create_system",
        "system_protocol": 1,
        "transaction_id": "8a1d1a3e-0000-4000-8000-000000000001",
        "rp_id": "example.com",
        "rp_name": "Example",
        "user_id": b64u_encode(b"user-0001"),
        "user_name": "ada@example.com",
        "user_display_name": "Ada",
        "client_data_hash": b64u_encode(bytes(range(32))),
        "algorithms": [-7, -257],
        "exclude_credentials": [],
        "resident_key": True,
        "user_verification": "required",
        "caller": {"image": "msedge.exe", "title": "Sign in"},
    }
    raw.update(overrides)
    return raw


def _get_raw(**overrides):
    raw = {
        "action": "passkey_get_system",
        "system_protocol": 1,
        "transaction_id": "8a1d1a3e-0000-4000-8000-000000000002",
        "rp_id": "example.com",
        "client_data_hash": b64u_encode(bytes(range(32))),
        "allow_credentials": [],
        "user_verification": "required",
    }
    raw.update(overrides)
    return raw


def _browser_create_options():
    return parse_create_options("https://example.com", {
        "rp": {"id": "example.com", "name": "Example"},
        "user": {"id": b64u_encode(b"user-0001"), "name": "ada@example.com", "displayName": "Ada"},
        "challenge": b64u_encode(b"c" * 32),
        "pubKeyCredParams": [{"type": "public-key", "alg": -7}],
        "authenticatorSelection": {"userVerification": "required"},
    })


# -- authenticator data --------------------------------------------------------

def test_rp_id_hash_vector():
    data = authenticator_data("example.com", user_verified=True)
    assert data[:32].hex() == RP_ID_HASH_EXAMPLE_COM
    assert data[:32] == hashlib.sha256(b"example.com").digest()
    assert data[32] == 0x1D  # UP | UV | BE | BS
    assert data[33:37] == b"\x00\x00\x00\x00"
    assert len(data) == 37


def test_discouraged_clears_uv_flag():
    assert authenticator_data("example.com", user_verified=False)[32] == 0x19


# -- get --------------------------------------------------------------------------

def test_get_from_hash_signs_auth_data_concat_hash():
    record = _record()
    client_data_hash = bytes(range(32))
    opts = parse_system_get(_get_raw(client_data_hash=b64u_encode(client_data_hash)))
    result = get_assertion_from_hash(opts, record, user_verified=True)
    assert set(result) == {"credential_id", "authenticator_data", "signature", "user_handle", "user_name",
                           "user_display_name"}
    auth_data = b64u_decode(result["authenticator_data"], max_bytes=1024)
    signature = b64u_decode(result["signature"], max_bytes=1024)
    assert auth_data == authenticator_data("example.com", user_verified=True)
    public_key = _public_key(record)
    assert _verifies(public_key, signature, auth_data + client_data_hash)
    assert not _verifies(public_key, signature, auth_data + hashlib.sha256(client_data_hash).digest())
    assert result["credential_id"] == record["credential_id"]
    assert result["user_handle"] == record["user_handle"]
    assert result["user_name"] == "ada@example.com"
    assert result["user_display_name"] == "Ada"


def test_get_from_hash_without_uv_clears_uv_flag():
    opts = parse_system_get(_get_raw(user_verification="discouraged"))
    result = get_assertion_from_hash(opts, _record(), user_verified=False)
    assert b64u_decode(result["authenticator_data"], max_bytes=64)[32] == 0x19


def test_hash_path_matches_browser_path():
    record = _record()
    challenge = b"x" * 32
    client_data = client_data_json("webauthn.get", challenge, "https://example.com")
    browser_opts = parse_get_options("https://example.com", {"rpId": "example.com",
                                                             "challenge": b64u_encode(challenge)})
    browser = get_assertion("https://example.com", browser_opts, record, user_verified=True)
    assert b64u_decode(browser["client_data_json"], max_bytes=4096) == client_data
    system = get_assertion_from_hash(
        SystemGetOptions(rp_id="example.com", client_data_hash=hashlib.sha256(client_data).digest(),
                         allow_ids=(), user_verification="required"),
        record, user_verified=True)
    assert system["authenticator_data"] == browser["authenticator_data"]
    auth_data = b64u_decode(system["authenticator_data"], max_bytes=1024)
    message = auth_data + hashlib.sha256(client_data).digest()
    public_key = _public_key(record)
    assert _verifies(public_key, b64u_decode(browser["signature"], max_bytes=1024), message)
    assert _verifies(public_key, b64u_decode(system["signature"], max_bytes=1024), message)


def test_get_from_hash_refuses_record_of_another_rp():
    opts = parse_system_get(_get_raw())
    with pytest.raises(PasskeyError) as info:
        get_assertion_from_hash(opts, _record(relying_party_id="evil.example"), user_verified=True)
    assert info.value.code == "invalid_request"


def test_get_from_hash_refuses_credential_outside_allow_list():
    opts = parse_system_get(_get_raw(allow_credentials=[b64u_encode(b"\x01" * 16)]))
    with pytest.raises(PasskeyError) as info:
        get_assertion_from_hash(opts, _record(), user_verified=True)
    assert info.value.code == "invalid_request"
    allowed = parse_system_get(_get_raw(allow_credentials=[b64u_encode(CREDENTIAL_ID)]))
    assert get_assertion_from_hash(allowed, _record(), user_verified=True)["credential_id"]


@pytest.mark.parametrize("bad_hash", [b"", bytes(31), bytes(33)])
def test_get_from_hash_refuses_wrong_hash_length_in_options(bad_hash):
    opts = SystemGetOptions(rp_id="example.com", client_data_hash=bad_hash, allow_ids=(),
                            user_verification="required")
    with pytest.raises(PasskeyError) as info:
        get_assertion_from_hash(opts, _record(), user_verified=True)
    assert info.value.code == "invalid_request"


def test_get_from_hash_refuses_unusable_record():
    opts = parse_system_get(_get_raw())
    with pytest.raises(PasskeyError) as info:
        get_assertion_from_hash(opts, _record(private_key="not-a-key"), user_verified=True)
    assert info.value.code == "invalid_request"
    with pytest.raises(PasskeyError):
        get_assertion_from_hash(opts, _record(algorithm="RS256"), user_verified=True)


# -- create -----------------------------------------------------------------------

def _check_create_auth_data(auth_data: bytes, credential_id: bytes, public_key, *, uv: bool):
    assert auth_data[:32].hex() == RP_ID_HASH_EXAMPLE_COM
    assert auth_data[32] == (0x1D if uv else 0x19) | FLAG_AT
    assert auth_data[33:37] == bytes(4)
    assert auth_data[37:53] == AAGUID
    assert int.from_bytes(auth_data[53:55], "big") == len(credential_id) == 16
    assert auth_data[55:71] == credential_id
    assert auth_data[71:] == cose_es256_public_key(public_key)


def test_create_from_hash_attestation_is_fmt_none():
    opts = parse_system_create(_create_raw())
    fields, response = create_credential_from_hash(opts, user_verified=True)
    auth_data = b64u_decode(response["authenticator_data"], max_bytes=4096)
    attestation = b64u_decode(response["attestation_object"], max_bytes=4096)
    assert attestation == cbor_encode({"fmt": "none", "attStmt": {}, "authData": auth_data})
    assert response["attestation_format"] == "none"
    assert response["public_key_algorithm"] == -7
    assert set(response) == {"credential_id", "authenticator_data", "attestation_object", "attestation_format",
                             "public_key_algorithm"}
    assert "private_key" not in response and "client_data_json" not in response


def test_create_from_hash_item_is_usable_by_browser_get():
    opts = parse_system_create(_create_raw(user_verification="discouraged"))
    fields, response = create_credential_from_hash(opts, user_verified=False)
    browser_fields, _ = create_credential("https://example.com", _browser_create_options(), user_verified=True)
    assert set(fields) == set(browser_fields)
    for name, value in fields.items():
        assert type(value) is type(browser_fields[name]), name
    assert {k: fields[k] for k in ("title", "relying_party_id", "rp_name", "user_handle", "user_name",
                                   "user_display_name", "algorithm", "discoverable")} == \
           {k: browser_fields[k] for k in ("title", "relying_party_id", "rp_name", "user_handle", "user_name",
                                           "user_display_name", "algorithm", "discoverable")}
    assert usable_record(fields)
    credential_id = b64u_decode(fields["credential_id"], max_bytes=64)
    assert len(credential_id) == 16
    assert response["credential_id"] == fields["credential_id"]
    public_key = _public_key(fields)
    _check_create_auth_data(b64u_decode(response["authenticator_data"], max_bytes=4096), credential_id,
                            public_key, uv=False)

    challenge = b"y" * 32
    get_opts = parse_get_options("https://example.com", {"rpId": "example.com",
                                                         "challenge": b64u_encode(challenge)})
    assertion = get_assertion("https://example.com", get_opts, fields, user_verified=True)
    client_data = b64u_decode(assertion["client_data_json"], max_bytes=4096)
    assert _verifies(public_key, b64u_decode(assertion["signature"], max_bytes=1024),
                     b64u_decode(assertion["authenticator_data"], max_bytes=1024)
                     + hashlib.sha256(client_data).digest())


def test_browser_created_item_is_usable_by_hash_get():
    fields, response = create_credential("https://example.com", _browser_create_options(), user_verified=True)
    assert usable_record(fields)
    credential_id = b64u_decode(fields["credential_id"], max_bytes=64)
    assert len(credential_id) == 16
    public_key = _public_key(fields)
    _check_create_auth_data(b64u_decode(response["authenticator_data"], max_bytes=4096), credential_id,
                            public_key, uv=True)
    client_data_hash = hashlib.sha256(b"some client data").digest()
    opts = parse_system_get(_get_raw(client_data_hash=b64u_encode(client_data_hash),
                                     allow_credentials=[fields["credential_id"]]))
    result = get_assertion_from_hash(opts, fields, user_verified=True)
    auth_data = b64u_decode(result["authenticator_data"], max_bytes=1024)
    assert _verifies(public_key, b64u_decode(result["signature"], max_bytes=1024), auth_data + client_data_hash)
    assert result["user_handle"] == fields["user_handle"]


def test_parse_system_create_fields():
    opts = parse_system_create(_create_raw(user_name="ana\nSite: evil", exclude_credentials=[b64u_encode(b"e" * 16)]))
    assert opts.rp_id == "example.com"
    assert opts.user_id == b"user-0001"
    assert opts.user_name == "ana Site: evil"
    assert opts.client_data_hash == bytes(range(32))
    assert opts.exclude_ids == (b"e" * 16,)
    assert opts.algorithms == (-7, -257)
    assert opts.user_verification == "required"
    assert CLIENT_DATA_HASH_BYTES == 32


# -- rejects ------------------------------------------------------------------------

@pytest.mark.parametrize("rp_id", ["example.com", "login.example.com", "xn--bcher-kva.example", "localhost"])
def test_validate_rp_id_syntax_accepts(rp_id):
    assert validate_rp_id_syntax(rp_id) == rp_id


@pytest.mark.parametrize("rp_id", [
    "https://a.com", "a.com:443", "a.com/path", "127.0.0.1", "[::1]", "::1", "a" * 254, "Example.com",
    "example.com.", "", None, 7, "bücher.example", "a..com", "-a.com", "a b.com", "1.2.3", "0x7f.1",
])
def test_validate_rp_id_syntax_rejects(rp_id):
    with pytest.raises(PasskeyError) as info:
        validate_rp_id_syntax(rp_id)
    assert info.value.code == "invalid_request"


_LONG_ID = b64u_encode(bytes(1024))

@pytest.mark.parametrize("which,overrides,code", [
    ("both", {"client_data_hash": b64u_encode(bytes(31))}, "invalid_request"),
    ("both", {"client_data_hash": b64u_encode(bytes(33))}, "invalid_request"),
    ("both", {"client_data_hash": "not base64url!"}, "invalid_request"),
    ("both", {"client_data_hash": b64u_encode(bytes(32)) + "=="}, "invalid_request"),
    ("both", {"client_data_hash": None}, "invalid_request"),
    ("both", {"rp_id": "https://a.com"}, "invalid_request"),
    ("both", {"rp_id": "a.com:443"}, "invalid_request"),
    ("both", {"rp_id": "127.0.0.1"}, "invalid_request"),
    ("both", {"rp_id": "[::1]"}, "invalid_request"),
    ("both", {"rp_id": "a" * 254}, "invalid_request"),
    ("both", {"rp_id": "EXAMPLE.COM"}, "invalid_request"),
    ("both", {"user_verification": "preferred"}, "invalid_request"),
    ("both", {"user_verification": None}, "invalid_request"),
    ("get", {"allow_credentials": [b64u_encode(bytes([i]) * 16) for i in range(65)]}, "invalid_request"),
    ("get", {"allow_credentials": [_LONG_ID]}, "invalid_request"),
    ("get", {"allow_credentials": [""]}, "invalid_request"),
    ("get", {"allow_credentials": "abc"}, "invalid_request"),
    ("create", {"exclude_credentials": [b64u_encode(bytes([i]) * 16) for i in range(65)]}, "invalid_request"),
    ("create", {"exclude_credentials": [_LONG_ID]}, "invalid_request"),
    ("create", {"algorithms": [-257]}, "not_supported"),
    ("create", {"algorithms": []}, "not_supported"),
    ("create", {"algorithms": "-7"}, "invalid_request"),
    ("create", {"algorithms": [True]}, "invalid_request"),
    ("create", {"user_id": ""}, "invalid_request"),
    ("create", {"user_id": b64u_encode(bytes(65))}, "invalid_request"),
    ("create", {"user_name": 5}, "invalid_request"),
    ("create", {"resident_key": "yes"}, "invalid_request"),
])
def test_parse_system_rejects(which, overrides, code):
    parsers = []
    if which in ("both", "create"):
        parsers.append((parse_system_create, _create_raw))
    if which in ("both", "get"):
        parsers.append((parse_system_get, _get_raw))
    for parse, build in parsers:
        with pytest.raises(PasskeyError) as info:
            parse(build(**overrides))
        assert info.value.code == code, parse.__name__


@pytest.mark.parametrize("raw", [None, [], "x"])
def test_parse_system_rejects_non_mapping(raw):
    for parse in (parse_system_create, parse_system_get):
        with pytest.raises(PasskeyError) as info:
            parse(raw)
        assert info.value.code == "invalid_request"


def test_parse_system_get_accepts_64_allow_ids():
    ids = [b64u_encode(bytes([i]) * 16) for i in range(64)]
    assert len(parse_system_get(_get_raw(allow_credentials=ids)).allow_ids) == 64
