"""Ed25519 verification used by ``lgk proof verify`` (RFC 8032), incl. the pure fallback lgk.exe uses."""
from __future__ import annotations

import hashlib

import pytest

from localvault import privacy_proof as pp

# RFC 8032 section 7.1: TEST 1, TEST 2, TEST 3 and TEST SHA(abc) (secret key, public key, message, signature).
RFC8032 = [
    ("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
     "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a", "",
     "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"),
    ("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
     "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c", "72",
     "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00"),
    ("c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
     "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025", "af82",
     "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a"),
    ("833fe62409237b9d62ec77587520911e9a759cec1d19755b7da901b96dca3d42",
     "ec172b93ad5e563bf4932c70e1245034c35467ef2efd4d64ebf819683467e2bf", hashlib.sha512(b"abc").hexdigest(),
     "dc2a4459e7369633a52b1bf277839a00201009a3efbf3ecb69bea2186c26b58909351fc9ac90b3ecfdfbc7c66431e0303dca179c138ac17ad9bef1177331a704"),
]

# The eight points of small order (orders 1, 2, 4, 4, 8, 8, 8, 8), canonical encodings.
SMALL_ORDER = [
    "0100000000000000000000000000000000000000000000000000000000000000",
    "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
    "0000000000000000000000000000000000000000000000000000000000000000",
    "0000000000000000000000000000000000000000000000000000000000000080",
    "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
    "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa",
    "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
    "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85",
]

VERIFIERS = [pp._ed25519_verify, pp._ed25519_verify_pure]


def _enc(y: int, sign: int = 0) -> bytes:
    return (y | (sign << 255)).to_bytes(32, "little")


@pytest.mark.parametrize("secret,public,message,signature", RFC8032)
@pytest.mark.parametrize("verify", VERIFIERS)
def test_rfc8032_vectors(verify, secret, public, message, signature):
    pk, msg, sig = bytes.fromhex(public), bytes.fromhex(message), bytes.fromhex(signature)
    assert verify(pk, sig, msg)
    assert not verify(pk, sig, msg + b"\x00")
    for index in (0, 31, 32, 63):  # a bit flipped in R, in S, and in the key
        bad = bytearray(sig)
        bad[index] ^= 0x01
        assert not verify(pk, bytes(bad), msg)
    bad_key = bytearray(pk)
    bad_key[0] ^= 0x01
    assert not verify(bytes(bad_key), sig, msg)


def test_rfc8032_keys_and_signatures_are_reproduced():
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ed25519

    for secret, public, message, signature in RFC8032:
        key = ed25519.Ed25519PrivateKey.from_private_bytes(bytes.fromhex(secret))
        raw = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        assert raw.hex() == public and key.sign(bytes.fromhex(message)).hex() == signature


@pytest.mark.parametrize("verify", VERIFIERS)
def test_non_canonical_s_is_refused(verify):
    _secret, public, message, signature = RFC8032[0]
    pk, msg, sig = bytes.fromhex(public), bytes.fromhex(message), bytes.fromhex(signature)
    s = int.from_bytes(sig[32:], "little")
    assert not verify(pk, sig[:32] + (s + pp._L).to_bytes(32, "little"), msg)  # same point equation, S >= L
    assert not verify(pk, sig[:32] + pp._L.to_bytes(32, "little"), msg)
    assert not verify(pk, sig[:32] + b"\xff" * 32, msg)


def test_small_order_points_are_recognised():
    for text in SMALL_ORDER:
        point = pp._edwards_decode(bytes.fromhex(text))
        assert point is not None and pp._small_order(point), text
    assert len({bytes.fromhex(t) for t in SMALL_ORDER}) == 8
    assert not pp._small_order(pp._BASE)
    _secret, public, _m, _s = RFC8032[1]
    assert not pp._small_order(pp._edwards_decode(bytes.fromhex(public)))


@pytest.mark.parametrize("verify", VERIFIERS)
@pytest.mark.parametrize("text", SMALL_ORDER)
def test_small_order_key_or_r_is_refused(verify, text):
    small = bytes.fromhex(text)
    # The classic forgery: A of small order, R = identity, S = 0 satisfies [S]B = R + [k]A for many messages.
    for message in (b"", b"any message", b"privacy proof"):
        assert not verify(small, bytes.fromhex(SMALL_ORDER[0]) + bytes(32), message)
        assert not verify(small, small + bytes(32), message)
    _secret, public, message, signature = RFC8032[0]
    assert not verify(bytes.fromhex(public), small + bytes.fromhex(signature)[32:], bytes.fromhex(message))


@pytest.mark.parametrize("verify", VERIFIERS)
def test_non_canonical_point_encodings_are_refused(verify):
    # y >= p: p + 1 encodes the identity, p - 1 + p is out of range; x = 0 with the sign bit set (y = 1, y = p - 1).
    for raw in (_enc(pp._P + 1), _enc(pp._P), _enc(pp._P + 18), _enc(2**255 - 1), _enc(1, 1), _enc(pp._P - 1, 1)):
        assert pp._edwards_decode(raw) is None
        assert not verify(raw, bytes.fromhex(SMALL_ORDER[0]) + bytes(32), b"")
        _secret, public, message, signature = RFC8032[0]
        assert not verify(bytes.fromhex(public), raw + bytes.fromhex(signature)[32:], bytes.fromhex(message))


def test_y_values_that_are_not_on_the_curve_are_refused():
    rejected = [y for y in range(2, 40) if pp._edwards_decode(_enc(y)) is None]
    assert rejected  # about half of all y have no x
    for y in rejected:
        assert not pp._ed25519_verify_pure(_enc(y), bytes(64), b"")


@pytest.mark.parametrize("verify", VERIFIERS)
def test_wrong_lengths_are_refused(verify):
    _secret, public, message, signature = RFC8032[0]
    pk, sig = bytes.fromhex(public), bytes.fromhex(signature)
    assert not verify(pk[:31], sig, b"")
    assert not verify(pk + b"\x00", sig, b"")
    assert not verify(pk, sig[:63], b"")
    assert not verify(pk, sig + b"\x00", b"")
