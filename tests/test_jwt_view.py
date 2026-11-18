"""JWT decode: the shared vectors plus size and mutation guards."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from localvault.jwt_view import MAX_JWT_CHARS, decode_jwt

CASES = json.loads((Path(__file__).parent / "vectors" / "jwt" / "cases.json").read_text(encoding="utf-8"))


@pytest.mark.parametrize("case", CASES, ids=[c["name"] for c in CASES])
def test_vector(case):
    info = decode_jwt(case["value"])
    expected = case["result"]
    if expected is None:
        assert info is None
        return
    assert info is not None
    assert info.header == expected["header"]
    assert info.claims == expected["claims"]
    assert (info.alg, info.issued, info.not_before, info.expires) == (
        expected["alg"], expected["issued"], expected["not_before"], expected["expires"])
    if "now" in case:
        assert info.expired(case["now"]) is case["expired"]


def test_vectors_cover_required_names():
    names = {c["name"] for c in CASES}
    assert {"hs256_basic", "rs256_with_aud_array", "no_signature_part", "exp_in_past", "numeric_strings_ignored",
            "not_json_payload", "array_payload", "two_parts_only_rejected", "whitespace_rejected",
            "exp_after_year_3000_ignored", "exp_at_cap", "duplicate_claim_rejected", "int_beyond_int64_rejected",
            "nan_payload_rejected", "huge_float_rejected", "lone_surrogate_rejected", "aud_string",
            "exp_negative_ignored", "exp_exponent_float_ignored", "json_with_whitespace"} <= names
    assert any(n.startswith("padding_free_base64url") for n in names)


def test_oversized_value_is_not_decoded():
    good = next(c["value"] for c in CASES if c["name"] == "hs256_basic")
    assert decode_jwt(good) is not None
    assert decode_jwt(good + "A" * MAX_JWT_CHARS) is None
