"""Tests that close gaps found by mutation testing of ``localvault.licensing`` (2026-10-24)."""
from __future__ import annotations

import base64
import json

import pytest
from test_licensing import make_bundle, signer  # noqa: F401 - fixture

from localvault import licensing
from localvault.updates import canonical_json


def _reason(fn, *args) -> str:
    with pytest.raises(licensing.LicenseError) as exc:
        fn(*args)
    return exc.value.reason


def _sign(signer, lic: dict) -> dict:  # noqa: F811
    private, key_id = signer
    return {
        "alg": "Ed25519",
        "key_id": key_id,
        "signature": base64.b64encode(private.sign(canonical_json(lic))).decode(),
    }


# --- parse_license_text ------------------------------------------------------------------


@pytest.mark.parametrize("text", ["{not json", "LGK1-" + base64.urlsafe_b64encode(b"{oops").decode(), "", "[1,"])
def test_unparseable_text_is_not_json(text) -> None:
    assert _reason(licensing.parse_license_text, text) == "not-json"


@pytest.mark.parametrize("value", [None, b"{}", 5, {"license": {}}, ["x"]])
def test_non_text_is_not_text(value) -> None:
    assert _reason(licensing.parse_license_text, value) == "not-text"


@pytest.mark.parametrize("text", ["[1, 2]", '"a string"', "5", "null", "LGK1-" + base64.urlsafe_b64encode(b"[]").decode()])
def test_json_that_is_not_an_object_is_license_shape(text) -> None:
    assert _reason(licensing.parse_license_text, text) == "license-shape"


def test_parse_returns_the_object(signer) -> None:  # noqa: F811
    bundle = make_bundle(signer)
    assert licensing.parse_license_text(json.dumps(bundle)) == bundle


# --- verify_bundle: signature block shape --------------------------------------------------


def test_signature_block_with_an_extra_field_is_license_shape(signer) -> None:  # noqa: F811
    bundle = make_bundle(signer)
    bundle["signature"]["extra"] = "x"  # the signature itself is still valid
    assert _reason(licensing.verify_bundle, bundle) == "license-shape"


@pytest.mark.parametrize("missing", ["alg", "key_id", "signature"])
def test_signature_block_missing_a_field_is_license_shape_not_key_error(signer, missing) -> None:  # noqa: F811
    bundle = make_bundle(signer)
    del bundle["signature"][missing]
    assert _reason(licensing.verify_bundle, bundle) == "license-shape"
    # The shared signature check refuses it on its own as well (no KeyError for any caller).
    assert _reason(licensing._check_signature, bundle["license"], bundle["signature"], licensing.LICENSE_KEYS) == (
        "license-shape"
    )


@pytest.mark.parametrize("sig", [None, [], "Ed25519", ("alg", "key_id", "signature")])
def test_signature_block_of_the_wrong_type_is_license_shape(signer, sig) -> None:  # noqa: F811
    bundle = make_bundle(signer)
    bundle["signature"] = sig
    assert _reason(licensing.verify_bundle, bundle) == "license-shape"


def test_signature_given_as_bytes_is_refused(signer) -> None:  # noqa: F811
    # b64decode accepts bytes, so only the type check refuses a non-string signature.
    bundle = make_bundle(signer)
    bundle["signature"]["signature"] = bundle["signature"]["signature"].encode("ascii")
    assert _reason(licensing.verify_bundle, bundle) == "bad-signature"


@pytest.mark.parametrize("delta", [-1, +1])
def test_wrong_length_signature_is_bad_signature(signer, delta) -> None:  # noqa: F811
    bundle = make_bundle(signer)
    raw = base64.b64decode(bundle["signature"]["signature"])
    raw = raw[:63] if delta < 0 else raw + b"\x00"
    bundle["signature"]["signature"] = base64.b64encode(raw).decode()
    assert _reason(licensing.verify_bundle, bundle) == "bad-signature"


def test_unknown_well_formed_key_id_is_unknown_key(signer) -> None:  # noqa: F811
    bundle = make_bundle(signer)
    assert _reason(licensing.verify_bundle, bundle, {"0123456789abcdef": "AAAA"}) == "unknown-key"
    assert _reason(licensing.verify_bundle, bundle, {}) == "unknown-key"


# --- newer_format ------------------------------------------------------------------------


def _newer_bundle(signer, **overrides) -> dict:  # noqa: F811
    bundle = make_bundle(signer, format=2, **overrides)
    return bundle


def test_newer_format_true_for_a_signed_format_2(signer) -> None:  # noqa: F811
    assert licensing.newer_format(_newer_bundle(signer)) is True


@pytest.mark.parametrize("bundle", [None, [], "x", 5, ("license", "signature")])
def test_newer_format_false_for_non_object_bundles(bundle) -> None:
    assert licensing.newer_format(bundle) is False


def test_newer_format_false_for_a_bundle_with_extra_fields(signer) -> None:  # noqa: F811
    bundle = _newer_bundle(signer)
    bundle["extra"] = 1
    assert licensing.newer_format(bundle) is False
    del bundle["extra"]
    del bundle["signature"]
    assert licensing.newer_format(bundle) is False


@pytest.mark.parametrize("lic", [None, [], "license", 2])
def test_newer_format_false_for_non_object_licence(signer, lic) -> None:  # noqa: F811
    bundle = _newer_bundle(signer)
    bundle["license"] = lic
    assert licensing.newer_format(bundle) is False


@pytest.mark.parametrize("missing", ["alg", "key_id", "signature"])
def test_newer_format_false_not_key_error_for_signature_block_missing_a_field(signer, missing) -> None:  # noqa: F811
    bundle = _newer_bundle(signer)
    del bundle["signature"][missing]
    assert licensing.newer_format(bundle) is False


def test_newer_format_false_for_signature_block_with_extra_field(signer) -> None:  # noqa: F811
    bundle = _newer_bundle(signer)
    bundle["signature"]["extra"] = "x"
    assert licensing.newer_format(bundle) is False
    bundle["signature"] = list(bundle["signature"])
    assert licensing.newer_format(bundle) is False


@pytest.mark.parametrize("fmt", [1, 0, -3, True, "2", 2.0, None])
def test_newer_format_false_for_current_or_bad_format_even_when_signed(signer, fmt) -> None:  # noqa: F811
    bundle = make_bundle(signer)
    bundle["license"]["format"] = fmt
    bundle["signature"] = _sign(signer, bundle["license"])
    assert licensing.newer_format(bundle) is False


def test_newer_format_false_for_bad_signature(signer) -> None:  # noqa: F811
    bundle = _newer_bundle(signer)
    bundle["license"]["name"] = "Mallory"
    assert licensing.newer_format(bundle) is False

