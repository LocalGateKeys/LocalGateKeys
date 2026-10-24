"""Tests that close gaps found by mutation testing of ``localvault.updates`` (2026-10-24).

Each test names the guard it pins down. Every rejection is checked by its
``reason`` so a guard that is removed cannot be masked by a later, different
check that happens to fail too.
"""
from __future__ import annotations

import base64
import json

import pytest
from test_updates import Publisher, check, make_manifest, publisher  # noqa: F401 - fixture

from localvault import config, updates


def _reason(raw: bytes, keys) -> str:
    with pytest.raises(updates.UpdateCheckError) as exc:
        updates._verify_signed(raw, keys)
    return exc.value.reason


def _bundle(manifest, signature_block) -> bytes:
    return json.dumps({"manifest": manifest, "signature": signature_block}).encode("utf-8")


def _signed_block(pub: Publisher, value) -> dict:
    signature = pub.private_key.sign(updates.canonical_json(value))
    return {"alg": "Ed25519", "key_id": pub.key_id, "signature": base64.b64encode(signature).decode("ascii")}


@pytest.fixture
def keys(publisher):  # noqa: F811 - pytest fixture
    return updates._load_publisher_keys({publisher.key_id: publisher.public_b64}, verify_key_ids=True)


# --- _verify_signed: envelope shape ------------------------------------------------------


def test_signed_non_object_manifest_is_bundle_shape(publisher, keys) -> None:  # noqa: F811
    # A correctly signed list must still be refused as the wrong shape (not passed on as a manifest).
    manifest = ["not", "a", "manifest"]
    assert _reason(_bundle(manifest, _signed_block(publisher, manifest)), keys) == "bundle-shape"


def test_signature_block_as_list_is_bundle_shape(publisher, keys) -> None:  # noqa: F811
    # set(["alg", "key_id", "signature"]) equals the field set: only the type check stops it.
    raw = _bundle(make_manifest(), ["alg", "key_id", "signature"])
    assert _reason(raw, keys) == "bundle-shape"


@pytest.mark.parametrize("value", [12345, None, ["AAAA"], {"b64": "AAAA"}])
def test_non_string_signature_is_signature_encoding(publisher, keys, value) -> None:  # noqa: F811
    block = _signed_block(publisher, make_manifest())
    block["signature"] = value
    assert _reason(_bundle(make_manifest(), block), keys) == "signature-encoding"


@pytest.mark.parametrize("value", ["!!!!", "AAA", "é" * 8, "AAAA AAAA"])
def test_bad_base64_signature_is_signature_encoding(publisher, keys, value) -> None:  # noqa: F811
    block = _signed_block(publisher, make_manifest())
    block["signature"] = value
    assert _reason(_bundle(make_manifest(), block), keys) == "signature-encoding"


@pytest.mark.parametrize("key_id", [7, None, ["x"], {"k": 1}])
def test_non_string_key_id_is_unknown_key(publisher, keys, key_id) -> None:  # noqa: F811
    block = _signed_block(publisher, make_manifest())
    block["key_id"] = key_id
    assert _reason(_bundle(make_manifest(), block), keys) == "unknown-key"


@pytest.mark.parametrize("delta", [-1, +1])
def test_wrong_length_signature_is_signature_length(publisher, keys, delta) -> None:  # noqa: F811
    manifest = make_manifest()
    block = _signed_block(publisher, manifest)
    raw_sig = base64.b64decode(block["signature"])
    raw_sig = raw_sig[:63] if delta < 0 else raw_sig + b"\x00"
    block["signature"] = base64.b64encode(raw_sig).decode("ascii")
    assert _reason(_bundle(manifest, block), keys) == "signature-length"


def test_manifest_that_cannot_be_canonicalised_is_rejected(publisher, keys) -> None:  # noqa: F811
    # Python's json accepts NaN; canonical_json (allow_nan=False) refuses it.
    raw = b'{"manifest": {"x": NaN}, "signature": ' + json.dumps(_signed_block(publisher, {"x": 1})).encode() + b"}"
    assert _reason(raw, keys) == "canonicalisation"


# --- validate_manifest -----------------------------------------------------------------


@pytest.mark.parametrize("artifacts", [{}, "", {"name": "x"}, None, ()])
def test_artifacts_must_be_a_list(artifacts) -> None:
    manifest = make_manifest(artifacts=artifacts)
    with pytest.raises(updates.UpdateCheckError) as exc:
        updates.validate_manifest(manifest)
    assert exc.value.reason == "artifacts"


@pytest.mark.parametrize("sequence", [-1, "7", 7.0, True, None])
def test_negative_or_non_int_sequence_is_rejected(sequence) -> None:
    with pytest.raises(updates.UpdateCheckError) as exc:
        updates.validate_manifest(make_manifest(sequence=sequence))
    assert exc.value.reason == "sequence"


# --- rollback protection -----------------------------------------------------------------


def test_sequence_rollback_is_rejected_with_its_reason(publisher) -> None:  # noqa: F811
    assert check(publisher.sign(make_manifest(sequence=10))) is not None
    with pytest.raises(updates.UpdateCheckError) as exc:
        check(publisher.sign(make_manifest(sequence=9)))
    assert exc.value.reason == "sequence-rollback"
    assert json.loads(updates.update_state_path().read_text("utf-8")) == {"last_sequence": 10}


def test_failed_state_write_is_not_ignored(publisher, monkeypatch) -> None:  # noqa: F811
    def refuse(*_args, **_kwargs):
        raise OSError("disk full")

    monkeypatch.setattr(config, "atomic_write_json", refuse)
    with pytest.raises(updates.UpdateCheckError) as exc:
        check(publisher.sign(make_manifest(sequence=3)))
    assert exc.value.reason == "state-write"
    assert updates._LAST_VERIFIED is None


@pytest.mark.parametrize("stored", ["100", -5, 1.5, True, None, [9], {"n": 9}])
def test_corrupt_last_sequence_values_read_as_unknown(publisher, stored) -> None:  # noqa: F811
    path = updates.update_state_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({"last_sequence": stored}), encoding="utf-8")
    assert updates._read_last_sequence(path) is None
    # And a check still succeeds and replaces the corrupt state.
    assert check(publisher.sign(make_manifest(sequence=7))) is not None
    assert json.loads(path.read_text("utf-8")) == {"last_sequence": 7}


# --- embedded publisher keys -------------------------------------------------------------


def _raw_key_b64() -> tuple[str, str]:
    pub = Publisher()
    return pub.key_id, pub.public_b64


@pytest.mark.parametrize("bad_id", ["BAD", "", "0123456789abcdeg", "0123456789ABCDEF", 5])
def test_malformed_key_id_is_refused_even_without_id_verification(bad_id) -> None:
    _key_id, encoded = _raw_key_b64()
    with pytest.raises(updates.UpdateCheckError):
        updates._load_publisher_keys({bad_id: encoded}, verify_key_ids=False)


def test_non_string_encoded_key_is_refused() -> None:
    key_id, encoded = _raw_key_b64()
    # bytes would decode fine with b64decode: only the type check refuses it.
    with pytest.raises(updates.UpdateCheckError):
        updates._load_publisher_keys({key_id: encoded.encode("ascii")}, verify_key_ids=True)
    with pytest.raises(updates.UpdateCheckError):
        updates._load_publisher_keys({key_id: None}, verify_key_ids=False)


@pytest.mark.parametrize("raw", [b"\x01" * 31, b"\x01" * 33, b""])
def test_wrong_length_key_is_refused(raw) -> None:
    with pytest.raises(updates.UpdateCheckError):
        updates._load_publisher_keys({"0123456789abcdef": base64.b64encode(raw).decode()}, verify_key_ids=False)


# --- field helpers -----------------------------------------------------------------------


@pytest.mark.parametrize("value", ["1.2", "x.y.z", "", None, 3, "1.2.3.4", "01.2.3 "])
def test_parse_version_without_reason_raises_update_check_error(value) -> None:
    with pytest.raises(updates.UpdateCheckError, match="x.y.z"):
        updates._parse_version(value)


def test_invalid_current_version_is_refused_before_any_request(publisher) -> None:  # noqa: F811
    with pytest.raises(updates.UpdateCheckError, match="x.y.z"):
        check(publisher.sign(make_manifest()), current_version="not-a-version")


@pytest.mark.parametrize(
    "value", ["2026-13-01T00:00:00Z", "2026-02-30T00:00:00Z", "2026-10-01T25:00:00+00:00", "nonsenseTZ"]
)
def test_unparseable_published_is_rejected(value) -> None:
    with pytest.raises(updates.UpdateCheckError) as exc:
        updates._parse_published(value)
    assert exc.value.reason == "published"


@pytest.mark.parametrize(
    "value",
    [
        "",
        None,
        42,
        b"https://updates.example.test/x",
        "https://updates.example.test/" + "a" * 2100,
    ],
)
def test_url_must_be_a_short_non_empty_string(value) -> None:
    with pytest.raises(updates.UpdateCheckError) as exc:
        updates._validate_https_url(value, reason="notes_url")
    assert exc.value.reason == "notes_url"
    with pytest.raises(updates.UpdateCheckError, match="invalid"):
        updates._validate_https_url(value, configuration=True)


def test_url_at_the_length_limit_is_accepted() -> None:
    base = "https://updates.example.test/"
    value = base + "a" * (2048 - len(base))
    assert updates._validate_https_url(value) == value


@pytest.mark.parametrize("value", ["https://updates.example.test:0/x", "https://updates.example.test:00/"])
def test_port_zero_is_rejected(value) -> None:
    with pytest.raises(updates.UpdateCheckError) as exc:
        updates._validate_https_url(value, reason="artifact-url")
    assert exc.value.reason == "artifact-url"
    with pytest.raises(updates.UpdateCheckError):
        updates._origin(value)


@pytest.mark.parametrize("value", ["https://updates.example.test:99999/x", "https://updates.example.test:x/"])
def test_invalid_port_is_rejected_by_origin(value) -> None:
    with pytest.raises(updates.UpdateCheckError):
        updates._origin(value)


def test_origin_defaults_to_443_and_lowercases() -> None:
    assert updates._origin("https://Updates.Example.TEST/x") == ("https", "updates.example.test", 443)
    assert updates._origin("https://updates.example.test:8443/") == ("https", "updates.example.test", 8443)
