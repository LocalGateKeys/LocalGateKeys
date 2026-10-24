from __future__ import annotations

import base64
import copy
import hashlib
import json
import subprocess
import sys
import types
from pathlib import Path
from urllib.request import Request

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

from localvault import config, updates
from localvault.settings import AppSettings
from localvault.tray import TrayController

FEED_URL = "https://updates.example.test/stable.json"
NOTES_URL = "https://updates.example.test/releases/0.4.0"
INSTALLER_URL = "https://updates.example.test/releases/0.4.0/LocalGateKeys-Setup-Personal.exe"
BUILD_DATE = "2026-10-05"
SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "sign_release_manifest.py"


# ---------------------------------------------------------------------------
# Test helpers: an in-test publisher key and a signed bundle builder
# ---------------------------------------------------------------------------


class Publisher:
    def __init__(self) -> None:
        self.private_key = ed25519.Ed25519PrivateKey.generate()
        self.public_raw = self.private_key.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
        self.public_b64 = base64.b64encode(self.public_raw).decode("ascii")
        self.key_id = hashlib.sha256(self.public_raw).digest()[:8].hex()

    def sign(self, manifest: dict, *, key_id: str | None = None) -> bytes:
        signature = self.private_key.sign(updates.canonical_json(manifest))
        bundle = {
            "manifest": manifest,
            "signature": {
                "alg": "Ed25519",
                "key_id": key_id or self.key_id,
                "signature": base64.b64encode(signature).decode("ascii"),
            },
        }
        return json.dumps(bundle).encode("utf-8")


def make_manifest(**overrides) -> dict:
    manifest = {
        "format": "localgatekeys-release-manifest",
        "version": 1,
        "app_version": "0.4.0",
        "published": "2026-10-01T12:00:00Z",
        "min_supported_version": "0.3.0",
        "notes_url": NOTES_URL,
        "artifacts": [
            {
                "name": "LocalGateKeys-Setup-Personal.exe",
                "sha256": "a" * 64,
                "size": 12345678,
                "url": INSTALLER_URL,
            }
        ],
        "sequence": 7,
    }
    manifest.update(overrides)
    return manifest


class FakeResponse:
    status = 200

    def __init__(self, body: bytes, headers: dict[str, str] | None = None) -> None:
        self.body = body
        self.headers = headers or {}

    def __enter__(self):
        return self

    def __exit__(self, *_args) -> None:
        return None

    def read(self, size: int) -> bytes:
        return self.body[:size]


class FakeOpener:
    def __init__(self, response: FakeResponse) -> None:
        self.response = response
        self.request: Request | None = None
        self.timeout: float | None = None

    def open(self, request: Request, *, timeout: float):
        self.request = request
        self.timeout = timeout
        return self.response


@pytest.fixture
def publisher(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Publisher:
    """Configure a feed, an in-test publisher key, a fresh data dir and build date."""
    pub = Publisher()
    monkeypatch.setattr(updates, "RELEASE_FEED_URL", FEED_URL)
    monkeypatch.setattr(updates, "PUBLISHER_KEYS", {pub.key_id: pub.public_b64})
    monkeypatch.setattr(updates, "BUILD_DATE", BUILD_DATE)
    monkeypatch.setenv("LOCALGATEKEYS_DATA_DIR", str(tmp_path / "data"))
    monkeypatch.setattr(updates, "_LAST_VERIFIED", None)
    return pub


def configure_release(monkeypatch: pytest.MonkeyPatch) -> None:
    """UI-level tests only need the module to report 'configured'."""
    pub = Publisher()
    monkeypatch.setattr(updates, "RELEASE_FEED_URL", FEED_URL)
    monkeypatch.setattr(updates, "PUBLISHER_KEYS", {pub.key_id: pub.public_b64})


def check(body: bytes, **kwargs):
    opener = FakeOpener(FakeResponse(body))
    return updates.check_for_updates(opener_factory=lambda *_args: opener, **kwargs)


# ---------------------------------------------------------------------------
# Configuration / fail-closed behaviour
# ---------------------------------------------------------------------------


def test_release_urls_are_unconfigured_by_default_and_do_not_open_network(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(updates, "RELEASE_FEED_URL", "")
    monkeypatch.setattr(updates, "PUBLISHER_KEYS", {})

    def unexpected_opener(*_args):
        raise AssertionError("unconfigured checks must not create a network opener")

    assert updates.release_configuration() is None
    assert updates.check_for_updates(opener_factory=unexpected_opener) is None


def test_shipped_module_trusts_exactly_the_release_key_and_feed() -> None:
    # Changing either value changes which releases every client will accept;
    # this test makes such a change deliberate.
    assert updates.PUBLISHER_KEYS == {
        "6a892769c82386b3": "wQv4rd+J5MvV2EhSe8rovFFw+jeAWyq2tyfe9fXBwlM=",
    }
    assert updates.RELEASE_FEED_URL == "https://updates.localgatekeys.app/stable.json"
    configuration = updates.release_configuration()
    assert configuration is not None
    assert set(configuration.publisher_keys) == {"6a892769c82386b3"}


def test_empty_publisher_keys_fail_closed_as_not_configured(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(updates, "RELEASE_FEED_URL", FEED_URL)
    monkeypatch.setattr(updates, "PUBLISHER_KEYS", {})

    def unexpected_opener(*_args):
        raise AssertionError("checks without publisher keys must not touch the network")

    assert updates.release_configuration() is None
    assert updates.check_for_updates(opener_factory=unexpected_opener) is None


def test_configuration_requires_https_feed(monkeypatch: pytest.MonkeyPatch) -> None:
    configure_release(monkeypatch)
    monkeypatch.setattr(updates, "RELEASE_FEED_URL", "http://updates.example.test/stable.json")
    with pytest.raises(updates.UpdateCheckError, match="HTTPS"):
        updates.release_configuration()

    monkeypatch.setattr(updates, "RELEASE_FEED_URL", "https://updates.example.test:99999/stable.json")
    with pytest.raises(updates.UpdateCheckError, match="configuration is invalid"):
        updates.release_configuration()


def test_configuration_rejects_malformed_publisher_keys(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(updates, "RELEASE_FEED_URL", FEED_URL)
    monkeypatch.setattr(updates, "PUBLISHER_KEYS", {"0011223344556677": "not base64!"})
    with pytest.raises(updates.UpdateCheckError, match="publisher key"):
        updates.release_configuration()

    # A key_id that does not match the key it labels is a misconfiguration.
    monkeypatch.setattr(
        updates, "PUBLISHER_KEYS", {"0011223344556677": base64.b64encode(b"k" * 32).decode()}
    )
    with pytest.raises(updates.UpdateCheckError, match="publisher key"):
        updates._load_publisher_keys(updates.PUBLISHER_KEYS, verify_key_ids=True)


# ---------------------------------------------------------------------------
# Happy path
# ---------------------------------------------------------------------------


def test_signed_manifest_is_verified_and_compared(publisher: Publisher) -> None:
    body = publisher.sign(make_manifest())
    opener = FakeOpener(FakeResponse(body, {"Content-Length": str(len(body))}))
    used_handlers = []

    def make_opener(handler):
        used_handlers.append(handler)
        return opener

    result = updates.check_for_updates(current_version="0.3.3", opener_factory=make_opener)

    assert result is not None
    assert result.is_newer
    assert result.current_version == "0.3.3"
    assert result.latest_version == "0.4.0"
    assert result.notes_url == NOTES_URL
    assert result.min_supported_version == "0.3.0"
    assert result.sequence == 7
    assert not result.is_unsupported
    assert opener.request is not None
    assert opener.request.full_url == FEED_URL
    assert opener.request.get_method() == "GET"
    # Only these two headers leave the machine; the agent carries just the version.
    assert sorted(opener.request.header_items()) == [
        ("Accept", "application/json"),
        ("User-agent", f"LocalGateKeys/{updates.APP_VERSION}"),
    ]
    assert opener.timeout == updates.REQUEST_TIMEOUT_SECONDS
    assert len(used_handlers) == 1
    # The sequence is now remembered for rollback protection.
    state = json.loads((config.data_dir() / "update-state.json").read_text("utf-8"))
    assert state == {"last_sequence": 7}


def test_update_result_does_not_treat_lower_release_as_newer() -> None:
    assert not updates.UpdateResult("0.10.0", "0.9.9").is_newer


def test_update_result_reports_unsupported_current_version() -> None:
    result = updates.UpdateResult("0.2.0", "0.4.0", min_supported_version="0.3.0")
    assert result.is_unsupported


def test_same_version_is_not_newer_but_still_verified(publisher: Publisher) -> None:
    result = check(publisher.sign(make_manifest(app_version="0.3.3")), current_version="0.3.3")
    assert result is not None
    assert not result.is_newer


# ---------------------------------------------------------------------------
# Tampering: every manifest field, the signature block, the key
# ---------------------------------------------------------------------------


def _tampered_manifests() -> list[tuple[str, dict]]:
    base = make_manifest()
    cases: list[tuple[str, dict]] = []
    for field, value in [
        ("format", "something-else"),
        ("version", 2),
        ("app_version", "9.9.9"),
        ("published", "2026-10-02T12:00:00Z"),
        ("min_supported_version", "0.0.1"),
        ("notes_url", "https://evil.example/releases"),
        ("sequence", 8),
    ]:
        tampered = copy.deepcopy(base)
        tampered[field] = value
        cases.append((field, tampered))
    for field, value in [
        ("name", "Other.exe"),
        ("sha256", "b" * 64),
        ("size", 1),
        ("url", "https://evil.example/installer.exe"),
    ]:
        tampered = copy.deepcopy(base)
        tampered["artifacts"][0][field] = value
        cases.append((f"artifacts.{field}", tampered))
    extra = copy.deepcopy(base)
    extra["download"] = "https://evil.example/x"
    cases.append(("extra-field", extra))
    return cases


@pytest.mark.parametrize(
    "field,tampered", _tampered_manifests(), ids=[case[0] for case in _tampered_manifests()]
)
def test_tampering_with_any_signed_field_is_rejected(
    publisher: Publisher, field: str, tampered: dict
) -> None:
    # Sign the genuine manifest, then swap in the tampered manifest.
    genuine = json.loads(publisher.sign(make_manifest()))
    genuine["manifest"] = tampered
    body = json.dumps(genuine).encode("utf-8")

    with pytest.raises(updates.UpdateCheckError, match="could not be verified"):
        check(body)
    assert not (config.data_dir() / "update-state.json").exists()


def test_tampered_signature_bytes_are_rejected(publisher: Publisher) -> None:
    bundle = json.loads(publisher.sign(make_manifest()))
    raw = bytearray(base64.b64decode(bundle["signature"]["signature"]))
    raw[0] ^= 0x01
    bundle["signature"]["signature"] = base64.b64encode(bytes(raw)).decode("ascii")

    with pytest.raises(updates.UpdateCheckError, match="could not be verified"):
        check(json.dumps(bundle).encode("utf-8"))


def test_unknown_key_id_is_rejected(publisher: Publisher) -> None:
    body = publisher.sign(make_manifest(), key_id="ffffffffffffffff")
    with pytest.raises(updates.UpdateCheckError, match="could not be verified"):
        check(body)


def test_signature_from_a_different_key_is_rejected(publisher: Publisher) -> None:
    other = Publisher()
    # Claim the trusted key_id but sign with an untrusted key.
    body = other.sign(make_manifest(), key_id=publisher.key_id)
    with pytest.raises(updates.UpdateCheckError, match="could not be verified"):
        check(body)


def test_key_rotation_accepts_any_embedded_publisher_key(
    publisher: Publisher, monkeypatch: pytest.MonkeyPatch
) -> None:
    second = Publisher()
    monkeypatch.setattr(
        updates,
        "PUBLISHER_KEYS",
        {publisher.key_id: publisher.public_b64, second.key_id: second.public_b64},
    )
    assert check(second.sign(make_manifest())) is not None


@pytest.mark.parametrize(
    "mutate",
    [
        lambda b: b["signature"].update(alg="RSA-PSS"),
        lambda b: b["signature"].pop("key_id"),
        lambda b: b["signature"].update(extra="x"),
        lambda b: b["signature"].update(signature="AAAA"),
        lambda b: b["signature"].update(signature="%%%"),
        lambda b: b.pop("signature"),
        lambda b: b.pop("manifest"),
        lambda b: b.update(installer="https://evil.example/x"),
    ],
)
def test_malformed_signature_block_is_rejected(publisher: Publisher, mutate) -> None:
    bundle = json.loads(publisher.sign(make_manifest()))
    mutate(bundle)
    with pytest.raises(updates.UpdateCheckError, match="could not be verified"):
        check(json.dumps(bundle).encode("utf-8"))


@pytest.mark.parametrize(
    "body",
    [
        b"not json",
        b"[]",
        b'{"manifest":{},"signature":{},"manifest":{}}',
        b'{"version":"0.10.0"}',
    ],
)
def test_non_bundle_payloads_are_rejected(publisher: Publisher, body: bytes) -> None:
    with pytest.raises(updates.UpdateCheckError):
        check(body)


# ---------------------------------------------------------------------------
# Correctly signed but unacceptable manifests
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "overrides",
    [
        {"app_version": "v0.4.0"},
        {"app_version": "01.4.0"},
        {"app_version": 4},
        {"min_supported_version": "0.3"},
        {"notes_url": "http://updates.example.test/releases"},
        {"notes_url": "https://user:pw@updates.example.test/releases"},
        {"notes_url": "javascript:alert(1)"},
        {"notes_url": ""},
        {"published": "yesterday"},
        {"published": "2026-10-01"},
        {"published": 1759320000},
        {"sequence": -1},
        {"sequence": True},
        {"sequence": 1.5},
        {"sequence": "7"},
        {"version": "1"},
        {"format": "localgatekeys-release-manifest-v2"},
        {"artifacts": "none"},
        {"artifacts": [{"name": "a.exe", "sha256": "zz", "size": 1, "url": INSTALLER_URL}]},
        {"artifacts": [{"name": "a.exe", "sha256": "A" * 64, "size": 1, "url": INSTALLER_URL}]},
        {"artifacts": [{"name": "a.exe", "sha256": "a" * 64, "size": -1, "url": INSTALLER_URL}]},
        {"artifacts": [{"name": "a.exe", "sha256": "a" * 64, "size": 1, "url": "http://x.test/a"}]},
        {"artifacts": [{"name": "../a.exe", "sha256": "a" * 64, "size": 1, "url": INSTALLER_URL}]},
        {"artifacts": [{"name": "a.exe", "sha256": "a" * 64, "size": 1}]},
        {
            "artifacts": [
                {"name": "a.exe", "sha256": "a" * 64, "size": 1, "url": INSTALLER_URL, "run": 1}
            ]
        },
    ],
)
def test_signed_but_invalid_manifest_fields_are_rejected(
    publisher: Publisher, overrides: dict
) -> None:
    with pytest.raises(updates.UpdateCheckError, match="could not be verified"):
        check(publisher.sign(make_manifest(**overrides)))


def test_missing_manifest_field_is_rejected(publisher: Publisher) -> None:
    manifest = make_manifest()
    del manifest["min_supported_version"]
    with pytest.raises(updates.UpdateCheckError, match="could not be verified"):
        check(publisher.sign(manifest))


def test_http_feed_url_is_rejected_before_any_request(publisher: Publisher, monkeypatch) -> None:
    monkeypatch.setattr(updates, "RELEASE_FEED_URL", "http://updates.example.test/stable.json")

    def unexpected_opener(*_args):
        raise AssertionError("an HTTP feed must never be requested")

    with pytest.raises(updates.UpdateCheckError, match="HTTPS"):
        updates.check_for_updates(opener_factory=unexpected_opener)


# ---------------------------------------------------------------------------
# Anti-freeze and rollback protection
# ---------------------------------------------------------------------------


def test_manifest_published_long_before_the_build_is_rejected(publisher: Publisher) -> None:
    # 400 days before BUILD_DATE (2026-10-05) is 2025-08-31; one day earlier is stale.
    stale = publisher.sign(make_manifest(published="2025-08-30T00:00:00Z"))
    with pytest.raises(updates.UpdateCheckError, match="could not be verified"):
        check(stale)

    fresh = publisher.sign(make_manifest(published="2025-08-31T00:00:00+00:00"))
    assert check(fresh) is not None


def test_published_with_timezone_offset_is_normalised(publisher: Publisher) -> None:
    # 2025-08-30T22:00:00-03:00 is 2025-08-31T01:00:00Z: inside the window.
    assert check(publisher.sign(make_manifest(published="2025-08-30T22:00:00-03:00"))) is not None


def test_replayed_lower_sequence_is_rejected(publisher: Publisher) -> None:
    assert check(publisher.sign(make_manifest(sequence=7))) is not None
    # Same sequence again (the same manifest refetched) is fine.
    assert check(publisher.sign(make_manifest(sequence=7))) is not None
    # A newer manifest advances the stored sequence.
    assert check(publisher.sign(make_manifest(sequence=9, app_version="0.5.0"))) is not None

    # Replaying a validly signed older manifest must now fail.
    with pytest.raises(updates.UpdateCheckError, match="could not be verified"):
        check(publisher.sign(make_manifest(sequence=8, app_version="0.4.5")))
    with pytest.raises(updates.UpdateCheckError, match="could not be verified"):
        check(publisher.sign(make_manifest(sequence=7)))

    state = json.loads((config.data_dir() / "update-state.json").read_text("utf-8"))
    assert state == {"last_sequence": 9}


def test_rollback_state_is_persisted_in_the_app_data_dir(
    publisher: Publisher, tmp_path: Path
) -> None:
    check(publisher.sign(make_manifest(sequence=3)))
    assert updates.update_state_path() == tmp_path / "data" / "update-state.json"
    assert updates.update_state_path().is_file()


def test_corrupt_rollback_state_is_treated_as_unknown_and_replaced(publisher: Publisher) -> None:
    path = updates.update_state_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("{not json", encoding="utf-8")

    assert check(publisher.sign(make_manifest(sequence=2))) is not None
    assert json.loads(path.read_text("utf-8")) == {"last_sequence": 2}


def test_state_is_not_updated_when_verification_fails(publisher: Publisher) -> None:
    check(publisher.sign(make_manifest(sequence=5)))
    with pytest.raises(updates.UpdateCheckError):
        check(publisher.sign(make_manifest(sequence=50, app_version="bad")))
    state = json.loads(updates.update_state_path().read_text("utf-8"))
    assert state == {"last_sequence": 5}


# ---------------------------------------------------------------------------
# Transport hardening
# ---------------------------------------------------------------------------


def test_manifest_size_limit_is_64kb_and_enforced(publisher: Publisher) -> None:
    assert updates.MAX_MANIFEST_BYTES == 65536
    oversized = b" " * (updates.MAX_MANIFEST_BYTES + 1)
    with pytest.raises(updates.UpdateCheckError, match="too large"):
        check(oversized)


def test_declared_oversize_is_rejected_before_reading(publisher: Publisher) -> None:
    body = publisher.sign(make_manifest())
    response = FakeResponse(body, {"Content-Length": str(updates.MAX_MANIFEST_BYTES + 1)})
    response.read = lambda _size: pytest.fail("oversized responses must not be read")
    with pytest.raises(updates.UpdateCheckError, match="too large"):
        updates.check_for_updates(opener_factory=lambda *_a: FakeOpener(response))


def test_non_200_response_is_rejected(publisher: Publisher) -> None:
    response = FakeResponse(publisher.sign(make_manifest()))
    response.status = 304
    with pytest.raises(updates.UpdateCheckError, match="unexpected response"):
        updates.check_for_updates(opener_factory=lambda *_a: FakeOpener(response))


def test_feed_request_identifies_as_the_app_not_python_urllib(publisher: Publisher) -> None:
    # Cloudflare blocks the default "Python-urllib/x.y" agent (error 1010).
    opener = FakeOpener(FakeResponse(publisher.sign(make_manifest())))
    updates.check_for_updates(opener_factory=lambda *_a: opener)
    assert opener.request.get_header("User-agent") == f"LocalGateKeys/{updates.APP_VERSION}"


@pytest.mark.parametrize(
    ("code", "message"),
    [(404, "No release has been published yet."),
     (403, "The release feed returned an unexpected response."),
     (500, "The release feed returned an unexpected response.")],
)
def test_http_errors_are_not_reported_as_unreachable(
    publisher: Publisher, code: int, message: str
) -> None:
    import io
    import urllib.error

    class ErrorOpener:
        def open(self, _request, *, timeout):
            raise urllib.error.HTTPError(FEED_URL, code, "error", {}, io.BytesIO(b""))

    with pytest.raises(updates.UpdateCheckError) as excinfo:
        updates.check_for_updates(opener_factory=lambda *_a: ErrorOpener())
    assert str(excinfo.value) == message


def test_transport_errors_do_not_leak_the_url(publisher: Publisher) -> None:
    class FailingOpener:
        def open(self, _request, *, timeout):
            raise OSError(f"connection refused to {FEED_URL}")

    with pytest.raises(updates.UpdateCheckError) as excinfo:
        updates.check_for_updates(opener_factory=lambda *_a: FailingOpener())
    assert FEED_URL not in str(excinfo.value)
    assert "example.test" not in str(excinfo.value)


def test_verification_errors_do_not_leak_urls(publisher: Publisher) -> None:
    with pytest.raises(updates.UpdateCheckError) as excinfo:
        check(publisher.sign(make_manifest(notes_url="http://leak.example.test/notes")))
    assert "leak.example.test" not in str(excinfo.value)
    assert "example.test" not in str(excinfo.value)


def test_feed_redirect_handler_rejects_cross_origin_and_allows_same_origin() -> None:
    handler = updates._SameOriginRedirectHandler(updates._origin(FEED_URL))
    original = Request(FEED_URL)

    with pytest.raises(updates.UpdateCheckError, match="different origin"):
        handler.redirect_request(
            original, None, 302, "Found", {}, "https://evil.example/redirected.json"
        )
    with pytest.raises(updates.UpdateCheckError):
        handler.redirect_request(
            original, None, 302, "Found", {}, "http://updates.example.test/stable.json"
        )
    redirected = handler.redirect_request(original, None, 302, "Found", {}, "/v2/stable.json")
    assert redirected is not None
    assert redirected.full_url == "https://updates.example.test/v2/stable.json"


# ---------------------------------------------------------------------------
# Release page: only the verified notes_url is ever opened
# ---------------------------------------------------------------------------


def test_open_release_page_uses_only_the_verified_notes_url(
    publisher: Publisher, monkeypatch: pytest.MonkeyPatch
) -> None:
    opened: list[tuple[str, int]] = []
    monkeypatch.setattr(
        updates.webbrowser, "open", lambda url, new: opened.append((url, new)) or True
    )

    with pytest.raises(updates.UpdateCheckError, match="verified"):
        updates.open_release_page()
    assert opened == []

    check(publisher.sign(make_manifest()))
    assert updates.open_release_page()
    assert opened == [(NOTES_URL, 2)]


def test_failed_check_clears_previously_verified_release_page(
    publisher: Publisher, monkeypatch: pytest.MonkeyPatch
) -> None:
    opened: list[str] = []
    monkeypatch.setattr(updates.webbrowser, "open", lambda url, new: opened.append(url) or True)
    check(publisher.sign(make_manifest()))
    with pytest.raises(updates.UpdateCheckError):
        check(b"garbage")
    with pytest.raises(updates.UpdateCheckError):
        updates.open_release_page()
    assert opened == []


def test_canonical_json_is_sorted_compact_and_utf8() -> None:
    assert updates.canonical_json({"b": 1, "a": [1, {"d": "é", "c": None}]}) == (
        b'{"a":[1,{"c":null,"d":"\xc3\xa9"}],"b":1}'
    )


# ---------------------------------------------------------------------------
# scripts/sign_release_manifest.py
# ---------------------------------------------------------------------------


def run_script(*args: str, env: dict[str, str] | None = None) -> subprocess.CompletedProcess:
    import os

    full_env = dict(os.environ)
    full_env.update(env or {})
    return subprocess.run(
        [sys.executable, str(SCRIPT), *args],
        capture_output=True,
        text=True,
        env=full_env,
        check=False,
    )


def test_signing_script_keygen_sign_verify_roundtrip(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    key_path = tmp_path / "release-key.pem"
    env = {"LGK_TEST_KEY_PASSWORD": "correct horse battery staple"}

    keygen = run_script(
        "keygen", "--out", str(key_path), "--password-env", "LGK_TEST_KEY_PASSWORD", env=env
    )
    assert keygen.returncode == 0, keygen.stderr
    output = json.loads(keygen.stdout)
    public_b64 = output["public_key"]
    key_id = output["key_id"]
    assert len(key_id) == 16 and int(key_id, 16) >= 0
    assert len(base64.b64decode(public_b64)) == 32
    pem = key_path.read_bytes()
    assert b"ENCRYPTED" in pem
    # key_id is the first 8 bytes of SHA-256 of the raw public key.
    assert key_id == hashlib.sha256(base64.b64decode(public_b64)).digest()[:8].hex()

    installer = tmp_path / "LocalGateKeys-Setup-Personal.exe"
    installer.write_bytes(b"MZ" + b"\x00" * 1000)
    manifest = make_manifest()
    manifest["artifacts"][0]["sha256"] = "0" * 64
    manifest["artifacts"][0]["size"] = 0
    manifest["sequence"] = 0
    manifest_path = tmp_path / "manifest.json"
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    signed_path = tmp_path / "signed.json"

    sign = run_script(
        "sign", "--manifest", str(manifest_path), "--key", str(key_path),
        "--password-env", "LGK_TEST_KEY_PASSWORD", "--artifact", str(installer),
        "--sequence", "42", "--out", str(signed_path), env=env,
    )
    assert sign.returncode == 0, sign.stderr
    bundle = json.loads(signed_path.read_text("utf-8"))
    assert bundle["signature"]["key_id"] == key_id
    assert bundle["signature"]["alg"] == "Ed25519"
    assert bundle["manifest"]["sequence"] == 42
    expected_digest = hashlib.sha256(installer.read_bytes()).hexdigest()
    assert bundle["manifest"]["artifacts"][0]["sha256"] == expected_digest
    assert bundle["manifest"]["artifacts"][0]["size"] == installer.stat().st_size

    verify = run_script("verify", "--bundle", str(signed_path), "--public-key", public_b64)
    assert verify.returncode == 0, verify.stderr
    assert "OK" in verify.stdout

    tampered = copy.deepcopy(bundle)
    tampered["manifest"]["app_version"] = "9.9.9"
    tampered_path = tmp_path / "tampered.json"
    tampered_path.write_text(json.dumps(tampered), encoding="utf-8")
    bad = run_script("verify", "--bundle", str(tampered_path), "--public-key", public_b64)
    assert bad.returncode != 0

    # The client accepts exactly what the script produced.
    monkeypatch.setattr(updates, "RELEASE_FEED_URL", FEED_URL)
    monkeypatch.setattr(updates, "PUBLISHER_KEYS", {key_id: public_b64})
    monkeypatch.setattr(updates, "BUILD_DATE", BUILD_DATE)
    monkeypatch.setenv("LOCALGATEKEYS_DATA_DIR", str(tmp_path / "data"))
    result = check(signed_path.read_bytes(), current_version="0.3.3")
    assert result is not None and result.is_newer and result.sequence == 42


def test_signing_script_works_without_a_key_file(tmp_path: Path) -> None:
    # keygen --print-key puts only the encrypted PEM on stdout (for `| clip`)
    # and sign --key-env reads it back, as pasted from a password manager.
    keygen = run_script("keygen", "--print-key", "--password-env", "P", env={"P": "pw"})
    assert keygen.returncode == 0, keygen.stderr
    pem = keygen.stdout
    assert pem.startswith("-----BEGIN ENCRYPTED PRIVATE KEY-----")
    assert pem.rstrip().endswith("-----END ENCRYPTED PRIVATE KEY-----")
    public = json.loads(keygen.stderr[: keygen.stderr.index("}") + 1])
    assert list(tmp_path.iterdir()) == []

    manifest_path = tmp_path / "m.json"
    manifest_path.write_text(json.dumps(make_manifest()), encoding="utf-8")
    out = tmp_path / "s.json"
    pasted = "  " + pem.replace("\n", "\r\n") + "\r\n"
    sign = run_script("sign", "--manifest", str(manifest_path), "--key-env", "K",
                      "--password-env", "P", "--out", str(out), env={"P": "pw", "K": pasted})
    assert sign.returncode == 0, sign.stderr
    verify = run_script("verify", "--bundle", str(out), "--public-key", public["public_key"])
    assert verify.returncode == 0, verify.stderr

    missing = run_script("sign", "--manifest", str(manifest_path), "--key-env", "UNSET_LGK_KEY",
                         "--password-env", "P", "--out", str(tmp_path / "x.json"),
                         env={"P": "pw"})
    assert missing.returncode != 0 and "UNSET_LGK_KEY" in missing.stderr


def test_signing_script_refuses_wrong_password_and_invalid_manifest(tmp_path: Path) -> None:
    key_path = tmp_path / "k.pem"
    keygen_args = ("keygen", "--out", str(key_path), "--password-env", "P")
    assert run_script(*keygen_args, env={"P": "pw"}).returncode == 0
    manifest_path = tmp_path / "m.json"
    manifest_path.write_text(json.dumps(make_manifest()), encoding="utf-8")
    out = tmp_path / "s.json"

    wrong = run_script("sign", "--manifest", str(manifest_path), "--key", str(key_path),
                       "--password-env", "P", "--out", str(out), env={"P": "wrong"})
    assert wrong.returncode != 0 and not out.exists()

    manifest_path.write_text(json.dumps(make_manifest(notes_url="http://x.test")), encoding="utf-8")
    invalid = run_script("sign", "--manifest", str(manifest_path), "--key", str(key_path),
                         "--password-env", "P", "--out", str(out), env={"P": "pw"})
    assert invalid.returncode != 0 and not out.exists()
    assert "notes_url" in invalid.stderr

    assert run_script(*keygen_args, env={"P": "pw"}).returncode != 0, (
        "keygen must not overwrite an existing key file"
    )


# ---------------------------------------------------------------------------
# UI integration (unchanged contract: not configured / offline / threading)
# ---------------------------------------------------------------------------


def test_build_age_and_reminder_are_decided_without_network(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from datetime import date

    monkeypatch.setattr(updates, "BUILD_DATE", "2026-01-01")
    fresh = date(2026, 3, 31)  # 89 days
    stale = date(2026, 4, 1)   # 90 days
    assert updates.build_age_days(fresh) == 89
    assert updates.build_age_days(date(2025, 12, 1)) == 0
    assert not updates.update_reminder_due("", fresh)
    assert updates.update_reminder_due("", stale)
    assert updates.update_reminder_due("garbage", stale)

    snooze = updates.reminder_snooze_date(stale)
    assert snooze == "2026-05-01"
    assert not updates.update_reminder_due(snooze, date(2026, 4, 30))
    assert updates.update_reminder_due(snooze, date(2026, 5, 1))


def test_settings_reject_a_malformed_reminder_date(tmp_path: Path) -> None:
    path = tmp_path / "settings.json"
    AppSettings(update_reminder_snoozed_until="2026-11-14").save(path)
    assert AppSettings.load(path).update_reminder_snoozed_until == "2026-11-14"
    raw = json.loads(path.read_text("utf-8"))
    for bad in ("tomorrow", 5, "2026-13-01", "20261114"):
        raw["update_reminder_snoozed_until"] = bad
        path.write_text(json.dumps(raw), "utf-8")
        assert AppSettings.load(path).update_reminder_snoozed_until == ""


def test_tray_has_manual_check_for_updates_action(monkeypatch: pytest.MonkeyPatch) -> None:
    menu_items = []
    calls = []

    class FakeMenu:
        SEPARATOR = object()

        def __init__(self, *items) -> None:
            self.items = items

    class FakeMenuItem:
        def __init__(self, text, action, **_kwargs) -> None:
            self.text = text
            self.action = action
            menu_items.append(self)

    class FakeIcon:
        def __init__(self, _name, _image, _title, menu) -> None:
            self.menu = menu

        def run(self) -> None:
            return None

    fake_pystray = types.ModuleType("pystray")
    fake_pystray.Menu = FakeMenu
    fake_pystray.MenuItem = FakeMenuItem
    fake_pystray.Icon = FakeIcon
    fake_pil = types.ModuleType("PIL")
    fake_image = types.ModuleType("PIL.Image")
    fake_image.open = lambda _path: (_ for _ in ()).throw(OSError("asset unavailable"))
    fake_image.new = lambda *_args, **_kwargs: object()
    fake_image_ops = types.ModuleType("PIL.ImageOps")
    fake_pil.Image = fake_image
    fake_pil.ImageOps = fake_image_ops
    monkeypatch.setitem(sys.modules, "pystray", fake_pystray)
    monkeypatch.setitem(sys.modules, "PIL", fake_pil)
    monkeypatch.setitem(sys.modules, "PIL.Image", fake_image)
    monkeypatch.setitem(sys.modules, "PIL.ImageOps", fake_image_ops)

    tray = TrayController(
        on_open=lambda: None,
        on_lock=lambda: None,
        on_unlock=lambda: None,
        on_toggle_browser=lambda: None,
        on_toggle_desktop=lambda: None,
        on_exit=lambda: None,
        state=dict,
        on_check_updates=lambda: calls.append("checked"),
    )
    tray._run()
    action = next(item for item in menu_items if item.text == "Check for updates")
    action.action()

    assert calls == ["checked"]


# ---------------------------------------------------------------------------
# Signed revocation list
# ---------------------------------------------------------------------------

ID_A = "lgk_" + "0" * 26
ID_B = "lgk_" + "7" * 25 + "Z"


def make_revocations(revoked=(ID_A, ID_B), **overrides) -> dict:
    manifest = {"format": 1, "published": "2026-10-10T00:00:00Z", "revoked": list(revoked)}
    manifest.update(overrides)
    return manifest


def fetch_revocations(body: bytes):
    opener = FakeOpener(FakeResponse(body))
    result = updates.fetch_revocations(opener_factory=lambda *_args: opener)
    return result, opener


def test_revocations_verify_and_cache(publisher: Publisher) -> None:
    assert updates.REVOCATIONS_URL.endswith("/revocations.json")
    assert updates.cached_revocations() == frozenset()
    result, opener = fetch_revocations(publisher.sign(make_revocations()))
    assert result == frozenset({ID_A, ID_B})
    assert opener.request.full_url == "https://updates.example.test/revocations.json"
    assert updates.revocation_cache_path() == config.data_dir() / "revocations.json"
    assert updates.cached_revocations() == frozenset({ID_A, ID_B})
    cached = json.loads(updates.revocation_cache_path().read_text("utf-8"))
    assert set(cached) == {"manifest", "signature"}


def test_revocations_larger_than_the_feed_limit_are_accepted(publisher: Publisher) -> None:
    ids = [f"lgk_{n:026d}" for n in range(10000)]
    body = publisher.sign(make_revocations(ids))
    assert len(body) > updates.MAX_MANIFEST_BYTES
    result, _ = fetch_revocations(body)
    assert len(result) == 10000
    assert len(updates.cached_revocations()) == 10000


def test_revocations_bad_signature_keeps_cache(publisher: Publisher) -> None:
    fetch_revocations(publisher.sign(make_revocations()))
    other = Publisher()
    forged = other.sign(make_revocations(revoked=[]), key_id=publisher.key_id)
    with pytest.raises(updates.UpdateCheckError):
        fetch_revocations(forged)
    assert updates.cached_revocations() == frozenset({ID_A, ID_B})


def test_revocations_unreachable_keeps_cache(publisher: Publisher) -> None:
    fetch_revocations(publisher.sign(make_revocations()))

    class Offline:
        def open(self, *_args, **_kwargs):
            raise OSError("offline")

    with pytest.raises(updates.UpdateCheckError):
        updates.fetch_revocations(opener_factory=lambda *_args: Offline())
    assert updates.cached_revocations() == frozenset({ID_A, ID_B})


def test_revocations_older_list_does_not_replace_newer_cache(publisher: Publisher) -> None:
    fetch_revocations(publisher.sign(make_revocations()))
    old = publisher.sign(make_revocations(revoked=[], published="2026-09-01T00:00:00Z"))
    with pytest.raises(updates.UpdateCheckError):
        fetch_revocations(old)
    assert updates.cached_revocations() == frozenset({ID_A, ID_B})


@pytest.mark.parametrize(
    "mutate",
    [
        lambda m: m.update(extra=1),
        lambda m: m.pop("published"),
        lambda m: m.update(format=2),
        lambda m: m.update(revoked="lgk_x"),
        lambda m: m.update(revoked=["lic-0001"]),
        lambda m: m.update(revoked=[ID_B.lower()]),
        lambda m: m.update(revoked=[f"lgk_{n:026d}" for n in range(10001)]),
        lambda m: m.update(published="yesterday"),
    ],
)
def test_revocations_rejects_extra_field(publisher: Publisher, mutate) -> None:
    manifest = make_revocations()
    mutate(manifest)
    with pytest.raises(updates.UpdateCheckError):
        fetch_revocations(publisher.sign(manifest))
    assert not updates.revocation_cache_path().exists()
    assert updates.cached_revocations() == frozenset()


def test_cached_revocations_are_reverified_on_load(publisher: Publisher) -> None:
    fetch_revocations(publisher.sign(make_revocations()))
    path = updates.revocation_cache_path()
    bundle = json.loads(path.read_text("utf-8"))
    bundle["manifest"]["revoked"] = []
    path.write_text(json.dumps(bundle), encoding="utf-8")
    # The tampered cache no longer verifies; the signed copy next to the licence still does.
    assert updates.cached_revocations() == frozenset({ID_A, ID_B})
    memory = updates.revocation_memory_path()
    memory.write_text(json.dumps(bundle), encoding="utf-8")
    assert updates.cached_revocations() == frozenset()
    path.write_bytes(b"not json")
    memory.write_bytes(b"not json")
    assert updates.cached_revocations() == frozenset()


def test_revocations_unconfigured_does_nothing(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(updates, "PUBLISHER_KEYS", {})
    result = updates.fetch_revocations(opener_factory=lambda *_a: pytest.fail("network"))
    assert result == frozenset()
    assert updates.cached_revocations() == frozenset()


def test_stable_manifest_unchanged(publisher: Publisher) -> None:
    # stable.json keeps its exact field set; revocation fields are not accepted there.
    assert check(publisher.sign(make_manifest())).latest_version == "0.4.0"
    with pytest.raises(updates.UpdateCheckError):
        check(publisher.sign(make_manifest(revoked=[])))
    with pytest.raises(updates.UpdateCheckError):
        updates.validate_manifest(make_revocations())


def test_signing_script_revocations_roundtrip(tmp_path: Path) -> None:
    key_path = tmp_path / "key.pem"
    env = {"LGK_TEST_KEY_PASSWORD": "correct horse battery staple"}
    keygen = run_script(
        "keygen", "--out", str(key_path), "--password-env", "LGK_TEST_KEY_PASSWORD", env=env
    )
    assert keygen.returncode == 0, keygen.stderr
    public_b64 = json.loads(keygen.stdout)["public_key"]
    ids = tmp_path / "ids.txt"
    ids.write_text(f"# refunded\n{ID_B}\n\n{ID_A}\n{ID_A}\n", encoding="utf-8")
    out = tmp_path / "revocations.json"
    signed = run_script(
        "revocations", "--key", str(key_path), "--ids-file", str(ids), "--out", str(out),
        "--password-env", "LGK_TEST_KEY_PASSWORD", "--published", "2026-10-10T00:00:00Z",
        env=env,
    )
    assert signed.returncode == 0, signed.stderr
    bundle = json.loads(out.read_text("utf-8"))
    assert bundle["manifest"] == make_revocations(revoked=sorted({ID_A, ID_B}))
    keys = updates._load_publisher_keys(
        {bundle["signature"]["key_id"]: public_b64}, verify_key_ids=True
    )
    manifest = updates._verified_revocations(out.read_bytes(), keys)
    assert manifest["revoked"] == sorted({ID_A, ID_B})

    ids.write_text("lic-0001\n", encoding="utf-8")
    bad = run_script(
        "revocations", "--key", str(key_path), "--ids-file", str(ids),
        "--out", str(tmp_path / "x"), "--password-env", "LGK_TEST_KEY_PASSWORD", env=env,
    )
    assert bad.returncode == 2


