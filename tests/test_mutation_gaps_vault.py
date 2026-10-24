"""Tests that close gaps found by mutation testing of ``localvault.vault`` (2026-10-24).

Rollback anchor (each protection layer on its own), anchor metadata bounds,
size limits, header/catalog generation binding, the v3 AAD and
``verify_master_password`` on locked sessions and on v1/v2 envelopes.
"""
from __future__ import annotations

import io
import json
import os
from pathlib import Path
from types import SimpleNamespace

import pytest
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from test_next_release_faults import _write_legacy_vault

from localvault import vault
from localvault.vault import (
    InvalidMasterPassword,
    VaultError,
    VaultLockedError,
    create_vault,
    unlock_vault,
)

KDF = {"time_cost": 1, "memory_cost_kib": 8192, "parallelism": 1, "hash_len": 32}
MASTER = "mutation-gaps-master-password"
WRONG = "not-the-mutation-gaps-password"
ANCHOR_KEY = bytes(range(32))
VAULT_ID = "0123456789abcdef0123456789abcdef"


def _protection(generation: int = 5, vault_id: str = VAULT_ID, key: bytes = ANCHOR_KEY, **extra) -> dict:
    record = vault._anchor_protection(key, generation, vault_id, seal=False)
    record.update(extra)
    return record


def _matches(protection, generation: int = 5, vault_id: str = VAULT_ID, key=ANCHOR_KEY, **kwargs) -> bool:
    return vault._anchor_protection_matches(protection, key, generation, vault_id, **kwargs)


# --- _anchor_protection_matches: one layer at a time ---------------------------------------


def test_valid_anchor_protection_matches() -> None:
    assert _matches(_protection()) is True
    assert _protection()["dpapi"] is None


@pytest.mark.parametrize("scheme", ["hkdf-hmac-sha256-v2", "", None, "HKDF-HMAC-SHA256-V1"])
def test_unknown_anchor_scheme_is_refused_even_with_a_valid_mac(scheme) -> None:
    assert _matches(_protection(scheme=scheme)) is False
    record = _protection()
    del record["scheme"]
    assert _matches(record) is False


@pytest.mark.parametrize("protection", [None, [], "anchor", 5])
def test_non_object_anchor_protection_is_refused(protection) -> None:
    assert _matches(protection) is False


def test_forged_mac_without_dpapi_is_refused() -> None:
    """The HMAC on its own: no DPAPI seal ("dpapi": null) must not mean "trusted"."""
    forged = _protection(key=b"\x55" * 32)
    assert forged["dpapi"] is None
    assert _matches(forged) is False
    # Right key, wrong generation: the MAC binds the generation.
    assert _matches(_protection(generation=4)) is False
    assert _matches(_protection(), generation=6) is False


def test_forged_anchor_file_without_dpapi_raises(tmp_path: Path) -> None:
    path = tmp_path / "vault.json"
    vault.atomic_write_json(vault._generation_anchor_path(path),
                            {"version": 1, "generation": 9, "anchor": _protection(9, key=b"\x01" * 32)})
    with pytest.raises(VaultError, match="failed authentication"):
        vault._read_generation_anchor(path, ANCHOR_KEY, VAULT_ID, require_mac=True)
    # The genuine record is accepted.
    vault.atomic_write_json(vault._generation_anchor_path(path),
                            {"version": 1, "generation": 9, "anchor": _protection(9)})
    assert vault._read_generation_anchor(path, ANCHOR_KEY, VAULT_ID, require_mac=True) == (9, False)


def test_anchor_for_another_vault_id_is_refused() -> None:
    # The MAC is computed over the record's own vault_id, so it verifies; the id check must refuse it.
    other = _protection(vault_id="f" * 32)
    assert _matches(other) is False
    # A record without a vault id (older anchors) and a caller without one are still accepted.
    assert _matches(_protection(vault_id="")) is True
    assert _matches(other, vault_id="") is True


def test_dpapi_layer_on_its_own(monkeypatch) -> None:
    """A valid MAC with a DPAPI seal that opens to something else is refused."""
    record = _protection(dpapi="c2VhbGVk")
    expected = vault._anchor_mac(ANCHOR_KEY, 5, VAULT_ID)
    opened: dict[str, object] = {}

    def unprotect(value, entropy):
        opened["value"], opened["entropy"] = value, entropy
        return result["value"]

    result = {"value": b"\x00" * 32}
    monkeypatch.setattr(vault, "_dpapi_unprotect", unprotect)
    assert _matches(record) is False
    assert opened == {"value": "c2VhbGVk", "entropy": expected}
    result["value"] = expected
    assert _matches(record) is True
    result["value"] = None  # DPAPI unavailable here: the HMAC alone decides
    assert _matches(record) is True
    # check_dpapi=False (the "previous" record of a rotation) never opens the seal.
    result["value"] = b"\x00" * 32
    assert _matches(record, check_dpapi=False) is True


def test_dpapi_failure_is_refused(monkeypatch) -> None:
    def broken(_value, _entropy):
        raise ValueError("DPAPI unprotect failed")

    monkeypatch.setattr(vault, "_dpapi_unprotect", broken)
    assert _matches(_protection(dpapi="c2VhbGVk")) is False
    assert _matches(_protection(dpapi="")) is True  # empty seal: nothing to open


def test_exceptions_inside_the_check_mean_no_match() -> None:
    assert _matches(_protection(), key=None) is False
    assert _matches(_protection(), key="not-bytes") is False


# --- _read_generation_anchor bounds --------------------------------------------------------


def _write_anchor(path: Path, record) -> None:
    anchor = vault._generation_anchor_path(path)
    anchor.write_text(record if isinstance(record, str) else json.dumps(record), encoding="utf-8")


def test_anchor_over_64_kib_is_malformed(tmp_path: Path) -> None:
    path = tmp_path / "vault.json"
    _write_anchor(path, {"version": 1, "generation": 3, "padding": "x" * (64 * 1024)})
    with pytest.raises(VaultError, match="malformed"):
        vault._read_generation_anchor(path)
    _write_anchor(path, {"version": 1, "generation": 3, "padding": "x" * (60 * 1024)})
    assert vault._read_generation_anchor(path) == (3, True)


@pytest.mark.parametrize("generation", ["3", 3.0, True, None, -1, 2**63, [3], {"g": 3}])
def test_anchor_generation_type_and_range(tmp_path: Path, generation) -> None:
    path = tmp_path / "vault.json"
    _write_anchor(path, {"version": 1, "generation": generation})
    with pytest.raises(VaultError, match="malformed"):
        vault._read_generation_anchor(path)


@pytest.mark.parametrize("generation", [0, 2**63 - 1])
def test_anchor_generation_range_is_inclusive(tmp_path: Path, generation) -> None:
    path = tmp_path / "vault.json"
    _write_anchor(path, {"version": 1, "generation": generation})
    assert vault._read_generation_anchor(path) == (generation, True)


@pytest.mark.parametrize("text", ["{not json", "[]", "null", '"x"'])
def test_unreadable_anchor_is_malformed(tmp_path: Path, text) -> None:
    path = tmp_path / "vault.json"
    _write_anchor(path, text)
    with pytest.raises(VaultError, match="malformed"):
        vault._read_generation_anchor(path)


def test_failed_anchor_write_is_not_ignored(tmp_path: Path, monkeypatch) -> None:
    path = tmp_path / "vault.json"

    def refuse(*_args, **_kwargs):
        raise OSError("read-only folder")

    monkeypatch.setattr(vault, "_write_generation_anchor", refuse)
    with pytest.raises(VaultError, match="Could not update vault rollback-protection"):
        vault._check_generation_anchor(path, {"generation": 4}, ANCHOR_KEY, VAULT_ID)


def test_failed_anchor_write_fails_the_unlock(tmp_path: Path, monkeypatch) -> None:
    path = tmp_path / "vault.json"
    session = create_vault(path, MASTER, kdf_overrides=KDF)
    session.lock()
    vault._generation_anchor_path(path).unlink()

    def refuse(*_args, **_kwargs):
        raise OSError("read-only folder")

    monkeypatch.setattr(vault, "_write_generation_anchor", refuse)
    with pytest.raises(VaultError, match="Could not update vault rollback-protection"):
        unlock_vault(path, MASTER)


# --- size limit ---------------------------------------------------------------------------


def test_oversized_vault_is_refused_before_it_is_read(tmp_path: Path, monkeypatch) -> None:
    path = tmp_path / "vault.json"
    path.write_bytes(b"{" + b" " * 200 + b"}")
    monkeypatch.setattr(vault, "MAX_VAULT_BYTES", 100)
    opened = []
    real_open = Path.open

    def tracking_open(self, *args, **kwargs):
        if self == path:
            opened.append(self)
        return real_open(self, *args, **kwargs)

    monkeypatch.setattr(Path, "open", tracking_open)
    with pytest.raises(VaultError, match="size limit"):
        vault._read_vault_header(path)
    assert opened == []
    with pytest.raises(VaultError, match="size limit"):
        unlock_vault(path, MASTER)


def test_vault_that_grows_after_stat_is_refused(monkeypatch) -> None:
    """The second check: the bytes actually read are bounded too (the file can grow after stat)."""
    monkeypatch.setattr(vault, "MAX_VAULT_BYTES", 100)
    body = b"{" + b" " * 200 + b"}"
    fake = SimpleNamespace(stat=lambda: SimpleNamespace(st_size=10), open=lambda _mode="rb": io.BytesIO(body))
    with pytest.raises(VaultError, match="size limit"):
        vault._read_vault_header(fake)  # type: ignore[arg-type]


def test_vault_at_the_size_limit_is_read(monkeypatch) -> None:
    monkeypatch.setattr(vault, "MAX_VAULT_BYTES", 100)
    body = b"[" + b" " * 98 + b"]"
    fake = SimpleNamespace(stat=lambda: SimpleNamespace(st_size=100), open=lambda _mode="rb": io.BytesIO(body))
    with pytest.raises(VaultError, match="must be an object"):
        vault._read_vault_header(fake)  # type: ignore[arg-type]


# --- header generation bound to the encrypted catalog -----------------------------------------


def _reencrypt_with_generation(path: Path, password: str, generation: int) -> None:
    """Re-encrypt the catalog with another ``generation`` under the same (valid) header and AAD."""
    session = unlock_vault(path, password)
    key = bytes(session._key)
    session.lock()
    header = json.loads(path.read_bytes())
    plaintext = AESGCM(key).decrypt(vault._b64d(header["cipher"]["nonce"]),
                                    vault._b64d(header["cipher"]["ciphertext"]), vault._aad(header))
    payload = json.loads(plaintext)
    payload["generation"] = generation
    nonce = os.urandom(12)
    header["cipher"]["nonce"] = vault._b64e(nonce)
    header["cipher"]["ciphertext"] = vault._b64e(AESGCM(key).encrypt(nonce, vault._canonical_json(payload),
                                                                     vault._aad(header)))
    path.write_bytes(json.dumps(header).encode("utf-8"))


@pytest.mark.parametrize("delta", [-1, +1, +5])
def test_header_generation_must_equal_the_encrypted_generation(tmp_path: Path, delta) -> None:
    path = tmp_path / "vault.json"
    session = create_vault(path, MASTER, kdf_overrides=KDF)
    session.save()
    session.lock()
    header_generation = json.loads(path.read_bytes())["generation"]
    _reencrypt_with_generation(path, MASTER, header_generation + delta)
    with pytest.raises(VaultError, match="generation does not match"):
        unlock_vault(path, MASTER)


def test_reencrypted_with_the_same_generation_still_opens(tmp_path: Path) -> None:
    path = tmp_path / "vault.json"
    create_vault(path, MASTER, kdf_overrides=KDF).lock()
    _reencrypt_with_generation(path, MASTER, json.loads(path.read_bytes())["generation"])
    unlock_vault(path, MASTER).lock()


# --- v3 AAD -------------------------------------------------------------------------------


def _v3_header(**overrides) -> dict:
    header = {"version": 3, "format": vault.FORMAT_V3_IDENTIFIER, "catalog": vault.CATALOG_FORMAT,
              "catalog_version": vault.CATALOG_VERSION, "vault_id": VAULT_ID, "generation": 7,
              "key_generation": 1, "kdf": {"name": "argon2id"}, "cipher": {"name": "aes-256-gcm"}}
    header.update(overrides)
    return header


def test_v3_aad_binds_vault_id_and_generation_not_the_kdf() -> None:
    aad = vault._aad(_v3_header())
    assert aad.startswith(vault.AAD_PREFIX_V3)
    assert vault._aad(_v3_header(generation=8)) != aad
    assert vault._aad(_v3_header(vault_id="f" * 32)) != aad
    assert vault._aad(_v3_header(key_generation=2)) != aad
    # The KDF is authenticated by the password wrapper, not by the catalog AAD.
    assert vault._aad(_v3_header(kdf={"name": "argon2id", "time_cost": 9})) == aad


def test_aesgcm_decrypt_fallback_uses_the_aad(monkeypatch) -> None:
    """cryptography < 44 has no ``decrypt_into``; the fallback must pass the real AAD."""
    key, nonce, aad = b"\x07" * 32, b"\x01" * 12, b"bound-aad"
    ciphertext = AESGCM(key).encrypt(nonce, b"secret catalog", aad)

    class OldAESGCM:
        def __init__(self, k):
            self._inner = AESGCM(k)

        def decrypt(self, n, c, a):
            return self._inner.decrypt(n, c, a)

    monkeypatch.setattr(vault, "AESGCM", OldAESGCM)
    assert bytes(vault._aesgcm_decrypt(key, nonce, ciphertext, aad)) == b"secret catalog"
    with pytest.raises(InvalidTag):
        vault._aesgcm_decrypt(key, nonce, ciphertext, b"")


# --- verify_master_password ------------------------------------------------------------------


@pytest.fixture
def v3_session(tmp_path: Path):
    session = create_vault(tmp_path / "v3.json", MASTER, kdf_overrides=KDF)
    yield session
    if session.is_unlocked:
        session.lock()


def test_verify_on_a_locked_session_raises_locked(v3_session) -> None:
    v3_session.lock()
    with pytest.raises(VaultLockedError):
        v3_session.verify_master_password(MASTER)
    with pytest.raises(VaultLockedError):
        v3_session._matches_key(b"\x00" * 32)
    with pytest.raises(VaultLockedError):
        v3_session._password_wrapper_matches(vault.as_secret(MASTER)[0])


def test_locked_session_never_runs_the_kdf(v3_session, monkeypatch) -> None:
    calls = []
    monkeypatch.setattr(vault, "_derive_key", lambda *a, **k: calls.append(a) or bytearray(32))
    v3_session.lock()
    with pytest.raises(VaultLockedError):
        v3_session._password_wrapper_matches(vault.as_secret(MASTER)[0])
    assert calls == []


def test_lock_during_the_kdf_reports_locked_not_a_match(v3_session, monkeypatch) -> None:
    real = vault._derive_key

    def derive_then_lock(password, kdf):
        key = real(password, kdf)
        v3_session.lock()
        return key

    monkeypatch.setattr(vault, "_derive_key", derive_then_lock)
    with pytest.raises(VaultError, match="locked") as exc:
        v3_session.verify_master_password(MASTER)
    # Neither a match nor a password failure.
    assert not isinstance(exc.value, InvalidMasterPassword)


def test_v3_verify_accepts_the_right_password_and_refuses_a_wrong_one(v3_session) -> None:
    assert v3_session.verify_master_password(MASTER) is True
    with pytest.raises(InvalidMasterPassword):
        v3_session.verify_master_password(WRONG)


def test_v1_envelope_verify(tmp_path: Path) -> None:
    path = tmp_path / "v1.json"
    _write_legacy_vault(path, MASTER)
    session = unlock_vault(path, MASTER, upgrade_envelope=False)
    try:
        assert vault._header_version(session._header) == vault.LEGACY_FORMAT_VERSION
        assert session.verify_master_password(MASTER) is True
        with pytest.raises(InvalidMasterPassword):
            session.verify_master_password(WRONG)
    finally:
        session.lock()


def _write_v2_vault(path: Path, password: str) -> None:
    """A format-2 envelope: the Argon2id output is the catalog key, the AAD binds the KDF."""
    kdf = {**vault.DEFAULT_KDF, **KDF, "salt": vault._b64e(os.urandom(16))}
    header = {"version": vault.CATALOG_ENVELOPE_VERSION, "format": vault.FORMAT_V2_IDENTIFIER,
              "catalog": vault.CATALOG_FORMAT, "kdf": kdf,
              "cipher": {"name": "aes-256-gcm", "nonce": "", "ciphertext": ""}}
    nonce = b"v2-nonce-123"
    header["cipher"]["nonce"] = vault._b64e(nonce)
    key = vault._derive_key(password, kdf)
    header["cipher"]["ciphertext"] = vault._b64e(AESGCM(bytes(key)).encrypt(
        nonce, vault._canonical_json(vault._empty_payload()), vault._aad(header)))
    vault.atomic_write_json(path, header)


def test_v2_envelope_verify(tmp_path: Path) -> None:
    path = tmp_path / "v2.json"
    _write_v2_vault(path, MASTER)
    session = unlock_vault(path, MASTER, upgrade_envelope=False)
    try:
        assert vault._header_version(session._header) == vault.CATALOG_ENVELOPE_VERSION
        assert session.verify_master_password(MASTER) is True
        with pytest.raises(InvalidMasterPassword):
            session.verify_master_password(WRONG)
        session.lock()
        with pytest.raises(VaultLockedError):
            session.verify_master_password(MASTER)
    finally:
        if session.is_unlocked:
            session.lock()
