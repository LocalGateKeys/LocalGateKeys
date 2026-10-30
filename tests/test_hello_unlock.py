"""Local envelope integration tests. The native OS provider is explicitly simulated."""
from __future__ import annotations

import base64
import json
import threading

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from localvault import hello_unlock as hello
from localvault.vault import InvalidMasterPassword, VaultError, create_vault, unlock_vault
from localvault.windows_hello import HelloCancelled, HelloError, NativeError, native_operation

MASTER = "Local-Only-Test-Master-0001"
KDF = {"memory_cost_kib": 8192, "time_cost": 1, "parallelism": 1}
PROFILE = "test-profile"


class SimulatedProvider:
    """Uses actual RSA/OAEP crypto, but does NOT simulate or certify biometrics."""
    def __init__(self):
        self.keys = {}
        self.calls = []
        self.outputs = []
        self.on_unwrap = None
        self.fail_delete = False

    def create(self, record_id, hwnd):
        self.calls.append("create")
        assert record_id not in self.keys and hwnd > 0
        self.keys[record_id] = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    def wrap(self, record_id, secret):
        self.calls.append("wrap")
        return self.keys[record_id].public_key().encrypt(bytes(secret), padding.OAEP(
            mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None))

    def unwrap(self, record_id, wrapped, hwnd):
        self.calls.append("unwrap")
        if record_id not in self.keys:
            raise HelloError("The local key no longer exists")
        try:
            result = bytearray(self.keys[record_id].decrypt(wrapped, padding.OAEP(
                mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)))
        except ValueError as exc:
            raise HelloError("Invalid protected secret") from exc
        self.outputs.append(result)
        if self.on_unwrap:
            self.on_unwrap()
        return result

    def delete(self, record_id):
        self.calls.append("delete")
        if self.fail_delete:
            raise HelloError("Simulated deletion error")
        self.keys.pop(record_id, None)


@pytest.fixture
def vault(tmp_path):
    session = create_vault(tmp_path / "vault.json", MASTER, kdf_overrides=KDF)
    session.upsert_web(origin="https://example.test", username="local-user", password="Test-Only-Site-Secret")
    yield session
    session.lock()


@pytest.fixture
def provider():
    return SimulatedProvider()


def enroll(session, provider):
    prepared = hello.prepare_enrollment(PROFILE, session.unlock_context(), 123, threading.Event(),
                                         provider_factory=lambda: provider)
    hello.commit_enrollment(session, prepared)
    return prepared


def unlock(session, provider, event=None, profile=PROFILE):
    return hello.unlock_with_hello(session.path, profile, 123, event or threading.Event(),
                                   provider_factory=lambda: provider)


def test_opt_in_no_write_until_commit_and_encrypted_roundtrip(vault, provider):
    original = vault.path.read_bytes()
    raw_key = bytes(vault._key)
    prepared = hello.prepare_enrollment(PROFILE, vault.unlock_context(), 123, threading.Event(),
                                         provider_factory=lambda: provider)
    assert not vault.hello_binding()
    assert vault.path.read_bytes() == original
    assert not hello.envelope_path(vault.path).exists()
    raw_secret = bytes(prepared.secret)
    hello.commit_enrollment(vault, prepared)
    assert prepared.committed and not any(prepared.secret)
    sidecar = hello.envelope_path(vault.path).read_bytes()
    for secret in (MASTER.encode(), b"Test-Only-Site-Secret", raw_key, raw_secret,
                   base64.b64encode(raw_key), base64.b64encode(raw_secret)):
        assert secret not in sidecar
        assert secret not in vault.path.read_bytes()
    assert b"hello_binding" not in vault.path.read_bytes()
    assert hello.has_envelope(vault.path, PROFILE)
    assert all(not any(output) for output in provider.outputs)
    vault.lock()
    result = unlock(vault, provider)
    assert result.find_web("https://example.test")[0]["password"] == "Test-Only-Site-Secret"
    result.lock()
    assert all(not any(output) for output in provider.outputs)
    assert provider.calls == ["create", "wrap", "unwrap", "unwrap"]


def test_password_still_works_with_hello_enabled(vault, provider):
    enroll(vault, provider)
    vault.lock()
    result = unlock_vault(vault.path, MASTER)
    assert result.hello_binding()
    result.lock()
    with pytest.raises(InvalidMasterPassword):
        unlock_vault(vault.path, "incorrect master")


def test_regular_vault_edits_do_not_invalidate_hello(vault, provider):
    enroll(vault, provider)
    vault.set_fill_and_sign_in_enabled(True)
    vault.upsert_web(origin="https://example.test", username="local-user", password="Replaced-Secret")
    result = unlock(vault, provider)
    assert result.fill_and_sign_in_enabled()
    assert result.find_web("https://example.test")[0]["password"] == "Replaced-Secret"
    result.lock()


@pytest.mark.parametrize("field", ["ciphertext", "nonce", "wrapped_secret"])
def test_tampered_envelope_never_unlocks(vault, provider, field):
    enroll(vault, provider)
    path = hello.envelope_path(vault.path)
    record = json.loads(path.read_text())
    raw = bytearray(base64.b64decode(record[field])); raw[0] ^= 1
    record[field] = base64.b64encode(raw).decode()
    path.write_text(json.dumps(record))
    with pytest.raises(HelloError):
        unlock(vault, provider)
    assert all(not any(output) for output in provider.outputs)


def test_copied_setup_cannot_unlock_another_profile(vault, provider):
    enroll(vault, provider)
    count = len(provider.calls)
    with pytest.raises(HelloError):
        unlock(vault, provider, profile="another-profile")
    assert len(provider.calls) == count


def test_changed_profile_metadata_invalidates_aead(vault, provider):
    enroll(vault, provider)
    path = hello.envelope_path(vault.path)
    record = json.loads(path.read_text()); record["profile"] = "another-profile"
    path.write_text(json.dumps(record))
    with pytest.raises(HelloError, match="authenticated"):
        unlock(vault, provider, profile="another-profile")


def test_another_vault_with_same_password_rejects_setup_before_native_prompt(vault, provider, tmp_path):
    enroll(vault, provider)
    other = create_vault(tmp_path / "other.json", MASTER, kdf_overrides=KDF)
    hello.envelope_path(other.path).write_bytes(hello.envelope_path(vault.path).read_bytes())
    count = len(provider.calls)
    with pytest.raises(HelloError, match="header changed"):
        unlock(other, provider)
    assert len(provider.calls) == count
    other.lock()


def test_encrypted_binding_not_sidecar_is_authority(vault, provider):
    enroll(vault, provider)
    vault.set_hello_binding(None)  # Simulates authenticated revocation, keeping sidecar/native key.
    with pytest.raises(VaultError, match="revoked"):
        unlock(vault, provider)
    assert all(not any(output) for output in provider.outputs)


def test_disable_deletes_key_and_sidecar_keeps_master(vault, provider):
    prepared = enroll(vault, provider)
    old_record = hello.envelope_path(vault.path).read_bytes()
    hello.disable_enrollment(vault, provider_factory=lambda: provider)
    assert not vault.hello_binding()
    assert not hello.envelope_path(vault.path).exists()
    assert prepared.record["id"] not in provider.keys
    hello.envelope_path(vault.path).write_bytes(old_record)
    with pytest.raises(HelloError):
        unlock(vault, provider)
    check = unlock_vault(vault.path, MASTER); check.lock()


def test_failed_key_deletion_does_not_claim_disabled(vault, provider):
    prepared = enroll(vault, provider)
    provider.fail_delete = True
    with pytest.raises(HelloError):
        hello.disable_enrollment(vault, provider_factory=lambda: provider)
    assert vault.hello_binding() == prepared.record["id"]
    assert hello.envelope_path(vault.path).exists()


def test_master_change_invalidates_old_envelope_before_prompt(vault, provider, monkeypatch):
    import localvault.vault as vault_module
    monkeypatch.setattr(vault_module, "DEFAULT_KDF", {**vault_module.DEFAULT_KDF, **KDF})
    enroll(vault, provider)
    new_master = "Replacement-Test-Master-0002"
    vault.change_master_password(MASTER, new_master)
    assert not vault.hello_binding()
    count = len(provider.calls)
    with pytest.raises(HelloError, match="header changed"):
        unlock(vault, provider)
    assert len(provider.calls) == count
    new = unlock_vault(vault.path, new_master); new.lock()
    with pytest.raises(InvalidMasterPassword):
        unlock_vault(vault.path, MASTER)


def test_cancellation_before_setup_never_touches_provider(vault, provider):
    event = threading.Event(); event.set()
    with pytest.raises(HelloCancelled):
        hello.prepare_enrollment(PROFILE, vault.unlock_context(), 123, event,
                                  provider_factory=lambda: provider)
    assert not provider.calls
    assert not hello.envelope_path(vault.path).exists()


def test_cancel_during_setup_discards_key_and_never_commits(vault, provider):
    event = threading.Event(); provider.on_unwrap = event.set
    with pytest.raises(HelloCancelled):
        hello.prepare_enrollment(PROFILE, vault.unlock_context(), 123, event,
                                  provider_factory=lambda: provider)
    assert not provider.keys and not vault.hello_binding()
    assert all(not any(output) for output in provider.outputs)
    assert not hello.envelope_path(vault.path).exists()


def test_cancel_unlock_wipes_os_result(vault, provider):
    enroll(vault, provider)
    event = threading.Event(); provider.on_unwrap = event.set
    with pytest.raises(HelloCancelled):
        unlock(vault, provider, event=event)
    assert all(not any(output) for output in provider.outputs)


def test_cancel_after_decryption_locks_late_session(vault, provider, monkeypatch):
    enroll(vault, provider)
    event = threading.Event()
    original = hello._unlock_vault_with_key
    results = []
    def cancel_late(*args, **kwargs):
        session = original(*args, **kwargs)
        results.append(session); event.set()
        return session
    monkeypatch.setattr(hello, "_unlock_vault_with_key", cancel_late)
    with pytest.raises(HelloCancelled):
        unlock(vault, provider, event=event)
    assert len(results) == 1 and not results[0].is_unlocked


def test_sidecar_write_failure_rolls_back_opt_in(vault, provider, monkeypatch):
    prepared = hello.prepare_enrollment(PROFILE, vault.unlock_context(), 123, threading.Event(),
                                         provider_factory=lambda: provider)
    def fail(*_args):
        raise OSError("simulated full disk")
    monkeypatch.setattr(hello, "atomic_write_json", fail)
    with pytest.raises(OSError):
        hello.commit_enrollment(vault, prepared)
    assert not any(prepared.secret) and not provider.keys
    assert not vault.hello_binding() and not hello.envelope_path(vault.path).exists()
    check = unlock_vault(vault.path, MASTER)
    assert not check.hello_binding(); check.lock()


def test_closed_session_cannot_commit(vault, provider):
    prepared = hello.prepare_enrollment(PROFILE, vault.unlock_context(), 123, threading.Event(),
                                         provider_factory=lambda: provider)
    vault.lock()
    with pytest.raises(VaultError):
        hello.commit_enrollment(vault, prepared)
    prepared.discard()
    assert not provider.keys and not any(prepared.secret)


def test_no_queued_native_operations(vault, provider):
    with native_operation():
        with pytest.raises(HelloError, match="still closing"):
            hello.prepare_enrollment(PROFILE, vault.unlock_context(), 123, threading.Event(),
                                      provider_factory=lambda: provider)
    assert not provider.calls


@pytest.mark.parametrize("content", [b"", b"[]", b"null", b"{}", b"x" * 8193])
def test_invalid_sidecar_does_not_break_master_unlock(vault, provider, content):
    hello.envelope_path(vault.path).write_bytes(content)
    assert not hello.has_envelope(vault.path, PROFILE)
    with pytest.raises(HelloError):
        unlock(vault, provider)
    check = unlock_vault(vault.path, MASTER); check.lock()
    assert not provider.calls


class Sha1OnlyProvider(SimulatedProvider):
    """A Passport provider (for example TPM 1.2 backed) that refuses OAEP with SHA-256."""
    def _hash(self, oaep_hash):
        return hashes.SHA1() if oaep_hash == "SHA1" else hashes.SHA256()

    def wrap(self, record_id, secret, oaep_hash="SHA256"):
        self.calls.append(f"wrap:{oaep_hash}")
        if oaep_hash != "SHA1":
            raise NativeError("encrypting", 0x80090027)
        return self.keys[record_id].public_key().encrypt(bytes(secret), padding.OAEP(
            mgf=padding.MGF1(hashes.SHA1()), algorithm=hashes.SHA1(), label=None))

    def unwrap(self, record_id, wrapped, hwnd, oaep_hash="SHA256"):
        self.calls.append(f"unwrap:{oaep_hash}")
        if oaep_hash != "SHA1":
            raise NativeError("decrypting", 0x80090027)
        result = bytearray(self.keys[record_id].decrypt(wrapped, padding.OAEP(
            mgf=padding.MGF1(hashes.SHA1()), algorithm=hashes.SHA1(), label=None)))
        self.outputs.append(result)
        return result


def test_provider_without_sha256_oaep_falls_back_to_sha1(vault):
    provider = Sha1OnlyProvider()
    enroll(vault, provider)
    record = json.loads(hello.envelope_path(vault.path).read_bytes())
    assert record["oaep"] == "SHA1"
    vault.lock()
    result = unlock(vault, provider)
    assert result.find_web("https://example.test")[0]["password"] == "Test-Only-Site-Secret"
    result.lock()
    assert provider.calls == ["create", "wrap:SHA256", "wrap:SHA1", "unwrap:SHA1", "unwrap:SHA1"]


def test_default_setup_records_no_oaep_field(vault, provider):
    enroll(vault, provider)
    assert "oaep" not in json.loads(hello.envelope_path(vault.path).read_bytes())


def test_unknown_oaep_hash_is_damaged_setup(vault, provider):
    enroll(vault, provider)
    path = hello.envelope_path(vault.path)
    record = json.loads(path.read_bytes())
    record["oaep"] = "MD5"
    path.write_text(json.dumps(record))
    assert not hello.has_envelope(vault.path, PROFILE)


def test_other_native_errors_do_not_fall_back(vault):
    provider = Sha1OnlyProvider()
    provider.wrap = lambda record_id, secret, oaep_hash="SHA256": (_ for _ in ()).throw(
        NativeError("encrypting", 0x80090016))
    with pytest.raises(NativeError):
        hello.prepare_enrollment(PROFILE, vault.unlock_context(), 123, threading.Event(),
                                 provider_factory=lambda: provider)
    assert provider.keys == {}
