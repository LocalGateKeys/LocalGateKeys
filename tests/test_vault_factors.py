"""Windows vault v4: key-file and YubiKey unlock factors (docs/formats/COMPOSITE_KEY_V1.md §5).

A vault without factors stays format 3 byte for byte; adding a factor writes v4 and only rewrites the
password wrapper, so the recovery phrase and the Hello / security-key / camera sidecars keep working.
Every vault here is a temporary one; the YubiKey is a fake responder in variable-input mode.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import shutil
import threading
from pathlib import Path

import pytest
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from localvault import vault as vault_module
from localvault import composite_key, keyfile
from localvault.vault import (
    DEFAULT_KDF,
    FactorInput,
    FactorMismatch,
    FactorRequired,
    FactorSecrets,
    InvalidMasterPassword,
    VaultError,
    VaultTooNew,
    add_factor,
    create_vault,
    remove_factor,
    unlock_vault,
    unlock_with_recovery_phrase,
    vault_factors,
)

ROOT = Path(__file__).resolve().parents[1]
VEC = ROOT / "tests" / "vectors" / "composite_key"
CASES = json.loads((VEC / "cases.json").read_text(encoding="utf-8"))
V4_CASE = next(case for case in CASES["cases"] if case["name"] == "windows_v4_header")
V3_VEC = ROOT / "tests" / "vectors" / "vault"
V3_EXPECTED = json.loads((V3_VEC / "v3_expected.json").read_text(encoding="utf-8"))

TEST_KDF = {"time_cost": 1, "memory_cost_kib": 8192, "parallelism": 1, "hash_len": 32}
MASTER = "correct horse battery staple"
NEW_MASTER = "replacement master password 0002"
KEYFILE_BYTES = keyfile.new_keepass_xml_v2()
OTHER_KEYFILE = keyfile.new_keepass_xml_v2()


@pytest.fixture(autouse=True)
def _fast_default_kdf(monkeypatch):
    monkeypatch.setattr(vault_module, "DEFAULT_KDF", {**DEFAULT_KDF, **TEST_KDF})
    vault_module._reset_unlock_throttle_state_for_tests()
    yield
    vault_module._reset_unlock_throttle_state_for_tests()


class FakeYubiKey:
    """HMAC-SHA1 challenge-response in variable-input mode (the trailing run of the last byte is padding)."""

    def __init__(self, secret: bytes = b"test-hmac-secret") -> None:
        self.secret = secret
        self.challenges: list[bytes] = []

    def __call__(self, padded: bytes) -> bytes:
        assert len(padded) == 64
        self.challenges.append(bytes(padded))
        message = padded.rstrip(padded[-1:])
        return hmac.new(self.secret, message, hashlib.sha1).digest()


def _new_vault(tmp_path: Path, name: str = "vault.json"):
    return create_vault(tmp_path / name, MASTER, kdf_overrides=TEST_KDF)


def _header(path: Path) -> dict:
    return json.loads(path.read_bytes())


def _with_keyfile(tmp_path: Path):
    session = _new_vault(tmp_path)
    session.add_factor(MASTER, FactorInput("keyfile", keyfile_bytes=KEYFILE_BYTES))
    return session


def test_vault_without_factors_byte_identical_v3(tmp_path, monkeypatch):
    # The password wrapper written without factors is exactly the committed v3 vector's wrapper.
    vector = json.loads((V3_VEC / "v3_vault.json").read_bytes())
    stored = vector["wrappers"]["password"]
    session = unlock_vault(shutil.copyfile(V3_VEC / "v3_vault.json", tmp_path / "vault.json"),
                           V3_EXPECTED["password"], upgrade_envelope=False)
    try:
        nonce = base64.b64decode(stored["nonce"])
        monkeypatch.setattr(vault_module.os, "urandom", lambda size: nonce if size == 12 else b"\0" * size)
        header = json.loads(json.dumps(vector))
        wrapper = session._password_wrapper(header, vault_module.as_secret(V3_EXPECTED["password"])[0],
                                            dict(vector["kdf"]))
        assert wrapper == stored
        assert header["version"] == 3 and header["format"] == vault_module.FORMAT_V3_IDENTIFIER
    finally:
        session.lock()
    monkeypatch.undo()
    # A new vault is v3 and has no factor field anywhere; the generator still reproduces the v3 vector.
    created = _new_vault(tmp_path, "created.json")
    created.lock()
    header = _header(tmp_path / "created.json")
    assert header["version"] == 3 and header["format"] == "localgatekeys-vault-v3"
    assert set(header["wrappers"]["password"]) == {"nonce", "ciphertext"}
    assert b"factors" not in (tmp_path / "created.json").read_bytes()
    assert vault_factors(tmp_path / "created.json") == []


def test_add_keyfile_writes_v4_and_unlocks(tmp_path):
    session = _new_vault(tmp_path)
    session.upsert_web(origin="https://example.test", username="u", password="Site-Secret-0001")
    context = session.unlock_context()
    specs = session.add_factor(MASTER, FactorInput("keyfile", keyfile_bytes=KEYFILE_BYTES))
    assert [spec.kind for spec in specs] == ["keyfile"]
    assert session.unlock_context() == context
    session.lock()
    header = _header(tmp_path / "vault.json")
    assert header["version"] == 4 and header["format"] == "localgatekeys-vault-v4"
    secret = keyfile.key_from_bytes(KEYFILE_BYTES)
    assert header["wrappers"]["password"]["factors"] == [
        {"kind": "keyfile", "check": composite_key.factor_check(secret)}]
    assert vault_factors(tmp_path / "vault.json") == specs
    assert KEYFILE_BYTES not in (tmp_path / "vault.json").read_bytes()
    opened = unlock_vault(tmp_path / "vault.json", MASTER, factors=FactorSecrets(keyfile=KEYFILE_BYTES))
    try:
        assert opened.find_web("https://example.test")[0]["password"] == "Site-Secret-0001"
    finally:
        opened.lock()


def test_add_yubikey_writes_v4_and_unlocks(tmp_path):
    session = _new_vault(tmp_path)
    key = FakeYubiKey()
    specs = session.add_factor(MASTER, FactorInput("yubikey-hmac", responder=key))
    session.lock()
    [spec] = specs
    assert spec.kind == "yubikey-hmac" and spec.slot == 2
    challenge = bytes.fromhex(spec.challenge)
    assert key.challenges == [composite_key.pad_challenge(challenge)]
    assert challenge[-1] not in (0x00, 0x20)
    assert _header(tmp_path / "vault.json")["wrappers"]["password"]["factors"] == [spec.to_json()]
    opened = unlock_vault(tmp_path / "vault.json", MASTER, factors=FactorSecrets(yubikey_response=key))
    opened.lock()
    assert key.challenges[-1] == composite_key.pad_challenge(challenge)
    # Slot 1 is recorded when chosen.
    other = _new_vault(tmp_path, "slot1.json")
    [slot1] = other.add_factor(MASTER, FactorInput("yubikey-hmac", slot=1, responder=FakeYubiKey()))
    other.lock()
    assert slot1.slot == 1


def test_both_factors(tmp_path):
    session = _new_vault(tmp_path)
    key = FakeYubiKey()
    session.add_factor(MASTER, FactorInput("yubikey-hmac", responder=key))
    specs = session.add_factor(MASTER, FactorInput("keyfile", keyfile_bytes=KEYFILE_BYTES))
    session.lock()
    assert [spec.kind for spec in specs] == ["keyfile", "yubikey-hmac"]  # §2 order, whatever the add order
    both = FactorSecrets(keyfile=KEYFILE_BYTES, yubikey_response=key)
    unlock_vault(tmp_path / "vault.json", MASTER, factors=both).lock()
    with pytest.raises(FactorMismatch) as caught:
        unlock_vault(tmp_path / "vault.json", MASTER,
                     factors=FactorSecrets(keyfile=KEYFILE_BYTES, yubikey_response=FakeYubiKey(b"another key")))
    assert caught.value.kind == "yubikey-hmac"
    # Module-level helpers: add then remove through the path.
    path2 = tmp_path / "second.json"
    _new_vault(tmp_path, "second.json").lock()
    add_factor(path2, MASTER, None, FactorInput("keyfile", keyfile_bytes=KEYFILE_BYTES))
    assert [spec.kind for spec in vault_factors(path2)] == ["keyfile"]
    remove_factor(path2, MASTER, FactorSecrets(keyfile=KEYFILE_BYTES), "keyfile")
    assert vault_factors(path2) == [] and _header(path2)["version"] == 3


def test_missing_factor_raises_required(tmp_path):
    session = _new_vault(tmp_path)
    key = FakeYubiKey()
    session.add_factor(MASTER, FactorInput("keyfile", keyfile_bytes=KEYFILE_BYTES))
    session.add_factor(MASTER, FactorInput("yubikey-hmac", responder=key))
    session.lock()
    asked = len(key.challenges)
    with pytest.raises(FactorRequired) as caught:
        unlock_vault(tmp_path / "vault.json", MASTER)
    assert caught.value.kinds == ["keyfile", "yubikey-hmac"]
    with pytest.raises(FactorRequired) as caught:
        unlock_vault(tmp_path / "vault.json", MASTER, factors=FactorSecrets(keyfile=KEYFILE_BYTES))
    assert caught.value.kinds == ["yubikey-hmac"]
    assert len(key.challenges) == asked  # nothing was asked of the YubiKey
    assert isinstance(caught.value, VaultError) and str(caught.value)


def test_wrong_keyfile_mismatch_not_throttled(tmp_path, monkeypatch):
    _with_keyfile(tmp_path).lock()
    calls = []
    real = vault_module._derive_key
    monkeypatch.setattr(vault_module, "_derive_key", lambda *a, **k: calls.append(1) or real(*a, **k))
    for _ in range(vault_module.THROTTLE_FREE_ATTEMPTS + 3):
        with pytest.raises(FactorMismatch) as caught:
            unlock_vault(tmp_path / "vault.json", MASTER, factors=FactorSecrets(keyfile=OTHER_KEYFILE))
        assert caught.value.kind == "keyfile"
    assert calls == []  # raised before Argon2 ran
    assert vault_module.remaining_backoff_seconds(tmp_path / "vault.json") == 0
    unlock_vault(tmp_path / "vault.json", MASTER, factors=FactorSecrets(keyfile=KEYFILE_BYTES)).lock()
    # A wrong password with the right key file is still a counted password failure.
    with pytest.raises(InvalidMasterPassword):
        unlock_vault(tmp_path / "vault.json", "wrong master password 1", factors=FactorSecrets(keyfile=KEYFILE_BYTES))


def test_changed_keyfile_mismatch_message(tmp_path):
    _with_keyfile(tmp_path).lock()
    with pytest.raises(FactorMismatch) as caught:
        unlock_vault(tmp_path / "vault.json", MASTER, factors=FactorSecrets(keyfile=OTHER_KEYFILE))
    assert isinstance(caught.value, composite_key.FactorMismatch) and isinstance(caught.value, VaultError)
    assert str(caught.value) == "This isn't the key file used for this vault."
    with pytest.raises(FactorMismatch) as caught:
        unlock_vault(tmp_path / "vault.json", MASTER, factors=FactorSecrets(keyfile=b"<KeyFile>broken"))
    assert caught.value.kind == "keyfile"
    # An edited copy of the right file (its Data no longer matches the Hash) is refused the same way.
    edited = KEYFILE_BYTES.replace(b"<Data Hash=\"", b"<Data Hash=\"0")
    with pytest.raises(FactorMismatch):
        unlock_vault(tmp_path / "vault.json", MASTER, factors=FactorSecrets(keyfile=edited))


@pytest.mark.kdf_upgrade
def test_kdf_upgrade_on_unlock_keeps_factors(tmp_path, monkeypatch):
    _with_keyfile(tmp_path).lock()
    monkeypatch.setattr(vault_module, "_low_memory_machine", lambda: False)
    monkeypatch.setattr(vault_module, "DEFAULT_KDF", {**DEFAULT_KDF, **TEST_KDF, "memory_cost_kib": 16384})
    session = unlock_vault(tmp_path / "vault.json", MASTER, factors=FactorSecrets(keyfile=KEYFILE_BYTES),
                           upgrade_kdf=True)
    try:
        assert session._last_kdf_upgrade_result["outcome"] == "upgraded"
    finally:
        session.lock()
    header = _header(tmp_path / "vault.json")
    assert header["version"] == 4 and header["kdf"]["memory_cost_kib"] == 16384
    assert [spec.kind for spec in vault_factors(tmp_path / "vault.json")] == ["keyfile"]
    unlock_vault(tmp_path / "vault.json", MASTER, factors=FactorSecrets(keyfile=KEYFILE_BYTES)).lock()


def test_recovery_phrase_opens_without_factors(tmp_path):
    session = _new_vault(tmp_path)
    phrase = session.create_recovery_phrase(MASTER)
    session.add_factor(MASTER, FactorInput("keyfile", keyfile_bytes=KEYFILE_BYTES))
    session.add_factor(MASTER, FactorInput("yubikey-hmac", responder=FakeYubiKey()))
    session.lock()
    recovered = unlock_with_recovery_phrase(tmp_path / "vault.json", phrase)
    try:
        assert recovered.recovery_unlocked
        result = recovered.set_master_password_after_recovery(NEW_MASTER)
        assert result["factors_removed"] == ["keyfile", "yubikey-hmac"]
    finally:
        recovered.lock()
    # The lost factors are dropped: the new password alone opens a v3 vault, and the phrase still works.
    assert _header(tmp_path / "vault.json")["version"] == 3
    unlock_vault(tmp_path / "vault.json", NEW_MASTER).lock()
    unlock_with_recovery_phrase(tmp_path / "vault.json", phrase).lock()
    # The committed v4 vector opens with its phrase too.
    (tmp_path / "v4").mkdir()
    path = shutil.copyfile(VEC / V4_CASE["file"], tmp_path / "v4" / "vault.json")
    opened = unlock_with_recovery_phrase(path, V4_CASE["recovery_phrase"])
    try:
        assert bytes(opened._key).hex() == V4_CASE["data_key_hex"]
    finally:
        opened.lock()


def test_hello_fido_face_unlock_still_work_with_factors(tmp_path):
    from localvault import fido_unlock
    from localvault import hello_unlock as hello
    from tests.test_fido_unlock import HWND, SimulatedKey
    from tests.test_hello_unlock import PROFILE, SimulatedProvider

    session = _new_vault(tmp_path)
    provider, security_key = SimulatedProvider(), SimulatedKey()
    prepared = hello.prepare_enrollment(PROFILE, session.unlock_context(), 123, threading.Event(),
                                        provider_factory=lambda: provider)
    hello.commit_enrollment(session, prepared)
    prepared_key = fido_unlock.prepare_enrollment(PROFILE, session.unlock_context(), HWND, threading.Event(),
                                                  provider_factory=lambda: security_key)
    fido_unlock.commit_enrollment(session, prepared_key)
    session.set_face_binding("c" * 32)
    context = session.unlock_context()
    session.add_factor(MASTER, FactorInput("keyfile", keyfile_bytes=KEYFILE_BYTES))
    session.add_factor(MASTER, FactorInput("yubikey-hmac", responder=FakeYubiKey()))
    assert session.unlock_context() == context  # the camera sidecar binds to this context as well
    assert session.hello_binding() and session.fido_binding() and session.face_binding()
    session.lock()
    header = _header(tmp_path / "vault.json")
    assert header["version"] == 4
    assert vault_module.unlock_context_for_header(header) == context
    by_hello = hello.unlock_with_hello(tmp_path / "vault.json", PROFILE, 123, threading.Event(),
                                       provider_factory=lambda: provider)
    try:
        assert by_hello.is_unlocked and by_hello.face_binding() == "c" * 32
        # Without the factors in memory, a password check asks for them.
        with pytest.raises(FactorRequired):
            by_hello.verify_master_password(MASTER)
    finally:
        by_hello.lock()
    by_key = fido_unlock.unlock_with_security_key(tmp_path / "vault.json", PROFILE, HWND, threading.Event(),
                                                  provider_factory=lambda: security_key)
    by_key.lock()


def test_change_password_keeps_factors_and_renews_challenge(tmp_path):
    session = _new_vault(tmp_path)
    key = FakeYubiKey()
    session.add_factor(MASTER, FactorInput("keyfile", keyfile_bytes=KEYFILE_BYTES))
    [_keyfile, old_spec] = session.add_factor(MASTER, FactorInput("yubikey-hmac", responder=key))
    session.lock()
    both = FactorSecrets(keyfile=KEYFILE_BYTES, yubikey_response=key)
    opened = unlock_vault(tmp_path / "vault.json", MASTER, factors=both)
    try:
        opened.change_master_password(MASTER, NEW_MASTER)
    finally:
        opened.lock()
    specs = vault_factors(tmp_path / "vault.json")
    assert [spec.kind for spec in specs] == ["keyfile", "yubikey-hmac"]
    assert specs[0] == _keyfile
    new_spec = specs[1]
    assert new_spec.challenge != old_spec.challenge and new_spec.check != old_spec.check
    assert new_spec.slot == old_spec.slot
    assert key.challenges[-1] == new_spec.padded_challenge
    unlock_vault(tmp_path / "vault.json", NEW_MASTER, factors=both).lock()
    with pytest.raises(InvalidMasterPassword):
        unlock_vault(tmp_path / "vault.json", MASTER, factors=both)
    # The responder is needed: without the YubiKey the password change is refused and nothing changes.
    before = (tmp_path / "vault.json").read_bytes()
    opened = unlock_vault(tmp_path / "vault.json", NEW_MASTER, factors=both)
    try:
        def unplugged(_padded):
            raise OSError("no YubiKey")
        opened._held_factors.responder = unplugged
        with pytest.raises(FactorRequired):
            opened.change_master_password(NEW_MASTER, MASTER)
    finally:
        opened.lock()
    assert (tmp_path / "vault.json").read_bytes() == before


def test_remove_last_factor_writes_v3(tmp_path):
    session = _new_vault(tmp_path)
    session.lock()
    original = _header(tmp_path / "vault.json")
    session = unlock_vault(tmp_path / "vault.json", MASTER)
    session.add_factor(MASTER, FactorInput("keyfile", keyfile_bytes=KEYFILE_BYTES))
    with pytest.raises(VaultError):
        session.remove_factor(MASTER, "yubikey-hmac")
    with pytest.raises(VaultError):
        session.add_factor(MASTER, FactorInput("keyfile", keyfile_bytes=OTHER_KEYFILE))
    assert session.remove_factor(MASTER, "keyfile") == []
    session.lock()
    header = _header(tmp_path / "vault.json")
    assert header["version"] == 3 and header["format"] == "localgatekeys-vault-v3"
    assert set(header["wrappers"]["password"]) == {"nonce", "ciphertext"}
    assert set(header) == set(original) and header["kdf"] == original["kdf"]
    assert vault_module.unlock_context_for_header(header) == vault_module.unlock_context_for_header(original)
    unlock_vault(tmp_path / "vault.json", MASTER).lock()


def test_v3_reader_rejects_v4_without_writing(tmp_path, monkeypatch):
    path = tmp_path / "vault.json"
    shutil.copyfile(VEC / V4_CASE["file"], path)
    header = _header(path)
    with pytest.raises(VaultError):
        vault_module._validate_v3_header(header)
    # A copy relabelled as v3 keeps a list-valued wrapper field, which the v3 rules refuse.
    relabelled = dict(header, version=3, format="localgatekeys-vault-v3")
    path.write_bytes(json.dumps(relabelled).encode("ascii"))
    before = sorted(p.name for p in tmp_path.iterdir()), path.read_bytes()
    with pytest.raises(VaultError):
        unlock_vault(path, V4_CASE["password"])
    assert path.read_bytes() == before[1]
    assert sorted(p.name for p in tmp_path.iterdir()) == before[0]
    # An older build (versions 1-3 only) gives its unsupported-version error.
    shutil.copyfile(VEC / V4_CASE["file"], path)
    monkeypatch.setattr(vault_module, "SUPPORTED_FORMAT_VERSIONS", (1, 2, 3))
    with pytest.raises(VaultError, match="Unsupported vault format version"):
        unlock_vault(path, V4_CASE["password"])
    assert path.read_bytes() == (VEC / V4_CASE["file"]).read_bytes()
    assert sorted(p.name for p in tmp_path.iterdir()) == before[0]
    # A v4 header with an empty or oversized factor list, or extra wrapper fields, is refused.
    for edit in ([], [header["wrappers"]["password"]["factors"][0]] * 3):
        bad = json.loads(json.dumps(header))
        bad["wrappers"]["password"]["factors"] = edit
        with pytest.raises(VaultError):
            vault_module._validate_v4_header(bad)
    bad = json.loads(json.dumps(header))
    bad["wrappers"]["password"]["extra"] = "x"
    with pytest.raises(VaultError):
        vault_module._validate_v4_header(bad)
    bad = json.loads(json.dumps(header))
    del bad["wrappers"]["password"]["factors"]
    with pytest.raises(VaultError):
        vault_module._validate_v4_header(bad)


def test_unknown_version_vault_too_new(tmp_path):
    path = tmp_path / "vault.json"
    header = _header(VEC / V4_CASE["file"])
    path.write_bytes(json.dumps(dict(header, version=5)).encode("ascii"))
    before = path.read_bytes()
    with pytest.raises(VaultTooNew) as caught:
        unlock_vault(path, V4_CASE["password"])
    assert caught.value.version == 5
    assert str(caught.value) == "This vault needs a newer LocalGateKeys."
    with pytest.raises(VaultTooNew):
        vault_factors(path)
    assert path.read_bytes() == before


def _vector_factors() -> FactorSecrets:
    return FactorSecrets(keyfile=(VEC / "keyfiles" / "xml_v2.keyx").read_bytes(),
                         yubikey_response=FakeYubiKey(CASES["yubikey"]["hmac_secret"].encode("ascii")))


def test_windows_v4_header_vector(tmp_path):
    header = _header(VEC / V4_CASE["file"])
    assert vault_module._aad(header) == base64.b64decode(V4_CASE["catalog_aad_b64"])
    specs = vault_module._header_factor_specs(header)
    assert [spec.to_json() for spec in specs] == V4_CASE["factors"]
    assert vault_module._wrapper_aad(header, "password", vault_module._password_metadata(header, specs)) == \
        base64.b64decode(V4_CASE["wrapper_aad_b64"])
    recovery = header["wrappers"]["recovery"]
    assert vault_module._wrapper_aad(header, "recovery", {"kind": recovery["kind"], "salt": recovery["salt"]}) == \
        base64.b64decode(V4_CASE["recovery_aad_b64"])
    path = tmp_path / "vault.json"
    shutil.copyfile(VEC / V4_CASE["file"], path)
    session = unlock_vault(path, V4_CASE["password"], factors=_vector_factors(), upgrade_envelope=False)
    try:
        assert bytes(session._key).hex() == V4_CASE["data_key_hex"]
        payload = session._require_payload()
        for name, value in V4_CASE["payload"].items():
            assert payload[name] == value, name
    finally:
        session.lock()
    # Every tampered row (the key and AAD an attacker would recompute) fails to open the wrapper.
    password = header["wrappers"]["password"]
    nonce, ciphertext = base64.b64decode(password["nonce"]), base64.b64decode(password["ciphertext"])
    for row in V4_CASE["tampered"]:
        with pytest.raises(InvalidTag):
            AESGCM(bytes.fromhex(row["key_hex"])).decrypt(nonce, ciphertext, bytes.fromhex(row["aad_hex"]))
    # The factors-removed file is a v3 vault that refuses the password and is left unchanged.
    tampered = tmp_path / "tampered" / "vault.json"
    tampered.parent.mkdir()
    shutil.copyfile(VEC / "windows_v4_tampered_no_factors.json", tampered)
    with pytest.raises(InvalidMasterPassword):
        unlock_vault(tampered, V4_CASE["password"])
    assert tampered.read_bytes() == (VEC / "windows_v4_tampered_no_factors.json").read_bytes()


def test_reauthenticate_uses_session_factors(tmp_path, monkeypatch):
    from test_app_login_extras import Bus, Port, Sched

    from localvault.api.result import ApiError
    from localvault.app.controller import WebController
    from localvault.app.secrets import SecretService
    from localvault.profiles import ProfileManager
    from localvault.settings import AppSettings

    monkeypatch.setattr("localvault.app.controller.clear_master_unlock_requirement", lambda _pid: None)
    profiles = ProfileManager(tmp_path / "data")
    profiles.ensure_profile()
    controller = WebController(profiles=profiles, settings=AppSettings(idle_source="vault"), bus=Bus(),
                               scheduler=Sched(), create_kwargs={"kdf_overrides": TEST_KDF})
    controller.create(MASTER, MASTER)
    key = FakeYubiKey()
    controller.session.add_factor(MASTER, FactorInput("keyfile", keyfile_bytes=KEYFILE_BYTES))
    controller.session.add_factor(MASTER, FactorInput("yubikey-hmac", responder=key))
    controller.lock()
    with pytest.raises(ApiError) as caught:
        controller.unlock(MASTER)
    assert caught.value.code == "factor_required"
    with pytest.raises(ApiError) as caught:
        controller.unlock(MASTER, factors=FactorSecrets(keyfile=OTHER_KEYFILE, yubikey_response=key))
    assert caught.value.code == "factor_mismatch"
    controller.unlock(MASTER, factors=FactorSecrets(keyfile=KEYFILE_BYTES, yubikey_response=key))
    session = controller.session
    held = session._held_factors.keyfile_secret
    assert isinstance(held, bytearray) and bytes(held) == keyfile.key_from_bytes(KEYFILE_BYTES)
    port = Port()
    port.passwords.append(MASTER)
    asked = len(key.challenges)
    SecretService(controller, port).reauthenticate("Strict login", controller.guard.lease())
    assert len(key.challenges) == asked + 1  # the YubiKey was asked again; no response was kept
    port.passwords.append("wrong master password 1")
    with pytest.raises(ApiError):
        SecretService(controller, port).reauthenticate("Strict login", controller.guard.lease())
    controller.lock()
    assert not any(held) and session._held_factors is None


def test_rotation_refuses_a_different_yubikey_for_the_new_challenge(tmp_path):
    session = _new_vault(tmp_path)
    key, other = FakeYubiKey(), FakeYubiKey(b"another slot secret")
    session.add_factor(MASTER, FactorInput("yubikey-hmac", responder=key))
    before = (tmp_path / "vault.json").read_bytes()
    # Verification succeeds with the right key, then a different key is inserted for the renewal.
    answers = iter([key, other, other])

    def swapped(padded):
        return next(answers)(padded)

    try:
        with pytest.raises(FactorMismatch) as caught:
            session.change_master_password(MASTER, NEW_MASTER, factors=FactorSecrets(yubikey_response=swapped))
        assert caught.value.kind == "yubikey-hmac"
        assert (tmp_path / "vault.json").read_bytes() == before
        assert len(other.challenges) == 1 and other.challenges[0] == vault_factors(tmp_path / "vault.json")[0].padded_challenge
    finally:
        session.lock()
    unlock_vault(tmp_path / "vault.json", MASTER, factors=FactorSecrets(yubikey_response=key)).lock()


def test_new_wrapper_is_verified_before_commit(tmp_path, monkeypatch):
    import os as _os

    session = _new_vault(tmp_path)
    session.add_factor(MASTER, FactorInput("keyfile", keyfile_bytes=KEYFILE_BYTES))
    # The password check (first derivation) is real; the new wrapper and its re-derivation get
    # different keys, so the check before the commit must refuse and nothing is written.
    real_combine = composite_key.combine
    calls = {"n": 0}

    def flaky_combine(*args):
        calls["n"] += 1
        return real_combine(*args) if calls["n"] == 1 else bytearray(_os.urandom(32))

    session.add_factor(MASTER, FactorInput("yubikey-hmac", responder=FakeYubiKey()))
    before = (tmp_path / "vault.json").read_bytes()
    for action in (
        lambda: session.remove_factor(MASTER, "yubikey-hmac"),
        lambda: session.change_master_password(MASTER, NEW_MASTER),
    ):
        calls["n"] = 0
        with monkeypatch.context() as patched:
            patched.setattr(composite_key, "combine", flaky_combine)
            with pytest.raises(VaultError, match="did not verify"):
                action()
        assert (tmp_path / "vault.json").read_bytes() == before
    # Adding a factor is checked the same way (the session still opens the unchanged file).
    session.remove_factor(MASTER, "yubikey-hmac")
    before = (tmp_path / "vault.json").read_bytes()
    calls["n"] = 0
    with monkeypatch.context() as patched:
        patched.setattr(composite_key, "combine", flaky_combine)
        with pytest.raises(VaultError, match="did not verify"):
            session.add_factor(MASTER, FactorInput("yubikey-hmac", responder=FakeYubiKey()))
    assert (tmp_path / "vault.json").read_bytes() == before
    session.lock()
    unlock_vault(tmp_path / "vault.json", MASTER, factors=FactorSecrets(keyfile=KEYFILE_BYTES)).lock()


def test_enrolment_bad_answer_names_the_slot(tmp_path):
    session = _new_vault(tmp_path)
    try:
        with pytest.raises(VaultError) as caught:
            session.add_factor(MASTER, FactorInput("yubikey-hmac", slot=1, responder=lambda _padded: b"\x01" * 8))
        assert str(caught.value) == ("The YubiKey did not answer correctly. "
                                     "Check that slot 1 is set to HMAC-SHA1 challenge-response.")
        assert not isinstance(caught.value, FactorMismatch)
    finally:
        session.lock()
    assert _header(tmp_path / "vault.json")["version"] == 3
