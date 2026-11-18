"""Argon2id 256 MiB default and the one-time KDF upgrade on a master-password unlock (WP-C)."""
from __future__ import annotations

import os
import threading
from pathlib import Path

import pytest
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from localvault import vault as vault_module
from localvault import backup, face_unlock, hello_unlock, phone_backup, share, transfer
from localvault.config import atomic_write_faults, read_json
from localvault.face_models import EMBEDDING_SIZE, normalize_embedding
from localvault.sync import keyring
from localvault.vault import (
    KDF_UPGRADE_CONTEXT_PREF,
    create_vault,
    unlock_vault,
    unlock_with_recovery_phrase,
    vault_migration_journal_path,
)

MASTER = "kdf upgrade test master password 0001"
OLD_KDF = {"time_cost": 1, "memory_cost_kib": 8192, "parallelism": 1}
# Stand-in for the 256 MiB target so the upgrade tests stay fast.
TARGET_KIB = 16384
PROFILE = "kdf-upgrade-profile"
GIB = 1024 ** 3

pytestmark = pytest.mark.kdf_upgrade


@pytest.fixture(autouse=True)
def _fast_target_and_enough_ram(monkeypatch):
    monkeypatch.setattr(vault_module, "DEFAULT_KDF", {**vault_module.DEFAULT_KDF, "time_cost": 1,
                                                      "memory_cost_kib": TARGET_KIB, "parallelism": 1})
    monkeypatch.setattr(vault_module, "_total_physical_memory_bytes", lambda: 16 * GIB)
    vault_module._reset_unlock_throttle_state_for_tests()
    yield
    vault_module._reset_unlock_throttle_state_for_tests()


def _old_vault(tmp_path: Path):
    backups = tmp_path / "Backups"
    session = create_vault(tmp_path / "vault.json", MASTER, kdf_overrides=OLD_KDF,
                           backup_dir=backups, backup_count=3)
    session.upsert_web(origin="https://example.test", username="user", password="Site-Secret-1")
    return session, backups


def _unlock(path: Path, backups: Path, **kwargs):
    return unlock_vault(path, MASTER, backup_dir=backups, backup_count=3, **kwargs)


class _Provider:
    """Real RSA-OAEP stand-in for the Windows Hello key (no biometrics simulated)."""

    def __init__(self):
        self.keys = {}

    def create(self, record_id, hwnd):
        self.keys[record_id] = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    def _oaep(self):
        return padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)

    def wrap(self, record_id, secret):
        return self.keys[record_id].public_key().encrypt(bytes(secret), self._oaep())

    def unwrap(self, record_id, wrapped, hwnd, *_oaep):
        return bytearray(self.keys[record_id].decrypt(wrapped, self._oaep()))

    def delete(self, record_id):
        self.keys.pop(record_id, None)


class _Protector:
    """Test-only AEAD stand-in for current-user DPAPI."""

    key = bytes.fromhex("24" * 32)

    def protect(self, value, entropy, description):
        nonce = os.urandom(12)
        return nonce + AESGCM(self.key).encrypt(nonce, bytes(value), bytes(entropy) + description.encode())

    def unprotect(self, value, entropy):
        raw = bytes(value)
        for description in ("LocalGateKeys face template", "LocalGateKeys local unlock key"):
            try:
                return bytearray(AESGCM(self.key).decrypt(raw[:12], raw[12:], bytes(entropy) + description.encode()))
            except InvalidTag:
                continue
        raise face_unlock.FaceError("Simulated protected value did not authenticate")


def _embeddings():
    values = []
    for offset in (0.00, 0.02, -0.02, 0.01, -0.01, 0.03):
        raw = [0.0] * EMBEDDING_SIZE
        raw[0], raw[1], raw[2] = 1.0, offset, offset / 2
        values.append(list(normalize_embedding(raw)))
    return values


def _enroll_both(session, provider):
    prepared = hello_unlock.prepare_enrollment(PROFILE, session.unlock_context(), 123, threading.Event(),
                                               provider_factory=lambda: provider)
    hello_unlock.commit_enrollment(session, prepared)
    face = face_unlock.prepare_enrollment(PROFILE, session.unlock_context(), _embeddings(),
                                          protector_factory=_Protector)
    face_unlock.commit_enrollment(session, face)


def _hello_unlock(path: Path, provider):
    return hello_unlock.unlock_with_hello(path, PROFILE, 123, threading.Event(), provider_factory=lambda: provider)


def _face_unlock(path: Path):
    material = face_unlock.load_face_material(path, PROFILE, protector_factory=_Protector)
    try:
        return face_unlock.unlock_verified_face(material, threading.Event(), protector_factory=_Protector)
    finally:
        material.discard()


def _assert_sidecars_unlock(path: Path, provider) -> None:
    for session in (_hello_unlock(path, provider), _face_unlock(path)):
        assert session.find_web("https://example.test")[0]["password"] == "Site-Secret-1"
        session.lock()


# --------------------------------------------------------------------------
# Defaults
# --------------------------------------------------------------------------

def test_default_is_256_mib_for_vault_backup_and_transfer_but_not_fixed_formats(monkeypatch) -> None:
    monkeypatch.undo()
    assert vault_module.DEFAULT_KDF["memory_cost_kib"] == 262144
    assert vault_module.DEFAULT_KDF["time_cost"] == 3 and vault_module.DEFAULT_KDF["parallelism"] == 4
    assert vault_module.MIN_KDF_MEMORY_KIB <= 262144 <= vault_module.MAX_KDF_MEMORY_KIB == 512 * 1024
    for kdf in (backup.BACKUP_KDF, backup.FULL_BACKUP_KDF, transfer.TRANSFER_KDF):
        assert (kdf["time_cost"], kdf["memory_cost_kib"], kdf["parallelism"]) == (3, 262144, 4)
    # Fixed cross-platform formats keep their own parameters.
    assert phone_backup.KDF["memory_cost_kib"] == 131072
    assert keyring.KDF_MEMORY_KIB == 131072
    assert share.KDF["memory_cost_kib"] == 19456


def test_new_vault_uses_256_mib(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr(vault_module, "DEFAULT_KDF", {**vault_module.DEFAULT_KDF, "memory_cost_kib": 262144})
    session = create_vault(tmp_path / "vault.json", MASTER)
    session.lock()
    kdf = read_json(tmp_path / "vault.json")["kdf"]
    assert kdf["memory_cost_kib"] == 262144 and kdf["time_cost"] == 1


@pytest.mark.parametrize("ram", [3 * GIB, None])
def test_new_vault_on_low_or_unknown_ram_uses_64_mib(tmp_path: Path, monkeypatch, ram) -> None:
    monkeypatch.setattr(vault_module, "DEFAULT_KDF", {**vault_module.DEFAULT_KDF, "memory_cost_kib": 262144})
    monkeypatch.setattr(vault_module, "_total_physical_memory_bytes", lambda: ram)
    create_vault(tmp_path / "vault.json", MASTER).lock()
    assert read_json(tmp_path / "vault.json")["kdf"]["memory_cost_kib"] == 65536


def test_physical_memory_probe_reports_this_machine() -> None:
    total = vault_module._total_physical_memory_bytes()
    assert total is None or total > 256 * 1024 * 1024


# --------------------------------------------------------------------------
# Upgrade on unlock
# --------------------------------------------------------------------------

def test_password_unlock_rewraps_same_data_key_under_new_parameters(tmp_path: Path) -> None:
    session, backups = _old_vault(tmp_path)
    phrase = session.create_recovery_phrase(MASTER)
    data_key = bytes(session._key)
    before = read_json(session.path)
    session.lock()

    upgraded = _unlock(session.path, backups, upgrade_kdf=True)
    after = read_json(upgraded.path)
    assert after["kdf"]["memory_cost_kib"] == TARGET_KIB
    assert after["kdf"]["salt"] != before["kdf"]["salt"]
    assert after["wrappers"]["password"] != before["wrappers"]["password"]
    assert after["wrappers"]["recovery"] == before["wrappers"]["recovery"]
    for name in ("vault_id", "key_generation", "format", "catalog_version"):
        assert after[name] == before[name]
    assert bytes(upgraded._key) == data_key
    result = upgraded.last_kdf_upgrade_result
    assert result["outcome"] == "upgraded" and result["data_key"] == "inherited"
    assert result["from_memory_cost_kib"] == 8192 and result["to_memory_cost_kib"] == TARGET_KIB
    assert result["snapshot_removed"] is True
    assert not list(backups.glob("migration-v*-*.json"))
    assert not vault_migration_journal_path(upgraded.path).exists()
    assert upgraded.find_web("https://example.test")[0]["password"] == "Site-Secret-1"
    upgraded.lock()

    again = _unlock(session.path, backups, upgrade_kdf=True)
    assert again.last_kdf_upgrade_result is None
    assert read_json(session.path)["kdf"] == after["kdf"]
    again.lock()
    by_phrase = unlock_with_recovery_phrase(session.path, phrase)
    assert bytes(by_phrase._key) == data_key
    by_phrase.lock()


def test_upgrade_never_lowers_time_cost(tmp_path: Path) -> None:
    session = create_vault(tmp_path / "vault.json", MASTER, kdf_overrides={**OLD_KDF, "time_cost": 4})
    session.lock()
    _unlock(session.path, tmp_path / "Backups", upgrade_kdf=True).lock()
    kdf = read_json(session.path)["kdf"]
    assert (kdf["memory_cost_kib"], kdf["time_cost"]) == (TARGET_KIB, 4)


def test_unlock_without_the_flag_and_stronger_vaults_are_left_alone(tmp_path: Path) -> None:
    session, backups = _old_vault(tmp_path)
    session.lock()
    source = session.path.read_bytes()
    plain = _unlock(session.path, backups)
    assert plain.last_kdf_upgrade_result is None
    plain.lock()
    probe = _unlock(session.path, backups, upgrade_kdf=True, upgrade_envelope=False)
    probe.lock()
    assert session.path.read_bytes() == source

    strong = create_vault(tmp_path / "strong.json", MASTER, kdf_overrides={**OLD_KDF, "memory_cost_kib": 32768})
    strong.lock()
    strong_source = strong.path.read_bytes()
    reopened = unlock_vault(strong.path, MASTER, upgrade_kdf=True)
    assert reopened.last_kdf_upgrade_result is None
    reopened.lock()
    assert strong.path.read_bytes() == strong_source


def test_low_memory_machine_skips_the_upgrade(tmp_path: Path, monkeypatch) -> None:
    session, backups = _old_vault(tmp_path)
    session.lock()
    source = session.path.read_bytes()
    monkeypatch.setattr(vault_module, "_total_physical_memory_bytes", lambda: 2 * GIB)
    reopened = _unlock(session.path, backups, upgrade_kdf=True)
    assert reopened.last_kdf_upgrade_result["outcome"] == "skipped"
    assert reopened.last_kdf_upgrade_result["reason"] == "low-memory"
    reopened.lock()
    assert session.path.read_bytes() == source


def test_hello_and_camera_sidecars_still_unlock_after_the_upgrade(tmp_path: Path) -> None:
    provider = _Provider()
    session, backups = _old_vault(tmp_path)
    _enroll_both(session, provider)
    session.lock()

    upgraded = _unlock(session.path, backups, upgrade_kdf=True)
    result = upgraded.last_kdf_upgrade_result
    assert result["outcome"] == "upgraded" and result["converted"] == ["face", "hello"]
    assert result["sidecars_pending"] == []
    assert upgraded.hello_binding() and upgraded.face_binding()
    upgraded.lock()
    assert read_json(session.path)["kdf"]["memory_cost_kib"] == TARGET_KIB
    _assert_sidecars_unlock(session.path, provider)


def test_alternative_unlocks_never_upgrade(tmp_path: Path) -> None:
    provider = _Provider()
    session, _backups = _old_vault(tmp_path)
    _enroll_both(session, provider)
    session.lock()
    source = session.path.read_bytes()
    _assert_sidecars_unlock(session.path, provider)
    assert session.path.read_bytes() == source


def test_crash_after_publish_before_sidecar_move_is_repaired_by_next_password_unlock(
        tmp_path: Path, monkeypatch) -> None:
    provider = _Provider()
    session, backups = _old_vault(tmp_path)
    _enroll_both(session, provider)
    session.lock()

    # The process "dies" after the vault was published: the sidecars are never rewritten.
    monkeypatch.setattr(hello_unlock, "upgrade_envelope_context", lambda *_args: False)
    monkeypatch.setattr(face_unlock, "upgrade_envelope_context", lambda *_args: False)
    upgraded = _unlock(session.path, backups, upgrade_kdf=True)
    assert upgraded.last_kdf_upgrade_result["sidecars_pending"] == ["face", "hello"]
    upgraded.lock()
    monkeypatch.undo()
    monkeypatch.setattr(vault_module, "DEFAULT_KDF", {**vault_module.DEFAULT_KDF, "time_cost": 1,
                                                      "memory_cost_kib": TARGET_KIB, "parallelism": 1})
    monkeypatch.setattr(vault_module, "_total_physical_memory_bytes", lambda: 16 * GIB)
    assert read_json(session.path)["kdf"]["memory_cost_kib"] == TARGET_KIB
    with pytest.raises(hello_unlock.HelloError):
        _hello_unlock(session.path, provider)

    repaired = _unlock(session.path, backups, upgrade_kdf=True)
    prefs = repaired._require_payload()["preferences"]
    stored = prefs.get(KDF_UPGRADE_CONTEXT_PREF)
    assert set(stored) == {"previous", "target"}
    assert stored["target"] == vault_module.unlock_context_for_header(repaired._header)
    repaired.lock()
    _assert_sidecars_unlock(session.path, provider)


def test_crash_mid_publish_rolls_back_then_upgrades_on_the_next_unlock(tmp_path: Path, monkeypatch) -> None:
    provider = _Provider()
    session, backups = _old_vault(tmp_path)
    _enroll_both(session, provider)
    session.lock()
    source = session.path.read_bytes()
    real_recover = vault_module._recover_vault_migration

    def no_in_process_recovery(path, *, in_process=False):
        if in_process:
            return None  # a crash: nothing cleans up in this process
        return real_recover(path)

    def fail(stage: str, target: Path) -> None:
        if stage == "after_replace" and target.name == "vault.json":
            raise OSError("simulated power loss after the vault was replaced")

    monkeypatch.setattr(vault_module, "_recover_vault_migration", no_in_process_recovery)
    with atomic_write_faults(fail):
        crashed = _unlock(session.path, backups, upgrade_kdf=True)
    assert crashed.is_unlocked
    assert crashed.last_kdf_upgrade_result["outcome"] == "failed"
    crashed.lock()
    assert vault_migration_journal_path(session.path).exists()
    monkeypatch.setattr(vault_module, "_recover_vault_migration", real_recover)

    # The next start rolls the half-published vault back from the journal.
    plain = _unlock(session.path, backups)
    assert session.path.read_bytes() == source
    assert not vault_migration_journal_path(session.path).exists()
    plain.lock()
    _assert_sidecars_unlock(session.path, provider)

    upgraded = _unlock(session.path, backups, upgrade_kdf=True)
    assert upgraded.last_kdf_upgrade_result["outcome"] == "upgraded"
    assert upgraded.find_web("https://example.test")[0]["password"] == "Site-Secret-1"
    upgraded.lock()
    _assert_sidecars_unlock(session.path, provider)


def test_publish_failure_keeps_the_old_vault_and_a_usable_session(tmp_path: Path) -> None:
    session, backups = _old_vault(tmp_path)
    session.lock()
    source = session.path.read_bytes()

    def fail(stage: str, target: Path) -> None:
        if stage == "after_replace" and target.name == "vault.json":
            raise OSError("synthetic publication fault")

    with atomic_write_faults(fail):
        reopened = _unlock(session.path, backups, upgrade_kdf=True)
    assert reopened.last_kdf_upgrade_result["outcome"] == "failed"
    assert session.path.read_bytes() == source
    assert not vault_migration_journal_path(session.path).exists()
    reopened.upsert_web(origin="https://after.test", username="u", password="Site-Secret-2")
    reopened.lock()
    assert read_json(session.path)["kdf"]["memory_cost_kib"] == 8192
    later = _unlock(session.path, backups, upgrade_kdf=True)
    assert later.last_kdf_upgrade_result["outcome"] == "upgraded"
    assert later.find_web("https://after.test")[0]["password"] == "Site-Secret-2"
    later.lock()


def test_derivation_failure_does_not_block_the_unlock(tmp_path: Path, monkeypatch) -> None:
    session, backups = _old_vault(tmp_path)
    session.lock()
    source = session.path.read_bytes()
    real = vault_module._derive_key

    def derive(password, kdf):
        if int(kdf["memory_cost_kib"]) == TARGET_KIB:
            raise vault_module.VaultError("Key derivation failed")
        return real(password, kdf)

    monkeypatch.setattr(vault_module, "_derive_key", derive)
    reopened = _unlock(session.path, backups, upgrade_kdf=True)
    assert reopened.is_unlocked and reopened.last_kdf_upgrade_result["outcome"] == "failed"
    reopened.lock()
    assert session.path.read_bytes() == source


def test_app_password_unlock_asks_for_the_upgrade(tmp_path: Path, monkeypatch) -> None:
    from localvault.api.result import ApiError
    from localvault.app import controller as controller_module

    calls = []

    def spy(*args, **kwargs):
        calls.append(kwargs)
        raise vault_module.VaultError("stop here")

    from localvault import duress as duress_module
    monkeypatch.setattr(duress_module, "unlock_vault", spy)
    monkeypatch.setattr("localvault.app.controller.clear_master_unlock_requirement", lambda _pid: None)
    from localvault.profiles import ProfileManager
    from localvault.settings import AppSettings

    profiles = ProfileManager(tmp_path / "data")
    profile = profiles.ensure_profile()
    profiles.vault_path(profile.id).parent.mkdir(parents=True, exist_ok=True)
    profiles.vault_path(profile.id).write_text("{}", encoding="utf-8")
    class _Bus:
        def emit(self, _name, _detail):
            pass

    controller = controller_module.WebController(profiles=profiles, settings=AppSettings(), bus=_Bus())
    with pytest.raises(ApiError):
        controller.unlock(MASTER)
    assert calls and calls[0].get("upgrade_kdf") is True


def _repair_calls(session, monkeypatch, stored) -> list[tuple[str, str]]:
    calls: list[tuple[str, str]] = []
    session._require_payload().setdefault("preferences", {})[KDF_UPGRADE_CONTEXT_PREF] = stored
    monkeypatch.setattr(session, "_bound_unlock_sidecars",
                        lambda: [("hello", lambda _p, old, new: calls.append((old, new)) or True)])
    session._repair_unlock_sidecars_after_kdf_upgrade()
    return calls


def test_repair_skips_a_stale_upgrade_context(tmp_path: Path, monkeypatch) -> None:
    session, backups = _old_vault(tmp_path)
    session.lock()
    unlocked = _unlock(session.path, backups)
    current = vault_module.unlock_context_for_header(unlocked._header)
    old, other = "a" * 64, "b" * 64
    # The header has moved on from the context that upgrade produced: no repair.
    assert _repair_calls(unlocked, monkeypatch, {"previous": old, "target": other}) == []
    # Still at the upgrade's target: the repair runs.
    assert _repair_calls(unlocked, monkeypatch, {"previous": old, "target": current}) == [(old, current)]
    # A malformed record never repairs.
    assert _repair_calls(unlocked, monkeypatch, {"previous": old}) == []
    # The single-string form from earlier builds keeps today's behaviour.
    assert _repair_calls(unlocked, monkeypatch, old) == [(old, current)]
    unlocked.lock()
