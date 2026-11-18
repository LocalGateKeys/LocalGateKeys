"""Backups, restores and recovery of a vault with key-file / YubiKey factors (COMPOSITE_KEY_V1.md §5).

A ``.lgk`` / ``.lgkfull`` holds the vault file verbatim, so a v4 vault stays v4 inside every backup.  Restoring
one asks for its factors before the vault's Argon2 runs (``FactorRequired``), opens with them, or opens with the
recovery phrase instead, which sets a new master password and drops the factors (format 3 again).  Backups of
vaults without factors restore exactly as before.  Every vault here is a temporary one; the YubiKey is a fake.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import shutil
import zipfile
from pathlib import Path

import pytest

import localvault.vault as vault_module
from localvault import keyfile
from localvault.api.result import ApiError
from localvault.app.controller import WebController
from localvault.app.recovery import RecoveryWebService
from localvault.backup import (
    BackupError,
    _full_read_container,
    export_encrypted_backup,
    export_full_backup,
    export_full_backup_to_key,
    preflight_full_backup,
    restore_full_backup,
    restore_verified_backup,
    verify_encrypted_backup,
)
from localvault.backup_key import build_record, derive_backup_key, new_kdf
from localvault.config import atomic_write_json
from localvault.next_release_ui import GuidedRecoveryDrill
from localvault.profiles import ProfileManager
from localvault.recovery import (
    RecoveryError,
    RecoveryService,
    create_recovery_backup,
    plan_restore_as_new_profile,
    restore_as_new_profile,
)
from localvault.settings import AppSettings
from localvault.vault import (
    DEFAULT_KDF,
    FactorInput,
    FactorMismatch,
    FactorRequired,
    FactorSecrets,
    create_vault,
    unlock_vault,
    unlock_with_recovery_phrase,
)

ROOT = Path(__file__).resolve().parents[1]
TEST_KDF = {"time_cost": 1, "memory_cost_kib": 8192, "parallelism": 1, "hash_len": 32}
CHEAP = {"time_cost": 1, "memory_cost_kib": 8192, "parallelism": 1}
MASTER = "synthetic factor master password"
NEW_MASTER = "replacement master password 0002"
BACKUP_PASSWORD = "synthetic independent backup password"
KEYFILE_BYTES = keyfile.new_keepass_xml_v2()
OTHER_KEYFILE = keyfile.new_keepass_xml_v2()


@pytest.fixture(autouse=True)
def _fast_default_kdf(monkeypatch):
    monkeypatch.setattr(vault_module, "DEFAULT_KDF", {**DEFAULT_KDF, **TEST_KDF})
    vault_module._reset_unlock_throttle_state_for_tests()
    yield
    vault_module._reset_unlock_throttle_state_for_tests()


class FakeYubiKey:
    """HMAC-SHA1 challenge-response in variable-input mode (as in test_vault_factors.py)."""

    def __init__(self, secret: bytes = b"test-hmac-secret") -> None:
        self.secret = secret
        self.slots: list[int] = []

    def __call__(self, padded: bytes) -> bytes:
        assert len(padded) == 64
        return hmac.new(self.secret, padded.rstrip(padded[-1:]), hashlib.sha1).digest()


def _profile(path: Path, *, yubikey: FakeYubiKey | None = None, phrase: bool = True) -> tuple[Path, str | None]:
    """A profile whose vault has a key file (and optionally a YubiKey); returns (profile, recovery phrase)."""
    path.mkdir(parents=True)
    session = create_vault(path / "vault.json", MASTER, kdf_overrides=TEST_KDF)
    try:
        entry_id = session.upsert_web(origin="https://example.test", username="synthetic-user",
                                      password="synthetic-secret", label="Synthetic login")
        session.set_details(entry_id, policy={"fill": "click", "sign_in": "enabled"})
        session.set_fill_and_sign_in_enabled(True)
        recovery_phrase = session.create_recovery_phrase(MASTER) if phrase else None
        session.add_factor(MASTER, FactorInput("keyfile", keyfile_bytes=KEYFILE_BYTES))
        if yubikey is not None:
            session.add_factor(MASTER, FactorInput("yubikey-hmac", responder=yubikey, slot=2))
    finally:
        session.lock()
    atomic_write_json(path / "settings.json", {"version": 5, "fill_and_sign_in": True})
    assert json.loads((path / "vault.json").read_bytes())["version"] == 4
    return path, recovery_phrase


def _full_backup(root: Path, **profile_kwargs) -> tuple[Path, Path, str | None]:
    profile, phrase = _profile(root / "source", **profile_kwargs)
    backup = root / "profile.lgk"
    export_full_backup(backup, profile_dir=profile, profile_name="Synthetic", backup_password=BACKUP_PASSWORD,
                       kdf_overrides=CHEAP)
    return profile, backup, phrase


def _catalog_backup(root: Path, **profile_kwargs) -> tuple[Path, Path, str | None]:
    profile, phrase = _profile(root / "source", **profile_kwargs)
    backup = root / "catalog.lgk"
    export_encrypted_backup(backup, vault_file=profile / "vault.json", settings_file=profile / "settings.json",
                            profile_name="Synthetic", backup_password=BACKUP_PASSWORD, kdf_overrides=CHEAP)
    return profile, backup, phrase


def _count_vault_kdf(monkeypatch) -> list[int]:
    calls: list[int] = []
    real = vault_module._derive_key
    monkeypatch.setattr(vault_module, "_derive_key", lambda *a, **k: calls.append(1) or real(*a, **k))
    return calls


def _header(path: Path) -> dict:
    return json.loads(Path(path).read_bytes())


def _keyfile() -> FactorSecrets:
    return FactorSecrets(keyfile=KEYFILE_BYTES)


# --------------------------------------------------------------------------- backup contents


def test_full_backup_of_v4_contains_v4_verbatim(tmp_path: Path) -> None:
    profile, backup, _phrase = _full_backup(tmp_path)
    seen: dict[str, bytes] = {}
    _full_read_container(backup, BACKUP_PASSWORD, on_entry=lambda entry, data: seen.__setitem__(entry["kind"], data))
    assert seen["vault"] == (profile / "vault.json").read_bytes()
    assert _header_bytes(seen["vault"])["version"] == 4
    assert _header_bytes(seen["vault"])["format"] == "localgatekeys-vault-v4"


def _header_bytes(data: bytes) -> dict:
    return json.loads(data)


# --------------------------------------------------------------------------- restore asks for the factors


def test_restore_v4_backup_asks_for_factors(tmp_path: Path, monkeypatch) -> None:
    _profile_dir, backup, _phrase = _full_backup(tmp_path, yubikey=FakeYubiKey())
    calls = _count_vault_kdf(monkeypatch)
    destination = tmp_path / "restored"
    with pytest.raises(FactorRequired) as missing:
        restore_full_backup(backup, profile_dir=destination, backup_password=BACKUP_PASSWORD,
                            vault_password=MASTER, validate_vault_password=True)
    assert missing.value.kinds == ["keyfile", "yubikey-hmac"]
    # The public factor list (no secret) travels with it, so the UI can name the YubiKey slot.
    assert [(spec.kind, spec.slot) for spec in missing.value.specs] == [("keyfile", None), ("yubikey-hmac", 2)]
    assert calls == []  # asked before the vault's Argon2 ran
    assert not destination.exists()
    # Only the key file: the YubiKey is still missing.
    with pytest.raises(FactorRequired) as partial:
        restore_full_backup(backup, profile_dir=destination, backup_password=BACKUP_PASSWORD,
                            vault_password=MASTER, validate_vault_password=True, factors=_keyfile())
    assert partial.value.kinds == ["yubikey-hmac"]
    # A wrong key file is its own error, never a generic "could not be unlocked".
    with pytest.raises(FactorMismatch):
        restore_full_backup(backup, profile_dir=destination, backup_password=BACKUP_PASSWORD,
                            vault_password=MASTER, validate_vault_password=True,
                            factors=FactorSecrets(keyfile=OTHER_KEYFILE, yubikey_response=FakeYubiKey()))
    assert calls == [] and not destination.exists()
    # The recovery layer passes both through unchanged (the preview and the confirmed restore).
    with pytest.raises(FactorRequired):
        plan_restore_as_new_profile(backup, tmp_path / "new", backup_password=BACKUP_PASSWORD, vault_password=MASTER)
    with pytest.raises(FactorRequired):
        restore_as_new_profile(backup, tmp_path / "new", backup_password=BACKUP_PASSWORD, vault_password=MASTER,
                               confirm=True)
    assert not (tmp_path / "new").exists()


def test_catalog_backup_of_v4_asks_for_factors(tmp_path: Path, monkeypatch) -> None:
    _profile_dir, backup, _phrase = _catalog_backup(tmp_path)
    calls = _count_vault_kdf(monkeypatch)
    with pytest.raises(FactorRequired) as missing:
        verify_encrypted_backup(backup, backup_password=BACKUP_PASSWORD, vault_password=MASTER)
    assert missing.value.kinds == ["keyfile"] and calls == []
    with pytest.raises(FactorMismatch):
        verify_encrypted_backup(backup, backup_password=BACKUP_PASSWORD, vault_password=MASTER,
                                factors=FactorSecrets(keyfile=OTHER_KEYFILE))
    with pytest.raises(FactorRequired):
        restore_verified_backup(backup, vault_file=tmp_path / "out" / "vault.json", settings_file=None,
                                backup_password=BACKUP_PASSWORD, vault_password=MASTER)
    assert not (tmp_path / "out" / "vault.json").exists()


# --------------------------------------------------------------------------- restore with the factors


def test_restore_v4_backup_with_factors(tmp_path: Path) -> None:
    yubikey = FakeYubiKey()
    _profile_dir, backup, _phrase = _full_backup(tmp_path, yubikey=yubikey)
    factors = FactorSecrets(keyfile=KEYFILE_BYTES, yubikey_response=yubikey)
    info = preflight_full_backup(backup, profile_dir=tmp_path / "probe", backup_password=BACKUP_PASSWORD,
                                 vault_password=MASTER, validate_vault_password=True, factors=factors)
    assert info["verified_vault"] and info["vault_entries"] == 1
    destination = tmp_path / "restored"
    info = restore_full_backup(backup, profile_dir=destination, backup_password=BACKUP_PASSWORD,
                               vault_password=MASTER, validate_vault_password=True, factors=factors)
    assert info["verified_vault"] and "factors_removed" not in info
    # The restored vault keeps its factors and opens with them, sanitised like any restore.
    assert _header(destination / "vault.json")["version"] == 4
    session = unlock_vault(destination / "vault.json", MASTER, factors=factors)
    try:
        assert session.fill_and_sign_in_enabled() is False
        assert len(session.summaries()) == 1
    finally:
        session.lock()
    with pytest.raises(FactorRequired):
        unlock_vault(destination / "vault.json", MASTER)


def test_catalog_backup_of_v4_restores_with_factors(tmp_path: Path) -> None:
    _profile_dir, backup, _phrase = _catalog_backup(tmp_path)
    info = verify_encrypted_backup(backup, backup_password=BACKUP_PASSWORD, vault_password=MASTER,
                                   factors=_keyfile())
    assert info["verified"] and info["entries"] == 1
    target = tmp_path / "out"
    target.mkdir()
    restore_verified_backup(backup, vault_file=target / "vault.json", settings_file=target / "settings.json",
                            backup_password=BACKUP_PASSWORD, vault_password=MASTER, factors=_keyfile())
    assert _header(target / "vault.json")["version"] == 4
    session = unlock_vault(target / "vault.json", MASTER, factors=_keyfile())
    try:
        assert session.fill_and_sign_in_enabled() is False
    finally:
        session.lock()


# --------------------------------------------------------------------------- restore with the recovery phrase


def test_restore_v4_backup_with_phrase(tmp_path: Path, monkeypatch) -> None:
    _profile_dir, backup, phrase = _full_backup(tmp_path, yubikey=FakeYubiKey())
    calls = _count_vault_kdf(monkeypatch)
    destination = tmp_path / "restored"
    plan = plan_restore_as_new_profile(backup, destination, backup_password=BACKUP_PASSWORD,
                                       vault_password=NEW_MASTER, recovery_phrase=phrase)
    assert plan["requires_confirmation"] and plan["verified_vault"]
    result = restore_as_new_profile(backup, destination, backup_password=BACKUP_PASSWORD, vault_password=NEW_MASTER,
                                    recovery_phrase=phrase, confirm=True)
    assert result["committed"] is True
    # The phrase opened the copy without the factors; the new password replaced them (format 3 again).
    assert result["factors_removed"] == ["keyfile", "yubikey-hmac"]
    assert calls  # the new password wrapper was derived
    assert _header(destination / "vault.json")["version"] == 3
    session = unlock_vault(destination / "vault.json", NEW_MASTER)
    try:
        assert len(session.summaries()) == 1
        assert session.fill_and_sign_in_enabled() is False
    finally:
        session.lock()
    unlock_with_recovery_phrase(destination / "vault.json", phrase).lock()
    # A wrong phrase restores nothing.
    with pytest.raises((RecoveryError, vault_module.VaultError)):
        restore_as_new_profile(backup, tmp_path / "other", backup_password=BACKUP_PASSWORD, vault_password=NEW_MASTER,
                               recovery_phrase=" ".join(["abandon"] * 24), confirm=True)
    assert not (tmp_path / "other").exists()


def test_catalog_backup_of_v4_restores_with_phrase(tmp_path: Path) -> None:
    _profile_dir, backup, phrase = _catalog_backup(tmp_path)
    target = tmp_path / "out"
    target.mkdir()
    info = restore_verified_backup(backup, vault_file=target / "vault.json", settings_file=target / "settings.json",
                                   backup_password=BACKUP_PASSWORD, vault_password=NEW_MASTER, recovery_phrase=phrase)
    assert info["factors_removed"] == ["keyfile"]
    assert _header(target / "vault.json")["version"] == 3
    unlock_vault(target / "vault.json", NEW_MASTER).lock()


# --------------------------------------------------------------------------- scheduled v3 (public key) backups


def _record(password: str) -> dict:
    key = derive_backup_key(password, new_kdf(parameters=CHEAP))
    try:
        return build_record(key, now=1793001000, set_by="set", reset_authority=None, previous=None)
    finally:
        key.wipe()


def test_scheduled_v3_public_key_backup_of_v4_vault_restores(tmp_path: Path) -> None:
    profile, _phrase = _profile(tmp_path / "source")
    record = _record(BACKUP_PASSWORD)
    path = tmp_path / "scheduled.lgk"
    result = export_full_backup_to_key(path, record=record, profile_dir=profile, profile_name="Synthetic")
    with result["verifier"] as verifier:  # the 9.1 self-verify needs no vault password and no factors
        verifier.verify(path, record=record)
    seen: dict[str, bytes] = {}
    _full_read_container(path, BACKUP_PASSWORD, on_entry=lambda entry, data: seen.__setitem__(entry["kind"], data))
    assert seen["vault"] == (profile / "vault.json").read_bytes()
    with pytest.raises(FactorRequired):
        restore_full_backup(path, profile_dir=tmp_path / "restored", backup_password=BACKUP_PASSWORD,
                            vault_password=MASTER, validate_vault_password=True)
    info = restore_full_backup(path, profile_dir=tmp_path / "restored", backup_password=BACKUP_PASSWORD,
                               vault_password=MASTER, validate_vault_password=True, factors=_keyfile())
    assert info["version"] == 3 and info["verified_vault"]
    unlock_vault(tmp_path / "restored" / "vault.json", MASTER, factors=_keyfile()).lock()


# --------------------------------------------------------------------------- recovery layer


def test_restore_as_new_profile_v4(tmp_path: Path) -> None:
    profile, phrase = _profile(tmp_path / "source")
    backup = tmp_path / "recovery.lgk"
    # Creating a recovery backup of a v4 vault validates it with the factors.
    with pytest.raises(FactorRequired):
        create_recovery_backup(backup, profile_dir=profile, profile_name="Synthetic", backup_password=BACKUP_PASSWORD,
                               vault_password=MASTER)
    assert not backup.exists()
    created = create_recovery_backup(backup, profile_dir=profile, profile_name="Synthetic",
                                     backup_password=BACKUP_PASSWORD, vault_password=MASTER, factors=_keyfile())
    assert created["committed"] is True
    service = RecoveryService(profile)
    verified = service.verify_backup(backup, backup_password=BACKUP_PASSWORD, vault_password=MASTER,
                                     factors=_keyfile())
    assert verified["verified"] is True
    destination = tmp_path / "restored"
    result = restore_as_new_profile(backup, destination, backup_password=BACKUP_PASSWORD, vault_password=MASTER,
                                    factors=_keyfile(), confirm=True)
    assert result["committed"] and "factors_removed" not in result
    assert _header(destination / "vault.json")["version"] == 4
    session = unlock_vault(destination / "vault.json", MASTER, factors=_keyfile())
    try:
        assert session.fill_and_sign_in_enabled() is False and session.hello_binding() == ""
    finally:
        session.lock()
    # The drill's catalog check of a restored v4 profile takes the same factors.
    drill = GuidedRecoveryDrill(service=service)
    with pytest.raises(FactorRequired):
        drill.verify_restored_catalog(destination, vault_password=MASTER)
    checked = drill.verify_restored_catalog(destination, vault_password=MASTER, factors=_keyfile())
    assert checked["catalog_verified"] is True


def test_old_backups_unchanged(tmp_path: Path) -> None:
    """The committed v2 and v3 full-backup vectors (v3 inner vaults) restore through the changed paths as before."""
    for folder in ("v2", "v3"):
        vectors = ROOT / "tests" / "vectors" / "backup" / folder
        expected = json.loads((vectors / "expected.json").read_text(encoding="utf-8"))
        source = vectors / "full.lgkfull"
        before = hashlib.sha256(source.read_bytes()).hexdigest()
        copy = tmp_path / folder / "full.lgkfull"
        copy.parent.mkdir()
        shutil.copyfile(source, copy)
        destination = tmp_path / folder / "restored"
        result = restore_as_new_profile(copy, destination, backup_password=expected["backup_password"],
                                        vault_password=expected["master_password"], confirm=True)
        assert result["committed"] and "factors_removed" not in result
        assert _header(destination / "vault.json")["version"] == 3
        unlock_vault(destination / "vault.json", expected["master_password"]).lock()
        # Factors given for a vault without any are ignored.
        restore_full_backup(copy, profile_dir=tmp_path / folder / "again", backup_password=expected["backup_password"],
                            vault_password=expected["master_password"], validate_vault_password=True,
                            factors=_keyfile())
        assert hashlib.sha256(source.read_bytes()).hexdigest() == before
        assert copy.read_bytes() == source.read_bytes()  # a restore never rewrites the backup
        with zipfile.ZipFile(copy) as archive:
            assert archive.testzip() is None


def test_backup_errors_still_wrap_ordinary_failures(tmp_path: Path) -> None:
    """A wrong master password on a v4 backup (with the right factors) stays the old BackupError."""
    _profile_dir, backup, _phrase = _full_backup(tmp_path)
    with pytest.raises(BackupError, match="could not be unlocked"):
        restore_full_backup(backup, profile_dir=tmp_path / "restored", backup_password=BACKUP_PASSWORD,
                            vault_password="not the master password", validate_vault_password=True,
                            factors=_keyfile())


# --------------------------------------------------------------------------- the Backup & restore page


class Bus:
    def __init__(self):
        self.notices = []

    def emit(self, name, detail):
        if name == "notice":
            self.notices.append(detail)


class Sched:
    def call_later(self, delay, fn):
        return fn

    def cancel(self, handle):
        pass


class Port:
    def __init__(self):
        self.asked = []

    def confirm(self, title, message):
        self.asked.append(title)
        return True


class Dialogs:
    def __init__(self):
        self.save_to = None
        self.open_from: list = []

    def save_file(self, title, name):
        return self.save_to

    def open_file(self, title):
        return self.open_from.pop(0) if self.open_from else None


@pytest.fixture
def env(tmp_path, monkeypatch):
    """An unlocked profile whose vault has a key file, and the Backup & restore service on it."""
    monkeypatch.setattr("localvault.app.controller.clear_master_unlock_requirement", lambda _pid: None)
    profiles = ProfileManager(tmp_path / "data")
    profiles.ensure_profile()
    bus = Bus()
    controller = WebController(profiles=profiles, settings=AppSettings(idle_source="vault"), bus=bus,
                               scheduler=Sched(), create_kwargs={"kdf_overrides": TEST_KDF})
    controller.create(MASTER, MASTER)
    controller.session.create_web_login(urls=[{"url": "https://a.test", "match": "exact_origin"}], username="a",
                                        password="pw-1234567890", label="Alpha")
    phrase = controller.session.create_recovery_phrase(MASTER)
    controller.session.add_factor(MASTER, FactorInput("keyfile", keyfile_bytes=KEYFILE_BYTES))
    controller.lock()
    controller.unlock(MASTER, _keyfile())
    (tmp_path / "vault.keyx").write_bytes(KEYFILE_BYTES)
    (tmp_path / "other.keyx").write_bytes(OTHER_KEYFILE)
    dialogs = Dialogs()
    service = RecoveryWebService(controller, Port(), dialogs)
    return service, controller, dialogs, tmp_path, phrase, bus


def test_page_creates_a_backup_of_a_v4_vault_with_the_unlocked_factors(env):
    service, _controller, dialogs, tmp, _phrase, _bus = env
    dialogs.save_to = tmp / "b.lgk"
    created = service.create_backup(BACKUP_PASSWORD, BACKUP_PASSWORD, MASTER)
    assert "created" in created["message"]


def test_page_asks_for_the_key_file_then_restores(env):
    service, controller, dialogs, tmp, _phrase, _bus = env
    dialogs.save_to = tmp / "b.lgk"
    service.create_backup(BACKUP_PASSWORD, BACKUP_PASSWORD, MASTER)
    dialogs.open_from = [tmp / "b.lgk"]
    service.choose("restore")
    with pytest.raises(ApiError) as needed:
        service.restore("Restored", BACKUP_PASSWORD, MASTER)
    assert needed.value.code == "factor_required"
    prompt = service.factors()
    assert prompt["kinds"] == ["keyfile"] and prompt["keyfile"] is None and prompt["phrase_allowed"] is True
    # A key file that is not this vault's: its own message, and the prompt stays.
    dialogs.open_from = [tmp / "other.keyx"]
    assert service.choose_keyfile()["keyfile"] == "other.keyx"
    with pytest.raises(ApiError) as wrong:
        service.restore("Restored", BACKUP_PASSWORD, MASTER)
    assert wrong.value.code == "factor_mismatch"
    dialogs.open_from = [tmp / "vault.keyx"]
    service.choose_keyfile()
    before = {p.id for p in controller.profiles.list_profiles()}
    restored = service.restore("Restored", BACKUP_PASSWORD, MASTER)
    assert restored["restored"] is True
    assert len({p.id for p in controller.profiles.list_profiles()} - before) == 1
    assert service.factors()["keyfile"] is None  # the key file is forgotten after the restore


def test_page_restores_with_the_phrase_and_says_the_factors_were_removed(env):
    service, controller, dialogs, tmp, phrase, _bus = env
    dialogs.save_to = tmp / "b.lgk"
    service.create_backup(BACKUP_PASSWORD, BACKUP_PASSWORD, MASTER)
    dialogs.open_from = [tmp / "b.lgk"]
    service.choose("restore")
    with pytest.raises(ApiError) as mismatch:
        service.restore_with_phrase("Restored", BACKUP_PASSWORD, phrase, NEW_MASTER, NEW_MASTER + "x")
    assert mismatch.value.code == "invalid"
    before = {p.id for p in controller.profiles.list_profiles()}
    restored = service.restore_with_phrase("Restored", BACKUP_PASSWORD, phrase, NEW_MASTER, NEW_MASTER)
    assert restored["restored"] is True
    assert "Key file / YubiKey removed; add them again" in restored["message"]
    (new_id,) = {p.id for p in controller.profiles.list_profiles()} - before
    unlock_vault(controller.profiles.vault_path(new_id), NEW_MASTER).lock()


def test_phrase_reset_of_a_v4_vault_says_the_factors_were_removed(env):
    _service, controller, _dialogs, _tmp, phrase, bus = env
    controller.lock()
    controller.recover(phrase, NEW_MASTER, NEW_MASTER)
    assert any("Key file / YubiKey removed; add them again" in notice.get("message", "")
               or "Key file / YubiKey removed; add them again" in notice.get("title", "") for notice in bus.notices)
