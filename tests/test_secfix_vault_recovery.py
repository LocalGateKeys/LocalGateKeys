"""M-1 (audit 2026-10-24): a replaced or removed recovery phrase must not open the current vault.

Before the fix the data key was only re-wrapped, so any older copy of the
vault (here: the rolling backups) still wrapped the *current* data key under
the old phrase.
"""
from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from localvault import vault as V

LOW = {"time_cost": 1, "memory_cost_kib": 8192, "parallelism": 1}
MASTER = "correct horse battery staple"


@pytest.fixture(autouse=True)
def cheap_kdf(monkeypatch):
    # Rotation wraps the new key under DEFAULT_KDF; keep it fast in tests.
    monkeypatch.setattr(V, "DEFAULT_KDF", {**V.DEFAULT_KDF, **LOW})
    V._reset_unlock_throttle_state_for_tests()
    yield
    V._reset_unlock_throttle_state_for_tests()


def _new(tmp_path: Path):
    path = tmp_path / "vault.json"
    backups = tmp_path / "Backups"
    session = V.create_vault(path, MASTER, kdf_overrides=LOW, backup_dir=backups, backup_count=5)
    session.upsert_web(origin="https://bank.example", username="alice", password="OLD-secret-1")
    return path, backups, session


def _old_phrase_opens_current(path: Path, phrase: str, directories: list[Path]) -> bool:
    """The audit PoC: unwrap a data key from any older copy, try it on the current file."""
    entropy = V.entropy_from_phrase(phrase)
    current = json.loads(path.read_text())
    for directory in directories:
        for copy in sorted(directory.glob("*.json")):
            header = json.loads(copy.read_text())
            wrapper = header.get("wrappers", {}).get("recovery")
            if not wrapper:
                continue
            try:
                key = V._unwrap_recovery_wrapper(header, wrapper, entropy)
            except V.VaultError:
                continue
            try:
                AESGCM(bytes(key)).decrypt(V._b64d(current["cipher"]["nonce"]),
                                           V._b64d(current["cipher"]["ciphertext"]), V._aad(current))
                return True
            except InvalidTag:
                continue
    return False


def test_regenerated_and_removed_phrase_cannot_open_current_vault_from_old_copies(tmp_path: Path) -> None:
    path, backups, session = _new(tmp_path)
    old_phrase = session.create_recovery_phrase(MASTER)
    # Keep a copy as an attacker would (shadow copy / external backup of the folder).
    stash = tmp_path / "stash"
    shutil.copytree(backups, stash)
    shutil.copy2(path, stash / "vault-current-at-theft.json")

    new_phrase = session.create_recovery_phrase(MASTER)
    assert session.last_recovery_phrase_change["operation"] == "replace"
    assert session.last_recovery_phrase_change["recovery_phrase_invalidated"] is True
    session.upsert_web(origin="https://mail.example", username="alice", password="NEW-secret-after-replace")
    assert not _old_phrase_opens_current(path, old_phrase, [backups, stash])
    # Rolling backups from the old key are purged.
    for backup in backups.glob("vault-*.json"):
        assert json.loads(backup.read_text())["key_generation"] == session._header["key_generation"]

    removed = session.remove_recovery_phrase(MASTER)
    assert removed is not None and removed["recovery_phrase_invalidated"] is True
    assert not session.has_recovery_phrase()
    session.upsert_web(origin="https://shop.example", username="alice", password="NEW-secret-after-removal")
    session.lock()
    assert not _old_phrase_opens_current(path, old_phrase, [backups, stash])
    assert not _old_phrase_opens_current(path, new_phrase, [backups, stash])
    with pytest.raises(V.RecoveryPhraseError):
        V.unlock_with_recovery_phrase(path, new_phrase)
    check = V.unlock_vault(path, MASTER)
    assert len(check.summaries()) == 3
    check.lock()


def test_new_phrase_works_after_replacement(tmp_path: Path) -> None:
    path, _backups, session = _new(tmp_path)
    session.create_recovery_phrase(MASTER)
    generation = session._header["key_generation"]
    phrase = session.create_recovery_phrase(MASTER)
    assert session._header["key_generation"] == generation + 1
    session.lock()
    opened = V.unlock_with_recovery_phrase(path, phrase)
    assert opened.summaries()[0].username == "alice"
    opened.lock()


def test_first_phrase_is_cheap_and_keeps_unlock_bindings(tmp_path: Path) -> None:
    _path, _backups, session = _new(tmp_path)
    session.set_face_binding("b" * 32)
    generation = session._header.get("key_generation")
    session.create_recovery_phrase(MASTER)
    assert session._header.get("key_generation") == generation
    assert session.face_binding() == "b" * 32
    assert session.last_recovery_phrase_change["operation"] == "create"
    session.lock()


def test_replacement_revokes_unlock_bindings(tmp_path: Path) -> None:
    _path, _backups, session = _new(tmp_path)
    session.create_recovery_phrase(MASTER)
    session.set_face_binding("b" * 32)
    session.create_recovery_phrase(MASTER)
    assert not session.face_binding()
    assert "face" in session.last_recovery_phrase_change["reenroll_required"]
    session.lock()


def test_phrase_after_old_unrotated_removal_rotates(tmp_path: Path) -> None:
    """A phrase removed by an older release left copies wrapping the current key: rotate on re-create."""
    path, backups, session = _new(tmp_path)
    old_phrase = session.create_recovery_phrase(MASTER)
    session.upsert_web(origin="https://two.example", username="alice", password="x")  # backup with wrapper
    # Simulate the pre-fix removal: drop the wrapper without rotating.
    header = json.loads(json.dumps(session._header))
    header["wrappers"].pop("recovery")
    session._commit_header_change(header)
    assert _old_phrase_opens_current(path, old_phrase, [backups])
    generation = session._header["key_generation"]
    session.create_recovery_phrase(MASTER)
    assert session._header["key_generation"] == generation + 1
    session.lock()
    assert not _old_phrase_opens_current(path, old_phrase, [backups])


def test_retained_pre_restore_copies_are_reported(tmp_path: Path) -> None:
    from localvault.app.recovery_center import recovery_phrase_change_warnings

    path, backups, session = _new(tmp_path)
    session.create_recovery_phrase(MASTER)
    backups.mkdir(exist_ok=True)
    shutil.copy2(path, backups / "before-restore-1.json")
    session.create_recovery_phrase(MASTER)
    change = session.last_recovery_phrase_change
    assert change["retained_old_copies"] == 1
    assert (backups / "before-restore-1.json").exists()  # kept: it is the user's restore safety copy
    notes = recovery_phrase_change_warnings(change)
    assert any("previous recovery phrase" in note for note in notes)
    assert any("1 older safety copy" in note for note in notes)
    session.lock()


def test_wrong_password_changes_nothing(tmp_path: Path) -> None:
    path, _backups, session = _new(tmp_path)
    session.create_recovery_phrase(MASTER)
    before = path.read_bytes()
    with pytest.raises(V.InvalidMasterPassword):
        session.create_recovery_phrase("not the master password")
    with pytest.raises(V.InvalidMasterPassword):
        session.remove_recovery_phrase("not the master password")
    assert path.read_bytes() == before
    session.lock()
