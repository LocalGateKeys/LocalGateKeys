"""Vault v3 presentation seams: recovery-phrase card, rollback confirmation, unlock countdown."""
from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from localvault.app import recovery_center
from localvault.app import unlock_backoff as auth_ui
from localvault.app.recovery_center import RecoveryCenter, RecoveryError
from localvault.recovery import (
    RecoveryController,
    _safe_inventory,
    create_recovery_backup,
    write_recovery_kit,
)
from localvault.vault import (
    InvalidMasterPassword,
    RecoveryPhraseError,
    UnlockThrottled,
    VaultError,
    create_vault,
    unlock_vault,
    unlock_with_recovery_phrase,
)

MASTER = "synthetic recovery master password"
NEW_MASTER = "synthetic replacement master password"
BACKUP_PASSWORD = "synthetic independent backup password"
TEST_KDF = {"time_cost": 1, "memory_cost_kib": 8192, "parallelism": 1}


@pytest.fixture(autouse=True)
def _fast_default_kdf(monkeypatch: pytest.MonkeyPatch) -> None:
    from localvault import vault as vault_module
    monkeypatch.setattr(vault_module, "DEFAULT_KDF", {**vault_module.DEFAULT_KDF, **TEST_KDF})
    vault_module._reset_unlock_throttle_state_for_tests()
    yield
    vault_module._reset_unlock_throttle_state_for_tests()


def _profile(root: Path) -> Path:
    root.mkdir(parents=True, exist_ok=True)
    session = create_vault(root / "vault.json", MASTER, kdf_overrides=TEST_KDF)
    session.upsert_web(origin="https://example.test", username="synthetic-user", password="synthetic-secret")
    session.lock()
    return root


# --------------------------------------------------------------------------
# Recovery phrase challenge (pure logic behind the show-once card)
# --------------------------------------------------------------------------

def test_recovery_phrase_challenge_picks_three_distinct_positions_and_verifies() -> None:
    phrase = " ".join(f"word{index}" for index in range(24))
    challenge = recovery_center.RecoveryPhraseChallenge(phrase)
    assert len(challenge.positions) == 3
    assert len(set(challenge.positions)) == 3
    assert all(1 <= position <= 24 for position in challenge.positions)
    answers = [f"  Word{position - 1} " for position in challenge.positions]
    assert challenge.verify(answers)
    assert not challenge.verify(["nope"] * 3)
    assert not challenge.verify(answers[:2])


def test_recovery_phrase_challenge_positions_are_random() -> None:
    phrase = " ".join(f"word{index}" for index in range(24))
    seen = {recovery_center.RecoveryPhraseChallenge(phrase).positions for _ in range(40)}
    assert len(seen) > 1


def test_recovery_phrase_challenge_rejects_wrong_word_count() -> None:
    with pytest.raises(RecoveryError):
        recovery_center.RecoveryPhraseChallenge("only three words")


# --------------------------------------------------------------------------
# RecoveryCenter: phrase lifecycle without ever storing the phrase
# --------------------------------------------------------------------------

def test_center_creates_and_regenerates_recovery_phrase(tmp_path: Path) -> None:
    path = _profile(tmp_path / "profile") / "vault.json"
    session = unlock_vault(path, MASTER)
    center = RecoveryCenter(RecoveryController(session))
    assert center.recovery_phrase_status() == {"operation": "recovery-phrase", "recovery_phrase_enrolled": False}

    phrase = center.create_recovery_phrase(MASTER)
    assert len(phrase.split()) == 24
    assert center.last_result == {"operation": "recovery-phrase", "committed": True, "recovery_phrase_enrolled": True}
    assert phrase not in json.dumps(center.last_result)
    assert center.recovery_phrase_status()["recovery_phrase_enrolled"] is True

    second = center.create_recovery_phrase(MASTER)
    assert second != phrase
    session.lock()
    with pytest.raises(RecoveryPhraseError):
        unlock_with_recovery_phrase(path, phrase)
    recovered = unlock_with_recovery_phrase(path, second)
    assert recovered.is_unlocked
    recovered.lock()


def test_center_recovery_phrase_rejects_wrong_password_and_needs_a_session(tmp_path: Path) -> None:
    path = _profile(tmp_path / "profile") / "vault.json"
    session = unlock_vault(path, MASTER)
    center = RecoveryCenter(RecoveryController(session))
    with pytest.raises(RecoveryError):
        center.create_recovery_phrase("not the master password")
    assert center.recovery_phrase_status()["recovery_phrase_enrolled"] is False
    session.lock()

    locked_center = RecoveryCenter(service=SimpleNamespace())
    with pytest.raises(RecoveryError, match="Unlock"):
        locked_center.create_recovery_phrase(MASTER)
    assert locked_center.recovery_phrase_status()["recovery_phrase_enrolled"] is False


def test_recover_with_phrase_sets_a_new_master_password(tmp_path: Path) -> None:
    path = _profile(tmp_path / "profile") / "vault.json"
    session = unlock_vault(path, MASTER)
    phrase = session.create_recovery_phrase(MASTER)
    session.lock()

    recovered = recovery_center.recover_with_phrase(path, phrase, NEW_MASTER)
    assert recovered.is_unlocked and not recovered.recovery_unlocked
    recovered.lock()
    with pytest.raises(InvalidMasterPassword):
        unlock_vault(path, MASTER)
    reopened = unlock_vault(path, NEW_MASTER)
    assert reopened.has_recovery_phrase()  # the phrase survives a password reset
    reopened.lock()
    with pytest.raises(RecoveryPhraseError):
        recovery_center.recover_with_phrase(path, "abandon " * 23 + "zoo", NEW_MASTER)
    with pytest.raises(VaultError):
        recovery_center.recover_with_phrase(path, phrase, "short")


# --------------------------------------------------------------------------
# RecoveryWindow flows (Tk-free, using stubbed forms/dialogs)
# --------------------------------------------------------------------------

def test_center_forwards_allow_rollback_to_the_verified_restore(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from localvault.recovery import sha256_file

    source = tmp_path / "catalog.lgk"
    source.write_text("{}", encoding="utf-8")
    seen: list[dict[str, object]] = []

    def restore(_snapshot, *, vault_file: Path, **kwargs):
        seen.append(kwargs)
        vault_file.parent.mkdir(parents=True, exist_ok=True)
        vault_file.write_text("encrypted", encoding="utf-8")
        return {"verified": True}

    monkeypatch.setattr(recovery_center, "restore_verified_backup", restore)
    center = RecoveryCenter(service=SimpleNamespace())
    center.restore(source, tmp_path / "one", confirm=True, expected_sha256=sha256_file(source),
                   backup_password="synthetic backup password", vault_password="synthetic vault password")
    center.restore(source, tmp_path / "two", confirm=True, expected_sha256=sha256_file(source), allow_rollback=True,
                   backup_password="synthetic backup password", vault_password="synthetic vault password")
    assert seen[0]["allow_rollback"] is False
    assert seen[1]["allow_rollback"] is True


# --------------------------------------------------------------------------
# recovery.py: the catalog notes that a phrase exists, never the phrase
# --------------------------------------------------------------------------

def test_backup_inventory_notes_recovery_phrase_enrolment_without_storing_it(tmp_path: Path) -> None:
    profile = _profile(tmp_path / "source")
    before = create_recovery_backup(tmp_path / "before.lgk", profile_dir=profile, backup_password=BACKUP_PASSWORD,
                                    vault_password=MASTER)
    assert before["recovery_phrase_enrolled"] is False

    session = unlock_vault(profile / "vault.json", MASTER)
    phrase = session.create_recovery_phrase(MASTER)
    session.lock()
    after = create_recovery_backup(tmp_path / "after.lgk", profile_dir=profile, backup_password=BACKUP_PASSWORD,
                                   vault_password=MASTER)
    assert after["recovery_phrase_enrolled"] is True
    manifest = json.loads((tmp_path / "after.lgk.sha256.json").read_text(encoding="utf-8")) \
        if (tmp_path / "after.lgk.sha256.json").exists() else {}
    # Single BIP39 words (e.g. "salt") can appear in ordinary keys; the phrase must not.
    words = phrase.split()
    for blob in (json.dumps(after), json.dumps(manifest)):
        assert phrase not in blob
        assert all(" ".join(words[i:i + 3]) not in blob for i in range(len(words) - 2))

    kit = write_recovery_kit(tmp_path / "kit.json", backup=tmp_path / "after.lgk", inventory=after)
    payload = json.loads((tmp_path / "kit.json").read_text(encoding="utf-8"))
    assert kit["committed"] is True
    assert payload["inventory"]["recovery_phrase_enrolled"] is True
    assert payload["safety"]["contains_recovery_phrase"] is False
    assert "recovery phrase" in payload["restore_guide"].lower()
    assert _safe_inventory({"recovery_phrase_enrolled": True})["recovery_phrase_enrolled"] is True
    assert recovery_center.summarize_recovery(after)["recovery_phrase_enrolled"] is True


# --------------------------------------------------------------------------
# auth_ui: countdown state driven by UnlockThrottled.retry_after
# --------------------------------------------------------------------------

class _Clock:
    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now


def test_unlock_backoff_countdown_uses_the_injected_clock() -> None:
    clock = _Clock()
    backoff = auth_ui.UnlockBackoff(clock=clock)
    assert backoff.remaining() == 0.0 and backoff.message() == ""
    backoff.start(4.2)
    assert backoff.remaining() == pytest.approx(4.2)
    assert backoff.message() == "Too many incorrect attempts. Try again in 5 s."
    clock.now += 3.0
    assert backoff.message() == "Too many incorrect attempts. Try again in 2 s."
    backoff.start(1.0)  # a shorter wait never cuts an active countdown
    assert backoff.remaining() == pytest.approx(1.2)
    clock.now += 1.2
    assert backoff.remaining() == 0.0 and backoff.message() == ""


def test_unlock_backoff_reads_retry_after_only_from_throttled_errors() -> None:
    assert auth_ui.backoff_seconds_from_error(UnlockThrottled(7.5)) == 7.5
    assert auth_ui.backoff_seconds_from_error(VaultError("other")) == 0.0
    assert auth_ui.backoff_seconds_from_error(InvalidMasterPassword("wrong")) == 0.0


# --------------------------------------------------------------------------
# The real Tk card: words shown, challenge answered, phrase scrubbed
# --------------------------------------------------------------------------

