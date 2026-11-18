"""Duress vault (sub-plan 08, Task 4): setup rules, the two-vault unlock, the hold and the signed marker."""
from __future__ import annotations

import json

import pytest

from localvault import duress
from localvault import vault as vault_module
from localvault.secret_text import SecretText
from localvault.sync.pairing import DeviceIdentity
from localvault.vault import (
    InvalidMasterPassword,
    ProFeatureRequired,
    RecoveryPhraseError,
    create_vault,
    unlock_vault,
)

KDF = {"time_cost": 1, "memory_cost_kib": 8192, "parallelism": 1, "hash_len": 32}
REAL = "correct horse battery"
DURESS = "orange tractor sunset"
HOURS = 6


@pytest.fixture(autouse=True)
def isolated(tmp_path, monkeypatch):
    monkeypatch.setenv("LOCALGATEKEYS_DATA_DIR", str(tmp_path / "lgk-data"))
    vault_module._reset_unlock_throttle_state_for_tests()
    yield
    vault_module._reset_unlock_throttle_state_for_tests()


@pytest.fixture(autouse=True)
def boot(monkeypatch):
    """A fake monotonic clock for the hold: [boot id, seconds since boot]."""
    clock = ["boot-1", 1000]
    monkeypatch.setattr(duress, "_boot_clock", lambda: (clock[0], clock[1]))
    return clock


@pytest.fixture
def real(tmp_path):
    path = tmp_path / "profile" / "vault.json"
    path.parent.mkdir()
    session = create_vault(path, REAL, kdf_overrides=KDF)
    session.upsert_web(origin="https://bank.example", username="owner", password="bank secret 1")
    session.upsert_web(origin="https://news.example", username="owner", password="news secret 1")
    session.item_service.create_note("Diary", "private text")
    session.item_service.create_bookmark("Recipes", "https://recipes.example/")
    session.save()
    yield session
    session.lock()


def _ids(session, *titles):
    by_title = {c["title"]: c["id"] for c in duress.copy_candidates(session)}
    return [by_title[title] for title in titles]


# ------------------------------------------------------------------------------------- setup rules
@pytest.mark.parametrize("candidate", [REAL, REAL + "!", REAL[:-1], "X" + REAL, REAL[:5] + "X" + REAL[6:],
                                       REAL[:3] + REAL[4:]])
def test_setup_refuses_the_master_password_and_one_edit_away(real, candidate):
    with pytest.raises(duress.DuressError) as refused:
        duress.setup(real, candidate, lock_hours=HOURS, master_password=REAL)
    assert refused.value.code == ("same" if candidate == REAL else "close")
    assert not duress.configured(real.path)


def test_two_edits_away_is_allowed(real):
    duress.setup(real, REAL + "!!", lock_hours=HOURS, master_password=REAL)
    assert duress.configured(real.path)


def test_within_one_edit_counts_code_points_not_bytes():
    assert duress.within_one_edit("pässwörd-long", "pässwörd-lon")
    assert duress.within_one_edit(SecretText.from_str("Χρήστος-key-1"), "Χρήστος-key-2")
    assert duress.within_one_edit("ab", "ba") is False  # a swap is two edits
    assert duress.within_one_edit("abcdef", "abcxyz") is False


def test_setup_needs_the_right_master_password_pro_and_valid_hours(real):
    with pytest.raises(InvalidMasterPassword):
        duress.setup(real, DURESS, lock_hours=HOURS, master_password="wrong password here")
    with pytest.raises(duress.DuressError) as hours:
        duress.setup(real, DURESS, lock_hours=0, master_password=REAL)
    assert hours.value.code == "hours"
    real.pro_features = frozenset()
    with pytest.raises(ProFeatureRequired):
        duress.setup(real, DURESS, lock_hours=HOURS, master_password=REAL)
    assert not duress.configured(real.path)


def test_setup_copies_the_picked_items_only(real):
    path = duress.setup(real, DURESS, lock_hours=HOURS, master_password=REAL,
                        items=_ids(real, "news.example", "Recipes"))
    assert path == real.path.parent / ".lgk-d" / "vault.json" and duress.lock_hours(real) == HOURS
    second = duress.try_open(path, DURESS)
    try:
        assert [s.label for s in second.summaries()] == ["news.example"]
        assert [i["title"] for i in second.item_service.list_items()] == ["Recipes"]
    finally:
        second.lock()


def test_setup_without_picks_makes_plausible_sample_items(real):
    path = duress.setup(real, DURESS, lock_hours=HOURS, master_password=REAL)
    second = duress.try_open(path, DURESS)
    try:
        logins = second.summaries()
        assert len(logins) == 2 and {s.username for s in logins} == {"owner"}
        assert {i["kind"] for i in second.item_service.list_items()} == {"note", "bookmark"}
        assert all("bank" not in s.label for s in logins)
    finally:
        second.lock()


def test_setup_and_remove_are_refused_inside_a_duress_session(real):
    path = duress.setup(real, DURESS, lock_hours=HOURS, master_password=REAL)
    second = duress.try_open(path, DURESS)
    try:
        with pytest.raises(duress.DuressError) as inside:
            duress.setup(second, "another long password", lock_hours=HOURS, master_password=DURESS)
        assert inside.value.code == "generic"
        assert str(inside.value) == vault_module.t("duress.err.generic")
        with pytest.raises(duress.DuressError):
            duress.remove(second)
    finally:
        second.lock()
    removed = duress.remove(real)
    assert removed is True and not duress.configured(real.path) and duress.lock_hours(real) is None
    assert not (real.path.parent / ".lgk-d").exists()


# ---------------------------------------------------------------------------------- the unlock
def test_try_open_flags_the_session(real):
    path = duress.setup(real, DURESS, lock_hours=HOURS, master_password=REAL)
    assert duress.try_open(path, "wrong password here") is None
    assert duress.try_open(path, REAL) is None
    second = duress.try_open(path, DURESS)
    try:
        assert second.decoy is True and second.sync_enabled is False and second.browser_enabled is False
        assert duress.is_decoy(second) and not duress.is_decoy(real)
    finally:
        second.lock()


def _counting(monkeypatch):
    calls = []
    original = vault_module._derive_key

    def derive(password, kdf):
        calls.append(kdf["salt"])
        return original(password, kdf)

    monkeypatch.setattr(vault_module, "_derive_key", derive)
    return calls


def _open(path, password, **kwargs):
    return duress.open_vault(path, password, **kwargs)


def test_open_vault_does_the_same_argon2_work_whichever_password_matched(real, monkeypatch):
    duress.setup(real, DURESS, lock_hours=HOURS, master_password=REAL)
    path = real.path
    real.lock()
    calls = _counting(monkeypatch)
    opened = _open(path, REAL, now=1000)
    assert not duress.is_decoy(opened) and len(calls) == 2
    opened.lock()
    calls.clear()
    opened = _open(path, DURESS, now=1000)
    assert duress.is_decoy(opened) and len(calls) == 2
    opened.lock()
    calls.clear()
    with pytest.raises(InvalidMasterPassword) as wrong:
        _open(path, "wrong password here", now=1000)
    assert len(calls) == 2
    # Same text as a vault that has no duress password at all.
    other = create_vault(path.parent.parent / "other.json", REAL, kdf_overrides=KDF)
    other.lock()
    with pytest.raises(InvalidMasterPassword) as plain:
        unlock_vault(other.path, "wrong password here")
    assert str(wrong.value) == str(plain.value)


def test_one_derivation_without_a_duress_password(real, monkeypatch):
    path = real.path
    real.lock()
    calls = _counting(monkeypatch)
    _open(path, REAL).lock()
    assert len(calls) == 1  # Ruling T4: no second derivation without a second vault
    calls.clear()
    with pytest.raises(InvalidMasterPassword):
        _open(path, "wrong password here")
    assert len(calls) == 1


def test_a_duress_unlock_does_not_count_as_a_failed_attempt(real):
    duress.setup(real, DURESS, lock_hours=HOURS, master_password=REAL)
    path = real.path
    real.lock()
    for _ in range(6):
        _open(path, DURESS, now=1000).lock()
    assert vault_module.UnlockThrottle(path).failures == 0


def test_the_real_vault_is_held_for_lock_hours_after_a_duress_unlock(real, boot):
    duress.setup(real, DURESS, lock_hours=HOURS, master_password=REAL)
    path = real.path
    real.lock()
    t0 = 1_000_000
    second = _open(path, DURESS, now=t0)
    assert duress.trip(path, second, now=t0) == t0 + HOURS * 3600
    second.lock()
    boot[1] += 3600
    with pytest.raises(InvalidMasterPassword) as held:
        _open(path, REAL, now=t0 + 3600)
    assert str(held.value) == vault_module.t("vault.err.wrongPasswordOrModified")
    assert vault_module.UnlockThrottle(path).failures == 1
    assert duress.release(path, now=t0 + 3600) is None  # still held: nothing removed
    # The duress password still opens the second vault during the hold.
    _open(path, DURESS, now=t0 + 7200).lock()
    boot[1] += HOURS * 3600 - 3600 + 1
    opened = _open(path, REAL, now=t0 + HOURS * 3600 + 1)
    assert not duress.is_decoy(opened)
    opened.lock()
    assert duress.release(path, now=t0 + HOURS * 3600 + 1) == t0
    assert not duress.hold_path(path).exists()


def test_a_later_trip_never_shortens_the_hold(real):
    duress.setup(real, DURESS, lock_hours=HOURS, master_password=REAL)
    second = duress.try_open(duress.decoy_path(real.path), DURESS)
    duress.atomic_write_json(duress.hold_path(real.path), {"version": 1, "since": 10, "until": 10**10})
    assert duress.trip(real.path, second, now=1000) == 10**10
    second.lock()


def test_an_unreadable_hold_fails_closed(real):
    duress.hold_path(real.path).write_text("not json", encoding="utf-8")
    assert duress.real_held(real.path)


def test_the_recovery_phrase_is_refused_while_held(real):
    phrase = real.create_recovery_phrase(REAL)
    duress.setup(real, DURESS, lock_hours=HOURS, master_password=REAL)
    with pytest.raises(RecoveryPhraseError) as refused:
        duress.refuse_recovery(real.path, phrase)
    assert str(refused.value) == vault_module.t("vault.err.recoveryWrongVault")
    with pytest.raises(RecoveryPhraseError) as wrong_word:
        duress.refuse_recovery(real.path, "notaword " * 24)
    assert str(wrong_word.value) == vault_module.t("vault.err.recoveryUnknownWord")


# ------------------------------------------------------------------------------------- the marker
def _pair():
    owner_device, other_device = DeviceIdentity.generate(), DeviceIdentity.generate()
    return owner_device, other_device


def test_marker_written_by_one_device_is_read_by_another(tmp_path):
    folder = tmp_path / "cloud"
    (folder / "LocalGateKeys Sync").mkdir(parents=True)
    tripped, reader = _pair()
    identity = duress.MarkerIdentity.create(tripped, "group-1", str(folder))
    path = duress.mark_tripped(folder, identity, now=5000)
    assert path is not None and path.parent.name == "alerts"
    assert "duress" not in path.name and "decoy" not in path.name
    trusted = {tripped.device_id: tripped.signing_public_key}
    (marker,) = duress.read_markers(folder, trusted, group_id="group-1", exclude={reader.device_id}, now=6000)
    assert (marker.device_id, marker.time) == (tripped.device_id, 5000)
    # Its own marker, another group, an unknown device, a stale marker: nothing.
    assert duress.read_markers(folder, trusted, group_id="group-1", exclude={tripped.device_id}, now=6000) == []
    assert duress.read_markers(folder, trusted, group_id="group-2", now=6000) == []
    assert duress.read_markers(folder, {reader.device_id: reader.signing_public_key}, group_id="group-1",
                               now=6000) == []
    assert duress.read_markers(folder, trusted, group_id="group-1", now=5000 + duress.MARKER_MAX_AGE + 1) == []


def test_a_marker_key_not_endorsed_by_the_device_is_refused(tmp_path):
    folder = tmp_path / "cloud"
    (folder / "LocalGateKeys Sync").mkdir(parents=True)
    tripped, forger = _pair()
    forged = duress.MarkerIdentity.create(forger, "group-1", str(folder))
    forged = duress.MarkerIdentity(tripped.device_id, "group-1", str(folder), forged.signing_key,
                                   forged.endorsement)
    duress.mark_tripped(folder, forged, now=5000)
    assert duress.read_markers(folder, {tripped.device_id: tripped.signing_public_key}, group_id="group-1",
                               now=6000) == []


def test_a_tampered_marker_is_refused(tmp_path):
    folder = tmp_path / "cloud"
    (folder / "LocalGateKeys Sync").mkdir(parents=True)
    tripped, _reader = _pair()
    path = duress.mark_tripped(folder, duress.MarkerIdentity.create(tripped, "g", str(folder)), now=5000)
    outer = json.loads(path.read_bytes())
    outer["sender"] = "x"
    path.write_text(json.dumps(outer), encoding="utf-8")
    assert duress.read_markers(folder, {tripped.device_id: tripped.signing_public_key}, group_id="g",
                               now=6000) == []


def test_no_marker_without_a_folder(tmp_path):
    tripped, _reader = _pair()
    identity = duress.MarkerIdentity.create(tripped, "g", str(tmp_path / "missing"))
    assert duress.mark_tripped(tmp_path / "missing", identity) is None
    assert duress.mark_tripped(None, identity) is None
    assert duress.mark_tripped(tmp_path, None) is None
    assert not (tmp_path / "missing").exists()


def test_the_marker_identity_travels_in_the_second_vault(real, tmp_path):
    tripped, _reader = _pair()
    identity = duress.MarkerIdentity.create(tripped, "g", str(tmp_path))
    path = duress.setup(real, DURESS, lock_hours=HOURS, master_password=REAL, marker=identity)
    second = duress.try_open(path, DURESS)
    try:
        kept = duress.marker_identity(second)
        assert kept is not None and kept.public == identity.public and kept.endorsement == identity.endorsement
        assert kept.folder == str(tmp_path) and kept.device_id == tripped.device_id
    finally:
        second.lock()
    assert duress.marker_identity(real) is None
    # The real vault keeps the hold time and the fingerprint, never the marker key.
    raw = json.dumps(real._read_prefs().get(duress.REAL_PREF))
    assert "marker" not in raw and identity.to_record()["key"] not in raw


def test_setup_again_after_a_half_removed_second_vault(real):
    path = duress.setup(real, DURESS, lock_hours=HOURS, master_password=REAL)
    second = duress.try_open(path, DURESS)
    for _ in range(3):
        second.item_service.create_note("more", "text")  # raises its generation and rollback record
    second.lock()
    path.unlink()  # the vault file gone, its rollback record left behind
    duress.setup(real, "another long duress one", lock_hours=HOURS, master_password=REAL)
    reopened = duress.try_open(path, "another long duress one")
    assert reopened is not None
    reopened.lock()


# ----------------------------------------------------------------------------- fix round 1 (review T4)
def test_the_first_layout_is_removed_on_sight(real):
    old = real.path.with_name("vault.json.decoy")
    old_vault = create_vault(old, DURESS, kdf_overrides=KDF)
    old_vault.lock()
    real.path.with_name("vault.json.decoy-hold").write_text("{}", encoding="utf-8")
    path = real.path
    real.lock()
    with pytest.raises(InvalidMasterPassword):
        _open(path, DURESS)  # the old second vault no longer opens: it is gone
    assert not old.exists() and not path.with_name("vault.json.decoy-hold").exists()
    assert not list(path.parent.glob("vault.json.*generation*"))
    # The real vault's own sidecars survive (review R5).
    for name in ("vault.generation.json", "vault.unlock-throttle.json", "vault.unlock-throttle.key"):
        assert path.with_name(name).exists(), name
    _open(path, REAL).lock()


def test_a_new_master_password_must_stay_away_from_the_duress_password(real):
    duress.setup(real, DURESS, lock_hours=HOURS, master_password=REAL)
    for close in (DURESS, DURESS + "!", DURESS[:-1], "X" + DURESS, DURESS[:4] + "X" + DURESS[5:],
                  SecretText.from_str(DURESS[:3] + DURESS[4:])):
        with pytest.raises(duress.DuressError) as refused:
            duress.check_new_master(real, close)
        assert refused.value.code == "near_duress"
    duress.check_new_master(real, DURESS + "!!")  # two edits away: allowed
    duress.check_new_master(real, "a completely new password")
    # The fingerprint is a keyed hash inside the encrypted real vault, never the password itself.
    record = json.dumps(real._read_prefs()[duress.REAL_PREF])
    assert DURESS not in record and "near" in record


def test_a_duress_password_changed_later_is_still_refused_exactly(real):
    path = duress.setup(real, DURESS, lock_hours=HOURS, master_password=REAL)
    second = duress.try_open(path, DURESS)
    second.change_master_password(DURESS, "a fresh duress password")
    second.lock()
    with pytest.raises(duress.DuressError):
        duress.check_new_master(real, "a fresh duress password")


def test_a_duress_session_never_tests_passwords_against_the_real_vault(real, monkeypatch):
    path = duress.setup(real, DURESS, lock_hours=HOURS, master_password=REAL)
    second = duress.try_open(path, DURESS)
    calls = _counting(monkeypatch)
    try:
        # Review R2: no real-vault oracle from inside (even during a hold) and no real throttle failures.
        duress.check_new_master(second, REAL)
        duress.check_new_master(second, "some other new password")
        assert calls == [] and vault_module.UnlockThrottle(real.path).failures == 0
    finally:
        second.lock()


def test_the_second_vault_keeps_its_own_documents(real, tmp_path):
    from localvault.attachments import DocumentService

    source = tmp_path / "real.txt"
    source.write_bytes(b"real document")
    real_docs = DocumentService(real)
    real_id = real_docs.create(source, title="Passport")
    path = duress.setup(real, DURESS, lock_hours=HOURS, master_password=REAL)
    second = duress.try_open(path, DURESS)
    try:
        docs = DocumentService(second)
        other = tmp_path / "other.txt"
        other.write_bytes(b"second document")
        second_id = docs.create(other, title="Letter")
        newer = tmp_path / "newer.txt"
        newer.write_bytes(b"replaced")
        docs.replace(second_id, newer)  # runs the attachment clean-up of the open vault
        assert docs.read(second_id) == b"replaced"
        assert docs.store.root.parent == path.parent
    finally:
        second.lock()
    assert real_docs.read(real_id) == b"real document"


def test_duress_password_opens_when_the_real_vault_wants_a_missing_security_key(real, monkeypatch):
    duress.setup(real, DURESS, lock_hours=HOURS, master_password=REAL)
    path = real.path
    real.lock()

    def needs_key(*args, **kwargs):
        raise vault_module.FactorRequired("security key required")

    monkeypatch.setattr(duress, "unlock_vault", needs_key)
    opened = _open(path, DURESS, now=1000)
    assert duress.is_decoy(opened)
    opened.lock()
    with pytest.raises(vault_module.FactorRequired):
        _open(path, "wrong password here", now=1000)
