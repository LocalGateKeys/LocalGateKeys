"""Sub-plan 08 Task 3: serverless emergency access flows (request, deny, grant now, combine and restore)."""
from __future__ import annotations

import base64
import json
import os
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric import ed25519

from localvault import vault as vault_module
from localvault import envelope, heir, heir_flow
from localvault.vault import DEFAULT_KDF, create_vault, entropy_from_phrase, unlock_vault

TEST_KDF = {"time_cost": 1, "memory_cost_kib": 8192, "parallelism": 1, "hash_len": 32}
MASTER = "correct horse battery staple"
NEW_PASSWORD = "the heir's new master password"
NOW = 1_800_000_000
DAY = 86400
HOLDERS = ("Anna", "Ben", "Chris")


@pytest.fixture(autouse=True)
def _isolated(monkeypatch, tmp_path):
    monkeypatch.setenv("LOCALGATEKEYS_DATA_DIR", str(tmp_path / "lgk-data"))
    monkeypatch.delenv(heir_flow.NOW_ENV, raising=False)
    monkeypatch.setattr(vault_module, "DEFAULT_KDF", {**DEFAULT_KDF, **TEST_KDF})
    vault_module._reset_unlock_throttle_state_for_tests()
    yield
    vault_module._reset_unlock_throttle_state_for_tests()


@pytest.fixture
def shared(tmp_path):
    folder = tmp_path / "shared"
    folder.mkdir()
    return folder


@pytest.fixture
def owner(tmp_path, shared):
    """The owner's profile (a vault with one login and a recovery phrase) and a 2-of-3, 7-day plan."""
    profile = tmp_path / "owner-profile"
    profile.mkdir()
    session = create_vault(profile / "vault.json", MASTER, kdf_overrides=TEST_KDF)
    session.upsert_web(origin="https://bank.example", username="ilias", password="owner secret 1")
    phrase = session.create_recovery_phrase(MASTER)
    plan, packages = heir.create_plan(session, k=2, n=3, holders=HOLDERS, wait_days=7, folder=shared,
                                      phrase=phrase, reauthenticate=lambda: True, owner="Ilias", now=NOW)
    return {"session": session, "phrase": phrase, "plan": plan, "packages": packages, "profile": profile}


def _backup(owner, *, now=NOW + 60):
    target = heir_flow.backup_target(owner["session"])
    assert target is not None
    return heir_flow.write_backup(target, profile_dir=owner["profile"], profile_name="Owner", now=now)


def _request(owner, shared, *, index=0, now=NOW + DAY):
    identity = heir_flow.RequesterIdentity.generate()
    path = heir_flow.request_access(shared, owner["packages"][index], identity, now=now)
    return identity, path


def _restore(shared, packages, identity, tmp_path, *, now, name="restored"):
    destination = tmp_path / "heir-profiles" / name
    destination.parent.mkdir(exist_ok=True)
    return heir_flow.combine_and_restore(shared, packages, identity, destination=destination,
                                         new_password=NEW_PASSWORD, now=now)


def _refused(reason, fn, *args, **kwargs):
    with pytest.raises(heir_flow.HeirFlowError) as raised:
        fn(*args, **kwargs)
    assert raised.value.reason == reason
    return raised.value


# ------------------------------------------------------------------------------------------- request
def test_request_is_pending_on_the_owner(owner, shared):
    _identity, path = _request(owner, shared, index=1, now=NOW + DAY)
    assert path.parent == heir_flow.plan_dir(shared, owner["plan"].plan_id) and path.is_file()
    (pending,) = heir_flow.pending_requests(owner["session"], now=NOW + 2 * DAY)
    assert pending.holder == "Ben" and pending.holder_index == 2
    assert pending.created == NOW + DAY and pending.days_left == 6
    assert not pending.denied and not pending.granted
    assert heir_flow.pending_requests(owner["session"], now=NOW + 9 * DAY)[0].days_left == 0


def test_request_needs_a_real_shard_of_the_plan(owner, shared, tmp_path):
    """A forged request (another plan's shard, or a tampered proof) never reaches the owner's list."""
    other = create_vault(tmp_path / "other.json", MASTER, kdf_overrides=TEST_KDF)
    other_phrase = other.create_recovery_phrase(MASTER)
    _plan, other_packages = heir.create_plan(other, k=2, n=2, holders=("X", "Y"), wait_days=1, folder=shared,
                                             phrase=other_phrase, reauthenticate=lambda: True, now=NOW)
    identity = heir_flow.RequesterIdentity.generate()
    stray = heir_flow.request_access(shared, other_packages[0], identity, now=NOW)
    assert stray.parent != heir_flow.plan_dir(shared, owner["plan"].plan_id)
    # A request with the right plan id whose proof was made with a guessed share.
    _identity, path = _request(owner, shared)
    outer = json.loads(path.read_bytes())
    payload = json.loads(base64.b64decode(outer["payload"]))
    payload["proof"] = base64.b64encode(b"\x01" * 32).decode()
    key = ed25519.Ed25519PrivateKey.generate()
    forged = envelope.seal_signed(heir.FORMAT, heir.VERSION, package_id=outer["id"], sender="Anna",
                                  payload=payload, signing_key=key)
    path.write_bytes(forged)
    (path.parent / "request-garbage.lgkheirreq").write_bytes(b"{not json")
    assert heir_flow.pending_requests(owner["session"], now=NOW + DAY) == []


def test_request_needs_an_existing_folder(owner, tmp_path):
    identity = heir_flow.RequesterIdentity.generate()
    _refused("no-folder", heir_flow.request_access, tmp_path / "missing", owner["packages"][0], identity, now=NOW)


def test_identity_round_trips_through_its_record():
    identity = heir_flow.RequesterIdentity.generate()
    again = heir_flow.RequesterIdentity.from_record(identity.to_record())
    assert again.signer == identity.signer and again.box_public == identity.box_public
    with pytest.raises(heir_flow.HeirFlowError):
        heir_flow.RequesterIdentity.from_record({**identity.to_record(), "box_key": "AAAA"})


# ---------------------------------------------------------------------------------------------- deny
def test_deny_makes_combine_refuse_with_denied(owner, shared, tmp_path):
    _backup(owner)
    identity, _path = _request(owner, shared)
    (pending,) = heir_flow.pending_requests(owner["session"], now=NOW + DAY)
    deny_path = heir_flow.deny(owner["session"], pending, now=NOW + 2 * DAY)
    assert deny_path.is_file()
    assert heir_flow.pending_requests(owner["session"], now=NOW + 2 * DAY) == []
    error = _refused("denied", _restore, shared, owner["packages"][:2], identity, tmp_path, now=NOW + 30 * DAY)
    assert "denied" in str(error).lower()
    assert not (tmp_path / "heir-profiles" / "restored").exists()


def test_veto_wins_even_from_an_owner_clock_far_in_the_future(owner, shared, tmp_path):
    _backup(owner)
    identity, _path = _request(owner, shared, now=NOW + DAY)
    (pending,) = heir_flow.pending_requests(owner["session"], now=NOW + DAY)
    heir_flow.deny(owner["session"], pending, now=NOW + 50 * 365 * DAY)  # "late" by any clock
    _refused("denied", _restore, shared, owner["packages"][:2], identity, tmp_path, now=NOW + 8 * DAY + 1)


def test_a_deleted_deny_file_is_written_again_by_the_owner(owner, shared, tmp_path):
    _backup(owner)
    identity, _path = _request(owner, shared)
    (pending,) = heir_flow.pending_requests(owner["session"], now=NOW + DAY)
    deny_path = heir_flow.deny(owner["session"], pending, now=NOW + DAY)
    deny_path.unlink()
    assert heir_flow.pending_requests(owner["session"], now=NOW + 2 * DAY) == []
    assert deny_path.is_file()
    _refused("denied", _restore, shared, owner["packages"][:2], identity, tmp_path, now=NOW + 9 * DAY)


def test_a_deny_signed_by_another_key_is_ignored(owner, shared, tmp_path):
    _backup(owner)
    identity, _path = _request(owner, shared)
    (pending,) = heir_flow.pending_requests(owner["session"], now=NOW + DAY)
    payload = {"kind": "heir-deny", "plan_id": pending.plan_id, "request_id": pending.request_id, "created": NOW}
    forged = envelope.seal_signed(heir.FORMAT, heir.VERSION, package_id=pending.request_id, sender="",
                                  payload=payload, signing_key=ed25519.Ed25519PrivateKey.generate())
    (heir_flow.plan_dir(shared, pending.plan_id) / f"deny-{pending.request_id}.lgkheirdeny").write_bytes(forged)
    restored = _restore(shared, owner["packages"][:2], identity, tmp_path, now=NOW + 8 * DAY + 1)
    assert restored.is_dir()


def test_request_again_after_a_deny_can_proceed(owner, shared, tmp_path):
    _backup(owner)
    identity = heir_flow.RequesterIdentity.generate()
    heir_flow.request_access(shared, owner["packages"][0], identity, now=NOW + DAY)
    (first,) = heir_flow.pending_requests(owner["session"], now=NOW + DAY)
    heir_flow.deny(owner["session"], first, now=NOW + DAY)
    heir_flow.request_access(shared, owner["packages"][0], identity, now=NOW + 2 * DAY)
    status = heir_flow.request_status(shared, owner["packages"][:2], identity, now=NOW + 3 * DAY)
    assert status.state == "waiting" and status.days_left == 6
    restored = _restore(shared, owner["packages"][:2], identity, tmp_path, now=NOW + 9 * DAY + 1)
    assert restored.is_dir()


# -------------------------------------------------------------------------------- combine and restore
def test_no_deny_after_the_waiting_period_restores_the_backup_into_a_new_vault(owner, shared, tmp_path):
    backup_path = _backup(owner)
    identity, _path = _request(owner, shared, index=2, now=NOW + DAY)
    status = heir_flow.request_status(shared, owner["packages"][1:], identity, now=NOW + 3 * DAY)
    assert status.state == "waiting" and status.days_left == 5
    _refused("waiting", _restore, shared, owner["packages"][1:], identity, tmp_path, now=NOW + 8 * DAY - 1)
    assert heir_flow.request_status(shared, owner["packages"][1:], identity, now=NOW + 8 * DAY).state == "ready"
    restored = _restore(shared, owner["packages"][1:], identity, tmp_path, now=NOW + 8 * DAY)
    assert restored == tmp_path / "heir-profiles" / "restored"
    session = unlock_vault(restored / "vault.json", NEW_PASSWORD)
    try:
        (entry,) = session.all_entries()
        assert entry["username"] == "ilias" and entry["password"] == "owner secret 1"
        # The copy is the heir's now: it carries no emergency access plan (no signing key of the owner's).
        assert session.heir_plan_record() is None
    finally:
        session.lock()
    # The owner's vault and the shared backup are untouched; nothing is left beside the destination.
    assert unlock_vault(owner["profile"] / "vault.json", MASTER).all_entries()
    assert backup_path.is_file()
    assert sorted(p.name for p in restored.parent.iterdir()) == ["restored"]


def test_the_heir_backup_is_locked_to_the_plan_key_not_a_password(owner):
    path = _backup(owner)
    header_data, header = heir_flow._backup_header(path)
    assert header_data and header["recipient"]["key_id"] == heir_flow.backup_key_id(owner["plan"])
    entropy = entropy_from_phrase(owner["phrase"])
    private = heir.backup_private_key(entropy, plan_id=owner["plan"].plan_id, salt=owner["plan"].check_salt)
    from localvault.backup_key import x25519_public
    assert x25519_public(private) == owner["plan"].backup_public


def test_a_backup_older_than_the_plan_is_refused_with_no_recent_backup(owner, shared, tmp_path):
    identity, _path = _request(owner, shared)
    error = _refused("no-backup", _restore, shared, owner["packages"][:2], identity, tmp_path,
                     now=NOW + 9 * DAY)
    assert "no recent backup" in str(error).lower()
    _backup(owner, now=NOW - 1)  # written before the plan (owner offline since)
    error = _refused("no-backup", _restore, shared, owner["packages"][:2], identity, tmp_path,
                     now=NOW + 9 * DAY)
    assert "no recent backup" in str(error).lower()
    assert heir_flow.request_status(shared, owner["packages"][:2], identity, now=NOW + 9 * DAY).state == "no-backup"


def test_a_backup_file_changed_after_it_was_signed_is_refused(owner, shared, tmp_path):
    path = _backup(owner)
    identity, _path = _request(owner, shared)
    data = bytearray(path.read_bytes())
    data[-30] ^= 1
    path.write_bytes(bytes(data))
    _refused("no-backup", _restore, shared, owner["packages"][:2], identity, tmp_path, now=NOW + 9 * DAY)


def test_requester_without_k_shards_needs_more(owner, shared, tmp_path):
    _backup(owner)
    identity, _path = _request(owner, shared)
    error = _refused("need-more", _restore, shared, owner["packages"][:1], identity, tmp_path, now=NOW + 9 * DAY)
    assert error.missing == 1 and "need 1 more shard" in str(error).lower()
    status = heir_flow.request_status(shared, owner["packages"][:1], identity, now=NOW + 9 * DAY)
    assert status.state == "need-more" and status.missing == 1


def test_combine_without_a_request_is_refused(owner, shared, tmp_path):
    _backup(owner)
    identity = heir_flow.RequesterIdentity.generate()
    _refused("no-request", _restore, shared, owner["packages"][:2], identity, tmp_path, now=NOW + 9 * DAY)
    assert heir_flow.request_status(shared, owner["packages"][:2], identity, now=NOW).state == "none"


def test_the_clock_override_is_read_from_the_environment(owner, shared, tmp_path, monkeypatch):
    _backup(owner)
    identity, _path = _request(owner, shared, now=NOW + DAY)
    monkeypatch.setenv(heir_flow.NOW_ENV, str(NOW + 2 * DAY))
    assert heir_flow.request_status(shared, owner["packages"][:2], identity).days_left == 6
    monkeypatch.setenv(heir_flow.NOW_ENV, str(NOW + 8 * DAY))
    destination = tmp_path / "restored"
    assert heir_flow.combine_and_restore(shared, owner["packages"][:2], identity, destination=destination,
                                         new_password=NEW_PASSWORD).is_dir()


# ------------------------------------------------------------------------------------------ grant now
def test_grant_now_lets_combine_work_before_the_period_ends(owner, shared, tmp_path):
    _backup(owner)
    identity, _path = _request(owner, shared, now=NOW + DAY)
    (pending,) = heir_flow.pending_requests(owner["session"], now=NOW + DAY)
    calls = []
    grant_path = heir_flow.grant_now(owner["session"], pending, phrase=owner["phrase"],
                                     reauthenticate=lambda: calls.append(1) or True, now=NOW + DAY)
    assert calls == [1] and grant_path.is_file()
    entropy = entropy_from_phrase(owner["phrase"])
    assert base64.b64encode(entropy).decode() not in grant_path.read_text()
    assert heir_flow.pending_requests(owner["session"], now=NOW + DAY)[0].granted
    assert heir_flow.request_status(shared, owner["packages"][:1], identity, now=NOW + DAY + 5).state == "ready"
    # One shard is enough once the owner granted: the entropy arrives wrapped to the requester's key.
    restored = _restore(shared, owner["packages"][:1], identity, tmp_path, now=NOW + DAY + 5)
    session = unlock_vault(restored / "vault.json", NEW_PASSWORD)
    assert session.all_entries()[0]["password"] == "owner secret 1"
    session.lock()


def test_grant_needs_reauthentication_and_the_current_phrase(owner, shared):
    _request(owner, shared)
    (pending,) = heir_flow.pending_requests(owner["session"], now=NOW + DAY)
    with pytest.raises(PermissionError):
        heir_flow.grant_now(owner["session"], pending, phrase=owner["phrase"], reauthenticate=lambda: False)
    assert not any(heir_flow.plan_dir(shared, pending.plan_id).glob("grant-*"))


def test_a_grant_is_usable_only_by_the_requester_it_names(owner, shared, tmp_path):
    _backup(owner)
    _request(owner, shared, now=NOW + DAY)
    (pending,) = heir_flow.pending_requests(owner["session"], now=NOW + DAY)
    heir_flow.grant_now(owner["session"], pending, phrase=owner["phrase"], reauthenticate=lambda: True)
    other, _ = _request(owner, shared, index=1, now=NOW + DAY)
    assert heir_flow.request_status(shared, owner["packages"][1:], other, now=NOW + DAY).state == "waiting"
    assert heir_flow.request_status(shared, owner["packages"][1:2], other, now=NOW + DAY).state == "need-more"


def test_a_denied_request_cannot_be_granted_and_a_deny_beats_a_grant(owner, shared, tmp_path):
    _backup(owner)
    identity, _path = _request(owner, shared)
    (pending,) = heir_flow.pending_requests(owner["session"], now=NOW + DAY)
    heir_flow.grant_now(owner["session"], pending, phrase=owner["phrase"], reauthenticate=lambda: True)
    heir_flow.deny(owner["session"], pending)
    _refused("denied", _restore, shared, owner["packages"][:2], identity, tmp_path, now=NOW + DAY)
    _refused("denied", heir_flow.grant_now, owner["session"], pending, phrase=owner["phrase"],
             reauthenticate=lambda: True)


def test_recovered_entropy_is_checked_before_any_restore(owner, shared, tmp_path, monkeypatch):
    """A grant signed with the plan key but carrying the wrong secret stops at the HKDF check."""
    _backup(owner)
    identity, _path = _request(owner, shared)
    (pending,) = heir_flow.pending_requests(owner["session"], now=NOW + DAY)
    key = heir.plan_signing_key(owner["session"])
    data = heir_flow._seal_grant(owner["plan"], key, pending, os.urandom(32), now=NOW + DAY)
    (heir_flow.plan_dir(shared, pending.plan_id) / f"grant-{pending.request_id}.lgkheirgrant").write_bytes(data)
    called = []
    original_open = heir_flow._open_backup
    import localvault.backup as backup_module

    def spy_open(*args, **kwargs):
        called.append("open")
        return original_open(*args, **kwargs)

    monkeypatch.setattr(heir_flow, "_open_backup", spy_open)
    monkeypatch.setattr(backup_module, "restore_full_backup", lambda *a, **k: called.append("restore"))
    _refused("check-failed", _restore, shared, owner["packages"][:1], identity, tmp_path, now=NOW + DAY)
    assert called == []  # neither the backup nor the restore was touched with the wrong secret
    assert not (tmp_path / "heir-profiles" / "restored").exists()


def test_a_stale_plan_neither_grants_nor_writes_backups(owner, shared):
    _request(owner, shared)
    (pending,) = heir_flow.pending_requests(owner["session"], now=NOW + DAY)
    session = owner["session"]
    session.change_master_password(MASTER, "another master password 1")  # drops the phrase: plan stale
    assert heir_flow.backup_target(session) is None
    _refused("stale-plan", heir_flow.grant_now, session, pending, phrase=owner["phrase"],
             reauthenticate=lambda: True)


def test_replacing_the_phrase_leaves_old_shards_no_backup_to_open(owner, shared, tmp_path):
    """Ruling F-I1: once the phrase is replaced, the plan's next look deletes its backups from the heir folder."""
    _backup(owner)
    identity, _path = _request(owner, shared, now=NOW + DAY)
    assert heir_flow.request_status(shared, owner["packages"][:2], identity, now=NOW + 9 * DAY).state == "ready"
    session = owner["session"]
    session.change_master_password(MASTER, "another master password 1")  # drops the phrase: plan stale
    directory = heir_flow.plan_dir(shared, owner["plan"].plan_id)
    (directory / "backup-notes.txt").write_text("not ours")
    heir_flow.pending_requests(session, now=NOW + 2 * DAY)
    assert sorted(p.name for p in directory.iterdir() if p.name.startswith("backup-")) == ["backup-notes.txt"]
    assert heir_flow.request_status(shared, owner["packages"][:2], identity, now=NOW + 9 * DAY).state == "no-backup"
    _refused("no-backup", _restore, shared, owner["packages"][:2], identity, tmp_path, now=NOW + 9 * DAY)


# ----------------------------------------------------------------------------------- owner's backups
def test_backups_are_signed_kept_two_deep_and_due_daily(owner, shared):
    target = heir_flow.backup_target(owner["session"])
    assert heir_flow.backup_due(target, now=NOW)
    for hour in range(3):
        heir_flow.write_backup(target, profile_dir=owner["profile"], now=NOW + 3600 * (hour + 1))
    folder = heir_flow.plan_dir(shared, owner["plan"].plan_id)
    assert len(list(folder.glob("backup-*.lgk"))) == 2
    assert len(list(folder.glob("backup-*.lgkheirbackup"))) == 2
    assert not heir_flow.backup_due(target, now=NOW + 3 * 3600 + DAY - 1)
    assert heir_flow.backup_due(target, now=NOW + 3 * 3600 + DAY)


def test_backup_target_needs_a_plan_with_a_folder(tmp_path):
    session = create_vault(tmp_path / "vault.json", MASTER, kdf_overrides=TEST_KDF)
    phrase = session.create_recovery_phrase(MASTER)
    assert heir_flow.backup_target(session) is None
    heir.create_plan(session, k=2, n=2, holders=("A", "B"), wait_days=1, folder=None, phrase=phrase,
                     reauthenticate=lambda: True, now=NOW)
    assert heir_flow.backup_target(session) is None
    assert heir_flow.pending_requests(session) == []


def test_heir_files_are_named_for_the_folder_transport(owner, shared):
    _backup(owner)
    _request(owner, shared)
    names = [p.name for p in heir_flow.plan_dir(shared, owner["plan"].plan_id).iterdir()]
    assert names and all(heir_flow.is_heir_file(name) for name in names)
    assert heir_flow.is_heir_file(heir_flow.FOLDER_NAME)
    assert not heir_flow.is_heir_file("abc.lgksync")


def test_plan_dir_accepts_the_root_or_the_emergency_folder(shared):
    plan_id = "0b5f0c43-7f6a-4c2a-9a55-7d3f9f2f9c11"
    expected = shared / heir_flow.FOLDER_NAME / plan_id
    assert heir_flow.plan_dir(shared, plan_id) == expected
    assert heir_flow.plan_dir(shared / heir_flow.FOLDER_NAME, plan_id) == expected
    assert heir_flow.plan_dir(expected, plan_id) == expected
    assert isinstance(expected, Path)


# ---------------------------------------------------------------------------------- review fix round 1
def test_the_clock_override_is_ignored_in_a_frozen_release_build(monkeypatch):
    import sys

    monkeypatch.setenv(heir_flow.NOW_ENV, "1")
    assert heir_flow._clock() == 1  # a source run (tests, manual checks)
    monkeypatch.setattr(sys, "frozen", True, raising=False)
    assert heir_flow._clock() > NOW - 10 * 365 * DAY  # the real clock: a requester cannot skip the wait


def test_a_deny_that_lands_while_restoring_wins_and_nothing_is_published(owner, shared, tmp_path, monkeypatch):
    _backup(owner)
    identity, _path = _request(owner, shared)
    (pending,) = heir_flow.pending_requests(owner["session"], now=NOW + DAY)
    original = heir_flow._heirs_copy

    def deny_meanwhile(stage, new_password):
        original(stage, new_password)
        assert stage.is_dir()
        heir_flow.deny(owner["session"], pending)  # the owner refuses while the copy is being staged

    monkeypatch.setattr(heir_flow, "_heirs_copy", deny_meanwhile)
    _refused("denied", _restore, shared, owner["packages"][:2], identity, tmp_path, now=NOW + 9 * DAY)
    parent = tmp_path / "heir-profiles"
    assert list(parent.iterdir()) == []  # the stage is gone and nothing was published


def test_junk_names_in_the_folder_hide_neither_requests_nor_denies(owner, shared, tmp_path):
    _backup(owner)
    identity, _path = _request(owner, shared)
    folder = heir_flow.plan_dir(shared, owner["plan"].plan_id)
    for n in range(heir_flow.MAX_SCAN + 50):
        (folder / f"request-!{n:04d}.lgkheirreq").write_bytes(b"x")
        (folder / f"deny-!{n:04d}.lgkheirdeny").write_bytes(b"x")
    (pending,) = heir_flow.pending_requests(owner["session"], now=NOW + DAY)
    heir_flow.deny(owner["session"], pending)
    # Well-named junk that sorts before the real deny fills the scan cap; the deny's own name is read first.
    for n in range(heir_flow.MAX_SCAN + 50):
        (folder / f"deny-00000000-0000-4000-8000-{n:012x}.lgkheirdeny").write_bytes(b"{}")
    assert heir_flow.request_status(shared, owner["packages"][:2], identity, now=NOW + 9 * DAY).state == "denied"
    assert heir_flow.pending_requests(owner["session"], now=NOW + DAY) == []


# ------------------------------------------------------------- the plan syncs to the owner's other devices
class _Lease:
    def check(self) -> None:
        return None


def _sync(dst, dst_id, src, src_id, *, now=NOW + DAY):
    """One direction of a sync run: dst pulls src's view (local_view, merge, apply)."""
    from localvault.sync.engine import merge
    from localvault.sync.vault_bridge import apply, local_view

    lease = _Lease()
    src_view = local_view(src, lease, device_id=src_id, now=now)
    dst_view = local_view(dst, lease, device_id=dst_id, now=now)
    return apply(dst, lease, merge(dst_view, src_view.values()), device_id=dst_id, now=now)


@pytest.fixture
def device_b(tmp_path):
    session = create_vault(tmp_path / "device-b" / "vault.json", "device b master password",
                           kdf_overrides=TEST_KDF)
    return session


def test_device_b_denies_a_plan_that_device_a_made(owner, shared, tmp_path, device_b):
    _backup(owner)
    identity, _path = _request(owner, shared)
    _sync(device_b, "device-b", owner["session"], "device-a")
    plan_b = heir.load_plan(device_b)
    assert plan_b.plan_id == owner["plan"].plan_id and plan_b.signer == owner["plan"].signer
    assert plan_b.folder is None and plan_b.home is False  # the path is A's; B chooses its own
    assert heir_flow.backup_target(device_b) is None  # only the device that made the plan writes backups
    heir.set_plan_folder(device_b, shared)
    (pending,) = heir_flow.pending_requests(device_b, now=NOW + DAY)
    assert pending.holder == "Anna"
    heir_flow.deny(device_b, pending)
    _refused("denied", _restore, shared, owner["packages"][:2], identity, tmp_path, now=NOW + 9 * DAY)
    # B's refusal travels back to A; A's folder stays its own.
    _sync(owner["session"], "device-a", device_b, "device-b")
    plan_a = heir.load_plan(owner["session"])
    assert pending.request_id in plan_a.denied and plan_a.folder == shared and plan_a.home is True
    # Any owner device writes a deleted deny again.
    (heir_flow.plan_dir(shared, pending.plan_id) / f"deny-{pending.request_id}.lgkheirdeny").unlink()
    assert heir_flow.pending_requests(owner["session"], now=NOW + DAY) == []
    assert (heir_flow.plan_dir(shared, pending.plan_id) / f"deny-{pending.request_id}.lgkheirdeny").is_file()


def test_device_b_grants_with_the_plans_phrase(owner, shared, tmp_path, device_b):
    _backup(owner)
    identity, _path = _request(owner, shared)
    _sync(device_b, "device-b", owner["session"], "device-a")
    heir.set_plan_folder(device_b, shared)
    (pending,) = heir_flow.pending_requests(device_b, now=NOW + DAY)
    other = create_vault(tmp_path / "other.json", MASTER, kdf_overrides=TEST_KDF).create_recovery_phrase(MASTER)
    _refused("wrong-phrase", heir_flow.grant_now, device_b, pending, phrase=other, reauthenticate=lambda: True)
    with pytest.raises(PermissionError):
        heir_flow.grant_now(device_b, pending, phrase=owner["phrase"], reauthenticate=lambda: False)
    heir_flow.grant_now(device_b, pending, phrase=owner["phrase"], reauthenticate=lambda: True)
    assert _restore(shared, owner["packages"][:1], identity, tmp_path, now=NOW + DAY + 5).is_dir()


def test_concurrent_denies_merge_and_a_removed_plan_is_removed_everywhere(owner, shared, device_b):
    _sync(device_b, "device-b", owner["session"], "device-a")
    heir.set_plan_folder(device_b, shared)
    _request(owner, shared, index=0)
    _request(owner, shared, index=1)
    first, second = heir_flow.pending_requests(owner["session"], now=NOW + DAY)
    heir_flow.deny(owner["session"], first)  # on A
    heir_flow.deny(device_b, second)  # on B, at the same time
    _sync(owner["session"], "device-a", device_b, "device-b")
    _sync(device_b, "device-b", owner["session"], "device-a")
    for session in (owner["session"], device_b):
        assert set(heir.load_plan(session).denied) == {first.request_id, second.request_id}
    assert heir.load_plan(device_b).folder == shared  # B's own folder survived the merge
    heir.remove_plan(owner["session"])
    _sync(device_b, "device-b", owner["session"], "device-a")
    assert heir.load_plan(device_b) is None


def test_a_stale_plan_is_stale_everywhere_but_only_its_home_marks_it(owner, shared, device_b):
    _request(owner, shared)
    _sync(device_b, "device-b", owner["session"], "device-a")
    heir.set_plan_folder(device_b, shared)
    # B replacing its own phrase is not about the plan (B's vault never held the plan's phrase).
    device_b.create_recovery_phrase("device b master password")
    device_b.change_master_password("device b master password", "device b master password 2")
    assert heir.load_plan(device_b).stale is False
    owner["session"].change_master_password(MASTER, "another master password 1")  # A drops the phrase
    assert heir.load_plan(owner["session"]).stale is True
    _sync(device_b, "device-b", owner["session"], "device-a")
    assert heir.load_plan(device_b).stale is True
    (pending,) = heir_flow.pending_requests(device_b, now=NOW + DAY)
    _refused("stale-plan", heir_flow.grant_now, device_b, pending, phrase=owner["phrase"],
             reauthenticate=lambda: True)


def test_a_damaged_synced_plan_is_refused(owner, device_b):
    from localvault.sync.engine import ItemState
    from localvault.sync.vault_bridge import (
        HEIR_STATE_ID,
        BridgeError,
        check_remote_state,
        local_view,
    )

    view = local_view(owner["session"], _Lease(), device_id="device-a", now=NOW)
    state = view[HEIR_STATE_ID]
    assert state.item["ns"] == "heir" and "folder" not in state.item["record"] and "home" not in state.item["record"]
    assert check_remote_state(state) is None
    record = dict(state.item["record"], signing_key=base64.b64encode(b"\x01" * 32).decode())
    forged = ItemState(HEIR_STATE_ID, state.vv, False, None, {**state.item, "record": record})
    assert check_remote_state(forged) == "bad-remote"
    extra = ItemState(HEIR_STATE_ID, state.vv, False, None,
                      {**state.item, "record": {**state.item["record"], "folder": "C:/x"}})
    assert check_remote_state(extra) == "bad-remote"
    assert BridgeError


# ------------------------------------------------------------------- the owner app's timer (bug 2026-11-10)
def _service(owner, clock):
    from types import SimpleNamespace

    from localvault.app.heir_service import HeirService

    profile = SimpleNamespace(id="p1", name="Owner")
    controller = SimpleNamespace(is_unlocked=lambda: True, session=owner["session"], on_lock=[],
                                 profiles=SimpleNamespace(active_profile=lambda: profile,
                                                          profile_dir=lambda _pid: owner["profile"]))
    return HeirService(controller, None, None, spawn=lambda fn: fn(), clock=clock)


def test_the_owner_app_timer_writes_a_deleted_deny_again(owner, shared, monkeypatch):
    _backup(owner)
    _request(owner, shared)
    (pending,) = heir_flow.pending_requests(owner["session"], now=NOW + DAY)
    deny_path = heir_flow.deny(owner["session"], pending, now=NOW + DAY)
    _request(owner, shared, now=NOW + DAY + 60)  # re-asked: a new id, still open
    clock = [float(NOW + DAY)]
    service = _service(owner, lambda: clock[0])
    deny_path.unlink()
    assert service.timer_check() is True
    assert deny_path.is_file()
    deny_path.unlink()
    clock[0] += 539
    service.timer_check()
    assert not deny_path.exists()  # at most one look per 10 minutes
    clock[0] += 1
    assert service.timer_check() is True
    assert deny_path.is_file()
    assert len(list(deny_path.parent.glob("deny-*.lgkheirdeny"))) == 1  # only the refused id


def test_a_running_heir_backup_does_not_hold_back_the_deny_look(owner, shared):
    _request(owner, shared)
    (pending,) = heir_flow.pending_requests(owner["session"], now=NOW + DAY)
    deny_path = heir_flow.deny(owner["session"], pending, now=NOW + DAY)
    service = _service(owner, lambda: float(NOW + DAY))
    service._running = True  # a long (or stuck) backup of the heir folder
    deny_path.unlink()
    assert service.timer_check() is True
    assert deny_path.is_file()


def test_opening_the_emergency_page_writes_a_deleted_deny_again(owner, shared, monkeypatch):
    _request(owner, shared)
    (pending,) = heir_flow.pending_requests(owner["session"], now=NOW + DAY)
    deny_path = heir_flow.deny(owner["session"], pending, now=NOW + DAY)
    service = _service(owner, lambda: float(NOW + DAY))
    monkeypatch.setattr(service, "_session", lambda: (owner["session"], None))
    deny_path.unlink()
    assert service.view()["requests"] == []
    assert deny_path.is_file()


# ------------------------------------------------------------------- holder side (bugs 2026-11-10)
def test_a_restore_removes_the_used_request_from_the_owner_list(owner, shared, tmp_path):
    _backup(owner)
    identity, _path = _request(owner, shared, index=2, now=NOW + DAY)
    assert heir_flow.pending_requests(owner["session"], now=NOW + 8 * DAY)
    _restore(shared, owner["packages"][1:], identity, tmp_path, now=NOW + 8 * DAY)
    assert heir_flow.pending_requests(owner["session"], now=NOW + 8 * DAY) == []


def test_the_holder_shards_and_folder_outlive_a_lock(owner, shared):
    from types import SimpleNamespace

    service = _service(owner, lambda: float(NOW))
    controller = service._controller
    controller.guard = SimpleNamespace(lease=lambda: None)
    controller.require_lease = lambda _lease: None
    controller.session = owner["session"]
    service._dialogs = SimpleNamespace(choose_folder=lambda _title: str(shared))
    service._add(owner["packages"][0])
    service.choose_receive_folder()
    service._drop()  # lock (or restart): memory is cleared
    view = service.receive_view()
    assert [s["index"] for s in view["shards"]] == [heir.read_package(owner["packages"][0]).index]
    assert view["folder"] == str(shared)
    service.shards_clear()
    service._drop()
    assert service.receive_view()["shards"] == []
