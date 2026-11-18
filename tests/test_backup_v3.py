"""Full backup v3 (scheduled backups to a public key): writer, reader, re-lock, describe and the 9.1 self-verify.

Design: ``docs/design/backup-public-key-2026-10-31.md`` sections 1.1, 3.4, 7.2, 8 and 9.1.  The committed vectors in
``tests/vectors/backup/v3`` are byte-compared by ``test_backup_v3_vectors.py``; this file reads them and checks the
behaviour, including the owner's hard rule that old-format (v1/v2) backups are never touched.
"""

from __future__ import annotations

import base64
import hashlib
import importlib.util
import io
import json
import os
import sys
import zipfile
from pathlib import Path

import pytest

from localvault import backup
from localvault.backup import (
    RELOCK_OLD_FORMAT,
    RELOCK_OTHER_KEY,
    RELOCK_RELOCKED,
    BackupError,
    _full_canonical,
    _full_read_container,
    describe_backup,
    export_encrypted_backup,
    export_full_backup,
    export_full_backup_to_key,
    preflight_full_backup,
    relock_full_backup,
    relock_full_backups,
    restore_full_backup,
)
from localvault.backup_key import build_record, derive_backup_key, new_kdf
from localvault.backup_schedule import ensure_encrypted_container, owned_backups

ROOT = Path(__file__).resolve().parents[1]
VEC = ROOT / "tests" / "vectors" / "backup" / "v3"
EXPECTED = json.loads((VEC / "expected.json").read_text(encoding="utf-8"))
WRONG = "Wrong backup password or modified full backup"
CHEAP = {"time_cost": 1, "memory_cost_kib": 8192, "parallelism": 1}
PASSWORD = "first scheduled backup password"  # noqa: S105 - test value
SECOND = "second scheduled backup password"  # noqa: S105 - test value
THIRD = "third scheduled backup password"  # noqa: S105 - test value
TAG = "0a1b2c3d"


def _generator():
    spec = importlib.util.spec_from_file_location("gen_mac_backup_vectors_v3", ROOT / "scripts" / "gen_mac_backup_vectors.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules["gen_mac_backup_vectors_v3"] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def gen():
    return _generator()


@pytest.fixture
def profile(tmp_path: Path, gen) -> Path:
    root = tmp_path / "profile"
    root.mkdir()
    gen._fixture_profile(root)
    return root


def _key(password: str):
    return derive_backup_key(password, new_kdf(parameters=CHEAP))


def _record(password: str, *, now: int = 1793001000, set_by: str = "set", previous=None):
    key = _key(password)
    try:
        return build_record(key, now=now, set_by=set_by, reset_authority=None, previous=previous)
    finally:
        key.wipe()


def _write_v3(path: Path, profile: Path, record) -> dict:
    result = export_full_backup_to_key(path, record=record, profile_dir=profile, profile_name="Profile")
    with result["verifier"] as verifier:
        result["verified"] = verifier.verify(path, record=record)
    return result


def _members(path: Path) -> list[tuple[str, bytes]]:
    with zipfile.ZipFile(path) as archive:
        return [(info.filename, archive.read(info)) for info in archive.infolist()]


def _rewrite(path: Path, members: list[tuple[str, bytes]]) -> None:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_STORED) as archive:
        for name, data in members:
            archive.writestr(backup._full_zip_info(name), data)
    path.write_bytes(buffer.getvalue())


def _header(path: Path) -> dict:
    return json.loads(_members(path)[0][1])


def _with_header(path: Path, header: dict) -> None:
    _rewrite(path, [("header.json", _full_canonical(header)), *_members(path)[1:]])


def _read(path: Path, password: str) -> dict:
    return _full_read_container(path, password, on_entry=lambda entry, data: None)


def _refusal(path: Path, password: str) -> str:
    with pytest.raises(BackupError) as caught:
        _read(path, password)
    return str(caught.value)


def _fingerprint(path: Path) -> tuple[str, int]:
    return hashlib.sha256(path.read_bytes()).hexdigest(), path.stat().st_mtime_ns


# --------------------------------------------------------------------------- the committed vectors
def test_vector_full_backup_opens_with_the_backup_password_and_matches_its_inputs() -> None:
    seen: dict[str, str] = {}
    info = _full_read_container(VEC / "full.lgkfull", EXPECTED["backup_password"],
                                on_entry=lambda entry, data: seen.__setitem__(entry["target"],
                                                                              hashlib.sha256(data).hexdigest()))
    assert info["manifest"] == EXPECTED["manifest"] and info["header"] == EXPECTED["header"]
    assert info["header"]["version"] == 3 and info["manifest"]["version"] == 3
    assert info["manifest"]["created_at"] == EXPECTED["created_at"]
    for target in ("vault.json", "generation.json", *(f"{a}.blob" for a in EXPECTED["attachment_ids"])):
        assert seen[target] == EXPECTED["inputs_sha256"][target], target
    assert info["header"]["recipient"]["key_id"] == EXPECTED["record"]["key_id"]
    assert info["header"]["recipient"]["key_set_at"] == EXPECTED["record"]["set_at"]
    assert info["header"]["recipient"]["kdf"] == EXPECTED["record"]["kdf"]
    raw = (VEC / "full.lgkfull").read_bytes()   # 2.2: only the key id is in the header, never the public key
    assert EXPECTED["record"]["public_key"].encode() not in raw
    assert base64.b64decode(EXPECTED["record"]["public_key"]) not in raw


def test_vector_inputs_are_the_v2_fixture_profile() -> None:
    v2 = ROOT / "tests" / "vectors" / "backup" / "v2" / "inputs"
    for name, digest in EXPECTED["inputs_sha256"].items():
        assert hashlib.sha256((v2 / name).read_bytes()).hexdigest() == digest, name


def test_vector_full_backup_preflights_with_the_master_password(tmp_path: Path) -> None:
    info = preflight_full_backup(VEC / "full.lgkfull", profile_dir=tmp_path / "p",
                                 backup_password=EXPECTED["backup_password"], vault_password=EXPECTED["master_password"],
                                 validate_vault_password=True)
    assert info["version"] == 3 and info["verified_vault"] and info["attachments"] == 2


def test_vector_relocked_changes_only_the_header_and_opens_only_with_the_second_password() -> None:
    full, relocked = _members(VEC / "full.lgkfull"), _members(VEC / "relocked.lgkfull")
    assert [name for name, _ in full] == [name for name, _ in relocked]
    assert full[0] != relocked[0] and full[1:] == relocked[1:]
    header = json.loads(relocked[0][1])
    assert header == EXPECTED["relocked_header"]
    assert {k: v for k, v in header.items() if k != "recipient"} == {
        k: v for k, v in EXPECTED["header"].items() if k != "recipient"}
    assert header["recipient"]["key_id"] == EXPECTED["relock_record"]["key_id"]
    assert _read(VEC / "relocked.lgkfull", EXPECTED["second_password"])["manifest"] == EXPECTED["manifest"]
    assert _refusal(VEC / "relocked.lgkfull", EXPECTED["backup_password"]) == WRONG


@pytest.mark.parametrize("name", sorted(n for n in EXPECTED["rejected"] if " " not in n))
def test_vector_rejected_files_fail_with_the_windows_message(name: str) -> None:
    assert _refusal(VEC / "rejected" / f"{name}.lgkfull", EXPECTED["backup_password"]) == EXPECTED["rejected"][name]


def test_vector_rejected_wrap_failures_use_the_v2_message() -> None:
    for name in ("key_id_mismatch", "tampered_recipient_kdf", "epk_low_order", "tampered_core_entry_count",
                 "recipient_from_other_file", "tampered_header", "tampered_member"):
        assert EXPECTED["rejected"][name] == WRONG, name
    assert EXPECTED["rejected"]["full.lgkfull with a wrong password"] == WRONG


def test_vector_from_mac_v3_when_present() -> None:
    source = VEC / "from_mac_v3.lgkfull"
    if not source.exists():
        pytest.skip("from_mac_v3.lgkfull is written by the Swift FullBackupV3Tests (design step 5)")
    info = _read(source, EXPECTED["backup_password"])
    assert info["header"]["version"] == 3


# --------------------------------------------------------------------------- writer and reader
def test_round_trip_restores_the_profile(tmp_path: Path, profile: Path, gen) -> None:
    record = _record(PASSWORD)
    path = tmp_path / "backup.lgk"
    result = _write_v3(path, profile, record)
    assert result["version"] == 3 and result["key_id"] == record["key_id"]
    assert result["verified"]["sha256"] == hashlib.sha256(path.read_bytes()).hexdigest()
    assert result["verified"]["preflight"]["dry_run"] is True
    header = _header(path)
    assert header["recipient"]["key_set_at"] == record["set_at"] and header["recipient"]["kdf"] == record["kdf"]
    info = restore_full_backup(path, profile_dir=tmp_path / "restored", backup_password=PASSWORD,
                               vault_password=gen.MASTER_PASSWORD, validate_vault_password=True)
    assert info["version"] == 3 and info["verified_vault"] and info["vault_entries"] >= 2
    restored = tmp_path / "restored"
    for attachment in gen.ATTACHMENT_IDS:
        name = f"Attachments/{attachment}.blob"
        assert (restored / name).read_bytes() == (profile / name).read_bytes()


def test_the_verifier_is_wiped_after_use(tmp_path: Path, profile: Path) -> None:
    record = _record(PASSWORD)
    result = export_full_backup_to_key(tmp_path / "b.lgk", record=record, profile_dir=profile)
    verifier = result["verifier"]
    verifier.wipe()
    assert not any(verifier._data_key) and not any(verifier._ephemeral.secret)
    with pytest.raises(BackupError):
        verifier.verify(tmp_path / "b.lgk")


@pytest.mark.parametrize("case", ["wrong password", "tampered header", "swapped recipient", "wrong key id",
                                  "tampered entry count", "non-canonical header"])
def test_failures_give_the_v2_message(tmp_path: Path, profile: Path, case: str) -> None:
    record = _record(PASSWORD)
    path = tmp_path / "b.lgk"
    _write_v3(path, profile, record)
    header = _header(path)
    password = PASSWORD
    if case == "wrong password":
        password = SECOND
    elif case == "tampered header":
        _with_header(path, dict(header, recipient=dict(header["recipient"], key_set_at=header["recipient"]["key_set_at"] + 1)))
    elif case == "swapped recipient":
        other = tmp_path / "other.lgk"
        _write_v3(other, profile, record)
        _with_header(path, dict(header, recipient=_header(other)["recipient"]))
    elif case == "wrong key id":
        _with_header(path, dict(header, recipient=dict(header["recipient"], key_id=_record(SECOND)["key_id"])))
    elif case == "tampered entry count":
        _with_header(path, dict(header, entry_count=header["entry_count"] + 1))
    else:
        _rewrite(path, [("header.json", json.dumps(header, sort_keys=True).encode()), *_members(path)[1:]])
    assert _refusal(path, password) == WRONG


def test_the_v2_message_matches_the_v2_reader(tmp_path: Path, profile: Path) -> None:
    path = tmp_path / "v2.lgk"
    export_full_backup(path, profile_dir=profile, backup_password=PASSWORD, kdf_overrides=CHEAP)
    assert _refusal(path, SECOND) == WRONG


def test_a_key_id_mismatch_makes_no_gcm_attempt(tmp_path: Path, profile: Path, monkeypatch) -> None:
    record = _record(PASSWORD)
    path = tmp_path / "b.lgk"
    _write_v3(path, profile, record)
    from localvault import backup_key
    calls = []
    monkeypatch.setattr(backup_key, "unwrap_data_key", lambda *a, **k: calls.append(a))
    assert _refusal(path, SECOND) == WRONG and calls == []


def test_the_data_key_path_is_internal_only(tmp_path: Path, profile: Path) -> None:
    v2 = tmp_path / "v2.lgk"
    export_full_backup(v2, profile_dir=profile, backup_password=PASSWORD, kdf_overrides=CHEAP)
    with pytest.raises(BackupError, match="Unsupported full backup format"):
        _full_read_container(v2, None, on_entry=lambda e, d: None, _data_key=bytes(32))
    v3 = tmp_path / "v3.lgk"
    _write_v3(v3, profile, _record(PASSWORD))
    with pytest.raises(BackupError, match="dry run"):
        restore_full_backup(v3, profile_dir=tmp_path / "x", backup_password=None, _data_key=bytes(32))
    with pytest.raises(BackupError, match=WRONG):
        preflight_full_backup(v3, profile_dir=tmp_path / "x", backup_password=None, _data_key=bytes(32))


def test_ensure_encrypted_container_accepts_v3(tmp_path: Path, profile: Path) -> None:
    path = tmp_path / "b.lgk"
    _write_v3(path, profile, _record(PASSWORD))
    ensure_encrypted_container(path)


# --------------------------------------------------------------------------- 9.1 self-verify
def test_verify_fails_after_tampering_with_a_member_or_the_header(tmp_path: Path, profile: Path) -> None:
    record = _record(PASSWORD)
    for target in ("member", "header"):
        path = tmp_path / f"{target}.lgk"
        result = export_full_backup_to_key(path, record=record, profile_dir=profile)
        members = _members(path)
        if target == "member":
            data = bytearray(members[-1][1])
            data[15] ^= 1
            members[-1] = (members[-1][0], bytes(data))
            _rewrite(path, members)
        else:
            header = json.loads(members[0][1])
            _with_header(path, dict(header, entry_count=header["entry_count"] + 1))
        with result["verifier"] as verifier, pytest.raises(BackupError):
            verifier.verify(path)


def test_verify_fails_when_the_record_was_swapped(tmp_path: Path, profile: Path) -> None:
    path = tmp_path / "b.lgk"
    result = export_full_backup_to_key(path, record=_record(PASSWORD), profile_dir=profile)
    with result["verifier"] as verifier, pytest.raises(BackupError, match="does not open with the backup key"):
        verifier.verify(path, record=_record(SECOND))


def test_verify_fails_for_a_file_wrapped_by_someone_else(tmp_path: Path, profile: Path) -> None:
    record = _record(PASSWORD)
    path, other = tmp_path / "b.lgk", tmp_path / "other.lgk"
    result = export_full_backup_to_key(path, record=record, profile_dir=profile)
    _write_v3(other, profile, record)
    path.write_bytes(other.read_bytes())   # a valid file, but not the one this verifier wrote
    with result["verifier"] as verifier, pytest.raises(BackupError):
        verifier.verify(path)


# --------------------------------------------------------------------------- 7.2 re-lock
def _scheduled(directory: Path, stamp: str) -> Path:
    return directory / f"LocalGateKeys-scheduled-{TAG}-{stamp}.lgk"


def test_relock_keeps_members_name_and_mtime_and_opens_only_with_the_new_password(tmp_path: Path, profile: Path) -> None:
    folder = tmp_path / "Scheduled"
    folder.mkdir()
    old_key = _key(PASSWORD)
    old = build_record(old_key, now=1793001000, set_by="set", reset_authority=None)
    new = build_record(_key(SECOND), now=1793002000, set_by="changed", reset_authority=None, previous=old)
    path = _scheduled(folder, "20261030-120000")
    _write_v3(path, profile, old)
    os.utime(path, ns=(1_700_000_000_000_000_000, 1_700_000_000_123_456_789))
    before, mtime = _members(path), path.stat().st_mtime_ns   # NTFS keeps 100 ns steps
    assert relock_full_backup(path, old_key=old_key, new_record=new) == RELOCK_RELOCKED
    after = _members(path)
    assert [n for n, _ in before] == [n for n, _ in after] and before[1:] == after[1:] and before[0] != after[0]
    assert path.stat().st_mtime_ns == mtime
    assert sorted(p.name for p in folder.iterdir()) == [path.name]   # no temporary or probe left
    header = _header(path)
    assert header["recipient"]["key_id"] == new["key_id"] and header["recipient"]["key_set_at"] == new["set_at"]
    assert _read(path, SECOND)["header"]["version"] == 3
    assert _refusal(path, PASSWORD) == WRONG
    # Running it again with the old key leaves it alone: it is under the new key now.
    assert relock_full_backup(path, old_key=old_key, new_record=new) == RELOCK_OTHER_KEY
    old_key.wipe()


def test_relock_skips_old_format_backups_without_opening_them(tmp_path: Path, profile: Path, gen, monkeypatch) -> None:
    folder = tmp_path / "Scheduled"
    folder.mkdir()
    v2 = _scheduled(folder, "20261028-120000")
    export_full_backup(v2, profile_dir=profile, backup_password=PASSWORD, kdf_overrides=CHEAP)
    vault_only = _scheduled(folder, "20261027-120000")
    export_encrypted_backup(vault_only, vault_file=profile / "vault.json", settings_file=profile / "settings.json",
                            profile_name="Profile", backup_password=PASSWORD, kdf_overrides=CHEAP)
    old_key = _key(PASSWORD)
    old = build_record(old_key, now=1793001000, set_by="set", reset_authority=None)
    other = _record(THIRD)
    v3 = _scheduled(folder, "20261030-120000")
    _write_v3(v3, profile, old)
    foreign = _scheduled(folder, "20261029-120000")
    _write_v3(foreign, profile, other)
    for index, path in enumerate((v2, vault_only, foreign)):
        os.utime(path, ns=(1_600_000_000_000_000_000 + index, 1_600_000_000_000_000_000 + index))
    untouched = {path: _fingerprint(path) for path in (v2, vault_only, foreign)}
    new = build_record(_key(SECOND), now=1793002000, set_by="changed", reset_authority=None, previous=old)

    opened: list[tuple[str, str]] = []
    real_open = zipfile.ZipFile.open

    def spy(self, name, *args, **kwargs):
        opened.append((Path(str(self.filename)).name, getattr(name, "filename", name)))
        return real_open(self, name, *args, **kwargs)

    monkeypatch.setattr(zipfile.ZipFile, "open", spy)
    result = relock_full_backups(owned_backups(folder, TAG), old_key=old_key, new_record=new)
    monkeypatch.undo()
    for path in (v2, vault_only):
        assert relock_full_backup(path, old_key=old_key, new_record=new) == RELOCK_OLD_FORMAT
    old_key.wipe()

    assert result["relocked"] == [v3] and result["failed"] == []
    assert sorted(result["left"]) == sorted([v2, vault_only, foreign])
    for path, fingerprint in untouched.items():
        assert _fingerprint(path) == fingerprint, path.name
    for name in (v2.name, foreign.name):
        assert {member for archive, member in opened if archive == name} == {"header.json"}, name
    assert not any(archive == vault_only.name for archive, _ in opened)
    # The v2 backup still restores exactly as before, with its own password and the master password.
    info = preflight_full_backup(v2, profile_dir=tmp_path / "probe", backup_password=PASSWORD,
                                 vault_password=gen.MASTER_PASSWORD, validate_vault_password=True)
    assert info["version"] == 2 and info["verified_vault"]
    assert _refusal(v2, SECOND) == WRONG


def test_a_failed_relock_keeps_the_original(tmp_path: Path, profile: Path, monkeypatch) -> None:
    folder = tmp_path / "Scheduled"
    folder.mkdir()
    old_key = _key(PASSWORD)
    old = build_record(old_key, now=1793001000, set_by="set", reset_authority=None)
    path = _scheduled(folder, "20261030-120000")
    _write_v3(path, profile, old)
    before = _fingerprint(path)
    new = _record(SECOND)

    def boom(*args, **kwargs):
        raise BackupError("simulated verification failure")

    monkeypatch.setattr(backup, "_v3_content_check", boom)
    result = relock_full_backups([path], old_key=old_key, new_record=new)
    old_key.wipe()
    assert result["failed"] == [(path, "simulated verification failure")] and result["relocked"] == []
    assert _fingerprint(path) == before
    assert sorted(p.name for p in folder.iterdir()) == [path.name]


def test_relock_with_the_wrong_old_key_fails_and_keeps_the_file(tmp_path: Path, profile: Path) -> None:
    record = _record(PASSWORD)
    path = tmp_path / "b.lgk"
    _write_v3(path, profile, record)
    header = _header(path)
    impostor = _key(SECOND)
    impostor.key_id = header["recipient"]["key_id"]   # claims the file's key id but holds another private key
    before = _fingerprint(path)
    with pytest.raises(BackupError, match=WRONG):
        relock_full_backup(path, old_key=impostor, new_record=_record(THIRD))
    impostor.wipe()
    assert _fingerprint(path) == before


# --------------------------------------------------------------------------- section 8: describe
def test_describe_v3_against_the_device_record(tmp_path: Path, profile: Path) -> None:
    first = _record(PASSWORD, now=1793001000)
    changed = _record(SECOND, now=1793002000, set_by="changed", previous=first)
    reset = _record(THIRD, now=1793003000, set_by="reset", previous=changed)
    paths = {}
    for name, record in (("first", first), ("changed", changed), ("reset", reset)):
        paths[name] = tmp_path / f"{name}.lgk"
        _write_v3(paths[name], profile, record)
    assert describe_backup(paths["reset"], record=reset) == {
        "format_kind": "full", "version": 3, "key_id": reset["key_id"], "key_set_at": 1793003000,
        "key_line": "current"}
    line = describe_backup(paths["changed"], record=reset)
    assert line["key_line"] == "earlier_reset" and line["reset_at"] == 1793003000 and line["key_set_at"] == 1793002000
    line = describe_backup(paths["first"], record=reset)
    assert line["key_line"] == "earlier_changed" and line["replaced_at"] == 1793002000
    assert describe_backup(paths["first"], record=_record("an unrelated password"))["key_line"] == "other_device"
    assert describe_backup(paths["first"])["key_line"] == "other_device"


def test_describe_old_formats(tmp_path: Path, profile: Path) -> None:
    from datetime import datetime
    scheduled = _scheduled(tmp_path, "20261028-073015")
    export_full_backup(scheduled, profile_dir=profile, backup_password=PASSWORD, kdf_overrides=CHEAP)
    line = describe_backup(scheduled)
    assert line == {"format_kind": "full", "version": 2, "key_line": "old_format", "date_source": "filename",
                    "date": int(datetime(2026, 10, 28, 7, 30, 15).timestamp())}
    manual = tmp_path / "manual.lgk"
    export_encrypted_backup(manual, vault_file=profile / "vault.json", settings_file=None, profile_name="P",
                            backup_password=PASSWORD, kdf_overrides=CHEAP)
    os.utime(manual, (1_790_000_000, 1_790_000_000))
    assert describe_backup(manual) == {"format_kind": "catalog", "version": 2, "key_line": "old_format",
                                       "date": 1_790_000_000, "date_source": "modified"}


def test_describe_refuses_damaged_headers(tmp_path: Path) -> None:
    for name in ("unknown_scheme", "extra_header_key", "wrapped_short"):
        with pytest.raises(BackupError):
            describe_backup(VEC / "rejected" / f"{name}.lgkfull")
    junk = tmp_path / "junk.lgk"
    junk.write_bytes(b"not a backup")
    with pytest.raises(BackupError):
        describe_backup(junk)


def test_header_kdf_must_be_strict(tmp_path: Path, profile: Path) -> None:
    path = tmp_path / "b.lgk"
    _write_v3(path, profile, _record(PASSWORD))
    header = _header(path)
    _with_header(path, dict(header, recipient=dict(header["recipient"], kdf=dict(header["recipient"]["kdf"], hash_len=32))))
    assert _refusal(path, PASSWORD) == "Unsupported backup encryption parameters"
    salt = base64.b64encode(bytes(15)).decode()
    _with_header(path, dict(header, recipient=dict(header["recipient"], kdf=dict(header["recipient"]["kdf"], salt=salt))))
    assert _refusal(path, PASSWORD) == "Malformed full backup KDF salt"
