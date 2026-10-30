"""Full backup v2 vectors shared with the Mac app (tests/vectors/backup/v2).

``full.lgkfull`` and the rejected set are written by ``scripts/gen_mac_backup_vectors.py backup``
with Windows ``export_full_backup``; the generator must reproduce them byte for byte.
``from_mac.lgkfull`` is written by the Swift ``FullBackupV2Tests`` (a Mac full backup holding a
Windows-format ``vault.json`` sealed by the Mac): Windows must open and restore it.
"""

from __future__ import annotations

import importlib.util
import json
import shutil
import sys
import zipfile
from pathlib import Path

import pytest

from localvault.backup import BackupError, _full_read_container, restore_full_backup
from localvault.vault import recovery_phrase_enrolled, unlock_vault

ROOT = Path(__file__).resolve().parents[1]
VEC = ROOT / "tests" / "vectors" / "backup" / "v2"
SCRIPT = ROOT / "scripts" / "gen_mac_backup_vectors.py"
EXPECTED = json.loads((VEC / "expected.json").read_text(encoding="utf-8"))


def _generator():
    spec = importlib.util.spec_from_file_location("gen_mac_backup_vectors", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    sys.modules["gen_mac_backup_vectors"] = module
    spec.loader.exec_module(module)
    return module


#: Deflated on purpose; zlib builds differ (Python on Windows and on macOS), so the archive's
#: compressed bytes may too.  Its members are compared instead.
DEFLATED = "rejected/deflated.lgkfull"


def _files(root: Path) -> dict[str, object]:
    files: dict[str, object] = {p.relative_to(root).as_posix(): p.read_bytes() for p in sorted(root.rglob("*"))
                                if p.is_file() and p.name != "from_mac.lgkfull"}
    if DEFLATED in files:
        with zipfile.ZipFile(root / DEFLATED) as archive:
            files[DEFLATED] = [(i.filename, i.compress_type, archive.read(i)) for i in archive.infolist()]
    return files


def test_generator_reproduces_the_committed_vectors(tmp_path: Path) -> None:
    out = tmp_path / "v2"
    _generator().backup_main(out)
    assert _files(out) == _files(VEC)


@pytest.mark.parametrize("name", sorted(n for n in EXPECTED["rejected"] if n.endswith(".lgkfull")))
def test_each_rejected_vector_is_refused_with_its_message(name: str) -> None:
    with pytest.raises(BackupError) as caught:
        _full_read_container(VEC / "rejected" / name, EXPECTED["backup_password"], on_entry=lambda e, d: None)
    assert str(caught.value) == EXPECTED["rejected"][name]


def _from_mac(tmp_path: Path) -> Path:
    source = VEC / "from_mac.lgkfull"
    assert source.is_file(), "run the Swift FullBackupV2Tests to write from_mac.lgkfull"
    copy = tmp_path / "from_mac.lgkfull"
    shutil.copyfile(source, copy)
    return copy


def test_mac_backup_opens_in_python_with_every_record(tmp_path: Path) -> None:
    members: dict[str, bytes] = {}
    info = _full_read_container(_from_mac(tmp_path), EXPECTED["backup_password"],
                                on_entry=lambda entry, data: members.__setitem__(entry["target"], data))
    assert info["manifest"]["profile_name"] == EXPECTED["profile_name"]
    expected_attachments = {f"{a}.blob" for a in EXPECTED["attachment_ids"]}
    assert set(members) == {"vault.json", "settings.json"} | expected_attachments
    for name in expected_attachments:
        assert members[name] == (VEC / "inputs" / name).read_bytes()
    # The Mac stores settings.json as given; from_mac.lgkfull was written from an inputs/settings.json that
    # predates later Windows settings, so check it restores and keeps the given values rather than its bytes.
    from localvault.backup import _full_validate_settings

    mac_settings = json.loads(members["settings.json"])
    restored = _full_validate_settings(mac_settings)
    given = json.loads((VEC / "inputs" / "settings.json").read_bytes())
    assert set(mac_settings) <= set(given)
    assert {k: restored[k] for k in mac_settings} == {k: given[k] for k in mac_settings}
    vault_file = tmp_path / "staged" / "vault.json"
    vault_file.parent.mkdir()
    vault_file.write_bytes(members["vault.json"])
    assert not recovery_phrase_enrolled(vault_file)
    session = unlock_vault(vault_file, EXPECTED["master_password"])
    try:
        payload = session._require_payload()
        records = list(payload["entries"]) + list(payload["items"])
        assert sorted(records, key=lambda r: r["id"]) == sorted(EXPECTED["records"], key=lambda r: r["id"])
    finally:
        session.lock()


def test_mac_backup_restores_as_a_windows_profile(tmp_path: Path) -> None:
    profile = tmp_path / "restored"
    result = restore_full_backup(_from_mac(tmp_path), profile_dir=profile,
                                 backup_password=EXPECTED["backup_password"],
                                 vault_password=EXPECTED["master_password"], validate_vault_password=True)
    logins = [r for r in EXPECTED["records"] if r.get("kind") in ("web", "desktop")]
    assert result["vault_entries"] == len(logins) > 0  # summaries() counts logins
    assert result["attachments"] == len(EXPECTED["attachment_ids"])
    session = unlock_vault(profile / "vault.json", EXPECTED["master_password"])
    try:
        payload = session._require_payload()
        assert sorted(r["id"] for r in payload["entries"] + payload["items"]) == sorted(
            r["id"] for r in EXPECTED["records"])
    finally:
        session.lock()
    for attachment_id in EXPECTED["attachment_ids"]:
        assert (profile / "Attachments" / f"{attachment_id}.blob").is_file()


@pytest.mark.parametrize("name", ["vault_v1.json", "vault_v2.json"])
def test_legacy_vault_inputs_open_in_windows(tmp_path: Path, name: str) -> None:
    probe = tmp_path / "vault.json"
    shutil.copyfile(VEC / "inputs" / name, probe)
    session = unlock_vault(probe, EXPECTED["master_password"], upgrade_envelope=False)
    try:
        payload = session._require_payload()
        ids = sorted(r["id"] for r in payload["entries"] + payload.get("items", []))
        assert ids == EXPECTED["legacy_vault_ids"][name]
    finally:
        session.lock()


# --- Task 6: a full backup made through the Mac's create path (MacFullBackupTests) -------------------------

KIT = ROOT / "tests" / "vectors" / "recovery" / "kit"


def _mac_created(tmp_path: Path) -> Path:
    source = KIT / "from_mac" / "mac-created.lgk"
    assert source.is_file(), "run the Mac MacFullBackupTests to write from_mac/mac-created.lgk"
    copy = tmp_path / source.name
    shutil.copyfile(source, copy)
    shutil.copyfile(KIT / "from_mac" / (source.name + ".sha256.json"), tmp_path / (source.name + ".sha256.json"))
    return copy


def test_kit_generator_reproduces_the_committed_vectors(tmp_path: Path) -> None:
    out = tmp_path / "kit"
    _generator().kit_main(out)
    ignore = {"from_mac"}
    produced = {p.relative_to(out).as_posix(): p.read_bytes() for p in sorted(out.rglob("*"))
                if p.is_file() and p.relative_to(out).parts[0] not in ignore}
    committed = {p.relative_to(KIT).as_posix(): p.read_bytes() for p in sorted(KIT.rglob("*"))
                 if p.is_file() and p.relative_to(KIT).parts[0] not in ignore}
    assert produced == committed


def test_mac_created_backup_verifies_and_restores_in_windows(tmp_path: Path) -> None:
    from localvault.recovery import verify_recovery_backup, verify_sha256_manifest
    backup = _mac_created(tmp_path)
    checked = verify_sha256_manifest(backup)
    assert checked["verified"] is True
    manifest = json.loads((tmp_path / (backup.name + ".sha256.json")).read_text(encoding="utf-8"))
    assert manifest["inventory"]["profile_name"] == EXPECTED["profile_name"]
    assert manifest["inventory"]["verified"] is True
    result = verify_recovery_backup(backup, backup_password=EXPECTED["backup_password"],
                                    vault_password=EXPECTED["master_password"])
    assert result["verified"] is True
    assert result["attachments"] == len(EXPECTED["attachment_ids"])
    profile = tmp_path / "restored"
    restore_full_backup(backup, profile_dir=profile, backup_password=EXPECTED["backup_password"],
                        vault_password=EXPECTED["master_password"], validate_vault_password=True)
    session = unlock_vault(profile / "vault.json", EXPECTED["master_password"])
    try:
        payload = session._require_payload()
        restored = {r["id"]: r for r in payload["entries"] + payload["items"]}
        # Windows sanitises a restored profile (sign-in policy off, so updated_at moves); the content is the same.
        assert restored.keys() == {r["id"] for r in EXPECTED["records"]}
        for record in EXPECTED["records"]:
            for field in ("kind", "label", "title", "username", "password", "notes", "fields"):
                assert restored[record["id"]].get(field) == record.get(field), (record["id"], field)
    finally:
        session.lock()
    for attachment_id in EXPECTED["attachment_ids"]:
        assert (profile / "Attachments" / f"{attachment_id}.blob").read_bytes() == (
            VEC / "inputs" / f"{attachment_id}.blob").read_bytes()


def test_mac_recovery_kit_describes_its_backup(tmp_path: Path) -> None:
    import hashlib
    kit = json.loads((KIT / "from_mac" / "recovery-kit.json").read_text(encoding="utf-8"))
    windows = json.loads((KIT / "recovery-kit.json").read_text(encoding="utf-8"))
    assert kit.keys() == windows.keys()
    assert kit["format"] == "localgatekeys-recovery-kit" and kit["version"] == 1
    assert kit["safety"] == windows["safety"]
    backup = (KIT / "from_mac" / "mac-created.lgk").read_bytes()
    assert kit["files"][0] == {"name": "mac-created.lgk", "role": "encrypted-full-backup-v2", "size": len(backup),
                               "sha256": hashlib.sha256(backup).hexdigest()}
    assert kit["files"][1]["role"] == "sha256-manifest"


RECOVERY = ROOT / "tests" / "vectors" / "recovery"


def test_recovery_generator_reproduces_the_committed_vectors(tmp_path: Path) -> None:
    out = tmp_path / "recovery"
    _generator().recovery_main(out)
    for name in ("phrases.json", "wrapper.json"):
        assert (out / name).read_bytes() == (RECOVERY / name).read_bytes(), name


def test_windows_recovery_vector_opens_with_its_phrase(tmp_path: Path) -> None:
    from localvault.vault import unlock_with_recovery_phrase
    doc = json.loads((RECOVERY / "wrapper.json").read_text(encoding="utf-8"))
    path = tmp_path / "vault.json"
    path.write_text(doc["vault"], encoding="utf-8")
    session = unlock_with_recovery_phrase(path, doc["phrase"])
    try:
        assert [r["id"] for r in session._require_payload()["entries"]] == [r["id"] for r in doc["records"]]
    finally:
        session.lock()


def test_mac_sealed_vault_opens_with_the_recovery_phrase(tmp_path: Path) -> None:
    """``from_mac_vault.json`` is written by the Swift ``BIP39Tests``: the phrase that protects the Mac store opens it."""
    from localvault.vault import unlock_with_recovery_phrase
    source = RECOVERY / "from_mac_vault.json"
    assert source.is_file(), "run the Swift BIP39Tests to write from_mac_vault.json"
    doc = json.loads(source.read_text(encoding="utf-8"))
    path = tmp_path / "vault.json"
    path.write_text(doc["vault"], encoding="utf-8")
    assert recovery_phrase_enrolled(path)
    session = unlock_with_recovery_phrase(path, doc["phrase"])
    try:
        assert sorted(r["id"] for r in session._require_payload()["entries"]) == sorted(doc["record_ids"])
    finally:
        session.lock()
    session = unlock_vault(path, doc["master_password"])
    session.lock()


SCHEDULE = ROOT / "tests" / "vectors" / "backup" / "schedule"


def test_schedule_generator_reproduces_the_committed_vectors(tmp_path: Path) -> None:
    out = tmp_path / "schedule"
    _generator().schedule_main(out)
    assert (out / "schedule.json").read_bytes() == (SCHEDULE / "schedule.json").read_bytes()
