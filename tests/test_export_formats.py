from __future__ import annotations

import csv
import io
import json
import os
import subprocess
import uuid
from pathlib import Path

import pytest

from localvault import export as export_module
from localvault.export import (
    ExportError,
    ExportSummary,
    ExportWarning,
    export_csv,
    export_json,
    export_kdbx,
    export_keepass_xml,
    export_records,
)
from localvault.importers import ImportedRecord, ImportPasswordError
from localvault.importers.bitwarden import load_bitwarden_csv, load_bitwarden_json
from localvault.importers.kdbx import load_kdbx, load_keepass_xml
from localvault.vault import create_vault

KDF = {"time_cost": 1, "memory_cost_kib": 8192, "parallelism": 1, "hash_len": 32}
MASTER = "export tests master"
FAST_ARGON = {"memory": 8 * 1024 * 1024, "iterations": 1, "parallelism": 1}


@pytest.fixture
def session():
    directory = Path(".n08-test-data") / uuid.uuid4().hex
    directory.mkdir(parents=True, exist_ok=False)
    vault = create_vault(directory / "vault.json", MASTER, kdf_overrides=KDF)
    entry_id = vault.upsert_web(origin="https://example.test", username="alice", password="pw-alice", label="Example")
    vault.set_details(entry_id, favorite=True, tags=["work"], notes="login note",
                      totp={"secret": "JBSWY3DPEHPK3PXP", "digits": 6, "period": 30, "algorithm": "SHA1"},
                      custom_fields=[{"name": "PIN", "value": "1234", "hidden": True}])
    vault.upsert_web(origin="https://second.test", username="bob", password="pw-bob")
    vault.items.create_note("Memo", "remember the milk", fields=[{"name": "Where", "value": "fridge", "hidden": False}])
    vault.items.create_identity("Me", {"given_name": "Alice", "family_name": "Smith", "email": "a@example.test"})
    vault.items.create_bookmark("Docs", "https://docs.example.test", notes="handy")
    return vault


def _by_title(result):
    return {record.title: record for record in result.records}


def test_export_csv_round_trips_through_bitwarden_csv_importer(session, tmp_path: Path):
    path = tmp_path / "out.csv"
    summary = export_csv(session, path, include_totp=False, restrict_permissions=False)
    assert isinstance(summary, ExportSummary) and summary.path == path and summary.format == "csv"
    assert summary.count == 5 and summary.by_kind == {"login": 3, "note": 1, "identity": 1}
    assert ExportWarning.PLAINTEXT in summary.warnings and ExportWarning.SPREADSHEET in summary.warnings
    assert ExportWarning.TOTP not in summary.warnings and ExportWarning.KDBX not in summary.warnings
    rows = list(csv.DictReader(io.StringIO(path.read_text(encoding="utf-8"))))
    assert list(rows[0]) == ["folder", "favorite", "type", "name", "notes", "fields", "reprompt", "login_uri",
                             "login_username", "login_password", "login_totp"]
    example = next(row for row in rows if row["name"] == "Example")
    assert example["login_password"] == "pw-alice" and example["login_totp"] == "" and example["favorite"] == "1"
    assert example["fields"] == "PIN: 1234" and example["notes"] == "login note"
    imported = _by_title(load_bitwarden_csv(path))
    assert imported["Example"].password == "pw-alice" and imported["Memo"].kind == "note"
    assert imported["Memo"].notes == "remember the milk" and "Where: fridge" in path.read_text(encoding="utf-8")
    assert imported["Me"].kind == "note" and any(f["name"] == "given_name" for f in imported["Me"].custom_fields)
    with_totp = export_csv(session, tmp_path / "totp.csv", include_totp=True, restrict_permissions=False)
    assert with_totp.totp_count == 1 and ExportWarning.TOTP in with_totp.warnings
    assert "otpauth://totp/Example?secret=JBSWY3DPEHPK3PXP" in (tmp_path / "totp.csv").read_text(encoding="utf-8")
    assert "pw-alice" not in repr(summary)


def test_export_json_round_trips_through_bitwarden_json_importer(session, tmp_path: Path):
    path = tmp_path / "out.json"
    summary = export_json(session, path, include_totp=True, restrict_permissions=False)
    assert summary.format == "json" and summary.count == 5
    document = json.loads(path.read_text(encoding="utf-8"))
    assert document["encrypted"] is False and {item["type"] for item in document["items"]} == {1, 2, 4}
    folders = {folder["name"] for folder in document["folders"]}
    assert "Bookmarks" in folders
    imported = _by_title(load_bitwarden_json(path))
    assert imported["Example"].password == "pw-alice" and imported["Example"].totp_uri.startswith("otpauth://")
    assert imported["Example"].favorite and {f["name"]: f["hidden"] for f in imported["Example"].custom_fields}["PIN"] is True
    assert imported["Me"].kind == "identity" and imported["Me"].identity["given_name"] == "Alice"
    assert imported["Me"].identity["email"] == "a@example.test"
    assert imported["Docs"].kind == "login" and imported["Docs"].urls == ["https://docs.example.test"] and imported["Docs"].folder == "Bookmarks"
    assert imported["Memo"].notes == "remember the milk"


def test_export_keepass_xml_round_trips(session, tmp_path: Path):
    path = tmp_path / "out.xml"
    summary = export_keepass_xml(session, path, include_totp=True, restrict_permissions=False)
    assert summary.format == "keepass-xml" and summary.count == 5
    text = path.read_text(encoding="utf-8")
    assert text.startswith("<?xml") and "<KeePassFile>" in text and 'Protected="True"' not in text
    imported = _by_title(load_keepass_xml(path))
    assert imported["Example"].password == "pw-alice" and "JBSWY3DPEHPK3PXP" in imported["Example"].totp_uri
    assert imported["Example"].urls == ["https://example.test"]
    assert imported["Memo"].kind == "note" and imported["Memo"].notes == "remember the milk"
    assert imported["Me"].notes.count("Alice") >= 1


def test_export_kdbx_is_encrypted_and_round_trips(session, tmp_path: Path):
    path = tmp_path / "out.kdbx"
    summary = export_kdbx(session, path, "a strong export password", kdf_params=FAST_ARGON, restrict_permissions=False)
    assert summary.encrypted and summary.warnings == (ExportWarning.KDBX,)
    raw = path.read_bytes()
    assert raw[:4] == b"\x03\xd9\xa2\x9a" and b"pw-alice" not in raw and b"JBSWY3DPEHPK3PXP" not in raw
    with pytest.raises(ImportPasswordError):
        load_kdbx(path, "wrong password")
    imported = _by_title(load_kdbx(path, "a strong export password"))
    assert imported["Example"].password == "pw-alice" and imported["Example"].username == "alice"
    assert "secret=JBSWY3DPEHPK3PXP" in imported["Example"].totp_uri
    assert {f["name"]: f["hidden"] for f in imported["Example"].custom_fields} == {"PIN": True}
    assert imported["Memo"].kind == "note" and imported["Docs"].folder == "Bookmarks"
    with pytest.raises(ExportError):
        export_kdbx(session, tmp_path / "weak.kdbx", "short", kdf_params=FAST_ARGON)


def test_export_accepts_entry_dicts_and_records(tmp_path: Path):
    entries = [
        {"id": "1", "kind": "web", "label": "Site", "username": "u", "password": "p", "scope": {"origin": "https://site.test"},
         "created_at": 1700000000, "updated_at": 1700000001, "recovery_codes": ["abc", "def"]},
        {"id": "2", "kind": "desktop", "label": "App", "username": "u2", "password": "p2",
         "scope": {"exe_path": "C:\\Apps\\app.exe", "window_title": "App"}},
        ImportedRecord(kind="login", title="Rec", username="r", password="rp", urls=["https://rec.test"]),
    ]
    summary = export_csv(entries, tmp_path / "entries.csv", restrict_permissions=False)
    assert summary.count == 3
    imported = _by_title(load_bitwarden_csv(tmp_path / "entries.csv"))
    assert imported["App"].folder == "Desktop applications" and any(f["name"] == "Application path" for f in imported["App"].custom_fields)
    assert any(f["name"] == "Recovery codes" for f in imported["Site"].custom_fields)
    with pytest.raises(ExportError):
        export_csv([object()], tmp_path / "bad.csv", restrict_permissions=False)


def test_export_write_is_atomic_and_refuses_to_clobber(session, tmp_path: Path, monkeypatch):
    path = tmp_path / "existing.csv"
    path.write_text("keep me", encoding="utf-8")
    with pytest.raises(ExportError, match="already exists"):
        export_csv(session, path, restrict_permissions=False)
    assert path.read_text(encoding="utf-8") == "keep me"
    assert export_csv(session, path, overwrite=True, restrict_permissions=False).count == 5
    assert path.read_text(encoding="utf-8").startswith("folder,favorite")

    def failing_replace(src, dst):
        raise OSError("disk full")

    monkeypatch.setattr(os, "replace", failing_replace)
    target = tmp_path / "never.csv"
    with pytest.raises(ExportError):
        export_csv(session, target, restrict_permissions=False)
    assert not target.exists()
    assert not list(tmp_path.glob(".lgk-export-*"))


def test_export_restricts_permissions_where_possible(session, tmp_path: Path):
    summary = export_json(session, tmp_path / "restricted.json")
    if os.name == "nt":
        assert summary.permissions_restricted is True
        assert ExportWarning.PERMISSIONS not in summary.warnings
    else:
        assert oct(os.stat(tmp_path / "restricted.json").st_mode & 0o777) == "0o600"


def test_export_permission_failure_leaves_default_acl_and_warns(session, tmp_path: Path, monkeypatch):
    # No usable SID: never fall back to an account name, keep the default ACL.
    monkeypatch.setattr(export_module, "_current_user_sid", lambda: None)
    summary = export_json(session, tmp_path / "unrestricted.json")
    assert summary.permissions_restricted is False
    assert ExportWarning.PERMISSIONS in summary.warnings
    assert (tmp_path / "unrestricted.json").read_bytes().startswith(b"{")

    # A failing icacls grant must be rolled back with /reset and still produce the file.
    calls: list[tuple[str, ...]] = []

    def fake_icacls(path, *arguments):
        calls.append(tuple(arguments))
        if "/grant:r" in arguments:
            raise subprocess.CalledProcessError(5, "icacls")

    monkeypatch.setattr(export_module, "_current_user_sid", lambda: "S-1-5-21-1-2-3-1001")
    monkeypatch.setattr(export_module, "_icacls", fake_icacls)
    summary = export_json(session, tmp_path / "rolled-back.json")
    assert summary.permissions_restricted is False and ExportWarning.PERMISSIONS in summary.warnings
    # The private staging directory is restricted (inheritable) first, then the empty file.
    assert calls == [("/inheritance:r", "/grant:r", "*S-1-5-21-1-2-3-1001:(OI)(CI)F"),
                     ("/inheritance:r", "/grant:r", "*S-1-5-21-1-2-3-1001:F"), ("/reset",)]
    assert (tmp_path / "rolled-back.json").read_bytes().startswith(b"{")

    # Access lost after an apparently successful grant is also rolled back.
    calls.clear()
    monkeypatch.setattr(export_module, "_icacls", lambda path, *arguments: calls.append(tuple(arguments)))
    monkeypatch.setattr(export_module, "_owner_can_access", lambda path: False)
    summary = export_json(session, tmp_path / "locked-out.json")
    assert summary.permissions_restricted is False and calls[-1] == ("/reset",)


def test_export_temporary_file_is_restricted_before_any_plaintext_is_written(session, tmp_path: Path, monkeypatch):
    """SEC-V19: the temp file lives in a restricted private directory and is restricted while empty."""
    seen: list[tuple[str, int, bool]] = []
    real_directory = export_module._restrict_directory

    def directory_spy(path: Path) -> bool:
        seen.append(("dir", 0, Path(path).is_dir()))
        return real_directory(path)

    def file_spy(path: Path) -> bool:
        path = Path(path)
        seen.append(("file", path.stat().st_size, path.parent.name.startswith(".lgk-export-")))
        return True

    monkeypatch.setattr(export_module, "_restrict_directory", directory_spy)
    monkeypatch.setattr(export_module, "_restrict_permissions", file_spy)
    summary = export_csv(session, tmp_path / "private.csv")
    assert summary.permissions_restricted is True
    assert seen == [("dir", 0, True), ("file", 0, True)]
    assert (tmp_path / "private.csv").read_bytes().startswith(b"folder,")
    assert not list(tmp_path.glob(".lgk-export-*"))


def test_kdbx_export_password_minimum_matches_other_passwords(session, tmp_path: Path):
    """SEC-V28: KDBX export passwords need 12 characters like the master and backup passwords."""
    assert export_module.KDBX_MIN_PASSWORD == 12
    with pytest.raises(ExportError, match="12 characters"):
        export_kdbx(session, tmp_path / "eleven.kdbx", "x" * 11, kdf_params=FAST_ARGON)
    assert not (tmp_path / "eleven.kdbx").exists()
    assert export_kdbx(session, tmp_path / "twelve.kdbx", "x" * 12, kdf_params=FAST_ARGON,
                       restrict_permissions=False).encrypted


def test_export_records_dispatch_and_locked_vault(session, tmp_path: Path):
    assert export_records(session, tmp_path / "d.csv", "csv", restrict_permissions=False).format == "csv"
    assert export_records(session, tmp_path / "d.kdbx", "kdbx", password="another strong one",
                          kdf_params=FAST_ARGON, restrict_permissions=False).encrypted
    with pytest.raises(ExportError):
        export_records(session, tmp_path / "d.x", "unknown")
    session.lock()
    with pytest.raises(ExportError, match="locked"):
        export_csv(session, tmp_path / "locked.csv", restrict_permissions=False)
    assert ExportWarning.for_format("csv", include_totp=True)[:2] == (ExportWarning.PLAINTEXT, ExportWarning.TOTP)
    assert export_module.EXPORT_FORMATS["kdbx"]
