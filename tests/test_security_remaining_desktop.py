"""Remaining 2026-10-24 findings, desktop: document titles, wrapper metadata, data-folder ACL,
desktop rebind layout, migration-journal safety copy, Store build flags."""
from __future__ import annotations

import dataclasses
import hashlib
from pathlib import Path
from types import SimpleNamespace as NS

import pytest
from test_app_desktop import _bind, control, env, snapshot  # noqa: F401 - env is a fixture

import localvault.vault as vault_module
from localvault import config, uia
from localvault.app.documents import DocumentService
from localvault.config import atomic_write_json, read_json
from localvault.uia import WindowSnapshot
from localvault.vault import (
    DEFAULT_KDF,
    VaultError,
    create_vault,
    unlock_vault,
    vault_migration_journal_path,
)

ROOT = Path(__file__).resolve().parents[1]
TEST_KDF = {"time_cost": 1, "memory_cost_kib": 8192, "parallelism": 1, "hash_len": 32}
MASTER = "correct horse battery staple"


@pytest.fixture(autouse=True)
def _fast_default_kdf(monkeypatch):
    monkeypatch.setattr(vault_module, "DEFAULT_KDF", {**DEFAULT_KDF, **TEST_KDF})
    vault_module._reset_unlock_throttle_state_for_tests()


# ------------------------------------------------------------- L-20 document title

def _document_service(picked: Path):
    created = []
    session = NS(documents=NS(create=lambda source, *, title, description: created.append(title) or "doc-1"))
    controller = NS(on_lock=[], on_unlock=[], is_unlocked=lambda: True, session=session,
                    guard=NS(lease=lambda: "lease"), require_lease=lambda lease: None, touch=lambda: None)
    service = DocumentService(controller, NS(), NS(open_file=lambda title, file_types=None: picked))
    return service, created


def test_default_document_title_drops_bidi_controls():
    service, created = _document_service(Path("Invoice‮fdp.exe"))
    service.create("", "")
    assert created == ["Invoicefdp.exe"]


def test_typed_document_title_and_an_all_control_name():
    service, created = _document_service(Path("‮​"))
    service.create("  My title ", "")
    service.create("", "")
    assert created == ["My title", "Document"]


# ------------------------------------------------------------- I-21 wrapper created_at

def test_new_wrappers_carry_no_created_at_and_old_ones_still_open(tmp_path: Path):
    path = tmp_path / "vault.json"
    session = create_vault(path, MASTER, kdf_overrides=TEST_KDF)
    session.create_recovery_phrase(MASTER)
    session.lock()
    wrappers = read_json(path)["wrappers"]
    assert set(wrappers) == {"password", "recovery"}
    assert all("created_at" not in wrapper for wrapper in wrappers.values())
    # A vault written by an older release still carries the field: it is tolerated.
    header = read_json(path)
    for wrapper in header["wrappers"].values():
        wrapper["created_at"] = 1_790_000_000
    atomic_write_json(path, header)
    reopened = unlock_vault(path, MASTER)
    reopened.change_master_password(MASTER, "replacement master password 0002")
    reopened.lock()
    assert "created_at" not in read_json(path)["wrappers"]["password"]


# ------------------------------------------------------------- I-24 data folder ACL

def test_existing_data_folder_gets_the_owner_only_acl_at_main_app_start(tmp_path: Path, monkeypatch):
    # R-2: data_dir() no longer rewrites an existing folder's ACL (the native host calls it per message);
    # the main app's secure_data_dir_once does, and only for a folder the app owns (R-3 marker).
    folder = tmp_path / "existing"
    folder.mkdir()
    (folder / config.OWNED_MARKER).write_text("x", encoding="utf-8")
    applied = []
    monkeypatch.setenv("LOCALGATEKEYS_DATA_DIR", str(folder))
    monkeypatch.setattr(config.os, "name", "nt")
    monkeypatch.setattr(config, "apply_owner_only_acl", applied.append)
    monkeypatch.setattr(config, "has_owner_only_acl", lambda path: False)
    assert config.data_dir() == folder.resolve()
    config.data_dir()
    assert applied == []
    assert config.secure_data_dir_once() is True
    assert applied == [folder.resolve()]


def test_acl_failure_does_not_stop_startup(tmp_path: Path, monkeypatch, caplog):
    def fail(path):
        raise OSError("access denied")

    folder = tmp_path / "new"
    monkeypatch.setenv("LOCALGATEKEYS_DATA_DIR", str(folder))
    monkeypatch.setattr(config.os, "name", "nt")
    monkeypatch.setattr(config, "apply_owner_only_acl", fail)
    assert config.data_dir() == folder.resolve()
    assert "owner-only ACL" in caplog.text


def test_acl_is_a_no_op_off_windows(tmp_path: Path, monkeypatch):
    applied = []
    monkeypatch.setattr(config, "apply_owner_only_acl", applied.append)
    monkeypatch.setattr(config.os, "name", "posix")
    config._restrict_data_dir(tmp_path)
    assert applied == []


# ------------------------------------------------------------- I-6 rebind layout

def _relaid_snapshot():
    """Same window and binary, one more edit control: the selectors still resolve, the layout differs."""
    base = snapshot()
    extra = dataclasses.replace(control(2, password=False), name="Domain")
    return WindowSnapshot(hwnd=base.hwnd, pid=base.pid, title=base.title, exe_path=base.exe_path,
                          exe_sha256=base.exe_sha256, controls=[*base.controls, extra], signer=None)


def test_identical_binary_with_new_login_fields_asks_first(env):  # noqa: F811
    _bind(env)
    env.state.snap = _relaid_snapshot()
    assert env.state.snap.control_fingerprint() != snapshot().control_fingerprint()
    env.service._uia.desktop_entry_matches_snapshot = lambda entry, snap: False
    env.service._uia.updated_binary_binding = lambda entry, snap: (dict(entry), True)
    env.port.answers = [False]
    env.service.fill_foreground()
    assert "App window changed" in env.port.asked and env.filled == []


def test_identical_binary_with_new_login_fields_fills_after_a_yes(env):  # noqa: F811
    _bind(env)
    env.state.snap = _relaid_snapshot()
    first = [True]

    def matches(entry, snap):  # the saved layout differs once, then the adopted binding matches
        if first.pop() if first else False:
            return False
        return uia.desktop_entry_matches_snapshot(entry, snap)

    env.service._uia.desktop_entry_matches_snapshot = matches
    env.service._uia.updated_binary_binding = lambda entry, snap: (dict(entry), True)
    env.port.answers = [True]
    env.service.fill_foreground()
    assert "App window changed" in env.port.asked and env.filled == ["ann"]


# ------------------------------------------------------------- migration journal safety copy

def _planted_journal(tmp_path: Path) -> tuple[Path, bytes, bytes]:
    path = tmp_path / "vault.json"
    session = create_vault(path, MASTER, kdf_overrides=TEST_KDF)
    session.upsert_web(origin="https://example.com", username="a", password="old")
    older = path.read_bytes()
    session.upsert_web(origin="https://example.org", username="b", password="new")
    session.lock()
    current = path.read_bytes()
    planted = tmp_path / "Backups" / "migration-v2-1.json"
    planted.parent.mkdir()
    planted.write_bytes(older)
    atomic_write_json(vault_migration_journal_path(path), {
        "version": vault_module.VAULT_MIGRATION_JOURNAL_VERSION, "operation": "envelope-v2-to-v3",
        "status": "publishing", "vault_path": str(path.resolve()), "backup_path": str(planted.resolve()),
        "source_sha256": "0" * 64, "backup_sha256": hashlib.sha256(older).hexdigest(),
        "source_generation": 10**6, "source_anchor": None,  # lies so the restore runs
    })
    return path, older, current


def test_journal_restore_keeps_the_replaced_vault(tmp_path: Path):
    path, older, current = _planted_journal(tmp_path)
    assert vault_module._recover_vault_migration(path) == "rolled_back"
    assert path.read_bytes() == older
    copies = list((tmp_path / "Backups").glob("before-restore-*.json"))
    assert len(copies) == 1 and copies[0].read_bytes() == current


def test_journal_restore_stops_when_the_safety_copy_fails(tmp_path: Path, monkeypatch):
    path, _older, current = _planted_journal(tmp_path)

    def refuse(source, target):
        raise PermissionError("locked")

    monkeypatch.setattr(vault_module, "replace_with_retry", refuse)
    with pytest.raises(VaultError, match="copy of the vault"):
        vault_module._recover_vault_migration(path)
    assert path.read_bytes() == current and vault_migration_journal_path(path).exists()
    assert not list((tmp_path / "Backups").glob("before-restore-*"))
    assert not list((tmp_path / "Backups").glob(".lgk-*"))


# ------------------------------------------------------------- L-9 Store build is a release

def test_store_msix_build_passes_release():
    script = (ROOT / "scripts" / "build_msix_package.ps1").read_text(encoding="utf-8")
    assert 'if ($Channel -eq "Store") { $buildArgs += "-Release" }' in script
    assert script.index('$buildArgs += "-Release"') < script.index("@buildArgs")


def test_discord_stable_build_output_is_ignored():
    assert "build-personal/agent-discord-stable/" in (ROOT / ".gitignore").read_text(encoding="utf-8").splitlines()
