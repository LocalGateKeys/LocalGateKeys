"""Regression tests for the property-fuzzing findings of 2026-10-24.

Every case failed closed before the fix, but with the wrong exception type: a
``RecursionError`` (Python 3.14's C JSON decoder on deeply nested input) or an
``OverflowError`` (``int(inf)``) escaped callers that only catch the module's
documented error.  O-1 and S-1 are idempotence bugs; the last group covers the
owner-only scratch folder that replaces the system temp for backup checks.
"""
from __future__ import annotations

import io
import json
import os
import struct
import tempfile
import zipfile
from pathlib import Path

import pytest

from localvault import backup, bridge_diagnostics, config, native_host, origin, protocol, transfer, vault
from localvault.sync.engine import ItemState, merge

DEEP = b"[" * 60000
TEST_KDF = {"time_cost": 1, "memory_cost_kib": 8192, "parallelism": 1, "hash_len": 32}
MASTER = "correct horse battery staple"
BACKUP_PASSWORD = "backup password 123"


def _native_frame(payload: bytes, fmt: str = "=I") -> bytes:
    return struct.pack(fmt, len(payload)) + payload


# --- F-1: native messaging / local agent frames ----------------------------------------------

def test_f1_native_host_deep_json_is_a_bridge_error() -> None:
    with pytest.raises(native_host.NativeBridgeError):
        native_host._read_native_message(io.BytesIO(_native_frame(DEEP)))


def test_f1_protocol_native_deep_json_is_a_protocol_error() -> None:
    with pytest.raises(protocol.ProtocolError):
        protocol.read_native_message(io.BytesIO(_native_frame(DEEP)))


def test_f1_protocol_local_deep_json_is_a_protocol_error() -> None:
    class _Sock:
        def __init__(self, data: bytes) -> None:
            self._data = io.BytesIO(data)

        def recv(self, n: int) -> bytes:
            return self._data.read(n)

    with pytest.raises(protocol.ProtocolError):
        protocol.recv_local_message(_Sock(_native_frame(DEEP, "!I")))  # type: ignore[arg-type]


def test_f1_bridge_diagnostics_reports_a_deep_reply_as_a_bad_frame(monkeypatch, tmp_path: Path) -> None:
    class _Process:
        def communicate(self, _payload: bytes, timeout: float) -> tuple[bytes, bytes]:
            return _native_frame(DEEP), b""

        def poll(self) -> int:
            return 0

    monkeypatch.setattr(bridge_diagnostics, "_pin_matches", lambda *a: True)
    monkeypatch.setattr(bridge_diagnostics.subprocess, "Popen", lambda *a, **k: _Process())
    result = bridge_diagnostics._ping_host({"native_host_path": tmp_path / "host.exe",
                                            "allowed_extension_origins": [bridge_diagnostics.EXTENSION_ORIGINS[0]]})
    assert result == {"status": "failed", "error": "invalid_native_frame"}


# --- V-1 / V-2: vault header ------------------------------------------------------------------

def _locked_vault(tmp_path: Path) -> Path:
    path = tmp_path / "vault.json"
    vault.create_vault(path, MASTER, kdf_overrides=TEST_KDF).lock()
    return path


@pytest.mark.parametrize("raw", ["Infinity", "-Infinity", "NaN", "1e400"])
def test_v1_non_finite_kdf_values_are_a_vault_error(tmp_path: Path, raw: str) -> None:
    path = _locked_vault(tmp_path)
    header = json.loads(path.read_bytes())
    header["kdf"]["time_cost"] = "__X__"
    path.write_text(json.dumps(header).replace('"__X__"', raw), encoding="utf-8")
    try:
        with pytest.raises(vault.VaultError):
            vault.unlock_vault(path, MASTER)
    finally:
        vault.UnlockThrottle(path).reset()


def test_v1_derive_key_rejects_an_overflowing_kdf_value() -> None:
    kdf = {"name": "argon2id", "salt": "AAAAAAAAAAAAAAAAAAAAAA==", "time_cost": float("inf"),
           "memory_cost_kib": 8192, "parallelism": 1, "hash_len": 32}
    with pytest.raises(vault.VaultError):
        vault._derive_key(MASTER, kdf)


def test_v2_deep_vault_file_is_a_vault_error(tmp_path: Path) -> None:
    path = tmp_path / "deep-vault.json"
    path.write_bytes(DEEP)
    with pytest.raises(vault.VaultError):
        vault.unlock_vault(path, MASTER)


# --- B-1: backups -------------------------------------------------------------------------------

def test_b1_deep_v1_backup_is_a_backup_error(tmp_path: Path) -> None:
    path = tmp_path / "deep.lgkbackup"
    path.write_bytes(DEEP)
    with pytest.raises(backup.BackupError):
        backup._read_backup_payload(path, BACKUP_PASSWORD)


def _deep_full_backup(path: Path) -> Path:
    with zipfile.ZipFile(path, "w", zipfile.ZIP_STORED) as archive:
        archive.writestr(backup._full_zip_info("header.json"), DEEP)
        archive.writestr(backup._full_zip_info("manifest.bin"), b"x")
        archive.writestr(backup._full_zip_info("data/a.bin"), b"x")
        archive.writestr(backup._full_zip_info("data/b.bin"), b"x")
    return path


@pytest.mark.parametrize("entry", [backup.restore_full_backup, backup.preflight_full_backup])
def test_b1_deep_full_backup_header_is_a_backup_error(tmp_path: Path, entry) -> None:  # type: ignore[no-untyped-def]
    source = _deep_full_backup(tmp_path / "deep.lgkfull")
    with pytest.raises(backup.BackupError):
        entry(source, profile_dir=tmp_path / "restored", backup_password=BACKUP_PASSWORD, vault_password=MASTER)


def test_b1_full_json_object_helper_maps_recursion() -> None:
    with pytest.raises(backup.BackupError):
        backup._full_validate_json_object(DEEP, "Full backup header")


def test_b1_overflowing_exported_at_is_a_backup_error(tmp_path: Path) -> None:
    path = _locked_vault(tmp_path)
    payload = {"vault": json.loads(path.read_bytes()), "profile_name": "p", "exported_at": float("inf")}
    with pytest.raises(backup.BackupError):
        backup._verify_payload(payload, vault._master_secret(MASTER, "x")[0])


# --- T-1: transfer packages -----------------------------------------------------------------------

def test_t1_deep_transfer_package_is_a_transfer_error(tmp_path: Path) -> None:
    path = tmp_path / "deep.lgktransfer"
    path.write_bytes(DEEP)
    with pytest.raises(transfer.TransferError):
        transfer.inspect_transfer(path)


# --- O-1: trailing ideographic / fullwidth dots ------------------------------------------------------

DOTS = ["。", "．", "｡"]


@pytest.mark.parametrize("dot", DOTS)
def test_o1_single_mapped_trailing_dot_is_stripped_idempotently(dot: str) -> None:
    once = origin.canonicalize_origin("https://victim.com" + dot)
    assert once == "https://victim.com"
    assert origin.canonicalize_origin(once) == once


@pytest.mark.parametrize("dot", DOTS)
@pytest.mark.parametrize("prefix", ["", "."])
def test_o1_two_trailing_dots_are_refused_when_mapped(dot: str, prefix: str) -> None:
    with pytest.raises(origin.OriginError):
        origin.canonicalize_origin("https://victim.com" + prefix + dot + ("" if prefix else dot))


@pytest.mark.parametrize("dot", DOTS)
def test_o1_mapped_dot_inside_a_host_is_a_label_separator(dot: str) -> None:
    assert origin.canonicalize_origin(f"https://victim{dot}com") == "https://victim.com"


# --- S-1: equal version vectors, different content ------------------------------------------------

def _apply(local: dict[str, ItemState], outcome) -> dict[str, ItemState]:  # type: ignore[no-untyped-def]
    result = dict(local)
    for state in (*outcome.upserts, *outcome.deletes, *outcome.copies):
        result[state.item_id] = state
    return result


@pytest.mark.parametrize("local_state, remote_state", [
    (ItemState("item-1", {}, False, None, {"updated_at": 0, "v": 0}), ItemState("item-1", {}, True, None, None)),
    (ItemState("item-1", {}, True, None, None), ItemState("item-1", {}, False, None, {"updated_at": 0, "v": 0})),
    (ItemState("item-1", {"A": 1}, False, None, {"updated_at": 9, "v": 1}),
     ItemState("item-1", {"A": 1}, False, None, {"updated_at": 1, "v": 2})),
    (ItemState("item-1", {"A": 1}, False, None, {"updated_at": 1, "v": 2}),
     ItemState("item-1", {"A": 1}, False, None, {"updated_at": 9, "v": 1})),
])
def test_s1_second_merge_of_the_same_remote_is_a_no_op(local_state: ItemState, remote_state: ItemState) -> None:
    local = {local_state.item_id: local_state}
    first = merge(local, [remote_state])
    second = merge(_apply(local, first), [remote_state])
    assert second.upserts == () and second.deletes == () and second.copies == () and second.conflicts == ()


def test_s1_equal_vectors_local_live_wins_without_a_report() -> None:
    local = {"item-1": ItemState("item-1", {}, False, None, {"updated_at": 0, "v": 0})}
    outcome = merge(local, [ItemState("item-1", {}, True, None, None)])
    assert outcome.upserts == () and outcome.conflicts == ()


# --- CPython TemporaryDirectory cleanup race: owner-only scratch folder ---------------------------

def test_private_temp_root_is_inside_the_data_folder() -> None:
    root = backup.private_temp_root()
    assert root.parent == config.data_dir()
    with backup.private_temporary_directory("lgk-test-") as directory:
        assert Path(directory).parent == root
        (Path(directory) / "x").write_bytes(b"1")
    assert not Path(directory).exists()


def test_private_temp_root_refuses_a_junction(tmp_path: Path) -> None:
    _winapi = pytest.importorskip("_winapi")
    if not hasattr(_winapi, "CreateJunction"):
        pytest.skip("no junction support")
    target = tmp_path / "elsewhere"
    target.mkdir()
    link = config.data_dir() / backup.PRIVATE_TEMP_FOLDER
    assert not link.exists()
    _winapi.CreateJunction(str(target), str(link))
    try:
        with pytest.raises(OSError):
            backup.private_temp_root()
    finally:
        os.rmdir(link)  # removes the junction itself, never the target's contents
    assert target.is_dir()


def test_backup_verify_uses_the_private_scratch_folder(monkeypatch, tmp_path: Path) -> None:
    vault_file = _locked_vault(tmp_path)
    source = tmp_path / "profile.lgk"
    backup.export_encrypted_backup(source, vault_file=vault_file, settings_file=None, profile_name="p",
                                   backup_password=BACKUP_PASSWORD, kdf_overrides=TEST_KDF)
    seen: list[str | None] = []
    real = tempfile.TemporaryDirectory

    def recording(*args, **kwargs):  # type: ignore[no-untyped-def]
        seen.append(str(kwargs.get("dir")) if kwargs.get("dir") is not None else None)
        return real(*args, **kwargs)

    monkeypatch.setattr(tempfile, "TemporaryDirectory", recording)
    info = backup.verify_encrypted_backup(source, backup_password=BACKUP_PASSWORD, vault_password=MASTER)
    assert info["verified"] is True
    assert seen and all(entry == str(backup.private_temp_root()) for entry in seen)
    assert list(backup.private_temp_root().iterdir()) == []
