"""Reproducers: deeply nested JSON at untrusted-input parse sites that catch ValueError but not
RecursionError (CPython 3.14's C decoder raises RecursionError "Stack overflow ... while decoding",
which is NOT a ValueError).  Each test expects the module's documented error type."""
from __future__ import annotations

import io
import struct

import pytest

from localvault import backup, native_host, protocol, transfer, vault

DEEP = b"[" * 60000


def test_native_host_frame():  # native_host.py:116
    with pytest.raises(native_host.NativeBridgeError):
        native_host._read_native_message(io.BytesIO(struct.pack("=I", len(DEEP)) + DEEP))


def test_protocol_native_frame():  # protocol.py:41 (and recv_local_message, protocol.py:81, with !I framing)
    with pytest.raises(protocol.ProtocolError):
        protocol.read_native_message(io.BytesIO(struct.pack("=I", len(DEEP)) + DEEP))


def test_vault_file(scratch):  # vault.py:3575
    path = scratch / "deep-vault.json"
    path.write_bytes(DEEP)
    with pytest.raises(vault.VaultError):
        vault.unlock_vault(path, "correct horse battery staple")


def test_backup_v1(scratch):  # backup.py:214
    path = scratch / "deep.lgkbackup"
    path.write_bytes(DEEP)
    with pytest.raises(backup.BackupError):
        backup._read_backup_payload(path, "backup password 123")


def test_transfer_package(scratch):  # transfer.py:206
    path = scratch / "deep.lgktransfer"
    path.write_bytes(DEEP)
    with pytest.raises(transfer.TransferError):
        transfer.inspect_transfer(path)
