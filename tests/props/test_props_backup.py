"""Property tests for the v2 full-backup archive reader (src/localvault/backup.py).

Argon2id is replaced by a BLAKE2b stand-in (``backup.hash_secret_raw`` /
``backup.argon2id_raw`` and the vault's ``secret_text.argon2id_raw``); every
bound, AES-GCM check and ZIP check runs unchanged.
"""
from __future__ import annotations

import hashlib
import io
import json
import os
import struct
import zipfile

import pytest
from hypothesis import given, note
from hypothesis import strategies as st

from localvault import backup, secret_text, vault
from localvault.backup import BackupError

BACKUP_PW = "backup password 123"
VAULT_PW = "correct horse battery staple"


def _fake(secret=None, salt=b"", *args, **kwargs):
    material = bytes(secret if secret is not None else kwargs.get("secret")) + bytes(salt or kwargs.get("salt", b""))
    return hashlib.blake2b(material, digest_size=32).digest()


def _fake_hash_secret_raw(secret, salt, **kwargs):
    return _fake(secret, salt)


def _fake_argon2id_raw(secret, salt, **kwargs):
    return bytearray(_fake(bytes(secret), salt))


@pytest.fixture(scope="module", autouse=True)
def fast_kdf():
    saved = (backup.hash_secret_raw, backup.argon2id_raw, secret_text.argon2id_raw, os.fsync)
    backup.hash_secret_raw = _fake_hash_secret_raw
    backup.argon2id_raw = _fake_argon2id_raw
    secret_text.argon2id_raw = _fake_argon2id_raw
    os.fsync = lambda fd: None
    try:
        yield
    finally:
        backup.hash_secret_raw, backup.argon2id_raw, secret_text.argon2id_raw, os.fsync = saved


@pytest.fixture(scope="module")
def container(scratch):
    profile = scratch / "bk-profile"
    profile.mkdir()
    session = vault.create_vault(profile / "vault.json", VAULT_PW)
    session.create_web_login(urls=[{"url": "https://example.com", "match": "exact_origin"}], username="u",
                             password="p")
    session.save()
    session.lock()
    (profile / "settings.json").write_text(json.dumps({}), encoding="utf-8")
    dest = scratch / "full.lgkbackup"
    backup.export_full_backup(dest, profile_dir=profile, backup_password=BACKUP_PW)
    raw = dest.read_bytes()
    info = _read(scratch, raw)
    return raw, [(e["member"], e["sha256"]) for e in info["entries"]]


_n = [0]


def _read(scratch, data: bytes):
    _n[0] += 1
    path = scratch / f"c{_n[0]}.zip"
    path.write_bytes(data)
    seen = []
    try:
        result = backup._full_read_container(path, BACKUP_PW, on_entry=lambda e, d: seen.append(len(d)))
    finally:
        path.unlink(missing_ok=True)
    return result


def _members(raw: bytes) -> list[tuple[zipfile.ZipInfo, bytes]]:
    with zipfile.ZipFile(io.BytesIO(raw)) as z:
        return [(info, z.read(info)) for info in z.infolist()]


def _rebuild(members, *, method=zipfile.ZIP_STORED) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", method) as z:
        import warnings
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")  # duplicate names
            for name, data in members:
                z.writestr(zipfile.ZipInfo(name, (2020, 1, 1, 0, 0, 0)), data, compress_type=method)
    return buf.getvalue()


def _accepts(scratch, data, expected):
    try:
        info = _read(scratch, data)
    except BackupError:
        return False
    assert [(e["member"], e["sha256"]) for e in info["entries"]] == expected
    return True


@given(st.data())
def test_byte_mutations_fail_closed(scratch, container, data):
    raw, expected = container
    kind = data.draw(st.sampled_from(["flip", "flip", "truncate", "extend", "insert", "overwrite"]))
    buf = bytearray(raw)
    if kind == "flip":
        pos = data.draw(st.integers(0, len(raw) - 1))
        buf[pos] ^= 1 << data.draw(st.integers(0, 7))
    elif kind == "truncate":
        del buf[data.draw(st.integers(0, len(raw) - 1)):]
    elif kind == "extend":
        buf += data.draw(st.binary(min_size=1, max_size=64))
    elif kind == "insert":
        pos = data.draw(st.integers(0, len(raw)))
        buf[pos:pos] = data.draw(st.binary(min_size=1, max_size=8))
    else:
        pos = data.draw(st.integers(0, len(raw) - 4))
        buf[pos:pos + 4] = struct.pack("<I", data.draw(st.sampled_from([0, 1, 0xFFFFFFFF, 0x7FFFFFFF, len(raw)])))
    note(kind)
    _accepts(scratch, bytes(buf), expected)  # either BackupError or the identical authenticated content


NAMES = ["header.json", "manifest.bin", "data/00000000.bin", "data/00000001.bin", "data/../header.json",
         "/data/00000000.bin", "\\data\\00000000.bin", "data/00000000.bin/", "data\\00000001.bin", "DATA/00000000.bin",
         "data/00000000.bin\x00", "data/0000000.bin", "data//00000000.bin", "C:/x.bin", "data/00000002.bin",
         "../../evil.bin", "header.json ", "data/00000000.BIN"]


@given(st.data())
def test_structural_member_edits(scratch, container, data):
    raw, expected = container
    members = [(info.filename, body) for info, body in _members(raw)]
    op = data.draw(st.sampled_from(["rename", "duplicate", "drop", "add", "swap", "reorder", "deflate"]))
    method = zipfile.ZIP_STORED
    changed = op in ("duplicate", "add", "drop", "deflate")
    if op == "rename":
        i = data.draw(st.integers(0, len(members) - 1))
        new = data.draw(st.sampled_from(NAMES))
        changed = new.split(chr(0), 1)[0].replace(chr(92), "/") != members[i][0]  # zipfile truncates at NUL, maps os.sep
        members[i] = (new, members[i][1])
    elif op == "duplicate":
        i = data.draw(st.integers(0, len(members) - 1))
        dup_body = data.draw(st.sampled_from([members[i][1], b"", b"x" * 64]))
        members.insert(data.draw(st.integers(0, len(members))), (members[i][0], dup_body))
    elif op == "drop":
        del members[data.draw(st.integers(0, len(members) - 1))]
    elif op == "add":
        members.append((data.draw(st.sampled_from(NAMES)), data.draw(st.binary(max_size=64))))
    elif op == "swap" and len(members) > 3:
        i, j = data.draw(st.integers(2, len(members) - 1)), data.draw(st.integers(2, len(members) - 1))
        members[i], members[j] = (members[i][0], members[j][1]), (members[j][0], members[i][1])
    elif op == "reorder":
        members = data.draw(st.permutations(members))
    else:
        method = zipfile.ZIP_DEFLATED
    note(f"{op}: {[m[0] for m in members]}")
    rebuilt = _rebuild(members, method=method)
    accepted = _accepts(scratch, rebuilt, expected)
    if changed:
        assert not accepted, f"{op} accepted"


def test_zip_bomb_member_rejected(scratch, container):
    raw, _expected = container
    members = [(info.filename, body) for info, body in _members(raw)]
    members.append(("data/00000009.bin", b"\0" * (40 * 1024 * 1024)))
    with pytest.raises(BackupError):
        _read(scratch, _rebuild(members, method=zipfile.ZIP_DEFLATED))


def test_lying_sizes_rejected(scratch, container):
    raw, _expected = container
    data = bytearray(raw)
    # Patch every central-directory uncompressed size of manifest.bin to 1 byte.
    pos = 0
    while (pos := data.find(b"PK\x01\x02", pos)) >= 0:
        name_len = struct.unpack("<H", data[pos + 28:pos + 30])[0]
        if data[pos + 46:pos + 46 + name_len] == b"manifest.bin":
            data[pos + 24:pos + 28] = struct.pack("<I", 1)
        pos += 4
    with pytest.raises(BackupError):
        _read(scratch, bytes(data))


def test_deep_json_header_is_backup_error(scratch, container):
    """header.json is read before authentication; a deeply nested one must stay a BackupError."""
    raw, _expected = container
    members = [(info.filename, body) for info, body in _members(raw)]
    members = [(n, b"[" * 60000 if n == "header.json" else b) for n, b in members]
    with pytest.raises(BackupError):
        _read(scratch, _rebuild(members))


def test_restore_writes_only_inside_destination(scratch, container, write_audit):
    raw, _expected = container
    src = scratch / "restore-src.lgkbackup"
    src.write_bytes(raw)
    target = scratch / "restored-profile"
    result = backup.restore_full_backup(src, profile_dir=target, backup_password=BACKUP_PW, vault_password=VAULT_PW)
    assert (target / "vault.json").exists()
    assert not write_audit.violations, write_audit.violations
    assert result


def test_deep_json_v1_backup_is_backup_error(scratch):
    """Same as above for the v1 single-file backup (_read_backup_payload)."""
    path = scratch / "deep-v1.lgkbackup"
    path.write_bytes(b"[" * 60000)
    with pytest.raises(BackupError):
        backup._read_backup_payload(path, BACKUP_PW)
