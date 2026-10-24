from __future__ import annotations

import base64
import hashlib
from pathlib import Path

import pytest

from localvault.importers import ImportedRecord, ImportPasswordError, kdbx
from localvault.importers.kdbx import KdbxError, load_kdbx, read_kdbx, write_kdbx

FAST_ARGON = {"memory": 8 * 1024 * 1024, "iterations": 1, "parallelism": 1}
FAST_AES = {"rounds": 64}
PASSWORD = "kdbx test master"


def _records() -> list[ImportedRecord]:
    return [
        ImportedRecord(kind="login", title="Example", username="alice", password="pw-alice",
                       urls=["https://example.test/login"], notes="line one\nline two",
                       totp_uri="otpauth://totp/Example:alice?secret=JBSWY3DPEHPK3PXP&issuer=Example",
                       folder="Work/Web", favorite=True,
                       custom_fields=[{"name": "PIN", "value": "1234", "hidden": True},
                                      {"name": "Plan", "value": "gold", "hidden": False}],
                       created=1_700_000_000, modified=1_700_000_100, tags=["a", "b"]),
        ImportedRecord(kind="login", title="Second", username="bob", password="pw-bob",
                       urls=["https://second.test"], folder=""),
        ImportedRecord(kind="note", title="Memo", notes="remember the milk", folder="Personal"),
    ]


def _assert_round_trip(result) -> None:
    by_title = {record.title: record for record in result.records}
    assert set(by_title) == {"Example", "Second", "Memo"}
    example = by_title["Example"]
    assert example.kind == "login"
    assert example.username == "alice"
    assert example.password == "pw-alice"
    assert example.urls == ["https://example.test/login"]
    assert example.notes == "line one\nline two"
    assert example.totp_uri.startswith("otpauth://totp/")
    assert "secret=JBSWY3DPEHPK3PXP" in example.totp_uri
    assert example.folder == "Work/Web"
    assert example.created == 1_700_000_000
    assert example.modified == 1_700_000_100
    assert {f["name"]: (f["value"], f["hidden"]) for f in example.custom_fields} == {
        "PIN": ("1234", True), "Plan": ("gold", False)}
    assert sorted(example.tags) == ["a", "b"]
    assert by_title["Memo"].kind == "note"
    assert by_title["Memo"].notes == "remember the milk"
    assert by_title["Memo"].folder == "Personal"
    assert by_title["Second"].folder == ""


def test_salsa20_matches_specification_vector():
    key = bytes(range(1, 17)) + bytes(range(201, 217))
    nonce = bytes(range(101, 109))
    counter = int.from_bytes(bytes(range(109, 117)), "little")
    block = kdbx._salsa20_block(key, nonce, counter)
    assert block == bytes([
        69, 37, 68, 39, 41, 15, 107, 193, 255, 139, 122, 6, 170, 233, 217, 98,
        89, 144, 182, 106, 21, 51, 200, 65, 239, 49, 222, 34, 215, 114, 40, 126,
        104, 197, 7, 225, 197, 153, 31, 2, 102, 78, 76, 176, 84, 245, 246, 184,
        177, 160, 133, 130, 6, 72, 149, 119, 192, 195, 132, 236, 234, 103, 246, 74])


@pytest.mark.parametrize("cipher,kdf,compress", [
    ("aes256", "argon2d", True),
    ("chacha20", "argon2id", False),
    ("aes256", "aes-kdf", True),
])
def test_kdbx4_round_trip(cipher, kdf, compress):
    params = FAST_AES if kdf == "aes-kdf" else FAST_ARGON
    data = write_kdbx(_records(), PASSWORD, version=4, cipher=cipher, kdf=kdf, compress=compress, kdf_params=params)
    assert data[:8] == bytes.fromhex("03d9a29a67fb4bb5")
    database = read_kdbx(data, PASSWORD)
    assert database.version == (4, 0)
    assert database.cipher == cipher
    result = load_kdbx(data, PASSWORD)
    assert result.source_format == "kdbx"
    _assert_round_trip(result)
    assert "pw-alice" not in repr(result.records)


def test_kdbx3_round_trip_with_salsa20_and_hashed_blocks():
    data = write_kdbx(_records(), PASSWORD, version=3, kdf_params=FAST_AES)
    database = read_kdbx(data, PASSWORD)
    assert database.version == (3, 1)
    _assert_round_trip(load_kdbx(data, PASSWORD))


def test_kdbx3_round_trip_without_compression():
    data = write_kdbx(_records(), PASSWORD, version=3, compress=False, kdf_params=FAST_AES)
    _assert_round_trip(load_kdbx(data, PASSWORD))


def test_kdbx_round_trip_from_file(tmp_path: Path):
    path = tmp_path / "vault.kdbx"
    path.write_bytes(write_kdbx(_records(), PASSWORD, kdf_params=FAST_ARGON))
    _assert_round_trip(load_kdbx(path, PASSWORD))


@pytest.mark.parametrize("version", [3, 4])
def test_wrong_password_is_reported(version):
    data = write_kdbx(_records(), PASSWORD, version=version, kdf_params=FAST_AES, kdf="aes-kdf")
    with pytest.raises(ImportPasswordError):
        read_kdbx(data, "not the password")
    assert issubclass(ImportPasswordError, KdbxError) or issubclass(kdbx.KdbxPasswordError, KdbxError)


@pytest.mark.parametrize("version", [3, 4])
def test_truncated_file_is_rejected(version):
    data = write_kdbx(_records(), PASSWORD, version=version, kdf_params=FAST_AES, kdf="aes-kdf")
    for cut in (4, 40, len(data) // 2, len(data) - 20):
        with pytest.raises(KdbxError):
            read_kdbx(data[:cut], PASSWORD)


def test_kdbx4_corrupted_body_fails_hmac():
    data = bytearray(write_kdbx(_records(), PASSWORD, version=4, kdf="aes-kdf", kdf_params=FAST_AES))
    data[-40] ^= 0x01
    with pytest.raises(KdbxError, match="(?i)hmac|integrity|corrupt"):
        read_kdbx(bytes(data), PASSWORD)


def test_kdbx4_corrupted_header_is_detected():
    data = bytearray(write_kdbx(_records(), PASSWORD, version=4, kdf="aes-kdf", kdf_params=FAST_AES))
    data[20] ^= 0x01
    with pytest.raises(KdbxError):
        read_kdbx(bytes(data), PASSWORD)


def test_kdbx3_corrupted_block_hash_is_detected():
    data = bytearray(write_kdbx(_records(), PASSWORD, version=3, kdf_params=FAST_AES))
    data[-60] ^= 0x01
    with pytest.raises(KdbxError):
        read_kdbx(bytes(data), PASSWORD)


def test_unsupported_kdf_parameters_are_rejected():
    with pytest.raises(KdbxError):
        kdbx._check_kdf_limits({"$UUID": kdbx.KDF_ARGON2D, "M": 16 * 1024 ** 3, "I": 1, "P": 1, "V": 0x13, "S": b"x" * 32})
    with pytest.raises(KdbxError):
        kdbx._check_kdf_limits({"$UUID": kdbx.KDF_AES, "R": 2 ** 40, "S": b"x" * 32})
    with pytest.raises(KdbxError, match="(?i)twofish"):
        header = kdbx._encode_header_v4(cipher=kdbx.CIPHER_TWOFISH, compress=True, master_seed=b"m" * 32,
                                        iv=b"i" * 16, kdf={"$UUID": kdbx.KDF_AES, "R": 1, "S": b"s" * 32})
        kdbx._parse_header(header + bytes(64))


def test_keyfile_variants_round_trip(tmp_path: Path):
    raw = bytes(range(32))
    xml_v2 = (
        '<?xml version="1.0" encoding="utf-8"?><KeyFile><Meta><Version>2.0</Version></Meta>'
        f'<Key><Data Hash="{hashlib.sha256(raw).hexdigest()[:8].upper()}">{raw.hex().upper()}</Data></Key></KeyFile>'
    ).encode()
    xml_v1 = ('<?xml version="1.0" encoding="utf-8"?><KeyFile><Meta><Version>1.00</Version></Meta>'
              f'<Key><Data>{base64.b64encode(raw).decode()}</Data></Key></KeyFile>').encode()
    for keyfile in (raw, raw.hex().encode(), xml_v2, xml_v1, b"arbitrary key material"):
        data = write_kdbx(_records(), PASSWORD, keyfile=keyfile, kdf="aes-kdf", kdf_params=FAST_AES)
        _assert_round_trip(load_kdbx(data, PASSWORD, keyfile=keyfile))
        with pytest.raises(ImportPasswordError):
            read_kdbx(data, PASSWORD)
    path = tmp_path / "key.keyx"
    path.write_bytes(xml_v2)
    data = write_kdbx(_records(), PASSWORD, keyfile=xml_v2, kdf="aes-kdf", kdf_params=FAST_AES)
    _assert_round_trip(load_kdbx(data, PASSWORD, keyfile=path))


def test_history_recycle_bin_and_totp_variants_are_parsed():
    xml = kdbx.build_keepass_xml(_records(), protect=True)
    # Inject history, a recycle bin and alternative TOTP field conventions.
    # The root group closes right before <DeletedObjects>; inject inside it.
    xml = xml.replace(
        "</Group><DeletedObjects",
        '<Group><UUID>AAAAAAAAAAAAAAAAAAAAAQ==</UUID><Name>Recycle Bin</Name>'
        '<Entry><UUID>AAAAAAAAAAAAAAAAAAAAAg==</UUID><String><Key>Title</Key><Value>Deleted</Value></String>'
        '<String><Key>Password</Key><Value Protected="True">deleted</Value></String></Entry></Group></Group><DeletedObjects',
    ).replace("<RecycleBinEnabled>False</RecycleBinEnabled>", "<RecycleBinEnabled>True</RecycleBinEnabled>"
    ).replace("<RecycleBinUUID>AAAAAAAAAAAAAAAAAAAAAA==</RecycleBinUUID>", "<RecycleBinUUID>AAAAAAAAAAAAAAAAAAAAAQ==</RecycleBinUUID>")
    variants = (
        '<Entry><UUID>AAAAAAAAAAAAAAAAAAAAAw==</UUID><String><Key>Title</Key><Value>Seeded</Value></String>'
        '<String><Key>UserName</Key><Value>seed</Value></String><String><Key>Password</Key><Value>x</Value></String>'
        '<String><Key>TOTP Seed</Key><Value>JBSW Y3DP EHPK 3PXP</Value></String>'
        '<String><Key>TOTP Settings</Key><Value>60;8</Value></String>'
        '<History><Entry><UUID>AAAAAAAAAAAAAAAAAAAAAw==</UUID><String><Key>Title</Key><Value>Seeded old</Value></String>'
        '<String><Key>Password</Key><Value Protected="True">old</Value></String></Entry></History></Entry>'
        '<Entry><UUID>AAAAAAAAAAAAAAAAAAAABA==</UUID><String><Key>Title</Key><Value>KeeOtp</Value></String>'
        '<String><Key>Password</Key><Value>y</Value></String>'
        '<String><Key>otp</Key><Value>key=JBSWY3DPEHPK3PXP&amp;step=30&amp;size=6</Value></String></Entry>'
        '<Entry><UUID>AAAAAAAAAAAAAAAAAAAABQ==</UUID><String><Key>Title</Key><Value>Builtin</Value></String>'
        '<String><Key>Password</Key><Value>z</Value></String>'
        '<String><Key>TimeOtp-Secret-Base32</Key><Value>JBSWY3DPEHPK3PXP</Value></String>'
        '<String><Key>TimeOtp-Length</Key><Value>8</Value></String>'
        '<String><Key>TimeOtp-Period</Key><Value>60</Value></String>'
        '<String><Key>TimeOtp-Algorithm</Key><Value>HMAC-SHA-256</Value></String></Entry>'
    )
    xml = xml.replace("</Group><DeletedObjects", variants + "</Group><DeletedObjects", 1)
    # Protected values in the injected XML are plaintext; the writer encrypts them with the inner stream.
    data = write_kdbx([], PASSWORD, xml=xml, kdf="aes-kdf", kdf_params=FAST_AES)
    database = read_kdbx(data, PASSWORD)
    titles = {entry.title: entry for entry in database.iter_entries(include_recycle_bin=True)}
    assert titles["Deleted"].password == "deleted"
    seeded = titles["Seeded"]
    assert len(seeded.history) == 1 and seeded.history[0].password == "old"
    result = load_kdbx(data, PASSWORD)
    by_title = {record.title: record for record in result.records}
    assert "Deleted" not in by_title
    assert any("Recycle Bin" in line for line in result.diagnostics)
    assert "period=60" in by_title["Seeded"].totp_uri and "digits=8" in by_title["Seeded"].totp_uri
    assert "secret=JBSWY3DPEHPK3PXP" in by_title["Seeded"].totp_uri
    assert by_title["KeeOtp"].totp_uri.startswith("otpauth://totp/") and "JBSWY3DPEHPK3PXP" in by_title["KeeOtp"].totp_uri
    assert "algorithm=SHA256" in by_title["Builtin"].totp_uri and "digits=8" in by_title["Builtin"].totp_uri
    assert not any(f["name"].startswith("TimeOtp") or f["name"] == "otp" for f in by_title["Builtin"].custom_fields)


def test_xml_with_doctype_is_rejected():
    xml = '<!DOCTYPE KeePassFile [<!ENTITY x "y">]>' + kdbx.build_keepass_xml(_records(), protect=False)
    # Raw bytes bypass the writer's own XML processing so the reader sees the DOCTYPE.
    data = write_kdbx([], PASSWORD, xml=xml.encode("utf-8"), kdf="aes-kdf", kdf_params=FAST_AES)
    with pytest.raises(KdbxError):
        read_kdbx(data, PASSWORD)


def test_not_a_kdbx_file():
    with pytest.raises(KdbxError):
        read_kdbx(b"not a database at all, just bytes " * 4, PASSWORD)
    with pytest.raises(KdbxError, match="(?i)1\\.x"):
        read_kdbx(bytes.fromhex("03d9a29a65fb4bb5") + b"\x00" * 100, PASSWORD)


def test_plain_keepass_xml_export_is_importable():
    xml = kdbx.build_keepass_xml(_records(), protect=False)
    assert "Protected=\"True\"" not in xml
    result = kdbx.load_keepass_xml(xml.encode("utf-8"))
    _assert_round_trip(result)
