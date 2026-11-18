"""KeePass key files (``localvault.keyfile``): the shared vectors and the KDBX importer agree."""

from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path

import pytest

from localvault import keyfile
from localvault.importers import kdbx
from localvault.importers.kdbx import KdbxError, read_kdbx, write_kdbx

ROOT = Path(__file__).resolve().parents[1]
VEC = ROOT / "tests" / "vectors" / "composite_key"
CASES = json.loads((VEC / "cases.json").read_text(encoding="utf-8"))
FAST_AES = {"rounds": 64}
PASSWORD = "kdbx test master"


@pytest.mark.parametrize("row", CASES["keyfiles"], ids=lambda row: row["name"])
def test_keyfile_vectors(row):
    assert keyfile.key_from_bytes((VEC / row["file"]).read_bytes()).hex() == row["key_hex"]


@pytest.mark.parametrize("row", CASES["keyfile_rejects"], ids=lambda row: row["name"])
def test_keyfile_rejects(row):
    with pytest.raises(keyfile.KeyFileError):
        keyfile.key_from_bytes((VEC / row["file"]).read_bytes())


@pytest.mark.parametrize("row", CASES["keyfiles"], ids=lambda row: row["name"])
def test_keyfile_rules_match_kdbx_importer(row):
    data = (VEC / row["file"]).read_bytes()
    assert kdbx.keyfile_key(data) == keyfile.key_from_bytes(data)
    assert kdbx.keyfile_key(VEC / row["file"]) == keyfile.key_from_bytes(data)


def test_kdbx_importer_keeps_its_errors():
    with pytest.raises(KdbxError, match="hash does not match"):
        kdbx.keyfile_key((VEC / "keyfiles" / "reject_xml_v2_bad_hash.keyx").read_bytes())
    with pytest.raises(KdbxError, match="DOCTYPE"):
        kdbx.keyfile_key((VEC / "keyfiles" / "reject_xml_doctype.key").read_bytes())
    assert kdbx.keyfile_key(None) is None


def test_kdbx_importer_still_accepts_short_xml_key_material():
    """The importer keeps KeePass's any-length XML data; only the unlock factor needs exactly 32 bytes."""
    data = (VEC / "keyfiles" / "reject_xml_v1_short.key").read_bytes()
    assert kdbx.keyfile_key(data) == b"sixteen byte key"


def test_new_xml_v2_is_random_and_valid():
    first, second = keyfile.new_keepass_xml_v2(), keyfile.new_keepass_xml_v2()
    assert first != second
    key = keyfile.key_from_bytes(first)
    assert len(key) == 32
    assert f'Hash="{hashlib.sha256(key).digest()[:4].hex().upper()}"'.encode() in first
    assert b"<Version>2.0</Version>" in first and first.endswith(b"</KeyFile>\n")


def test_new_xml_v2_loads_in_kdbx_reader(tmp_path: Path):
    xml = keyfile.new_keepass_xml_v2()
    path = tmp_path / "vault.keyx"
    path.write_bytes(xml)
    data = write_kdbx([], PASSWORD, keyfile=xml, kdf="aes-kdf", kdf_params=FAST_AES)
    assert read_kdbx(data, PASSWORD, keyfile=path) is not None
    with pytest.raises(KdbxError):
        read_kdbx(data, PASSWORD, keyfile=keyfile.new_keepass_xml_v2())


def _xml_v2_with(data_text: str) -> bytes:
    return ('<?xml version="1.0" encoding="utf-8"?><KeyFile><Meta><Version>2.0</Version></Meta>'
            f"<Key><Data>{data_text}</Data></Key></KeyFile>").encode()


def test_xml_data_ignores_only_ascii_whitespace():
    key = bytes(range(32))
    hex_key = key.hex()
    spaced = " \t\r\n".join(hex_key[i:i + 8] for i in range(0, 64, 8))
    assert keyfile.key_from_bytes(_xml_v2_with(spaced)) == key
    with pytest.raises(keyfile.KeyFileError):
        keyfile.key_from_bytes(_xml_v2_with(hex_key[:32] + "\u00a0" + hex_key[32:]))  # NBSP is data
    v1 = ('<?xml version="1.0" encoding="utf-8"?><KeyFile><Meta><Version>1.00</Version></Meta>'
          f"<Key><Data>\u00a0{base64.b64encode(key).decode()}</Data></Key></KeyFile>").encode()
    with pytest.raises(keyfile.KeyFileError):
        keyfile.key_from_bytes(v1)


def test_file_trim_is_ascii_whitespace_only():
    xml = _xml_v2_with(bytes(range(32)).hex())
    assert keyfile.key_from_bytes(b" \t\r\n" + xml + b"\n") == bytes(range(32))
    # A vertical tab or form feed is not trimmed: the XML rule misses and the file is hashed.
    assert keyfile.key_from_bytes(b"\x0b" + xml) == hashlib.sha256(b"\x0b" + xml).digest()
    # Nor is a UTF-8 BOM: unlike KeePass, the XML rule misses and the file is hashed (inherited, on purpose).
    assert keyfile.key_from_bytes(b"\xef\xbb\xbf" + xml) == hashlib.sha256(b"\xef\xbb\xbf" + xml).digest()
