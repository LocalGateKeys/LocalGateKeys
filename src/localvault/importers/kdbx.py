"""KeePass 2 KDBX 3.1 and 4.x reader and writer.

Implemented with the primitives already shipped with the application
(``cryptography`` for AES/ChaCha20, ``argon2-cffi`` for Argon2d/Argon2id) plus
pure-Python Salsa20/ARC4 for the KDBX 3 inner stream.  Supported:

* outer ciphers AES-256-CBC and ChaCha20 (Twofish is rejected),
* key derivation AES-KDF, Argon2d and Argon2id with bounded parameters,
* KDBX 4 HMAC-SHA256 block stream, KDBX 3 hashed block stream,
* gzip inner compression, inner headers / binaries,
* protected values via Salsa20 (v3), ChaCha20 (v4) and legacy ARC4,
* groups, entries, history, tags, times, custom strings and the TOTP
  conventions used by KeePassXC (``otp``), KeeOtp (``key=``), KeeTrayTOTP
  (``TOTP Seed``/``TOTP Settings``) and KeePass 2.51+ (``TimeOtp-*``),
* optional key files (raw 32 bytes, 64 hex characters, XML 1.0/2.0,
  arbitrary bytes hashed).

The writer produces either version so the reader can be exercised by
synthetic round-trip fixtures and so the application can export ``.kdbx``.
"""
from __future__ import annotations

import base64
import gzip
import hashlib
import hmac
import io
import os
import re
import struct
import uuid as uuid_module
import xml.etree.ElementTree as ET
import xml.parsers.expat as _expat
from collections.abc import Iterable, Iterator, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs

from argon2.low_level import Type as _ArgonType
from argon2.low_level import hash_secret_raw
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from . import (
    MAX_RECORDS,
    ImportedRecord,
    ImportFormatError,
    ImportPasswordError,
    ImportResult,
    check_record_count,
    enforce_record_limit,
    totp_uri_from_secret,
)
from ._source import iso_timestamp, parse_timestamp, read_source_bytes
from ..i18n import t

SIGNATURE_1 = 0x9AA2D903
SIGNATURE_2 = 0xB54BFB67
SIGNATURE_2_KDB1 = 0xB54BFB65
SIGNATURE_2_PRERELEASE = 0xB54BFB66
MAGIC = struct.pack("<II", SIGNATURE_1, SIGNATURE_2)

CIPHER_AES = bytes.fromhex("31c1f2e6bf714350be5805216afc5aff")
CIPHER_CHACHA20 = bytes.fromhex("d6038a2b8b6f4cb5a524339a31dbb59a")
CIPHER_TWOFISH = bytes.fromhex("ad68f29f576f4bb9a36ad47af965346c")
KDF_AES = bytes.fromhex("c9d9f39a628a4460bf740d08c18a4fea")
KDF_ARGON2D = bytes.fromhex("ef636ddf8c29444b91f7a9a403e30a0c")
KDF_ARGON2ID = bytes.fromhex("9e298b1956db4773b23dfc3ec6f0a1e6")

CIPHER_NAMES = {CIPHER_AES: "aes256", CIPHER_CHACHA20: "chacha20", CIPHER_TWOFISH: "twofish"}
CIPHER_IDS = {"aes256": CIPHER_AES, "aes": CIPHER_AES, "chacha20": CIPHER_CHACHA20}
KDF_NAMES = {KDF_AES: "aes-kdf", KDF_ARGON2D: "argon2d", KDF_ARGON2ID: "argon2id"}
KDF_IDS = {"aes-kdf": KDF_AES, "aes": KDF_AES, "argon2d": KDF_ARGON2D, "argon2": KDF_ARGON2D, "argon2id": KDF_ARGON2ID}

SALSA20_NONCE = bytes.fromhex("e830094b97205d2a")
STREAM_NONE, STREAM_ARC4, STREAM_SALSA20, STREAM_CHACHA20 = 0, 1, 2, 3

MAX_KDBX_BYTES = 64 * 1024 * 1024
MAX_XML_BYTES = 128 * 1024 * 1024
# Element budget checked by the expat pre-pass before ElementTree builds the
# tree (about 90 bytes per element): a 5,000-entry database with full history
# stays well below it, a crafted ``<Entry/>`` flood is refused before parsing.
MAX_XML_ELEMENTS = 4_000_000
# Historical versions are parsed only to be counted; KeePass keeps 10 per entry by default.
MAX_HISTORY_ENTRIES = 20 * MAX_RECORDS
# A protected value is decrypted only if it could be imported: the largest
# vault value is a note (20,000 characters, overflowing into 50 custom fields
# of 4,096), so 1 MiB is generous.  The totals bound decryption time: the
# pure-Python Salsa20/ARC4 keystreams of KDBX 3 run at about 1 s per MiB,
# ChaCha20 (KDBX 4) is native.  KeePass protects only passwords by default.
MAX_PROTECTED_VALUE_BYTES = 1024 * 1024
MAX_PROTECTED_TOTAL_BYTES = 64 * 1024 * 1024
MAX_SLOW_STREAM_TOTAL_BYTES = 4 * 1024 * 1024
# Import KDF ceilings. Real KeePass/KeePassXC databases use Argon2 at
# 64 MiB with a handful of iterations (KeePass default 2; KeePassXC calibrates
# to a ~1 s unlock, often tens of iterations; even its 5 s setting stays well
# under the budget). Total work (memory x iterations) is capped at 32 GiB of
# Argon2 passes - well under a minute even on a slow machine - so a hostile
# file cannot pin the importer for many minutes with 1 GiB x 1000.
MAX_ARGON2_MEMORY = 1024 * 1024 * 1024
MAX_ARGON2_ITERATIONS = 1_000
MAX_ARGON2_WORK = 32 * 1024 * 1024 * 1024
MAX_ARGON2_PARALLELISM = 64
MAX_AES_KDF_ROUNDS = 50_000_000
HMAC_BLOCK_SIZE = 1024 * 1024
_EPOCH_OFFSET = 62_135_596_800  # seconds between 0001-01-01 and 1970-01-01
_END_OF_HEADER = b"\r\n\r\n"
_STANDARD_KEYS = ("Title", "UserName", "Password", "URL", "Notes")
_TOTP_KEYS = {"otp", "totp seed", "totp settings", "timeotp-secret-base32", "timeotp-secret", "timeotp-secret-hex",
              "timeotp-length", "timeotp-period", "timeotp-algorithm"}
_XML_CONTROL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f]")


class KdbxError(ImportFormatError):
    """The file is not a readable KDBX database."""


class KdbxPasswordError(KdbxError, ImportPasswordError):
    """The credentials do not open the database (or it is corrupted)."""


class KdbxIntegrityError(KdbxError):
    """An authenticated block or header hash did not verify."""


# --------------------------------------------------------------------------- stream ciphers
_M32 = 0xFFFFFFFF


def _rotl(value: int, count: int) -> int:
    return ((value << count) & _M32) | (value >> (32 - count))


def _salsa20_block(key: bytes, nonce: bytes, counter: int) -> bytes:
    k = struct.unpack("<8I", key)
    n = struct.unpack("<2I", nonce)
    state = [0x61707865, k[0], k[1], k[2], k[3], 0x3320646E, n[0], n[1],
             counter & _M32, (counter >> 32) & _M32, 0x79622D32, k[4], k[5], k[6], k[7], 0x6B206574]
    x = list(state)
    rounds = ((0, 4, 8, 12), (5, 9, 13, 1), (10, 14, 2, 6), (15, 3, 7, 11),
              (0, 1, 2, 3), (5, 6, 7, 4), (10, 11, 8, 9), (15, 12, 13, 14))
    for _ in range(10):
        for a, b, c, d in rounds:
            x[b] ^= _rotl((x[a] + x[d]) & _M32, 7)
            x[c] ^= _rotl((x[b] + x[a]) & _M32, 9)
            x[d] ^= _rotl((x[c] + x[b]) & _M32, 13)
            x[a] ^= _rotl((x[d] + x[c]) & _M32, 18)
    return struct.pack("<16I", *[(x[i] + state[i]) & _M32 for i in range(16)])


class _KeyStream:
    """Incrementally XORs data with a keystream (Salsa20, ChaCha20 or ARC4).

    Each call generates the missing keystream in one go and XORs it as one
    integer, so a value costs linear time (growing the buffer block by block
    and XORing byte by byte made a 4 MiB value take half a minute).
    """

    def __init__(self, stream_id: int, key: bytes):
        self.stream_id = stream_id
        self._buffer = b""
        self._counter = 0
        if stream_id == STREAM_NONE:
            self._generate = None
        elif stream_id == STREAM_SALSA20:
            self._key = hashlib.sha256(key).digest()
            self._generate = self._salsa20
        elif stream_id == STREAM_CHACHA20:
            digest = hashlib.sha512(key).digest()
            self._encryptor = Cipher(algorithms.ChaCha20(digest[:32], b"\x00" * 4 + digest[32:44]), None).encryptor()
            self._generate = lambda count: self._encryptor.update(bytes(count))
        elif stream_id == STREAM_ARC4:
            self._arc4_init(key)
            self._generate = self._arc4
        else:
            raise KdbxError(f"Unsupported inner random stream {stream_id}")

    def _salsa20(self, count: int) -> bytes:
        """At least ``count`` bytes of keystream (whole 64-byte blocks)."""
        start = self._counter
        self._counter += (count + 63) // 64
        return b"".join(_salsa20_block(self._key, SALSA20_NONCE, counter) for counter in range(start, self._counter))

    def _arc4_init(self, key: bytes) -> None:
        if not key:
            raise KdbxError("Empty ARC4 inner stream key")
        s = list(range(256))
        j = 0
        for i in range(256):
            j = (j + s[i] + key[i % len(key)]) & 0xFF
            s[i], s[j] = s[j], s[i]
        self._s, self._i, self._j = s, 0, 0
        self._arc4(512)  # KeePass discards the first 512 keystream bytes.

    def _arc4(self, count: int) -> bytes:
        s, i, j = self._s, self._i, self._j
        out = bytearray()
        for _ in range(count):
            i = (i + 1) & 0xFF
            j = (j + s[i]) & 0xFF
            s[i], s[j] = s[j], s[i]
            out.append(s[(s[i] + s[j]) & 0xFF])
        self._i, self._j = i, j
        return bytes(out)

    def process(self, data: bytes) -> bytes:
        if self._generate is None or not data:
            return data
        size = len(data)
        if len(self._buffer) < size:
            self._buffer += self._generate(size - len(self._buffer))
        stream, self._buffer = self._buffer[:size], self._buffer[size:]
        mixed = int.from_bytes(data, "little") ^ int.from_bytes(stream, "little")
        return mixed.to_bytes(size, "little")


# --------------------------------------------------------------------------- variant dictionary
_VD_UINT32, _VD_UINT64, _VD_BOOL, _VD_INT32, _VD_INT64, _VD_STRING, _VD_BYTES = 0x04, 0x05, 0x08, 0x0C, 0x0D, 0x18, 0x42


def _parse_variant_dict(data: bytes) -> dict[str, Any]:
    if len(data) < 3:
        raise KdbxError("KDF parameters are truncated")
    version = struct.unpack_from("<H", data, 0)[0]
    if version & 0xFF00 != 0x0100:
        raise KdbxError("Unsupported KDF parameter dictionary version")
    result: dict[str, Any] = {}
    pos = 2
    while True:
        if pos >= len(data):
            raise KdbxError("KDF parameters are truncated")
        kind = data[pos]
        pos += 1
        if kind == 0:
            break
        if pos + 4 > len(data):
            raise KdbxError("KDF parameters are truncated")
        name_len = struct.unpack_from("<i", data, pos)[0]
        pos += 4
        if name_len < 0 or pos + name_len > len(data):
            raise KdbxError("KDF parameters are truncated")
        name = data[pos:pos + name_len].decode("utf-8", "replace")
        pos += name_len
        if pos + 4 > len(data):
            raise KdbxError("KDF parameters are truncated")
        value_len = struct.unpack_from("<i", data, pos)[0]
        pos += 4
        if value_len < 0 or pos + value_len > len(data):
            raise KdbxError("KDF parameters are truncated")
        raw = data[pos:pos + value_len]
        pos += value_len
        try:
            if kind == _VD_UINT32:
                value: Any = struct.unpack("<I", raw)[0]
            elif kind == _VD_UINT64:
                value = struct.unpack("<Q", raw)[0]
            elif kind == _VD_BOOL:
                value = raw != b"\x00"
            elif kind == _VD_INT32:
                value = struct.unpack("<i", raw)[0]
            elif kind == _VD_INT64:
                value = struct.unpack("<q", raw)[0]
            elif kind == _VD_STRING:
                value = raw.decode("utf-8")
            elif kind == _VD_BYTES:
                value = raw
            else:
                raise KdbxError(f"Unsupported KDF parameter type {kind:#x}")
        except (struct.error, UnicodeDecodeError) as exc:
            raise KdbxError("KDF parameters are malformed") from exc
        result[name] = value
    return result


def _encode_variant_dict(values: Mapping[str, Any]) -> bytes:
    out = bytearray(struct.pack("<H", 0x0100))
    for name, value in values.items():
        if isinstance(value, bool):
            kind, raw = _VD_BOOL, (b"\x01" if value else b"\x00")
        elif isinstance(value, int):
            if name in {"P", "V"} or (0 <= value < 2 ** 32 and name not in {"R", "M", "I"}):
                kind, raw = _VD_UINT32, struct.pack("<I", value)
            else:
                kind, raw = _VD_UINT64, struct.pack("<Q", value)
        elif isinstance(value, str):
            kind, raw = _VD_STRING, value.encode("utf-8")
        elif isinstance(value, (bytes, bytearray)):
            kind, raw = _VD_BYTES, bytes(value)
        else:
            raise KdbxError(f"Cannot encode KDF parameter {name!r}")
        encoded_name = name.encode("utf-8")
        out += bytes([kind]) + struct.pack("<i", len(encoded_name)) + encoded_name
        out += struct.pack("<i", len(raw)) + raw
    out += b"\x00"
    return bytes(out)


def _check_kdf_limits(kdf: Mapping[str, Any]) -> None:
    kdf_id = kdf.get("$UUID")
    if kdf_id == KDF_AES:
        rounds = kdf.get("R")
        seed = kdf.get("S")
        if not isinstance(rounds, int) or rounds < 1 or rounds > MAX_AES_KDF_ROUNDS:
            raise KdbxError("AES-KDF round count is outside the supported range")
        if not isinstance(seed, (bytes, bytearray)) or len(seed) != 32:
            raise KdbxError("AES-KDF seed must be 32 bytes")
    elif kdf_id in (KDF_ARGON2D, KDF_ARGON2ID):
        memory, iterations, parallelism, salt = kdf.get("M"), kdf.get("I"), kdf.get("P"), kdf.get("S")
        if not isinstance(memory, int) or memory < 8 * 1024 or memory > MAX_ARGON2_MEMORY:
            raise KdbxError("Argon2 memory parameter is outside the supported range")
        if not isinstance(iterations, int) or iterations < 1 or iterations > MAX_ARGON2_ITERATIONS:
            raise KdbxError("Argon2 iteration count is outside the supported range")
        if not isinstance(parallelism, int) or parallelism < 1 or parallelism > MAX_ARGON2_PARALLELISM:
            raise KdbxError("Argon2 parallelism is outside the supported range")
        if memory * iterations > MAX_ARGON2_WORK:
            raise KdbxError("Argon2 memory x iterations exceeds the supported import budget")
        if not isinstance(salt, (bytes, bytearray)) or not 8 <= len(salt) <= 64:
            raise KdbxError("Argon2 salt length is unsupported")
        if kdf.get("V", 0x13) not in (0x10, 0x13):
            raise KdbxError("Unsupported Argon2 version")
        if kdf.get("K") or kdf.get("A"):
            raise KdbxError("Argon2 secret key / associated data are unsupported")
    else:
        raise KdbxError("Unsupported key derivation function")


# --------------------------------------------------------------------------- header
@dataclass
class _Header:
    version: tuple[int, int]
    raw: bytes
    end: int
    cipher: bytes
    compress: bool
    master_seed: bytes
    iv: bytes
    kdf: dict[str, Any]
    inner_stream_id: int = STREAM_NONE
    inner_stream_key: bytes = b""
    stream_start: bytes = b""


def _parse_header(data: bytes) -> _Header:
    if len(data) < 12:
        raise KdbxError("File is too short to be a KDBX database")
    sig1, sig2, minor, major = struct.unpack_from("<IIHH", data, 0)
    if sig1 != SIGNATURE_1 or sig2 not in (SIGNATURE_2, SIGNATURE_2_KDB1, SIGNATURE_2_PRERELEASE):
        raise KdbxError("Not a KeePass KDBX database")
    if sig2 == SIGNATURE_2_KDB1:
        raise KdbxError(t("kdbx.keepass1XKdbDatabases"))
    if major not in (3, 4):
        raise KdbxError(f"Unsupported KDBX version {major}.{minor}")
    fields: dict[int, bytes] = {}
    pos = 12
    size_fmt, size_len = ("<I", 4) if major == 4 else ("<H", 2)
    while True:
        if pos + 1 + size_len > len(data):
            raise KdbxError("KDBX header is truncated")
        field_id = data[pos]
        size = struct.unpack_from(size_fmt, data, pos + 1)[0]
        pos += 1 + size_len
        if pos + size > len(data):
            raise KdbxError("KDBX header is truncated")
        value = data[pos:pos + size]
        pos += size
        if field_id == 0:
            break
        fields[field_id] = value
    cipher = fields.get(2, b"")
    if cipher not in CIPHER_NAMES:
        raise KdbxError("Unsupported outer cipher")
    if cipher == CIPHER_TWOFISH:
        raise KdbxError(t("kdbx.twofishEncryptedDatabasesAreNot"))
    compression = fields.get(3, b"")
    if len(compression) != 4:
        raise KdbxError("KDBX header is missing the compression flag")
    compress_flag = struct.unpack("<I", compression)[0]
    if compress_flag not in (0, 1):
        raise KdbxError("Unsupported compression algorithm")
    master_seed = fields.get(4, b"")
    if len(master_seed) != 32:
        raise KdbxError("KDBX master seed must be 32 bytes")
    iv = fields.get(7, b"")
    expected_iv = 16 if cipher == CIPHER_AES else 12
    if len(iv) != expected_iv:
        raise KdbxError("KDBX encryption IV has an unexpected length")
    header = _Header((major, minor), data[:pos], pos, cipher, compress_flag == 1, master_seed, iv, {})
    if major == 4:
        if 11 not in fields:
            raise KdbxError("KDBX 4 header is missing KDF parameters")
        header.kdf = _parse_variant_dict(fields[11])
        _check_kdf_limits(header.kdf)
    else:
        if cipher != CIPHER_AES:
            raise KdbxError("KDBX 3 databases must use AES-256")
        seed, rounds = fields.get(5, b""), fields.get(6, b"")
        if len(rounds) != 8:
            raise KdbxError("KDBX 3 header is missing the transform rounds")
        header.kdf = {"$UUID": KDF_AES, "S": seed, "R": struct.unpack("<Q", rounds)[0]}
        _check_kdf_limits(header.kdf)
        header.inner_stream_key = fields.get(8, b"")
        header.stream_start = fields.get(9, b"")
        if len(header.stream_start) != 32:
            raise KdbxError("KDBX 3 header is missing the stream start bytes")
        stream = fields.get(10, b"")
        if len(stream) != 4:
            raise KdbxError("KDBX 3 header is missing the inner stream id")
        header.inner_stream_id = struct.unpack("<I", stream)[0]
    return header


def _header_field(field_id: int, value: bytes, *, v4: bool) -> bytes:
    return bytes([field_id]) + (struct.pack("<I", len(value)) if v4 else struct.pack("<H", len(value))) + value


def _encode_header_v4(*, cipher: bytes, compress: bool, master_seed: bytes, iv: bytes, kdf: Mapping[str, Any]) -> bytes:
    out = bytearray(MAGIC + struct.pack("<HH", 0, 4))
    out += _header_field(2, cipher, v4=True)
    out += _header_field(3, struct.pack("<I", 1 if compress else 0), v4=True)
    out += _header_field(4, master_seed, v4=True)
    out += _header_field(7, iv, v4=True)
    out += _header_field(11, _encode_variant_dict(kdf), v4=True)
    out += _header_field(0, _END_OF_HEADER, v4=True)
    return bytes(out)


def _encode_header_v3(*, compress: bool, master_seed: bytes, transform_seed: bytes, rounds: int, iv: bytes,
                      stream_key: bytes, stream_start: bytes, stream_id: int) -> bytes:
    out = bytearray(MAGIC + struct.pack("<HH", 1, 3))
    out += _header_field(2, CIPHER_AES, v4=False)
    out += _header_field(3, struct.pack("<I", 1 if compress else 0), v4=False)
    out += _header_field(4, master_seed, v4=False)
    out += _header_field(5, transform_seed, v4=False)
    out += _header_field(6, struct.pack("<Q", rounds), v4=False)
    out += _header_field(7, iv, v4=False)
    out += _header_field(8, stream_key, v4=False)
    out += _header_field(9, stream_start, v4=False)
    out += _header_field(10, struct.pack("<I", stream_id), v4=False)
    out += _header_field(0, _END_OF_HEADER, v4=False)
    return bytes(out)


# --------------------------------------------------------------------------- key derivation
def keyfile_key(source: bytes | Path | str | None) -> bytes | None:
    """Return the 32-byte key material a KeePass key file contributes."""
    if source is None:
        return None
    data = read_source_bytes(source, limit=MAX_KDBX_BYTES) if not isinstance(source, (bytes, bytearray)) else bytes(source)
    text = data.strip()
    if text.startswith(b"<?xml") or text.startswith(b"<KeyFile"):
        root = _safe_fromstring(text, doctype_message="Key file contains a DOCTYPE and was rejected",
                                malformed_message="Key file XML is malformed")
        version = (root.findtext("Meta/Version") or "1.0").strip()
        node = root.find("Key/Data")
        if node is None or not (node.text or "").strip():
            raise KdbxError("Key file XML has no key data")
        payload = "".join((node.text or "").split())
        if version.startswith("2"):
            try:
                key = bytes.fromhex(payload)
            except ValueError as exc:
                raise KdbxError("Key file 2.0 data must be hexadecimal") from exc
            expected = node.get("Hash")
            if expected and hashlib.sha256(key).hexdigest()[:len(expected)].casefold() != expected.casefold():
                raise KdbxError("Key file hash does not match its data")
            return key
        try:
            return base64.b64decode(payload, validate=True)
        except (ValueError, TypeError) as exc:
            raise KdbxError("Key file 1.0 data must be Base64") from exc
    if len(data) == 32:
        return data
    if len(text) == 64:
        try:
            return bytes.fromhex(text.decode("ascii"))
        except (UnicodeDecodeError, ValueError):
            pass
    return hashlib.sha256(data).digest()


def _composite_key(password: str | None, key_material: bytes | None) -> bytes:
    parts = b""
    if password is not None and (password != "" or key_material is None):
        parts += hashlib.sha256(password.encode("utf-8")).digest()
    if key_material:
        parts += key_material
    if not parts:
        raise KdbxPasswordError(t("kdbx.aPasswordOrKeyFile"))
    return hashlib.sha256(parts).digest()


def _transform_key(composite: bytes, kdf: Mapping[str, Any]) -> bytes:
    kdf_id = kdf["$UUID"]
    if kdf_id == KDF_AES:
        encryptor = Cipher(algorithms.AES(bytes(kdf["S"])), modes.ECB()).encryptor()  # noqa: S305 - KeePass AES-KDF
        key = composite
        for _ in range(int(kdf["R"])):
            key = encryptor.update(key)
        return hashlib.sha256(key).digest()
    argon_type = _ArgonType.D if kdf_id == KDF_ARGON2D else _ArgonType.ID
    return hash_secret_raw(
        secret=composite, salt=bytes(kdf["S"]), time_cost=int(kdf["I"]),
        memory_cost=int(kdf["M"]) // 1024, parallelism=int(kdf["P"]), hash_len=32,
        type=argon_type, version=int(kdf.get("V", 0x13)),
    )


def _derive_keys(header: _Header, composite: bytes) -> tuple[bytes, bytes]:
    transformed = _transform_key(composite, header.kdf)
    master = hashlib.sha256(header.master_seed + transformed).digest()
    hmac_base = hashlib.sha512(header.master_seed + transformed + b"\x01").digest()
    return master, hmac_base


def _hmac_block_key(base: bytes, index: int) -> bytes:
    return hashlib.sha512(struct.pack("<Q", index) + base).digest()


def _block_hmac(base: bytes, index: int, data: bytes) -> bytes:
    key = _hmac_block_key(base, index)
    return hmac.new(key, struct.pack("<Q", index) + struct.pack("<i", len(data)) + data, hashlib.sha256).digest()


# --------------------------------------------------------------------------- payload codecs
def _cipher(cipher_id: bytes, key: bytes, iv: bytes) -> Cipher:
    if cipher_id == CIPHER_AES:
        return Cipher(algorithms.AES(key), modes.CBC(iv))
    return Cipher(algorithms.ChaCha20(key, b"\x00" * 4 + iv), None)


def _decrypt(cipher_id: bytes, key: bytes, iv: bytes, data: bytes) -> bytes:
    if cipher_id == CIPHER_AES:
        if not data or len(data) % 16:
            raise KdbxError("Encrypted payload is truncated")
        decryptor = _cipher(cipher_id, key, iv).decryptor()
        padded = decryptor.update(data) + decryptor.finalize()
        unpadder = padding.PKCS7(128).unpadder()
        try:
            return unpadder.update(padded) + unpadder.finalize()
        except ValueError as exc:
            raise KdbxPasswordError(t("kdbx.wrongPasswordOrCorruptedDatabase")) from exc
    decryptor = _cipher(cipher_id, key, iv).decryptor()
    return decryptor.update(data) + decryptor.finalize()


def _encrypt(cipher_id: bytes, key: bytes, iv: bytes, data: bytes) -> bytes:
    if cipher_id == CIPHER_AES:
        padder = padding.PKCS7(128).padder()
        data = padder.update(data) + padder.finalize()
    encryptor = _cipher(cipher_id, key, iv).encryptor()
    return encryptor.update(data) + encryptor.finalize()


def _read_hmac_blocks(data: bytes, pos: int, hmac_base: bytes) -> bytes:
    out = bytearray()
    index = 0
    while True:
        if pos + 36 > len(data):
            raise KdbxError("HMAC block stream is truncated")
        expected = data[pos:pos + 32]
        size = struct.unpack_from("<i", data, pos + 32)[0]
        pos += 36
        if size < 0 or pos + size > len(data):
            raise KdbxError("HMAC block stream is truncated")
        block = data[pos:pos + size]
        pos += size
        if not hmac.compare_digest(_block_hmac(hmac_base, index, block), expected):
            raise KdbxIntegrityError(t("kdbx.hmacVerificationFailedWrongPassword"))
        if size == 0:
            break
        out += block
        if len(out) > MAX_KDBX_BYTES:
            raise KdbxError("Database payload is too large")
        index += 1
    return bytes(out)


def _write_hmac_blocks(data: bytes, hmac_base: bytes) -> bytes:
    out = bytearray()
    index = 0
    for start in range(0, len(data), HMAC_BLOCK_SIZE):
        block = data[start:start + HMAC_BLOCK_SIZE]
        out += _block_hmac(hmac_base, index, block) + struct.pack("<i", len(block)) + block
        index += 1
    out += _block_hmac(hmac_base, index, b"") + struct.pack("<i", 0)
    return bytes(out)


def _read_hashed_blocks(data: bytes) -> bytes:
    out = bytearray()
    pos = 0
    expected_index = 0
    while True:
        if pos + 40 > len(data):
            raise KdbxError("Hashed block stream is truncated")
        index, digest, size = struct.unpack_from("<I32sI", data, pos)
        pos += 40
        if index != expected_index:
            raise KdbxIntegrityError("Hashed block stream index mismatch")
        if size == 0:
            if digest != b"\x00" * 32:
                raise KdbxIntegrityError("Hashed block stream terminator is corrupted")
            break
        if size > MAX_KDBX_BYTES or pos + size > len(data):
            raise KdbxError("Hashed block stream is truncated")
        block = data[pos:pos + size]
        pos += size
        if not hmac.compare_digest(hashlib.sha256(block).digest(), digest):
            raise KdbxIntegrityError("Hashed block verification failed: corrupted data")
        out += block
        expected_index += 1
    return bytes(out)


def _write_hashed_blocks(data: bytes) -> bytes:
    out = bytearray()
    index = 0
    for start in range(0, len(data), HMAC_BLOCK_SIZE):
        block = data[start:start + HMAC_BLOCK_SIZE]
        out += struct.pack("<I", index) + hashlib.sha256(block).digest() + struct.pack("<I", len(block)) + block
        index += 1
    out += struct.pack("<I", index) + b"\x00" * 32 + struct.pack("<I", 0)
    return bytes(out)


def _gunzip(data: bytes) -> bytes:
    try:
        # Read in chunks: read(MAX_XML_BYTES + 1) preallocates the whole 128 MiB for every file.
        chunks: list[bytes] = []
        total = 0
        with gzip.GzipFile(fileobj=io.BytesIO(data)) as handle:
            while total <= MAX_XML_BYTES:
                chunk = handle.read(1024 * 1024)
                if not chunk:
                    break
                chunks.append(chunk)
                total += len(chunk)
        out = b"".join(chunks)
    except (OSError, EOFError, ValueError) as exc:
        raise KdbxError("Compressed payload is corrupted") from exc
    if len(out) > MAX_XML_BYTES:
        raise KdbxError("Decompressed database is too large")
    return out


def _parse_inner_header(data: bytes) -> tuple[int, bytes, list[tuple[bool, bytes]], int]:
    pos = 0
    stream_id, stream_key = STREAM_NONE, b""
    binaries: list[tuple[bool, bytes]] = []
    while True:
        if pos + 5 > len(data):
            raise KdbxError("Inner header is truncated")
        field_id = data[pos]
        size = struct.unpack_from("<i", data, pos + 1)[0]
        pos += 5
        if size < 0 or pos + size > len(data):
            raise KdbxError("Inner header is truncated")
        value = data[pos:pos + size]
        pos += size
        if field_id == 0:
            break
        if field_id == 1:
            if len(value) != 4:
                raise KdbxError("Inner header stream id is malformed")
            stream_id = struct.unpack("<I", value)[0]
        elif field_id == 2:
            stream_key = value
        elif field_id == 3:
            if not value:
                raise KdbxError("Inner header binary is malformed")
            binaries.append((bool(value[0] & 1), value[1:]))
        else:
            raise KdbxError(f"Unsupported inner header field {field_id}")
    return stream_id, stream_key, binaries, pos


def _encode_inner_header(stream_id: int, stream_key: bytes) -> bytes:
    out = bytearray()
    out += bytes([1]) + struct.pack("<i", 4) + struct.pack("<I", stream_id)
    out += bytes([2]) + struct.pack("<i", len(stream_key)) + stream_key
    out += bytes([0]) + struct.pack("<i", 0)
    return bytes(out)


# --------------------------------------------------------------------------- data model
@dataclass
class KdbxEntry:
    uuid: str = ""
    title: str = ""
    username: str = ""
    password: str = field(default="", repr=False)
    url: str = ""
    notes: str = field(default="", repr=False)
    strings: dict[str, str] = field(default_factory=dict, repr=False)
    protected: set[str] = field(default_factory=set)
    created: int | None = None
    modified: int | None = None
    tags: list[str] = field(default_factory=list)
    icon_id: int = 0
    history: list[KdbxEntry] = field(default_factory=list, repr=False)
    binaries: list[str] = field(default_factory=list)
    group_path: tuple[str, ...] = ()


@dataclass
class KdbxGroup:
    uuid: str = ""
    name: str = ""
    notes: str = ""
    path: tuple[str, ...] = ()
    groups: list[KdbxGroup] = field(default_factory=list)
    entries: list[KdbxEntry] = field(default_factory=list)


@dataclass
class KdbxDatabase:
    version: tuple[int, int]
    cipher: str
    kdf: str
    compressed: bool
    root: KdbxGroup
    meta: dict[str, str] = field(default_factory=dict)
    recycle_bin_uuid: str = ""
    binary_count: int = 0

    def iter_groups(self) -> Iterator[KdbxGroup]:
        stack = [self.root]
        while stack:
            group = stack.pop()
            yield group
            stack.extend(reversed(group.groups))

    def iter_entries(self, *, include_recycle_bin: bool = False) -> Iterator[KdbxEntry]:
        def walk(group: KdbxGroup, in_bin: bool) -> Iterator[KdbxEntry]:
            in_bin = in_bin or (bool(self.recycle_bin_uuid) and group.uuid == self.recycle_bin_uuid)
            if in_bin and not include_recycle_bin:
                return
            yield from group.entries
            for child in group.groups:
                yield from walk(child, in_bin)
        yield from walk(self.root, False)

    def recycle_bin_entry_count(self) -> int:
        total = sum(1 for _ in self.iter_entries(include_recycle_bin=True))
        return total - sum(1 for _ in self.iter_entries())


# --------------------------------------------------------------------------- XML
def _parse_time(text: str | None) -> int | None:
    if not text:
        return None
    text = text.strip()
    if ":" in text or "-" in text[1:]:
        return parse_timestamp(text)
    try:
        raw = base64.b64decode(text, validate=True)
    except (ValueError, TypeError):
        return None
    if len(raw) != 8:
        return None
    return struct.unpack("<q", raw)[0] - _EPOCH_OFFSET


def _encode_time(value: int | None, *, v4: bool) -> str:
    stamp = int(value) if value is not None else 0
    if v4:
        return base64.b64encode(struct.pack("<q", stamp + _EPOCH_OFFSET)).decode("ascii")
    return iso_timestamp(stamp)


def _b64_uuid(value: bytes | None = None) -> str:
    return base64.b64encode(value or uuid_module.uuid4().bytes).decode("ascii")


def _parse_entry(node: ET.Element, path: tuple[str, ...]) -> KdbxEntry:
    entry = KdbxEntry(uuid=(node.findtext("UUID") or "").strip(), group_path=path)
    for string in node.findall("String"):
        key = string.findtext("Key") or ""
        value_node = string.find("Value")
        value = (value_node.text or "") if value_node is not None else ""
        if value_node is not None and (value_node.get("Protected", "").casefold() == "true"
                                       or value_node.get("ProtectInMemory", "").casefold() == "true"):
            entry.protected.add(key)
        entry.strings[key] = value
    entry.title = entry.strings.get("Title", "")
    entry.username = entry.strings.get("UserName", "")
    entry.password = entry.strings.get("Password", "")
    entry.url = entry.strings.get("URL", "")
    entry.notes = entry.strings.get("Notes", "")
    times = node.find("Times")
    if times is not None:
        entry.created = _parse_time(times.findtext("CreationTime"))
        entry.modified = _parse_time(times.findtext("LastModificationTime"))
    tags = node.findtext("Tags") or ""
    entry.tags = [tag.strip() for tag in re.split(r"[;,]", tags) if tag.strip()]
    try:
        entry.icon_id = int(node.findtext("IconID") or 0)
    except ValueError:
        entry.icon_id = 0
    entry.binaries = [binary.findtext("Key") or "" for binary in node.findall("Binary")]
    history = node.find("History")
    if history is not None:
        entry.history = [_parse_entry(child, path) for child in history.findall("Entry")]
    return entry


def _parse_group(node: ET.Element, path: tuple[str, ...], *, is_root: bool) -> KdbxGroup:
    name = (node.findtext("Name") or "").strip()
    own_path = path if is_root else path + (name,)
    group = KdbxGroup(uuid=(node.findtext("UUID") or "").strip(), name=name,
                      notes=node.findtext("Notes") or "", path=own_path)
    group.entries = [_parse_entry(child, own_path) for child in node.findall("Entry")]
    group.groups = [_parse_group(child, own_path, is_root=False) for child in node.findall("Group")]
    return group


def _unprotect_tree(root: ET.Element, stream: _KeyStream | None) -> None:
    """Decrypt protected values in document order (history included).

    A value larger than anything the vault could keep is refused before any
    keystream is generated, and so is a database whose protected values add
    up to more than :data:`MAX_PROTECTED_TOTAL_BYTES` (or
    :data:`MAX_SLOW_STREAM_TOTAL_BYTES` for the pure-Python streams).
    """
    total = 0
    budget = MAX_PROTECTED_TOTAL_BYTES
    if stream is not None and stream.stream_id in (STREAM_SALSA20, STREAM_ARC4):
        budget = MAX_SLOW_STREAM_TOTAL_BYTES
    for value in root.iter("Value"):
        if value.get("Protected", "").casefold() != "true":
            continue
        text = (value.text or "").strip()
        if not text:
            value.text = ""
            continue
        size = len(text) // 4 * 3  # decoded size bound, checked before decoding
        total += size
        if size > MAX_PROTECTED_VALUE_BYTES + 3:
            raise KdbxError("A protected value in this database is too large to import")
        if total > budget:
            raise KdbxError("The protected values in this database are too large to import")
        try:
            raw = base64.b64decode(text, validate=True)
        except (ValueError, TypeError) as exc:
            raise KdbxError("Protected value is not valid Base64") from exc
        if stream is None:
            value.text = raw.decode("utf-8", "replace")
            continue
        try:
            value.text = stream.process(raw).decode("utf-8")
        except UnicodeDecodeError as exc:
            raise KdbxIntegrityError("Protected value did not decrypt to text") from exc


class _DoctypeRejected(Exception):
    pass


def _reject_doctype(*_args: Any) -> None:
    raise _DoctypeRejected


class _BudgetExceeded(Exception):
    pass


class _ElementBudget:
    """Counts elements in the expat pre-pass so a crafted document stops early.

    Current ``Entry`` elements (outside ``History``; Recycle Bin entries
    included) are limited to :data:`MAX_RECORDS`, historical versions to
    :data:`MAX_HISTORY_ENTRIES` and all elements to :data:`MAX_XML_ELEMENTS`,
    before ElementTree builds anything.
    """

    def __init__(self) -> None:
        self.elements = 0
        self.entries = 0
        self.history_entries = 0
        self._history_depth = 0

    def start(self, name: str, _attributes: Any) -> None:
        self.elements += 1
        if self.elements > MAX_XML_ELEMENTS:
            raise _BudgetExceeded("Database XML has too many elements to import")
        if name == "History":
            self._history_depth += 1
        elif name == "Entry":
            if self._history_depth:
                self.history_entries += 1
                if self.history_entries > MAX_HISTORY_ENTRIES:
                    raise _BudgetExceeded("Database has too many historical entry versions to import")
            else:
                self.entries += 1
                if self.entries > MAX_RECORDS:
                    raise _BudgetExceeded(f"At most {MAX_RECORDS:,} records per import")

    def end(self, name: str) -> None:
        if name == "History" and self._history_depth:
            self._history_depth -= 1


def _safe_fromstring(data: bytes, *, doctype_message: str, malformed_message: str) -> ET.Element:
    """Parse untrusted XML, refusing any DOCTYPE or entity declaration.

    The check runs inside expat (a first, handler-only pass) rather than on the
    raw bytes, so it holds for every encoding expat accepts: a UTF-16 document
    hides ``<!DOCTYPE`` from a byte search but not from these handlers. KeePass
    never writes a DOCTYPE, so nothing legitimate is refused.
    """
    probe = _expat.ParserCreate()
    budget = _ElementBudget()
    probe.StartElementHandler = budget.start
    probe.EndElementHandler = budget.end
    probe.StartDoctypeDeclHandler = _reject_doctype
    probe.EntityDeclHandler = _reject_doctype
    probe.UnparsedEntityDeclHandler = _reject_doctype
    probe.NotationDeclHandler = _reject_doctype
    probe.SetParamEntityParsing(_expat.XML_PARAM_ENTITY_PARSING_NEVER)
    try:
        probe.Parse(data, True)
    except _DoctypeRejected:
        raise KdbxError(doctype_message) from None
    except _BudgetExceeded as exc:
        raise KdbxError(str(exc)) from None
    except (_expat.ExpatError, ValueError, LookupError) as exc:
        # LookupError: an XML declaration naming an unknown encoding.
        raise KdbxError(malformed_message) from exc
    try:
        return ET.fromstring(data)  # noqa: S314 - DOCTYPE/ENTITY declarations rejected by the expat pass above
    except (ET.ParseError, LookupError) as exc:
        raise KdbxError(malformed_message) from exc


def _parse_document(xml_bytes: bytes, *, allow_doctype: bool = False) -> ET.Element:
    if len(xml_bytes) > MAX_XML_BYTES:
        raise KdbxError("Database XML is too large")
    if allow_doctype:
        # Only the writer's own freshly built XML takes this path.
        try:
            root = ET.fromstring(xml_bytes)  # noqa: S314 - local writer output, not imported data
        except ET.ParseError as exc:
            raise KdbxError("Database XML is malformed") from exc
    else:
        root = _safe_fromstring(xml_bytes, doctype_message="Database XML contains a DOCTYPE declaration and was rejected",
                                malformed_message="Database XML is malformed")
    if root.tag != "KeePassFile":
        raise KdbxError("Database XML is not a KeePassFile document")
    return root


def _database_from_tree(root: ET.Element, *, version: tuple[int, int], cipher: bytes,
                        kdf: Mapping[str, Any], compressed: bool, binary_count: int = 0) -> KdbxDatabase:
    meta_node = root.find("Meta")
    meta: dict[str, str] = {}
    if meta_node is not None:
        for child in meta_node:
            if child.text and not len(child):
                meta[child.tag] = child.text.strip()
    root_group_node = root.find("Root/Group")
    if root_group_node is None:
        raise KdbxError("Database XML has no root group")
    root_group = _parse_group(root_group_node, (), is_root=True)
    return KdbxDatabase(version=version, cipher=CIPHER_NAMES.get(cipher, "unknown"),
                        kdf=KDF_NAMES.get(kdf.get("$UUID"), "unknown"), compressed=compressed,
                        root=root_group, meta=meta, recycle_bin_uuid=meta.get("RecycleBinUUID", ""),
                        binary_count=binary_count)


# --------------------------------------------------------------------------- reading
def read_kdbx(source: Path | str | bytes, password: str | None, *, keyfile: bytes | Path | str | None = None) -> KdbxDatabase:
    """Decrypt and parse a KDBX 3.1 or 4.x database."""
    data = read_source_bytes(source, limit=MAX_KDBX_BYTES)
    header = _parse_header(data)
    composite = _composite_key(password, keyfile_key(keyfile))
    master, hmac_base = _derive_keys(header, composite)
    if header.version[0] == 4:
        pos = header.end
        if pos + 64 > len(data):
            raise KdbxError("KDBX 4 header hash is truncated")
        if not hmac.compare_digest(hashlib.sha256(header.raw).digest(), data[pos:pos + 32]):
            raise KdbxIntegrityError("KDBX header hash mismatch: the file is corrupted")
        expected = hmac.new(_hmac_block_key(hmac_base, 0xFFFFFFFFFFFFFFFF), header.raw, hashlib.sha256).digest()
        if not hmac.compare_digest(expected, data[pos + 32:pos + 64]):
            raise KdbxPasswordError(t("kdbx.wrongPasswordOrKeyFile"))
        ciphertext = _read_hmac_blocks(data, pos + 64, hmac_base)
        plain = _decrypt(header.cipher, master, header.iv, ciphertext)
        if header.compress:
            plain = _gunzip(plain)
        stream_id, stream_key, binaries, offset = _parse_inner_header(plain)
        xml_bytes = plain[offset:]
        binary_count = len(binaries)
    else:
        ciphertext = data[header.end:]
        plain = _decrypt(header.cipher, master, header.iv, ciphertext)
        if len(plain) < 32 or not hmac.compare_digest(plain[:32], header.stream_start):
            raise KdbxPasswordError(t("kdbx.wrongPasswordOrKeyFile2"))
        xml_bytes = _read_hashed_blocks(plain[32:])
        if header.compress:
            xml_bytes = _gunzip(xml_bytes)
        stream_id, stream_key = header.inner_stream_id, header.inner_stream_key
        binary_count = 0
    root = _parse_document(xml_bytes)
    if header.version[0] == 3:
        expected_hash = root.findtext("Meta/HeaderHash")
        if expected_hash:
            actual = base64.b64encode(hashlib.sha256(header.raw).digest()).decode("ascii")
            if not hmac.compare_digest(actual, expected_hash.strip()):
                raise KdbxIntegrityError("KDBX header hash mismatch: the file is corrupted")
        binary_count = len(root.findall("Meta/Binaries/Binary"))
    stream = _KeyStream(stream_id, stream_key) if stream_id != STREAM_NONE else None
    _unprotect_tree(root, stream)
    return _database_from_tree(root, version=header.version, cipher=header.cipher, kdf=header.kdf,
                               compressed=header.compress, binary_count=binary_count)


def _totp_from_strings(strings: Mapping[str, str], title: str) -> tuple[str, set[str]]:
    """Return (otpauth URI, consumed keys) for the known TOTP conventions."""
    lowered = {key.casefold(): key for key in strings}
    consumed: set[str] = set()
    otp_key = lowered.get("otp")
    if otp_key and strings[otp_key].strip():
        value = strings[otp_key].strip()
        consumed.add(otp_key)
        if value.casefold().startswith("otpauth://"):
            return value, consumed
        if "key=" in value.casefold():
            params = parse_qs(value, keep_blank_values=False)
            params = {key.casefold(): values[0] for key, values in params.items() if values}
            secret = params.get("key", "")
            if secret:
                try:
                    return totp_uri_from_secret(secret, label=title, digits=int(params.get("size", 6) or 6),
                                                period=int(params.get("step", 30) or 30),
                                                algorithm=params.get("otphashmode", "SHA1")), consumed
                except ValueError:
                    pass
        return totp_uri_from_secret(value, label=title), consumed
    seed_key = lowered.get("totp seed")
    if seed_key and strings[seed_key].strip():
        consumed.add(seed_key)
        digits, period = 6, 30
        settings_key = lowered.get("totp settings")
        if settings_key:
            consumed.add(settings_key)
            parts = strings[settings_key].split(";")
            try:
                period = int(parts[0]) if parts and parts[0].strip() else 30
                digits = int(parts[1]) if len(parts) > 1 and parts[1].strip().isdigit() else 6
            except ValueError:
                digits, period = 6, 30
        return totp_uri_from_secret(strings[seed_key], label=title, digits=digits, period=period), consumed
    builtin_key = lowered.get("timeotp-secret-base32")
    if builtin_key and strings[builtin_key].strip():
        consumed.add(builtin_key)
        digits, period, algorithm = 6, 30, "SHA1"
        for name, setter in (("timeotp-length", "digits"), ("timeotp-period", "period"), ("timeotp-algorithm", "algorithm")):
            key = lowered.get(name)
            if key:
                consumed.add(key)
                value = strings[key].strip()
                if setter == "digits" and value.isdigit():
                    digits = int(value)
                elif setter == "period" and value.isdigit():
                    period = int(value)
                elif setter == "algorithm" and value:
                    algorithm = value.upper().replace("HMAC-", "").replace("-", "")
        return totp_uri_from_secret(strings[builtin_key], label=title, digits=digits, period=period, algorithm=algorithm), consumed
    for name in ("timeotp-secret", "timeotp-secret-hex"):
        key = lowered.get(name)
        if key:
            consumed.add(key)
    return "", consumed


def entry_to_record(entry: KdbxEntry, *, source_row: int | None = None) -> ImportedRecord:
    totp_uri, consumed = _totp_from_strings(entry.strings, entry.title)
    custom_fields = []
    for key, value in entry.strings.items():
        if key in _STANDARD_KEYS or key in consumed or key.casefold() in _TOTP_KEYS:
            continue
        if not value:
            continue
        custom_fields.append({"name": key, "value": value, "hidden": key in entry.protected})
    kind = "login"
    if not (entry.username or entry.password or entry.url or totp_uri) and entry.notes:
        kind = "note"
    return ImportedRecord(
        kind=kind, title=entry.title, username=entry.username, password=entry.password,
        urls=[entry.url] if entry.url else [], notes=entry.notes, totp_uri=totp_uri,
        folder="/".join(entry.group_path), custom_fields=custom_fields, created=entry.created,
        modified=entry.modified, tags=list(entry.tags), source_row=source_row,
    )


def records_from_database(database: KdbxDatabase) -> ImportResult:
    result = ImportResult("kdbx")
    history_count = 0
    binary_entries = 0
    for index, entry in enumerate(database.iter_entries(), 1):
        check_record_count(index)
        history_count += len(entry.history)
        if entry.binaries:
            binary_entries += 1
        result.records.append(entry_to_record(entry, source_row=index))
    recycled = database.recycle_bin_entry_count()
    if recycled:
        result.diagnostics.append(t("kdbx.entriesInTheKeepassRecycle", recycled=recycled))
    if history_count:
        result.diagnostics.append(t("kdbx.historicalEntryVersionsWereNot", history_count=history_count))
    if binary_entries:
        result.diagnostics.append(t("kdbx.entriesHaveAttachmentsThatWere", binary_entries=binary_entries))
    result.records = enforce_record_limit(result.records)
    return result


def load_kdbx(source: Path | str | bytes, password: str | None, *, keyfile: bytes | Path | str | None = None) -> ImportResult:
    """Read a KDBX file into normalised records."""
    return records_from_database(read_kdbx(source, password, keyfile=keyfile))


def load_keepass_xml(source: Path | str | bytes) -> ImportResult:
    """Read an unencrypted KeePass 2 XML export."""
    data = read_source_bytes(source)
    root = _parse_document(data)
    _unprotect_tree(root, None)
    database = _database_from_tree(root, version=(0, 0), cipher=b"", kdf={}, compressed=False)
    result = records_from_database(database)
    result.source_format = "keepass-xml"
    return result


# --------------------------------------------------------------------------- writing
def _xml_text(value: Any) -> str:
    return _XML_CONTROL.sub("", str(value or ""))


def _sub(parent: ET.Element, tag: str, text: str | None = None, **attrib: str) -> ET.Element:
    node = ET.SubElement(parent, tag, attrib)
    if text is not None:
        node.text = _xml_text(text)
    return node


def _add_string(entry: ET.Element, key: str, value: str, *, protected: bool | None) -> None:
    """``protected=None`` marks a sensitive value in a plaintext XML export."""
    string = ET.SubElement(entry, "String")
    _sub(string, "Key", key)
    value_node = _sub(string, "Value", value)
    if protected:
        value_node.set("Protected", "True")
    elif protected is None:
        value_node.set("ProtectInMemory", "True")


def _add_times(parent: ET.Element, created: int | None, modified: int | None, *, v4: bool) -> None:
    import time as _time
    now = int(_time.time())
    created = created if created is not None else now
    modified = modified if modified is not None else created
    times = ET.SubElement(parent, "Times")
    _sub(times, "CreationTime", _encode_time(created, v4=v4))
    _sub(times, "LastModificationTime", _encode_time(modified, v4=v4))
    _sub(times, "LastAccessTime", _encode_time(modified, v4=v4))
    _sub(times, "ExpiryTime", _encode_time(created, v4=v4))
    _sub(times, "Expires", "False")
    _sub(times, "UsageCount", "0")
    _sub(times, "LocationChanged", _encode_time(created, v4=v4))


def _record_to_xml(parent: ET.Element, record: ImportedRecord, *, protect: bool, v4: bool, include_totp: bool) -> None:
    entry = ET.SubElement(parent, "Entry")
    _sub(entry, "UUID", _b64_uuid())
    _sub(entry, "IconID", "0")
    _sub(entry, "ForegroundColor")
    _sub(entry, "BackgroundColor")
    _sub(entry, "OverrideURL")
    _sub(entry, "Tags", ";".join(_xml_text(tag) for tag in record.tags))
    _add_times(entry, record.created, record.modified, v4=v4)
    notes = record.notes
    if record.kind == "identity" and record.identity:
        extra = "\n".join(f"{key}: {value}" for key, value in record.identity.items() if value)
        notes = f"{notes}\n\n{extra}".strip() if notes else extra
    _add_string(entry, "Notes", notes, protected=False)
    _add_string(entry, "Password", record.password, protected=protect or None)
    _add_string(entry, "Title", record.title, protected=False)
    _add_string(entry, "URL", record.url, protected=False)
    _add_string(entry, "UserName", record.username, protected=False)
    if include_totp and record.totp_uri:
        _add_string(entry, "otp", record.totp_uri, protected=protect or None)
    used = {"Notes", "Password", "Title", "URL", "UserName", "otp"}
    for extra_url in record.urls[1:]:
        name = "KP2A_URL"
        counter = 1
        while name in used:
            counter += 1
            name = f"KP2A_URL_{counter}"
        used.add(name)
        _add_string(entry, name, extra_url, protected=False)
    for item in record.custom_fields:
        name = _xml_text(item.get("name", ""))[:100] or "Field"
        counter = 1
        base = name
        while name in used:
            counter += 1
            name = f"{base} ({counter})"
        used.add(name)
        hidden = bool(item.get("hidden"))
        _add_string(entry, name, str(item.get("value", "")), protected=(protect or None) if hidden else False)
    ET.SubElement(entry, "AutoType")
    ET.SubElement(entry, "History")


def _group_xml(parent: ET.Element, name: str, *, v4: bool) -> ET.Element:
    group = ET.SubElement(parent, "Group")
    _sub(group, "UUID", _b64_uuid())
    _sub(group, "Name", name)
    _sub(group, "Notes")
    _sub(group, "IconID", "48")
    _add_times(group, None, None, v4=v4)
    _sub(group, "IsExpanded", "True")
    _sub(group, "EnableAutoType", "null")
    _sub(group, "EnableSearching", "null")
    _sub(group, "LastTopVisibleEntry", "AAAAAAAAAAAAAAAAAAAAAA==")
    return group


def build_keepass_xml(records: Iterable[ImportedRecord], *, protect: bool = True, version: int = 4,
                      database_name: str = "LocalGateKeys", include_totp: bool = True,
                      header_hash: str | None = None) -> str:
    """Build a KeePass 2 XML document for ``records``.

    With ``protect=True`` the password/otp/hidden-field values carry
    ``Protected="True"`` but still hold plaintext; :func:`write_kdbx`
    encrypts them with the inner stream while serialising the database.
    """
    v4 = version == 4
    root = ET.Element("KeePassFile")
    meta = ET.SubElement(root, "Meta")
    _sub(meta, "Generator", "LocalGateKeys")
    if header_hash is not None:
        _sub(meta, "HeaderHash", header_hash)
    _sub(meta, "DatabaseName", database_name)
    _sub(meta, "DatabaseNameChanged", _encode_time(None, v4=v4))
    _sub(meta, "DatabaseDescription")
    _sub(meta, "DefaultUserName")
    _sub(meta, "MaintenanceHistoryDays", "365")
    _sub(meta, "Color")
    _sub(meta, "MasterKeyChanged", _encode_time(None, v4=v4))
    _sub(meta, "MasterKeyChangeRec", "-1")
    _sub(meta, "MasterKeyChangeForce", "-1")
    protection = ET.SubElement(meta, "MemoryProtection")
    for key, flag in (("ProtectTitle", "False"), ("ProtectUserName", "False"), ("ProtectPassword", "True"),
                      ("ProtectURL", "False"), ("ProtectNotes", "False")):
        _sub(protection, key, flag)
    _sub(meta, "RecycleBinEnabled", "False")
    _sub(meta, "RecycleBinUUID", "AAAAAAAAAAAAAAAAAAAAAA==")
    _sub(meta, "RecycleBinChanged", _encode_time(None, v4=v4))
    _sub(meta, "EntryTemplatesGroup", "AAAAAAAAAAAAAAAAAAAAAA==")
    _sub(meta, "HistoryMaxItems", "10")
    _sub(meta, "HistoryMaxSize", "6291456")
    if not v4:
        ET.SubElement(meta, "Binaries")
    ET.SubElement(meta, "CustomData")
    root_node = ET.SubElement(root, "Root")
    root_group = _group_xml(root_node, database_name, v4=v4)
    groups: dict[tuple[str, ...], ET.Element] = {(): root_group}

    def group_for(path: tuple[str, ...]) -> ET.Element:
        if path in groups:
            return groups[path]
        parent = group_for(path[:-1])
        node = _group_xml(parent, path[-1], v4=v4)
        groups[path] = node
        return node

    for record in records:
        parts = tuple(part.strip() for part in record.folder.replace("\\", "/").split("/") if part.strip())
        _record_to_xml(group_for(parts), record, protect=protect, v4=v4, include_totp=include_totp)
    ET.SubElement(root_node, "DeletedObjects")
    return ET.tostring(root, encoding="unicode", xml_declaration=False)


def _protect_tree(root: ET.Element, stream: _KeyStream) -> None:
    for value in root.iter("Value"):
        if value.get("Protected", "").casefold() != "true":
            continue
        text = value.text or ""
        value.text = base64.b64encode(stream.process(text.encode("utf-8"))).decode("ascii") if text else ""


def _default_kdf(kdf: str, params: Mapping[str, Any] | None) -> dict[str, Any]:
    params = dict(params or {})
    kdf_id = KDF_IDS.get(kdf.casefold())
    if kdf_id is None:
        raise KdbxError(f"Unknown KDF {kdf!r}")
    if kdf_id == KDF_AES:
        return {"$UUID": KDF_AES, "R": int(params.get("rounds", 600_000)), "S": os.urandom(32)}
    return {
        "$UUID": kdf_id, "S": os.urandom(32), "P": int(params.get("parallelism", 2)),
        "M": int(params.get("memory", 64 * 1024 * 1024)), "I": int(params.get("iterations", 3)), "V": 0x13,
    }


def write_kdbx(records: Iterable[ImportedRecord], password: str | None, *, version: int = 4,
               cipher: str = "aes256", kdf: str | None = None, compress: bool = True,
               kdf_params: Mapping[str, Any] | None = None, keyfile: bytes | Path | str | None = None,
               database_name: str = "LocalGateKeys", include_totp: bool = True, xml: str | bytes | None = None) -> bytes:
    """Serialise ``records`` into an encrypted KDBX 4.0 (default) or 3.1 file.

    ``xml`` lets callers supply a complete KeePass XML document (as produced
    by :func:`build_keepass_xml`, protected values in plaintext) instead of
    records.
    """
    if version not in (3, 4):
        raise KdbxError("Only KDBX versions 3 and 4 can be written")
    kdf = kdf or ("argon2d" if version == 4 else "aes-kdf")
    kdf_dict = _default_kdf(kdf, kdf_params)
    if version == 3 and kdf_dict["$UUID"] != KDF_AES:
        raise KdbxError("KDBX 3 supports only AES-KDF")
    cipher_id = CIPHER_IDS.get(cipher.casefold())
    if cipher_id is None or (version == 3 and cipher_id != CIPHER_AES):
        raise KdbxError(f"Unsupported cipher {cipher!r} for KDBX {version}")
    _check_kdf_limits(kdf_dict)
    composite = _composite_key(password, keyfile_key(keyfile))
    master_seed = os.urandom(32)
    iv = os.urandom(16 if cipher_id == CIPHER_AES else 12)
    raw_xml: bytes | None = None
    if isinstance(xml, (bytes, bytearray)):
        # Verbatim payload (test fixtures): no protection pass, no header hash.
        raw_xml = bytes(xml)
        root = ET.Element("KeePassFile")
    else:
        if xml is None:
            xml = build_keepass_xml(records, protect=True, version=version, database_name=database_name, include_totp=include_totp)
        # The writer's own XML is local, trusted input; the reader stays strict.
        root = _parse_document(xml.encode("utf-8"), allow_doctype=True)

    if version == 4:
        header = _encode_header_v4(cipher=cipher_id, compress=compress, master_seed=master_seed, iv=iv, kdf=kdf_dict)
        stream_key = os.urandom(64)
        stream = _KeyStream(STREAM_CHACHA20, stream_key)
        _protect_tree(root, stream)
        xml_bytes = raw_xml if raw_xml is not None else ET.tostring(root, encoding="utf-8", xml_declaration=True)
        body = _encode_inner_header(STREAM_CHACHA20, stream_key) + xml_bytes
        if compress:
            body = gzip.compress(body, mtime=0)
        transformed = _transform_key(composite, kdf_dict)
        master = hashlib.sha256(master_seed + transformed).digest()
        hmac_base = hashlib.sha512(master_seed + transformed + b"\x01").digest()
        ciphertext = _encrypt(cipher_id, master, iv, body)
        header_hmac = hmac.new(_hmac_block_key(hmac_base, 0xFFFFFFFFFFFFFFFF), header, hashlib.sha256).digest()
        return header + hashlib.sha256(header).digest() + header_hmac + _write_hmac_blocks(ciphertext, hmac_base)

    stream_key = os.urandom(32)
    stream_start = os.urandom(32)
    header = _encode_header_v3(compress=compress, master_seed=master_seed, transform_seed=kdf_dict["S"],
                               rounds=kdf_dict["R"], iv=iv, stream_key=stream_key, stream_start=stream_start,
                               stream_id=STREAM_SALSA20)
    meta = root.find("Meta")
    if meta is None:
        meta = ET.Element("Meta")
        root.insert(0, meta)
    hash_node = meta.find("HeaderHash")
    if hash_node is None:
        hash_node = ET.Element("HeaderHash")
        meta.insert(1 if len(meta) else 0, hash_node)
    hash_node.text = base64.b64encode(hashlib.sha256(header).digest()).decode("ascii")
    _protect_tree(root, _KeyStream(STREAM_SALSA20, stream_key))
    xml_bytes = raw_xml if raw_xml is not None else ET.tostring(root, encoding="utf-8", xml_declaration=True)
    if compress:
        xml_bytes = gzip.compress(xml_bytes, mtime=0)
    transformed = _transform_key(composite, kdf_dict)
    master = hashlib.sha256(master_seed + transformed).digest()
    return header + _encrypt(CIPHER_AES, master, iv, stream_start + _write_hashed_blocks(xml_bytes))


__all__ = [
    "KdbxDatabase", "KdbxEntry", "KdbxError", "KdbxGroup", "KdbxIntegrityError", "KdbxPasswordError",
    "build_keepass_xml", "entry_to_record", "keyfile_key", "load_kdbx", "load_keepass_xml", "read_kdbx",
    "records_from_database", "write_kdbx",
]
