"""KeePass key files: the 32-byte key a key file contributes (docs/formats/COMPOSITE_KEY_V1.md).

Used by the KDBX importer and, as an unlock factor, by the composite key.  The rules are
KeePass's, checked in this order:

1. XML (the file, trimmed of ASCII space/tab/CR/LF, starts with ``<?xml`` or ``<KeyFile``): ``Meta/Version``
   starting with "2" means hex data with an optional ``Hash`` check, anything else Base64 data;
2. exactly 32 bytes: the file itself;
3. exactly 64 bytes, all hex digits: the decoded hex;
4. anything else: SHA-256 of the whole file.
"""

from __future__ import annotations

import base64
import hashlib
import os
import re

KEY_SIZE = 32
_HEX64 = re.compile(rb"[0-9A-Fa-f]{64}")
#: The only whitespace trimmed from the file and removed from XML key data (not VT, FF or Unicode).
_ASCII_WHITESPACE = " \t\n\r"


class KeyFileError(ValueError):
    """The key file looks like a KeePass XML key file but is not a valid one."""


def key_material(data: bytes) -> bytes:
    """The key material under KeePass rules; XML data may have any length (the KDBX importer's view)."""
    text = data.strip(_ASCII_WHITESPACE.encode("ascii"))
    if text.startswith(b"<?xml") or text.startswith(b"<KeyFile"):
        return _xml_key(text)
    if len(data) == KEY_SIZE:
        return bytes(data)
    if len(data) == 2 * KEY_SIZE and _HEX64.fullmatch(data):
        return bytes.fromhex(data.decode("ascii"))
    return hashlib.sha256(data).digest()


def key_from_bytes(data: bytes) -> bytes:
    """The 32-byte key of a key file used as an unlock factor; XML data of another length is refused."""
    key = key_material(data)
    if len(key) != KEY_SIZE:
        raise KeyFileError("Key file data must be 32 bytes")
    return key


def keepass_xml_v2(key: bytes) -> bytes:
    """A KeePass XML 2.0 key file for ``key`` in the layout KeePass and KeePassXC write."""
    if len(key) != KEY_SIZE:
        raise ValueError("key must be 32 bytes")
    hex_key = key.hex().upper()
    groups = [hex_key[i:i + 8] for i in range(0, len(hex_key), 8)]
    lines = "".join(f"\n            {' '.join(groups[i:i + 4])}" for i in range(0, len(groups), 4))
    checksum = hashlib.sha256(key).digest()[:4].hex().upper()
    return (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        "<KeyFile>\n"
        "    <Meta>\n"
        "        <Version>2.0</Version>\n"
        "    </Meta>\n"
        "    <Key>\n"
        f'        <Data Hash="{checksum}">{lines}\n'
        "        </Data>\n"
        "    </Key>\n"
        "</KeyFile>\n"
    ).encode("ascii")


def new_keepass_xml_v2() -> bytes:
    """A new random KeePass XML 2.0 key file ("Create key file"); it also opens in KeePassXC."""
    return keepass_xml_v2(os.urandom(KEY_SIZE))


def _xml_key(text: bytes) -> bytes:
    # The importer's hardened parser (DOCTYPE/entity refusal, element budget); imported lazily
    # because the importer imports this module.
    from .importers.kdbx import KdbxError, _safe_fromstring  # noqa: PLC0415

    try:
        root = _safe_fromstring(text, doctype_message="Key file contains a DOCTYPE and was rejected",
                                malformed_message="Key file XML is malformed")
    except KdbxError as exc:
        raise KeyFileError(str(exc)) from None
    version = (root.findtext("Meta/Version") or "1.0").strip(_ASCII_WHITESPACE)
    node = root.find("Key/Data")
    payload = (node.text or "") if node is not None else ""
    payload = payload.translate({ord(char): None for char in _ASCII_WHITESPACE})
    if not payload:
        raise KeyFileError("Key file XML has no key data")
    if version.startswith("2"):
        try:
            key = bytes.fromhex(payload)
        except ValueError as exc:
            raise KeyFileError("Key file 2.0 data must be hexadecimal") from exc
        expected = node.get("Hash")
        if expected and hashlib.sha256(key).hexdigest()[:len(expected)].casefold() != expected.casefold():
            raise KeyFileError("Key file hash does not match its data")
        return key
    try:
        return base64.b64decode(payload, validate=True)
    except (ValueError, TypeError) as exc:
        raise KeyFileError("Key file 1.0 data must be Base64") from exc
