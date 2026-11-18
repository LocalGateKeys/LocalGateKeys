"""Credential Exchange Format (CXF v1.0) account exports.

Maps one CXF ``Account`` object (the JSON Apple Passwords and other
providers write) to :class:`ImportedRecord` values, following the same
mapping as the iOS and macOS apps:

* ``basic-auth`` -> login (``scope.urls``, username, password);
* ``totp`` -> the login of the same item as an ``otpauth://`` URI, or a
  login holding only the code when the item has no ``basic-auth``;
* ``note`` -> the login's notes, or a secure note when there is no login;
* ``passkey`` -> a ``passkey`` record whose ``custom_fields`` carry the
  vault passkey payload keys (``import_workflow`` validates them);
* any other credential type is skipped and named, never dropped silently.

Unknown fields inside known types are ignored.  The file is untrusted: size
is capped and any malformed value is skipped rather than raised.
"""
from __future__ import annotations

import base64
import binascii
import datetime as _dt
import json
import re
from pathlib import Path
from typing import Any

from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa

from . import (
    MAX_JSON_BYTES,
    MAX_RECORDS,
    ImportedRecord,
    ImportFormatError,
    ImportResult,
    totp_uri_from_secret,
)
from ._source import read_source_bytes
from ..i18n import t

SOURCE_FORMAT = "cxf"
PASSKEY_KEYS = ("relying_party_id", "user_handle", "credential_id", "private_key", "algorithm", "user_name",
                "user_display_name", "created")
_MAX_CREDENTIAL_ID = 1023
_MAX_USER_HANDLE = 64
_MAX_KEY_BYTES = 4096
_MAX_TEXT = 4096
_LONE_SURROGATE = re.compile("[" + chr(0xD800) + "-" + chr(0xDFFF) + "]")
_CURVES = {"secp256r1": "ES256", "secp384r1": "ES384", "secp521r1": "ES512"}


def _mend(value: str) -> str:
    """A lone surrogate (a broken Unicode escape) becomes U+FFFD, as the Android and Apple JSON readers do.

    Such a value cannot be encoded or stored, so leaving it would refuse the whole file.
    """
    return _LONE_SURROGATE.sub(chr(0xFFFD), value)


def _text(value: Any, limit: int = _MAX_TEXT) -> str:
    """An EditableField (``{"value": ...}``) or a bare string; anything else is empty."""
    if isinstance(value, dict):
        value = value.get("value")
    return _mend(value[:limit]) if isinstance(value, str) else ""


def _b64(value: Any, max_bytes: int) -> bytes | None:
    """Decode base64url or standard base64, padded or not; ``None`` when invalid or too long."""
    if not isinstance(value, str) or len(value) > (max_bytes * 4) // 3 + 4:
        return None
    text = value.strip().replace("+", "-").replace("/", "_").rstrip("=")
    try:
        data = base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))
    except (binascii.Error, ValueError):
        return None
    return data if len(data) <= max_bytes else None


def _b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def _int(value: Any, default: int, low: int, high: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not low <= value <= high:
        return default
    return value


def _otpauth(credential: dict[str, Any], fallback_username: str) -> str:
    secret = _text(credential.get("secret"), 1024)
    if not secret:
        return ""
    algorithm = credential.get("algorithm")
    algorithm = algorithm.upper() if isinstance(algorithm, str) and algorithm.upper() in {"SHA1", "SHA256", "SHA512"} else "SHA1"
    issuer = _text(credential.get("issuer"), 256)
    username = _text(credential.get("username"), 256) or fallback_username
    label = f"{issuer}:{username}" if issuer and username else (username or issuer)
    return totp_uri_from_secret(secret, label=label, issuer=issuer,
                                digits=_int(credential.get("digits"), 6, 6, 8),
                                period=_int(credential.get("period"), 30, 1, 86400), algorithm=algorithm)


def _algorithm(der: bytes) -> str | None:
    try:
        key = serialization.load_der_private_key(der, password=None)
    except (ValueError, TypeError, UnsupportedAlgorithm):
        return None
    if isinstance(key, ec.EllipticCurvePrivateKey):
        return _CURVES.get(key.curve.name)
    if isinstance(key, ed25519.Ed25519PrivateKey):
        return "EdDSA"
    if isinstance(key, rsa.RSAPrivateKey):
        return "RS256"
    return None


def _created(item: dict[str, Any]) -> str:
    stamp = item.get("creationAt")
    if isinstance(stamp, bool) or not isinstance(stamp, int) or not 0 < stamp < 253402300800:
        return ""
    return _dt.datetime.fromtimestamp(stamp, _dt.timezone.utc).date().isoformat()


def _passkey(credential: dict[str, Any], title: str, urls: list[str], item: dict[str, Any]) -> ImportedRecord | None:
    credential_id = _b64(credential.get("credentialId"), _MAX_CREDENTIAL_ID)
    rp_id = _text(credential.get("rpId"), 253).strip().casefold()
    der = _b64(credential.get("key"), _MAX_KEY_BYTES)
    if not credential_id or not rp_id or not der:
        return None
    algorithm = _algorithm(der)
    if algorithm is None:
        return None
    handle = credential.get("userHandle")
    user_handle = b""
    if handle not in (None, ""):
        decoded = _b64(handle, _MAX_USER_HANDLE)
        if decoded is None:
            return None
        user_handle = decoded
    user_name = _text(credential.get("username"), 256) or _text(credential.get("userName"), 256)
    payload = {
        "relying_party_id": rp_id, "user_handle": _b64u(user_handle), "credential_id": _b64u(credential_id),
        "private_key": _b64u(der), "algorithm": algorithm, "user_name": user_name,
        "user_display_name": _text(credential.get("userDisplayName"), 256), "created": _created(item),
    }
    return ImportedRecord(
        kind="passkey", title=title or rp_id, username=user_name, urls=urls or [f"https://{rp_id}"],
        custom_fields=[{"name": key, "value": payload[key], "hidden": key == "private_key"}
                       for key in PASSKEY_KEYS if payload[key]],
    )


def _map_item(item: dict[str, Any], skipped: list[str]) -> list[ImportedRecord]:
    title = _text(item.get("title"), 512)
    scope = item.get("scope")
    raw_urls = scope.get("urls") if isinstance(scope, dict) else None
    urls = [_mend(url) for url in raw_urls if isinstance(url, str) and url][:50] if isinstance(raw_urls, list) else []
    credentials = item.get("credentials")
    if not isinstance(credentials, list):
        return []
    logins: list[dict[str, Any]] = []
    totps: list[dict[str, Any]] = []
    notes: list[str] = []
    has_note = False
    out: list[ImportedRecord] = []
    for credential in credentials:
        if not isinstance(credential, dict) or not isinstance(credential.get("type"), str):
            skipped.append("unknown")
            continue
        kind = _mend(credential["type"])
        if kind == "basic-auth":
            if logins:
                skipped.append(kind)  # one login per item, as on iOS and macOS
            else:
                logins.append(credential)
        elif kind == "totp":
            totps.append(credential)
        elif kind == "note":
            has_note = True
            text = _text(credential.get("content"), 64 * 1024)
            if text:
                notes.append(text)
        elif kind == "passkey":
            record = _passkey(credential, title, urls, item)
            if record is None:
                skipped.append("passkey")
            else:
                out.append(record)
        else:
            skipped.append(kind[:64] or "unknown")
    note_text = "\n\n".join(notes)
    created = _created(item)
    for index, credential in enumerate(logins or ([{}] if totps else [])):
        username = _text(credential.get("username"), 512)
        totp = _otpauth(totps[index], username) if index < len(totps) else ""
        record = ImportedRecord(kind="login", title=title, username=username,
                                password=_text(credential.get("password")), urls=urls,
                                notes=note_text if index == 0 else "", totp_uri=totp)
        if created:
            record.created = int(item["creationAt"])
        out.append(record)
    for extra in totps[max(len(logins), 1):]:
        out.append(ImportedRecord(kind="login", title=title, urls=urls, totp_uri=_otpauth(extra, "")))
    # A note-only item is a secure note even when its body is empty (a title-only note).
    if (note_text or (has_note and not out)) and not logins and not totps:
        out.insert(0, ImportedRecord(kind="note", title=title, notes=note_text))
    return out


def parse_cxf(data: bytes) -> tuple[list[ImportedRecord], list[str]]:
    """Parse a CXF account document; returns ``(records, skipped credential type names)``."""
    data = read_source_bytes(data, limit=MAX_JSON_BYTES)
    try:
        document = json.loads(data.decode("utf-8-sig"))
    except (ValueError, RecursionError, UnicodeError) as exc:
        raise ImportFormatError(t("cxf.notACxfExport")) from exc
    if not isinstance(document, dict) or not isinstance(document.get("items"), list):
        raise ImportFormatError(t("cxf.notACxfExport"))
    records: list[ImportedRecord] = []
    skipped: list[str] = []
    for item in document["items"]:
        if not isinstance(item, dict):
            continue
        records.extend(_map_item(item, skipped))
        if len(records) > MAX_RECORDS:
            raise ImportFormatError(t("cxf.tooManyItems", limit=MAX_RECORDS))
    return records, skipped


def import_cxf(path: Path | str | bytes) -> ImportResult:
    """Load a CXF file (path or bytes) into an :class:`ImportResult`."""
    records, skipped = parse_cxf(read_source_bytes(path, limit=MAX_JSON_BYTES))
    diagnostics: list[str] = []
    if skipped:
        counts: dict[str, int] = {}
        for name in skipped:
            counts[name] = counts.get(name, 0) + 1
        names = ", ".join(f"{name} ({count})" for name, count in sorted(counts.items()))
        diagnostics.append(t("cxf.skippedTypes", count=len(skipped), types=names))
    return ImportResult(SOURCE_FORMAT, records, diagnostics)


load_cxf = import_cxf

__all__ = ["PASSKEY_KEYS", "import_cxf", "load_cxf", "parse_cxf"]
