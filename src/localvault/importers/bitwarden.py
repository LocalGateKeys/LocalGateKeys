"""Bitwarden JSON (plain and password-protected) and CSV importers.

The password-protected export format is Bitwarden's ``2.`` EncString:
AES-256-CBC with HMAC-SHA256, keys stretched from PBKDF2-SHA256 (or
Argon2id) via HKDF-Expand with the ``enc``/``mac`` info strings.  An
``encrypt_bitwarden_export`` helper exists so the application can write the
same format and so tests can build fixtures with identical primitives.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import uuid
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from argon2.low_level import Type as _ArgonType
from argon2.low_level import hash_secret_raw
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from ..i18n import t

from . import (
    ImportedRecord,
    ImportFormatError,
    ImportPasswordError,
    ImportPasswordRequired,
    ImportResult,
    add_custom_field,
    card_expiry,
    check_record_count,
    enforce_record_limit,
    totp_uri_from_secret,
)
from ._source import (
    as_list,
    decode_text,
    parse_timestamp,
    pick,
    read_csv_table,
    read_source_bytes,
    truthy,
)

# KDF ceilings match what Bitwarden itself accepts for an account/export
# (PBKDF2-SHA256 up to 2,000,000 iterations; Argon2id up to 10 iterations,
# 1024 MiB and 16 lanes), so every genuine export imports while a hostile
# file cannot pin the importer for minutes (worst case is a few seconds).
MAX_PBKDF2_ITERATIONS = 2_000_000
MAX_ARGON2_MEMORY_MIB = 1024
MAX_ARGON2_ITERATIONS = 10
MAX_ARGON2_PARALLELISM = 16
TYPE_LOGIN, TYPE_NOTE, TYPE_CARD, TYPE_IDENTITY, TYPE_SSH_KEY = 1, 2, 3, 4, 5

ACCOUNT_RESTRICTED_MESSAGE = (
    "bitwarden.thisBitwardenExportIsEncrypted")

_IDENTITY_MAP = {
    "firstName": "given_name", "middleName": "middle_name", "lastName": "family_name", "company": "company",
    "email": "email", "phone": "phone", "address1": "address_line1", "address2": "address_line2", "city": "city",
    "state": "state", "postalCode": "postal_code", "country": "country",
}
_IDENTITY_SENSITIVE = {"ssn": "SSN", "passportNumber": "Passport number", "licenseNumber": "Licence number"}
_IDENTITY_EXTRA = {"title": "Title", "username": "Username", "address3": "Address 3"}


class BitwardenError(ImportFormatError):
    """The document is not a readable Bitwarden export."""


class BitwardenPasswordError(BitwardenError, ImportPasswordError):
    """Wrong password for a password-protected export."""


# --------------------------------------------------------------------------- crypto
def _hkdf_expand(key: bytes, info: bytes, length: int = 32) -> bytes:
    out = b""
    block = b""
    counter = 1
    while len(out) < length:
        block = hmac.new(key, block + info + bytes([counter]), hashlib.sha256).digest()
        out += block
        counter += 1
    return out[:length]


def derive_export_keys(password: str, document: Mapping[str, Any]) -> tuple[bytes, bytes]:
    """Return (encryption key, MAC key) for a password-protected export."""
    salt = document.get("salt")
    if not isinstance(salt, str) or not salt:
        raise BitwardenError(t("bitwarden.encryptedExportIsMissingIts"))
    kdf_type = document.get("kdfType", 0)
    try:
        iterations = int(document.get("kdfIterations") or 0)
    except (TypeError, ValueError) as exc:
        raise BitwardenError(t("bitwarden.encryptedExportKdfParametersAre")) from exc
    if kdf_type == 0:
        if not 1 <= iterations <= MAX_PBKDF2_ITERATIONS:
            raise BitwardenError(t("bitwarden.encryptedExportIterationCountIs"))
        master = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt.encode("utf-8"), iterations, 32)
    elif kdf_type == 1:
        try:
            memory = int(document.get("kdfMemory") or 64)
            parallelism = int(document.get("kdfParallelism") or 4)
        except (TypeError, ValueError) as exc:
            raise BitwardenError(t("bitwarden.encryptedExportKdfParametersAre")) from exc
        if not 1 <= iterations <= MAX_ARGON2_ITERATIONS or not 8 <= memory <= MAX_ARGON2_MEMORY_MIB or not 1 <= parallelism <= MAX_ARGON2_PARALLELISM:
            raise BitwardenError(t("bitwarden.encryptedExportArgon2ParametersAre"))
        master = hash_secret_raw(password.encode("utf-8"), hashlib.sha256(salt.encode("utf-8")).digest(),
                                 time_cost=iterations, memory_cost=memory * 1024, parallelism=parallelism,
                                 hash_len=32, type=_ArgonType.ID)
    else:
        raise BitwardenError(t("bitwarden.unsupportedBitwardenKdfType"))
    return _hkdf_expand(master, b"enc"), _hkdf_expand(master, b"mac")


def _split_enc_string(value: Any) -> tuple[bytes, bytes, bytes]:
    if not isinstance(value, str) or not value.startswith("2."):
        raise BitwardenError(t("bitwarden.unsupportedBitwardenEncryptionStringType"))
    parts = value[2:].split("|")
    if len(parts) != 3:
        raise BitwardenError(t("bitwarden.bitwardenEncryptionStringIsMalformed"))
    try:
        iv, ciphertext, mac = (base64.b64decode(part, validate=True) for part in parts)
    except (ValueError, TypeError) as exc:
        raise BitwardenError(t("bitwarden.bitwardenEncryptionStringIsNot")) from exc
    if len(iv) != 16 or len(mac) != 32 or not ciphertext or len(ciphertext) % 16:
        raise BitwardenError(t("bitwarden.bitwardenEncryptionStringHasUnexpected"))
    return iv, ciphertext, mac


def decrypt_enc_string(value: Any, enc_key: bytes, mac_key: bytes) -> bytes:
    iv, ciphertext, mac = _split_enc_string(value)
    expected = hmac.new(mac_key, iv + ciphertext, hashlib.sha256).digest()
    if not hmac.compare_digest(expected, mac):
        raise BitwardenPasswordError(t("bitwarden.wrongPasswordOrCorruptedExport"))
    decryptor = Cipher(algorithms.AES(enc_key), modes.CBC(iv)).decryptor()
    padded = decryptor.update(ciphertext) + decryptor.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    try:
        return unpadder.update(padded) + unpadder.finalize()
    except ValueError as exc:
        raise BitwardenError(t("bitwarden.encryptedExportPaddingIsInvalid")) from exc


def encrypt_enc_string(plaintext: bytes, enc_key: bytes, mac_key: bytes) -> str:
    iv = os.urandom(16)
    padder = padding.PKCS7(128).padder()
    data = padder.update(plaintext) + padder.finalize()
    encryptor = Cipher(algorithms.AES(enc_key), modes.CBC(iv)).encryptor()
    ciphertext = encryptor.update(data) + encryptor.finalize()
    mac = hmac.new(mac_key, iv + ciphertext, hashlib.sha256).digest()
    return "2." + "|".join(base64.b64encode(part).decode("ascii") for part in (iv, ciphertext, mac))


def encrypt_bitwarden_export(plain: Mapping[str, Any], password: str, *, kdf: str = "pbkdf2",
                             iterations: int | None = None, memory: int = 64, parallelism: int = 4) -> dict[str, Any]:
    """Wrap an unencrypted export document in Bitwarden's password-protected envelope."""
    if not password:
        raise BitwardenError(t("bitwarden.aPasswordIsRequiredFor"))
    document: dict[str, Any] = {
        "encrypted": True, "passwordProtected": True,
        "salt": base64.b64encode(os.urandom(16)).decode("ascii"),
    }
    if kdf == "pbkdf2":
        document.update({"kdfType": 0, "kdfIterations": int(iterations or 600_000)})
    elif kdf == "argon2id":
        document.update({"kdfType": 1, "kdfIterations": int(iterations or 3), "kdfMemory": int(memory), "kdfParallelism": int(parallelism)})
    else:
        raise BitwardenError("kdf must be 'pbkdf2' or 'argon2id'")
    enc_key, mac_key = derive_export_keys(password, document)
    document["encKeyValidation_DO_NOT_EDIT"] = encrypt_enc_string(str(uuid.uuid4()).encode("utf-8"), enc_key, mac_key)
    payload = dict(plain)
    payload["encrypted"] = False
    document["data"] = encrypt_enc_string(json.dumps(payload, ensure_ascii=False).encode("utf-8"), enc_key, mac_key)
    return document


def decrypt_bitwarden_export(document: Mapping[str, Any], password: str | None) -> dict[str, Any]:
    if not document.get("passwordProtected"):
        raise BitwardenError(t(ACCOUNT_RESTRICTED_MESSAGE))
    if not password:
        raise ImportPasswordRequired(t("bitwarden.thisBitwardenExportIsPassword"))
    enc_key, mac_key = derive_export_keys(password, document)
    if "encKeyValidation_DO_NOT_EDIT" in document:
        decrypt_enc_string(document["encKeyValidation_DO_NOT_EDIT"], enc_key, mac_key)
    raw = decrypt_enc_string(document.get("data"), enc_key, mac_key)
    try:
        inner = json.loads(raw.decode("utf-8"))
    except (ValueError, UnicodeDecodeError, RecursionError) as exc:
        raise BitwardenError(t("bitwarden.decryptedExportIsNotValid")) from exc
    if not isinstance(inner, dict):
        raise BitwardenError(t("bitwarden.decryptedExportIsNotA"))
    return inner


# --------------------------------------------------------------------------- mapping
def _folder_names(document: Mapping[str, Any]) -> dict[str, str]:
    names: dict[str, str] = {}
    for key in ("folders", "collections"):
        for folder in as_list(document.get(key)):
            if isinstance(folder, dict) and folder.get("id") is not None:
                names[str(folder["id"])] = str(folder.get("name") or "")
    return names


def _custom_fields(item: Mapping[str, Any], record: ImportedRecord) -> None:
    for field in as_list(item.get("fields")):
        if not isinstance(field, dict):
            continue
        name = str(field.get("name") or "")
        value = field.get("value")
        kind = field.get("type", 0)
        if kind == 3 or value is None:
            continue
        if kind == 2:
            value = "true" if str(value).casefold() == "true" else "false"
        add_custom_field(record, name, value, hidden=kind == 1)


def item_to_record(item: Mapping[str, Any], folders: Mapping[str, str], *, source_row: int | None = None) -> ImportedRecord | None:
    item_type = item.get("type")
    name = str(item.get("name") or "")
    folder_id = item.get("folderId")
    folder = folders.get(str(folder_id), "") if folder_id else ""
    if not folder:
        for collection_id in as_list(item.get("collectionIds")):
            folder = folders.get(str(collection_id), "")
            if folder:
                break
    base = {
        "title": name, "notes": str(item.get("notes") or ""), "folder": folder, "favorite": bool(item.get("favorite")),
        "created": parse_timestamp(item.get("creationDate")), "modified": parse_timestamp(item.get("revisionDate")),
        "source_row": source_row,
    }
    if item_type == TYPE_LOGIN:
        login = item.get("login") if isinstance(item.get("login"), dict) else {}
        uris = [str(uri.get("uri")) for uri in as_list(login.get("uris")) if isinstance(uri, dict) and uri.get("uri")]
        record = ImportedRecord(kind="login", username=str(login.get("username") or ""),
                                password=str(login.get("password") or ""), urls=uris,
                                totp_uri=totp_uri_from_secret(str(login.get("totp") or ""), label=name), **base)
    elif item_type == TYPE_NOTE:
        record = ImportedRecord(kind="note", **base)
    elif item_type == TYPE_CARD:
        card = item.get("card") if isinstance(item.get("card"), dict) else {}
        values = {"cardholder": _text(card.get("cardholderName")), "number": _text(card.get("number")),
                  "cvv": _text(card.get("code")), "brand": _text(card.get("brand"))}
        record = ImportedRecord(kind="card", card=values, **base)
        expiry = card_expiry(_text(card.get("expMonth")), _text(card.get("expYear")))
        if expiry:
            record.card["expiry"] = expiry
        else:
            raw = "/".join(_text(card.get(key)) for key in ("expMonth", "expYear") if card.get(key))
            add_custom_field(record, "Expiry", raw)
    elif item_type == TYPE_IDENTITY:
        identity = item.get("identity") if isinstance(item.get("identity"), dict) else {}
        values = {target: str(identity[key]) for key, target in _IDENTITY_MAP.items() if identity.get(key)}
        full_name = " ".join(str(identity.get(key)) for key in ("firstName", "middleName", "lastName") if identity.get(key))
        if full_name:
            values["name"] = full_name
        record = ImportedRecord(kind="identity", identity=values, **base)
        for key, label in {**_IDENTITY_EXTRA}.items():
            add_custom_field(record, label, identity.get(key))
        for key, label in _IDENTITY_SENSITIVE.items():
            add_custom_field(record, label, identity.get(key), hidden=True)
    elif item_type == TYPE_SSH_KEY:
        key = item.get("sshKey") if isinstance(item.get("sshKey"), dict) else {}
        record = ImportedRecord(kind="note", **base)
        add_custom_field(record, "Bitwarden item type", "SSH key")
        add_custom_field(record, "Private key", key.get("privateKey"), hidden=True)
        add_custom_field(record, "Public key", key.get("publicKey"))
        add_custom_field(record, "Fingerprint", key.get("keyFingerprint"))
    else:
        return None
    _custom_fields(item, record)
    return record


def _text(value: Any) -> str:
    return "" if value is None or isinstance(value, (dict, list)) else str(value)


def records_from_document(document: Mapping[str, Any], *, source_format: str) -> ImportResult:
    items = document.get("items")
    if not isinstance(items, list):
        raise BitwardenError(t("bitwarden.expectedABitwardenJsonExport"))
    result = ImportResult(source_format)
    check_record_count(len(items))  # trashed and malformed items count too
    folders = _folder_names(document)
    passkeys = 0
    for index, item in enumerate(items, 1):
        if not isinstance(item, dict):
            result.diagnostics.append(t("bitwarden.itemNotAnObjectSkipped", index=index))
            continue
        if item.get("deletedDate"):
            result.diagnostics.append(t("bitwarden.itemInTheBitwardenTrash", index=index))
            continue
        record = item_to_record(item, folders, source_row=index)
        if record is None:
            # Never drop data silently: unknown future item types keep their
            # name, notes and custom fields as a secure note.
            record = ImportedRecord(kind="note", title=str(item.get("name") or ""), notes=str(item.get("notes") or ""),
                                    source_row=index)
            add_custom_field(record, "Bitwarden item type", item.get("type"))
            _custom_fields(item, record)
            result.diagnostics.append(t("bitwarden.itemUnknownBitwardenItemType", index=index, v2=item.get('type')))
        login = item.get("login")
        if isinstance(login, dict) and login.get("fido2Credentials"):
            passkeys += 1
        result.records.append(record)
    if passkeys:
        result.diagnostics.append(t("bitwarden.loginsHavePasskeys", count=passkeys))
    result.records = enforce_record_limit(result.records)
    return result


def parse_bitwarden_json(source: Path | str | bytes) -> dict[str, Any]:
    data = read_source_bytes(source)
    try:
        document = json.loads(decode_text(data))
    except (ValueError, RecursionError) as exc:
        # RecursionError: pathologically nested JSON must stay a format error.
        raise BitwardenError(t("bitwarden.invalidJson")) from exc
    if not isinstance(document, dict):
        raise BitwardenError(t("bitwarden.expectedABitwardenJsonExport2"))
    return document


def is_encrypted(document: Mapping[str, Any]) -> bool:
    return bool(document.get("encrypted")) and "data" in document


def load_bitwarden_json(source: Path | str | bytes, *, password: str | None = None) -> ImportResult:
    """Load an unencrypted or password-protected Bitwarden JSON export."""
    document = parse_bitwarden_json(source)
    if document.get("encrypted") is True and not document.get("passwordProtected"):
        # Account-restricted exports keep a plain items list whose strings are
        # all "2.xxx" EncStrings; importing them would create garbage items.
        raise BitwardenError(t(ACCOUNT_RESTRICTED_MESSAGE))
    if is_encrypted(document):
        inner = decrypt_bitwarden_export(document, password)
        return records_from_document(inner, source_format="bitwarden-encrypted-json")
    return records_from_document(document, source_format="bitwarden-json")


BITWARDEN_CSV_COLUMNS = ("folder", "favorite", "type", "name", "notes", "fields", "reprompt", "login_uri",
                         "login_username", "login_password", "login_totp")


def _parse_fields_column(record: ImportedRecord, text: str) -> None:
    for line in text.splitlines():
        if ":" not in line:
            continue
        name, value = line.split(":", 1)
        add_custom_field(record, name.strip(), value.strip())


def load_bitwarden_csv(source: Path | str | bytes) -> ImportResult:
    """Load the Bitwarden CSV export (also the format :mod:`localvault.export` writes)."""
    header, rows = read_csv_table(decode_text(read_source_bytes(source)))
    result = ImportResult("bitwarden-csv", fields=tuple(header))
    for row in rows:
        number = int(row["__row__"])
        kind = pick(row, "type").casefold() or "login"
        name = pick(row, "name")
        notes = pick(row, "notes")
        uris = [uri.strip() for uri in pick(row, "login_uri").split(",") if uri.strip()]
        base = {"title": name, "notes": notes, "folder": pick(row, "folder"), "favorite": truthy(pick(row, "favorite")),
                "source_row": number}
        if kind == "note":
            record = ImportedRecord(kind="note", **base)
        elif kind in {"login", ""}:
            record = ImportedRecord(kind="login", username=pick(row, "login_username"), password=pick(row, "login_password"),
                                    urls=uris, totp_uri=totp_uri_from_secret(pick(row, "login_totp"), label=name), **base)
        else:
            result.diagnostics.append(t("bitwarden.rowUnsupportedTypeImportedAs", number=number, kind=kind))
            record = ImportedRecord(kind="note", **base)
        _parse_fields_column(record, pick(row, "fields"))
        result.records.append(record)
    result.records = enforce_record_limit(result.records)
    return result


__all__ = [
    "ACCOUNT_RESTRICTED_MESSAGE", "BITWARDEN_CSV_COLUMNS", "BitwardenError", "BitwardenPasswordError", "decrypt_bitwarden_export",
    "decrypt_enc_string", "derive_export_keys", "encrypt_bitwarden_export", "encrypt_enc_string", "is_encrypted",
    "item_to_record", "load_bitwarden_csv", "load_bitwarden_json", "parse_bitwarden_json", "records_from_document",
]
