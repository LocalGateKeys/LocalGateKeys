"""Proton Pass importers: the JSON export (zip or bare ``data.json``) and the CSV export.

Proton Pass writes ``Proton Pass/data.json`` inside a zip.  The document maps
vault share IDs to ``{"name", "items": [...]}``; each item carries
``data.type`` (``login``, ``note``, ``creditCard``, ``identity``, ``alias``,
``sshKey``, ``wifi``, ``custom``), ``data.metadata`` (name, note),
``data.content`` (type specific) and ``data.extraFields``.  ``state`` 2
means the item is in the trash.  The PGP-encrypted export (``data.pgp``) is
refused with instructions because no vetted OpenPGP dependency is available.
"""
from __future__ import annotations

import io
import json
import zipfile
import zlib
from collections.abc import Mapping
from pathlib import Path
from typing import Any
from ..i18n import t

from . import (
    MAX_JSON_BYTES,
    ImportedRecord,
    ImportFormatError,
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
    read_bounded,
    read_csv_table,
    read_source_bytes,
)

MAX_DATA_BYTES = 64 * 1024 * 1024  # the zip (Proton exports may carry attachments)
MAX_JSON_DATA_BYTES = MAX_JSON_BYTES  # data.json once decompressed
DATA_MEMBER = "Proton Pass/data.json"
PGP_MEMBER = "Proton Pass/data.pgp"
STATE_TRASHED = 2
PROTON_CSV_COLUMNS = ("type", "name", "url", "email", "username", "password", "note", "totp", "createTime",
                      "modifyTime", "vault")
ENCRYPTED_MESSAGE = (
    "protonpass.thisProtonPassExportIs")
_SUPPORTED_ZIP_METHODS = frozenset({zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED})

_IDENTITY_MAP = {
    "fullName": "name", "firstName": "given_name", "middleName": "middle_name", "lastName": "family_name",
    "email": "email", "phoneNumber": "phone", "organization": "organization", "company": "company",
    "jobTitle": "job_title", "streetAddress": "address_line1", "city": "city", "stateOrProvince": "state",
    "zipOrPostalCode": "postal_code", "countryOrRegion": "country", "website": "website",
}
_IDENTITY_HIDDEN = {"socialSecurityNumber": "Social security number", "passportNumber": "Passport number",
                    "licenseNumber": "Licence number"}
_IDENTITY_SECTIONS = ("extraPersonalDetails", "extraAddressDetails", "extraContactDetails", "extraWorkDetails")
_TYPE_LABELS = {"alias": "Email alias", "sshKey": "SSH key", "wifi": "Wi-Fi network", "custom": "Custom item"}


class ProtonPassError(ImportFormatError):
    """The archive or document is not a readable Proton Pass export."""


def _text(value: Any) -> str:
    return "" if value is None or isinstance(value, (dict, list)) else str(value)


def _dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _extra_fields(fields: Any, record: ImportedRecord, title: str) -> None:
    """Map Proton ``extraFields`` (text, hidden, totp, timestamp) onto the record."""
    for field in as_list(fields):
        if not isinstance(field, dict):
            continue
        name = _text(field.get("fieldName")) or "Field"
        kind = _text(field.get("type")).casefold()
        data = _dict(field.get("data"))
        if kind == "totp":
            uri = _text(data.get("totpUri"))
            if uri and not record.totp_uri and record.kind == "login":
                record.totp_uri = totp_uri_from_secret(uri, label=title)
            else:
                add_custom_field(record, name, uri, hidden=True)
            continue
        if kind == "timestamp":
            add_custom_field(record, name, _text(data.get("timestamp")))
            continue
        add_custom_field(record, name, _text(data.get("content")), hidden=kind == "hidden")


def _sections(sections: Any, record: ImportedRecord) -> None:
    """Identity and custom items group extra fields into named sections."""
    for section in as_list(sections):
        if isinstance(section, dict):
            _extra_fields(section.get("sectionFields"), record, record.title)


def item_to_record(item: Mapping[str, Any], vault_name: str, *, source_row: int | None = None) -> ImportedRecord:
    data = _dict(item.get("data"))
    metadata = _dict(data.get("metadata"))
    content = _dict(data.get("content"))
    kind = _text(data.get("type"))
    title = _text(metadata.get("name"))
    base = {
        "title": title, "notes": _text(metadata.get("note")), "folder": vault_name,
        "favorite": bool(item.get("pinned")), "created": parse_timestamp(item.get("createTime")),
        "modified": parse_timestamp(item.get("modifyTime")), "source_row": source_row,
    }
    if kind == "login":
        urls = [_text(url) for url in as_list(content.get("urls")) if _text(url)]
        email = _text(content.get("itemEmail"))
        username = _text(content.get("itemUsername")) or _text(content.get("username"))
        record = ImportedRecord(kind="login", username=username or email, password=_text(content.get("password")),
                                urls=urls, totp_uri=totp_uri_from_secret(_text(content.get("totpUri")), label=title),
                                **base)
        if email and username and email != username:
            add_custom_field(record, "Email", email)
        if content.get("passkeys"):
            add_custom_field(record, "Passkeys", t("protonpass.thisLoginHadAPasskey"))
    elif kind == "note":
        record = ImportedRecord(kind="note", **base)
    elif kind == "creditCard":
        record = ImportedRecord(kind="card", card={
            "cardholder": _text(content.get("cardholderName")), "number": _text(content.get("number")),
            "cvv": _text(content.get("verificationNumber")), "pin": _text(content.get("pin")),
            "expiry": card_expiry(_text(content.get("expirationDate"))),
        }, **base)
        if content.get("expirationDate") and not record.card.get("expiry"):
            add_custom_field(record, "Expiry", _text(content.get("expirationDate")))
    elif kind == "identity":
        values = {target: _text(content.get(key)) for key, target in _IDENTITY_MAP.items() if _text(content.get(key))}
        if "name" not in values:
            full = " ".join(values.get(key, "") for key in ("given_name", "middle_name", "family_name")).split()
            if full:
                values["name"] = " ".join(full)
        record = ImportedRecord(kind="identity", identity=values, **base)
        for key, label in _IDENTITY_HIDDEN.items():
            add_custom_field(record, label, _text(content.get(key)), hidden=True)
        for key in ("birthdate", "gender", "floor", "county", "secondPhoneNumber", "workPhoneNumber", "workEmail",
                    "personalWebsite", "xHandle", "linkedin", "reddit", "facebook", "yahoo", "instagram"):
            add_custom_field(record, key, _text(content.get(key)))
        for key in _IDENTITY_SECTIONS:
            _extra_fields(content.get(key), record, title)
        _sections(content.get("extraSections"), record)
    else:
        record = ImportedRecord(kind="note", **base)
        add_custom_field(record, "Proton Pass item type", _TYPE_LABELS.get(kind, kind or "unknown"))
        if kind == "alias":
            add_custom_field(record, "Alias address", _text(item.get("aliasEmail")))
        elif kind == "sshKey":
            add_custom_field(record, "Private key", _text(content.get("privateKey")), hidden=True)
            add_custom_field(record, "Public key", _text(content.get("publicKey")))
        elif kind == "wifi":
            add_custom_field(record, "Network name (SSID)", _text(content.get("ssid")))
            add_custom_field(record, "Wi-Fi password", _text(content.get("password")), hidden=True)
            add_custom_field(record, "Security", _text(content.get("security")))
        _sections(content.get("sections"), record)
    _extra_fields(data.get("extraFields"), record, title)
    return record


def records_from_document(document: Mapping[str, Any]) -> ImportResult:
    if document.get("encrypted") is True:
        raise ProtonPassError(t(ENCRYPTED_MESSAGE))
    vaults = document.get("vaults")
    if not isinstance(vaults, dict):
        raise ProtonPassError("Proton Pass export has no 'vaults' object")
    result = ImportResult("protonpass-json")
    trashed = 0
    index = 0
    for vault in vaults.values():
        if not isinstance(vault, dict):
            continue
        vault_name = _text(vault.get("name"))
        items = vault.get("items")
        for item in as_list(items):
            index += 1
            check_record_count(index)
            if not isinstance(item, dict):
                result.diagnostics.append(t("bitwarden.itemNotAnObjectSkipped", index=index))
                continue
            if item.get("state") == STATE_TRASHED:
                trashed += 1
                continue
            result.records.append(item_to_record(item, vault_name, source_row=index))
    if trashed:
        result.diagnostics.append(t("protonpass.itemsInTheProtonPass", trashed=trashed))
    result.records = enforce_record_limit(result.records)
    return result


def read_data_json(source: Path | str | bytes) -> dict[str, Any]:
    """Return the parsed ``data.json`` from a Proton Pass zip (or a bare JSON file)."""
    data = read_source_bytes(source, limit=MAX_DATA_BYTES)
    if data[:2] == b"PK":
        try:
            with zipfile.ZipFile(io.BytesIO(data)) as archive:
                names = {info.filename: info for info in archive.infolist()}
                if PGP_MEMBER in names or any(name.endswith(".pgp") for name in names):
                    raise ProtonPassError(t(ENCRYPTED_MESSAGE))
                info = names.get(DATA_MEMBER) or next(
                    (value for name, value in names.items() if name.rsplit("/", 1)[-1] == "data.json"), None)
                if info is None:
                    raise ProtonPassError(t("protonpass.theZipArchiveDoesNot"))
                if info.file_size > MAX_JSON_DATA_BYTES:
                    raise ProtonPassError(t("protonpass.dataJsonIsTooLarge"))
                if info.flag_bits & 0x1 or info.compress_type not in _SUPPORTED_ZIP_METHODS:
                    raise ProtonPassError(t("protonpass.dataJsonIsEncryptedOr"))
                with archive.open(info) as handle:
                    raw = read_bounded(handle, MAX_JSON_DATA_BYTES)
        except ProtonPassError:
            raise
        except (zipfile.BadZipFile, zipfile.LargeZipFile, RuntimeError, NotImplementedError, OSError, EOFError,
                ValueError, zlib.error) as exc:
            raise ProtonPassError(t("protonpass.theProtonPassArchiveIs")) from exc
    else:
        raw = data
    if len(raw) > MAX_JSON_DATA_BYTES:
        raise ProtonPassError(t("protonpass.dataJsonIsTooLarge"))
    if raw.lstrip()[:27] == b"-----BEGIN PGP MESSAGE-----":
        raise ProtonPassError(t(ENCRYPTED_MESSAGE))
    try:
        document = json.loads(decode_text(raw))
    except (ValueError, RecursionError) as exc:
        raise ProtonPassError(t("protonpass.protonPassDataJsonIs2")) from exc
    if not isinstance(document, dict):
        raise ProtonPassError(t("protonpass.protonPassDataJsonIs"))
    return document


def load_protonpass_json(source: Path | str | bytes) -> ImportResult:
    return records_from_document(read_data_json(source))


def load_protonpass_csv(source: Path | str | bytes) -> ImportResult:
    """Load the Proton Pass CSV export (logins, notes, aliases; other types become notes)."""
    header, rows = read_csv_table(decode_text(read_source_bytes(source)))
    result = ImportResult("protonpass-csv", fields=tuple(header))
    for row in rows:
        number = int(row["__row__"])
        kind = pick(row, "type").casefold() or "login"
        title = pick(row, "name")
        email = pick(row, "email")
        username = pick(row, "username") or email
        base = {"title": title, "notes": pick(row, "note"), "folder": pick(row, "vault"),
                "created": parse_timestamp(pick(row, "createTime")),
                "modified": parse_timestamp(pick(row, "modifyTime")), "source_row": number}
        if kind == "login":
            urls = [url.strip() for url in pick(row, "url").split(",") if url.strip()]
            record = ImportedRecord(kind="login", username=username, password=pick(row, "password"), urls=urls,
                                    totp_uri=totp_uri_from_secret(pick(row, "totp"), label=title), **base)
            if email and email != username:
                add_custom_field(record, "Email", email)
        else:
            record = ImportedRecord(kind="note", **base)
            if kind != "note":
                add_custom_field(record, "Proton Pass item type", _TYPE_LABELS.get(kind, kind))
                add_custom_field(record, "Email", email)
                add_custom_field(record, "Username", pick(row, "username"))
                add_custom_field(record, "Password", pick(row, "password"), hidden=True)
                add_custom_field(record, "URL", pick(row, "url"))
                if kind in {"creditcard", "identity"}:
                    result.diagnostics.append(
                        t("protonpass.rowProtonPassCsvDoes", number=number, kind=kind))
        result.records.append(record)
        check_record_count(len(result.records))
    result.records = enforce_record_limit(result.records)
    return result


__all__ = ["ENCRYPTED_MESSAGE", "PROTON_CSV_COLUMNS", "ProtonPassError", "item_to_record", "load_protonpass_csv",
           "load_protonpass_json", "read_data_json", "records_from_document"]
