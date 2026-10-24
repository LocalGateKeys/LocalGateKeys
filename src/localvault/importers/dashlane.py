"""Dashlane CSV importer: the zip export and each CSV it contains.

Dashlane's CSV export is a zip of ``credentials.csv``, ``securenotes.csv``,
``payments.csv``, ``ids.csv`` and ``personalInfo.csv``.  Each file can also be
imported on its own; the legacy single-file layout
(``title,url,username,password,note``) is still accepted.
"""
from __future__ import annotations

import io
import zipfile
import zlib
from collections.abc import Callable, Mapping
from pathlib import Path

from . import (
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
    decode_text,
    normalize_header,
    pick,
    read_bounded,
    read_csv_table,
    read_source_bytes,
)

DASHLANE_CREDENTIAL_COLUMNS = ("username", "username2", "username3", "title", "password", "note", "url", "category", "otpSecret")
DASHLANE_NOTE_COLUMNS = ("title", "note")
DASHLANE_LEGACY_COLUMNS = ("title", "url", "username", "password", "note")
DASHLANE_PAYMENT_COLUMNS = ("type", "account_name", "account_holder", "cc_number", "code", "expiration_month",
                            "expiration_year", "routing_number", "account_number", "country", "issuing_bank")
DASHLANE_ID_COLUMNS = ("type", "number", "name", "issue_date", "expiration_date", "place_of_issue", "state")
DASHLANE_PERSONAL_COLUMNS = ("type", "title", "first_name", "middle_name", "last_name", "login", "date_of_birth",
                             "place_of_birth", "email", "email_type", "item_name", "phone_number", "address", "country",
                             "state", "city", "zip", "address_recipient", "address_building", "address_apartment",
                             "address_floor", "address_door_code", "job_title", "url")
MAX_ZIP_MEMBER_BYTES = 8 * 1024 * 1024
MAX_ZIP_BYTES = 64 * 1024 * 1024
_ZIP_FILES = ("credentials.csv", "securenotes.csv", "payments.csv", "ids.csv", "personalinfo.csv")
_ID_TYPES = {"card": "ID card", "passport": "Passport", "license": "Driving licence", "driver_license": "Driving licence",
             "social_security": "Social security number", "tax_number": "Tax number"}
_PERSONAL_MAP = {"first name": "given_name", "middle name": "middle_name", "last name": "family_name",
                 "email": "email", "phone number": "phone", "address": "address_line1", "country": "country",
                 "state": "state", "city": "city", "zip": "postal_code", "job title": "job_title", "url": "website"}


class DashlaneError(ImportFormatError):
    """The archive or file is not a readable Dashlane export."""


def classify_header(header: list[str]) -> str:
    keys = {normalize_header(cell) for cell in header}
    if {"cc number", "account name"} <= keys or {"cc number", "expiration month"} <= keys:
        return "payments"
    if {"first name", "last name", "item name"} <= keys:
        return "personal"
    if {"type", "number", "name", "issue date", "expiration date"} <= keys:
        return "ids"
    if {"title", "password"} <= keys and ({"username2", "otpsecret", "otpurl", "category"} & keys):
        return "credentials"
    if keys == {"title", "note"} or keys == {"title", "note", "category"}:
        return "notes"
    if {"title", "url", "password"} <= keys:
        return "credentials"
    return ""


def _credentials(rows: list[dict[str, str]], result: ImportResult) -> None:
    for row in rows:
        number = int(row["__row__"])
        title = pick(row, "title")
        note = pick(row, "note", "notes")
        url = pick(row, "url")
        username = pick(row, "username", "login", "email")
        password = pick(row, "password")
        if not (url or username or password):
            result.records.append(ImportedRecord(kind="note", title=title, notes=note, folder=pick(row, "category"),
                                                 source_row=number))
            continue
        record = ImportedRecord(kind="login", title=title or url, username=username, password=password,
                                urls=[url] if url else [], notes=note, folder=pick(row, "category"),
                                totp_uri=totp_uri_from_secret(pick(row, "otpUrl", "otpSecret", "totp"), label=title),
                                source_row=number)
        for extra in ("username2", "username3"):
            value = pick(row, extra)
            if value and value != username:
                add_custom_field(record, "Alternative username", value)
        result.records.append(record)


def _notes(rows: list[dict[str, str]], result: ImportResult) -> None:
    for row in rows:
        result.records.append(ImportedRecord(kind="note", title=pick(row, "title"), notes=pick(row, "note", "notes"),
                                             folder=pick(row, "category"), source_row=int(row["__row__"])))


def _payments(rows: list[dict[str, str]], result: ImportResult) -> None:
    for row in rows:
        number = int(row["__row__"])
        kind = pick(row, "type").casefold()
        title = pick(row, "account_name", "name") or ("Bank account" if kind == "bank" else "Payment card")
        if kind in {"", "credit_card", "payment_card", "card"} and pick(row, "cc_number"):
            record = ImportedRecord(kind="card", title=title, notes=pick(row, "note"), source_row=number, card={
                "cardholder": pick(row, "account_holder"), "number": pick(row, "cc_number"), "cvv": pick(row, "code"),
                "expiry": card_expiry(pick(row, "expiration_month"), pick(row, "expiration_year")),
            })
            add_custom_field(record, "Issuing bank", pick(row, "issuing_bank"))
            add_custom_field(record, "Country", pick(row, "country"))
        else:
            record = ImportedRecord(kind="note", title=title, notes=pick(row, "note"), source_row=number)
            add_custom_field(record, "Dashlane payment type", kind or "unknown")
            add_custom_field(record, "Account holder", pick(row, "account_holder"))
            add_custom_field(record, "Account number", pick(row, "account_number"), hidden=True)
            add_custom_field(record, "Routing number", pick(row, "routing_number"), hidden=True)
            add_custom_field(record, "Card number", pick(row, "cc_number"), hidden=True)
            add_custom_field(record, "Bank", pick(row, "issuing_bank"))
            add_custom_field(record, "Country", pick(row, "country"))
        result.records.append(record)


def _ids(rows: list[dict[str, str]], result: ImportResult) -> None:
    for row in rows:
        kind = pick(row, "type").casefold()
        label = _ID_TYPES.get(kind, kind.replace("_", " ").capitalize() or "ID document")
        name = pick(row, "name")
        record = ImportedRecord(kind="note", title=f"{label} - {name}" if name else label,
                                source_row=int(row["__row__"]))
        add_custom_field(record, "Document type", label)
        add_custom_field(record, "Number", pick(row, "number"), hidden=True)
        add_custom_field(record, "Name", name)
        for column, field_name in (("issue_date", "Issue date"), ("expiration_date", "Expiry date"),
                                   ("place_of_issue", "Place of issue"), ("state", "State")):
            add_custom_field(record, field_name, pick(row, column))
        result.records.append(record)


def _personal(rows: list[dict[str, str]], result: ImportResult) -> None:
    for row in rows:
        values: dict[str, str] = {}
        for column, target in _PERSONAL_MAP.items():
            value = row.get(column, "")
            if value and target not in values:
                values[target] = value
        full = " ".join(values.get(key, "") for key in ("given_name", "middle_name", "family_name")).split()
        if full:
            values["name"] = " ".join(full)
        title = pick(row, "item_name", "title") or values.get("name") or pick(row, "type").capitalize() or "Personal info"
        record = ImportedRecord(kind="identity", title=title, identity=values, source_row=int(row["__row__"]))
        for column, field_name in (("date_of_birth", "Date of birth"), ("place_of_birth", "Place of birth"),
                                   ("login", "Login"), ("address_recipient", "Recipient"),
                                   ("address_building", "Building"), ("address_apartment", "Apartment"),
                                   ("address_floor", "Floor"), ("address_door_code", "Door code")):
            add_custom_field(record, field_name, pick(row, column), hidden=column == "address_door_code")
        result.records.append(record)


_LAYOUTS: Mapping[str, Callable[[list[dict[str, str]], ImportResult], None]] = {
    "credentials": _credentials, "notes": _notes, "payments": _payments, "ids": _ids, "personal": _personal,
}


def _load_text(text: str, result: ImportResult, *, name: str = "") -> None:
    header, rows = read_csv_table(text)
    layout = classify_header(header)
    if not layout:
        if name:
            result.diagnostics.append(f"{name}: columns not recognised; skipped.")
            return
        layout = "credentials"
    offset = len(result.records)
    _LAYOUTS[layout](rows, result)
    if name:
        for record in result.records[offset:]:
            record.source_row = None  # row numbers repeat across the files of a zip


def load_dashlane_csv(source: Path | str | bytes) -> ImportResult:
    data = read_source_bytes(source, limit=MAX_ZIP_BYTES)
    if data[:2] == b"PK":
        return load_dashlane_zip(data)
    data = read_source_bytes(data)  # plain CSV keeps the 8 MiB text bound
    text = decode_text(data)
    header, _rows = read_csv_table(text)
    result = ImportResult("dashlane-csv", fields=tuple(header))
    _load_text(text, result)
    result.records = enforce_record_limit(result.records)
    return result


def load_dashlane_zip(source: Path | str | bytes) -> ImportResult:
    """Load every recognised CSV inside a Dashlane export zip."""
    data = read_source_bytes(source, limit=MAX_ZIP_BYTES)
    result = ImportResult("dashlane-zip")
    found = False
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            members = {info.filename.rsplit("/", 1)[-1].casefold(): info for info in archive.infolist()}
            for name in _ZIP_FILES:
                info = members.get(name)
                if info is None:
                    continue
                if info.file_size > MAX_ZIP_MEMBER_BYTES or info.flag_bits & 0x1 \
                        or info.compress_type not in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED):
                    raise DashlaneError(f"{name} inside the zip is too large, encrypted or unsupported")
                with archive.open(info) as handle:
                    raw = read_bounded(handle, MAX_ZIP_MEMBER_BYTES)
                if len(raw) > MAX_ZIP_MEMBER_BYTES:
                    raise DashlaneError(f"{name} inside the zip is too large")
                found = True
                if raw.strip():
                    _load_text(decode_text(raw), result, name=name)
                    check_record_count(len(result.records))
    except ImportFormatError:
        raise
    except (zipfile.BadZipFile, zipfile.LargeZipFile, RuntimeError, NotImplementedError, OSError, EOFError,
            ValueError, zlib.error) as exc:
        raise DashlaneError("The Dashlane archive is corrupted or unsupported") from exc
    if not found:
        raise DashlaneError("The zip archive does not contain Dashlane CSV files (credentials.csv, securenotes.csv, ...)")
    result.records = enforce_record_limit(result.records)
    return result


__all__ = ["DASHLANE_CREDENTIAL_COLUMNS", "DASHLANE_ID_COLUMNS", "DASHLANE_LEGACY_COLUMNS", "DASHLANE_NOTE_COLUMNS",
           "DASHLANE_PAYMENT_COLUMNS", "DASHLANE_PERSONAL_COLUMNS", "DashlaneError", "classify_header",
           "load_dashlane_csv", "load_dashlane_zip"]
