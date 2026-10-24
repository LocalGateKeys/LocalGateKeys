"""LastPass CSV importer (``url,username,password,totp,extra,name,grouping,fav``)."""
from __future__ import annotations

from pathlib import Path

from . import (
    ImportedRecord,
    ImportResult,
    add_custom_field,
    card_expiry,
    enforce_record_limit,
    totp_uri_from_secret,
)
from ._source import decode_text, pick, read_csv_table, read_source_bytes, truthy

LASTPASS_COLUMNS = ("url", "username", "password", "totp", "extra", "name", "grouping", "fav")
SECURE_NOTE_URL = "http://sn"
_CARD_FIELDS = {"name on card": "cardholder", "number": "number", "security code": "cvv",
                "expiration date": "expiry", "type": "brand", "pin": "pin"}
_ADDRESS_FIELDS = {
    "first name": "given_name", "middle name": "middle_name", "last name": "family_name", "company": "company",
    "address 1": "address_line1", "address 2": "address_line2", "city / town": "city", "state": "state",
    "zip / postal code": "postal_code", "country": "country", "email address": "email", "phone": "phone",
    "mobile phone": "phone", "username": "username",
}


def parse_secure_note(extra: str) -> tuple[str, dict[str, str], str]:
    """Split a LastPass templated secure note into (type, fields, free notes)."""
    lines = extra.splitlines()
    if not lines or not lines[0].startswith("NoteType:"):
        return "", {}, extra
    note_type = lines[0].split(":", 1)[1].strip()
    fields: dict[str, str] = {}
    notes: list[str] = []
    in_notes = False
    for line in lines[1:]:
        if in_notes:
            notes.append(line)
            continue
        if line.startswith("Notes:"):
            in_notes = True
            remainder = line.split(":", 1)[1]
            if remainder:
                notes.append(remainder)
            continue
        if ":" in line:
            key, value = line.split(":", 1)
            fields[key.strip()] = value
        elif line.strip():
            notes.append(line)
    return note_type, fields, "\n".join(notes)


def _note_record(title: str, extra: str, folder: str, favorite: bool, number: int) -> ImportedRecord:
    note_type, fields, notes = parse_secure_note(extra)
    if note_type.casefold() == "address":
        identity = {}
        for key, value in fields.items():
            target = _ADDRESS_FIELDS.get(key.casefold())
            if target == "username":
                continue
            if target and value and not identity.get(target):
                identity[target] = value
        name = " ".join(identity.get(key, "") for key in ("given_name", "middle_name", "family_name")).split()
        if name:
            identity["name"] = " ".join(name)
        record = ImportedRecord(kind="identity", title=title, notes=notes, folder=folder, favorite=favorite,
                                identity=identity, source_row=number)
        for key, value in fields.items():
            if _ADDRESS_FIELDS.get(key.casefold()) is None and value and key.casefold() not in {"language", "title"}:
                add_custom_field(record, key, value)
        return record
    if note_type.casefold() == "credit card":
        record = ImportedRecord(kind="card", title=title, notes=notes, folder=folder, favorite=favorite, source_row=number)
        for key, value in fields.items():
            target = _CARD_FIELDS.get(key.casefold())
            if target == "expiry":
                parsed = card_expiry(value)
                value, target = (parsed, target) if parsed else (value, None)
            if target and value and not record.card.get(target):
                record.card[target] = value.strip()
            elif value and key.casefold() != "language":
                hidden = any(hint in key.casefold() for hint in ("number", "code", "pin"))
                add_custom_field(record, key, value, hidden=hidden)
        return record
    if note_type:
        record = ImportedRecord(kind="note", title=title, notes=notes, folder=folder, favorite=favorite, source_row=number)
        add_custom_field(record, "LastPass note type", note_type)
        for key, value in fields.items():
            if value and key.casefold() != "language":
                hidden = any(hint in key.casefold() for hint in ("password", "pin", "secret", "number", "code", "key"))
                add_custom_field(record, key, value, hidden=hidden)
        return record
    return ImportedRecord(kind="note", title=title, notes=extra, folder=folder, favorite=favorite, source_row=number)


def load_lastpass_csv(source: Path | str | bytes) -> ImportResult:
    header, rows = read_csv_table(decode_text(read_source_bytes(source)))
    result = ImportResult("lastpass-csv", fields=tuple(header))
    for row in rows:
        number = int(row["__row__"])
        url = pick(row, "url").strip()
        name = pick(row, "name")
        folder = pick(row, "grouping").replace("\\", "/")
        favorite = truthy(pick(row, "fav"))
        extra = pick(row, "extra")
        if url.casefold() == SECURE_NOTE_URL or (not url and not pick(row, "username") and not pick(row, "password")):
            result.records.append(_note_record(name, extra, folder, favorite, number))
            continue
        record = ImportedRecord(kind="login", title=name or url, username=pick(row, "username"),
                                password=pick(row, "password"), urls=[url] if url else [], notes=extra,
                                totp_uri=totp_uri_from_secret(pick(row, "totp"), label=name), folder=folder,
                                favorite=favorite, source_row=number)
        result.records.append(record)
    result.records = enforce_record_limit(result.records)
    return result


__all__ = ["LASTPASS_COLUMNS", "SECURE_NOTE_URL", "load_lastpass_csv", "parse_secure_note"]
