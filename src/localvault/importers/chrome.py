"""Browser CSV importers (Chrome/Edge/Brave, Firefox, Safari) and the generic mapped CSV loader."""
from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path
from urllib.parse import urlsplit

from . import (
    ImportedRecord,
    ImportFormatError,
    ImportResult,
    enforce_record_limit,
    totp_uri_from_secret,
)
from ._source import (
    decode_text,
    normalize_header,
    parse_timestamp,
    pick,
    read_csv_table,
    read_source_bytes,
    truthy,
)

CHROME_COLUMNS = ("name", "url", "username", "password", "note")
FIREFOX_COLUMNS = ("url", "username", "password", "httpRealm", "formActionOrigin", "guid", "timeCreated",
                   "timeLastUsed", "timePasswordChanged")
SAFARI_COLUMNS = ("Title", "URL", "Username", "Password", "Notes", "OTPAuth")

MAPPING_TARGETS = ("title", "url", "username", "password", "notes", "totp", "folder", "favorite")
FIELD_ALIASES: dict[str, tuple[str, ...]] = {
    "title": ("name", "title", "account", "label", "item"),
    "url": ("url", "login uri", "web site", "website", "uri", "login url", "site", "address", "hostname"),
    "username": ("username", "login username", "login name", "user name", "user", "login", "email"),
    "password": ("password", "login password", "pass", "pwd", "secret"),
    "notes": ("notes", "note", "comments", "comment", "extra", "notesplain"),
    "totp": ("totp", "login totp", "otpauth", "otp", "one-time password", "otpsecret", "totp secret"),
    "folder": ("folder", "group", "grouping", "category", "collection", "vault"),
    "favorite": ("favorite", "favourite", "fav", "starred"),
}


def classify_browser_header(header: list[str]) -> str:
    keys = {normalize_header(cell) for cell in header}
    if {"url", "username", "password", "httprealm", "formactionorigin"} <= keys:
        return "firefox-csv"
    if {"title", "url", "username", "password", "otpauth"} <= keys and not ({"favorite", "archived", "tags"} & keys):
        return "safari-csv"
    if {"name", "url", "username", "password"} <= keys:
        return "chrome-csv"
    return ""


def host_title(url: str) -> str:
    try:
        host = urlsplit(url.strip()).hostname or ""
    except ValueError:
        host = ""
    return host or url.strip()


def guess_mapping(header: list[str]) -> dict[str, str]:
    """Return {target: original column} using :data:`FIELD_ALIASES`."""
    normalized = {normalize_header(cell): cell for cell in header}
    mapping: dict[str, str] = {}
    for target, aliases in FIELD_ALIASES.items():
        for alias in aliases:
            column = normalized.get(normalize_header(alias))
            if column is not None and column not in mapping.values():
                mapping[target] = column
                break
    return mapping


def load_generic_csv(source: Path | str | bytes, *, column_mapping: Mapping[str, str] | None = None,
                     source_format: str = "csv") -> ImportResult:
    """Load any CSV using an explicit ``{target: column}`` mapping or alias guessing.

    Targets are listed in :data:`MAPPING_TARGETS`; at least ``password`` (or
    ``notes``) must be mapped.  Column names are matched case-insensitively.
    """
    header, rows = read_csv_table(decode_text(read_source_bytes(source)))
    if column_mapping is None:
        mapping = guess_mapping(header)
    else:
        normalized = {normalize_header(cell): cell for cell in header}
        mapping = {}
        for target, column in column_mapping.items():
            if target not in MAPPING_TARGETS:
                raise ImportFormatError(f"Unknown mapping target {target!r}")
            if not column:
                continue
            if normalize_header(column) not in normalized:
                raise ImportFormatError(f"Column {column!r} does not exist in the CSV header")
            mapping[target] = normalized[normalize_header(column)]
    if "password" not in mapping and "notes" not in mapping:
        raise ImportFormatError("CSV columns could not be mapped; choose the password column")
    result = ImportResult(source_format, fields=tuple(header))
    for row in rows:
        number = int(row["__row__"])
        values = {target: row.get(normalize_header(column), "") for target, column in mapping.items()}
        url = values.get("url", "").strip()
        username = values.get("username", "")
        password = values.get("password", "")
        title = values.get("title", "") or host_title(url)
        notes = values.get("notes", "")
        if not (url or username or password):
            if notes:
                result.records.append(ImportedRecord(kind="note", title=title or f"Row {number}", notes=notes,
                                                     folder=values.get("folder", ""), source_row=number))
            else:
                result.diagnostics.append(f"Row {number}: empty row; skipped.")
            continue
        result.records.append(ImportedRecord(
            kind="login", title=title, username=username, password=password, urls=[url] if url else [],
            notes=notes, totp_uri=totp_uri_from_secret(values.get("totp", ""), label=title),
            folder=values.get("folder", "").replace("\\", "/"), favorite=truthy(values.get("favorite", "")),
            source_row=number,
        ))
    result.records = enforce_record_limit(result.records)
    return result


def load_browser_csv(source: Path | str | bytes) -> ImportResult:
    """Load Chrome/Edge/Brave, Firefox or Safari password CSV exports."""
    data = read_source_bytes(source)
    header, rows = read_csv_table(decode_text(data))
    layout = classify_browser_header(header) or "chrome-csv"
    result = ImportResult(layout, fields=tuple(header))
    for row in rows:
        number = int(row["__row__"])
        url = pick(row, "url").strip()
        if not url and layout == "firefox-csv":
            url = pick(row, "formActionOrigin").strip()
        username = pick(row, "username")
        password = pick(row, "password")
        if not (url or username or password):
            result.diagnostics.append(f"Row {number}: empty row; skipped.")
            continue
        title = pick(row, "name", "title") or host_title(url)
        record = ImportedRecord(kind="login", title=title, username=username, password=password,
                                urls=[url] if url else [], notes=pick(row, "note", "notes"),
                                totp_uri=totp_uri_from_secret(pick(row, "otpauth", "totp"), label=title), source_row=number)
        if layout == "firefox-csv":
            record.created = parse_timestamp(pick(row, "timeCreated"))
            record.modified = parse_timestamp(pick(row, "timePasswordChanged")) or parse_timestamp(pick(row, "timeLastUsed"))
        result.records.append(record)
    result.records = enforce_record_limit(result.records)
    return result


load_chrome_csv = load_browser_csv

__all__ = ["CHROME_COLUMNS", "FIELD_ALIASES", "FIREFOX_COLUMNS", "MAPPING_TARGETS", "SAFARI_COLUMNS",
           "classify_browser_header", "guess_mapping", "host_title", "load_browser_csv", "load_chrome_csv",
           "load_generic_csv"]
