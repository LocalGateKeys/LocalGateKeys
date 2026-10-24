"""KeePass 2 / KeePassXC CSV importer."""
from __future__ import annotations

from pathlib import Path

from . import ImportedRecord, ImportResult, enforce_record_limit, totp_uri_from_secret
from ._source import (
    decode_text,
    normalize_header,
    parse_timestamp,
    pick,
    read_csv_table,
    read_source_bytes,
)

KEEPASS2_COLUMNS = ("Account", "Login Name", "Password", "Web Site", "Comments")
KEEPASSXC_COLUMNS = ("Group", "Title", "Username", "Password", "URL", "Notes", "TOTP", "Icon", "Last Modified", "Created")


def is_keepass_header(header: list[str]) -> bool:
    keys = {normalize_header(cell) for cell in header}
    return {"account", "login name", "password"} <= keys or {"group", "title", "username", "password", "url"} <= keys


def strip_root_group(group: str) -> str:
    parts = [part for part in group.replace("\\", "/").split("/") if part.strip()]
    if parts and parts[0].casefold() in {"root", "database", "passwords"}:
        parts = parts[1:]
    return "/".join(parts)


def load_keepass_csv(source: Path | str | bytes) -> ImportResult:
    header, rows = read_csv_table(decode_text(read_source_bytes(source)))
    result = ImportResult("keepass-csv", fields=tuple(header))
    for row in rows:
        number = int(row["__row__"])
        title = pick(row, "title", "account")
        url = pick(row, "url", "web site")
        username = pick(row, "username", "login name")
        password = pick(row, "password")
        notes = pick(row, "notes", "comments")
        folder = strip_root_group(pick(row, "group"))
        if not (url or username or password):
            result.records.append(ImportedRecord(kind="note", title=title, notes=notes, folder=folder, source_row=number))
            continue
        result.records.append(ImportedRecord(
            kind="login", title=title or url, username=username, password=password, urls=[url] if url else [],
            notes=notes, totp_uri=totp_uri_from_secret(pick(row, "totp", "otp"), label=title), folder=folder,
            created=parse_timestamp(pick(row, "created")), modified=parse_timestamp(pick(row, "last modified")),
            source_row=number,
        ))
    result.records = enforce_record_limit(result.records)
    return result


__all__ = ["KEEPASS2_COLUMNS", "KEEPASSXC_COLUMNS", "is_keepass_header", "load_keepass_csv", "strip_root_group"]
