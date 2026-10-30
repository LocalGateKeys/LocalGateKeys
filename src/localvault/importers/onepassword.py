"""1Password importers: 1PUX archives and 1Password CSV exports."""
from __future__ import annotations

import io
import json
import zipfile
import zlib
from collections.abc import Mapping
from datetime import UTC, datetime
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
    truthy,
)

MAX_EXPORT_BYTES = 64 * 1024 * 1024  # the 1PUX zip (it may carry attachment files)
MAX_EXPORT_DATA_BYTES = MAX_JSON_BYTES  # export.data once decompressed
# 1Password writes export.data stored or deflated; anything else is refused.
_SUPPORTED_ZIP_METHODS = frozenset({zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED})

CATEGORY_LOGIN = {"001", "005", "102", "109", "110", "111", "112"}
CATEGORY_NOTE = {"003"}
CATEGORY_IDENTITY = {"004"}
CATEGORY_CARD = {"002"}
CATEGORY_NAMES = {
    "001": "Login", "002": "Credit Card", "003": "Secure Note", "004": "Identity", "005": "Password",
    "006": "Document", "100": "Software License", "101": "Bank Account", "102": "Database",
    "103": "Driver License", "104": "Outdoor License", "105": "Membership", "106": "Passport",
    "107": "Reward Program", "108": "Social Security Number", "109": "Wireless Router", "110": "Server",
    "111": "Email Account", "112": "API Credential", "113": "Medical Record", "114": "Crypto Wallet",
}
_IDENTITY_IDS = {
    "firstname": "given_name", "initial": "middle_name", "lastname": "family_name", "company": "company",
    "jobtitle": "job_title", "email": "email", "defphone": "phone", "cellphone": "phone", "homephone": "phone",
    "busphone": "phone", "website": "website",
}
_CARD_IDS = {"cardholder": "cardholder", "ccnum": "number", "cvv": "cvv", "expiry": "expiry", "pin": "pin",
             "type": "brand"}
_ADDRESS_KEYS = {"street": "address_line1", "city": "city", "state": "state", "zip": "postal_code", "country": "country"}
_SENSITIVE_HINTS = ("password", "secret", "pin", "key", "number", "cvv", "code", "token", "seed", "passphrase")


class OnePasswordError(ImportFormatError):
    """The archive or document is not a readable 1Password export."""


def _field_value(value: Any) -> tuple[str, str]:
    """Return (type, text) for a 1PUX section field value object."""
    if not isinstance(value, dict) or not value:
        return "", ""
    key, raw = next(iter(value.items()))
    if raw is None:
        return key, ""
    if key == "email" and isinstance(raw, dict):
        return key, str(raw.get("email_address") or "")
    if key == "address" and isinstance(raw, dict):
        parts = [str(raw.get(part) or "") for part in ("street", "city", "state", "zip", "country")]
        return key, ", ".join(part for part in parts if part)
    if key == "monthYear" and isinstance(raw, int):
        text = str(raw)
        return key, f"{text[4:6]}/{text[:4]}" if len(text) == 6 else text
    if key == "date" and isinstance(raw, (int, float)):
        try:
            return key, datetime.fromtimestamp(int(raw), tz=UTC).strftime("%Y-%m-%d")
        except (OverflowError, OSError, ValueError):
            return key, str(raw)
    if isinstance(raw, (dict, list)):
        return key, json.dumps(raw, ensure_ascii=False)
    return key, str(raw)


def _login_fields(details: Mapping[str, Any]) -> tuple[str, str]:
    username = password = ""
    for field in as_list(details.get("loginFields")):
        if not isinstance(field, dict):
            continue
        designation = str(field.get("designation") or "").casefold()
        value = str(field.get("value") or "")
        if designation == "username" and not username:
            username = value
        elif designation == "password" and not password:
            password = value
        elif not designation and field.get("fieldType") == "P" and not password:
            password = value
    if not password and str(details.get("password") or ""):
        password = str(details["password"])
    return username, password


def item_to_record(item: Mapping[str, Any], vault_name: str, *, source_row: int | None = None) -> ImportedRecord | None:
    overview = item.get("overview") if isinstance(item.get("overview"), dict) else {}
    details = item.get("details") if isinstance(item.get("details"), dict) else {}
    category = str(item.get("categoryUuid") or "001")
    title = str(overview.get("title") or "")
    urls: list[str] = []
    if overview.get("url"):
        urls.append(str(overview["url"]))
    for entry in as_list(overview.get("urls")):
        if isinstance(entry, dict) and entry.get("url") and str(entry["url"]) not in urls:
            urls.append(str(entry["url"]))
    folder = vault_name
    if str(item.get("state") or "").casefold() == "archived":
        folder = f"{vault_name}/Archive" if vault_name else "Archive"
    base = {
        "title": title, "notes": str(details.get("notesPlain") or ""), "folder": folder,
        "favorite": bool(item.get("favIndex")), "created": parse_timestamp(item.get("createdAt")),
        "modified": parse_timestamp(item.get("updatedAt")), "tags": [str(tag) for tag in as_list(overview.get("tags"))],
        "source_row": source_row,
    }
    if category in CATEGORY_NOTE:
        record = ImportedRecord(kind="note", **base)
    elif category in CATEGORY_IDENTITY:
        record = ImportedRecord(kind="identity", **base)
    elif category in CATEGORY_CARD:
        record = ImportedRecord(kind="card", **base)
    elif category in CATEGORY_LOGIN:
        username, password = _login_fields(details)
        record = ImportedRecord(kind="login", username=username, password=password, urls=urls, **base)
    else:
        record = ImportedRecord(kind="note", **base)
        add_custom_field(record, "1Password category", CATEGORY_NAMES.get(category, category))
    for section in as_list(details.get("sections")):
        if not isinstance(section, dict):
            continue
        for field in as_list(section.get("fields")):
            if not isinstance(field, dict):
                continue
            field_id = str(field.get("id") or "").casefold()
            label = str(field.get("title") or field.get("id") or "")
            value_type, text = _field_value(field.get("value"))
            if not text:
                continue
            if value_type == "totp":
                if not record.totp_uri:
                    record.totp_uri = totp_uri_from_secret(text, label=title)
                continue
            if record.kind == "identity":
                if value_type == "address" and isinstance(field.get("value", {}).get("address"), dict):
                    address = field["value"]["address"]
                    for key, target in _ADDRESS_KEYS.items():
                        if address.get(key):
                            record.identity[target] = str(address[key])
                    continue
                target = _IDENTITY_IDS.get(field_id)
                if target and not record.identity.get(target):
                    record.identity[target] = text
                    continue
            if record.kind == "card" and field_id in _CARD_IDS and not record.card.get(_CARD_IDS[field_id]):
                value = card_expiry(text) if field_id == "expiry" else text
                if value:
                    record.card[_CARD_IDS[field_id]] = value
                    continue
            if record.kind == "login" and field_id in {"username", "password"} and not getattr(record, field_id):
                setattr(record, field_id, text)
                continue
            if value_type == "url" and record.kind == "login":
                if text not in record.urls:
                    record.urls.append(text)
                continue
            hidden = value_type in {"concealed", "creditCardNumber", "sshKey"} or bool(field.get("guarded")) \
                or any(hint in field_id or hint in label.casefold() for hint in _SENSITIVE_HINTS)
            add_custom_field(record, label, text, hidden=hidden)
    if record.kind == "identity":
        name = " ".join(record.identity.get(key, "") for key in ("given_name", "middle_name", "family_name")).strip()
        if name:
            record.identity.setdefault("name", " ".join(name.split()))
    if category == "006" or details.get("documentAttributes"):
        add_custom_field(record, "Attached file", "The file itself was not imported. Save it from 1Password and "
                         "add it to LocalGateKeys as a document.")
    # Historical passwords (details.passwordHistory) are intentionally not imported.
    return record


def records_from_export(document: Mapping[str, Any]) -> ImportResult:
    accounts = document.get("accounts")
    if not isinstance(accounts, list):
        raise OnePasswordError(t("onepassword.exportDataHasNoAccounts"))
    result = ImportResult("1pux")
    trashed = 0
    index = 0
    for account in accounts:
        if not isinstance(account, dict):
            continue
        for vault in as_list(account.get("vaults")):
            if not isinstance(vault, dict):
                continue
            attrs = vault.get("attrs") if isinstance(vault.get("attrs"), dict) else {}
            vault_name = str(attrs.get("name") or "")
            for item in as_list(vault.get("items")):
                index += 1
                check_record_count(index)
                if not isinstance(item, dict):
                    result.diagnostics.append(t("bitwarden.itemNotAnObjectSkipped", index=index))
                    continue
                if item.get("trashed") or str(item.get("state") or "").casefold() == "trashed":
                    trashed += 1
                    continue
                record = item_to_record(item, vault_name, source_row=index)
                if record is not None:
                    result.records.append(record)
    if trashed:
        result.diagnostics.append(t("onepassword.itemsInThe1passwordTrash", trashed=trashed))
    result.records = enforce_record_limit(result.records)
    return result


def read_export_data(source: Path | str | bytes) -> dict[str, Any]:
    """Return the parsed ``export.data`` JSON from a 1PUX zip (or raw JSON)."""
    data = read_source_bytes(source, limit=MAX_EXPORT_BYTES)
    if data[:2] == b"PK":
        try:
            with zipfile.ZipFile(io.BytesIO(data)) as archive:
                names = {info.filename: info for info in archive.infolist()}
                info = names.get("export.data")
                if info is None:
                    raise OnePasswordError(t("onepassword.t1puxArchiveDoesNotContain"))
                if info.file_size > MAX_EXPORT_DATA_BYTES:
                    raise OnePasswordError(t("onepassword.exportDataIsTooLarge"))
                if info.flag_bits & 0x1:
                    raise OnePasswordError(t("onepassword.exportDataIsEncryptedInside"))
                if info.compress_type not in _SUPPORTED_ZIP_METHODS:
                    raise OnePasswordError(t("onepassword.exportDataUsesAnUnsupported"))
                with archive.open(info) as handle:
                    raw = read_bounded(handle, MAX_EXPORT_DATA_BYTES)
        except OnePasswordError:
            raise
        except (zipfile.BadZipFile, zipfile.LargeZipFile, RuntimeError, NotImplementedError, OSError, EOFError,
                ValueError, zlib.error) as exc:
            # zipfile signals encrypted members (RuntimeError), unknown methods
            # (NotImplementedError) and truncated/corrupt streams through many
            # exception types; all are a malformed export, not a crash.
            raise OnePasswordError(t("onepassword.t1puxArchiveIsCorruptedOr")) from exc
    else:
        raw = data
    if len(raw) > MAX_EXPORT_DATA_BYTES:
        raise OnePasswordError(t("onepassword.exportDataIsTooLarge"))
    try:
        document = json.loads(decode_text(raw))
    except (ValueError, RecursionError) as exc:
        raise OnePasswordError(t("onepassword.exportDataIsNotValid")) from exc
    if not isinstance(document, dict):
        raise OnePasswordError(t("onepassword.exportDataIsNotA"))
    return document


def load_1pux(source: Path | str | bytes) -> ImportResult:
    return records_from_export(read_export_data(source))


ONEPASSWORD_CSV_COLUMNS = ("title", "url", "username", "password", "otpauth", "favorite", "archived", "tags", "notes")


def load_1password_csv(source: Path | str | bytes) -> ImportResult:
    """Load the 1Password 8 CSV export (also accepts 1Password 7 column names)."""
    header, rows = read_csv_table(decode_text(read_source_bytes(source)))
    result = ImportResult("1password-csv", fields=tuple(header))
    for row in rows:
        number = int(row["__row__"])
        title = pick(row, "title")
        url = pick(row, "url", "website", "urls")
        username = pick(row, "username")
        password = pick(row, "password")
        notes = pick(row, "notes", "notesplain")
        if not (url or username or password):
            record = ImportedRecord(kind="note", title=title, notes=notes, source_row=number)
        else:
            record = ImportedRecord(kind="login", title=title or url, username=username, password=password,
                                    urls=[url] if url else [], notes=notes,
                                    totp_uri=totp_uri_from_secret(pick(row, "otpauth", "one-time password", "totp"), label=title),
                                    source_row=number)
        record.favorite = truthy(pick(row, "favorite"))
        if truthy(pick(row, "archived")):
            record.folder = "Archive"
        record.tags = [tag.strip() for tag in pick(row, "tags").replace(";", ",").split(",") if tag.strip()]
        result.records.append(record)
        check_record_count(len(result.records))
    result.records = enforce_record_limit(result.records)
    return result


__all__ = ["CATEGORY_NAMES", "ONEPASSWORD_CSV_COLUMNS", "OnePasswordError", "item_to_record", "load_1password_csv",
           "load_1pux", "read_export_data", "records_from_export"]
