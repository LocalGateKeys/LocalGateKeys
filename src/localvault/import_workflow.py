"""Review-first, source-bound import workflow over :class:`ImportedRecord` lists.

The format readers in :mod:`localvault.importers` normalise third-party
exports into records.  This module turns records into a reviewable
:class:`ImportPlan`:

* :func:`inspect_source` - non-secret information about a file (format,
  columns, row count, whether a password is needed),
* :func:`build_import_plan` - load a file and plan it against the vault,
* :func:`plan_records` - plan an in-memory record list (UI column mapping,
  KDBX decrypted elsewhere, tests),
* :meth:`ImportPlan.set_decision` - ``skip``/``add``/``replace``/``merge``/
  ``keep_both`` with per-field choices (``label``, ``password``, ``details``),
* :func:`apply_import_plan` - revalidate and apply inside one vault
  transaction; any failure or cancellation rolls everything back.

Website logins become ``web`` credentials (with every website URL, notes,
TOTP, custom fields, tags and favourite).  Notes, identities and payment cards
become typed catalog items in a collection named after the source folder.
Nothing readable is dropped: a login without a usable website or password, a
card that fails validation and values a typed item cannot hold are kept in
secure notes.  Plans never expose secrets through ``repr`` and wipe them once
applied or cancelled.
"""
from __future__ import annotations

import hashlib
import json
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from .importers import (
    MAX_RECORDS,
    MAX_SOURCE_BYTES,
    ImportedRecord,
    ImporterError,
    ImportFormatError,
    ImportResult,
    cap_diagnostics,
)
from .importers._source import decode_text, normalize_header, read_bounded, read_csv_table
from .importers.chrome import guess_mapping
from .importers.detect import (
    CSV_FORMATS,
    PASSWORD_FORMATS,
    SUPPORTED_FORMATS,
    detect_format,
    load_records,
)
from .item_schema import (
    IDENTITY_FIELD_LIMITS,
    IDENTITY_MAX_TOTAL,
    MAX_NOTE_BODY,
    ItemSchemaError,
    validate_card_fields,
)
from .origin import OriginError, canonicalize_origin, origin_of
from .totp import TotpError, parse_otpauth_uri
from .vault import ItemLimitReached, VaultError, VaultLockedError, free_item_slots

MAX_IMPORT_ROWS = MAX_RECORDS
MASK = "********"
DECISIONS = ("skip", "add", "replace", "merge", "keep_both")
MAX_ARCHIVE_BYTES = 64 * 1024 * 1024
_MAX_WEB_URLS = 20
_MAX_FIELDS, _MAX_FIELD_VALUE, _MAX_FIELD_NAME = 50, 4096, 100
_MAX_COLLECTION_NAME = 100
_LOOPBACK_HOSTS = frozenset({"localhost", "127.0.0.1", "[::1]", "::1"})
MERGE_FIELDS = ("label", "password", "details")
_MAX_TAGS, _MAX_TAG_LENGTH, _MAX_TITLE = 20, 40, 512
_KNOWN_EXTRA_COLUMNS = frozenset({
    "type", "reprompt", "fields", "httprealm", "formactionorigin", "guid", "timecreated", "timelastused",
    "timepasswordchanged", "archived", "tags", "username2", "category", "otpurl", "otpauth", "fav", "notesplain",
    "last modified", "created", "modified", "last used", "icon", "modified time", "created time",
    "vault", "createtime", "modifytime", "username3", "otpsecret", "email",
})


class ImportWorkflowError(ImporterError):
    """A reviewed import cannot be planned or applied safely."""


class ImportCancelled(ImportWorkflowError):
    """The caller cancelled before the atomic transaction completed."""


# --------------------------------------------------------------------------- source inspection
def _read_source(path: Path) -> tuple[bytes, str]:
    """Read a bounded source: 8 MiB for text exports, 64 MiB for zip archives."""
    path = Path(path)
    try:
        if path.stat().st_size > MAX_ARCHIVE_BYTES:
            raise ImportWorkflowError("Import file exceeds 64 MiB")
        with path.open("rb") as handle:
            data = read_bounded(handle, MAX_ARCHIVE_BYTES)
    except ImportWorkflowError:
        raise
    except OSError as exc:
        raise ImportWorkflowError("Could not read the import source") from exc
    if len(data) > MAX_ARCHIVE_BYTES:
        raise ImportWorkflowError("Import file exceeds 64 MiB")
    if len(data) > MAX_SOURCE_BYTES and data[:2] != b"PK":
        raise ImportWorkflowError("Import file exceeds 8 MiB; only zip exports may be larger")
    return data, hashlib.sha256(data).hexdigest()


def _csv_schema(data: bytes) -> tuple[tuple[str, ...], tuple[str, ...], tuple[str, ...], int]:
    header, rows = read_csv_table(decode_text(data))
    mapping = guess_mapping(header)
    mapped = tuple(f"{target}:{column}" for target, column in mapping.items())
    unmapped = tuple(column for column in header
                     if column not in mapping.values() and normalize_header(column) not in _KNOWN_EXTRA_COLUMNS)
    return tuple(header), mapped, unmapped, len(rows)


@dataclass(frozen=True)
class SourceInspection:
    """Non-secret source information suitable for an ordinary preview."""

    path: Path | None
    source_format: str
    source_hash: str
    size_bytes: int
    fields: tuple[str, ...] = ()
    mapping: tuple[str, ...] = ()
    unmapped: tuple[str, ...] = ()
    row_count: int = 0
    issues: tuple[str, ...] = ()
    needs_password: bool = False

    @property
    def format(self) -> str:
        return self.source_format

    @property
    def hash(self) -> str:
        return self.source_hash

    @property
    def label(self) -> str:
        return SUPPORTED_FORMATS.get(self.source_format, self.source_format)

    @property
    def is_csv(self) -> bool:
        return self.source_format in CSV_FORMATS


def inspect_source(path: Path | str, *, source_format: str | None = None) -> SourceInspection:
    """Inspect a supported source without returning any source secret.

    Encrypted sources (``kdbx``, password-protected Bitwarden JSON) report
    ``needs_password`` and a ``row_count`` of 0; plain sources are parsed once
    so the row count matches what :func:`build_import_plan` will show.
    """
    path = Path(path)
    data, digest = _read_source(path)
    detection = detect_format(path, data)
    fmt = source_format or detection.format
    if fmt not in SUPPORTED_FORMATS:
        raise ImportWorkflowError(f"Unsupported import format {fmt!r}")
    fields, mapping, unmapped, row_count = detection.fields, (), (), 0
    issues: list[str] = []
    if fmt in CSV_FORMATS:
        fields, mapping, unmapped, row_count = _csv_schema(data)
    elif fmt not in PASSWORD_FORMATS:
        result = load_records(path, source_format=fmt)
        row_count = len(result)
        issues.extend(result.diagnostics)
        result.wipe()
    if row_count > MAX_IMPORT_ROWS:
        raise ImportWorkflowError(f"At most {MAX_IMPORT_ROWS:,} records per import")
    return SourceInspection(path, fmt, digest, len(data), fields, mapping, unmapped, row_count, tuple(issues),
                            needs_password=fmt in PASSWORD_FORMATS)


# --------------------------------------------------------------------------- record normalisation
def canonical_origin_for(value: str) -> str:
    """Canonical origin for a URL; rejects embedded credentials.

    Raises only :class:`OriginError`: ``urlsplit`` signals malformed brackets
    (``https://[::1``) with a bare ``ValueError``.
    """
    text = str(value).strip()
    try:
        parsed = urlsplit(text)
        parsed.port  # noqa: B018 - an out-of-range or non-numeric port raises here
    except ValueError as exc:
        raise OriginError("Invalid IPv6 URL" if "[" in text or "]" in text else "URL is malformed") from exc
    if parsed.username or parsed.password:
        raise OriginError("URLs containing embedded credentials are unsupported")
    return canonicalize_origin(f"{parsed.scheme}://{parsed.netloc}")


def _web_url(value: str) -> tuple[str, bool]:
    """Return (canonical origin, upgraded-from-http) for a website URL, or ("", False).

    Bare hosts (``example.com/login``) get ``https://``; plain ``http://``
    sites are upgraded to ``https://`` because the vault only fills over
    HTTPS (loopback hosts keep HTTP).  Anything else (app links, ``ftp://``,
    malformed text) is not a website.
    """
    text = str(value).strip()
    if not text or any(ch.isspace() for ch in text) or len(text) > 2048:
        return "", False
    if "://" not in text:
        host = text.split("/", 1)[0]
        if "." not in host or host.startswith(".") or "@" in host:
            return "", False
        text = "https://" + text
    upgraded = False
    try:
        parts = urlsplit(text)
        if parts.username is not None or parts.password is not None:
            return "", False
        if parts.scheme.casefold() == "http" and (parts.hostname or "").casefold() not in _LOOPBACK_HOSTS:
            text = "https://" + text.split("://", 1)[1]
            upgraded = True
        return canonical_origin_for(origin_of(text)), upgraded
    except (ValueError, OriginError):
        return "", False


def _first_origin(record: ImportedRecord) -> str:
    for url in record.urls:
        origin, _upgraded = _web_url(url)
        if origin:
            return origin
    return ""


def _web_rows(record: ImportedRecord) -> tuple[str, list[dict[str, str]], list[str], bool]:
    """Split ``record.urls`` into (primary origin, URL rows, non-web URLs, any upgraded)."""
    rows: list[dict[str, str]] = []
    other: list[str] = []
    upgraded_any = False
    for url in record.urls:
        origin, upgraded = _web_url(url)
        if not origin:
            other.append(str(url))
            continue
        upgraded_any = upgraded_any or upgraded
        row = {"url": origin, "match": "exact_origin"}
        if row not in rows:
            rows.append(row)
    if len(rows) > _MAX_WEB_URLS:
        other.extend(row["url"] for row in rows[_MAX_WEB_URLS:])
        rows = rows[:_MAX_WEB_URLS]
    return (rows[0]["url"] if rows else ""), rows, other, upgraded_any


def _add_field(record: ImportedRecord, name: str, value: str, *, hidden: bool = False) -> bool:
    if not value:
        return True
    if len(record.custom_fields) >= _MAX_FIELDS:
        return False
    record.custom_fields.append({"name": name[:100], "value": value[:_MAX_FIELD_VALUE], "hidden": hidden})
    return len(value) <= _MAX_FIELD_VALUE


def _fit_notes(record: ImportedRecord, number: int, issues: list[str], limit: int = MAX_NOTE_BODY) -> None:
    """Keep notes longer than the vault limit by moving the overflow into custom fields."""
    if len(record.notes) <= limit:
        return
    overflow = record.notes[limit:]
    record.notes = record.notes[:limit]
    part = 1
    while overflow and len(record.custom_fields) < _MAX_FIELDS:
        record.custom_fields.append({"name": f"Notes (continued {part})", "value": overflow[:_MAX_FIELD_VALUE],
                                     "hidden": False})
        overflow = overflow[_MAX_FIELD_VALUE:]
        part += 1
    if overflow:
        issues.append(f"Row {number}: notes are longer than the vault allows; the last {len(overflow):,} "
                      "characters were not imported.")


def _fit_fields(record: ImportedRecord, number: int, issues: list[str]) -> None:
    """Hold custom fields to the vault's item_schema limits (50 fields, 100-character names, 4,096-character values)."""
    clean = []
    for field_value in record.custom_fields[:_MAX_FIELDS]:
        name = str(field_value.get("name", ""))[:_MAX_FIELD_NAME]
        value = str(field_value.get("value", ""))
        if len(value) > _MAX_FIELD_VALUE:
            issues.append(f"Row {number}: custom field {name!r} was shortened to {_MAX_FIELD_VALUE:,} characters.")
            value = value[:_MAX_FIELD_VALUE]
        clean.append({**field_value, "name": name, "value": value})
    record.custom_fields = clean


def _has_null(record: ImportedRecord) -> bool:
    values = [record.title, record.username, record.password, record.notes, record.totp_uri, record.folder,
              *record.urls, *record.identity.values(), *record.card.values()]
    for field_value in record.custom_fields:
        values.extend((str(field_value.get("name", "")), str(field_value.get("value", ""))))
    return any("\x00" in str(value) for value in values)


def _folder_tag(folder: str) -> str:
    text = " / ".join(part.strip() for part in str(folder).replace("\\", "/").split("/") if part.strip())
    return text[-_MAX_TAG_LENGTH:].strip()


def _clean_tags(tags: Iterable[str]) -> list[str]:
    result: list[str] = []
    for tag in tags:
        text = str(tag).strip()[:_MAX_TAG_LENGTH]
        if text and text not in result:
            result.append(text)
    return result[:_MAX_TAGS]


def _title(record: ImportedRecord, number: int, fallback: str = "") -> str:
    text = (record.title or fallback or record.username or record.url or f"Imported row {number}").strip()
    return text[:_MAX_TITLE] or f"Imported row {number}"


def totp_dict(uri: str) -> dict[str, Any] | None:
    """Vault ``totp`` mapping for an ``otpauth://`` URI, or ``None`` if invalid."""
    if not uri:
        return None
    try:
        parsed = parse_otpauth_uri(uri)
    except (TotpError, ValueError):
        return None
    return {"secret": parsed["secret"], "digits": int(parsed["digits"]), "period": int(parsed["period"]),
            "algorithm": str(parsed["algorithm"])}


def _login_as_note(record: ImportedRecord, number: int, *, title: str = "") -> ImportedRecord:
    """A secure note that keeps every value of a login (or a login copy)."""
    fields = []
    for index, url in enumerate(record.urls):
        fields.append({"name": "Website" if index == 0 else f"Website {index + 1}", "value": str(url)[:_MAX_FIELD_VALUE],
                       "hidden": False})
    if record.username:
        fields.append({"name": "Username", "value": record.username[:_MAX_FIELD_VALUE], "hidden": False})
    if record.password:
        fields.append({"name": "Password", "value": record.password[:_MAX_FIELD_VALUE], "hidden": True})
    if record.totp_uri:
        fields.append({"name": "One-time password (otpauth)", "value": record.totp_uri[:_MAX_FIELD_VALUE],
                       "hidden": True})
    fields.extend(record.custom_fields)
    return ImportedRecord(kind="note", title=title or _title(record, number), notes=record.notes,
                          custom_fields=fields[:_MAX_FIELDS], folder=record.folder, favorite=record.favorite,
                          tags=record.tags, created=record.created, modified=record.modified,
                          source_row=record.source_row)


def _card_as_note(record: ImportedRecord, number: int) -> ImportedRecord:
    labels = (("cardholder", "Cardholder", False), ("number", "Card number", True), ("expiry", "Expiry", False),
              ("cvv", "Security code", True), ("pin", "PIN", True), ("brand", "Brand", False))
    fields = [{"name": label, "value": record.card[key], "hidden": hidden}
              for key, label, hidden in labels if record.card.get(key)]
    fields.extend(record.custom_fields)
    return ImportedRecord(kind="note", title=_title(record, number), notes=record.notes,
                          custom_fields=fields[:_MAX_FIELDS], folder=record.folder, favorite=record.favorite,
                          tags=record.tags, created=record.created, modified=record.modified,
                          source_row=record.source_row)


def card_payload(record: ImportedRecord) -> dict[str, Any]:
    """The validated vault ``card`` payload for a card record (raises ItemSchemaError)."""
    card = record.card
    expiry = card.get("expiry", "")
    month, _sep, year = expiry.partition("/")
    if len(year) == 4:
        expiry = f"{month}/{year[2:]}" if year.startswith("20") else expiry
    return validate_card_fields({
        "cardholder": card.get("cardholder", ""), "number": card.get("number", ""), "expiry": expiry,
        "cvv": card.get("cvv", ""), "pin": card.get("pin", ""), "notes": record.notes,
    })


def _companion(record: ImportedRecord, title: str, fields: list[dict[str, Any]], notes: str = "") -> ImportedRecord | None:
    """A secure note holding values a typed item cannot store (identity extras, card extras)."""
    if not fields and not notes:
        return None
    return ImportedRecord(kind="note", title=f"{title} (extra details)"[:_MAX_TITLE], notes=notes,
                          custom_fields=fields[:_MAX_FIELDS], folder=record.folder, tags=record.tags,
                          source_row=record.source_row)


def _item_digest(item: Mapping[str, Any]) -> str:
    payload = {"id": str(item.get("id", "")), "kind": str(item.get("kind", "")), "title": str(item.get("title", "")),
               "updated_at": int(item.get("updated_at", 0) or 0), "payload": item.get("payload", {})}
    return hashlib.sha256(json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str).encode()).hexdigest()


def _target_digest(entry: Mapping[str, Any]) -> str:
    """Stable guard for a web credential without putting the password into diagnostics."""
    fields = {
        "id": str(entry.get("id", "")), "kind": str(entry.get("kind", "")),
        "origin": str(entry.get("scope", {}).get("origin", "")) if isinstance(entry.get("scope"), dict) else "",
        "username": str(entry.get("username", "")), "label": str(entry.get("label", "")),
        "password": str(entry.get("password", "")), "updated_at": int(entry.get("updated_at", 0) or 0),
    }
    return hashlib.sha256(json.dumps(fields, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def _profile_generation(session: Any) -> str:
    value = getattr(session, "workspace_session_generation", None)
    if not isinstance(value, str) or not value:
        value = getattr(session, "profile_generation", None)
    if not isinstance(value, str) or not value:
        value = f"session:{id(session)}"
    return value


@dataclass
class ImportRowPlan:
    """One normalised record in a reviewed plan; secrets are never repr'd.

    ``kind`` is ``login`` (a website credential), ``note``, ``identity`` or
    ``card``.  ``status`` is ``new``, ``duplicate`` (same data already
    present, or a repeat inside the import when ``target_id`` is ``None``) or
    ``conflict``.  ``web_urls`` are the login's URL rows; ``extra`` is a
    companion secure note for values the typed item cannot hold.
    """

    row: int
    kind: str
    record: ImportedRecord = field(repr=False)
    origin: str = ""
    status: str = "new"
    decision: str = "skip"
    target_id: str | None = None
    target_revision: str | None = None
    field_decisions: dict[str, str] = field(default_factory=dict)
    target_label: str = ""
    target_password_present: bool = False
    web_urls: list[dict[str, str]] = field(default_factory=list)
    extra: ImportedRecord | None = field(default=None, repr=False)
    limited: bool = False

    @property
    def new_items(self) -> int:
        """Live items this row's decision creates (the free plan slots it needs).

        Adds and keep-both copies create the record, plus a card's or
        identity's "extra details" note.  Replace and merge update an existing
        record and need a slot only for an extra details note they bring.
        """
        if self.decision == "skip":
            return 0
        extra = 1 if self.extra is not None else 0
        if self.decision in {"add", "keep_both"}:
            return 1 + (extra if self.kind != "login" else 0)
        if self.kind != "login" and self.field_decisions.get("details") == "import":
            return extra
        return 0

    @property
    def state(self) -> str:
        """The decision as shown in the preview: ``limited`` when the free plan has no slot for it."""
        return "limited" if self.limited else self.decision

    @property
    def label(self) -> str:
        return self.record.title

    @property
    def title(self) -> str:
        return self.record.title

    @property
    def username(self) -> str:
        return self.record.username

    @property
    def password(self) -> str:
        return self.record.password

    @property
    def masked_password(self) -> str:
        return MASK if self.record.password else ""

    @property
    def password_mask(self) -> str:
        return self.masked_password

    @property
    def has_totp(self) -> bool:
        return bool(self.record.totp_uri)

    @property
    def in_import_duplicate(self) -> bool:
        return self.status == "duplicate" and self.target_id is None

    @property
    def changes(self) -> tuple[str, ...]:
        return tuple(sorted(key for key, value in self.field_decisions.items() if value == "import"))

    def review_view(self) -> dict[str, Any]:
        target_password = MASK if self.target_password_present else ""
        selected = {key: self.field_decisions.get(key) == "import" for key in MERGE_FIELDS}
        return {
            "row": self.row, "kind": self.kind, "label": self.label, "origin": self.origin, "username": self.username,
            "status": self.status, "decision": self.decision, "limited": self.limited, "state": self.state,
            "target_id": self.target_id,
            "password": self.masked_password, "target_password": target_password, "has_totp": self.has_totp,
            "folder": self.record.folder,
            "fields": {
                "label": {"source": self.label, "target": self.target_label, "selected": selected["label"]},
                "password": {"source": self.masked_password, "target": target_password, "selected": selected["password"]},
                "details": {"source": self._details_summary(), "target": "", "selected": selected["details"]},
            },
        }

    def _details_summary(self) -> str:
        parts = []
        if self.record.notes:
            parts.append("notes")
        if self.record.totp_uri:
            parts.append("one-time password")
        if self.record.custom_fields:
            parts.append(f"{len(self.record.custom_fields)} custom fields")
        if self.record.identity:
            parts.append(f"{len(self.record.identity)} identity fields")
        if self.record.card:
            parts.append("card details")
        if len(self.web_urls) > 1:
            parts.append(f"{len(self.web_urls)} websites")
        if self.extra is not None:
            parts.append("extra details note")
        if self.record.tags:
            parts.append("tags")
        return ", ".join(parts)

    def __repr__(self) -> str:
        return (f"ImportRowPlan(row={self.row!r}, kind={self.kind!r}, label={self.label!r}, origin={self.origin!r}, "
                f"username={self.username!r}, status={self.status!r}, decision={self.decision!r})")


def normalise_records(records: Iterable[ImportedRecord]) -> tuple[list[ImportRowPlan], list[str]]:
    """Turn records into unclassified rows (all ``new``) plus diagnostics.

    Website logins keep ``kind="login"``; notes, identities and cards become
    catalog item rows.  Logins without a usable website or password, and
    cards that fail validation, become secure notes so no value is lost.  A
    repeated website account inside the import is ``duplicate``: skipped when
    identical, kept as a secure-note copy (``keep_both``) when it differs.
    """
    rows: list[ImportRowPlan] = []
    issues: list[str] = []
    seen: dict[tuple[str, str], tuple[int, str]] = {}
    upgraded_rows: list[int] = []
    for index, record in enumerate(records, 1):
        if not isinstance(record, ImportedRecord):
            raise ImportWorkflowError("Import sources must yield ImportedRecord objects")
        if len(rows) >= MAX_IMPORT_ROWS:
            raise ImportWorkflowError(f"At most {MAX_IMPORT_ROWS:,} records per import")
        number = record.source_row if record.source_row is not None else index
        if _has_null(record):
            issues.append(f"Row {number}: null characters in fields; skipped.")
            continue
        if record.folder:
            record.folder = record.folder.replace("\\", "/").strip("/ ")
        record.tags = _clean_tags(record.tags)
        _fit_fields(record, number, issues)
        if record.kind == "login":
            origin, web_rows, other_urls, upgraded = _web_rows(record)
            reason = ""
            if not origin:
                reason = "has no website address" if not record.urls else "has no usable website address"
            elif not record.password:
                reason = "has no password"
            elif len(record.password) > 4096 or len(record.username) > 512:
                issues.append(f"Row {number}: password or username is longer than the vault allows; skipped.")
                continue
            if reason:
                issues.append(f"Row {number}: login {reason}; imported as a secure note.")
                note = _login_as_note(record, number)
                _fit_notes(note, number, issues)
                rows.append(ImportRowPlan(number, "note", note, decision="add"))
                continue
            if upgraded:
                upgraded_rows.append(number)
            for url in other_urls:
                # A URL with embedded credentials stays hidden like a password.
                hidden = "@" in url.split("://", 1)[-1].split("/", 1)[0]
                if not _add_field(record, "Other website or app", url, hidden=hidden):
                    issues.append(f"Row {number}: too many custom fields; an extra address was not imported.")
            if record.totp_uri and totp_dict(record.totp_uri) is None:
                issues.append(f"Row {number}: one-time password secret is not valid; kept as a hidden custom field.")
                _add_field(record, "One-time password (unrecognised)", record.totp_uri, hidden=True)
                record.totp_uri = ""
            folder_tag = _folder_tag(record.folder)
            if folder_tag:
                record.tags = _clean_tags([*record.tags, folder_tag])
            _fit_notes(record, number, issues)
            record.title = _title(record, number, origin)
            row = ImportRowPlan(number, "login", record, origin=origin, decision="add", web_urls=web_rows)
            key = (origin, record.username)
            if key in seen:
                first, password = seen[key]
                row.status = "duplicate"
                if password == record.password:
                    row.decision = "skip"
                    issues.append(f"Row {number}: same account as row {first}; skipped.")
                else:
                    row.decision = "keep_both"
                    issues.append(f"Row {number}: same website and username as row {first} but a different password; "
                                  "it will be kept as a secure note copy (choose Skip to drop it).")
            else:
                seen[key] = (number, record.password)
            rows.append(row)
            continue
        if record.kind == "card":
            if record.card:
                try:
                    card_payload(record)
                except ItemSchemaError as exc:
                    issues.append(f"Row {number}: card details could not be stored as a payment card ({exc}); "
                                  "imported as a secure note.")
                    note = _card_as_note(record, number)
                    _fit_notes(note, number, issues)
                    rows.append(ImportRowPlan(number, "note", note, decision="add"))
                    continue
                record.title = _title(record, number)
                row = ImportRowPlan(number, "card", record, decision="add")
                row.extra = _companion(record, record.title, record.custom_fields)
                record.custom_fields = []
                rows.append(row)
                continue
            record = _card_as_note(record, number)
        if record.kind == "identity":
            extra_fields: list[dict[str, Any]] = []
            kept: dict[str, str] = {}
            total = 0
            for field_name, value in record.identity.items():
                limit = IDENTITY_FIELD_LIMITS.get(field_name)
                if limit is None or len(value) > limit or total + len(value) > IDENTITY_MAX_TOTAL:
                    extra_fields.append({"name": field_name.replace("_", " ").capitalize(),
                                         "value": value[:_MAX_FIELD_VALUE], "hidden": False})
                    continue
                kept[field_name] = value
                total += len(value)
            if extra_fields:
                names = ", ".join(sorted({item["name"].casefold() for item in extra_fields}))
                issues.append(f"Row {number}: identity values without a matching identity field ({names}) were kept "
                              "in an 'extra details' secure note.")
            record.identity = kept
            record.title = _title(record, number)
            row = ImportRowPlan(number, "identity", record, decision="add")
            row.extra = _companion(record, record.title, extra_fields + record.custom_fields, record.notes)
            if row.extra is not None:
                _fit_notes(row.extra, number, issues)
            rows.append(row)
            continue
        if record.kind != "note":
            record = ImportedRecord(kind="note", title=record.title, notes=record.notes, custom_fields=record.custom_fields,
                                    folder=record.folder, favorite=record.favorite, tags=record.tags, created=record.created,
                                    modified=record.modified, source_row=record.source_row)
        _fit_notes(record, number, issues)
        record.title = _title(record, number)
        rows.append(ImportRowPlan(number, "note", record, decision="add"))
    for row in rows:
        # Notes built above (card and login conversions, companions) carry
        # values that were never fitted; the preview must only accept rows
        # that apply_import_plan can write.
        _fit_fields(row.record, row.row, issues)
        if row.extra is not None:
            _fit_fields(row.extra, row.row, issues)
    if upgraded_rows:
        shown = ", ".join(str(number) for number in upgraded_rows[:10]) + (" ..." if len(upgraded_rows) > 10 else "")
        issues.append(f"{len(upgraded_rows)} login(s) used plain http:// addresses and were saved for https:// "
                      f"(rows {shown}); LocalGateKeys only fills passwords over HTTPS.")
    return rows, issues


def classify_rows(rows: Iterable[ImportRowPlan], entries: Iterable[Mapping[str, Any]],
                  items: Iterable[Mapping[str, Any]] = ()) -> dict[str, str]:
    """Set status/target against existing web credentials and catalog items; return target revisions."""
    existing = {(entry.get("scope", {}).get("origin"), entry.get("username")): entry
                for entry in entries if entry.get("kind") == "web" and isinstance(entry.get("scope"), dict)}
    catalog: dict[tuple[str, str], Mapping[str, Any]] = {}
    for item in items:
        catalog.setdefault((str(item.get("kind")), str(item.get("title", "")).casefold()), item)
    revisions: dict[str, str] = {}
    for row in rows:
        if row.in_import_duplicate:
            continue
        if row.kind == "login":
            entry = existing.get((row.origin, row.username))
            if entry is None:
                continue
            row.target_id = str(entry["id"])
            row.target_revision = _target_digest(entry)
            row.target_label = str(entry.get("label", ""))
            row.target_password_present = bool(entry.get("password"))
            row.status = "duplicate" if entry.get("password") == row.password else "conflict"
        else:
            item = catalog.get((row.kind, row.record.title.casefold()))
            if item is None:
                continue
            raw_payload = item.get("payload")
            payload: Mapping[str, Any] = raw_payload if isinstance(raw_payload, dict) else {}
            if row.kind == "note":
                same = payload.get("body", "") == row.record.notes and (payload.get("fields") or []) == row.record.custom_fields
            elif row.kind == "card":
                try:
                    wanted = card_payload(row.record)
                except ItemSchemaError:
                    wanted = {}
                same = all(payload.get(key, "") == wanted.get(key, "") for key in ("number", "expiry", "cardholder"))
            else:
                same = {k: v for k, v in payload.items() if k != "template_id"} == row.record.identity
            row.target_id = str(item["id"])
            row.target_revision = _item_digest(item)
            row.target_label = str(item.get("title", ""))
            row.status = "duplicate" if same else "conflict"
        row.decision = "skip"
        row.field_decisions = {"label": "keep", "password": "keep", "details": "keep"}
        revisions[row.target_id] = row.target_revision
    return revisions


# --------------------------------------------------------------------------- plans
@dataclass
class ImportPlan:
    source: SourceInspection | None
    rows: list[ImportRowPlan]
    profile_generation: str
    target_revisions: dict[str, str]
    source_path: Path | None
    issues: tuple[str, ...] = ()
    reviewed: bool = False
    cancelled: bool = False
    applied: bool = False
    free_slots: int | None = None
    item_limit: int | None = None

    def recompute_limits(self) -> int:
        """Mark rows beyond the free slots left as limited, in preview order; returns how many.

        Only rows that create new live items use slots; an update to an
        existing record never does.  With no limit (Pro) nothing is limited.
        """
        remaining = self.free_slots
        limited = 0
        for row in self.rows:
            needed = row.new_items
            row.limited = remaining is not None and needed > 0 and needed > remaining
            if row.limited:
                limited += 1
            elif remaining is not None:
                remaining -= needed
        return limited

    def new_item_count(self) -> int:
        """Live items the plan will create as reviewed (limited rows excluded)."""
        return sum(row.new_items for row in self.rows if not row.limited)

    def limit_note(self) -> str:
        """Review/result note for the free plan; empty when there is no limit."""
        if self.free_slots is None:
            return ""
        limited = sum(1 for row in self.rows if row.limited)
        if not limited:
            slots = self.free_slots
            return f"{slots} free slot{'' if slots == 1 else 's'} left on the free plan"
        imported = sum(1 for row in self.rows if row.decision != "skip" and not row.limited)
        return f"{imported} will be imported on the free plan; {limited} need Pro"

    def limit_summary(self) -> dict[str, Any]:
        """``item_limit`` and the limited rows, in the shape ``transfer_ui.notify_item_limit`` reads."""
        return {"item_limit": self.item_limit if self.free_slots is not None else None,
                "free_slots": self.free_slots,
                "limit_skipped_ids": [row.row for row in self.rows if row.limited]}

    @property
    def source_hash(self) -> str:
        return self.source.source_hash if self.source else ""

    @property
    def source_format(self) -> str:
        return self.source.source_format if self.source else "records"

    @property
    def generation(self) -> str:
        return self.profile_generation

    @property
    def preview(self) -> list[dict[str, Any]]:
        return [row.review_view() for row in self.rows]

    @property
    def diagnostics(self) -> tuple[str, ...]:
        return self.issues

    @property
    def records(self) -> list[ImportedRecord]:
        return [row.record for row in self.rows]

    def summary(self) -> dict[str, int]:
        counts = {decision: 0 for decision in DECISIONS}
        limited = 0
        for row in self.rows:
            if row.limited:
                limited += 1
            else:
                counts[row.decision] += 1
        skipped = sum(1 for issue in self.issues if issue.rstrip().endswith("skipped."))
        return {"total": len(self.rows), **counts, "limited": limited, "skipped_rows": skipped}

    def review(self) -> ImportPlan:
        if self.cancelled:
            raise ImportCancelled("Import plan was cancelled")
        self.reviewed = True
        return self

    approve = review
    confirm = review

    def cancel(self) -> None:
        self.cancelled = True
        self.reviewed = False
        self.wipe()

    def wipe(self) -> None:
        for row in self.rows:
            row.record.wipe()

    def find(self, row: int | ImportRowPlan) -> ImportRowPlan:
        if isinstance(row, ImportRowPlan):
            return row
        target = next((item for item in self.rows if item.row == row), None)
        if target is None:
            raise ImportWorkflowError("Unknown import row")
        return target

    def set_decision(self, row: int | ImportRowPlan, decision: str, *, fields: Mapping[str, str] | None = None) -> None:
        target = self.find(row)
        decision = str(decision).casefold()
        if decision == "update":
            decision = "replace"
        if decision in {"keep-both", "keepboth", "both"}:
            decision = "keep_both"
        if decision not in DECISIONS:
            raise ImportWorkflowError("Unknown import decision")
        if decision == "add" and target.status != "new":
            raise ImportWorkflowError("An existing account cannot be added without an explicit merge")
        if decision in {"replace", "merge", "keep_both"} and target.status == "new":
            raise ImportWorkflowError("Only an existing account can be replaced, merged or kept alongside")
        if target.in_import_duplicate and decision not in {"skip", "keep_both"}:
            raise ImportWorkflowError("A duplicate row inside the import can only be skipped or kept as a copy")
        target.decision = decision
        if fields is not None:
            selected = {str(key): str(value).casefold() for key, value in fields.items()}
            if any(key not in MERGE_FIELDS or value not in {"import", "keep"} for key, value in selected.items()):
                raise ImportWorkflowError("Unsupported field merge decision")
            target.field_decisions = {key: selected.get(key, "keep") for key in MERGE_FIELDS}
        elif decision in {"replace", "merge"}:
            target.field_decisions = {key: "import" for key in MERGE_FIELDS}
        self.recompute_limits()

    choose = set_decision

    def set_all(self, decision: str, *, statuses: Iterable[str] | None = None) -> int:
        """Apply ``decision`` to every row (optionally only rows with the given statuses)."""
        wanted = set(statuses) if statuses is not None else None
        count = 0
        for row in self.rows:
            if wanted is not None and row.status not in wanted:
                continue
            if decision == "add" and row.status != "new":
                continue
            if decision in {"replace", "merge"} and (row.status == "new" or row.in_import_duplicate):
                continue
            if decision == "keep_both" and row.status == "new":
                continue
            self.set_decision(row, decision)
            count += 1
        self.recompute_limits()
        return count

    def apply(self, session: Any, *, cancel: Callable[[], bool] | None = None) -> int:
        return apply_import_plan(session, self, cancel=cancel)


def _session_items(session: Any) -> list[dict[str, Any]]:
    items = getattr(session, "items", None)
    if items is None:
        return []
    result = []
    for summary in items.list_items():
        item = items.get_item(str(summary.get("id")), include_protected=True)
        if item is not None:
            result.append(item)
    return result


def _keep_totp_as_fields(session: Any, rows: list[ImportRowPlan]) -> list[str]:
    """On the free plan, keep imported two-factor keys as hidden custom fields.

    Two-factor codes are Pro-only.  The key is never dropped: it moves into a
    hidden field the user can paste into the two-factor field after upgrading.
    """
    allowed = getattr(session, "pro_features", None)
    if allowed is None or "totp" in allowed:
        return []
    kept = 0
    for row in rows:
        record = row.record
        if row.kind != "login" or not record.totp_uri:
            continue
        if _add_field(record, "Two-factor key (needs Pro)", record.totp_uri, hidden=True):
            record.totp_uri = ""
            kept += 1
    if not kept:
        return []
    return [f"Two-factor codes need LocalGateKeys Pro: {kept} key{'' if kept == 1 else 's'} "
            "kept as hidden custom fields."]


def plan_records(session: Any, records: Iterable[ImportedRecord], *, source: SourceInspection | None = None,
                 diagnostics: Iterable[str] = ()) -> ImportPlan:
    """Plan an in-memory record list against the unlocked ``session``."""
    if not getattr(session, "is_unlocked", False):
        raise VaultLockedError("Vault is locked")
    rows, issues = normalise_records(records)
    # Per-row messages are capped (first 50 plus "and N more") so a crafted
    # source cannot push thousands of strings into the review screen.
    issues = cap_diagnostics(issues) + _keep_totp_as_fields(session, rows)
    revisions = classify_rows(rows, session.all_entries(), _session_items(session))
    all_issues = tuple(cap_diagnostics(diagnostics) + issues)
    plan = ImportPlan(source, rows, _profile_generation(session), revisions, source.path if source else None, all_issues)
    plan.free_slots = free_item_slots(session)
    plan.item_limit = getattr(session, "item_limit", None) if plan.free_slots is not None else None
    plan.recompute_limits()
    return plan


def build_import_plan(session: Any, path: Path | str, *, password: str | None = None,
                      keyfile: bytes | Path | str | None = None, source_format: str | None = None,
                      column_mapping: Mapping[str, str] | None = None) -> ImportPlan:
    """Load a file with the format importers and plan it; nothing is applied.

    Raises :class:`localvault.importers.ImportPasswordRequired` when an
    encrypted source is opened without ``password``/``keyfile``, the
    importer's :class:`ImportPasswordError` for a wrong password and
    :class:`ImportFormatError` for malformed input.
    """
    if not getattr(session, "is_unlocked", False):
        raise VaultLockedError("Vault is locked")
    path = Path(path)
    source = inspect_source(path, source_format=source_format)
    result: ImportResult = load_records(path, password=password, keyfile=keyfile, source_format=source.source_format,
                                        column_mapping=column_mapping)
    try:
        return plan_records(session, result.records, source=source, diagnostics=result.diagnostics)
    finally:
        result.records = []


preview_import = build_import_plan
create_import_plan = build_import_plan
stage_import = build_import_plan


# --------------------------------------------------------------------------- apply
def _cancelled(plan: ImportPlan, cancel: Callable[[], bool] | None) -> bool:
    return plan.cancelled or (cancel is not None and bool(cancel()))


def _revalidate_source(plan: ImportPlan) -> None:
    if plan.source_path is None:
        return
    _data, digest = _read_source(plan.source_path)
    if digest != plan.source_hash:
        raise ImportWorkflowError("Import source changed after review")


class _Collections:
    """Resolve source folder names to vault collections, creating them on first use."""

    def __init__(self, session: Any):
        self.session = session
        self.ids: dict[str, str | None] = {}

    def ids_for(self, folder: str) -> list[str]:
        name = str(folder or "").strip()[:_MAX_COLLECTION_NAME].strip()
        if not name:
            return []
        key = name.casefold()
        if key not in self.ids:
            self.ids[key] = self._resolve(name)
        resolved = self.ids[key]
        return [resolved] if resolved else []

    def _resolve(self, name: str) -> str | None:
        service = getattr(self.session, "collections", None)
        if service is None:
            return None
        try:
            for row in service.list():
                if str(row.get("name", "")).strip().casefold() == name.casefold():
                    return str(row["id"])
            return str(service.create(name))
        except (ItemSchemaError, VaultError, AttributeError, KeyError):
            return None


def _create_item(session: Any, record: ImportedRecord, collections: _Collections) -> None:
    items = getattr(session, "items", None)
    if items is None:
        raise ImportWorkflowError("This vault cannot store notes, cards or identities")
    collection_ids = collections.ids_for(record.folder)
    tags = record.tags
    if record.folder and not collection_ids:
        tags = _clean_tags([*tags, _folder_tag(record.folder)])
    metadata = {"tags": tags, "favorite": record.favorite, "collection_ids": collection_ids}
    if record.kind == "identity":
        items.create_identity(record.title, record.identity, **metadata)
    elif record.kind == "card":
        payload = card_payload(record)
        items.create_card(record.title, cardholder=payload["cardholder"], number=payload["number"],
                          expiry=payload["expiry"], cvv=payload["cvv"], pin=payload["pin"], notes=payload["notes"],
                          **metadata)
    else:
        items.create_note(record.title, record.notes, fields=record.custom_fields, **metadata)


def _apply_login(session: Any, item: ImportRowPlan, collections: _Collections) -> bool:
    record = item.record
    if item.decision == "keep_both":
        _create_item(session, _login_as_note(record, item.row, title=f"{record.title} (imported copy)"[:_MAX_TITLE]),
                     collections)
        return True
    matches = [entry for entry in session.find_web(item.origin) if entry.get("username") == record.username]
    target = matches[0] if len(matches) == 1 else None
    if item.decision == "add":
        if matches:
            raise ImportWorkflowError("Import target changed after review")
        totp = totp_dict(record.totp_uri)
        create = getattr(session, "create_web_login", None)
        if create is not None and getattr(session, "items", None) is not None:
            create(urls=item.web_urls or [{"url": item.origin, "match": "exact_origin"}], username=record.username,
                   password=record.password, label=record.title, favorite=record.favorite, tags=record.tags,
                   notes=record.notes, totp=totp, custom_fields=record.custom_fields)
            return True
        entry_id = session.upsert_web(origin=item.origin, username=record.username, password=record.password,
                                      label=record.title)
        if record.notes or record.totp_uri or record.custom_fields or record.favorite or record.tags:
            session.set_details(entry_id, favorite=record.favorite, tags=record.tags, notes=record.notes,
                                totp=totp, custom_fields=record.custom_fields)
        return True
    if target is None or target.get("id") != item.target_id:
        raise ImportWorkflowError("Import target changed after review")
    if item.target_revision != _target_digest(target):
        raise ImportWorkflowError("Import target revision changed after review")
    fields = item.field_decisions
    label = record.title if fields.get("label") == "import" else None
    password = record.password if fields.get("password") == "import" else None
    details = fields.get("details") == "import"
    if label is None and password is None and not details:
        return False
    if label is not None or password is not None:
        session.update_entry_fields(str(target["id"]), label=label, password=password)
    if details:
        tags = _clean_tags(list(target.get("tags") or []) + list(record.tags))
        session.set_details(
            str(target["id"]), favorite=bool(record.favorite or target.get("favorite")), tags=tags,
            notes=record.notes or str(target.get("notes") or ""),
            totp=totp_dict(record.totp_uri) or target.get("totp"),
            recovery_codes=list(target.get("recovery_codes") or []), policy=target.get("policy"),
            custom_fields=record.custom_fields or list(target.get("custom_fields") or []),
        )
        items = getattr(session, "items", None)
        if items is not None and len(item.web_urls) > 1:
            existing = [row for row in items.web_urls(str(target["id"]))]
            merged = existing + [row for row in item.web_urls if row not in existing]
            items.set_web_urls(str(target["id"]), merged[:_MAX_WEB_URLS])
    return True


def _apply_item(session: Any, item: ImportRowPlan, collections: _Collections) -> bool:
    record = item.record
    items = getattr(session, "items", None)
    if items is None:
        raise ImportWorkflowError("This vault cannot store notes, cards or identities")
    if item.decision in {"add", "keep_both"}:
        _create_item(session, record, collections)
        if item.extra is not None:
            _create_item(session, item.extra, collections)
        return True
    target = items.get_item(item.target_id or "", include_protected=True)
    if target is None or target.get("kind") != record.kind:
        raise ImportWorkflowError("Import target changed after review")
    if item.target_revision != _item_digest(target):
        raise ImportWorkflowError("Import target revision changed after review")
    fields = item.field_decisions
    title = record.title if fields.get("label") == "import" else None
    details = fields.get("details") == "import"
    if title is None and not details:
        return False
    tags = _clean_tags(list(target.get("tags") or []) + list(record.tags)) if details else None
    favorite = bool(record.favorite or target.get("favorite")) if details else None
    if record.kind == "identity":
        items.update_identity(item.target_id, record.identity if details else None, title=title, tags=tags, favorite=favorite)
    elif record.kind == "card":
        items.update_typed_item(item.target_id, payload=card_payload(record) if details else None, title=title,
                                tags=tags, favorite=favorite)
    else:
        items.update_item(item.target_id, title=title, body=record.notes if details else None,
                          fields=record.custom_fields if details else None, tags=tags, favorite=favorite)
    if details and item.extra is not None:
        _create_item(session, item.extra, collections)
    return True


def item_limit_cause(error: BaseException | None) -> ItemLimitReached | None:
    """The free plan limit behind an import failure, if that is what stopped it."""
    seen: set[int] = set()
    while error is not None and id(error) not in seen:
        if isinstance(error, ItemLimitReached):
            return error
        seen.add(id(error))
        error = error.__cause__
    return None


def free_slots_note(session: Any) -> str:
    """Review-summary note on the free slots left; empty when there is no limit."""
    slots = free_item_slots(session)
    if slots is None:
        return ""
    return f"{slots} free slot{'' if slots == 1 else 's'} left on the free plan"


def apply_import_plan(session: Any, plan: ImportPlan, *, cancel: Callable[[], bool] | None = None) -> int:
    """Revalidate and atomically apply a reviewed plan; returns the number of records written.

    Every target is re-read while the transaction is open.  Secrets are
    handed only to the existing vault mutation methods (which keep the
    encrypted password history) and wiped from the plan afterwards.
    """
    if not isinstance(plan, ImportPlan):
        raise TypeError("plan must be an ImportPlan")
    if not getattr(session, "is_unlocked", False):
        raise VaultLockedError("Vault is locked")
    if plan.applied:
        raise ImportWorkflowError("Import plan has already been applied")
    if plan.cancelled:
        raise ImportCancelled("Import plan was not approved")
    if not plan.reviewed:
        raise ImportWorkflowError("Import plan must be reviewed before applying")
    if _profile_generation(session) != plan.profile_generation:
        raise ImportWorkflowError("Vault profile changed after review")
    _revalidate_source(plan)
    if _cancelled(plan, cancel):
        plan.cancel()
        raise ImportCancelled("Import was cancelled")

    # Guard the whole plan up front so a drifted count never leaves a partial import.
    check = getattr(session, "_check_can_create", None)
    new_items = plan.new_item_count()
    if new_items and callable(check):
        try:
            check(new_items)
        except ItemLimitReached as exc:
            raise ImportWorkflowError(str(exc)) from exc
    count = 0
    collections = _Collections(session)
    try:
        with session.transaction():
            for item in plan.rows:
                if _cancelled(plan, cancel):
                    raise ImportCancelled("Import was cancelled")
                if item.decision == "skip" or item.limited:
                    continue
                if item.decision not in DECISIONS:
                    raise ImportWorkflowError("Unknown import decision")
                try:
                    if item.kind == "login":
                        written = _apply_login(session, item, collections)
                    else:
                        written = _apply_item(session, item, collections)
                except ImportWorkflowError:
                    raise
                except (VaultError, ItemSchemaError, ValueError) as exc:
                    raise ImportWorkflowError(f"Row {item.row}: {exc}") from exc
                count += int(written)
    except ImportCancelled:
        plan.cancel()
        raise
    plan.applied = True
    plan.wipe()
    return count


commit_import = apply_import_plan
apply_plan = apply_import_plan


class ImportWorkflow:
    """Small object facade for callers that prefer a staged workflow."""

    def __init__(self, session: Any):
        self.session = session

    def inspect(self, path: Path | str, **kwargs: Any) -> SourceInspection:
        return inspect_source(path, **kwargs)

    def preview(self, path: Path | str, **kwargs: Any) -> ImportPlan:
        return build_import_plan(self.session, path, **kwargs)

    def plan(self, records: Iterable[ImportedRecord], **kwargs: Any) -> ImportPlan:
        return plan_records(self.session, records, **kwargs)

    def apply(self, plan: ImportPlan, *, cancel: Callable[[], bool] | None = None) -> int:
        return apply_import_plan(self.session, plan, cancel=cancel)

    commit = apply


__all__ = [
    "DECISIONS", "ImportCancelled", "ImportFormatError", "ImportPlan", "ImportRowPlan", "ImportWorkflow",
    "ImportWorkflowError", "MASK", "MAX_IMPORT_ROWS", "MERGE_FIELDS", "SourceInspection", "apply_import_plan",
    "apply_plan", "build_import_plan", "canonical_origin_for", "card_payload", "classify_rows", "commit_import", "create_import_plan",
    "inspect_source", "normalise_records", "plan_records", "preview_import", "stage_import", "totp_dict",
]
