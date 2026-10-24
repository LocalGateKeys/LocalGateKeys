"""Format-specific readers that normalise third-party exports.

Every importer returns :class:`ImportResult`: a list of
:class:`ImportedRecord` plus human-readable diagnostics.  Records never
include secrets in their ``repr`` so review views and logs cannot leak them.
The reviewed apply step lives in :mod:`localvault.import_workflow`.
"""
from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import quote

MAX_SOURCE_BYTES = 8 * 1024 * 1024
MAX_RECORDS = 5_000
# Decompressed JSON documents (Proton Pass data.json, 1PUX export.data,
# Bitwarden JSON) are parsed whole; 16 MiB is far above a 5,000-item export
# and keeps a crafted document's object graph to a few hundred MiB.
MAX_JSON_BYTES = 16 * 1024 * 1024
MAX_DIAGNOSTICS = 50
RECORD_KINDS = ("login", "note", "identity", "card", "other")
CARD_KEYS = ("cardholder", "number", "expiry", "cvv", "pin", "brand")
_MONTHS = {name: index for index, name in enumerate(
    ("january", "february", "march", "april", "may", "june", "july", "august", "september", "october",
     "november", "december"), 1)}


class ImporterError(ValueError):
    """Base error for every importer; the workflow re-raises subclasses."""


class ImportPasswordRequired(ImporterError):
    """The source is encrypted and no password was supplied."""


class ImportPasswordError(ImporterError):
    """The supplied password (or key file) does not open the source."""


class ImportFormatError(ImporterError):
    """The source is malformed, truncated or of an unsupported format."""


@dataclass
class ImportedRecord:
    """One normalised item from a third-party export.

    ``kind`` is one of :data:`RECORD_KINDS`.  Secrets (``password``,
    ``notes``, ``totp_uri``, ``custom_fields``, ``identity``, ``card``) are
    excluded from ``repr``.  ``card`` holds the structured payment-card
    values of a ``card`` record (keys from :data:`CARD_KEYS`); anything a card
    cannot hold stays in ``custom_fields``.
    """

    kind: str = "login"
    title: str = ""
    username: str = ""
    password: str = field(default="", repr=False)
    urls: list[str] = field(default_factory=list)
    notes: str = field(default="", repr=False)
    totp_uri: str = field(default="", repr=False)
    folder: str = ""
    favorite: bool = False
    custom_fields: list[dict[str, Any]] = field(default_factory=list, repr=False)
    created: int | None = None
    modified: int | None = None
    tags: list[str] = field(default_factory=list)
    identity: dict[str, str] = field(default_factory=dict, repr=False)
    card: dict[str, str] = field(default_factory=dict, repr=False)
    source_row: int | None = None

    def __post_init__(self) -> None:
        if self.kind not in RECORD_KINDS:
            raise ImporterError(f"Unsupported record kind {self.kind!r}")
        self.urls = [str(url) for url in self.urls if url]
        self.custom_fields = [
            {"name": str(item.get("name", "")), "value": str(item.get("value", "")),
             "hidden": bool(item.get("hidden", False))}
            for item in self.custom_fields if isinstance(item, dict) and item.get("name")
        ]
        self.card = {key: str(value).strip() for key, value in self.card.items() if key in CARD_KEYS and value}

    @property
    def url(self) -> str:
        return self.urls[0] if self.urls else ""

    @property
    def has_secret(self) -> bool:
        return bool(self.password or self.totp_uri or self.card.get("number")
                    or any(f.get("hidden") for f in self.custom_fields))

    def wipe(self) -> None:
        """Overwrite secret fields once a record is no longer needed."""
        self.password = ""
        self.notes = ""
        self.totp_uri = ""
        self.custom_fields = []
        self.identity = {}
        self.card = {}


@dataclass
class ImportResult:
    source_format: str
    records: list[ImportedRecord] = field(default_factory=list)
    diagnostics: list[str] = field(default_factory=list)
    fields: tuple[str, ...] = ()

    def __len__(self) -> int:
        return len(self.records)

    def __iter__(self):
        return iter(self.records)

    def wipe(self) -> None:
        for record in self.records:
            record.wipe()
        self.records.clear()


def add_custom_field(record: ImportedRecord, name: str, value: Any, *, hidden: bool = False) -> None:
    """Append a custom field, skipping blanks and capping at 50 fields."""
    if value is None:
        return
    text = str(value)
    if not name or not text or len(record.custom_fields) >= 50:
        return
    record.custom_fields.append({"name": str(name)[:100], "value": text[:4096], "hidden": bool(hidden)})


def totp_uri_from_secret(secret: str, *, label: str = "", issuer: str = "", digits: int = 6,
                         period: int = 30, algorithm: str = "SHA1") -> str:
    """Build an ``otpauth://totp`` URI from a bare Base32 secret.

    Values that already look like an ``otpauth://`` URI are returned
    unchanged (after trimming) so callers can pass either form.
    """
    value = (secret or "").strip()
    if not value:
        return ""
    if value.casefold().startswith("otpauth://"):
        return value
    compact = "".join(value.replace("-", "").split()).upper().rstrip("=")
    if not compact:
        return ""
    name = quote(label or "account", safe="@:")
    query = [f"secret={compact}"]
    if issuer:
        query.append(f"issuer={quote(issuer, safe='')}")
    if int(digits) != 6:
        query.append(f"digits={int(digits)}")
    if int(period) != 30:
        query.append(f"period={int(period)}")
    algorithm = str(algorithm or "SHA1").upper().replace("HMAC-", "").replace("-", "")
    if algorithm != "SHA1":
        query.append(f"algorithm={algorithm}")
    return f"otpauth://totp/{name}?" + "&".join(query)


def _ascii_digits(text: str) -> bool:
    return text.isascii() and text.isdigit()


def card_expiry(month: Any = "", year: Any = "") -> str:
    """Normalise card expiry parts to ``MM/YYYY`` ("" when unusable).

    Accepts numeric months, English month names (LastPass writes
    ``January,2027``), two- or four-digit years and a combined value in the
    ``month`` argument such as ``2027-01`` (Proton Pass), ``01/27``,
    ``01/2027`` or ``202701`` (1Password ``monthYear``).
    """
    month_text, year_text = str(month or "").strip(), str(year or "").strip()
    if month_text and not year_text:
        compact = month_text.replace(" ", "")
        if _ascii_digits(compact) and len(compact) == 6:
            year_text, month_text = compact[:4], compact[4:]
        else:
            for separator in ("/", "-", ",", "."):
                if separator in compact:
                    first, _sep, second = compact.partition(separator)
                    if len(first) == 4 and _ascii_digits(first):
                        year_text, month_text = first, second
                    else:
                        month_text, year_text = first, second
                    break
    month_key = month_text.casefold()
    if month_key in _MONTHS:
        number = _MONTHS[month_key]
    elif month_key[:3] in {name[:3] for name in _MONTHS} and not _ascii_digits(month_key):
        number = next(index for name, index in _MONTHS.items() if name[:3] == month_key[:3])
    elif _ascii_digits(month_text):
        number = int(month_text)
    else:
        return ""
    if not 1 <= number <= 12 or not _ascii_digits(year_text) or len(year_text) not in (2, 4):
        return ""
    year_value = int(year_text) + (2000 if len(year_text) == 2 else 0)
    return f"{number:02d}/{year_value:04d}"


def check_record_count(count: int) -> None:
    """Stop a reader as soon as it has seen more than :data:`MAX_RECORDS` items.

    Readers call this while iterating, counting every item they see (trashed
    and malformed ones included), so a crafted export cannot make them build
    millions of records or diagnostics before the limit applies.
    """
    if count > MAX_RECORDS:
        raise ImportFormatError(f"At most {MAX_RECORDS:,} records per import")


def cap_diagnostics(messages: Iterable[str], limit: int = MAX_DIAGNOSTICS) -> list[str]:
    """Return the first ``limit`` messages plus one "and N more" line."""
    kept: list[str] = []
    extra = 0
    for message in messages:
        if len(kept) < limit:
            kept.append(message)
        else:
            extra += 1
    if extra:
        kept.append(f"...and {extra:,} more {'message' if extra == 1 else 'messages'}.")
    return kept


def enforce_record_limit(records: Iterable[ImportedRecord]) -> list[ImportedRecord]:
    result = list(records)
    if len(result) > MAX_RECORDS:
        raise ImportFormatError(f"At most {MAX_RECORDS:,} records per import")
    return result


__all__ = [
    "CARD_KEYS", "ImportFormatError", "ImportPasswordError", "ImportPasswordRequired", "ImportResult",
    "ImportedRecord", "ImporterError", "MAX_DIAGNOSTICS", "MAX_JSON_BYTES", "MAX_RECORDS", "MAX_SOURCE_BYTES",
    "RECORD_KINDS", "add_custom_field", "cap_diagnostics", "card_expiry", "check_record_count",
    "enforce_record_limit", "totp_uri_from_secret",
]
