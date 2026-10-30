"""Versioned encrypted catalog item schemas.

This module deliberately contains validation and metadata projection only.  It
does not open files, fetch bookmark URLs, render documents, or decide whether a
secret may be released.  The vault owns encryption and the domain service owns
mutations.
"""
from __future__ import annotations

import base64
import copy
import datetime as _datetime
import hashlib
import re
import time
import uuid
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlsplit

from .i18n import t
from .origin import (
    DEFAULT_MATCH_MODE,
    MATCH_MODES,
    OriginError,
    canonicalize_origin,
    host_of,
    normalize_url,
    origin_of,
)

CATALOG_VERSION = 2
# Version of the per-item payload schemas.  ``CATALOG_VERSION`` above is the
# vault container version owned by ``vault.py``; it is deliberately *not*
# bumped for new item kinds because the container format is compatible.  The
# item schema version is bumped instead and forward migration happens on read
# (see ``migrate_web_scope`` and the derived-field recomputation performed by
# ``validate_payload`` for card/bank/SSH payloads).
#
# 1: web/desktop/note/bookmark/document/license/purchase/warranty/subscription/identity
# 2: + card, bank_account, ssh_key, api_key, wifi, passkey; web ``scope.urls`` rows
# 3: + passkey user_name, user_display_name, rp_name, discoverable
ITEM_SCHEMA_VERSION = 3
CATALOG_FORMAT = "localgatekeys-catalog"
MAX_ITEMS = 20_000
MAX_COLLECTIONS = 500
MAX_TEMPLATES = 200
MAX_EVENTS = 5_000
MAX_TITLE = 512
MAX_NOTE_BODY = 20_000
MAX_URL = 4_096
MAX_TAGS = 20
MAX_TAG_LENGTH = 40
MAX_COLLECTION_MEMBERSHIPS = 20
MAX_TEMPLATE_DESCRIPTION = 500

# These kinds have explicit schema boundaries even though their UI/secret
# handling is intentionally deferred to later milestones.
SECRET_ITEM_KINDS = frozenset({"card", "bank_account", "ssh_key", "api_key", "wifi", "passkey"})
ITEM_KINDS = frozenset(
    {
        "web", "desktop", "note", "bookmark", "document", "license", "purchase",
        "warranty", "subscription", "identity",
    }
) | SECRET_ITEM_KINDS
M2_ITEM_KINDS = frozenset({"note", "bookmark"})
TEMPLATE_KINDS = frozenset({
    "note", "document", "license", "purchase", "warranty", "subscription", "identity", "bookmark",
}) | SECRET_ITEM_KINDS

# Multi-URL web logins.  ``scope.urls`` rows are validated by
# ``validate_web_urls``; the legacy single ``scope.origin`` is always kept equal
# to ``urls[0]`` so older readers and exact-origin matching keep working.
WEB_MATCH_MODES = MATCH_MODES
MAX_WEB_URLS = 20
MAX_PRIVATE_KEY = 20_000

MAX_ATTACHMENT_RECORDS = 20_000
MAX_ATTACHMENT_NAME = 512
MAX_MIME_TYPE = 255
MAX_DOCUMENT_DESCRIPTION = 20_000
MAX_DOCUMENT_LINKS = 50
MAX_PROTECTED_VALUE = 4_096
MAX_VENDOR = 512
MAX_CURRENCY = 3
MAX_REMINDERS = 20_000

# Identity data is deliberately a closed, text-only schema.  These are the
# only fields that the browser release path may ever return.  Keep the bounds
# per field rather than accepting a generic custom-field blob: a value is
# opaque user data, but its name and type are still security-sensitive.
IDENTITY_FIELD_LIMITS: dict[str, int] = {
    "name": 256,
    "given_name": 128,
    "middle_name": 128,
    "family_name": 128,
    "organization": 256,
    "company": 256,
    "job_title": 160,
    "email": 320,
    "phone": 64,
    "address": 1_024,
    "address_line1": 256,
    "address_line2": 256,
    "city": 128,
    "state": 128,
    "postal_code": 64,
    "country": 128,
    "website": 2_048,
}
IDENTITY_FIELDS = frozenset(IDENTITY_FIELD_LIMITS)
IDENTITY_MAX_FIELDS = len(IDENTITY_FIELD_LIMITS)
IDENTITY_MAX_TOTAL = 8_192

# Payload fields that list/search projections must redact and that the editor
# must mask by default.  The item service and the typed editor read this single
# table so a new kind cannot leak by omission.
PROTECTED_FIELDS_BY_KIND: dict[str, tuple[str, ...]] = {
    "note": ("body", "fields"),
    "bookmark": ("url", "notes"),
    "identity": tuple(IDENTITY_FIELD_LIMITS),
    "license": ("license_value",),
    "card": ("number", "cvv", "pin"),
    "bank_account": ("account_number", "pin"),
    "ssh_key": ("private_key", "passphrase"),
    "api_key": ("key", "secret"),
    "wifi": ("password",),
    "passkey": ("private_key",),
}

CARD_BRANDS = ("visa", "mastercard", "amex", "discover", "diners", "jcb", "unionpay", "maestro", "unknown")
# HTML ``autocomplete`` tokens a browser card fill may populate.  The PIN is
# never part of this set: it is not a web form field and stays desktop-only.
CARD_FILL_TOKENS = ("cc-name", "cc-number", "cc-exp", "cc-exp-month", "cc-exp-year", "cc-csc", "cc-type")

# Safe, metadata-only display hints for protected fields.  The editor masks
# these fields by default and list/choice rows may show the hint instead of
# the value (for example ``Visa •••• 1111``).  ``last4`` is derived from the
# card number on validation and is deliberately the only fragment kept
# outside the protected field.
PROTECTED_FIELD_LABELS: dict[str, dict[str, str]] = {
    "card": {"number": "Card number", "cvv": "CVV", "pin": "PIN"},
    "bank_account": {"account_number": "IBAN / account number", "pin": "PIN"},
    "ssh_key": {"private_key": "Private key", "passphrase": "Passphrase"},
    "api_key": {"key": "Key", "secret": "Secret"},
    "wifi": {"password": "Password"},
    "passkey": {"private_key": "Private key"},
    "license": {"license_value": "License key / serial"},
}
# Protected fields that hold multi-line armoured material rather than a
# single secret line; the editor renders them in a masked text box.
MULTILINE_PROTECTED_FIELDS: frozenset[tuple[str, str]] = frozenset({
    ("ssh_key", "private_key"), ("passkey", "private_key"),
})
MASK_GLYPH = "•"
WIFI_SECURITY_TYPES = ("none", "wep", "wpa", "wpa2", "wpa3", "wpa2-enterprise", "wpa3-enterprise")
PASSKEY_ALGORITHMS = ("ES256", "ES384", "ES512", "RS256", "PS256", "EdDSA")
_IBAN_RE = re.compile(r"^[A-Z]{2}[0-9]{2}[A-Z0-9]{11,30}$")
_BASE64URL_RE = re.compile(r"^[A-Za-z0-9_\-]+=*$")
_HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)(\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*$"
)


class ItemSchemaError(ValueError):
    """Stable validation error for catalog and typed item input."""


@dataclass(frozen=True)
class ItemSummary:
    """Safe list/palette projection; it never contains an item payload."""

    id: str
    kind: str
    title: str
    created_at: int
    updated_at: int
    revision: int = 1
    favorite: bool = False
    tags: tuple[str, ...] = ()
    collection_ids: tuple[str, ...] = ()
    # Credential compatibility fields.  New item summaries leave them empty.
    username: str = ""
    scope: dict[str, Any] | None = None


_FIELD_LABELS = {
    "bookmark URL": "itemSchema.field.bookmarkUrl",
    "title": "itemSchema.field.title",
    "name": "itemSchema.field.name",
}


def _text(value: Any, field: str, limit: int, *, allow_empty: bool = False) -> str:
    if not isinstance(value, str):
        raise ItemSchemaError(f"{field} must be text")
    if not allow_empty and not value:
        raise ItemSchemaError(t("itemSchema.cannotBeEmpty", field=t(_FIELD_LABELS[field]) if field in _FIELD_LABELS else field))
    if len(value) > limit:
        raise ItemSchemaError(f"{field} is too long")
    if "\x00" in value:
        raise ItemSchemaError(f"{field} contains a null character")
    return value


def normalize_tags(tags: Iterable[str] | None) -> list[str]:
    if tags is None:
        return []
    if isinstance(tags, (str, bytes)):
        raise ItemSchemaError("tags must be a list of text values")
    result: list[str] = []
    seen: set[str] = set()
    for value in tags:
        tag = _text(value, "tag", MAX_TAG_LENGTH).strip()
        if not tag:
            continue
        key = tag.casefold()
        if key not in seen:
            seen.add(key)
            result.append(tag)
    if len(result) > MAX_TAGS:
        raise ItemSchemaError(f"At most {MAX_TAGS} tags are supported per item")
    return result


def validate_bookmark_url(value: Any) -> str:
    """Accept only explicitly opened HTTP(S) bookmarks.

    No network request is made here.  In particular, active schemes and local
    command/file URLs are rejected before they can reach the UI.
    """
    url = _text(value, "bookmark URL", MAX_URL)
    if any(ord(char) < 32 or char.isspace() for char in url):
        raise ItemSchemaError("bookmark URL contains whitespace or a control character")
    try:
        parsed = urlsplit(url)
    except ValueError:  # malformed brackets, NFKC netloc
        raise ItemSchemaError("bookmark URL is malformed") from None
    if parsed.scheme.casefold() not in {"http", "https"}:
        raise ItemSchemaError("bookmark URL must use http or https")
    if not parsed.netloc or parsed.hostname is None:
        raise ItemSchemaError("bookmark URL must contain a host")
    if parsed.username is not None or parsed.password is not None:
        raise ItemSchemaError("bookmark URL must not contain embedded credentials")
    return url


def _id(value: Any, field: str) -> str:
    result = _text(value, field, 128)
    try:
        result = str(uuid.UUID(result))
    except (ValueError, AttributeError):
        raise ItemSchemaError(f"{field} must be a UUID") from None
    return result


def _timestamp(value: Any, field: str) -> int:
    if type(value) is not int or not 0 <= value <= 2**63 - 1:
        raise ItemSchemaError(f"{field} must be a bounded UTC timestamp")
    return value


def _uuid_list(values: Any, field: str, limit: int) -> list[str]:
    if values is None:
        return []
    if not isinstance(values, list) or len(values) > limit:
        raise ItemSchemaError(f"{field} must be a list of at most {limit} IDs")
    result: list[str] = []
    seen: set[str] = set()
    for value in values:
        parsed = _id(value, field[:-1] if field.endswith("s") else field)
        if parsed in seen:
            raise ItemSchemaError(f"{field} contains a duplicate ID")
        seen.add(parsed)
        result.append(parsed)
    return result


def _date(value: Any, field: str, *, allow_empty: bool = False) -> str:
    if allow_empty and value in (None, ""):
        return ""
    value = _text(value, field, 10)
    try:
        _datetime.date.fromisoformat(value)
    except ValueError:
        raise ItemSchemaError(f"{field} must be an ISO date (YYYY-MM-DD)") from None
    return value


def _currency(value: Any) -> str:
    value = _text(value, "currency", MAX_CURRENCY).upper()
    if len(value) != 3 or not value.isascii() or not value.isalpha():
        raise ItemSchemaError("currency must be a three-letter code")
    return value


def _amount_minor(value: Any) -> int:
    if type(value) is not int or not -(10**15) <= value <= 10**15:
        raise ItemSchemaError("amount_minor must be a bounded integer in minor currency units")
    return value


def validate_attachment_records(value: Any) -> list[dict[str, Any]]:
    if value is None:
        return []
    if not isinstance(value, list) or len(value) > MAX_ATTACHMENT_RECORDS:
        raise ItemSchemaError("attachment records are malformed or exceed the limit")
    result: list[dict[str, Any]] = []
    seen: set[str] = set()
    for row in value:
        if not isinstance(row, dict):
            raise ItemSchemaError("attachment record must be an object")
        allowed = {"id", "name", "mime_type", "size", "sha256", "key"}
        if set(row) - allowed:
            raise ItemSchemaError("attachment record contains unsupported fields")
        attachment_id = _id(row.get("id"), "attachment id")
        if attachment_id in seen:
            raise ItemSchemaError("duplicate attachment IDs")
        seen.add(attachment_id)
        name = _text(row.get("name", ""), "attachment name", MAX_ATTACHMENT_NAME)
        if name in {".", ".."} or "/" in name or "\\" in name:
            raise ItemSchemaError("attachment name must not contain path separators")
        if any(ord(char) < 32 for char in name):
            raise ItemSchemaError("attachment name contains a control character")
        mime_type = _text(row.get("mime_type", "application/octet-stream"), "MIME type", MAX_MIME_TYPE)
        size = row.get("size")
        if type(size) is not int or not 0 <= size <= 25 * 1024 * 1024:
            raise ItemSchemaError("attachment size is outside the accepted bound")
        digest = _text(row.get("sha256", ""), "attachment SHA-256", 64).lower()
        if len(digest) != 64 or any(char not in "0123456789abcdef" for char in digest):
            raise ItemSchemaError("attachment SHA-256 is malformed")
        key = _text(row.get("key", ""), "attachment key", 128)
        try:
            decoded_key = __import__("base64").b64decode(key.encode("ascii"), validate=True)
        except Exception:
            raise ItemSchemaError("attachment key is malformed") from None
        if len(decoded_key) != 32:
            raise ItemSchemaError("attachment key has an invalid length")
        result.append({"id": attachment_id, "name": name, "mime_type": mime_type,
                       "size": size, "sha256": digest, "key": key})
    return result


def validate_attachment_references(
    items: Any,
    trash: Any,
    attachments: list[dict[str, Any]],
) -> None:
    """Ensure every document item points at an authenticated catalog record.

    Sidecar authentication belongs to the attachment store, but a malformed
    catalog must fail before any sidecar metadata is used.  Deleted typed
    items remain references until their retention window expires, so they are
    included in the same check.
    """
    known = {row["id"] for row in attachments}
    if not isinstance(items, list) or not isinstance(trash, list):
        raise ItemSchemaError("attachment references are malformed")
    candidates = list(items)
    for record in trash:
        if isinstance(record, dict) and isinstance(record.get("entry"), dict):
            candidates.append(record["entry"])
    for item in candidates:
        if not isinstance(item, dict) or item.get("kind") != "document":
            continue
        payload = item.get("payload")
        attachment_id = payload.get("attachment_id") if isinstance(payload, dict) else None
        if attachment_id not in known:
            raise ItemSchemaError("document attachment reference is missing")


def validate_reminders(value: Any) -> list[dict[str, Any]]:
    if value is None:
        return []
    if not isinstance(value, list) or len(value) > MAX_REMINDERS:
        raise ItemSchemaError("reminders are malformed or exceed the limit")
    result: list[dict[str, Any]] = []
    seen: set[str] = set()
    for row in value:
        if not isinstance(row, dict):
            raise ItemSchemaError("reminder must be an object")
        allowed = {"id", "item_id", "due_date", "lead_days", "status", "snooze_until", "last_notified"}
        if set(row) - allowed:
            raise ItemSchemaError("reminder contains unsupported fields")
        reminder_id = _id(row.get("id"), "reminder id")
        if reminder_id in seen:
            raise ItemSchemaError("duplicate reminder IDs")
        seen.add(reminder_id)
        item_id = _id(row.get("item_id"), "reminder item id")
        due_date = _date(row.get("due_date"), "reminder due date")
        lead_days = row.get("lead_days", 0)
        if type(lead_days) is not int or not 0 <= lead_days <= 3650:
            raise ItemSchemaError("reminder lead_days is malformed")
        status = row.get("status", "pending")
        if status not in {"pending", "snoozed", "dismissed"}:
            raise ItemSchemaError("reminder status is malformed")
        snooze_until = _date(row.get("snooze_until", ""), "reminder snooze_until", allow_empty=True)
        last_notified = row.get("last_notified", "")
        if last_notified != "":
            last_notified = _text(last_notified, "reminder last_notified", 32)
        result.append({"id": reminder_id, "item_id": item_id, "due_date": due_date,
                       "lead_days": lead_days, "status": status,
                       "snooze_until": snooze_until, "last_notified": last_notified})
    return result


def _collection_ids(values: Any) -> list[str]:
    if values is None:
        return []
    if not isinstance(values, list):
        raise ItemSchemaError("collection_ids must be a list")
    result = []
    seen: set[str] = set()
    for value in values:
        collection_id = _id(value, "collection id")
        if collection_id not in seen:
            seen.add(collection_id)
            result.append(collection_id)
    if len(result) > MAX_COLLECTION_MEMBERSHIPS:
        raise ItemSchemaError("An item cannot belong to more than 20 collections")
    return result


def _validate_custom_fields(fields: Any) -> list[dict[str, Any]]:
    if fields is None:
        return []
    if not isinstance(fields, list) or len(fields) > 50:
        raise ItemSchemaError("template fields must be a list of at most 50 values")
    result = []
    for field in fields:
        if not isinstance(field, dict):
            raise ItemSchemaError("template field must be an object")
        allowed = {"name", "value", "hidden"}
        if set(field) - allowed:
            raise ItemSchemaError("template field contains unsupported data")
        result.append(
            {
                "name": _text(field.get("name", ""), "field name", 100),
                "value": _text(field.get("value", ""), "field value", 4_096, allow_empty=True),
                "hidden": field.get("hidden", False) is True,
            }
        )
    return result


def validate_identity_fields(value: Any) -> dict[str, str | None]:
    """Validate the contact/address values of an identity item.

    Identity payloads are flat data objects, not templates or executable
    field definitions.  Only the named text fields above are accepted.  In
    particular, password-like, payment, government-ID, HTML and script
    fields cannot enter the catalog or the later browser release path.
    """
    if not isinstance(value, dict):
        raise ItemSchemaError("identity payload must be an object")
    allowed = IDENTITY_FIELDS | {"template_id"}
    if set(value) - allowed:
        raise ItemSchemaError("identity payload contains unsupported fields")
    if len([key for key in value if key != "template_id"]) > IDENTITY_MAX_FIELDS:
        raise ItemSchemaError("identity payload contains too many fields")
    result: dict[str, str | None] = {}
    total = 0
    for field, limit in IDENTITY_FIELD_LIMITS.items():
        if field not in value:
            continue
        text = _text(value[field], f"identity field {field}", limit, allow_empty=True)
        result[field] = text
        total += len(text)
    if total > IDENTITY_MAX_TOTAL:
        raise ItemSchemaError("identity payload is too large")
    if "template_id" in value:
        # Null means "no template", as for every other kind.
        template_id = value["template_id"]
        result["template_id"] = None if template_id is None else _text(template_id, "template id", 128)
    return result


# ---------------------------------------------------------------------------
# Payment card helpers
# ---------------------------------------------------------------------------

def normalize_card_number(value: Any) -> str:
    """Strip spaces and dashes; the result is digits only or an error."""
    text = _text(value, "card number", 64, allow_empty=True)
    digits = text.replace(" ", "").replace("-", "")
    if not digits:
        return ""
    if not digits.isascii() or not digits.isdigit():
        raise ItemSchemaError("card number must contain digits only")
    if not 12 <= len(digits) <= 19:
        raise ItemSchemaError("card number must be 12 to 19 digits")
    return digits


def luhn_valid(number: Any) -> bool:
    """Return whether ``number`` (digits, spaces or dashes) passes the Luhn check."""
    try:
        digits = normalize_card_number(number)
    except ItemSchemaError:
        return False
    if not digits:
        return False
    total = 0
    for index, char in enumerate(reversed(digits)):
        digit = ord(char) - 48
        if index % 2 == 1:
            digit *= 2
            if digit > 9:
                digit -= 9
        total += digit
    return total % 10 == 0


def card_brand(number: Any) -> str:
    """Detect the card network from the issuer identification number."""
    try:
        digits = normalize_card_number(number)
    except ItemSchemaError:
        return "unknown"
    if not digits:
        return ""
    length = len(digits)
    prefix2 = int(digits[:2])
    prefix3 = int(digits[:3])
    prefix4 = int(digits[:4])
    prefix6 = int(digits[:6])
    if prefix2 in {34, 37} and length == 15:
        return "amex"
    if digits[0] == "4" and length in {13, 16, 19}:
        return "visa"
    if (51 <= prefix2 <= 55 or 2221 <= prefix4 <= 2720) and length == 16:
        return "mastercard"
    if (prefix4 == 6011 or 622126 <= prefix6 <= 622925 or 644 <= prefix3 <= 649
            or prefix2 == 65) and 16 <= length <= 19:
        return "discover"
    if (300 <= prefix3 <= 305 or prefix4 == 3095 or prefix2 in {36, 38, 39}) and 14 <= length <= 19:
        return "diners"
    if 3528 <= prefix4 <= 3589 and 16 <= length <= 19:
        return "jcb"
    if prefix2 == 62 and 16 <= length <= 19:
        return "unionpay"
    if (prefix2 == 50 or 56 <= prefix2 <= 69) and 12 <= length <= 19:
        return "maestro"
    return "unknown"


def _card_expiry(value: Any) -> str:
    """Accept ``MM/YY``, ``M/YY``, ``MM/YYYY`` or ``MM-YY`` and store ``MM/YY``."""
    text = _text(value, "card expiry", 10, allow_empty=True).strip()
    if not text:
        return ""
    match = re.fullmatch(r"(\d{1,2})\s*[/-]\s*(\d{2}|\d{4})", text)
    if match is None:
        raise ItemSchemaError("card expiry must be MM/YY")
    month = int(match.group(1))
    year = match.group(2)
    if not 1 <= month <= 12:
        raise ItemSchemaError("card expiry month must be 01-12")
    if len(year) == 4:
        if not year.startswith("20"):
            raise ItemSchemaError("card expiry year is out of range")
        year = year[2:]
    return f"{month:02d}/{year}"


def card_last4(number: Any) -> str:
    """Return the last four digits of a card number ("" when absent/malformed)."""
    try:
        digits = normalize_card_number(number)
    except ItemSchemaError:
        return ""
    return digits[-4:] if digits else ""


def masked_hint(kind: str, field: str, payload: Mapping[str, Any] | None = None) -> str:
    """Return a value-free display string for one protected field.

    Only the card ``last4`` fragment is ever included; every other field is
    rendered as a fixed mask so the hint can be shown in lists and choice
    rows without reading the protected value.
    """
    if field not in PROTECTED_FIELDS_BY_KIND.get(kind, ()):
        raise ItemSchemaError("Unsupported protected field")
    payload = payload or {}
    present = bool(payload.get(f"{field}_present")) or bool(payload.get(field))
    if not present:
        return ""
    if kind == "card" and field == "number":
        last4 = str(payload.get("last4", "")) or card_last4(payload.get("number", ""))
        if last4:
            return f"{MASK_GLYPH * 4} {last4}"
    return MASK_GLYPH * 8


def card_expiry_parts(expiry: str) -> tuple[str, str]:
    """Return ``(MM, YYYY)`` for a stored ``MM/YY`` expiry or ``("", "")``."""
    if not isinstance(expiry, str) or "/" not in expiry:
        return "", ""
    month, _, year = expiry.partition("/")
    if len(year) == 2:
        year = "20" + year
    return month, year


def _digits(value: Any, field: str, minimum: int, maximum: int) -> str:
    text = _text(value, field, maximum + 16, allow_empty=True).strip()
    if not text:
        return ""
    if not text.isascii() or not text.isdigit() or not minimum <= len(text) <= maximum:
        raise ItemSchemaError(f"{field} must be {minimum} to {maximum} digits")
    return text


def validate_card_fields(value: Any) -> dict[str, Any]:
    """Validate a payment card.  ``brand`` is always derived from the number."""
    if not isinstance(value, dict):
        raise ItemSchemaError("card payload must be an object")
    allowed = {"cardholder", "number", "brand", "last4", "expiry", "cvv", "pin", "billing_address_id",
               "notes", "template_id"}
    if set(value) - allowed:
        raise ItemSchemaError("card payload contains unsupported data")
    number = normalize_card_number(value.get("number", ""))
    if number and not luhn_valid(number):
        raise ItemSchemaError("card number failed its checksum")
    billing = value.get("billing_address_id", "")
    billing = "" if billing in (None, "") else _id(billing, "billing address id")
    return {
        "cardholder": _text(value.get("cardholder", ""), "cardholder", 256, allow_empty=True),
        "number": number,
        "brand": card_brand(number) if number else "",
        "last4": card_last4(number),
        "expiry": _card_expiry(value.get("expiry", "")),
        "cvv": _digits(value.get("cvv", ""), "card CVV", 3, 4),
        "pin": _digits(value.get("pin", ""), "card PIN", 4, 8),
        "billing_address_id": billing,
        "notes": _text(value.get("notes", ""), "card notes", MAX_NOTE_BODY, allow_empty=True),
        "template_id": _optional_template_id(value),
    }


# ---------------------------------------------------------------------------
# Bank account helpers
# ---------------------------------------------------------------------------

def validate_iban(value: Any) -> str:
    """Return the compact upper-case IBAN after a mod-97 checksum."""
    text = _text(value, "IBAN", 64).replace(" ", "").upper()
    if not _IBAN_RE.fullmatch(text):
        raise ItemSchemaError("IBAN is malformed")
    rearranged = text[4:] + text[:4]
    numeric = "".join(str(int(char, 36)) for char in rearranged)
    if int(numeric) % 97 != 1:
        raise ItemSchemaError("IBAN failed its checksum")
    return text


def validate_bank_account_fields(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ItemSchemaError("bank account payload must be an object")
    allowed = {"bank", "account_holder", "account_number", "number_format", "routing", "pin", "notes",
               "template_id"}
    if set(value) - allowed:
        raise ItemSchemaError("bank account payload contains unsupported data")
    account = _text(value.get("account_number", ""), "account number", 64, allow_empty=True).strip()
    number_format = ""
    if account:
        compact = account.replace(" ", "").upper()
        if _IBAN_RE.fullmatch(compact):
            account = validate_iban(compact)
            number_format = "iban"
        else:
            if any(ord(char) < 32 for char in account):
                raise ItemSchemaError("account number contains a control character")
            number_format = "other"
    routing = _text(value.get("routing", ""), "routing or BIC", 34, allow_empty=True).strip().upper()
    if routing and not re.fullmatch(r"[A-Z0-9-]+", routing):
        raise ItemSchemaError("routing or BIC must be alphanumeric")
    return {
        "bank": _text(value.get("bank", ""), "bank", 256, allow_empty=True),
        "account_holder": _text(value.get("account_holder", ""), "account holder", 256, allow_empty=True),
        "account_number": account,
        "number_format": number_format,
        "routing": routing,
        "pin": _digits(value.get("pin", ""), "bank PIN", 4, 8),
        "notes": _text(value.get("notes", ""), "bank account notes", MAX_NOTE_BODY, allow_empty=True),
        "template_id": _optional_template_id(value),
    }


# ---------------------------------------------------------------------------
# SSH key helpers
# ---------------------------------------------------------------------------

_PEM_FORMATS = (
    ("-----BEGIN OPENSSH PRIVATE KEY-----", "openssh"),
    ("-----BEGIN RSA PRIVATE KEY-----", "pem-rsa"),
    ("-----BEGIN EC PRIVATE KEY-----", "pem-ec"),
    ("-----BEGIN DSA PRIVATE KEY-----", "pem-dsa"),
    ("-----BEGIN ENCRYPTED PRIVATE KEY-----", "pem-pkcs8-encrypted"),
    ("-----BEGIN PRIVATE KEY-----", "pem-pkcs8"),
    ("---- BEGIN SSH2 ENCRYPTED PRIVATE KEY ----", "ssh2"),
    ("PuTTY-User-Key-File-", "putty"),
)
_OPENSSH_KEY_TYPES = ("ssh-", "ecdsa-sha2-", "sk-ssh-", "sk-ecdsa-")


def sniff_private_key_format(text: Any) -> str:
    """Classify a private key blob by its armour header without parsing it."""
    if not isinstance(text, str):
        return "unknown"
    stripped = text.strip()
    if not stripped:
        return ""
    for header, name in _PEM_FORMATS:
        if stripped.startswith(header):
            if name == "pem-rsa" and "Proc-Type: 4,ENCRYPTED" in stripped[:512]:
                return "pem-rsa-encrypted"
            return name
    return "unknown"


def openssh_fingerprint(public_key: Any) -> str:
    """Return ``SHA256:<base64>`` for an OpenSSH ``type base64 [comment]`` line.

    Non-OpenSSH input (PEM public keys, empty text) yields ``""`` so callers
    can keep a user-supplied fingerprint instead.  An OpenSSH line whose blob
    is not valid base64 raises because the key itself is unusable.
    """
    if not isinstance(public_key, str) or not public_key.strip():
        return ""
    parts = public_key.strip().split()
    if len(parts) < 2 or not parts[0].startswith(_OPENSSH_KEY_TYPES):
        return ""
    try:
        blob = base64.b64decode(parts[1].encode("ascii"), validate=True)
    except (ValueError, UnicodeEncodeError):
        raise ItemSchemaError("OpenSSH public key is not valid base64") from None
    if not blob:
        raise ItemSchemaError("OpenSSH public key is empty")
    return "SHA256:" + base64.b64encode(hashlib.sha256(blob).digest()).decode("ascii").rstrip("=")


def validate_ssh_key_fields(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ItemSchemaError("SSH key payload must be an object")
    allowed = {"private_key", "public_key", "passphrase", "fingerprint", "key_format", "notes", "template_id"}
    if set(value) - allowed:
        raise ItemSchemaError("SSH key payload contains unsupported data")
    private_key = _text(value.get("private_key", ""), "private key", MAX_PRIVATE_KEY, allow_empty=True)
    public_key = _text(value.get("public_key", ""), "public key", MAX_PRIVATE_KEY, allow_empty=True)
    computed = openssh_fingerprint(public_key)
    fingerprint = computed or _text(value.get("fingerprint", ""), "fingerprint", 128, allow_empty=True).strip()
    return {
        "private_key": private_key,
        "public_key": public_key,
        "passphrase": _text(value.get("passphrase", ""), "passphrase", MAX_PROTECTED_VALUE, allow_empty=True),
        "fingerprint": fingerprint,
        "key_format": sniff_private_key_format(private_key),
        "notes": _text(value.get("notes", ""), "SSH key notes", MAX_NOTE_BODY, allow_empty=True),
        "template_id": _optional_template_id(value),
    }


# ---------------------------------------------------------------------------
# API key, Wi-Fi, passkey
# ---------------------------------------------------------------------------

def validate_api_key_fields(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ItemSchemaError("API key payload must be an object")
    allowed = {"service", "key", "secret", "expires", "notes", "template_id"}
    if set(value) - allowed:
        raise ItemSchemaError("API key payload contains unsupported data")
    return {
        "service": _text(value.get("service", ""), "service", MAX_VENDOR, allow_empty=True),
        "key": _text(value.get("key", ""), "API key", MAX_PROTECTED_VALUE, allow_empty=True),
        "secret": _text(value.get("secret", ""), "API secret", MAX_PROTECTED_VALUE, allow_empty=True),
        "expires": _date(value.get("expires", ""), "API key expiry", allow_empty=True),
        "notes": _text(value.get("notes", ""), "API key notes", MAX_NOTE_BODY, allow_empty=True),
        "template_id": _optional_template_id(value),
    }


def validate_wifi_fields(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ItemSchemaError("Wi-Fi payload must be an object")
    allowed = {"ssid", "password", "security", "hidden", "notes", "template_id"}
    if set(value) - allowed:
        raise ItemSchemaError("Wi-Fi payload contains unsupported data")
    security = value.get("security", "wpa2")
    if not isinstance(security, str):
        raise ItemSchemaError("Wi-Fi security type must be text")
    security = security.strip().casefold() or "wpa2"
    if security not in WIFI_SECURITY_TYPES:
        raise ItemSchemaError("Wi-Fi security type is unsupported")
    hidden = value.get("hidden", False)
    if type(hidden) is not bool:
        raise ItemSchemaError("Wi-Fi hidden flag must be boolean")
    return {
        "ssid": _text(value.get("ssid", ""), "SSID", 32, allow_empty=True),
        "password": _text(value.get("password", ""), "Wi-Fi password", MAX_PROTECTED_VALUE, allow_empty=True),
        "security": security,
        "hidden": hidden,
        "notes": _text(value.get("notes", ""), "Wi-Fi notes", MAX_NOTE_BODY, allow_empty=True),
        "template_id": _optional_template_id(value),
    }


def _base64url(value: Any, field: str) -> str:
    text = _text(value, field, 1_024, allow_empty=True).strip()
    if text and not _BASE64URL_RE.fullmatch(text):
        raise ItemSchemaError(f"{field} must be base64url text")
    return text


def validate_passkey_fields(value: Any) -> dict[str, Any]:
    """Validate a passkey (WebAuthn credential) record.

    Websites create these through the browser extension (see
    :mod:`localvault.passkeys`).  A record is usable for sign-in only when it
    is ES256 with a parseable P-256 PKCS#8 private key
    (``passkeys.usable_record``); anything else, such as an imported record
    with another algorithm, is kept as backup data and never offered.  The
    private key is a protected field and is never released by the broker:
    the agent signs with it and returns only the signature.
    """
    if not isinstance(value, dict):
        raise ItemSchemaError("passkey payload must be an object")
    allowed = {"relying_party_id", "user_handle", "credential_id", "private_key", "algorithm", "created",
               "notes", "template_id", "user_name", "user_display_name", "rp_name", "discoverable"}
    if set(value) - allowed:
        raise ItemSchemaError("passkey payload contains unsupported data")
    rp_id = _text(value.get("relying_party_id", ""), "relying party id", 253, allow_empty=True).strip().casefold()
    if rp_id and not _HOSTNAME_RE.fullmatch(rp_id):
        raise ItemSchemaError("relying party id must be a bare hostname")
    algorithm = value.get("algorithm", "")
    if algorithm in (None, ""):
        algorithm = ""
    elif algorithm not in PASSKEY_ALGORITHMS:
        raise ItemSchemaError("passkey algorithm is unsupported")
    discoverable = value.get("discoverable", True)
    if type(discoverable) is not bool:
        raise ItemSchemaError("passkey discoverable flag must be true or false")
    return {
        "relying_party_id": rp_id,
        "user_handle": _base64url(value.get("user_handle", ""), "user handle"),
        "credential_id": _base64url(value.get("credential_id", ""), "credential id"),
        "private_key": _text(value.get("private_key", ""), "passkey private key", MAX_PRIVATE_KEY,
                             allow_empty=True),
        "algorithm": algorithm,
        "created": _date(value.get("created", ""), "passkey created date", allow_empty=True),
        "notes": _text(value.get("notes", ""), "passkey notes", MAX_NOTE_BODY, allow_empty=True),
        "user_name": _text(value.get("user_name", ""), "passkey user name", 256, allow_empty=True),
        "user_display_name": _text(value.get("user_display_name", ""), "passkey display name", 256,
                                   allow_empty=True),
        "rp_name": _text(value.get("rp_name", ""), "passkey site name", 256, allow_empty=True),
        "discoverable": discoverable,
        "template_id": _optional_template_id(value),
    }


def _optional_template_id(value: Mapping[str, Any]) -> str | None:
    template_id = value.get("template_id")
    if template_id is None:
        return None
    return _text(template_id, "template id", 128)


# ---------------------------------------------------------------------------
# Web login URL rows
# ---------------------------------------------------------------------------

def validate_web_urls(value: Any) -> list[dict[str, str]]:
    """Validate ``[{"url": str, "match": mode}]`` rows for a web login.

    ``exact_origin`` rows are stored as canonical origins; other modes keep a
    normalized URL (path/query preserved for ``starts_with``).  Plain HTTP is
    accepted only for loopback hosts, matching ``canonicalize_origin``.
    Duplicate rows collapse; order is otherwise preserved because ``urls[0]``
    doubles as the legacy ``origin``.
    """
    if value is None:
        return []
    if not isinstance(value, list) or len(value) > MAX_WEB_URLS:
        raise ItemSchemaError(f"urls must be a list of at most {MAX_WEB_URLS} rows")
    result: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for row in value:
        if isinstance(row, str):
            row = {"url": row}
        if not isinstance(row, Mapping):
            raise ItemSchemaError("url row must be an object")
        if set(row) - {"url", "match"}:
            raise ItemSchemaError("url row contains unsupported data")
        mode = row.get("match", DEFAULT_MATCH_MODE)
        if mode not in WEB_MATCH_MODES:
            raise ItemSchemaError("url match mode is unsupported")
        raw = _text(row.get("url", ""), "url", MAX_URL)
        try:
            if mode == "exact_origin":
                url = canonicalize_origin(raw)
            else:
                url = normalize_url(raw)
                if url.startswith("http://"):
                    # Reuse the loopback-only HTTP policy of canonical origins.
                    canonicalize_origin(origin_of(url))
        except OriginError as exc:
            raise ItemSchemaError(f"url is malformed: {exc}") from None
        key = (url, mode)
        if key in seen:
            continue
        seen.add(key)
        result.append({"url": url, "match": mode})
    return result


def migrate_web_scope(scope: Any) -> dict[str, Any]:
    """Forward-migrate a web login scope to the multi-URL shape.

    * A legacy scope with only ``origin`` gains ``urls == [{origin, exact_origin}]``.
    * When ``urls[0]`` is an ``exact_origin`` row it is authoritative and
      ``origin`` is rewritten to match it.
    * Otherwise the legacy origin (or the origin of ``urls[0]``) is inserted
      as the first row so ``urls[0]`` is always the exact origin.

    Other scope keys are preserved untouched.
    """
    if not isinstance(scope, Mapping):
        raise ItemSchemaError("web login scope must be an object")
    result = dict(scope)
    urls = validate_web_urls(scope.get("urls"))
    origin = scope.get("origin")
    if origin not in (None, ""):
        try:
            origin = canonicalize_origin(_text(origin, "origin", MAX_URL))
        except OriginError as exc:
            raise ItemSchemaError(f"origin is malformed: {exc}") from None
    else:
        origin = None
    if urls and urls[0]["match"] == "exact_origin":
        origin = urls[0]["url"]
    else:
        if origin is None:
            if not urls:
                raise ItemSchemaError("web login needs at least one URL")
            origin = origin_of(urls[0]["url"])
        first = {"url": origin, "match": "exact_origin"}
        urls = [first] + [row for row in urls if row != first]
    result["origin"] = origin
    result["urls"] = urls
    return result


def web_page_address(scope: Any) -> str:
    """The address to show and open for a web login: its primary origin, or the
    first ``starts_with`` row on that same origin (an imported full page
    address, 2026-10-29).  Display only; matching always uses every row."""
    if not isinstance(scope, Mapping):
        return ""
    origin = scope.get("origin")
    origin = origin if isinstance(origin, str) else ""
    rows = scope.get("urls")
    if origin and isinstance(rows, list):
        for row in rows:
            if isinstance(row, Mapping) and row.get("match") == "starts_with" and isinstance(row.get("url"), str):
                try:
                    if origin_of(row["url"]) == origin:
                        return row["url"]
                except OriginError:
                    continue
    return origin


def web_login_host(scope: Mapping[str, Any]) -> str:
    """Return the hostname of a web login's primary origin ("" when unknown)."""
    try:
        return host_of(str(scope.get("origin", "")))
    except OriginError:
        return ""


def validate_payload(kind: str, payload: Any) -> dict[str, Any]:
    if not isinstance(payload, dict):
        raise ItemSchemaError(f"{kind} payload must be an object")
    payload = copy.deepcopy(payload)
    if kind == "note":
        allowed = {"body", "fields", "template_id"}
        if set(payload) - allowed:
            raise ItemSchemaError("note payload contains unsupported data")
        body = _text(payload.get("body", ""), "note body", MAX_NOTE_BODY, allow_empty=True)
        template_id = payload.get("template_id")
        if template_id is not None:
            template_id = _text(template_id, "template id", 128)
        return {"body": body, "fields": _validate_custom_fields(payload.get("fields")), "template_id": template_id}
    if kind == "bookmark":
        allowed = {"url", "notes", "template_id"}
        if set(payload) - allowed:
            raise ItemSchemaError("bookmark payload contains unsupported data")
        template_id = payload.get("template_id")
        if template_id is not None:
            template_id = _text(template_id, "template id", 128)
        return {
            "url": validate_bookmark_url(payload.get("url", "")),
            "notes": _text(payload.get("notes", ""), "bookmark notes", MAX_NOTE_BODY, allow_empty=True),
            "template_id": template_id,
        }

    if kind == "document":
        allowed = {"attachment_id", "description", "template_id"}
        if set(payload) - allowed:
            raise ItemSchemaError("document payload contains unsupported data")
        return {
            "attachment_id": _id(payload.get("attachment_id"), "attachment id"),
            "description": _text(payload.get("description", ""), "document description",
                                  MAX_DOCUMENT_DESCRIPTION, allow_empty=True),
            "template_id": (_text(payload["template_id"], "template id", 128)
                            if payload.get("template_id") is not None else None),
        }
    if kind == "license":
        allowed = {"license_value", "product", "vendor", "purchase_date", "expiration_date",
                   "document_ids", "notes", "template_id"}
        if set(payload) - allowed:
            raise ItemSchemaError("license payload contains unsupported data")
        expiration = _date(payload.get("expiration_date", ""), "expiration date", allow_empty=True)
        purchase = _date(payload.get("purchase_date", ""), "purchase date", allow_empty=True)
        if purchase and expiration and expiration < purchase:
            raise ItemSchemaError("expiration date cannot precede purchase date")
        return {
            "license_value": _text(payload.get("license_value", ""), "license value",
                                    MAX_PROTECTED_VALUE, allow_empty=True),
            "product": _text(payload.get("product", ""), "product", MAX_VENDOR, allow_empty=True),
            "vendor": _text(payload.get("vendor", ""), "vendor", MAX_VENDOR, allow_empty=True),
            "purchase_date": purchase,
            "expiration_date": expiration,
            "document_ids": _uuid_list(payload.get("document_ids", []), "document_ids", MAX_DOCUMENT_LINKS),
            "notes": _text(payload.get("notes", ""), "license notes", MAX_NOTE_BODY, allow_empty=True),
            "template_id": (_text(payload["template_id"], "template id", 128)
                            if payload.get("template_id") is not None else None),
        }
    if kind in {"purchase", "warranty", "subscription"}:
        allowed = {"product", "vendor", "provider", "purchase_date", "expiration_date", "renewal_date",
                   "amount_minor", "currency", "document_ids", "notes", "active", "template_id"}
        if set(payload) - allowed:
            raise ItemSchemaError(f"{kind} payload contains unsupported data")
        purchase = _date(payload.get("purchase_date", ""), "purchase date", allow_empty=True)
        expiration = _date(payload.get("expiration_date", ""), "expiration date", allow_empty=True)
        renewal = _date(payload.get("renewal_date", ""), "renewal date", allow_empty=True)
        if purchase and expiration and expiration < purchase:
            raise ItemSchemaError("expiration date cannot precede purchase date")
        if purchase and renewal and renewal < purchase:
            raise ItemSchemaError("renewal date cannot precede purchase date")
        if "amount_minor" not in payload and "currency" in payload:
            raise ItemSchemaError("currency requires amount_minor")
        if "amount_minor" in payload and "currency" not in payload:
            raise ItemSchemaError("amount_minor requires currency")
        amount = _amount_minor(payload.get("amount_minor", 0))
        currency = _currency(payload.get("currency", "XXX"))
        active = payload.get("active", True)
        if type(active) is not bool:
            raise ItemSchemaError("active must be boolean")
        return {
            "product": _text(payload.get("product", ""), "product", MAX_VENDOR, allow_empty=True),
            "vendor": _text(payload.get("vendor", ""), "vendor", MAX_VENDOR, allow_empty=True),
            "provider": _text(payload.get("provider", ""), "provider", MAX_VENDOR, allow_empty=True),
            "purchase_date": purchase,
            "expiration_date": expiration,
            "renewal_date": renewal,
            "amount_minor": amount,
            "currency": currency,
            "document_ids": _uuid_list(payload.get("document_ids", []), "document_ids", MAX_DOCUMENT_LINKS),
            "notes": _text(payload.get("notes", ""), f"{kind} notes", MAX_NOTE_BODY, allow_empty=True),
            "active": active,
            "template_id": (_text(payload["template_id"], "template id", 128)
                            if payload.get("template_id") is not None else None),
        }
    if kind == "identity":
        return validate_identity_fields(payload)
    if kind == "card":
        return validate_card_fields(payload)
    if kind == "bank_account":
        return validate_bank_account_fields(payload)
    if kind == "ssh_key":
        return validate_ssh_key_fields(payload)
    if kind == "api_key":
        return validate_api_key_fields(payload)
    if kind == "wifi":
        return validate_wifi_fields(payload)
    if kind == "passkey":
        return validate_passkey_fields(payload)
    raise ItemSchemaError(f"Unsupported item kind: {kind}")


def validate_item(item: Any, *, known_collection_ids: set[str] | None = None) -> dict[str, Any]:
    if not isinstance(item, dict):
        raise ItemSchemaError("catalog item must be an object")
    allowed = {
        "id", "kind", "title", "created_at", "updated_at", "revision", "favorite",
        "tags", "collection_ids", "payload",
    }
    if set(item) - allowed:
        raise ItemSchemaError("catalog item contains unsupported fields")
    kind = _text(item.get("kind", ""), "item kind", 32)
    if kind not in ITEM_KINDS:
        raise ItemSchemaError(f"Unsupported item kind: {kind}")
    item_id = _id(item.get("id"), "item id")
    title = _text(item.get("title", ""), "item title", MAX_TITLE)
    created = _timestamp(item.get("created_at"), "created_at")
    updated = _timestamp(item.get("updated_at"), "updated_at")
    if updated < created:
        raise ItemSchemaError("updated_at cannot be earlier than created_at")
    revision = item.get("revision", 1)
    if type(revision) is not int or not 1 <= revision <= 2**63 - 1:
        raise ItemSchemaError("item revision is malformed")
    favorite = item.get("favorite", False)
    if type(favorite) is not bool:
        raise ItemSchemaError("favorite must be boolean")
    tags = normalize_tags(item.get("tags", []))
    collection_ids = _collection_ids(item.get("collection_ids", []))
    if known_collection_ids is not None and any(value not in known_collection_ids for value in collection_ids):
        raise ItemSchemaError("catalog item references an unknown collection")
    return {
        "id": item_id,
        "kind": kind,
        "title": title,
        "created_at": created,
        "updated_at": updated,
        "revision": revision,
        "favorite": favorite,
        "tags": tags,
        "collection_ids": collection_ids,
        "payload": validate_payload(kind, item.get("payload", {})),
    }


def new_item(kind: str, title: str, payload: dict[str, Any], *, tags: Iterable[str] | None = None,
             collection_ids: Iterable[str] | None = None, favorite: bool = False,
             template_id: str | None = None, now: int | None = None) -> dict[str, Any]:
    if kind not in ITEM_KINDS:
        raise ItemSchemaError(f"Unsupported item kind: {kind}")
    timestamp = int(time.time()) if now is None else _timestamp(now, "now")
    payload = copy.deepcopy(payload)
    if template_id is not None:
        payload["template_id"] = template_id
    return validate_item(
        {
            "id": str(uuid.uuid4()),
            "kind": kind,
            "title": title,
            "created_at": timestamp,
            "updated_at": timestamp,
            "revision": 1,
            "favorite": favorite,
            "tags": list(tags or []),
            "collection_ids": list(collection_ids or []),
            "payload": payload,
        }
    )


def summary_from_item(item: dict[str, Any]) -> ItemSummary:
    """Project an already validated item without inspecting payload values."""
    return ItemSummary(
        id=item["id"],
        kind=item["kind"],
        title=item["title"],
        created_at=item["created_at"],
        updated_at=item["updated_at"],
        revision=item["revision"],
        favorite=item["favorite"],
        tags=tuple(item.get("tags", [])),
        collection_ids=tuple(item.get("collection_ids", [])),
    )


def validate_collections(collections: Any) -> list[dict[str, Any]]:
    if collections is None:
        return []
    if not isinstance(collections, list) or len(collections) > MAX_COLLECTIONS:
        raise ItemSchemaError("collections are malformed or exceed the limit")
    result = []
    ids: set[str] = set()
    names: set[str] = set()
    for row in collections:
        if not isinstance(row, dict) or set(row) - {"id", "name", "description", "created_at", "updated_at", "revision", "starter"}:
            raise ItemSchemaError("collection contains unsupported fields")
        collection_id = _id(row.get("id"), "collection id")
        if collection_id in ids:
            raise ItemSchemaError("Duplicate collection IDs")
        ids.add(collection_id)
        name = _text(row.get("name", ""), "collection name", 100).strip()
        if name.casefold() in names:
            raise ItemSchemaError("Duplicate collection names")
        names.add(name.casefold())
        created = _timestamp(row.get("created_at"), "collection created_at")
        updated = _timestamp(row.get("updated_at"), "collection updated_at")
        if updated < created:
            raise ItemSchemaError("collection updated_at cannot precede created_at")
        revision = row.get("revision", 1)
        if type(revision) is not int or not 1 <= revision <= 2**63 - 1:
            raise ItemSchemaError("collection revision is malformed")
        starter = row.get("starter", False)
        if type(starter) is not bool:
            raise ItemSchemaError("collection starter flag is malformed")
        result.append(
            {
                "id": collection_id,
                "name": name,
                "description": _text(row.get("description", ""), "collection description", 500, allow_empty=True),
                "created_at": created,
                "updated_at": updated,
                "revision": revision,
                "starter": starter,
            }
        )
    return result


def validate_template(value: Any) -> dict[str, Any]:
    """Validate one declarative template definition.

    Template definitions are data only.  Their fields are deliberately kept
    to a small allow-list so loading a catalog can never turn a custom value
    into executable UI or code.
    """
    if not isinstance(value, dict):
        raise ItemSchemaError("template must be an object")
    allowed = {"id", "kind", "name", "description", "fields", "created_at", "updated_at", "revision"}
    if set(value) - allowed:
        raise ItemSchemaError("template contains unsupported fields")
    template_id = _text(value.get("id", ""), "template id", 128)
    kind = value.get("kind")
    if kind not in TEMPLATE_KINDS:
        raise ItemSchemaError("template kind is unsupported")
    name = _text(value.get("name", ""), "template name", 100).strip()
    fields = value.get("fields", [])
    if not isinstance(fields, list) or len(fields) > 50:
        raise ItemSchemaError("template fields exceed the limit")
    allowed_types = {"text", "multiline", "date", "url", "number"}
    clean_fields: list[dict[str, Any]] = []
    names: set[str] = set()
    for field in fields:
        if not isinstance(field, dict) or set(field) - {"name", "label", "type", "required", "secret"}:
            raise ItemSchemaError("template field contains unsupported data")
        field_name = _text(field.get("name", ""), "template field name", 64)
        if field_name in names:
            raise ItemSchemaError("template field name is malformed or duplicated")
        field_type = field.get("type", "text")
        if field_type not in allowed_types:
            raise ItemSchemaError("template field type is unsupported")
        label = field.get("label", field_name)
        if not isinstance(label, str) or not label.strip() or len(label) > 100:
            raise ItemSchemaError("template field label is malformed")
        required = field.get("required", False)
        secret = field.get("secret", False)
        if type(required) is not bool or type(secret) is not bool:
            raise ItemSchemaError("template field flags are malformed")
        names.add(field_name)
        clean_fields.append({
            "name": field_name,
            "label": label.strip(),
            "type": field_type,
            "required": required,
            "secret": secret,
        })
    description = value.get("description", "")
    if not isinstance(description, str) or len(description) > MAX_TEMPLATE_DESCRIPTION or "\x00" in description:
        raise ItemSchemaError("template description is malformed")
    now = int(time.time())
    created = value.get("created_at", now)
    updated = value.get("updated_at", now)
    revision = value.get("revision", 1)
    created = _timestamp(created, "template created_at")
    updated = _timestamp(updated, "template updated_at")
    if updated < created:
        raise ItemSchemaError("template updated_at cannot precede created_at")
    if type(revision) is not int or not 1 <= revision <= 2**63 - 1:
        raise ItemSchemaError("template revision is malformed")
    return {
        "id": template_id,
        "kind": kind,
        "name": name,
        "description": description,
        "fields": clean_fields,
        "created_at": created,
        "updated_at": updated,
        "revision": revision,
    }


def validate_templates(templates: Any) -> list[dict[str, Any]]:
    if templates is None:
        return []
    if not isinstance(templates, list) or len(templates) > MAX_TEMPLATES:
        raise ItemSchemaError("templates are malformed or exceed the limit")
    result: list[dict[str, Any]] = []
    ids: set[str] = set()
    names: set[str] = set()
    for value in templates:
        row = validate_template(value)
        if row["id"] in ids:
            raise ItemSchemaError("Duplicate template IDs")
        if row["name"].casefold() in names:
            raise ItemSchemaError("Duplicate template names")
        ids.add(row["id"])
        names.add(row["name"].casefold())
        result.append(row)
    return result


def validate_events(events: Any) -> list[dict[str, Any]]:
    if events is None:
        return []
    if not isinstance(events, list) or len(events) > MAX_EVENTS:
        raise ItemSchemaError("activity history exceeds its bound")
    result = []
    for event in events:
        if not isinstance(event, dict) or set(event) - {"id", "event_type", "timestamp", "item_id", "result", "count"}:
            raise ItemSchemaError("activity event contains unsupported fields")
        event_id = _id(event.get("id"), "event id")
        item_id = event.get("item_id")
        if item_id is not None:
            item_id = _id(item_id, "event item id")
        count = event.get("count", 0)
        if type(count) is not int or not 0 <= count <= 2**31 - 1:
            raise ItemSchemaError("activity event count is malformed")
        result.append(
            {
                "id": event_id,
                "event_type": _text(event.get("event_type", ""), "event type", 64),
                "timestamp": _timestamp(event.get("timestamp"), "event timestamp"),
                "item_id": item_id,
                "result": _text(event.get("result", ""), "event result", 32),
                "count": count,
            }
        )
    return result
