"""Approved, selected-field identity release for the browser boundary.

This module deliberately has no browser or UI dependencies.  It validates the
typed identity request, binds an approval to the current session/origin/tab
document/item revision, and consumes the capability on every release attempt.
The browser broker supplies the trusted user-review step and the current item
view; this module never exposes a complete identity implicitly.
"""
from __future__ import annotations

import json
import secrets
import threading
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any

from .item_schema import (
    CARD_FILL_TOKENS,
    IDENTITY_FIELDS,
    ItemSchemaError,
    card_expiry_parts,
    validate_identity_fields,
)
from .origin import OriginError, canonicalize_origin
from .session_guard import Lease, SessionGuard, StaleSession

IDENTITY_FILL_PROTOCOL = 1
IDENTITY_APPROVAL_TTL = 60.0
IDENTITY_MAX_SELECTED_FIELDS = 16

# Card fill shares the identity capability model: metadata first, trusted
# desktop review, a one-use approval bound to session/origin/tab document/
# item revision, then a release of exactly the approved tokens.
CARD_FILL_PROTOCOL = 1
CARD_FILL_LABELS: dict[str, str] = {
    "cc-name": "Cardholder name",
    "cc-number": "Card number",
    "cc-exp": "Expiry (MM/YYYY)",
    "cc-exp-month": "Expiry month",
    "cc-exp-year": "Expiry year",
    "cc-csc": "Security code (CVV)",
    "cc-type": "Card brand",
}
# Tokens whose values the trusted review dialog masks and whose release is
# flagged ``protected`` in metadata.  The PIN has no token at all.
CARD_PROTECTED_TOKENS = frozenset({"cc-number", "cc-csc"})
CARD_MAX_SELECTED_FIELDS = len(CARD_FILL_TOKENS)
_CARD_VALUE_LIMIT = 256


class IdentityReleaseError(StaleSession):
    """A typed identity approval is stale, mismatched, or already consumed."""


@dataclass(frozen=True)
class IdentityBrowserContext:
    """Browser-derived identity target bound into an approval capability."""

    tab_id: int
    document_id: str
    origin: str
    operation_id: str


def validate_identity_context(context: Any, origin: str) -> IdentityBrowserContext:
    """Validate the exact top-level document context used by identity release.

    The extension creates this tuple from browser-owned sender metadata.  Keep
    parsing here as a second boundary so a direct/native caller cannot replace
    it with an arbitrary string or bind an approval to a different origin.
    """
    if not isinstance(context, str) or not 16 <= len(context) <= 8192:
        raise ItemSchemaError("identity browser context is malformed")
    try:
        expected_origin = canonicalize_origin(origin)
    except (OriginError, TypeError) as exc:
        raise ItemSchemaError("identity origin is malformed") from exc
    try:
        value = json.loads(context)
    except (TypeError, ValueError, json.JSONDecodeError) as exc:
        raise ItemSchemaError("identity browser context is malformed") from exc
    if not isinstance(value, list) or len(value) != 4:
        raise ItemSchemaError("identity browser context is malformed")
    tab_id, document_id, context_origin, operation_id = value
    if type(tab_id) is not int or tab_id < 0:
        raise ItemSchemaError("identity tab context is malformed")
    if (not isinstance(document_id, str) or not 1 <= len(document_id) <= 256
            or "\x00" in document_id):
        raise ItemSchemaError("identity document context is malformed")
    if context_origin != expected_origin:
        raise ItemSchemaError("identity origin context does not match the request")
    if (not isinstance(operation_id, str) or not 1 <= len(operation_id) <= 128
            or "\x00" in operation_id):
        raise ItemSchemaError("identity operation context is malformed")
    return IdentityBrowserContext(tab_id, document_id, expected_origin, operation_id)


def normalize_selected_fields(fields: Any) -> tuple[str, ...]:
    """Return a bounded, duplicate-free list of browser-fillable fields."""
    if not isinstance(fields, (list, tuple)):
        raise ItemSchemaError("selected identity fields must be a list")
    if not 1 <= len(fields) <= IDENTITY_MAX_SELECTED_FIELDS:
        raise ItemSchemaError("select between one and sixteen identity fields")
    result: list[str] = []
    seen: set[str] = set()
    for field in fields:
        if not isinstance(field, str) or field not in IDENTITY_FIELDS:
            raise ItemSchemaError("identity field is not approved for browser fill")
        if field in seen:
            raise ItemSchemaError("selected identity fields contain a duplicate")
        seen.add(field)
        result.append(field)
    return tuple(result)


def selected_identity_values(identity: Mapping[str, Any], fields: Any) -> dict[str, str]:
    """Return exactly the requested values from a validated identity view."""
    selected = normalize_selected_fields(fields)
    if not isinstance(identity, Mapping):
        raise ItemSchemaError("identity release view is malformed")
    values = validate_identity_fields(dict(identity.get("fields", identity)))
    result: dict[str, str] = {}
    for field in selected:
        if field not in values:
            raise IdentityReleaseError("The selected identity field is no longer available")
        result[field] = values[field]
    return result


# ---------------------------------------------------------------------------
# Card fill helpers
# ---------------------------------------------------------------------------

def _card_source(card_item: Any) -> Mapping[str, Any]:
    if not isinstance(card_item, Mapping):
        raise ItemSchemaError("card fill view is malformed")
    fields = card_item.get("fields")
    if isinstance(fields, Mapping) and fields and set(fields) <= set(CARD_FILL_TOKENS):
        return fields
    payload = card_item.get("payload", card_item)
    if not isinstance(payload, Mapping):
        raise ItemSchemaError("card payload is malformed")
    return payload


def card_fill_fields(card_item: Any) -> dict[str, str]:
    """Map a card item (or a service ``card_fill_view``) to autocomplete tokens.

    The result always contains every token in :data:`CARD_FILL_TOKENS` (empty
    when the card lacks that value) and never the PIN, notes, or any other
    payload field.  Non-text values fail closed.
    """
    source = _card_source(card_item)
    if set(source) <= set(CARD_FILL_TOKENS):
        raw = {token: source.get(token, "") for token in CARD_FILL_TOKENS}
    else:
        month, year = card_expiry_parts(str(source.get("expiry", "") or ""))
        raw = {
            "cc-name": source.get("cardholder", ""),
            "cc-number": source.get("number", ""),
            "cc-exp": f"{month}/{year}" if month and year else "",
            "cc-exp-month": month,
            "cc-exp-year": year,
            "cc-csc": source.get("cvv", ""),
            "cc-type": source.get("brand", ""),
        }
    result: dict[str, str] = {}
    for token in CARD_FILL_TOKENS:
        value = raw.get(token, "")
        if value is None:
            value = ""
        if not isinstance(value, str) or len(value) > _CARD_VALUE_LIMIT or "\x00" in value:
            raise ItemSchemaError(f"card field {token} is malformed")
        result[token] = value
    return result


def card_fill_metadata(card_item: Any) -> dict[str, dict[str, Any]]:
    """Return value-free, per-token approval metadata for the review step."""
    values = card_fill_fields(card_item)
    return {
        token: {"label": CARD_FILL_LABELS[token], "protected": token in CARD_PROTECTED_TOKENS,
                "present": bool(values[token])}
        for token in CARD_FILL_TOKENS
    }


def normalize_selected_card_fields(fields: Any) -> tuple[str, ...]:
    """Return a bounded, duplicate-free list of approved card tokens."""
    if not isinstance(fields, (list, tuple)):
        raise ItemSchemaError("selected card fields must be a list")
    if not 1 <= len(fields) <= CARD_MAX_SELECTED_FIELDS:
        raise ItemSchemaError("select between one and seven card fields")
    result: list[str] = []
    seen: set[str] = set()
    for field in fields:
        if not isinstance(field, str) or field not in CARD_FILL_TOKENS:
            raise ItemSchemaError("card field is not approved for browser fill")
        if field in seen:
            raise ItemSchemaError("selected card fields contain a duplicate")
        seen.add(field)
        result.append(field)
    return tuple(result)


def selected_card_values(card: Mapping[str, Any], fields: Any) -> dict[str, str]:
    """Return exactly the requested token values from a card view."""
    selected = normalize_selected_card_fields(fields)
    values = card_fill_fields(card)
    result: dict[str, str] = {}
    for field in selected:
        if not values.get(field):
            raise IdentityReleaseError("The selected card field is no longer available")
        result[field] = values[field]
    return result


@dataclass(frozen=True)
class IdentityApproval:
    token: str
    lease: Lease
    identity_id: str
    revision: int
    origin: str
    context: str
    fields: tuple[str, ...]
    until: float
    kind: str = "identity"


class IdentityReleaseManager:
    """Manage one-use identity capabilities independently of credential grants."""

    # Field normalization and selection hooks.  ``CardReleaseManager`` swaps
    # them for the autocomplete-token versions; everything else (binding,
    # TTL, consumption, fail-closed errors) is shared.
    _normalize = staticmethod(normalize_selected_fields)
    _select = staticmethod(selected_identity_values)
    # Approvals are tagged with the kind of item they release and checked on use.
    kind = "identity"

    def __init__(self, guard: SessionGuard, *, monotonic: Callable[[], float] = time.monotonic) -> None:
        self.guard = guard
        self._mono = monotonic
        self._lock = threading.RLock()
        self._approvals: dict[str, IdentityApproval] = {}

    def _prune(self, now: float | None = None) -> None:
        now = self._mono() if now is None else now
        self._approvals = {token: approval for token, approval in self._approvals.items()
                           if approval.until > now}

    def issue(self, *, identity_id: str, revision: int, origin: str, context: str,
              fields: Any, ttl: float = IDENTITY_APPROVAL_TTL) -> str:
        """Create an approval after the caller has performed trusted review."""
        if not isinstance(identity_id, str) or not identity_id:
            raise ItemSchemaError("identity id is malformed")
        if type(revision) is not int or revision < 1:
            raise ItemSchemaError("identity revision is malformed")
        browser_context = validate_identity_context(context, origin)
        if type(ttl) not in (int, float) or not 0 < float(ttl) <= IDENTITY_APPROVAL_TTL:
            raise ItemSchemaError("identity approval lifetime is malformed")
        selected = self._normalize(fields)
        with self._lock:
            lease = self.guard.lease()
            self._prune()
            if len(self._approvals) >= 128:
                self._approvals.pop(next(iter(self._approvals)))
            token = secrets.token_urlsafe(32)
            self._approvals[token] = IdentityApproval(
                token=token, lease=lease, identity_id=identity_id,
                revision=revision, origin=browser_context.origin, context=context,
                fields=selected, until=self._mono() + float(ttl), kind=self.kind,
            )
            return token

    create_approval = issue

    def release(self, token: str, *, identity_id: str, revision: int, origin: str,
                context: str, fields: Any,
                identity: Mapping[str, Any] | None = None,
                resolver: Callable[[], Mapping[str, Any]] | None = None) -> dict[str, str]:
        """Consume and release only the fields approved for this exact target.

        The token is removed before validation.  Thus an expired, replayed,
        cross-origin, cross-tab, changed-revision, locked-session, or malformed
        attempt cannot be retried against a later destination.
        """
        with self._lock:
            approval = self._approvals.pop(token, None) if isinstance(token, str) else None
        if approval is None:
            raise IdentityReleaseError("The identity approval was already used or expired")
        try:
            browser_context = validate_identity_context(context, origin)
            selected = self._normalize(fields)
            if approval.until <= self._mono():
                raise IdentityReleaseError("The identity approval expired")
            self.guard.require(approval.lease)
            if (approval.kind != self.kind or approval.identity_id != identity_id or approval.revision != revision
                    or approval.origin != browser_context.origin or approval.context != context
                    or approval.fields != selected):
                raise IdentityReleaseError("The identity destination or selection changed")
            if identity is None:
                if resolver is None:
                    raise IdentityReleaseError("No identity release view was supplied")
                identity = resolver()
            result = self._select(identity, selected)
            # Revalidate the lease immediately before returning values.  The
            # browser still must revalidate its live controls before applying.
            self.guard.require(approval.lease)
            return result
        except IdentityReleaseError:
            raise
        except StaleSession as exc:
            raise IdentityReleaseError("The identity session changed") from exc
        except Exception as exc:  # fail closed while preserving a stable error
            raise IdentityReleaseError("The identity release could not be validated") from exc

    def revoke(self, token: str) -> None:
        with self._lock:
            self._approvals.pop(token, None)

    def clear(self) -> None:
        with self._lock:
            self._approvals.clear()


class CardReleaseManager(IdentityReleaseManager):
    """One-use card-fill capabilities with identity semantics and token fields."""

    _normalize = staticmethod(normalize_selected_card_fields)
    _select = staticmethod(selected_card_values)
    kind = "card"


__all__ = [
    "CARD_FILL_LABELS",
    "CARD_FILL_PROTOCOL",
    "CARD_FILL_TOKENS",
    "CARD_MAX_SELECTED_FIELDS",
    "CARD_PROTECTED_TOKENS",
    "CardReleaseManager",
    "IDENTITY_APPROVAL_TTL",
    "IDENTITY_FILL_PROTOCOL",
    "IDENTITY_MAX_SELECTED_FIELDS",
    "IdentityApproval",
    "IdentityBrowserContext",
    "IdentityReleaseError",
    "IdentityReleaseManager",
    "card_fill_fields",
    "card_fill_metadata",
    "normalize_selected_card_fields",
    "normalize_selected_fields",
    "selected_card_values",
    "selected_identity_values",
    "validate_identity_context",
]
