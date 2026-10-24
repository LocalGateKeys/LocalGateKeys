"""Domain services for the encrypted v2 catalog.

The service accepts an already-unlocked :class:`VaultSession`.  It stores all
typed item data through that session, so lock/profile changes invalidate access
without needing a second key or cache.
"""
from __future__ import annotations

import copy
import time
from collections.abc import Iterable, Mapping
from typing import Any

from .item_schema import (
    CARD_FILL_TOKENS,
    ITEM_KINDS,
    MAX_ITEMS,
    MAX_NOTE_BODY,
    PROTECTED_FIELDS_BY_KIND,
    SECRET_ITEM_KINDS,
    ItemSchemaError,
    ItemSummary,
    card_expiry_parts,
    migrate_web_scope,
    new_item,
    normalize_tags,
    summary_from_item,
    validate_bookmark_url,
    validate_identity_fields,
    validate_item,
    validate_web_urls,
)
from .origin import OriginError, candidates_for, entry_urls
from .vault import VaultError, VaultLockedError

TYPED_SAFE_KINDS = frozenset({"license", "purchase", "warranty", "subscription"})

# The schema deliberately stores one protected value for a license.  The
# aliases make the deliberate reveal/copy boundary useful to callers that
# describe that value as a key or serial without creating a second plaintext
# field in the encrypted payload.  Other kinds release exactly the protected
# fields listed in ``PROTECTED_FIELDS_BY_KIND``.
_LICENSE_SECRET_ALIASES = {
    "license_value": "license_value",
    "serial": "license_value",
    "serial_number": "license_value",
    "key": "license_value",
    "value": "license_value",
}
RELEASABLE_SECRET_KINDS = frozenset({"license"}) | SECRET_ITEM_KINDS

_WEB_ENTRY_SECRETS = ("password", "password_history", "totp", "recovery_codes")


class ItemService:
    """Create, update, delete and search typed catalog items."""

    def __init__(self, session: Any) -> None:
        self.session = session

    def _payload(self) -> dict[str, Any]:
        if not getattr(self.session, "is_unlocked", False):
            raise VaultLockedError("Vault is locked")
        return self.session._require_typed_catalog()

    def _items(self) -> list[dict[str, Any]]:
        items = self._payload().setdefault("items", [])
        if not isinstance(items, list):
            raise VaultError("Typed catalog items are malformed")
        return items

    def _known_collection_ids(self, payload: dict[str, Any]) -> set[str]:
        return {row["id"] for row in payload.get("collections", [])}

    def _redact_item(self, item: Mapping[str, Any], *, include_protected: bool = False) -> dict[str, Any]:
        """Return an item projection with protected payloads omitted by default.

        The UI uses ``include_protected=True`` only after the user chooses an
        explicit edit/reveal action.  List, palette, activity and diagnostics
        callers therefore cannot accidentally receive note bodies, bookmark
        URLs, identity values, or license keys.
        """
        result = copy.deepcopy(dict(item))
        typed = result.get("payload")
        if isinstance(typed, dict) and not include_protected:
            kind = result.get("kind")
            protected = PROTECTED_FIELDS_BY_KIND.get(kind, ())
            if kind == "identity":
                protected = tuple(key for key in typed if key != "template_id")
            for key in protected:
                value = typed.pop(key, None)
                if value not in (None, "", [], {}):
                    typed[f"{key}_present"] = True
        return result

    def _document_context(self, payload: dict[str, Any]) -> tuple[dict[str, dict[str, Any]], set[str]]:
        """Return live document items and authenticated attachment IDs.

        ``vault._validate_catalog_payload`` verifies document attachment
        references on load/save.  M4 references need the stricter live-item
        check at the service boundary so a purchase cannot point at a deleted
        document or a document whose attachment catalog record is absent.
        """
        documents = {
            item["id"]: item
            for item in self._items()
            if isinstance(item, dict) and item.get("kind") == "document"
        }
        attachments = {
            row["id"] for row in payload.get("attachments", [])
            if isinstance(row, dict) and isinstance(row.get("id"), str)
        }
        return documents, attachments

    def _validate_document_references(self, item: Mapping[str, Any], payload: dict[str, Any]) -> None:
        """Validate M4 document_ids against live, catalog-backed documents."""
        documents, attachments = self._document_context(payload)
        typed = item.get("payload")
        if not isinstance(typed, dict):
            return
        if item.get("kind") == "document":
            attachment_id = typed.get("attachment_id")
            if attachment_id not in attachments:
                raise ItemSchemaError("document attachment reference is missing")
            return
        if item.get("kind") not in TYPED_SAFE_KINDS:
            return
        for document_id in typed.get("document_ids", []):
            document = documents.get(document_id)
            if document is None:
                raise ItemSchemaError("document_ids references a missing live document")
            document_payload = document.get("payload", {})
            attachment_id = document_payload.get("attachment_id") if isinstance(document_payload, dict) else None
            if attachment_id not in attachments:
                raise ItemSchemaError("document_ids references a document with a missing attachment")

    def _validate_card_references(self, item: Mapping[str, Any]) -> None:
        """A card's billing address must point at a live identity item."""
        if item.get("kind") != "card":
            return
        typed = item.get("payload")
        billing = typed.get("billing_address_id") if isinstance(typed, dict) else ""
        if not billing:
            return
        target = next((value for value in self._items()
                       if isinstance(value, dict) and value.get("id") == billing), None)
        if target is None or target.get("kind") != "identity":
            raise ItemSchemaError("card billing address must reference a live identity item")

    def _validate_references(self, item: Mapping[str, Any], payload: dict[str, Any]) -> None:
        self._validate_document_references(item, payload)
        self._validate_card_references(item)

    def _check_can_create(self) -> None:
        """Enforce the session's free-plan item limit before any mutation."""
        check = getattr(self.session, "_check_can_create", None)
        if callable(check):
            check()

    def _append(self, item: dict[str, Any]) -> str:
        payload = self._payload()
        items = self._items()
        self._check_can_create()
        if len(items) >= MAX_ITEMS:
            raise ItemSchemaError("The typed item limit has been reached")
        validated = validate_item(item, known_collection_ids=self._known_collection_ids(payload))
        self._validate_references(validated, payload)
        items.append(validated)
        payload["updated_at"] = int(time.time())
        try:
            self.session.save()
        except BaseException:
            # save() restores the session payload on failure; keep the local
            # list consistent for lightweight fake sessions used by callers.
            if validated in items:
                items.remove(validated)
            raise
        return validated["id"]

    def list_items(self, *, kinds: Iterable[str] | None = None) -> list[dict[str, Any]]:
        allowed = set(kinds) if kinds is not None else None
        if allowed is not None and not allowed.issubset(ITEM_KINDS):
            raise ItemSchemaError("Unsupported item kind filter")
        return [self._redact_item(item) for item in self._items()
                if allowed is None or item["kind"] in allowed]

    def metadata_summaries(self, *, kinds: Iterable[str] | None = None,
                           collection_id: str | None = None,
                           favorite_only: bool = False) -> list[ItemSummary]:
        allowed = set(kinds) if kinds is not None else None
        if allowed is not None and not allowed.issubset(ITEM_KINDS):
            raise ItemSchemaError("Unsupported item kind filter")
        result: list[ItemSummary] = []
        for item in self._items():
            if allowed is not None and item["kind"] not in allowed:
                continue
            if collection_id is not None and collection_id not in item.get("collection_ids", []):
                continue
            if favorite_only and not item.get("favorite", False):
                continue
            result.append(summary_from_item(item))
        return result

    def all_metadata_summaries(self) -> list[ItemSummary]:
        """Return credentials plus typed items without loading secret payloads."""
        result: list[ItemSummary] = []
        for summary in self.session.summaries():
            result.append(
                ItemSummary(
                    id=summary.id,
                    kind=summary.kind,
                    title=summary.label,
                    created_at=summary.created_at,
                    updated_at=summary.updated_at,
                    favorite=summary.favorite,
                    tags=summary.tags,
                    username=summary.username,
                    scope=copy.deepcopy(summary.scope),
                )
            )
        result.extend(self.metadata_summaries())
        return result

    def search_metadata(self, query: str = "", *, kinds: Iterable[str] | None = None,
                        collection_id: str | None = None, favorite_only: bool = False) -> list[ItemSummary]:
        if not isinstance(query, str):
            raise ItemSchemaError("search query must be text")
        needle = query.casefold().strip()
        summaries = self.all_metadata_summaries()
        allowed = set(kinds) if kinds is not None else None
        if allowed is not None and not allowed.issubset(ITEM_KINDS):
            raise ItemSchemaError("Unsupported item kind filter")
        result = []
        for summary in summaries:
            if allowed is not None and summary.kind not in allowed:
                continue
            if collection_id is not None and collection_id not in summary.collection_ids:
                continue
            if favorite_only and not summary.favorite:
                continue
            # Only safe metadata is searched.  Credential username/scope are
            # existing metadata; typed payloads (note body/bookmark URL/notes)
            # are never read here.
            haystack = " ".join((summary.title, summary.kind, summary.username, *summary.tags)).casefold()
            if not needle or needle in haystack:
                result.append(summary)
        return sorted(result, key=lambda value: (not value.favorite, value.title.casefold(), value.id))

    def get_item(self, item_id: str, *, include_protected: bool = False) -> dict[str, Any] | None:
        """Return one item projection; protected values require explicit intent."""
        for item in self._items():
            if item.get("id") == item_id:
                return self._redact_item(item, include_protected=include_protected)
        return None

    def get_item_for_edit(self, item_id: str) -> dict[str, Any] | None:
        """Return payload data for an already-authorized editor action."""
        return self.get_item(item_id, include_protected=True)

    def create_note(self, title: str, body: str = "", *, tags: Iterable[str] | None = None,
                    collection_ids: Iterable[str] | None = None, favorite: bool = False,
                    template_id: str | None = None, fields: list[dict[str, Any]] | None = None) -> str:
        if not isinstance(body, str) or len(body) > MAX_NOTE_BODY:
            raise ItemSchemaError("note body is too long")
        item = new_item("note", title, {"body": body, "fields": fields or []}, tags=tags,
                        collection_ids=collection_ids, favorite=favorite, template_id=template_id)
        return self._append(item)

    def create_bookmark(self, title: str, url: str, *, notes: str = "",
                        tags: Iterable[str] | None = None, collection_ids: Iterable[str] | None = None,
                        favorite: bool = False, template_id: str | None = None) -> str:
        item = new_item("bookmark", title, {"url": validate_bookmark_url(url), "notes": notes},
                        tags=tags, collection_ids=collection_ids, favorite=favorite, template_id=template_id)
        return self._append(item)

    @staticmethod
    def _metadata_values(*, tags: Iterable[str] | None = None,
                         collection_ids: Iterable[str] | None = None,
                         favorite: bool = False) -> dict[str, Any]:
        return {"tags": tags, "collection_ids": collection_ids, "favorite": favorite}

    @staticmethod
    def _optional_payload(**values: Any) -> dict[str, Any]:
        return {key: value for key, value in values.items() if value is not None}

    def _create_safe_item(self, kind: str, title: str, typed_payload: dict[str, Any], *,
                          tags: Iterable[str] | None = None,
                          collection_ids: Iterable[str] | None = None,
                          favorite: bool = False, template_id: str | None = None) -> str:
        item = new_item(kind, title, typed_payload, tags=tags, collection_ids=collection_ids,
                        favorite=favorite, template_id=template_id)
        return self._append(item)

    def create_license(self, title: str, *, license_value: str = "", serial: str | None = None,
                       product: str = "", vendor: str = "", purchase_date: str = "",
                       expiration_date: str = "", document_ids: Iterable[str] | None = None,
                       notes: str = "", tags: Iterable[str] | None = None,
                       collection_ids: Iterable[str] | None = None, favorite: bool = False,
                       template_id: str | None = None) -> str:
        if serial is not None:
            if license_value:
                raise ItemSchemaError("Specify either license_value or serial, not both")
            license_value = serial
        return self._create_safe_item(
            "license", title,
            {"license_value": license_value, "product": product, "vendor": vendor,
             "purchase_date": purchase_date, "expiration_date": expiration_date,
             "document_ids": list(document_ids or []), "notes": notes},
            **self._metadata_values(tags=tags, collection_ids=collection_ids, favorite=favorite),
            template_id=template_id,
        )

    def _create_purchase_like(self, kind: str, title: str, *, product: str = "",
                              vendor: str = "", provider: str = "", purchase_date: str = "",
                              expiration_date: str = "", renewal_date: str = "",
                              amount_minor: int | None = None, currency: str | None = None,
                              document_ids: Iterable[str] | None = None, notes: str = "",
                              active: bool = True, tags: Iterable[str] | None = None,
                              collection_ids: Iterable[str] | None = None, favorite: bool = False,
                              template_id: str | None = None) -> str:
        typed_payload = {
            "product": product, "vendor": vendor, "provider": provider,
            "purchase_date": purchase_date, "expiration_date": expiration_date,
            "renewal_date": renewal_date, "document_ids": list(document_ids or []),
            "notes": notes, "active": active,
        }
        if amount_minor is not None or currency is not None:
            typed_payload["amount_minor"] = 0 if amount_minor is None else amount_minor
            typed_payload["currency"] = "XXX" if currency is None else currency
        return self._create_safe_item(
            kind, title, typed_payload,
            **self._metadata_values(tags=tags, collection_ids=collection_ids, favorite=favorite),
            template_id=template_id,
        )

    def create_purchase(self, title: str, **kwargs: Any) -> str:
        return self._create_purchase_like("purchase", title, **kwargs)

    def create_warranty(self, title: str, **kwargs: Any) -> str:
        return self._create_purchase_like("warranty", title, **kwargs)

    def create_subscription(self, title: str, **kwargs: Any) -> str:
        return self._create_purchase_like("subscription", title, **kwargs)

    def create_typed(self, kind: str, title: str, payload: Mapping[str, Any], **metadata: Any) -> str:
        """Create one schema-validated typed item for generic integrations."""
        if kind not in TYPED_SAFE_KINDS and kind != "identity" and kind not in SECRET_ITEM_KINDS:
            raise ItemSchemaError("create_typed only accepts supported typed-item kinds")
        if not isinstance(payload, Mapping):
            raise ItemSchemaError("typed item payload must be an object")
        return self._create_safe_item(kind, title, dict(payload), **metadata)

    def create_identity(self, title: str, fields: Mapping[str, Any] | None = None, *,
                        tags: Iterable[str] | None = None,
                        collection_ids: Iterable[str] | None = None,
                        favorite: bool = False, template_id: str | None = None) -> str:
        """Create a contact/address identity with a closed field allowlist.

        The values remain encrypted catalog data.  This method does not make
        them part of metadata summaries; browser release is a separate,
        approval-bound operation in :mod:`localvault.identity_fill`.
        """
        if fields is None:
            fields = {}
        if not isinstance(fields, Mapping):
            raise ItemSchemaError("identity fields must be an object")
        # Validate before constructing the item so callers get the same strict
        # boundary whether they use this named API or create_typed().
        clean = validate_identity_fields(dict(fields))
        return self._create_safe_item(
            "identity", title, clean,
            **self._metadata_values(tags=tags, collection_ids=collection_ids, favorite=favorite),
            template_id=template_id,
        )

    # -- secret-bearing kinds (card, bank account, SSH key, API key, Wi-Fi, passkey) --

    def _create_secret_kind(self, kind: str, title: str, typed_payload: dict[str, Any], *,
                            tags: Iterable[str] | None = None,
                            collection_ids: Iterable[str] | None = None,
                            favorite: bool = False, template_id: str | None = None) -> str:
        return self._create_safe_item(
            kind, title, self._optional_payload(**typed_payload),
            **self._metadata_values(tags=tags, collection_ids=collection_ids, favorite=favorite),
            template_id=template_id,
        )

    def create_card(self, title: str, *, cardholder: str = "", number: str = "", expiry: str = "",
                    cvv: str = "", pin: str = "", billing_address_id: str = "", notes: str = "",
                    **metadata: Any) -> str:
        """Create a payment card; the brand is derived from the Luhn-checked number."""
        return self._create_secret_kind("card", title, {
            "cardholder": cardholder, "number": number, "expiry": expiry, "cvv": cvv, "pin": pin,
            "billing_address_id": billing_address_id, "notes": notes,
        }, **metadata)

    def create_bank_account(self, title: str, *, bank: str = "", account_holder: str = "",
                            account_number: str = "", routing: str = "", pin: str = "",
                            notes: str = "", **metadata: Any) -> str:
        return self._create_secret_kind("bank_account", title, {
            "bank": bank, "account_holder": account_holder, "account_number": account_number,
            "routing": routing, "pin": pin, "notes": notes,
        }, **metadata)

    def create_ssh_key(self, title: str, *, private_key: str = "", public_key: str = "",
                       passphrase: str = "", fingerprint: str = "", notes: str = "",
                       **metadata: Any) -> str:
        return self._create_secret_kind("ssh_key", title, {
            "private_key": private_key, "public_key": public_key, "passphrase": passphrase,
            "fingerprint": fingerprint, "notes": notes,
        }, **metadata)

    def create_api_key(self, title: str, *, service: str = "", key: str = "", secret: str = "",
                       expires: str = "", notes: str = "", **metadata: Any) -> str:
        return self._create_secret_kind("api_key", title, {
            "service": service, "key": key, "secret": secret, "expires": expires, "notes": notes,
        }, **metadata)

    def create_wifi(self, title: str, *, ssid: str = "", password: str = "", security: str = "wpa2",
                    hidden: bool = False, notes: str = "", **metadata: Any) -> str:
        return self._create_secret_kind("wifi", title, {
            "ssid": ssid, "password": password, "security": security, "hidden": hidden, "notes": notes,
        }, **metadata)

    def create_passkey(self, title: str, *, relying_party_id: str = "", user_handle: str = "",
                       credential_id: str = "", private_key: str = "", algorithm: str = "",
                       created: str = "", notes: str = "", user_name: str = "",
                       user_display_name: str = "", rp_name: str = "", discoverable: bool = True,
                       **metadata: Any) -> str:
        """Store a passkey record (created by a website or imported)."""
        return self._create_secret_kind("passkey", title, {
            "relying_party_id": relying_party_id, "user_handle": user_handle,
            "credential_id": credential_id, "private_key": private_key, "algorithm": algorithm,
            "created": created, "notes": notes, "user_name": user_name,
            "user_display_name": user_display_name, "rp_name": rp_name, "discoverable": discoverable,
        }, **metadata)

    def passkey_records(self, rp_id: str) -> list[dict[str, Any]]:
        """Return the live passkeys for one relying party, private key included.

        Only the broker's WebAuthn handlers use this: they sign inside the
        agent and never release the key.  Trashed items are not included.
        """
        records = []
        for item in self._items():
            payload = item.get("payload")
            if item.get("kind") != "passkey" or not isinstance(payload, dict):
                continue
            if payload.get("relying_party_id") != rp_id:
                continue
            records.append({**copy.deepcopy(payload), "id": item["id"], "title": item.get("title", "")})
        records.sort(key=lambda record: (record["title"].casefold(), record["id"]))
        return records

    def card_fill_view(self, item_id: str, *, expected_revision: int | None = None) -> dict[str, Any]:
        """Return the browser-fillable projection of one card.

        The result maps HTML ``autocomplete`` tokens to values and never
        contains the PIN.  Like ``identity_release_view`` this is not used by
        listing APIs; the caller still owns approval and origin binding (see
        :mod:`localvault.identity_fill`).
        """
        self._payload()
        item = next((value for value in self._items() if value.get("id") == item_id), None)
        if item is None or item.get("kind") != "card":
            raise VaultError("Card item was not found")
        revision = item.get("revision")
        if expected_revision is not None and revision != expected_revision:
            raise VaultError("Card revision conflict")
        typed = item.get("payload", {})
        month, year = card_expiry_parts(str(typed.get("expiry", "")))
        fields = {
            "cc-name": str(typed.get("cardholder", "")),
            "cc-number": str(typed.get("number", "")),
            "cc-exp": f"{month}/{year}" if month and year else "",
            "cc-exp-month": month,
            "cc-exp-year": year,
            "cc-csc": str(typed.get("cvv", "")),
            "cc-type": str(typed.get("brand", "")),
        }
        return {"id": item["id"], "title": item["title"], "revision": revision,
                "fields": {token: fields[token] for token in CARD_FILL_TOKENS}}

    # -- multi-URL web logins --------------------------------------------------

    def _web_entry(self, entry_id: str) -> dict[str, Any]:
        entries = self._payload().get("entries", [])
        if not isinstance(entries, list):
            raise VaultError("Vault entries are malformed")
        entry = next((value for value in entries
                      if isinstance(value, dict) and value.get("id") == entry_id), None)
        if entry is None or entry.get("kind") != "web":
            raise VaultError("Website login was not found")
        return entry

    def web_urls(self, entry_id: str) -> list[dict[str, str]]:
        """Return the URL rows of a web login, migrating a legacy single origin."""
        entry = self.session.get_entry(entry_id)
        if entry is None or entry.get("kind") != "web":
            raise VaultError("Website login was not found")
        try:
            return migrate_web_scope(entry.get("scope", {}))["urls"]
        except (ItemSchemaError, OriginError):
            # An address stored before the stricter origin rules (2026-10-24)
            # stays visible as typed so the user can fix it; saving it again
            # is validated, and it is never offered for fill.
            return [{"url": row["url"], "match": row["match"]} for row in entry_urls(entry)]

    def set_web_urls(self, entry_id: str, urls: Any) -> bool:
        """Replace the URL rows of a web login.

        ``urls[0]`` must be an ``exact_origin`` row (or the first row's origin
        is promoted to one) and becomes the legacy ``scope.origin`` so exact
        matching and older readers keep working.
        """
        rows = validate_web_urls(urls)
        if not rows:
            raise ItemSchemaError("A website login needs at least one URL")
        payload = self._payload()
        entry = self._web_entry(entry_id)
        original = copy.deepcopy(entry)
        scope = dict(entry.get("scope", {}))
        scope["urls"] = rows
        scope.pop("origin", None)
        migrated = migrate_web_scope(scope)
        if migrated.get("urls") == original.get("scope", {}).get("urls") and                 migrated.get("origin") == original.get("scope", {}).get("origin"):
            return False
        entry["scope"] = migrated
        now = int(time.time())
        entry["updated_at"] = now
        payload["updated_at"] = now
        try:
            self.session.save()
        except BaseException:
            entry.clear()
            entry.update(original)
            raise
        return True

    def find_web_candidates(self, url: str) -> list[dict[str, Any]]:
        """Return redacted web logins whose URL rows match ``url``, best first.

        Secrets (password, history, TOTP, recovery codes) are stripped; the
        broker must fetch the password through its own permission path.
        """
        entries = self._payload().get("entries", [])
        if not isinstance(entries, list):
            raise VaultError("Vault entries are malformed")
        result = []
        for entry in candidates_for(entries, url):
            redacted = copy.deepcopy(entry)
            for key in _WEB_ENTRY_SECRETS:
                redacted.pop(key, None)
            try:
                redacted["scope"] = migrate_web_scope(redacted.get("scope", {}))
            except (ItemSchemaError, OriginError):
                # A stored address the current origin rules refuse (an old
                # vault) is never offered for fill, even if another row matched.
                continue
            result.append(redacted)
        return result

    def _update_candidate(self, item_id: str, *, kind: str | None = None,
                          typed_payload: Mapping[str, Any] | None = None,
                          title: str | None = None, favorite: bool | None = None,
                          tags: Iterable[str] | None = None,
                          collection_ids: Iterable[str] | None = None,
                          expected_revision: int | None = None) -> bool:
        payload = self._payload()
        item = next((value for value in self._items() if value.get("id") == item_id), None)
        if item is None:
            return False
        if kind is not None and item.get("kind") != kind:
            raise VaultError(f"This item is not a {kind}")
        if (expected_revision is not None
                and (type(expected_revision) is not int or expected_revision != item.get("revision"))):
            raise VaultError("Item revision conflict")
        original = copy.deepcopy(item)
        candidate = copy.deepcopy(item)
        if title is not None:
            candidate["title"] = title
        if favorite is not None:
            candidate["favorite"] = favorite
        if tags is not None:
            candidate["tags"] = normalize_tags(tags)
        if collection_ids is not None:
            candidate["collection_ids"] = list(collection_ids)
        if typed_payload is not None:
            if not isinstance(typed_payload, Mapping):
                raise ItemSchemaError("typed item payload must be an object")
            candidate["payload"].update(copy.deepcopy(dict(typed_payload)))
        candidate["updated_at"] = int(time.time())
        candidate["revision"] = int(candidate.get("revision", 1)) + 1
        validated = validate_item(candidate, known_collection_ids=self._known_collection_ids(payload))
        self._validate_references(validated, payload)
        # Editing a form without changing its semantic values is a no-op: it
        # must not consume a revision or create a history snapshot.  The
        # timestamps and revision counter are intentionally excluded from
        # this comparison.
        semantic_original = {key: value for key, value in original.items()
                             if key not in {"updated_at", "revision"}}
        semantic_candidate = {key: value for key, value in validated.items()
                              if key not in {"updated_at", "revision"}}
        if semantic_original == semantic_candidate:
            return False
        history = getattr(self.session, "history", None)
        history_rows = copy.deepcopy(payload.get("history", []))
        if history is not None:
            history.record_before_change(original, persist=False)
        item.clear()
        item.update(validated)
        payload["updated_at"] = int(time.time())
        try:
            self.session.save()
        except BaseException:
            item.clear()
            item.update(original)
            if history is not None:
                payload["history"] = history_rows
            raise
        return True

    def update_item(self, item_id: str, *, title: str | None = None, body: str | None = None,
                    url: str | None = None, notes: str | None = None,
                    favorite: bool | None = None, tags: Iterable[str] | None = None,
                    collection_ids: Iterable[str] | None = None,
                    fields: list[dict[str, Any]] | None = None,
                    typed_payload: Mapping[str, Any] | None = None,
                    expected_revision: int | None = None) -> bool:
        item = next((value for value in self._items() if value.get("id") == item_id), None)
        if item is None:
            return False
        if item["kind"] in TYPED_SAFE_KINDS:
            changes = dict(typed_payload or {})
            if any(value is not None for value in (body, url, fields)):
                raise ItemSchemaError("Use typed_payload for this item kind")
            if notes is not None:
                changes["notes"] = notes
            return self._update_candidate(
                item_id, kind=item["kind"], typed_payload=changes, title=title,
                favorite=favorite, tags=tags, collection_ids=collection_ids,
                expected_revision=expected_revision,
            )
        if item["kind"] in SECRET_ITEM_KINDS:
            changes = dict(typed_payload or {})
            if any(value is not None for value in (body, url, fields)):
                raise ItemSchemaError("Use typed_payload for this item kind")
            if notes is not None:
                changes["notes"] = notes
            return self._update_candidate(
                item_id, kind=item["kind"], typed_payload=changes, title=title,
                favorite=favorite, tags=tags, collection_ids=collection_ids,
                expected_revision=expected_revision,
            )
        if item["kind"] == "identity":
            if any(value is not None for value in (body, url, notes, fields)):
                raise ItemSchemaError("Use typed_payload for an identity item")
            return self._update_candidate(
                item_id, kind="identity", typed_payload=typed_payload, title=title,
                favorite=favorite, tags=tags, collection_ids=collection_ids,
                expected_revision=expected_revision,
            )
        if item["kind"] not in {"note", "bookmark"}:
            raise VaultError("This item type is reserved for a later milestone")
        if typed_payload is not None:
            raise ItemSchemaError("Use body/url/notes/fields for note and bookmark items")
        changes: dict[str, Any] = {}
        if item["kind"] == "note":
            if body is not None:
                changes["body"] = body
            if fields is not None:
                changes["fields"] = fields
        else:
            if url is not None:
                changes["url"] = validate_bookmark_url(url)
            if notes is not None:
                changes["notes"] = notes
        return self._update_candidate(
            item_id, kind=item["kind"], typed_payload=changes, title=title,
            favorite=favorite, tags=tags, collection_ids=collection_ids,
            expected_revision=expected_revision,
        )

    def update_typed_item(self, item_id: str, *, payload: Mapping[str, Any] | None = None,
                          title: str | None = None, favorite: bool | None = None,
                          tags: Iterable[str] | None = None,
                          collection_ids: Iterable[str] | None = None,
                          expected_revision: int | None = None) -> bool:
        item = next((value for value in self._items() if value.get("id") == item_id), None)
        if item is None:
            return False
        if item.get("kind") not in ITEM_KINDS - {"web", "desktop"}:
            raise VaultError("This item is not a supported typed item")
        return self._update_candidate(
            item_id, kind=item["kind"], typed_payload=payload, title=title,
            favorite=favorite, tags=tags, collection_ids=collection_ids,
            expected_revision=expected_revision,
        )

    def update_identity(self, item_id: str, fields: Mapping[str, Any] | None = None, *,
                        title: str | None = None, tags: Iterable[str] | None = None,
                        collection_ids: Iterable[str] | None = None,
                        favorite: bool | None = None,
                        expected_revision: int | None = None) -> bool:
        """Update only allowlisted identity fields with revision protection."""
        if fields is not None and not isinstance(fields, Mapping):
            raise ItemSchemaError("identity fields must be an object")
        return self._update_candidate(
            item_id, kind="identity",
            typed_payload=dict(fields) if fields is not None else None,
            title=title, favorite=favorite, tags=tags, collection_ids=collection_ids,
            expected_revision=expected_revision,
        )

    def identity_release_view(self, item_id: str, *, expected_revision: int | None = None) -> dict[str, Any]:
        """Return the minimum authenticated view needed for an approved release.

        This is intentionally not used by listing/search APIs.  The caller
        must still perform user approval and a session/context-bound release.
        """
        self._payload()
        item = next((value for value in self._items() if value.get("id") == item_id), None)
        if item is None or item.get("kind") != "identity":
            raise VaultError("Identity item was not found")
        revision = item.get("revision")
        if expected_revision is not None and revision != expected_revision:
            raise VaultError("Identity revision conflict")
        return {
            "id": item["id"],
            "title": item["title"],
            "revision": revision,
            "fields": validate_identity_fields(item.get("payload", {})),
        }

    def _update_license(self, item_id: str, *, license_value: str | None = None,
                        serial: str | None = None, **changes: Any) -> bool:
        if license_value is not None and serial is not None:
            raise ItemSchemaError("Specify either license_value or serial, not both")
        if serial is not None:
            changes["license_value"] = serial
        elif license_value is not None:
            changes["license_value"] = license_value
        return self.update_typed_item(item_id, payload=changes)

    def update_license(self, item_id: str, *, title: str | None = None,
                       license_value: str | None = None, serial: str | None = None,
                       product: str | None = None, vendor: str | None = None,
                       purchase_date: str | None = None, expiration_date: str | None = None,
                       document_ids: Iterable[str] | None = None, notes: str | None = None,
                       tags: Iterable[str] | None = None,
                       collection_ids: Iterable[str] | None = None, favorite: bool | None = None,
                       expected_revision: int | None = None) -> bool:
        changes = self._optional_payload(product=product, vendor=vendor, purchase_date=purchase_date,
                                         expiration_date=expiration_date, document_ids=(
                                             list(document_ids) if document_ids is not None else None),
                                         notes=notes)
        if license_value is not None and serial is not None:
            raise ItemSchemaError("Specify either license_value or serial, not both")
        changes["license_value"] = serial if serial is not None else license_value if license_value is not None else None
        changes = {key: value for key, value in changes.items() if value is not None}
        return self._update_candidate(item_id, kind="license", typed_payload=changes, title=title,
                                      favorite=favorite, tags=tags, collection_ids=collection_ids,
                                      expected_revision=expected_revision)

    def _update_purchase_like(self, item_id: str, kind: str, *, title: str | None = None,
                              product: str | None = None, vendor: str | None = None,
                              provider: str | None = None, purchase_date: str | None = None,
                              expiration_date: str | None = None, renewal_date: str | None = None,
                              amount_minor: int | None = None, currency: str | None = None,
                              document_ids: Iterable[str] | None = None, notes: str | None = None,
                              active: bool | None = None, tags: Iterable[str] | None = None,
                              collection_ids: Iterable[str] | None = None, favorite: bool | None = None,
                              expected_revision: int | None = None) -> bool:
        changes = self._optional_payload(
            product=product, vendor=vendor, provider=provider, purchase_date=purchase_date,
            expiration_date=expiration_date, renewal_date=renewal_date,
            amount_minor=amount_minor, currency=currency,
            document_ids=list(document_ids) if document_ids is not None else None,
            notes=notes, active=active,
        )
        return self._update_candidate(item_id, kind=kind, typed_payload=changes, title=title,
                                      favorite=favorite, tags=tags, collection_ids=collection_ids,
                                      expected_revision=expected_revision)

    def update_purchase(self, item_id: str, **kwargs: Any) -> bool:
        return self._update_purchase_like(item_id, "purchase", **kwargs)

    def update_warranty(self, item_id: str, **kwargs: Any) -> bool:
        return self._update_purchase_like(item_id, "warranty", **kwargs)

    def update_subscription(self, item_id: str, **kwargs: Any) -> bool:
        return self._update_purchase_like(item_id, "subscription", **kwargs)

    def set_metadata(self, item_id: str, *, favorite: bool | None = None,
                     tags: Iterable[str] | None = None, collection_ids: Iterable[str] | None = None) -> bool:
        # Favorite, tags and collections never touch the payload, so every
        # typed kind accepts them, including kinds without a payload editor.
        item = next((value for value in self._items() if value.get("id") == item_id), None)
        if item is None:
            return False
        if item.get("kind") in {"web", "desktop"}:
            raise VaultError("Use the credential service for logins")
        return self._update_candidate(item_id, kind=item["kind"], favorite=favorite,
                                      tags=tags, collection_ids=collection_ids)

    def delete_item(self, item_id: str) -> bool:
        payload = self._payload()
        items = self._items()
        item = next((value for value in items if value.get("id") == item_id), None)
        if item is None:
            return False
        if (item.get("kind") == "document"
                and any(item_id in value.get("payload", {}).get("document_ids", [])
                        for value in items if value is not item and isinstance(value, dict))):
            raise VaultError("Document is referenced by a live item")
        trash = payload.setdefault("trash", [])
        if len(trash) >= MAX_ITEMS:
            raise ItemSchemaError("The deleted-item limit has been reached")
        history = getattr(self.session, "history", None)
        history_rows = copy.deepcopy(payload.get("history", []))
        if history is not None:
            history.record_before_change(item, change_type="delete", persist=False)
        trash.append({"entry": copy.deepcopy(item), "deleted_at": int(time.time())})
        items.remove(item)
        payload["updated_at"] = int(time.time())
        try:
            self.session.save()
        except BaseException:
            if history is not None:
                payload["history"] = history_rows
            raise
        return True

    def trash_summaries(self) -> list[dict[str, Any]]:
        """Return safe metadata for deleted typed items only."""
        self._payload()
        result = []
        for record in self.session._require_typed_catalog().get("trash", []):
            entry = record.get("entry") if isinstance(record, dict) else None
            if not isinstance(entry, dict) or entry.get("kind") in {"web", "desktop"}:
                continue
            summary = summary_from_item(entry)
            result.append({"id": summary.id, "kind": summary.kind, "title": summary.title,
                           "created_at": summary.created_at, "updated_at": summary.updated_at,
                           "revision": summary.revision, "favorite": summary.favorite,
                           "tags": summary.tags, "collection_ids": summary.collection_ids,
                           "deleted_at": record["deleted_at"]})
        return result

    def restore_item(self, item_id: str) -> bool:
        """Restore one deleted typed item without exposing its protected payload."""
        payload = self._payload()
        record = next((value for value in payload.get("trash", [])
                       if isinstance(value, dict) and isinstance(value.get("entry"), dict)
                       and value["entry"].get("id") == item_id
                       and value["entry"].get("kind") not in {"web", "desktop"}), None)
        if record is None:
            return False
        if any(value.get("id") == item_id for value in self._items()):
            raise VaultError("A live item with this ID already exists")
        items = self._items()
        if len(items) >= MAX_ITEMS:
            raise ItemSchemaError("The typed item limit has been reached")
        self._check_can_create()
        restored = validate_item(record["entry"], known_collection_ids=self._known_collection_ids(payload))
        self._validate_references(restored, payload)
        items.append(restored)
        payload["trash"].remove(record)
        payload["updated_at"] = int(time.time())
        try:
            self.session.save()
        except BaseException:
            if restored in items:
                items.remove(restored)
            if record not in payload.get("trash", []):
                payload.setdefault("trash", []).append(record)
            raise
        return True

    restore_typed_item = restore_item

    def _secret_value(self, item_id: str, field: str, *, intent: str | None) -> str:
        self._payload()
        if not isinstance(intent, str) or not intent.strip():
            raise ItemSchemaError("An explicit caller intent is required to release a secret")
        if not isinstance(field, str) or not field:
            raise ItemSchemaError("Unsupported protected field")
        item = next((value for value in self._items() if value.get("id") == item_id), None)
        if item is None:
            raise VaultError("Item was not found")
        kind = item.get("kind")
        if kind not in RELEASABLE_SECRET_KINDS:
            raise ItemSchemaError("This item has no releasable protected field")
        if kind == "license":
            resolved = _LICENSE_SECRET_ALIASES.get(field.casefold())
        else:
            resolved = field if field in PROTECTED_FIELDS_BY_KIND.get(kind, ()) else None
        if resolved is None:
            raise ItemSchemaError("Unsupported protected field")
        value = item.get("payload", {}).get(resolved, "")
        if not isinstance(value, str):
            raise VaultError("Protected value is malformed")
        return value

    def reveal_secret(self, item_id: str, field: str = "license_value", *,
                      intent: str | None = None) -> str:
        """Release one protected field only for an explicit action.

        ``field`` is a license alias (``serial``/``key``...) or, for the
        secret-bearing kinds, a name from ``PROTECTED_FIELDS_BY_KIND``.
        """
        return self._secret_value(item_id, field, intent=intent)

    def copy_secret(self, item_id: str, field: str = "license_value", *,
                    intent: str | None = None) -> str:
        """Return a protected value for a caller-owned, explicit copy action.

        Clipboard lifecycle and clearing remain the responsibility of the
        caller (for example, ClipboardGuard); this service never copies a
        secret implicitly during listing, searching, or filtering.
        """
        return self._secret_value(item_id, field, intent=intent)

    def reveal_license_value(self, item_id: str, *, intent: str | None = None) -> str:
        return self.reveal_secret(item_id, "license_value", intent=intent)

    def copy_license_value(self, item_id: str, *, intent: str | None = None) -> str:
        return self.copy_secret(item_id, "license_value", intent=intent)

    reveal_serial = reveal_license_value
    copy_serial = copy_license_value


# The name used in the implementation plan is intentionally kept as an alias
# for callers that want to emphasize the aggregate boundary.
CatalogService = ItemService
