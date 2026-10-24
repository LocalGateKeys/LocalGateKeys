"""Declarative, local templates for typed safe items."""
from __future__ import annotations

import copy
import time
import uuid
from typing import Any

from .item_schema import MAX_TEMPLATES, ItemSchemaError, validate_template, validate_templates
from .vault import VaultLockedError

BUILTIN_TEMPLATES: tuple[dict[str, Any], ...] = (
    {"id": "builtin.note", "kind": "note", "name": "Note", "description": "A private plain-text note.",
     "fields": [{"name": "body", "label": "Body", "type": "multiline", "required": False, "secret": False}]},
    {"id": "builtin.bookmark", "kind": "bookmark", "name": "Bookmark", "description": "A local HTTPS bookmark opened only by explicit user action.",
     "fields": [{"name": "url", "label": "HTTPS URL", "type": "url", "required": True, "secret": False},
                {"name": "notes", "label": "Notes", "type": "multiline", "required": False, "secret": False}]},
    {"id": "builtin.document", "kind": "document", "name": "Document", "description": "Metadata for a later encrypted document attachment.",
     "fields": [{"name": "description", "label": "Description", "type": "text", "required": False, "secret": False}]},
    {"id": "builtin.license", "kind": "license", "name": "License", "description": "Software license metadata; protected value arrives in M4.",
     "fields": [{"name": "product", "label": "Product", "type": "text", "required": True, "secret": False},
                {"name": "license_value", "label": "License key / serial", "type": "text", "required": False, "secret": True}]},
    {"id": "builtin.purchase", "kind": "purchase", "name": "Purchase", "description": "Purchase and receipt metadata with optional linked documents.",
     "fields": [{"name": "product", "label": "Product", "type": "text", "required": False, "secret": False},
                {"name": "vendor", "label": "Vendor", "type": "text", "required": False, "secret": False},
                {"name": "amount_minor", "label": "Amount in minor units", "type": "number", "required": False, "secret": False},
                {"name": "currency", "label": "Currency", "type": "text", "required": False, "secret": False}]},
    {"id": "builtin.receipt", "kind": "purchase", "name": "Receipt", "description": "Purchase receipt metadata; linked files arrive in M3/M4.",
     "fields": [{"name": "vendor", "label": "Vendor", "type": "text", "required": False, "secret": False}]},
    {"id": "builtin.warranty", "kind": "warranty", "name": "Warranty", "description": "Warranty metadata and dates with an optional linked receipt.",
     "fields": [{"name": "provider", "label": "Provider", "type": "text", "required": False, "secret": False}]},
    {"id": "builtin.subscription", "kind": "subscription", "name": "Subscription", "description": "Subscription metadata; renewal dates are informational only.",
     "fields": [{"name": "provider", "label": "Provider", "type": "text", "required": False, "secret": False},
                {"name": "renewal_date", "label": "Renewal date", "type": "date", "required": False, "secret": False}]},
    # Identity payloads are intentionally limited to the contact/address
    # schema.  Keep this built-in as a chooser label without advertising an
    # ``instructions`` field that the identity validator cannot persist.
    {"id": "builtin.emergency-information", "kind": "identity", "name": "Emergency information", "description": "Local contact information; identity release is deferred.",
     "fields": []},
    {"id": "builtin.card", "kind": "card", "name": "Payment card", "description": "Card details; the number is Luhn-checked and the brand is detected. PIN is desktop-only.",
     "fields": [{"name": "cardholder", "label": "Cardholder", "type": "text", "required": False, "secret": False},
                {"name": "number", "label": "Card number", "type": "text", "required": True, "secret": True},
                {"name": "expiry", "label": "Expiry MM/YY", "type": "text", "required": False, "secret": False},
                {"name": "cvv", "label": "CVV", "type": "text", "required": False, "secret": True},
                {"name": "pin", "label": "PIN", "type": "text", "required": False, "secret": True}]},
    {"id": "builtin.bank-account", "kind": "bank_account", "name": "Bank account", "description": "Bank account with IBAN checksum validation and a protected PIN.",
     "fields": [{"name": "bank", "label": "Bank", "type": "text", "required": False, "secret": False},
                {"name": "account_holder", "label": "Account holder", "type": "text", "required": False, "secret": False},
                {"name": "account_number", "label": "IBAN / account number", "type": "text", "required": True, "secret": True},
                {"name": "routing", "label": "Routing / BIC", "type": "text", "required": False, "secret": False},
                {"name": "pin", "label": "PIN", "type": "text", "required": False, "secret": True}]},
    {"id": "builtin.ssh-key", "kind": "ssh_key", "name": "SSH key", "description": "Private key with format sniffing and a SHA256 fingerprint computed from the OpenSSH public key.",
     "fields": [{"name": "private_key", "label": "Private key", "type": "multiline", "required": True, "secret": True},
                {"name": "public_key", "label": "Public key", "type": "multiline", "required": False, "secret": False},
                {"name": "passphrase", "label": "Passphrase", "type": "text", "required": False, "secret": True}]},
    {"id": "builtin.api-key", "kind": "api_key", "name": "API key", "description": "Service credential with protected key/secret and an optional expiry.",
     "fields": [{"name": "service", "label": "Service", "type": "text", "required": True, "secret": False},
                {"name": "key", "label": "Key", "type": "text", "required": False, "secret": True},
                {"name": "secret", "label": "Secret", "type": "text", "required": False, "secret": True},
                {"name": "expires", "label": "Expires", "type": "date", "required": False, "secret": False}]},
    {"id": "builtin.wifi", "kind": "wifi", "name": "Wi-Fi network", "description": "Network name, protected password, security type and hidden flag.",
     "fields": [{"name": "ssid", "label": "Network name (SSID)", "type": "text", "required": True, "secret": False},
                {"name": "password", "label": "Password", "type": "text", "required": False, "secret": True},
                {"name": "security", "label": "Security type", "type": "text", "required": False, "secret": False}]},
    {"id": "builtin.passkey", "kind": "passkey", "name": "Passkey (scaffold)", "description": "Stores passkey material for backup only. No WebAuthn sign-in flow exists yet.",
     "fields": [{"name": "relying_party_id", "label": "Relying party id", "type": "text", "required": True, "secret": False},
                {"name": "user_handle", "label": "User handle", "type": "text", "required": False, "secret": False},
                {"name": "credential_id", "label": "Credential id", "type": "text", "required": False, "secret": False},
                {"name": "private_key", "label": "Private key", "type": "multiline", "required": False, "secret": True},
                {"name": "algorithm", "label": "Algorithm", "type": "text", "required": False, "secret": False}]},
)
def _validate_definition(value: Any) -> dict[str, Any]:
    return validate_template(value)


class TemplateService:
    def __init__(self, session: Any) -> None:
        self.session = session

    def _payload(self) -> dict[str, Any]:
        if not getattr(self.session, "is_unlocked", False):
            raise VaultLockedError("Vault is locked")
        return self.session._require_typed_catalog()

    def list(self, *, kind: str | None = None) -> list[dict[str, Any]]:
        builtins = [copy.deepcopy(value) for value in BUILTIN_TEMPLATES if kind is None or value["kind"] == kind]
        custom = [copy.deepcopy(value) for value in validate_templates(self._payload().get("templates", []))
                  if kind is None or value["kind"] == kind]
        return builtins + custom

    def get(self, template_id: str) -> dict[str, Any] | None:
        return next((value for value in self.list() if value["id"] == template_id), None)

    def create(self, *, kind: str, name: str, fields: list[dict[str, Any]] | None = None,
               description: str = "") -> str:
        payload = self._payload()
        templates = payload.setdefault("templates", [])
        if len(templates) >= MAX_TEMPLATES:
            raise ItemSchemaError("Template limit reached")
        row = _validate_definition({"id": str(uuid.uuid4()), "kind": kind, "name": name,
                                    "description": description, "fields": fields or []})
        if any(value["name"].casefold() == row["name"].casefold() for value in templates):
            raise ItemSchemaError("A custom template with that name already exists")
        templates.append(row)
        payload["updated_at"] = int(time.time())
        self.session.save()
        self._record_activity("template.create")
        return row["id"]

    def _record_activity(self, event_type: str) -> None:
        try:
            self.session.activity.record(event_type)
        except (AttributeError, ItemSchemaError, VaultLockedError):
            pass

    def update(self, template_id: str, *, name: str | None = None,
               fields: list[dict[str, Any]] | None = None, description: str | None = None) -> bool:
        payload = self._payload()
        row = next((value for value in payload.get("templates", []) if value["id"] == template_id), None)
        if row is None:
            return False
        candidate = copy.deepcopy(row)
        if name is not None:
            candidate["name"] = name
        if fields is not None:
            candidate["fields"] = fields
        if description is not None:
            candidate["description"] = description
        candidate["updated_at"] = int(time.time())
        candidate["revision"] = int(row.get("revision", 1)) + 1
        validated = _validate_definition(candidate)
        row.clear()
        row.update(validated)
        payload["updated_at"] = int(time.time())
        self.session.save()
        self._record_activity("template.update")
        return True

    def delete(self, template_id: str) -> bool:
        payload = self._payload()
        before = len(payload.get("templates", []))
        payload["templates"] = [value for value in payload.get("templates", []) if value["id"] != template_id]
        if len(payload["templates"]) == before:
            return False
        payload["updated_at"] = int(time.time())
        self.session.save()
        self._record_activity("template.delete")
        return True

    def select(self, template_id: str, *, kind: str | None = None) -> dict[str, Any] | None:
        """Return one validated declarative definition for an explicit chooser."""
        value = next((row for row in self.list(kind=kind) if row["id"] == template_id), None)
        return copy.deepcopy(value) if value is not None else None

    def editor_definition(self, template_id: str, *, kind: str | None = None) -> dict[str, Any] | None:
        """Return a safe editor definition with blank draft values.

        Template schemas describe form shape only.  The editor may use this
        projection to render useful labels and blank non-secret controls, but
        no template field is ever copied into a protected value.
        """
        value = self.select(template_id, kind=kind)
        if value is None:
            return None
        fields = [field for field in value.get("fields", []) if isinstance(field, dict)]
        value["draft_values"] = {
            str(field["name"]): ""
            for field in fields
            if field.get("name") and not field.get("secret")
        }
        value["protected_fields"] = [
            str(field["name"]) for field in fields if field.get("name") and field.get("secret")
        ]
        return value
