"""Typed item form vocabulary shared by every UI: kind labels, per-kind fields, choices and notes."""
from __future__ import annotations

from ..item_schema import (
    PASSKEY_ALGORITHMS,
    WIFI_SECURITY_TYPES,
)

KIND_LABELS = {
    "note": "Note",
    "bookmark": "Bookmark",
    "document": "Document",
    "license": "License",
    "purchase": "Purchase",
    "warranty": "Warranty",
    "subscription": "Subscription",
    "identity": "Identity",
    "card": "Payment card",
    "bank_account": "Bank account",
    "ssh_key": "SSH key",
    "api_key": "API key",
    "wifi": "Wi-Fi network",
    "passkey": "Passkey",
}


KIND_ORDER = tuple(KIND_LABELS)


KIND_CODE_BY_LABEL = {label: kind for kind, label in KIND_LABELS.items()}


PURCHASE_LIKE = {"purchase", "warranty", "subscription"}


# Catalog keys; typed.py translates them when it builds the form.
IDENTITY_LABELS = {
    "name": "typed.identity.name",
    "given_name": "typed.identity.given_name",
    "middle_name": "typed.identity.middle_name",
    "family_name": "typed.identity.family_name",
    "organization": "typed.identity.organization",
    "company": "typed.identity.company",
    "job_title": "typed.identity.job_title",
    "email": "typed.identity.email",
    "phone": "typed.identity.phone",
    "address": "typed.identity.address",
    "address_line1": "typed.identity.address_line1",
    "address_line2": "typed.identity.address_line2",
    "city": "typed.identity.city",
    "state": "typed.identity.state",
    "postal_code": "typed.identity.postal_code",
    "country": "typed.identity.country",
    "website": "typed.identity.website",
}


# Editor layout for the secret-bearing kinds: ``(key, label, control)`` where
# control is ``text``, ``multiline``, ``choice`` or ``bool``.  Whether a field
# is masked by default is NOT decided here: it comes from
# ``PROTECTED_FIELDS_BY_KIND`` so the editor cannot drift from the schema.
SECRET_KIND_FIELDS: dict[str, tuple[tuple[str, str, str], ...]] = {
    "card": (
        ("cardholder", "typed.field.card.cardholder", "text"),
        ("number", "typed.field.card.number", "text"),
        ("expiry", "typed.field.card.expiry", "text"),
        ("cvv", "typed.field.card.cvv", "text"),
        ("pin", "typed.field.card.pin", "text"),
    ),
    "bank_account": (
        ("bank", "typed.field.bank_account.bank", "text"),
        ("account_holder", "typed.field.bank_account.account_holder", "text"),
        ("account_number", "typed.field.bank_account.account_number", "text"),
        ("routing", "typed.field.bank_account.routing", "text"),
        ("pin", "typed.field.bank_account.pin", "text"),
    ),
    "ssh_key": (
        ("private_key", "typed.field.ssh_key.private_key", "multiline"),
        ("public_key", "typed.field.ssh_key.public_key", "multiline"),
        ("passphrase", "typed.field.ssh_key.passphrase", "text"),
        ("fingerprint", "typed.field.ssh_key.fingerprint", "text"),
    ),
    "api_key": (
        ("service", "typed.field.api_key.service", "text"),
        ("key", "typed.field.api_key.key", "text"),
        ("secret", "typed.field.api_key.secret", "text"),
        ("expires", "typed.field.api_key.expires", "text"),
    ),
    "wifi": (
        ("ssid", "typed.field.wifi.ssid", "text"),
        ("password", "typed.field.wifi.password", "text"),
        ("security", "typed.field.wifi.security", "choice"),
        ("hidden", "typed.field.wifi.hidden", "bool"),
    ),
    "passkey": (
        ("rp_name", "typed.field.passkey.rp_name", "text"),
        ("relying_party_id", "typed.field.passkey.relying_party_id", "text"),
        ("user_name", "typed.field.passkey.user_name", "text"),
        ("user_handle", "typed.field.passkey.user_handle", "text"),
        ("credential_id", "typed.field.passkey.credential_id", "text"),
        ("private_key", "typed.field.passkey.private_key", "multiline"),
        ("algorithm", "typed.field.passkey.algorithm", "choice"),
        ("created", "typed.field.passkey.created", "text"),
    ),
}


SECRET_KIND_CHOICES: dict[str, tuple[str, ...]] = {
    "security": WIFI_SECURITY_TYPES,
    "algorithm": ("", *PASSKEY_ALGORITHMS),
}


SECRET_KIND_NOTES: dict[str, str] = {
    "card": "typed.note.card",
    "bank_account": "typed.note.bank_account",
    "ssh_key": "typed.note.ssh_key",
    "api_key": "typed.note.api_key",
    "wifi": "typed.note.wifi",
    "passkey": "typed.note.passkey",
}


# Payload fields a secret kind keeps but its edit form does not show. Saving
# the form carries them over from the stored item instead of dropping them.
SECRET_FORM_HIDDEN_FIELDS: dict[str, tuple[str, ...]] = {
    "passkey": ("user_display_name", "discoverable"),
}


def kind_title(kind: str) -> str:
    """The shown name of an item kind, in the active language."""
    from ..i18n import t

    return t(f"kind.{kind}") if kind in KIND_LABELS else kind
