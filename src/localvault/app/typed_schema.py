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


IDENTITY_LABELS = {
    "name": "Full name", "given_name": "Given name", "middle_name": "Middle name",
    "family_name": "Family name", "organization": "Organization", "company": "Company",
    "job_title": "Job title", "email": "Email", "phone": "Phone", "address": "Address",
    "address_line1": "Address line 1", "address_line2": "Address line 2", "city": "City",
    "state": "State / province", "postal_code": "Postal code", "country": "Country",
    "website": "Website",
}


# Editor layout for the secret-bearing kinds: ``(key, label, control)`` where
# control is ``text``, ``multiline``, ``choice`` or ``bool``.  Whether a field
# is masked by default is NOT decided here: it comes from
# ``PROTECTED_FIELDS_BY_KIND`` so the editor cannot drift from the schema.
SECRET_KIND_FIELDS: dict[str, tuple[tuple[str, str, str], ...]] = {
    "card": (
        ("cardholder", "Cardholder", "text"),
        ("number", "Card number (Luhn-checked; brand is detected)", "text"),
        ("expiry", "Expiry MM/YY", "text"),
        ("cvv", "CVV", "text"),
        ("pin", "PIN (desktop only; never filled into a browser)", "text"),
    ),
    "bank_account": (
        ("bank", "Bank", "text"),
        ("account_holder", "Account holder", "text"),
        ("account_number", "IBAN / account number (IBAN checksum is verified)", "text"),
        ("routing", "Routing number / BIC", "text"),
        ("pin", "PIN", "text"),
    ),
    "ssh_key": (
        ("private_key", "Private key", "multiline"),
        ("public_key", "Public key (OpenSSH line; fingerprint is computed)", "multiline"),
        ("passphrase", "Passphrase", "text"),
        ("fingerprint", "Fingerprint", "text"),
    ),
    "api_key": (
        ("service", "Service", "text"),
        ("key", "Key", "text"),
        ("secret", "Secret", "text"),
        ("expires", "Expires YYYY-MM-DD", "text"),
    ),
    "wifi": (
        ("ssid", "Network name (SSID)", "text"),
        ("password", "Password", "text"),
        ("security", "Security type", "choice"),
        ("hidden", "Hidden network", "bool"),
    ),
    "passkey": (
        ("rp_name", "Site name", "text"),
        ("relying_party_id", "Relying party id (hostname)", "text"),
        ("user_name", "Account", "text"),
        ("user_handle", "User handle (base64url)", "text"),
        ("credential_id", "Credential id (base64url)", "text"),
        ("private_key", "Private key", "multiline"),
        ("algorithm", "Algorithm", "choice"),
        ("created", "Created YYYY-MM-DD", "text"),
    ),
}


SECRET_KIND_CHOICES: dict[str, tuple[str, ...]] = {
    "security": WIFI_SECURITY_TYPES,
    "algorithm": ("", *PASSKEY_ALGORITHMS),
}


SECRET_KIND_NOTES: dict[str, str] = {
    "card": "Card details are stored encrypted. Browser fill releases only approved fields and never the PIN.",
    "bank_account": "An IBAN is normalized and checksum-verified; other account numbers are stored as entered.",
    "ssh_key": "The key format is detected from the private key header. Nothing here signs or connects.",
    "api_key": "Key and secret are protected fields; copy them deliberately from the item.",
    "wifi": "The password is protected. Security type and hidden flag are plain metadata.",
    "passkey": "Created by websites through the browser extension. The private key never leaves LocalGateKeys.",
}


# Payload fields a secret kind keeps but its edit form does not show. Saving
# the form carries them over from the stored item instead of dropping them.
SECRET_FORM_HIDDEN_FIELDS: dict[str, tuple[str, ...]] = {
    "passkey": ("user_display_name", "discoverable"),
}
