"""Schema, service, template and icon coverage for the card/bank/SSH/API/Wi-Fi/passkey kinds."""
from __future__ import annotations

import uuid
from pathlib import Path

import pytest

from localvault import item_schema
from localvault.item_schema import (
    ITEM_KINDS,
    ITEM_SCHEMA_VERSION,
    PROTECTED_FIELDS_BY_KIND,
    SECRET_ITEM_KINDS,
    TEMPLATE_KINDS,
    ItemSchemaError,
    card_brand,
    luhn_valid,
    migrate_web_scope,
    openssh_fingerprint,
    sniff_private_key_format,
    validate_iban,
    validate_payload,
    validate_web_urls,
)
from localvault.templates import BUILTIN_TEMPLATES
from localvault.vault import VaultError, create_vault

KDF = {"time_cost": 1, "memory_cost_kib": 8192, "parallelism": 1, "hash_len": 32}
MASTER = "new kinds test master password"
NEW_KINDS = {"card", "bank_account", "ssh_key", "api_key", "wifi", "passkey"}

# A well-known test key: ``ssh-keygen -t ed25519`` style public key whose
# SHA256 fingerprint is stable and independently reproducible.
ED25519_PUBLIC = (
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl test@example"
)
ED25519_FINGERPRINT = "SHA256:+DiY3wvvV6TuJJhbpZisF/zLDA0zPMSvHdkr4UvCOqU"


@pytest.fixture
def session(tmp_path: Path):
    return create_vault(tmp_path / "vault.json", MASTER, kdf_overrides=KDF)


# ---------------------------------------------------------------------------
# Catalog constants
# ---------------------------------------------------------------------------

def test_new_kinds_are_registered_everywhere() -> None:
    assert NEW_KINDS <= ITEM_KINDS
    assert NEW_KINDS <= TEMPLATE_KINDS
    assert NEW_KINDS == SECRET_ITEM_KINDS
    assert ITEM_SCHEMA_VERSION == 3
    for kind in NEW_KINDS:
        assert PROTECTED_FIELDS_BY_KIND[kind], kind
    assert PROTECTED_FIELDS_BY_KIND["card"] == ("number", "cvv", "pin")
    assert PROTECTED_FIELDS_BY_KIND["bank_account"] == ("account_number", "pin")
    assert PROTECTED_FIELDS_BY_KIND["ssh_key"] == ("private_key", "passphrase")
    assert PROTECTED_FIELDS_BY_KIND["api_key"] == ("key", "secret")
    assert PROTECTED_FIELDS_BY_KIND["wifi"] == ("password",)
    assert PROTECTED_FIELDS_BY_KIND["passkey"] == ("private_key",)
    # Existing kinds keep their protected sets.
    assert PROTECTED_FIELDS_BY_KIND["license"] == ("license_value",)
    assert PROTECTED_FIELDS_BY_KIND["note"] == ("body", "fields")


def test_builtin_templates_exist_for_new_kinds_with_secret_flags() -> None:
    by_kind = {row["kind"]: row for row in BUILTIN_TEMPLATES}
    for kind in NEW_KINDS:
        assert kind in by_kind, kind
        fields = {field["name"]: field for field in by_kind[kind]["fields"]}
        for protected in PROTECTED_FIELDS_BY_KIND[kind]:
            if protected in fields:
                assert fields[protected]["secret"] is True, (kind, protected)
    assert "WebAuthn" in by_kind["passkey"]["description"]


# ---------------------------------------------------------------------------
# Card
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(("number", "brand"), [
    ("4111 1111 1111 1111", "visa"),
    ("5555555555554444", "mastercard"),
    ("2221000000000009", "mastercard"),
    ("378282246310005", "amex"),
    ("6011111111111117", "discover"),
    ("3530111333300000", "jcb"),
    ("30569309025904", "diners"),
    ("6200000000000005", "unionpay"),
    ("6759649826438453", "maestro"),
])
def test_luhn_and_brand_detection(number: str, brand: str) -> None:
    assert luhn_valid(number)
    assert card_brand(number) == brand
    assert not luhn_valid(number[:-1] + ("0" if number[-1] != "0" else "1"))
    assert card_brand("9999999999999999") == "unknown"


def test_card_payload_normalizes_number_and_derives_brand() -> None:
    identity_ref = str(uuid.uuid4())
    payload = validate_payload("card", {
        "cardholder": "Ada Example", "number": "4111-1111 1111 1111", "expiry": "7/29",
        "cvv": "123", "pin": "4321", "billing_address_id": identity_ref,
    })
    assert payload == {
        "cardholder": "Ada Example", "number": "4111111111111111", "brand": "visa", "last4": "1111",
        "expiry": "07/29", "cvv": "123", "pin": "4321", "billing_address_id": identity_ref,
        "notes": "", "template_id": None,
    }
    # A stale stored brand is always recomputed from the number.
    assert validate_payload("card", {"number": "378282246310005", "brand": "visa"})["brand"] == "amex"
    assert validate_payload("card", {})["brand"] == ""
    assert validate_payload("card", {})["last4"] == ""
    # A stale stored last4 is recomputed from the number as well.
    assert validate_payload("card", {"number": "378282246310005", "last4": "0000"})["last4"] == "0005"


@pytest.mark.parametrize("bad", [
    {"number": "4111111111111112"},            # Luhn failure
    {"number": "4111 1111 1111 111a"},         # not digits
    {"number": "411"},                         # too short
    {"expiry": "13/29"},
    {"expiry": "2029-07"},
    {"cvv": "12"},
    {"cvv": "12345"},
    {"pin": "12a4"},
    {"pin": "123456789"},
    {"billing_address_id": "not-a-uuid"},
    {"ssn": "123-45-6789"},
])
def test_card_payload_rejects_malformed_values(bad: dict) -> None:
    with pytest.raises(ItemSchemaError):
        validate_payload("card", bad)


# ---------------------------------------------------------------------------
# Bank account
# ---------------------------------------------------------------------------

def test_iban_checksum_and_bank_account_payload() -> None:
    assert validate_iban("GB82 WEST 1234 5698 7654 32") == "GB82WEST12345698765432"
    assert validate_iban("de89370400440532013000") == "DE89370400440532013000"
    with pytest.raises(ItemSchemaError):
        validate_iban("GB82WEST12345698765433")
    with pytest.raises(ItemSchemaError):
        validate_iban("GB82")
    payload = validate_payload("bank_account", {
        "bank": "Example Bank", "account_holder": "Ada", "account_number": "gb82 west 1234 5698 7654 32",
        "routing": "WESTGB2L", "pin": "0000",
    })
    assert payload["account_number"] == "GB82WEST12345698765432"
    assert payload["number_format"] == "iban"
    assert payload["routing"] == "WESTGB2L"
    domestic = validate_payload("bank_account", {"account_number": "12345678", "routing": "021000021"})
    assert domestic["number_format"] == "other"
    assert domestic["account_number"] == "12345678"
    with pytest.raises(ItemSchemaError):
        validate_payload("bank_account", {"account_number": "GB82WEST12345698765433"})
    with pytest.raises(ItemSchemaError):
        validate_payload("bank_account", {"pin": "abc"})
    with pytest.raises(ItemSchemaError):
        validate_payload("bank_account", {"routing": "bad routing!"})


# ---------------------------------------------------------------------------
# SSH key
# ---------------------------------------------------------------------------

OPENSSH_PRIVATE = (
    "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW\n"
    "-----END OPENSSH PRIVATE KEY-----\n"
)
PEM_RSA = "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA\n-----END RSA PRIVATE KEY-----\n"
PEM_PKCS8 = "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBg\n-----END PRIVATE KEY-----"
PEM_ENCRYPTED = "-----BEGIN ENCRYPTED PRIVATE KEY-----\nMIIFHDBOBgkq\n-----END ENCRYPTED PRIVATE KEY-----"
PEM_EC = "-----BEGIN EC PRIVATE KEY-----\nMHcCAQEEI\n-----END EC PRIVATE KEY-----"
PUTTY = "PuTTY-User-Key-File-3: ssh-ed25519\nEncryption: none\n"


@pytest.mark.parametrize(("text", "expected"), [
    (OPENSSH_PRIVATE, "openssh"),
    (PEM_RSA, "pem-rsa"),
    (PEM_PKCS8, "pem-pkcs8"),
    (PEM_ENCRYPTED, "pem-pkcs8-encrypted"),
    (PEM_EC, "pem-ec"),
    (PUTTY, "putty"),
    ("", ""),
    ("not a key at all", "unknown"),
])
def test_private_key_format_sniffing(text: str, expected: str) -> None:
    assert sniff_private_key_format(text) == expected


def test_openssh_fingerprint_is_sha256_without_padding() -> None:
    assert openssh_fingerprint(ED25519_PUBLIC) == ED25519_FINGERPRINT
    assert openssh_fingerprint("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl") == ED25519_FINGERPRINT
    assert openssh_fingerprint("") == ""
    assert openssh_fingerprint("-----BEGIN PUBLIC KEY-----\nMFkw\n-----END PUBLIC KEY-----") == ""
    with pytest.raises(ItemSchemaError):
        openssh_fingerprint("ssh-ed25519 not*base64")


def test_ssh_key_payload_sniffs_format_and_computes_fingerprint() -> None:
    payload = validate_payload("ssh_key", {
        "private_key": OPENSSH_PRIVATE, "public_key": ED25519_PUBLIC, "passphrase": "pw",
        "fingerprint": "SHA256:stale",
    })
    assert payload["key_format"] == "openssh"
    assert payload["fingerprint"] == ED25519_FINGERPRINT
    assert payload["private_key"] == OPENSSH_PRIVATE
    assert payload["passphrase"] == "pw"
    no_public = validate_payload("ssh_key", {"private_key": PEM_RSA, "fingerprint": "SHA256:kept"})
    assert no_public["key_format"] == "pem-rsa"
    # Without an OpenSSH public key a user-entered fingerprint is kept verbatim.
    assert no_public["fingerprint"] == "SHA256:kept"
    with pytest.raises(ItemSchemaError):
        validate_payload("ssh_key", {"private_key": "x" * 20_001})
    with pytest.raises(ItemSchemaError):
        validate_payload("ssh_key", {"public_key": "ssh-rsa %%%"})


# ---------------------------------------------------------------------------
# API key, Wi-Fi, passkey
# ---------------------------------------------------------------------------

def test_api_key_payload() -> None:
    payload = validate_payload("api_key", {"service": "Example API", "key": "AKIA", "secret": "s", "expires": "2030-01-31"})
    assert payload == {"service": "Example API", "key": "AKIA", "secret": "s", "expires": "2030-01-31",
                       "notes": "", "template_id": None}
    with pytest.raises(ItemSchemaError):
        validate_payload("api_key", {"expires": "soon"})
    with pytest.raises(ItemSchemaError):
        validate_payload("api_key", {"token": "unsupported"})


def test_wifi_payload() -> None:
    payload = validate_payload("wifi", {"ssid": "Home", "password": "hunter22", "security": "WPA2", "hidden": True})
    assert payload == {"ssid": "Home", "password": "hunter22", "security": "wpa2", "hidden": True,
                       "notes": "", "template_id": None}
    assert validate_payload("wifi", {})["security"] == "wpa2"
    with pytest.raises(ItemSchemaError):
        validate_payload("wifi", {"security": "rot13"})
    with pytest.raises(ItemSchemaError):
        validate_payload("wifi", {"hidden": "yes"})
    with pytest.raises(ItemSchemaError):
        validate_payload("wifi", {"ssid": "x" * 33})


def test_passkey_scaffold_payload() -> None:
    assert "WebAuthn" in item_schema.validate_passkey_fields.__doc__
    payload = validate_payload("passkey", {
        "relying_party_id": "Example.COM", "user_handle": "dXNlcg", "credential_id": "Y3JlZA",
        "private_key": PEM_PKCS8, "algorithm": "ES256", "created": "2026-01-02",
    })
    assert payload["relying_party_id"] == "example.com"
    assert payload["algorithm"] == "ES256"
    assert payload["created"] == "2026-01-02"
    with pytest.raises(ItemSchemaError):
        validate_payload("passkey", {"algorithm": "none"})
    with pytest.raises(ItemSchemaError):
        validate_payload("passkey", {"relying_party_id": "https://example.com"})
    with pytest.raises(ItemSchemaError):
        validate_payload("passkey", {"credential_id": "not base64url!"})


# ---------------------------------------------------------------------------
# Web login URL rows
# ---------------------------------------------------------------------------

def test_validate_web_urls_normalizes_and_rejects() -> None:
    rows = validate_web_urls([
        {"url": "https://EXAMPLE.com:443/", "match": "exact_origin"},
        {"url": "https://login.example.com/App", "match": "starts_with"},
        {"url": "https://example.co.uk", "match": "base_domain"},
        {"url": "https://example.com:8443/x?y=1", "match": "host"},
    ])
    assert rows == [
        {"url": "https://example.com", "match": "exact_origin"},
        {"url": "https://login.example.com/App", "match": "starts_with"},
        {"url": "https://example.co.uk/", "match": "base_domain"},
        {"url": "https://example.com:8443/x?y=1", "match": "host"},
    ]
    with pytest.raises(ItemSchemaError):
        validate_web_urls([{"url": "https://example.com/login", "match": "exact_origin"}])
    with pytest.raises(ItemSchemaError):
        validate_web_urls([{"url": "javascript:alert(1)", "match": "host"}])
    with pytest.raises(ItemSchemaError):
        validate_web_urls([{"url": "https://example.com", "match": "regex"}])
    with pytest.raises(ItemSchemaError):
        validate_web_urls([{"url": "https://example.com", "match": "host", "extra": 1}])
    with pytest.raises(ItemSchemaError):
        validate_web_urls([{"url": "https://example.com"}] * 21)
    with pytest.raises(ItemSchemaError):
        validate_web_urls([{"url": "http://example.com", "match": "host"}])
    assert validate_web_urls([{"url": "http://localhost:8000", "match": "host"}]) == [
        {"url": "http://localhost:8000/", "match": "host"}]
    assert validate_web_urls(None) == []
    # Duplicates collapse.
    assert validate_web_urls([{"url": "https://a.test"}, {"url": "https://A.test/"}]) == [
        {"url": "https://a.test", "match": "exact_origin"}]


def test_migrate_web_scope_keeps_legacy_origin_as_first_row() -> None:
    scope = migrate_web_scope({"origin": "https://example.com"})
    assert scope == {"origin": "https://example.com",
                     "urls": [{"url": "https://example.com", "match": "exact_origin"}]}
    existing = migrate_web_scope({"origin": "https://example.com",
                                  "urls": [{"url": "https://other.test", "match": "host"}]})
    assert existing["urls"][0] == {"url": "https://example.com", "match": "exact_origin"}
    assert existing["urls"][1] == {"url": "https://other.test/", "match": "host"}
    # The origin is always derived from urls[0] when they disagree.
    repaired = migrate_web_scope({"origin": "https://old.test",
                                  "urls": [{"url": "https://new.test", "match": "exact_origin"}]})
    assert repaired["origin"] == "https://new.test"
    assert repaired["urls"][0]["url"] == "https://new.test"
    with pytest.raises(ItemSchemaError):
        migrate_web_scope({"urls": []})
    derived = migrate_web_scope({"urls": [{"url": "https://a.test:8443/path", "match": "host"}]})
    assert derived["origin"] == "https://a.test:8443"
    assert derived["urls"][0] == {"url": "https://a.test:8443", "match": "exact_origin"}


# ---------------------------------------------------------------------------
# Service behaviour
# ---------------------------------------------------------------------------

def test_service_creates_redacts_and_reveals_new_kinds(session) -> None:
    items = session.items
    card_id = items.create_card("Visa", cardholder="Ada", number="4111 1111 1111 1111", expiry="07/29",
                                cvv="123", pin="4321")
    bank_id = items.create_bank_account("Current account", bank="Example Bank",
                                        account_number="GB82 WEST 1234 5698 7654 32", pin="0000")
    ssh_id = items.create_ssh_key("Deploy key", private_key=OPENSSH_PRIVATE, public_key=ED25519_PUBLIC,
                                  passphrase="pw")
    api_id = items.create_api_key("Cloud", service="Cloud", key="AKIA", secret="shh")
    wifi_id = items.create_wifi("Home", ssid="Home", password="hunter22", security="wpa3", hidden=True)
    passkey_id = items.create_passkey("Example passkey", relying_party_id="example.com", user_handle="dXNlcg",
                                      credential_id="Y3JlZA", private_key=PEM_PKCS8, algorithm="ES256")
    secrets = {"4111111111111111", "123", "4321", "GB82WEST12345698765432", "0000", OPENSSH_PRIVATE,
               "AKIA", "shh", "hunter22", PEM_PKCS8}
    for item_id in (card_id, bank_id, ssh_id, api_id, wifi_id, passkey_id):
        safe = items.get_item(item_id)
        assert safe is not None
        # Compare against the payload only: ids and timestamps are random and
        # may legitimately contain a short digit sequence such as "123".
        for secret in secrets:
            assert secret not in repr(safe["payload"]), (safe["kind"], secret)
    card = items.get_item(card_id)
    assert card["payload"]["brand"] == "visa"
    assert card["payload"]["number_present"] is True
    assert "number" not in card["payload"]
    assert items.get_item(ssh_id)["payload"]["fingerprint"] == ED25519_FINGERPRINT
    assert items.get_item(ssh_id)["payload"]["key_format"] == "openssh"
    assert items.get_item(bank_id)["payload"]["number_format"] == "iban"
    assert all(not any(secret in repr(row["payload"]) for secret in secrets) for row in items.list_items())
    assert items.search_metadata("4111111111111111") == []
    assert set(items.metadata_summaries(kinds=NEW_KINDS)) and all(
        summary.kind in NEW_KINDS for summary in items.metadata_summaries(kinds=NEW_KINDS))

    with pytest.raises(ItemSchemaError, match="explicit caller intent"):
        items.reveal_secret(card_id, "number")
    assert items.reveal_secret(card_id, "number", intent="reveal") == "4111111111111111"
    assert items.copy_secret(card_id, "cvv", intent="copy") == "123"
    assert items.reveal_secret(bank_id, "account_number", intent="reveal") == "GB82WEST12345698765432"
    assert items.reveal_secret(ssh_id, "private_key", intent="reveal") == OPENSSH_PRIVATE
    assert items.reveal_secret(api_id, "secret", intent="reveal") == "shh"
    assert items.reveal_secret(wifi_id, "password", intent="reveal") == "hunter22"
    assert items.reveal_secret(passkey_id, "private_key", intent="reveal") == PEM_PKCS8
    with pytest.raises(ItemSchemaError, match="Unsupported protected field"):
        items.reveal_secret(card_id, "cardholder", intent="reveal")
    with pytest.raises(ItemSchemaError):
        items.reveal_secret(wifi_id, "number", intent="reveal")

    assert items.update_typed_item(card_id, payload={"expiry": "08/30"}, expected_revision=1)
    assert items.get_item(card_id)["payload"]["expiry"] == "08/30"
    assert items.update_item(wifi_id, typed_payload={"hidden": False}, title="Home 5G")
    assert items.get_item(wifi_id)["payload"]["hidden"] is False
    with pytest.raises(ItemSchemaError):
        items.update_item(wifi_id, body="not for wifi")
    with pytest.raises(ItemSchemaError):
        items.create_card("Bad", number="4111111111111112")
    assert items.create_typed("api_key", "Generic", {"service": "x", "key": "k"})

    edit = items.get_item_for_edit(card_id)
    assert edit["payload"]["number"] == "4111111111111111"
    assert items.delete_item(card_id)
    assert [row["kind"] for row in items.trash_summaries()] == ["card"]
    assert items.restore_item(card_id)
    session.lock()


def test_card_billing_address_must_reference_live_identity(session) -> None:
    identity_id = session.items.create_identity("Home", {"name": "Ada"})
    card_id = session.items.create_card("Visa", number="4111111111111111", billing_address_id=identity_id)
    assert session.items.get_item(card_id)["payload"]["billing_address_id"] == identity_id
    with pytest.raises(ItemSchemaError, match="billing address"):
        session.items.create_card("Visa 2", number="4111111111111111",
                                  billing_address_id=str(uuid.uuid4()))
    note_id = session.items.create_note("Not an identity")
    with pytest.raises(ItemSchemaError, match="billing address"):
        session.items.create_card("Visa 3", number="4111111111111111", billing_address_id=note_id)


def test_card_fill_view_never_contains_pin(session) -> None:
    card_id = session.items.create_card("Visa", cardholder="Ada", number="4111111111111111", expiry="07/29",
                                        cvv="123", pin="4321")
    view = session.items.card_fill_view(card_id)
    assert view["id"] == card_id and view["revision"] == 1
    assert view["fields"] == {"cc-name": "Ada", "cc-number": "4111111111111111", "cc-exp": "07/2029",
                              "cc-exp-month": "07", "cc-exp-year": "2029", "cc-csc": "123", "cc-type": "visa"}
    assert "4321" not in repr(view)
    with pytest.raises(VaultError, match="revision"):
        session.items.card_fill_view(card_id, expected_revision=5)
    with pytest.raises(VaultError):
        session.items.card_fill_view(str(uuid.uuid4()))


def test_web_login_urls_round_trip_through_service(session) -> None:
    entry_id = session.upsert_web(origin="https://example.com", username="ada", password="pw")
    assert session.items.web_urls(entry_id) == [{"url": "https://example.com", "match": "exact_origin"}]
    assert session.items.set_web_urls(entry_id, [
        {"url": "https://example.com", "match": "exact_origin"},
        {"url": "https://login.example.com/sso", "match": "starts_with"},
        {"url": "https://example.co.uk", "match": "base_domain"},
    ])
    stored = session.get_entry(entry_id)
    assert stored["scope"]["origin"] == "https://example.com"
    assert len(stored["scope"]["urls"]) == 3
    assert session.items.web_urls(entry_id)[1]["match"] == "starts_with"
    # Origin follows urls[0] so legacy exact matching keeps working.
    assert session.items.set_web_urls(entry_id, [{"url": "https://new.example.com", "match": "exact_origin"}])
    assert session.get_entry(entry_id)["scope"]["origin"] == "https://new.example.com"
    assert session.find_web("https://new.example.com")
    with pytest.raises(ItemSchemaError):
        session.items.set_web_urls(entry_id, [])
    with pytest.raises(VaultError):
        session.items.set_web_urls(str(uuid.uuid4()), [{"url": "https://x.test"}])
    assert session.items.set_web_urls(entry_id, [
        {"url": "https://new.example.com", "match": "exact_origin"},
        {"url": "https://shop.example.co.uk", "match": "base_domain"},
    ])
    ranked = session.items.find_web_candidates("https://pay.example.co.uk/checkout")
    assert [row["id"] for row in ranked] == [entry_id]
    assert "pw" not in repr(ranked)
    assert session.items.find_web_candidates("https://evil-example.co.uk/") == []
    # Reopening the vault keeps the rows.
    session.lock()


# ---------------------------------------------------------------------------
# Protected-field masking metadata
# ---------------------------------------------------------------------------

def test_masked_hints_are_value_free_and_card_shows_only_last4(session) -> None:
    from localvault.item_schema import (
        MASK_GLYPH,
        MULTILINE_PROTECTED_FIELDS,
        PROTECTED_FIELD_LABELS,
        card_last4,
        masked_hint,
    )
    for kind in NEW_KINDS | {"license"}:
        assert set(PROTECTED_FIELD_LABELS[kind]) == set(PROTECTED_FIELDS_BY_KIND[kind]), kind
    assert ("ssh_key", "private_key") in MULTILINE_PROTECTED_FIELDS
    assert card_last4("4111 1111 1111 1111") == "1111" and card_last4("") == "" and card_last4("abc") == ""
    card_id = session.items.create_card("Visa", number="4111111111111111", cvv="123", pin="4321")
    redacted = session.items.get_item(card_id)["payload"]
    assert redacted["last4"] == "1111" and "number" not in redacted
    assert masked_hint("card", "number", redacted) == f"{MASK_GLYPH * 4} 1111"
    assert masked_hint("card", "cvv", redacted) == MASK_GLYPH * 8
    assert masked_hint("card", "pin", {}) == ""
    assert masked_hint("wifi", "password", {"password": "hunter22"}) == MASK_GLYPH * 8
    with pytest.raises(ItemSchemaError):
        masked_hint("card", "cardholder", redacted)
    assert "4111111111111111" not in repr(session.items.metadata_summaries())
