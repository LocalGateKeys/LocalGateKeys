from __future__ import annotations

import base64
import datetime as dt
import hashlib
import json

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

from localvault import licensing
from localvault.updates import canonical_json

ISSUED = dt.date(2026, 10, 15)
UNTIL = ISSUED + dt.timedelta(days=365)


@pytest.fixture
def signer(tmp_path, monkeypatch):
    monkeypatch.setenv("LOCALGATEKEYS_DATA_DIR", str(tmp_path))
    private = ed25519.Ed25519PrivateKey.generate()
    raw = private.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    key_id = hashlib.sha256(raw).digest()[:8].hex()
    monkeypatch.setattr(licensing, "LICENSE_KEYS", {key_id: base64.b64encode(raw).decode()})
    return private, key_id


def make_bundle(signer, **overrides):
    private, key_id = signer
    lic = {
        "format": 1,
        "license_id": "lic-0001",
        "edition": "pro",
        "name": "Ada Lovelace",
        "email": "ada@example.com",
        "issued_at": ISSUED.isoformat(),
        "updates_until": UNTIL.isoformat(),
    }
    lic.update(overrides)
    sig = private.sign(canonical_json(lic))
    return {
        "license": lic,
        "signature": {
            "alg": "Ed25519",
            "key_id": key_id,
            "signature": base64.b64encode(sig).decode(),
        },
    }


def test_round_trip_paste_and_file(signer):
    bundle = make_bundle(signer)
    lic = licensing.install_license(licensing.encode_paste(bundle))
    assert lic.license_id == "lic-0001"
    assert licensing.status(build_date=ISSUED).state == "pro"
    licensing.remove_license()
    licensing.install_license(json.dumps(bundle))
    assert licensing.status(build_date=ISSUED).state == "pro"


def test_paste_tolerates_wrapping(signer):
    text = licensing.encode_paste(make_bundle(signer))
    wrapped = "\r\n".join(text[i : i + 40] for i in range(0, len(text), 40))
    licensing.install_license("   " + wrapped + ".\r\n")
    assert licensing.status(build_date=ISSUED).state == "pro"


def test_rejects_tamper(signer):
    bundle = make_bundle(signer)
    bundle["license"]["name"] = "Mallory"
    with pytest.raises(licensing.LicenseError) as exc:
        licensing.verify_bundle(bundle)
    assert exc.value.reason == "bad-signature"


def test_rejects_unknown_fields_and_key(signer):
    bundle = make_bundle(signer, extra="x")
    with pytest.raises(licensing.LicenseError) as exc:
        licensing.verify_bundle(bundle)
    assert exc.value.reason == "license-shape"
    bundle = make_bundle(signer)
    bundle["signature"]["key_id"] = "0" * 16
    with pytest.raises(licensing.LicenseError) as exc:
        licensing.verify_bundle(bundle)
    assert exc.value.reason == "unknown-key"


@pytest.mark.parametrize("key_id", ["XYZ", "0" * 15, "0" * 17, "ABCDEF0123456789", 7, None])
def test_malformed_key_id_is_damaged_not_unknown(signer, key_id):
    """Only a well-formed key id that this build lacks means a newer build; anything else is damage."""
    bundle = make_bundle(signer)
    bundle["signature"]["key_id"] = key_id
    with pytest.raises(licensing.LicenseError) as exc:
        licensing.verify_bundle(bundle)
    assert exc.value.reason == "license-shape"


def test_build_on_last_day_is_covered(signer):
    licensing.install_license(licensing.encode_paste(make_bundle(signer)))
    assert licensing.status(build_date=UNTIL).state == "pro"
    late = licensing.status(build_date=UNTIL + dt.timedelta(days=1))
    assert late.state == "expired_for_this_build"
    assert late.pro_enabled is False
    assert UNTIL.isoformat() in late.message


def test_revoked(signer):
    licensing.install_license(licensing.encode_paste(make_bundle(signer)))
    st = licensing.status(build_date=ISSUED, revoked=["lic-0001"])
    assert st.state == "revoked"
    assert st.pro_enabled is False


def test_no_file_is_free(signer):
    st = licensing.status(build_date=ISSUED)
    assert st.state == "free"
    assert st.pro_enabled is False
    assert licensing.is_pro(licensing.Feature.UNLIMITED_ITEMS) is False


def test_corrupt_file_is_invalid_not_raise(signer):
    licensing.license_path().write_bytes(b"\xff\x00garbage")
    assert licensing.status(build_date=ISSUED).state == "invalid"


def test_unconfigured_allows_pro(tmp_path, monkeypatch):
    monkeypatch.setenv("LOCALGATEKEYS_DATA_DIR", str(tmp_path))
    monkeypatch.setattr(licensing, "LICENSE_KEYS", {})
    st = licensing.status()
    assert st.state == "unconfigured"
    assert st.pro_enabled is True
    assert licensing.is_pro(licensing.Feature.UNLIMITED_ITEMS) is True


def test_install_rejects_without_writing(signer):
    bundle = make_bundle(signer)
    bundle["license"]["name"] = "Mallory"
    with pytest.raises(licensing.LicenseError):
        licensing.install_license(json.dumps(bundle))
    with pytest.raises(licensing.LicenseError):
        licensing.install_license("not a licence")
    assert not licensing.license_path().exists()


def test_covers(signer):
    lic = licensing.verify_bundle(make_bundle(signer))
    assert licensing.covers(UNTIL, lic) is True
    assert licensing.covers(UNTIL + dt.timedelta(days=1), lic) is False


def test_cached_revocation_makes_status_revoked(signer, monkeypatch):
    from localvault import updates

    revoked_id = "lgk_" + "0" * 26
    licensing.install_license(
        licensing.encode_paste(make_bundle(signer, license_id=revoked_id))
    )
    assert licensing.status(build_date=ISSUED).state == "pro"

    publisher = ed25519.Ed25519PrivateKey.generate()
    raw = publisher.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    pub_id = hashlib.sha256(raw).digest()[:8].hex()
    monkeypatch.setattr(updates, "RELEASE_FEED_URL", "https://updates.example.test/stable.json")
    monkeypatch.setattr(updates, "PUBLISHER_KEYS", {pub_id: base64.b64encode(raw).decode()})
    manifest = {"format": 1, "published": "2026-10-10T00:00:00Z", "revoked": [revoked_id]}
    bundle = {
        "manifest": manifest,
        "signature": {
            "alg": "Ed25519",
            "key_id": pub_id,
            "signature": base64.b64encode(publisher.sign(canonical_json(manifest))).decode(),
        },
    }
    updates.revocation_cache_path().write_text(json.dumps(bundle), encoding="utf-8")
    st = licensing.status(build_date=ISSUED)
    assert st.state == "revoked"
    assert st.pro_enabled is False


def _pro_status():
    lic = licensing.License(
        license_id="lic-0001",
        edition="pro",
        name="Ada Lovelace",
        email="ada@example.com",
        issued_at=ISSUED,
        updates_until=UNTIL,
    )
    return licensing.LicenseStatus("pro", lic, "Pro")


def test_coverage_note_for_uncovered_release():
    from localvault.version import APP_VERSION

    note = licensing.update_coverage_note("2027-10-16T00:00:00Z", _pro_status())
    assert note == (
        "This update isn't covered by your licence: the free plan would apply (4 items, no device sync). "
        f"Get a current licence, or stay on {APP_VERSION}."
    )
    assert "desktop" not in note


def test_coverage_note_never_for_lifetime_licence():
    lic = licensing.License("lic-life", "pro", "Ada", "ada@example.com", ISSUED, licensing.LIFETIME_UNTIL)
    st = licensing.LicenseStatus("pro", lic, "Pro")
    assert licensing.update_coverage_note("9999-12-31T23:59:59Z", st) is None
    assert licensing.update_coverage_note("2100-01-01T00:00:00Z", st) is None


def test_coverage_note_none_when_covered():
    assert licensing.update_coverage_note(f"{UNTIL.isoformat()}T23:59:59Z", _pro_status()) is None
    assert licensing.update_coverage_note("2026-11-01T00:00:00Z", _pro_status()) is None


@pytest.mark.parametrize("state", ["free", "unconfigured", "expired_for_this_build", "revoked", "invalid"])
def test_coverage_note_none_for_non_pro(state):
    st = licensing.LicenseStatus(state, None, "x")
    assert licensing.update_coverage_note("2030-01-01T00:00:00Z", st) is None


def test_coverage_note_none_for_bad_input():
    assert licensing.update_coverage_note("", _pro_status()) is None
    assert licensing.update_coverage_note("not a date", _pro_status()) is None


def test_coverage_note_defaults_to_status(signer):
    licensing.install_license(licensing.encode_paste(make_bundle(signer)))
    assert licensing.update_coverage_note("2030-01-01T00:00:00Z") is not None


def test_update_result_published_defaults_empty():
    from localvault.updates import UpdateResult

    assert UpdateResult("0.4.0", "0.5.0").published == ""


# --- reason-specific messages -------------------------------------------------

_DAMAGED = "The licence key looks incomplete or damaged. Copy the whole key from your purchase email or page and try again."


@pytest.mark.parametrize(
    ("reason", "expected"),
    [
        ("bad-encoding", _DAMAGED),
        ("not-json", _DAMAGED),
        ("license-shape", _DAMAGED),
        ("duplicate-field", _DAMAGED),
        ("unknown-key", "This licence was issued for a newer LocalGateKeys version. Update the app, then enter it again."),
        ("bad-signature", "This licence key is not valid."),
        ("bad-alg", "The licence could not be verified."),
        ("whatever", "The licence could not be verified."),
    ],
)
def test_reason_text_mapping(reason, expected):
    assert licensing.reason_text(reason) == expected
    assert str(licensing._fail(reason)) == expected


def test_errors_carry_reason_specific_message(signer):
    with pytest.raises(licensing.LicenseError) as exc:
        licensing.install_license("LGK1-!!!not base64!!!")
    assert exc.value.reason == "bad-encoding"
    assert str(exc.value) == _DAMAGED
    bundle = make_bundle(signer)
    bundle["license"]["name"] = "Mallory"
    with pytest.raises(licensing.LicenseError) as exc:
        licensing.verify_bundle(bundle)
    assert str(exc.value) == "This licence key is not valid."


def test_invalid_status_includes_reason_text(signer):
    bundle = make_bundle(signer)
    bundle["license"]["name"] = "Mallory"
    licensing.license_path().write_text(json.dumps(bundle), encoding="utf-8")
    st = licensing.status(build_date=ISSUED)
    assert st.state == "invalid"
    assert "This licence key is not valid." in st.message
    licensing.license_path().write_text("{not json", encoding="utf-8")
    assert _DAMAGED in licensing.status(build_date=ISSUED).message


# --- negative paths -----------------------------------------------------------


def _reason(bundle, keys=None):
    with pytest.raises(licensing.LicenseError) as exc:
        licensing.verify_bundle(bundle, keys)
    return exc.value.reason


def test_bad_alg(signer):
    bundle = make_bundle(signer)
    bundle["signature"]["alg"] = "RS256"
    assert _reason(bundle) == "bad-alg"


def test_duplicate_field_rejected(signer):
    text = json.dumps(make_bundle(signer))
    dup = text.replace('"edition": "pro"', '"edition": "pro", "edition": "pro"', 1)
    assert dup != text
    with pytest.raises(licensing.LicenseError) as exc:
        licensing.parse_license_text(dup)
    assert exc.value.reason == "duplicate-field"
    with pytest.raises(licensing.LicenseError) as exc:
        licensing.install_license(dup)
    assert exc.value.reason == "duplicate-field"


def test_key_entry_with_mismatched_key_id(signer):
    private, key_id = signer
    other = ed25519.Ed25519PrivateKey.generate().public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    keys = {key_id: base64.b64encode(other).decode()}
    assert _reason(make_bundle(signer), keys) == "unknown-key"


def test_key_entry_with_bad_length_or_base64(signer):
    _, key_id = signer
    assert _reason(make_bundle(signer), {key_id: base64.b64encode(b"short").decode()}) == "unknown-key"
    assert _reason(make_bundle(signer), {key_id: "!!!"}) == "unknown-key"


@pytest.mark.parametrize("sig_value", ["!!not base64!!", "", "abc"])
def test_malformed_signature_base64(signer, sig_value):
    bundle = make_bundle(signer)
    bundle["signature"]["signature"] = sig_value
    assert _reason(bundle) == "bad-signature"


def test_wrong_signature_length(signer):
    bundle = make_bundle(signer)
    raw = base64.b64decode(bundle["signature"]["signature"])
    bundle["signature"]["signature"] = base64.b64encode(raw[:63]).decode()
    assert _reason(bundle) == "bad-signature"
    bundle["signature"]["signature"] = base64.b64encode(raw + b"\0").decode()
    assert _reason(bundle) == "bad-signature"


@pytest.mark.parametrize("value", [123, None, ["x"], {"a": 1}])
def test_non_string_signature(signer, value):
    bundle = make_bundle(signer)
    bundle["signature"]["signature"] = value
    assert _reason(bundle) == "bad-signature"


@pytest.mark.parametrize(
    "overrides",
    [
        {"format": 2},
        {"format": True},
        {"format": "1"},
        {"edition": "free"},
        {"edition": "Pro"},
        {"license_id": ""},
        {"name": 5},
        {"email": ""},
    ],
)
def test_wrong_format_or_edition_signed(signer, overrides):
    assert _reason(make_bundle(signer, **overrides)) == "license-shape"


@pytest.mark.parametrize(
    "overrides",
    [
        {"issued_at": "2026-13-01"},
        {"updates_until": "2026-02-30"},
        {"issued_at": "26-1-1"},
        {"updates_until": 20270101},
        {"updates_until": "2027-01-01T00:00:00"},
    ],
)
def test_invalid_signed_dates(signer, overrides):
    assert _reason(make_bundle(signer, **overrides)) == "license-shape"


def test_explicit_keys_override_empty_license_keys(tmp_path, monkeypatch, signer):
    private, key_id = signer
    explicit = dict(licensing.LICENSE_KEYS)
    monkeypatch.setattr(licensing, "LICENSE_KEYS", {})
    assert licensing.status().state == "unconfigured"
    st = licensing.status(build_date=ISSUED, keys=explicit)
    assert st.state == "free"
    assert st.pro_enabled is False
    licensing.license_path().write_text(json.dumps(make_bundle(signer)), encoding="utf-8")
    assert licensing.status(build_date=ISSUED, keys=explicit).state == "pro"
    assert licensing.status(build_date=ISSUED, keys={"0" * 16: explicit[key_id]}).state == "invalid"


def test_is_pro_false_for_expired_revoked_invalid(signer, monkeypatch):
    feature = licensing.Feature.UNLIMITED_ITEMS
    licensing.install_license(licensing.encode_paste(make_bundle(signer)))
    monkeypatch.setattr(licensing, "BUILD_DATE", UNTIL.isoformat())
    monkeypatch.setattr(licensing, "_cached_revoked_ids", lambda: frozenset())
    assert licensing.is_pro(feature) is True
    monkeypatch.setattr(licensing, "BUILD_DATE", (UNTIL + dt.timedelta(days=1)).isoformat())
    assert licensing.is_pro(feature) is False  # expired
    monkeypatch.setattr(licensing, "BUILD_DATE", ISSUED.isoformat())
    monkeypatch.setattr(licensing, "_cached_revoked_ids", lambda: frozenset({"lic-0001"}))
    assert licensing.is_pro(feature) is False  # revoked
    monkeypatch.setattr(licensing, "_cached_revoked_ids", lambda: frozenset())
    licensing.license_path().write_text("garbage", encoding="utf-8")
    assert licensing.is_pro(feature) is False  # invalid


# --- item-limit model, lifetime licences, vault copy ---------------------------------

import uuid  # noqa: E402
from pathlib import Path  # noqa: E402

from localvault.vault import VaultError, create_vault  # noqa: E402

_KDF = {"time_cost": 1, "memory_cost_kib": 8192, "parallelism": 1, "hash_len": 32}


@pytest.fixture
def vault_session():
    directory = Path(".m5-test-data") / uuid.uuid4().hex
    directory.mkdir(parents=True, exist_ok=False)
    return create_vault(directory / "vault.json", "licence vault test password", kdf_overrides=_KDF)


@pytest.mark.parametrize(
    ("state", "expected"),
    [
        ("pro", None),
        ("unconfigured", None),
        ("free", licensing.FREE_ITEM_LIMIT),
        ("invalid", licensing.FREE_ITEM_LIMIT),
        ("revoked", licensing.FREE_ITEM_LIMIT),
        ("expired_for_this_build", licensing.FREE_ITEM_LIMIT),
    ],
)
def test_item_limit_per_state(state, expected):
    assert licensing.item_limit(licensing.LicenseStatus(state, None, "")) == expected


def test_free_item_limit_is_four():
    assert licensing.FREE_ITEM_LIMIT == 4
    assert licensing.Feature.UNLIMITED_ITEMS.value == "unlimited_items"


def test_item_limit_defaults_to_status_and_swallows_errors(signer, monkeypatch):
    assert licensing.item_limit() == licensing.FREE_ITEM_LIMIT  # keys set, no file
    monkeypatch.setattr(licensing, "status", lambda: (_ for _ in ()).throw(RuntimeError("x")))
    assert licensing.item_limit() == licensing.FREE_ITEM_LIMIT


def test_lifetime_licence_is_pro_in_any_build(signer):
    bundle = make_bundle(signer, updates_until="9999-12-31")
    licensing.install_license(licensing.encode_paste(bundle))
    st = licensing.status(build_date=dt.date(2100, 1, 1))
    assert st.state == "pro"
    assert st.license.updates_until == licensing.LIFETIME_UNTIL == dt.date(9999, 12, 31)
    assert licensing.covers(dt.date(9999, 12, 31), st.license)
    assert licensing.item_limit(st) is None


def test_vault_copy_round_trip_and_clear(signer, vault_session):
    bundle = make_bundle(signer)
    assert licensing.vault_copy(vault_session) is None
    licensing.store_in_vault(vault_session, bundle)
    assert licensing.vault_copy(vault_session) == bundle
    assert vault_session._require_typed_catalog()["license"] == bundle
    licensing.clear_vault_copy(vault_session)
    assert licensing.vault_copy(vault_session) is None
    licensing.clear_vault_copy(vault_session)  # idempotent


def test_vault_copy_survives_reload(signer, vault_session):
    from localvault.vault import unlock_vault

    bundle = make_bundle(signer)
    licensing.store_in_vault(vault_session, bundle)
    reopened = unlock_vault(vault_session.path, "licence vault test password")
    assert licensing.vault_copy(reopened) == bundle


def test_vault_drops_oversized_or_non_dict_license_on_save(vault_session):
    from localvault.vault import unlock_vault

    for bad in ("nope", {"x": "a" * 20_000}):
        payload = vault_session._require_typed_catalog()
        payload["license"] = bad
        vault_session.save()  # a bad copy never blocks the vault
        assert "license" not in vault_session._require_typed_catalog()
    reopened = unlock_vault(vault_session.path, "licence vault test password")
    assert licensing.vault_copy(reopened) is None


def test_malformed_vault_licence_copy_never_blocks_unlock(vault_session, monkeypatch, caplog):
    from localvault import vault as vault_module

    # Write a vault whose encrypted catalog holds a malformed copy, as an older
    # or damaged build might have left it.
    payload = vault_session._require_typed_catalog()
    payload["license"] = ["not", "a", "dict"]
    monkeypatch.setattr(vault_module, "_validate_payload", lambda value, version=None: value)
    vault_session.save()
    monkeypatch.undo()

    with caplog.at_level("WARNING", logger="localvault.vault"):
        reopened = vault_module.unlock_vault(vault_session.path, "licence vault test password")
    assert reopened.is_unlocked
    assert "license" not in reopened._require_typed_catalog()
    assert licensing.vault_copy(reopened) is None
    assert any("licence" in record.getMessage().lower() for record in caplog.records)


def test_store_in_vault_rejects_bad_copy_without_touching_the_payload(signer, vault_session):
    good = make_bundle(signer)
    licensing.store_in_vault(vault_session, good)
    for bad in ({"license": {"x": "a" * 20_000}}, "nope", ["x"]):
        with pytest.raises(licensing.LicenseError):
            licensing.store_in_vault(vault_session, bad)
        assert vault_session._require_typed_catalog()["license"] == good


def test_store_in_vault_restores_previous_copy_when_save_fails(signer, vault_session, monkeypatch):
    first = make_bundle(signer, license_id="lic-first")
    licensing.store_in_vault(vault_session, first)

    def failing_save():
        raise VaultError("disk full")

    monkeypatch.setattr(vault_session, "save", failing_save)
    with pytest.raises(VaultError):
        licensing.store_in_vault(vault_session, make_bundle(signer, license_id="lic-second"))
    assert vault_session._require_typed_catalog()["license"] == first

    monkeypatch.undo()
    licensing.clear_vault_copy(vault_session)
    monkeypatch.setattr(vault_session, "save", failing_save)
    with pytest.raises(VaultError):
        licensing.store_in_vault(vault_session, first)
    assert "license" not in vault_session._require_typed_catalog()


def test_restore_when_file_missing(signer, vault_session):
    bundle = make_bundle(signer)
    licensing.store_in_vault(vault_session, bundle)
    assert licensing.restore_file_from_vault(vault_session) is True
    assert licensing.status().state == "pro"
    assert licensing.restore_file_from_vault(vault_session) is False  # now valid


def test_restore_replaces_invalid_file(signer, vault_session):
    licensing.store_in_vault(vault_session, make_bundle(signer))
    licensing.license_path().write_text("garbage", encoding="utf-8")
    assert licensing.status().state == "invalid"
    assert licensing.restore_file_from_vault(vault_session) is True
    assert licensing.status().state == "pro"


def test_restore_never_overwrites_valid_different_file(signer, vault_session):
    licensing.store_in_vault(vault_session, make_bundle(signer, license_id="lic-vault"))
    licensing.install_license(licensing.encode_paste(make_bundle(signer, license_id="lic-file")))
    assert licensing.restore_file_from_vault(vault_session) is False
    assert licensing.status().license.license_id == "lic-file"


def test_restore_skips_unverifiable_vault_copy(signer, vault_session):
    bundle = make_bundle(signer)
    bundle["license"]["name"] = "Mallory"
    licensing.store_in_vault(vault_session, bundle)
    assert licensing.restore_file_from_vault(vault_session) is False
    assert not licensing.license_path().exists()


def test_restore_without_copy_or_when_unconfigured(vault_session, tmp_path, monkeypatch):
    monkeypatch.setenv("LOCALGATEKEYS_DATA_DIR", str(tmp_path))
    monkeypatch.setattr(licensing, "LICENSE_KEYS", {})
    assert licensing.restore_file_from_vault(vault_session) is False


def test_features_are_items_sync_totp_and_attachments():
    assert [f.name for f in licensing.Feature] == ["UNLIMITED_ITEMS", "SYNC", "TOTP", "ATTACHMENTS"]


# --- reconcile the licence file with the vault copy (after unlock / install / remove) ---


def test_reconcile_restores_licence_on_fresh_install(signer, vault_session):
    licensing.store_in_vault(vault_session, make_bundle(signer))
    assert licensing.status().state == "free"
    licensing.reconcile_vault_copy(vault_session)
    assert licensing.status().state == "pro"
    assert licensing.item_limit() is None


def test_reconcile_stores_installed_licence_missing_from_vault(signer, vault_session):
    bundle = make_bundle(signer)
    licensing.install_license(licensing.encode_paste(bundle))
    licensing.reconcile_vault_copy(vault_session)
    assert licensing.vault_copy(vault_session) == bundle


def test_reconcile_replaces_older_vault_copy_with_installed_licence(signer, vault_session):
    licensing.store_in_vault(vault_session, make_bundle(signer, license_id="lic-old"))
    newer = make_bundle(signer, license_id="lic-new")
    licensing.install_license(licensing.encode_paste(newer))
    licensing.reconcile_vault_copy(vault_session)
    assert licensing.vault_copy(vault_session) == newer
    assert licensing.status().license.license_id == "lic-new"


def test_remove_licence_clears_vault_copy(signer, vault_session):
    bundle = make_bundle(signer)
    licensing.install_license(licensing.encode_paste(bundle))
    licensing.reconcile_vault_copy(vault_session)
    assert licensing.vault_copy(vault_session) == bundle
    licensing.remove_license()
    assert licensing.removal_pending() is True
    licensing.reconcile_vault_copy(vault_session)
    assert licensing.vault_copy(vault_session) is None
    assert not licensing.license_path().exists()
    assert licensing.removal_pending() is True  # kept until a licence is installed again
    assert licensing.item_limit() == licensing.FREE_ITEM_LIMIT
    licensing.reconcile_vault_copy(vault_session)  # nothing left to restore
    assert licensing.status().state == "free"


def test_remove_while_locked_is_not_restored_on_next_unlock(signer, vault_session):
    licensing.store_in_vault(vault_session, make_bundle(signer))
    licensing.reconcile_vault_copy(vault_session)
    assert licensing.status().state == "pro"
    licensing.remove_license()  # vault locked: only the marker records the removal
    licensing.reconcile_vault_copy(vault_session)  # next unlock
    assert licensing.status().state == "free"
    assert licensing.vault_copy(vault_session) is None


def test_install_clears_a_pending_removal(signer, vault_session):
    licensing.remove_license()
    assert licensing.removal_pending() is True
    bundle = make_bundle(signer)
    licensing.install_license(licensing.encode_paste(bundle))
    assert licensing.removal_pending() is False
    licensing.reconcile_vault_copy(vault_session)
    assert licensing.vault_copy(vault_session) == bundle


def test_reconcile_never_raises(signer, monkeypatch):
    broken = object()  # no vault API at all
    licensing.reconcile_vault_copy(broken)
    monkeypatch.setattr(licensing, "status", lambda: (_ for _ in ()).throw(RuntimeError("x")))
    licensing.reconcile_vault_copy(broken)


def test_reconcile_noop_when_unconfigured(vault_session, tmp_path, monkeypatch):
    monkeypatch.setenv("LOCALGATEKEYS_DATA_DIR", str(tmp_path))
    monkeypatch.setattr(licensing, "LICENSE_KEYS", {})
    licensing.reconcile_vault_copy(vault_session)
    assert licensing.vault_copy(vault_session) is None


def test_removed_licence_does_not_return_from_another_profile(signer, vault_session):
    from localvault.vault import create_vault

    other_dir = Path(".m5-test-data") / uuid.uuid4().hex
    other_dir.mkdir(parents=True, exist_ok=False)
    vault_b = create_vault(other_dir / "vault.json", "licence vault test password", kdf_overrides=_KDF)
    bundle = make_bundle(signer)
    licensing.install_license(licensing.encode_paste(bundle))
    licensing.reconcile_vault_copy(vault_session)  # profile A holds a copy
    licensing.reconcile_vault_copy(vault_b)  # profile B holds a copy
    assert licensing.vault_copy(vault_b) == bundle
    licensing.remove_license()  # while A is unlocked
    licensing.reconcile_vault_copy(vault_session)
    assert licensing.vault_copy(vault_session) is None
    licensing.reconcile_vault_copy(vault_b)  # later: unlock B
    assert licensing.status().state == "free"
    assert licensing.vault_copy(vault_b) is None
    licensing.reconcile_vault_copy(vault_session)  # and A again
    assert licensing.status().state == "free"
    assert licensing.removal_pending() is True


def test_install_succeeds_when_removal_marker_cannot_be_deleted(signer, monkeypatch):
    class StuckMarker:
        def unlink(self, missing_ok=False):
            raise PermissionError("marker locked")

        def exists(self):
            return True

    monkeypatch.setattr(licensing, "_removed_marker_path", lambda: StuckMarker())
    lic = licensing.install_license(licensing.encode_paste(make_bundle(signer)))
    assert lic.license_id == "lic-0001"
    assert licensing.license_path().exists()


def test_sync_state_id_shape():
    import re

    assert re.fullmatch(r"lic:[0-9a-f]{32}", licensing.sync_state_id("any text é"))
    assert licensing.sync_state_id("lic-0001") == "lic:" + hashlib.sha256(b"lic-0001").hexdigest()[:32]


def test_newer_format_needs_a_valid_signature(signer):
    assert licensing.newer_format(make_bundle(signer, format=2))
    assert not licensing.newer_format(make_bundle(signer))
    assert not licensing.newer_format(make_bundle(signer, format=True))
    tampered = make_bundle(signer, format=2)
    tampered["license"]["name"] = "Mallory"
    assert not licensing.newer_format(tampered)
