"""CXF export: the exact inverse of ``importers.cxf`` for logins, codes, notes and passkeys."""
from __future__ import annotations

import base64
import datetime as dt
import json
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from localvault.export import EXPORT_SUFFIXES, ExportError, ExportWarning, export_records
from localvault.exporters.cxf import build_cxf, export_cxf
from localvault.i18n import t
from localvault.importers import ImportedRecord, totp_uri_from_secret
from localvault.importers.cxf import PASSKEY_KEYS, parse_cxf
from localvault.vault import create_vault

KDF = {"time_cost": 1, "memory_cost_kib": 8192, "parallelism": 1, "hash_len": 32}
NOW = dt.datetime(2026, 11, 8, 12, 0, tzinfo=dt.timezone.utc)


def _b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def _p256_der() -> str:
    key = ec.generate_private_key(ec.SECP256R1())
    return _b64u(key.private_bytes(serialization.Encoding.DER, serialization.PrivateFormat.PKCS8,
                                   serialization.NoEncryption()))


def _passkey_record(private_key: str) -> ImportedRecord:
    payload = {"relying_party_id": "pk.example.test", "user_handle": _b64u(b"\x0a\x0b\x0c"),
               "credential_id": _b64u(b"\x01\x02\x03\x04"), "private_key": private_key, "algorithm": "ES256",
               "user_name": "bob", "user_display_name": "Bob B", "created": "2026-01-02"}
    return ImportedRecord(kind="passkey", title="Passkey Site", username="bob", urls=["https://pk.example.test"],
                          custom_fields=[{"name": key, "value": payload[key], "hidden": key == "private_key"}
                                         for key in PASSKEY_KEYS])


def test_roundtrip_login_passkey_note():
    login = ImportedRecord(kind="login", title="Example Mail", username="ada", password="correct horse",
                           urls=["https://mail.example.test/login", "https://example.test"], notes="in the drawer",
                           totp_uri=totp_uri_from_secret("JBSWY3DPEHPK3PXP", label="Example:ada", issuer="Example",
                                                         digits=8, period=60, algorithm="SHA256"),
                           created=1700000000)
    bare = ImportedRecord(kind="login", title="Plain", username="u", password="p", urls=["https://plain.test"])
    note = ImportedRecord(kind="note", title="Memo", notes="remember the milk\nand bread")
    passkey = _passkey_record(_p256_der())
    data = build_cxf([login, bare, note, passkey], now=NOW)
    records, skipped = parse_cxf(data)
    assert skipped == []
    assert records == [login, bare, note, passkey]
    document = json.loads(data)
    assert isinstance(document["items"], list) and len(document["items"]) == 4
    key = next(c for c in document["items"][3]["credentials"] if c["type"] == "passkey")["key"]
    assert "=" not in key and "+" not in key and "/" not in key  # base64url PKCS#8 DER, as the CXF spec reads it
    serialization.load_der_private_key(base64.urlsafe_b64decode(key + "=" * (-len(key) % 4)), password=None)


def test_build_refuses_unsupported_kinds():
    with pytest.raises(ValueError):
        build_cxf([ImportedRecord(kind="identity", title="Me", identity={"given_name": "A"})], now=NOW)


@pytest.fixture
def vault(tmp_path):
    session = create_vault(tmp_path / "vault.json", "cxf export master pw", kdf_overrides=KDF)
    ids = {
        "login": session.create_web_login(urls=[{"url": "https://a.test", "match": "exact_origin"}],
                                          username="alice", password="pw-alice", label="A site"),
        "other": session.create_web_login(urls=[{"url": "https://b.test", "match": "exact_origin"}],
                                          username="bob", password="pw-bob", label="B site"),
        "note": session.items.create_note("Memo", "the body"),
        "identity": session.items.create_identity("Me", {"given_name": "Alice"}),
    }
    session.set_details(ids["login"], totp={"secret": "JBSWY3DPEHPK3PXP", "digits": 6, "period": 30,
                                            "algorithm": "SHA1"})
    ids["passkey"] = session.items.create_passkey(
        "PK site", relying_party_id="pk.example.test", credential_id=_b64u(b"\x01\x02\x03"),
        user_handle=_b64u(b"\x09"), private_key=_p256_der(), algorithm="ES256", user_name="carol",
        created="2026-01-02")
    return session, ids


def _release(session, calls):
    def release(ids):
        calls.append(list(ids))
        return {item_id: session.items.reveal_secret(item_id, "private_key", intent="test CXF export")
                for item_id in ids}
    return release


def test_only_selected_ids_exported(vault, tmp_path: Path):
    session, ids = vault
    calls: list[list[str]] = []
    path = tmp_path / "out.json"
    summary = export_cxf(session, [ids["login"], ids["note"], ids["passkey"]], path,
                         release_private_keys=_release(session, calls), restrict_permissions=False)
    assert calls == [[ids["passkey"]]]
    records, skipped = parse_cxf(path.read_bytes())
    assert skipped == []
    assert sorted(record.title for record in records) == ["A site", "Memo", "PK site"]
    login = next(record for record in records if record.title == "A site")
    assert (login.username, login.password, login.urls) == ("alice", "pw-alice", ["https://a.test"])
    assert login.totp_uri == "otpauth://totp/alice?secret=JBSWY3DPEHPK3PXP"
    passkey = next(record for record in records if record.kind == "passkey")
    fields = {field["name"]: field["value"] for field in passkey.custom_fields}
    assert fields["private_key"] == session.items.reveal_secret(ids["passkey"], "private_key", intent="test")
    assert fields["user_name"] == "carol" and fields["created"] == "2026-01-02"
    assert summary.format == "cxf" and summary.count == 3 and not summary.encrypted
    assert t(ExportWarning.PLAINTEXT) in summary.warnings


def test_no_passkey_selected_does_not_release(vault, tmp_path: Path):
    session, ids = vault
    calls: list[list[str]] = []
    export_cxf(session, [ids["other"]], tmp_path / "out.json", release_private_keys=_release(session, calls),
               restrict_permissions=False)
    assert calls == []


def test_unsupported_kind_is_skipped_and_named(vault, tmp_path: Path):
    session, ids = vault
    summary = export_cxf(session, [ids["identity"], ids["note"]], tmp_path / "out.json",
                         release_private_keys=_release(session, []), restrict_permissions=False)
    assert summary.count == 1 and summary.skipped == 1 and "Me" in summary.diagnostics[0]


def test_totp_left_out_when_not_requested(vault, tmp_path: Path):
    session, ids = vault
    path = tmp_path / "out.json"
    export_cxf(session, [ids["login"]], path, release_private_keys=_release(session, []), include_totp=False,
               restrict_permissions=False)
    assert "JBSWY3DPEHPK3PXP" not in path.read_text(encoding="utf-8")


def test_declined_release_writes_nothing(vault, tmp_path: Path):
    session, ids = vault
    path = tmp_path / "out.json"

    def decline(item_ids):
        raise PermissionError("declined")

    with pytest.raises(PermissionError):
        export_cxf(session, [ids["login"], ids["passkey"]], path, release_private_keys=decline,
                   restrict_permissions=False)
    assert not path.exists()
    assert list(tmp_path.glob(".lgk-export-*")) == []


def test_missing_released_key_aborts(vault, tmp_path: Path):
    session, ids = vault
    path = tmp_path / "out.json"
    with pytest.raises(ExportError):
        export_cxf(session, [ids["passkey"]], path, release_private_keys=lambda item_ids: {},
                   restrict_permissions=False)
    assert not path.exists()


def test_empty_selection_is_refused(vault, tmp_path: Path):
    session, _ids = vault
    with pytest.raises(ExportError):
        export_cxf(session, [], tmp_path / "out.json", release_private_keys=lambda item_ids: {})


def test_export_records_dispatches_cxf(vault, tmp_path: Path):
    session, ids = vault
    assert EXPORT_SUFFIXES["cxf"] == ".json"
    path = tmp_path / "out.json"
    summary = export_records(session, path, "cxf", ids=[ids["other"]], release_private_keys=lambda item_ids: {},
                             restrict_permissions=False)
    assert summary.count == 1 and parse_cxf(path.read_bytes())[0][0].username == "bob"
    with pytest.raises(ExportError):  # a CXF export always names the selected items
        export_records(session, tmp_path / "all.json", "cxf")


def test_cxf_warnings_match_csv_plaintext_warnings():
    csv = ExportWarning.for_format("csv", include_totp=True)
    cxf = ExportWarning.for_format("cxf", include_totp=True)
    assert t(ExportWarning.PLAINTEXT) in cxf and t(ExportWarning.TOTP) in cxf and t(ExportWarning.DELETE_AFTER) in cxf
    assert set(csv) - set(cxf) == {t(ExportWarning.SPREADSHEET)}


def test_empty_logins_stay_logins():
    with_notes = ImportedRecord(kind="login", title="Only notes", notes="kept here", urls=["https://n.test"])
    empty = ImportedRecord(kind="login", title="Empty")
    data = build_cxf([with_notes, empty], now=NOW)
    records, skipped = parse_cxf(data)
    assert skipped == [] and len(records) == 2
    assert records == [with_notes, empty] and all(record.kind == "login" for record in records)


def test_passkey_notes_left_out_are_named(tmp_path: Path):
    session = create_vault(tmp_path / "vault.json", "cxf export master pw", kdf_overrides=KDF)
    item_id = session.items.create_passkey("PK", relying_party_id="pk.test", credential_id="AQID",
                                           private_key=_p256_der(), algorithm="ES256", notes="backup codes elsewhere")
    summary = export_cxf(session, [item_id], tmp_path / "out.json", restrict_permissions=False,
                         release_private_keys=lambda ids: {i: session.items.reveal_secret(i, "private_key", intent="t")
                                                           for i in ids})
    assert summary.count == 1 and summary.diagnostics == (t("export.cxfPasskeyNotesLeftOut", title="PK"),)
    assert "backup codes elsewhere" not in (tmp_path / "out.json").read_text(encoding="utf-8")
