"""Credential Exchange (CXF) importer: mapping, detection and apply of passkeys."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from localvault.import_workflow import apply_import_plan, plan_records
from localvault.importers import ImportFormatError
from localvault.importers.cxf import import_cxf, parse_cxf
from localvault.importers.detect import SUPPORTED_FORMATS, detect_format, load_records
from localvault.vault import create_vault

SAMPLE = Path(__file__).parent / "vectors" / "cxf" / "apple-passwords-sample.json"
KDF = {"time_cost": 1, "memory_cost_kib": 8192, "parallelism": 1, "hash_len": 32}


def _doc(*items: dict) -> bytes:
    return json.dumps({"id": "QQ", "userName": "u", "items": list(items)}).encode()


def _fields(record) -> dict[str, str]:
    return {f["name"]: f["value"] for f in record.custom_fields}


def test_sample_counts() -> None:
    records, skipped = parse_cxf(SAMPLE.read_bytes())
    kinds = [r.kind for r in records]
    assert kinds.count("login") == 2
    assert kinds.count("passkey") == 1
    assert kinds.count("note") == 0
    assert skipped == ["credit-card"]
    mail = next(r for r in records if r.title == "Example Mail")
    assert mail.urls == ["https://mail.example.test/login", "https://example.test"]
    assert (mail.username, mail.password, mail.notes) == ("ada", "correct horse", "recovery in drawer")
    passkey = next(r for r in records if r.kind == "passkey")
    fields = _fields(passkey)
    assert fields["relying_party_id"] == "pk.example.test"
    assert fields["credential_id"] == "AQIDBAUGBwg"
    assert fields["user_handle"] == "CgsMDQ4P"
    assert fields["user_name"] == "bob"
    assert fields["user_display_name"] == "Bob B"
    assert fields["algorithm"] == "ES256"
    assert fields["private_key"]
    assert next(f for f in passkey.custom_fields if f["name"] == "private_key")["hidden"] is True


def test_totp_merges_into_login() -> None:
    records, _ = parse_cxf(SAMPLE.read_bytes())
    mail = next(r for r in records if r.title == "Example Mail")
    assert mail.totp_uri.startswith("otpauth://totp/")
    assert "secret=JBSWY3DPEHPK3PXP" in mail.totp_uri
    assert "issuer=Example" in mail.totp_uri


def test_orphan_totp_becomes_login() -> None:
    records, skipped = parse_cxf(_doc({"id": "a", "title": "Codes", "scope": {"urls": ["https://c.test"]},
                                       "credentials": [{"type": "totp", "secret": "JBSWY3DPEHPK3PXP"}]}))
    assert skipped == []
    assert len(records) == 1
    record = records[0]
    assert record.kind == "login"
    assert (record.username, record.password) == ("", "")
    assert record.urls == ["https://c.test"]
    assert "secret=JBSWY3DPEHPK3PXP" in record.totp_uri


def test_orphan_note_becomes_note() -> None:
    records, _ = parse_cxf(_doc({"id": "a", "title": "Memo", "credentials": [
        {"type": "note", "content": {"value": "hello"}}]}))
    assert [(r.kind, r.title, r.notes) for r in records] == [("note", "Memo", "hello")]


def test_unknown_type_skipped_and_named() -> None:
    records, skipped = parse_cxf(_doc({"id": "a", "title": "X", "credentials": [
        {"type": "ssh-key", "privateKey": "x"}, {"type": "wifi"}, {"type": "ssh-key"}, {"notype": 1}]}))
    assert records == []
    assert skipped == ["ssh-key", "wifi", "ssh-key", "unknown"]
    result = import_cxf(_doc({"id": "a", "title": "X", "credentials": [{"type": "ssh-key"}]}))
    assert any("ssh-key" in line for line in result.diagnostics)


def test_unknown_passkey_field_ignored() -> None:
    sample = json.loads(SAMPLE.read_text(encoding="utf-8"))
    passkey = sample["items"][1]["credentials"][1]
    passkey["fido2Extensions"] = {"hmacCredentials": {"algorithm": "x"}}
    passkey["futureField"] = 42
    sample["items"][1]["credentials"][0]["extra"] = "ignored"
    records, skipped = parse_cxf(json.dumps(sample).encode())
    assert [r.kind for r in records].count("passkey") == 1
    assert skipped == ["credit-card"]


def test_bad_passkey_is_skipped_not_fatal() -> None:
    records, skipped = parse_cxf(_doc({"id": "a", "title": "P", "credentials": [
        {"type": "passkey", "credentialId": "!!", "rpId": "x.test", "key": "zz"}]}))
    assert records == []
    assert skipped == ["passkey"]


def test_detect_format_returns_cxf(tmp_path: Path) -> None:
    assert SUPPORTED_FORMATS["cxf"] == "Credential Exchange (CXF)"
    detection = detect_format(SAMPLE)
    assert detection.format == "cxf"
    path = tmp_path / "export.cxf"
    path.write_bytes(SAMPLE.read_bytes())
    assert detect_format(path).format == "cxf"
    result = load_records(path)
    assert result.source_format == "cxf"
    assert len(result.records) == 3


def test_bitwarden_json_still_detected() -> None:
    blob = json.dumps({"encrypted": False, "items": [{"type": 1, "name": "x", "login": {}}]}).encode()
    assert detect_format(Path("x.json"), blob).format == "bitwarden-json"


@pytest.mark.parametrize("blob", [b"", b"[]", b"{}", b'{"items": 5}', b"{not json", b'{"items": [1, "x", null]}'])
def test_malformed_input_raises_format_error_or_empty(blob: bytes) -> None:
    try:
        records, _ = parse_cxf(blob)
    except ImportFormatError:
        return
    assert records == []


def test_oversized_file_rejected() -> None:
    with pytest.raises(ImportFormatError):
        parse_cxf(b"{" + b" " * (17 * 1024 * 1024) + b"}")


def test_sample_applies_with_passkey(tmp_path: Path) -> None:
    session = create_vault(tmp_path / "vault.json", "cxf test master", kdf_overrides=KDF)
    plan = plan_records(session, import_cxf(SAMPLE).records)
    plan.review()
    apply_import_plan(session, plan)
    passkeys = [item for item in session.items.list_items(kinds=["passkey"]) if item.get("kind") == "passkey"]
    assert len(passkeys) == 1
    full = session.items.get_item(passkeys[0]["id"], include_protected=True)
    assert full["payload"]["relying_party_id"] == "pk.example.test"
    assert full["payload"]["algorithm"] == "ES256"
    from localvault.passkeys import usable_record
    assert usable_record(full["payload"])


def test_second_basic_auth_is_skipped_like_swift() -> None:
    records, skipped = parse_cxf(_doc({"id": "a", "title": "Two", "scope": {"urls": ["https://two.test"]},
                                       "credentials": [{"type": "basic-auth", "username": "a", "password": "p1"},
                                                       {"type": "basic-auth", "username": "b", "password": "p2"}]}))
    assert [(r.kind, r.username) for r in records] == [("login", "a")]
    assert skipped == ["basic-auth"]


def test_free_vault_one_below_limit_imports_one_of_three(tmp_path: Path) -> None:
    session = create_vault(tmp_path / "vault.json", "cxf test master", kdf_overrides=KDF)
    for i in range(6):
        session.upsert_web(origin=f"https://site{i}.example", username="me", password=f"pw-{i}")
    session.item_limit = 7
    plan = plan_records(session, import_cxf(SAMPLE).records)
    assert plan.free_slots == 1
    assert [row.kind for row in plan.rows].count("passkey") == 1
    assert [row.limited for row in plan.rows] == [False, True, True]
    assert plan.limit_note() == "1 will be imported on the free plan; 2 need Pro"
    plan.review()
    apply_import_plan(session, plan)
    assert session.live_item_count() == 7


def _passkey_doc(credential_id: str, user_handle: str, username: str) -> bytes:
    sample = json.loads(SAMPLE.read_text(encoding="utf-8"))
    passkey = dict(sample["items"][1]["credentials"][1], credentialId=credential_id, userHandle=user_handle,
                   username=username)
    return _doc({"id": "p", "title": "Example Passkey Site", "scope": {"urls": ["https://pk.example.test"]},
                 "credentials": [passkey]})


def test_same_site_passkeys_match_by_credential_not_title(tmp_path: Path) -> None:
    session = create_vault(tmp_path / "vault.json", "cxf test master", kdf_overrides=KDF)
    first = plan_records(session, import_cxf(_passkey_doc("AQIDBAUGBwg", "CgsMDQ4P", "bob")).records)
    first.review()
    apply_import_plan(session, first)
    # A second account on the same site: same title, different credential ID -> a new item, never a conflict.
    second = plan_records(session, import_cxf(_passkey_doc("CQkJCQkJCQk", "AQEBAQ", "eve")).records)
    assert [(row.kind, row.status, row.decision) for row in second.rows] == [("passkey", "new", "add")]
    second.review()
    apply_import_plan(session, second)
    passkeys = [item for item in session.items.list_items(kinds=["passkey"]) if item.get("kind") == "passkey"]
    assert len(passkeys) == 2
    # The same credential ID again is a duplicate of the stored one.
    again = plan_records(session, import_cxf(_passkey_doc("CQkJCQkJCQk", "AQEBAQ", "eve")).records)
    assert [(row.status, row.decision) for row in again.rows] == [("duplicate", "skip")]
    assert again.rows[0].target_id is not None


def test_broken_unicode_escape_is_mended_not_fatal() -> None:
    lone, mended = chr(0xD800), chr(0xFFFD)  # json.dumps writes a lone-surrogate escape
    records, skipped = parse_cxf(_doc(
        {"id": "a", "title": "Codes", "scope": {"urls": ["https://c.test"]},
         "credentials": [{"type": "basic-auth", "username": "ann", "password": "pw" + lone},
                         {"type": "totp", "secret": "JBSWY3DPEHPK3PXP", "issuer": "Bad" + lone}]},
        {"id": "b", "title": "Fine", "credentials": [{"type": "note", "content": "kept"}]}))
    assert skipped == []
    assert [(r.kind, r.title) for r in records] == [("login", "Codes"), ("note", "Fine")]
    login = records[0]
    assert (login.username, login.password) == ("ann", "pw" + mended)
    assert "secret=JBSWY3DPEHPK3PXP" in login.totp_uri and "issuer=Bad%EF%BF%BD" in login.totp_uri


def test_note_only_items_import_as_notes() -> None:
    records, skipped = parse_cxf(_doc(
        {"id": "a", "title": "Title only", "credentials": [{"type": "note", "content": ""}]},
        {"id": "b", "title": "With text", "credentials": [{"type": "note", "content": "body"}]}))
    assert skipped == []
    assert [(r.kind, r.title, r.notes) for r in records] == [
        ("note", "Title only", ""), ("note", "With text", "body")]
