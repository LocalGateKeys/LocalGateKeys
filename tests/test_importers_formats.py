from __future__ import annotations

import base64
import io
import json
import zipfile
from pathlib import Path

import pytest

from localvault.importers import (
    ImportedRecord,
    ImporterError,
    ImportFormatError,
    ImportPasswordError,
    ImportPasswordRequired,
    bitwarden,
    chrome,
    dashlane,
    detect,
    keepass_csv,
    lastpass,
    onepassword,
)
from localvault.importers.bitwarden import (
    BitwardenError,
    encrypt_bitwarden_export,
    load_bitwarden_json,
)

PASSWORD = "export password 123"


def _bitwarden_payload() -> dict:
    return {
        "encrypted": False,
        "folders": [{"id": "f1", "name": "Work"}],
        "items": [
            {"id": "i1", "folderId": "f1", "type": 1, "name": "Example", "notes": "hello", "favorite": True,
             "fields": [{"name": "PIN", "value": "1234", "type": 1}, {"name": "Plan", "value": "gold", "type": 0}],
             "login": {"uris": [{"uri": "https://example.test/login"}, {"uri": "https://alt.example.test"}],
                       "username": "alice", "password": "pw-alice", "totp": "JBSWY3DPEHPK3PXP"},
             "creationDate": "2024-01-02T03:04:05.000Z", "revisionDate": "2024-02-02T03:04:05.000Z"},
            {"id": "i2", "folderId": None, "type": 2, "name": "Memo", "notes": "remember", "secureNote": {"type": 0}},
            {"id": "i3", "type": 3, "name": "Visa", "card": {"cardholderName": "Alice", "number": "4111111111111111",
                                                               "expMonth": "12", "expYear": "2030", "code": "123", "brand": "Visa"}},
            {"id": "i4", "type": 4, "name": "Me", "identity": {"firstName": "Alice", "lastName": "Smith", "email": "a@example.test",
                                                                 "address1": "1 Road", "city": "Town", "ssn": "000-00-0000"}},
        ],
    }


def test_bitwarden_unencrypted_json_maps_all_item_types():
    result = load_bitwarden_json(json.dumps(_bitwarden_payload()).encode())
    assert result.source_format == "bitwarden-json"
    kinds = {record.title: record for record in result.records}
    login = kinds["Example"]
    assert login.kind == "login" and login.folder == "Work" and login.favorite
    assert login.urls == ["https://example.test/login", "https://alt.example.test"]
    assert login.password == "pw-alice" and login.username == "alice"
    assert login.totp_uri.startswith("otpauth://totp/") and "JBSWY3DPEHPK3PXP" in login.totp_uri
    assert {f["name"]: f["hidden"] for f in login.custom_fields} == {"PIN": True, "Plan": False}
    assert login.created == 1704164645 and login.modified == 1706843045
    assert kinds["Memo"].kind == "note" and kinds["Memo"].notes == "remember"
    assert kinds["Visa"].kind == "card"
    assert kinds["Visa"].card == {"cardholder": "Alice", "number": "4111111111111111", "cvv": "123", "brand": "Visa",
                                  "expiry": "12/2030"}
    identity = kinds["Me"]
    assert identity.kind == "identity"
    assert identity.identity["given_name"] == "Alice" and identity.identity["family_name"] == "Smith"
    assert identity.identity["email"] == "a@example.test" and identity.identity["address_line1"] == "1 Road"
    assert "ssn" not in identity.identity and any(f["name"].casefold() == "ssn" and f["hidden"] for f in identity.custom_fields)
    assert "pw-alice" not in repr(result.records)


@pytest.mark.parametrize("kdf", ["pbkdf2", "argon2id"])
def test_bitwarden_password_protected_json_round_trip(kdf):
    encrypted = encrypt_bitwarden_export(_bitwarden_payload(), PASSWORD, kdf=kdf, iterations=1000 if kdf == "pbkdf2" else 1,
                                         memory=8, parallelism=1)
    assert encrypted["encrypted"] is True and encrypted["passwordProtected"] is True
    assert encrypted["data"].startswith("2.") and encrypted["encKeyValidation_DO_NOT_EDIT"].startswith("2.")
    raw = json.dumps(encrypted).encode()
    with pytest.raises(ImportPasswordRequired):
        load_bitwarden_json(raw)
    with pytest.raises(ImportPasswordError):
        load_bitwarden_json(raw, password="wrong")
    result = load_bitwarden_json(raw, password=PASSWORD)
    assert result.source_format == "bitwarden-encrypted-json"
    assert {r.title for r in result.records} == {"Example", "Memo", "Visa", "Me"}
    # Tampered ciphertext must fail the MAC rather than decrypt garbage.
    tampered = dict(encrypted)
    iv, ct, mac = tampered["data"][2:].split("|")
    broken = bytearray(base64.b64decode(ct))
    broken[5] ^= 0x01
    tampered["data"] = "2." + "|".join([iv, base64.b64encode(bytes(broken)).decode(), mac])
    with pytest.raises(BitwardenError):
        load_bitwarden_json(json.dumps(tampered).encode(), password=PASSWORD)
    assert issubclass(BitwardenError, ImporterError)


def test_bitwarden_account_encrypted_export_is_rejected_clearly():
    payload = {"encrypted": True, "passwordProtected": False, "data": "2.a|b|c"}
    with pytest.raises(BitwardenError, match="(?i)account"):
        load_bitwarden_json(json.dumps(payload).encode(), password=PASSWORD)


def test_bitwarden_json_rejects_malformed_documents():
    with pytest.raises(BitwardenError):
        load_bitwarden_json(b"{not json")
    with pytest.raises(BitwardenError):
        load_bitwarden_json(b"[]")
    encrypted = encrypt_bitwarden_export(_bitwarden_payload(), PASSWORD, iterations=1000)
    encrypted["data"] = encrypted["data"][:40]
    with pytest.raises(BitwardenError):
        load_bitwarden_json(json.dumps(encrypted).encode(), password=PASSWORD)


def test_bitwarden_csv_import():
    text = ("folder,favorite,type,name,notes,fields,reprompt,login_uri,login_username,login_password,login_totp\n"
            "Work,1,login,Example,\"line1\nline2\",\"PIN: 1234\nPlan: gold\",0,https://example.test,alice,pw-alice,otpauth://totp/x?secret=JBSWY3DPEHPK3PXP\n"
            ",,note,Memo,remember,,0,,,,\n")
    result = bitwarden.load_bitwarden_csv(text.encode())
    assert result.source_format == "bitwarden-csv"
    login, note = result.records
    assert login.folder == "Work" and login.favorite and login.notes == "line1\nline2"
    assert login.password == "pw-alice" and login.totp_uri.startswith("otpauth://")
    assert [f["name"] for f in login.custom_fields] == ["PIN", "Plan"]
    assert note.kind == "note" and note.notes == "remember"


def _onepassword_export() -> dict:
    return {"accounts": [{"attrs": {"name": "Family"}, "vaults": [{"attrs": {"name": "Private"}, "items": [
        {"uuid": "a", "favIndex": 1, "createdAt": 1700000000, "updatedAt": 1700000100, "state": "active", "categoryUuid": "001",
         "details": {"loginFields": [{"value": "alice", "designation": "username", "fieldType": "T"},
                                     {"value": "pw-alice", "designation": "password", "fieldType": "P"}],
                     "notesPlain": "login note",
                     "sections": [{"title": "Extra", "fields": [
                         {"title": "one-time password", "id": "TOTP_x", "value": {"totp": "JBSWY3DPEHPK3PXP"}},
                         {"title": "PIN", "id": "pin", "value": {"concealed": "1234"}},
                         {"title": "Plan", "id": "plan", "value": {"string": "gold"}}]}]},
         "overview": {"title": "Example", "url": "https://example.test/login", "urls": [{"label": "alt", "url": "https://alt.example.test"}],
                      "tags": ["shopping"]}},
        {"uuid": "b", "favIndex": 0, "state": "active", "categoryUuid": "003",
         "details": {"notesPlain": "remember", "sections": []}, "overview": {"title": "Memo"}},
        {"uuid": "c", "favIndex": 0, "state": "archived", "categoryUuid": "004",
         "details": {"sections": [{"title": "Identification", "fields": [
             {"title": "first name", "id": "firstname", "value": {"string": "Alice"}},
             {"title": "last name", "id": "lastname", "value": {"string": "Smith"}},
             {"title": "email", "id": "email", "value": {"email": {"email_address": "a@example.test"}}},
             {"title": "address", "id": "address", "value": {"address": {"street": "1 Road", "city": "Town", "zip": "12345", "country": "us"}}},
             {"title": "phone", "id": "defphone", "value": {"phone": "+1 555"}}]}]},
         "overview": {"title": "Me"}},
        {"uuid": "d", "favIndex": 0, "state": "active", "categoryUuid": "002",
         "details": {"sections": [{"title": "", "fields": [
             {"title": "number", "id": "ccnum", "value": {"creditCardNumber": "4111111111111111"}},
             {"title": "expiry date", "id": "expiry", "value": {"monthYear": 203012}}]}]},
         "overview": {"title": "Visa"}},
        {"uuid": "e", "favIndex": 0, "state": "active", "categoryUuid": "001", "trashed": True,
         "details": {"loginFields": [{"value": "gone", "designation": "password", "fieldType": "P"}]}, "overview": {"title": "Trashed"}},
    ]}]}]}


def _onepassword_zip(export: dict) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("export.attributes", json.dumps({"version": 3}))
        archive.writestr("export.data", json.dumps(export))
    return buffer.getvalue()


def test_onepassword_1pux_zip_import(tmp_path: Path):
    path = tmp_path / "export.1pux"
    path.write_bytes(_onepassword_zip(_onepassword_export()))
    result = onepassword.load_1pux(path)
    assert result.source_format == "1pux"
    by_title = {record.title: record for record in result.records}
    assert set(by_title) == {"Example", "Memo", "Me", "Visa"}
    login = by_title["Example"]
    assert login.username == "alice" and login.password == "pw-alice" and login.favorite
    assert login.urls == ["https://example.test/login", "https://alt.example.test"]
    assert login.notes == "login note" and login.folder == "Private" and login.tags == ["shopping"]
    assert "JBSWY3DPEHPK3PXP" in login.totp_uri and login.totp_uri.startswith("otpauth://totp/")
    assert {f["name"]: f["hidden"] for f in login.custom_fields} == {"PIN": True, "Plan": False}
    assert login.created == 1700000000 and login.modified == 1700000100
    assert by_title["Memo"].kind == "note" and by_title["Memo"].notes == "remember"
    identity = by_title["Me"]
    assert identity.kind == "identity" and identity.folder.endswith("Archive")
    assert identity.identity["given_name"] == "Alice" and identity.identity["family_name"] == "Smith"
    assert identity.identity["email"] == "a@example.test" and identity.identity["city"] == "Town"
    assert identity.identity["phone"] == "+1 555"
    assert by_title["Visa"].kind == "card"
    assert any("Trashed" in line or "trash" in line.casefold() for line in result.diagnostics)


def test_onepassword_1pux_rejects_bad_archives(tmp_path: Path):
    with pytest.raises(onepassword.OnePasswordError):
        onepassword.load_1pux(b"PK\x03\x04 not really a zip")
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr("other.txt", "x")
    with pytest.raises(onepassword.OnePasswordError, match="export.data"):
        onepassword.load_1pux(buffer.getvalue())
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr("export.data", "{not json")
    with pytest.raises(onepassword.OnePasswordError):
        onepassword.load_1pux(buffer.getvalue())
    assert issubclass(onepassword.OnePasswordError, ImportFormatError)


def test_onepassword_csv_import():
    text = ("Title,Url,Username,Password,OTPAuth,Favorite,Archived,Tags,Notes\n"
            "Example,https://example.test,alice,pw-alice,otpauth://totp/Example?secret=JBSWY3DPEHPK3PXP,true,false,a;b,hello\n")
    result = onepassword.load_1password_csv(text.encode())
    record = result.records[0]
    assert record.title == "Example" and record.favorite and record.tags == ["a", "b"]
    assert record.totp_uri.startswith("otpauth://") and record.notes == "hello" and record.password == "pw-alice"


def test_lastpass_csv_import_with_notes_and_identity():
    text = ("url,username,password,totp,extra,name,grouping,fav\n"
            "https://example.test/login,alice,pw-alice,JBSWY3DPEHPK3PXP,some notes,Example,Work\\Web,1\n"
            "http://sn,,,,\"NoteType:Address\nLanguage:en-US\nTitle:Mr\nFirst Name:Alice\nLast Name:Smith\nAddress 1:1 Road\nCity / Town:Town\nZip / Postal Code:12345\nEmail Address:a@example.test\nNotes:hi\",Me,Personal,0\n"
            "http://sn,,,,plain secure note,Memo,,0\n")
    result = lastpass.load_lastpass_csv(text.encode())
    assert result.source_format == "lastpass-csv"
    login, identity, note = result.records
    assert login.kind == "login" and login.folder == "Work/Web" and login.favorite
    assert login.urls == ["https://example.test/login"] and login.notes == "some notes"
    assert "secret=JBSWY3DPEHPK3PXP" in login.totp_uri
    assert identity.kind == "identity" and identity.identity["given_name"] == "Alice"
    assert identity.identity["address_line1"] == "1 Road" and identity.identity["postal_code"] == "12345"
    assert identity.identity["email"] == "a@example.test" and identity.notes == "hi"
    assert note.kind == "note" and note.notes == "plain secure note" and note.title == "Memo"


def test_dashlane_csv_import_credentials_and_notes():
    creds = ("username,username2,username3,title,password,note,url,category,otpSecret\n"
             "alice,,,Example,pw-alice,hello,https://example.test,Work,JBSWY3DPEHPK3PXP\n")
    result = dashlane.load_dashlane_csv(creds.encode())
    record = result.records[0]
    assert result.source_format == "dashlane-csv"
    assert record.username == "alice" and record.password == "pw-alice" and record.folder == "Work"
    assert record.urls == ["https://example.test"] and "JBSWY3DPEHPK3PXP" in record.totp_uri and record.notes == "hello"
    notes = dashlane.load_dashlane_csv(b"title,note\nMemo,remember\n")
    assert notes.records[0].kind == "note" and notes.records[0].notes == "remember"
    legacy = dashlane.load_dashlane_csv(b"title,url,username,password,note\nX,https://x.test,u,p,n\n")
    assert legacy.records[0].password == "p"


def test_chrome_firefox_safari_and_generic_csv():
    chrome_text = "name,url,username,password,note\nExample,https://example.test/login,alice,pw-alice,hi\n"
    result = chrome.load_browser_csv(chrome_text.encode())
    assert result.source_format == "chrome-csv"
    assert result.records[0].password == "pw-alice" and result.records[0].notes == "hi"
    firefox_text = ("url,username,password,httpRealm,formActionOrigin,guid,timeCreated,timeLastUsed,timePasswordChanged\n"
                    "https://ff.test,bob,pw-bob,,https://ff.test,{x},1700000000000,1700000001000,1700000002000\n")
    result = chrome.load_browser_csv(firefox_text.encode())
    assert result.source_format == "firefox-csv"
    assert result.records[0].title == "ff.test" and result.records[0].created == 1700000000 and result.records[0].modified == 1700000002
    safari_text = "Title,URL,Username,Password,Notes,OTPAuth\nSafari,https://s.test,carol,pw-carol,n,otpauth://totp/s?secret=JBSWY3DPEHPK3PXP\n"
    result = chrome.load_browser_csv(safari_text.encode())
    assert result.source_format == "safari-csv" and result.records[0].totp_uri.startswith("otpauth://")
    generic = "Website,Who,Code,Label\nhttps://g.test,dave,pw-dave,Generic\n"
    with pytest.raises(ImportFormatError):
        chrome.load_generic_csv(generic.encode())
    with pytest.raises(ImportFormatError):
        chrome.load_generic_csv(generic.encode(), column_mapping={"password": "Missing"})
    result = chrome.load_generic_csv(generic.encode(), column_mapping={"url": "Website", "username": "Who",
                                                                      "password": "code", "title": "Label"})
    assert result.records[0].password == "pw-dave" and result.records[0].title == "Generic"
    assert result.fields == ("Website", "Who", "Code", "Label")
    guessed = chrome.load_generic_csv(b"Website,Login,Secret\nhttps://g.test,dave,pw-dave\n")
    assert guessed.records[0].username == "dave" and guessed.records[0].password == "pw-dave"


def test_keepass_csv_variants():
    keepass2 = '"Account","Login Name","Password","Web Site","Comments"\n"Example","alice","pw-alice","https://example.test","hi"\n'
    result = keepass_csv.load_keepass_csv(keepass2.encode())
    assert result.source_format == "keepass-csv"
    assert result.records[0].title == "Example" and result.records[0].password == "pw-alice" and result.records[0].notes == "hi"
    keepassxc = ('"Group","Title","Username","Password","URL","Notes","TOTP","Icon","Last Modified","Created"\n'
                 '"Root/Work","Example","alice","pw-alice","https://example.test","hi","otpauth://totp/x?secret=JBSWY3DPEHPK3PXP","0","2024-01-02T03:04:05Z","2024-01-01T00:00:00Z"\n')
    result = keepass_csv.load_keepass_csv(keepassxc.encode())
    record = result.records[0]
    assert record.folder == "Work" and record.totp_uri.startswith("otpauth://") and record.created == 1704067200


def test_detect_format_by_content_and_extension(tmp_path: Path):
    cases = {
        "a.kdbx": (b"\x03\xd9\xa2\x9a\x67\xfb\x4b\xb5" + b"\x00" * 10, "kdbx", True),
        "a.1pux": (_onepassword_zip(_onepassword_export()), "1pux", False),
        "bw.json": (json.dumps(_bitwarden_payload()).encode(), "bitwarden-json", False),
        "bwe.json": (json.dumps(encrypt_bitwarden_export({"items": []}, PASSWORD, iterations=1000)).encode(), "bitwarden-encrypted-json", True),
        "lp.csv": (b"url,username,password,totp,extra,name,grouping,fav\n", "lastpass-csv", False),
        "dl.csv": (b"username,username2,username3,title,password,note,url,category,otpSecret\n", "dashlane-csv", False),
        "op.csv": (b"Title,Url,Username,Password,OTPAuth,Favorite,Archived,Tags,Notes\n", "1password-csv", False),
        "ch.csv": (b"name,url,username,password,note\n", "chrome-csv", False),
        "ff.csv": (b"url,username,password,httpRealm,formActionOrigin,guid,timeCreated,timeLastUsed,timePasswordChanged\n", "firefox-csv", False),
        "sf.csv": (b"Title,URL,Username,Password,Notes,OTPAuth\n", "safari-csv", False),
        "kp.csv": (b'"Account","Login Name","Password","Web Site","Comments"\n', "keepass-csv", False),
        "kx.csv": (b'"Group","Title","Username","Password","URL","Notes","TOTP","Icon","Last Modified","Created"\n', "keepass-csv", False),
        "bw.csv": (b"folder,favorite,type,name,notes,fields,reprompt,login_uri,login_username,login_password,login_totp\n", "bitwarden-csv", False),
        "gen.csv": (b"Website,Login,Secret\n", "csv", False),
        "kp.xml": (b'<?xml version="1.0"?><KeePassFile><Meta/><Root><Group/></Root></KeePassFile>', "keepass-xml", False),
    }
    for name, (data, expected, needs_password) in cases.items():
        path = tmp_path / name
        path.write_bytes(data)
        detection = detect.detect_format(path)
        assert detection.format == expected, (name, detection)
        assert detection.needs_password is needs_password, name
        assert detection.label
    with pytest.raises(ImportFormatError, match="(?i)1\\.x"):
        detect.detect_format(tmp_path / "old.kdb", b"\x03\xd9\xa2\x9a\x65\xfb\x4b\xb5")
    with pytest.raises(ImportFormatError):
        detect.detect_format(tmp_path / "x.bin", b"\x00\x01\x02 binary garbage")


def test_load_records_dispatches_and_requires_passwords(tmp_path: Path):
    from localvault.importers.kdbx import write_kdbx
    path = tmp_path / "db.kdbx"
    path.write_bytes(write_kdbx([ImportedRecord(title="K", username="u", password="p", urls=["https://k.test"])],
                                PASSWORD, kdf="aes-kdf", kdf_params={"rounds": 16}))
    with pytest.raises(ImportPasswordRequired):
        detect.load_records(path)
    result = detect.load_records(path, password=PASSWORD)
    assert result.source_format == "kdbx" and result.records[0].title == "K"
    csv_path = tmp_path / "chrome.csv"
    csv_path.write_text("name,url,username,password\nE,https://e.test,u,p\n", encoding="utf-8")
    assert detect.load_records(csv_path).records[0].title == "E"
    assert detect.load_records(csv_path, source_format="csv", column_mapping={"url": "url", "password": "password", "username": "username"}).records[0].title == "e.test"
    with pytest.raises(ImportFormatError):
        detect.load_records(csv_path, source_format="made-up")
    assert "kdbx" in detect.SUPPORTED_FORMATS and "1pux" in detect.SUPPORTED_FORMATS
