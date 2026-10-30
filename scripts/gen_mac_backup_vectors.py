"""Generate the Mac import/backup vectors in ``tests/vectors/import``.

Test-only.  The Windows importers (``localvault.importers``) run unmodified over every file in
``tests/fixtures/imports`` plus a set of edge-case inputs written by this script into
``tests/vectors/import/_inputs``.  Each run is stored, normalised to plain JSON, as
``tests/vectors/import/<format>/<name>.expected.json``; ``<format>`` is the Swift
``ImportFormat`` raw value.  ``detect.json`` pins ``detect_format`` for every input and
``generic_mapping.json`` pins ``guess_mapping`` (restricted to the Swift mapping targets).

Usage::

    python scripts/gen_mac_backup_vectors.py [OUT_DIR]      # default: tests/vectors/import
    python scripts/gen_mac_backup_vectors.py backup [OUT]  # default: tests/vectors/backup/v2
    python scripts/gen_mac_backup_vectors.py kit [OUT]     # default: tests/vectors/recovery/kit
    python scripts/gen_mac_backup_vectors.py recovery [OUT]  # default: tests/vectors/recovery
    python scripts/gen_mac_backup_vectors.py schedule [OUT]  # default: tests/vectors/backup/schedule

The ``backup`` section (Task 5) writes a full backup v2 (``full.lgkfull``) with Windows
``export_full_backup`` over a fixture profile, with every random byte and the clock fixed, plus
the inputs it was made from, the random stream it consumed (``expected.json``) and a rejected set
(``rejected/*.lgkfull``, each with the message Windows gives).  ``from_mac.lgkfull`` is written by
the Swift ``FullBackupV2Tests`` and only read here (``tests/test_mac_backup_vectors.py``).

The ``kit`` section (Task 6) writes, with Windows ``recovery.py`` and the clock fixed, the
``.sha256.json`` checksum manifest and the recovery kit for ``backup/v2/full.lgkfull``, plus a
rejected set of manifests (``rejected/*.sha256.json``, each with the message Windows gives).
``from_mac/`` is written by the Swift ``MacFullBackupTests`` (a backup made through the Mac's
create path) and only read here.

The ``recovery`` section (Task 7) writes ``phrases.json`` (Windows ``phrase_from_entropy`` and
``entropy_from_phrase`` over fixed entropies and typed variants, with the message for each refusal)
and ``wrapper.json`` (a Windows vault with a recovery phrase enrolled, every random byte fixed).
``from_mac_vault.json`` is written by the Swift ``BIP39Tests`` (a Mac-sealed vault carrying a
recovery wrapper) and only read here.

The ``schedule`` section (Task 9) writes ``schedule.json``: Windows ``backup_schedule.py``
``latest_slot``, ``is_due``, ``validated_time``, ``profile_tag``, ``scheduled_filename``,
``owned_backups`` and ``prune`` over fixed clocks (naive local times) and folder listings.
"""

# ruff: noqa: S101

from __future__ import annotations

import io
import json
import shutil
import sys
import zipfile
from pathlib import Path

from localvault.importers import ImporterError, ImportPasswordError, ImportPasswordRequired
from localvault.importers.chrome import guess_mapping
from localvault.importers.detect import detect_format, load_records

ROOT = Path(__file__).resolve().parent.parent
FIXTURES = ROOT / "tests/fixtures/imports"

# Python detect/load format -> Swift ImportFormat raw value.
SWIFT_FORMAT = {
    "kdbx": "keePassKDBX", "keepass-xml": "keePassXML", "keepass-csv": "keePassCSV", "1pux": "onePassword1PUX",
    "1password-csv": "onePasswordCSV", "protonpass-json": "protonPass", "protonpass-csv": "protonPass",
    "bitwarden-json": "bitwarden", "bitwarden-encrypted-json": "bitwardenEncrypted", "bitwarden-csv": "bitwarden",
    "lastpass-csv": "lastPass", "dashlane-zip": "dashlane", "dashlane-csv": "dashlane", "chrome-csv": "chrome",
    "firefox-csv": "firefox", "safari-csv": "appleCSV", "csv": "generic",
}
GENERIC_TARGETS = ("title", "url", "username", "password", "notes", "totp")
TEXT_FORMATS = {"keepass-xml", "keepass-csv", "1password-csv", "protonpass-json", "protonpass-csv", "bitwarden-json",
                "bitwarden-csv", "lastpass-csv", "dashlane-csv", "chrome-csv", "firefox-csv", "safari-csv", "csv"}


# --------------------------------------------------------------------------- edge-case inputs
def _lastpass_notes() -> str:
    many = "\n".join(f"Field {i}:value {i}" for i in range(60))
    long_name = "N" * 150
    rows = [
        "url,username,password,totp,extra,name,grouping,fav",
        'http://sn,,,,"NoteType:Address\nLanguage:en-GB\nTitle:mr\nFirst Name:Alex\nMiddle Name:Q\nLast Name:Example\n'
        'Username:alexq\nCompany:Example Ltd\nAddress 1:1 Example Road\nCity / Town:Exampleton\n'
        'Zip / Postal Code:EX1 2PL\nCountry:GB\nEmail Address:alex@example.com\nPhone:0100\nMobile Phone:0200\n'
        'Fax:0300\nNotes:Home address\nsecond line",Home,Personal,1',
        'http://sn,,,,"NoteType:Credit Card\nLanguage:en-GB\nName on Card:Alex Example\nType:Visa\n'
        'Number:4111111111111111\nSecurity Code:123\nStart Date:January,2020\nExpiration Date:January,2027\n'
        'Notes:Main card",Visa card,Finance,0',
        'http://sn,,,,"NoteType:Credit Card\nNumber:5555555555554444\nExpiration Date:sometime\nPIN code:9999",Odd card,,0',
        f'http://sn,,,,"NoteType:Server\nHostname:db.example.test\nPassword:srv-secret\nLanguage:en\n{many}\n'
        f'{long_name}:{"v" * 5000}",Server note,Work\\Infra,0',
        'http://sn,,,,"Just a plain note\nwith two lines",Plain note,,0',
        ',,,,"No URL note",Loose note,,0',
        'https://site.example.com,alex,pw,JBSWY3DP EHPK3PXP,,,Folder\\Sub,yes',
    ]
    return "\r\n".join(rows) + "\r\n"


def _bitwarden_types() -> str:
    uris = [{"uri": f"https://u{i}.example.com"} for i in range(25)]
    doc = {
        "encrypted": False,
        "folders": [{"id": "f1", "name": "Work"}],
        "collections": [{"id": "c1", "name": "Shared"}],
        "items": [
            {"type": 1, "name": "Many URLs", "folderId": "f1", "favorite": True, "notes": "n",
             "creationDate": "2024-01-02T03:04:05.123Z", "revisionDate": "2024-02-03T04:05:06Z",
             "login": {"username": "u", "password": "p", "totp": "JBSWY3DPEHPK3PXP", "uris": uris,
                       "fido2Credentials": [{"credentialId": "x"}]},
             "fields": [{"name": "Text", "value": "t", "type": 0}, {"name": "Hidden", "value": "h", "type": 1},
                        {"name": "Bool", "value": "TRUE", "type": 2}, {"name": "Linked", "value": None, "type": 3},
                        {"name": "", "value": "no name", "type": 0}, {"name": "Null", "value": None, "type": 0},
                        {"name": "Number", "value": 42, "type": 0}]},
            {"type": 1, "name": "Collection only", "collectionIds": ["c1"], "login": {"username": "c"}},
            {"type": 2, "name": "Secure note", "notes": "secret text", "secureNote": {"type": 0}},
            {"type": 3, "name": "Card", "card": {"cardholderName": "Alex", "number": "4111111111111111",
                                                 "code": "123", "brand": "Visa", "expMonth": "1", "expYear": "2027"}},
            {"type": 3, "name": "Bad expiry", "card": {"number": "5555555555554444", "expMonth": "13",
                                                       "expYear": "27"}},
            {"type": 4, "name": "Identity", "identity": {
                "title": "Mr", "firstName": "Alex", "middleName": None, "lastName": "Example", "company": "Ex",
                "email": "a@example.com", "phone": "0100", "address1": "1 Road", "city": "Town", "postalCode": "EX1",
                "country": "GB", "ssn": "000-00-0000", "passportNumber": "P1", "username": "alexe",
                "address3": "Flat 2"}},
            {"type": 5, "name": "SSH", "sshKey": {"privateKey": "-----BEGIN-----", "publicKey": "ssh-ed25519 AAA",
                                                  "keyFingerprint": "SHA256:x"}},
            {"type": 9, "name": "Future", "notes": "kept", "fields": [{"name": "F", "value": "v", "type": 0}]},
            {"type": 1, "name": "Trashed", "deletedDate": "2024-01-01T00:00:00Z", "login": {}},
            "not an object",
            {"type": 1, "name": "Epoch ms", "creationDate": 1700000000000, "login": {"uris": [{"uri": None}, "x"]}},
        ],
    }
    return json.dumps(doc, indent=2)


def _protonpass_types() -> str:
    def item(kind, name, content, **extra):
        data = {"type": kind, "metadata": {"name": name, "note": f"{name} note"}, "content": content}
        data.update(extra.pop("data", {}))
        return {"itemId": name, "state": 1, "createTime": 1700000000, "modifyTime": 1700000500, "data": data,
                **extra}
    doc = {"encrypted": False, "vaults": {
        "s1": {"name": "Personal", "items": [
            item("login", "Login", {"itemEmail": "a@example.com", "itemUsername": "alex",
                                    "password": "pw", "urls": ["https://a.example.com", "", None],
                                    "totpUri": "", "passkeys": [{"k": 1}]}, pinned=True,
                 data={"extraFields": [
                     {"fieldName": "Second TOTP", "type": "totp", "data": {"totpUri": "JBSWY3DPEHPK3PXP"}},
                     {"fieldName": "Third TOTP", "type": "totp", "data": {"totpUri": "otpauth://totp/x?secret=AA"}},
                     {"fieldName": "Hidden", "type": "hidden", "data": {"content": "h"}},
                     {"fieldName": "", "type": "text", "data": {"content": "nameless"}},
                     {"fieldName": "When", "type": "timestamp", "data": {"timestamp": "2024-01-01"}}]}),
            item("login", "Email only", {"itemEmail": "e@example.com", "password": "pw2", "urls": []}),
            item("creditCard", "Card", {"cardholderName": "Alex", "number": "4111111111111111",
                                        "verificationNumber": "123", "pin": "0000", "expirationDate": "2027-01"}),
            item("creditCard", "Odd card", {"number": "5555", "expirationDate": "soon"}),
            item("identity", "Me", {"firstName": "Alex", "lastName": "Example", "email": "a@example.com",
                                    "socialSecurityNumber": "000", "birthdate": "1990-01-01",
                                    "extraPersonalDetails": [{"fieldName": "Nick", "type": "text",
                                                              "data": {"content": "Al"}}],
                                    "extraSections": [{"sectionName": "More", "sectionFields": [
                                        {"fieldName": "Pet", "type": "text", "data": {"content": "Cat"}}]}]}),
            item("identity", "Full", {"fullName": "Alex Q Example", "firstName": "Alex"}),
        ]},
        "s2": {"name": "Other", "items": [
            {**item("alias", "Alias", {}), "aliasEmail": "x@alias.test"},
            item("sshKey", "Key", {"privateKey": "priv", "publicKey": "pub"}),
            item("wifi", "Home Wi-Fi", {"ssid": "Net", "password": "wifipw", "security": "WPA2"}),
            item("custom", "Custom", {"sections": [{"sectionFields": [
                {"fieldName": "Code", "type": "hidden", "data": {"content": "c0de"}}]}]}),
            {**item("note", "Trashed", {}), "state": 2},
            "bad",
        ]},
        "s3": "not a vault",
    }}
    return json.dumps(doc, indent=2)


def _keepass_types() -> str:
    return """<?xml version="1.0" encoding="utf-8" standalone="yes"?>
<KeePassFile>
\t<Meta>
\t\t<Generator>KeePassXC</Generator>
\t\t<RecycleBinUUID> YmluYmluYmluYmluYmluMA== </RecycleBinUUID>
\t</Meta>
\t<Root>
\t\t<Group>
\t\t\t<UUID>cm9vdA==</UUID>
\t\t\t<Name>Root</Name>
\t\t\t<Entry>
\t\t\t\t<Tags>a, b;c</Tags>
\t\t\t\t<Times><CreationTime>AAAAAAAAAAA=</CreationTime><LastModificationTime>gIW+3A4AAAA=</LastModificationTime></Times>
\t\t\t\t<String><Key>Title</Key><Value>Key query</Value></String>
\t\t\t\t<String><Key>UserName</Key><Value>u1</Value></String>
\t\t\t\t<String><Key>otp</Key><Value>key=JBSWY3DPEHPK3PXP&amp;size=8&amp;step=60&amp;otpHashMode=sha256</Value></String>
\t\t\t\t<String><Key>Protected</Key><Value Protected="True">c2VjcmV0IHZhbHVl</Value></String>
\t\t\t\t<String><Key>Empty</Key><Value/></String>
\t\t\t</Entry>
\t\t\t<Entry>
\t\t\t\t<String><Key>Title</Key><Value>Seed</Value></String>
\t\t\t\t<String><Key>TOTP Seed</Key><Value>JBSW Y3DP EHPK 3PXP</Value></String>
\t\t\t\t<String><Key>TOTP Settings</Key><Value>60;8</Value></String>
\t\t\t</Entry>
\t\t\t<Entry>
\t\t\t\t<String><Key>Title</Key><Value>Built-in</Value></String>
\t\t\t\t<String><Key>TimeOtp-Secret-Base32</Key><Value>JBSWY3DPEHPK3PXP</Value></String>
\t\t\t\t<String><Key>TimeOtp-Length</Key><Value>7</Value></String>
\t\t\t\t<String><Key>TimeOtp-Period</Key><Value>45</Value></String>
\t\t\t\t<String><Key>TimeOtp-Algorithm</Key><Value>HMAC-SHA-512</Value></String>
\t\t\t</Entry>
\t\t\t<Entry>
\t\t\t\t<String><Key>Title</Key><Value>Hex only</Value></String>
\t\t\t\t<String><Key>TimeOtp-Secret-Hex</Key><Value>48656c6c6f</Value></String>
\t\t\t\t<String><Key>Notes</Key><Value>just a note</Value></String>
\t\t\t</Entry>
\t\t\t<Entry>
\t\t\t\t<String><Key>Title</Key><Value>Bare secret</Value></String>
\t\t\t\t<String><Key>OTP</Key><Value>jbswy3dpehpk3pxp==</Value></String>
\t\t\t\t<String><Key>Title</Key><Value>Duplicate title</Value></String>
\t\t\t</Entry>
\t\t\t<Group>
\t\t\t\t<UUID>YmluYmluYmluYmluYmluMA==</UUID>
\t\t\t\t<Name>Recycle Bin</Name>
\t\t\t\t<Entry><String><Key>Title</Key><Value>Deleted</Value></String></Entry>
\t\t\t\t<Group><Name>Inner</Name><Entry><String><Key>Title</Key><Value>Deleted 2</Value></String></Entry></Group>
\t\t\t</Group>
\t\t\t<Group>
\t\t\t\t<Name> Work </Name>
\t\t\t\t<Group>
\t\t\t\t\t<Name>Servers</Name>
\t\t\t\t\t<Entry>
\t\t\t\t\t\t<String><Key>Title</Key><Value>Deep</Value></String>
\t\t\t\t\t\t<String><Key>URL</Key><Value>https://deep.example.com</Value></String>
\t\t\t\t\t\t<Binary><Key>a.txt</Key><Value Ref="0"/></Binary>
\t\t\t\t\t\t<History><Entry><String><Key>Title</Key><Value>Old</Value></String></Entry>
\t\t\t\t\t\t<Entry><String><Key>Title</Key><Value>Older</Value></String></Entry></History>
\t\t\t\t\t</Entry>
\t\t\t\t</Group>
\t\t\t</Group>
\t\t</Group>
\t</Root>
</KeePassFile>
"""


def _inputs() -> dict[str, bytes]:
    """Edge-case inputs: name -> bytes."""
    out: dict[str, bytes] = {}
    out["generic.csv"] = (
        "Label,Address,Email,Pwd,Comments,TOTP Secret,Group\n"
        "My site,https://my.example.com/login,me@example.com,pw1,hello,JBSWY3DPEHPK3PXP,A\\B\n"
        ",https://User:x@Host.Example.COM:8443/p,,pw2,,,\n"
        "Only notes,,,,a note body,,\n"
        ",,,,,,\n"
        "Bare,example.org/path,bob,pw3,,,\n"
        "IPv6,http://[::1]:80/x,,pw4,,,\n"
        "Bad v6,http://[::1/x,,pw5,,,\n"
        ",,,,,TOTPONLY,\n"
    ).encode()
    out["semicolon.csv"] = (
        "name;url;username;password;note\r\n"
        "\r\n"
        'Quoted;"https://q.example.com";"al""ex";"p;w";"line1\r\nline2"\r\n'
        'Stray;https://s.example.com;ab"c;"x"y;\r\n'
        "Extra;https://e.example.com;e;pw;n;extra1;extra2\r\n"
        "Short;https://short.example.com\r\n"
        "  \t ;;;;\r\n"
        '"Unterminated;https://u.example.com;u;pw;n\r\nmore'
    ).encode()
    out["cp1252.csv"] = "name,url,username,password,note\nCafé,https://cafe.example.com,jürgen,pw,€\n".encode("cp1252")
    out["utf16.csv"] = "﻿name,url,username,password,note\nUnicode,https://u.example.com,élève,pw☃,n\n".encode("utf-16-le")
    out["bom_tabs.csv"] = "﻿Name\tURL\tUser Name\tPassword\tNote\nTab,https://t.example.com,x\tt\tpw\tnote\n".encode()
    out["lastpass_notes.csv"] = _lastpass_notes().encode()
    out["bitwarden_types.json"] = _bitwarden_types().encode()
    out["bitwarden_types.csv"] = (
        "folder,favorite,type,name,notes,fields,reprompt,login_uri,login_username,login_password,login_totp\n"
        'F,true,note,A note,body,"k: v\nno colon\n: empty name",0,,,,\n'
        ",0,card,A card,,,0,,,,\n"
        ',,,No type,,,0,"https://a.example.com, ,https://b.example.com",u,p,otpauth://totp/x?secret=AB\n'
    ).encode()
    out["protonpass_types.json"] = _protonpass_types().encode()
    out["protonpass_types.csv"] = (
        "type,name,url,email,username,password,note,totp,createTime,modifyTime,vault\n"
        "login,L,https://l.example.com,e@example.com,,pw,,,2024-01-01T00:00:00Z,bad,V\n"
        "alias,A,,a@alias.test,,,,,,,V\n"
        "creditCard,C,,,,,,,,,V\n"
        "wifi,W,,,u,secret,,,,,V\n"
        ",Typeless,https://t.example.com,,u,p,,,1700000000,,V\n"
    ).encode()
    out["keepass_types.xml"] = _keepass_types().encode()
    out["firefox_fallback.csv"] = (
        "url,username,password,httpRealm,formActionOrigin,guid,timeCreated,timeLastUsed,timePasswordChanged\n"
        ",alex,pw,,https://form.example.com,{g},1700000000000,1700000100000,\n"
        "https://x.example.com,,,,,{g2},,,\n"
    ).encode()
    out["dashlane_legacy.csv"] = (
        "title,url,username,password,note\n"
        "Legacy,https://legacy.example.com,u,pw,n\n"
        "Note only,,,,just text\n"
    ).encode()
    out["dashlane_credentials_dupes.csv"] = (
        "username,username2,username3,title,password,note,url,category,otpSecret\n"
        "alex,alex,alt,Dupes,pw,,https://d.example.com,Cat,JBSWY3DPEHPK3PXP\n"
    ).encode()
    out["onepassword_tags.csv"] = (
        "Title,Url,Username,Password,OTPAuth,Favorite,Archived,Tags,Notes\n"
        "Tagged,https://t.example.com,u,pw,,yes,1,\"a; b,c ,,\",n\n"
        "Note only,,,,,,,,note body\n"
        ",https://untitled.example.com,u,pw,,,,,\n"
    ).encode()
    out["keepassxc_root.csv"] = (
        '"Group","Title","Username","Password","URL","Notes","TOTP","Icon","Last Modified","Created"\n'
        '"Passwords\\\\Web","T","u","p","https://k.example.com","","JBSWY3DPEHPK3PXP","0","2024-01-01 10:00:00","2023-12-31"\n'
        '"Root/","Note","","","","only notes","","0","",""\n'
    ).encode()
    out["too_many.csv"] = ("name,url,username,password\n" + "".join(
        f"n{i},https://h{i}.example.com,u,p\n" for i in range(5001))).encode()
    # Detection-only inputs.
    out["pgp.txt"] = b"-----BEGIN PGP MESSAGE-----\nabc\n"
    out["kdb1.kdb"] = bytes.fromhex("03d9a29a65fb4bb5") + b"\0" * 8
    out["kdbx4.kdbx"] = bytes.fromhex("03d9a29a67fb4bb5") + b"\0" * 8
    out["not_kdbx.kdbx"] = b"hello"
    out["other.xml"] = b"<root/>"
    out["other.json"] = b'{"hello": 1}'
    out["array.json"] = b"[1, 2]"
    out["empty.csv"] = b""
    out["one_column.txt"] = b"just words\n"
    out["binary.bin"] = b"\x00\x01\x02 binary"
    out["proton_encrypted.json"] = b'{"encrypted": true, "vaults": {}}'
    out["onepif.1pif"] = b"***"
    for name, members in (
        ("dashlane.zip", {"credentials.csv": "title,password\n"}),
        ("onepux.1pux", {"export.data": "{}", "export.attributes": "{}"}),
        ("proton.zip", {"Proton Pass/data.json": "{}"}),
        ("proton_pgp.zip", {"Proton Pass/data.pgp": "x"}),
        ("random.zip", {"readme.txt": "hi"}),
    ):
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
            for member, text in members.items():
                archive.writestr(member, text)
        out[name] = buffer.getvalue()
    out["not_a_zip.1pux"] = b"plain"
    return out



# --------------------------------------------------------------------------- encrypted and archive inputs (Task 2)
KDBX_PASSWORD = "kdbx fixture password"
BITWARDEN_PASSWORD = "fixture export password"
FAST_ARGON = {"memory": 1024 * 1024, "iterations": 2, "parallelism": 2}
FAST_AES = {"rounds": 1000}


class _SeededRandom:
    """Deterministic ``os.urandom`` while the encrypted inputs are written, so the vectors are stable."""

    def __init__(self, seed: int) -> None:
        import random
        self._random = random.Random(seed)

    def __call__(self, count: int) -> bytes:
        return self._random.randbytes(count)


def _zip(members, *, method=zipfile.ZIP_DEFLATED) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        for name, data in members:
            info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
            info.compress_type = method
            archive.writestr(info, data)
    return buffer.getvalue()


def _set_encrypted_flag(data: bytes) -> bytes:
    """Mark every member as encrypted (general-purpose bit 0) in the local and central headers."""
    out = bytearray(data)
    for signature, offset in ((b"PK\x03\x04", 6), (b"PK\x01\x02", 8)):
        start = 0
        while (index := out.find(signature, start)) >= 0:
            out[index + offset] |= 0x01
            start = index + 4
    return bytes(out)


def _onepassword_types() -> str:
    def item(category, title, *, sections=(), details=None, **extra):
        body = {"uuid": title, "favIndex": extra.pop("fav", 0), "createdAt": 1700000000, "updatedAt": 1700000500,
                "state": extra.pop("state", "active"), "categoryUuid": category,
                "overview": {"title": title, "url": extra.pop("url", ""), "urls": extra.pop("urls", []),
                             "tags": extra.pop("tags", [])},
                "details": {"notesPlain": f"{title} notes", "sections": list(sections), **(details or {})}}
        body.update(extra)
        return body

    def field(title, value, fid="", **extra):
        return {"title": title, "id": fid, "value": value, **extra}

    totp = {"totp": "JBSWY3DPEHPK3PXP"}
    doc = {"accounts": [{"attrs": {"name": "Alex"}, "vaults": [
        {"attrs": {"name": "Private"}, "items": [
            item("001", "Login", url="https://a.example.com",
                 urls=[{"url": "https://a.example.com"}, {"url": "https://b.example.com"}, "bad"], fav=3,
                 tags=["web", 7], details={"loginFields": [
                     {"designation": "username", "value": "alex"}, {"designation": "", "fieldType": "P", "value": "pw"},
                     {"designation": "username", "value": "second"}]},
                 sections=[{"fields": [
                     field("one-time password", totp, "TOTP_1"), field("second code", {"totp": "AAAA"}, "TOTP_2"),
                     field("Website", {"url": "https://c.example.com"}), field("Website", {"url": "https://a.example.com"}),
                     field("Email", {"email": {"email_address": "a@example.com"}}),
                     field("When", {"date": 1700000000}), field("Expires", {"monthYear": 202701}),
                     field("Odd month", {"monthYear": 27}), field("Blob", {"string": {"a": [1, 2.5, True, None]}}),
                     field("Recovery key", {"string": "rk"}, "recovery"), field("Guarded", {"string": "g"}, guarded=True),
                     field("", {"concealed": "c"}, "conc_id"), field("Empty", {"string": ""}), field("Null", {"string": None}),
                     field("Nothing", {}), "not a field"]}, "not a section"]),
            item("005", "Password only", details={"password": "only-pw"}),
            item("003", "Note with code", sections=[{"fields": [field("one-time password", totp, "TOTP_n")]}]),
            item("002", "Card", sections=[{"fields": [
                field("cardholder name", {"string": "Alex"}, "cardholder"), field("number", {"creditCardNumber": "4111111111111111"}, "ccnum"),
                field("verification number", {"concealed": "123"}, "cvv"), field("expiry date", {"monthYear": 202701}, "expiry"),
                field("type", {"cardType": "visa"}, "type"), field("PIN", {"concealed": "0000"}, "pin"),
                field("one-time password", {"totp": "otpauth://totp/Card?secret=JBSWY3DPEHPK3PXP"}, "TOTP_c")]}]),
            item("004", "Identity", sections=[{"fields": [
                field("first name", {"string": "Alex"}, "firstname"), field("initial", {"string": "Q"}, "initial"),
                field("last name", {"string": "Example"}, "lastname"),
                field("address", {"address": {"street": "1 Road", "city": "Town", "zip": "EX1", "country": "gb", "state": ""}}, "address"),
                field("cell", {"phone": "0200"}, "cellphone"), field("home", {"phone": "0100"}, "homephone"),
                field("one-time password", totp, "TOTP_i")]}]),
            item("101", "Bank", sections=[{"fields": [field("PIN", {"concealed": "1234"}, "telephonePin"),
                                                      field("one-time password", totp, "TOTP_b")]}]),
            item("006", "Document", details={"documentAttributes": {"fileName": "a.pdf"}}),
            item("999", "Unknown category"),
            item("001", "Archived", state="archived"),
            item("001", "Trashed", trashed=True),
            "not an item",
        ]},
        {"attrs": {}, "items": [item("001", "No vault name", state="archived")]},
        "not a vault",
    ]}, "not an account"]}
    return json.dumps(doc, indent=2)


def _patch_variant(data: bytes, name: bytes, value: int) -> bytes:
    """Rewrite one UINT64 entry of the KDBX 4 KDF parameter dictionary (header checks run before any HMAC)."""
    marker = bytes([0x05]) + len(name).to_bytes(4, "little") + name + (8).to_bytes(4, "little")
    index = data.index(marker) + len(marker)
    return data[:index] + value.to_bytes(8, "little") + data[index + 8:]


def _archive_inputs(inputs_dir: Path) -> list[tuple[str, str, str | None, str]]:
    import os
    from unittest import mock

    from localvault.importers import bitwarden, kdbx
    from localvault.importers.kdbx import CIPHER_AES, CIPHER_TWOFISH, write_kdbx

    files: dict[str, bytes] = {}
    with mock.patch.object(os, "urandom", _SeededRandom(20261030)):
        types_doc = json.loads(_bitwarden_types())
        argon = bitwarden.encrypt_bitwarden_export(types_doc, "argon fixture password", kdf="argon2id", iterations=2,
                                                   memory=16, parallelism=2)
        files["bitwarden_argon2.json"] = json.dumps(argon, indent=2).encode()
        pbkdf2 = bitwarden.encrypt_bitwarden_export(types_doc, BITWARDEN_PASSWORD, iterations=5000)
        files["bitwarden_pbkdf2.json"] = json.dumps(pbkdf2, indent=2).encode()
        files["bitwarden_bad_iterations.json"] = json.dumps({**pbkdf2, "kdfIterations": 2_000_001}).encode()
        files["bitwarden_bad_argon.json"] = json.dumps({**argon, "kdfMemory": 2048}).encode()
        tampered = dict(pbkdf2)
        iv, body, mac = tampered["data"][2:].split("|")
        tampered["data"] = "2." + "|".join((iv, body, mac[:-4] + ("AAA=" if mac[-4:] != "AAA=" else "BBB=")))
        tampered.pop("encKeyValidation_DO_NOT_EDIT")
        files["bitwarden_tampered.json"] = json.dumps(tampered).encode()

        keepass_xml = (FIXTURES / "keepass.xml").read_text(encoding="utf-8")
        types_xml = _keepass_types()
        files["kdbx4_aes_argon2d.kdbx"] = write_kdbx([], KDBX_PASSWORD, xml=keepass_xml, kdf_params=FAST_ARGON)
        files["kdbx4_chacha_argon2id.kdbx"] = write_kdbx([], KDBX_PASSWORD, xml=types_xml, cipher="chacha20",
                                                        kdf="argon2id", kdf_params=FAST_ARGON)
        files["kdbx4_aeskdf_plain.kdbx"] = write_kdbx([], KDBX_PASSWORD, xml=types_xml, kdf="aes-kdf",
                                                      kdf_params=FAST_AES, compress=False)
        files["kdbx3_salsa20.kdbx"] = write_kdbx([], KDBX_PASSWORD, xml=types_xml, version=3, kdf_params=FAST_AES)
        files["kdbx3_keepass.kdbx"] = write_kdbx([], KDBX_PASSWORD, xml=keepass_xml, version=3, kdf_params=FAST_AES,
                                                 compress=False)
        files["kdbx4_keyfile.kdbx"] = write_kdbx([], KDBX_PASSWORD, xml=keepass_xml, kdf="aes-kdf", kdf_params=FAST_AES,
                                                 keyfile=b"arbitrary key material")
        base = files["kdbx4_aes_argon2d.kdbx"]
        files["kdbx4_twofish.kdbx"] = base.replace(CIPHER_AES, CIPHER_TWOFISH, 1)
        files["kdbx4_argon_iterations.kdbx"] = _patch_variant(base, b"I", kdbx.MAX_ARGON2_ITERATIONS + 1)
        files["kdbx4_argon_memory.kdbx"] = _patch_variant(base, b"M", kdbx.MAX_ARGON2_MEMORY + 1024)
        files["kdbx4_argon_work.kdbx"] = _patch_variant(_patch_variant(base, b"M", kdbx.MAX_ARGON2_MEMORY), b"I", 33)
        files["kdbx4_aeskdf_rounds.kdbx"] = _patch_variant(files["kdbx4_aeskdf_plain.kdbx"], b"R",
                                                           kdbx.MAX_AES_KDF_ROUNDS + 1)
        files["kdbx4_truncated.kdbx"] = base[:len(base) - 40]

    export_data = (FIXTURES / "onepassword/export.data").read_bytes()
    attributes = b'{"version": 3, "description": "1Password Unencrypted Export", "createdAt": 1700000000}'
    files["onepassword.1pux"] = _zip([("export.attributes", attributes), ("export.data", export_data)])
    files["onepassword_stored.1pux"] = _zip([("export.data", export_data)], method=zipfile.ZIP_STORED)
    files["onepassword_types.1pux"] = _zip([("export.attributes", attributes),
                                            ("export.data", _onepassword_types().encode()),
                                            ("files/abc__a.pdf", b"%PDF-1.4 not really")])
    files["onepassword_no_data.1pux"] = _zip([("export.attributes", attributes)])
    files["onepassword_bad_json.1pux"] = _zip([("export.data", b"{not json")])
    files["onepassword_encrypted.1pux"] = _set_encrypted_flag(_zip([("export.data", export_data)],
                                                                   method=zipfile.ZIP_STORED))
    single = _zip([("export.data", export_data)])
    files["onepassword_corrupt.1pux"] = single[:80] + bytes(b ^ 0x5A for b in single[80:120]) + single[120:]
    dashlane = sorted((FIXTURES / "dashlane").iterdir())
    files["dashlane_export.zip"] = _zip([(p.name, p.read_bytes()) for p in dashlane]
                                        + [("unknown.csv", b"a,b\n1,2\n")])
    files["dashlane_nested.zip"] = _zip([("export/" + p.name, p.read_bytes()) for p in dashlane[:2]]
                                        + [("export/personalInfo.csv", b"x,y\n1,2\n")])
    files["dashlane_encrypted.zip"] = _set_encrypted_flag(_zip([("credentials.csv", dashlane[0].read_bytes())],
                                                               method=zipfile.ZIP_STORED))
    proton = (FIXTURES / "protonpass/Proton Pass/data.json").read_bytes()
    files["protonpass_export.zip"] = _zip([("Proton Pass/data.json", proton), ("Proton Pass/files/x.bin", b"x")])
    files["protonpass_elsewhere.zip"] = _zip([("export/data.json", proton)], method=zipfile.ZIP_STORED)
    files["protonpass_no_data.zip"] = _zip([("Proton Pass/readme.json", b"{}")])
    for name, data in files.items():
        (inputs_dir / name).write_bytes(data)

    def rel(name: str) -> str:
        return f"tests/vectors/import/_inputs/{name}"

    cases: list[tuple[str, str, str | None, str]] = [
        ("tests/fixtures/imports/bitwarden_protected.json", "bitwarden-encrypted-json", BITWARDEN_PASSWORD, ""),
        ("tests/fixtures/imports/bitwarden_protected.json", "bitwarden-encrypted-json", "not the password", "wrong"),
        ("tests/fixtures/imports/bitwarden_protected.json", "bitwarden-encrypted-json", None, "nopassword"),
        (rel("bitwarden_argon2.json"), "bitwarden-encrypted-json", "argon fixture password", ""),
        (rel("bitwarden_argon2.json"), "bitwarden-encrypted-json", "wrong argon password", "wrong"),
        (rel("bitwarden_pbkdf2.json"), "bitwarden-encrypted-json", BITWARDEN_PASSWORD, ""),
        (rel("bitwarden_bad_iterations.json"), "bitwarden-encrypted-json", BITWARDEN_PASSWORD, ""),
        (rel("bitwarden_bad_argon.json"), "bitwarden-encrypted-json", BITWARDEN_PASSWORD, ""),
        (rel("bitwarden_tampered.json"), "bitwarden-encrypted-json", BITWARDEN_PASSWORD, ""),
        ("tests/fixtures/imports/onepassword/export.data", "1pux", None, ""),
    ]
    for name in ("kdbx4_aes_argon2d.kdbx", "kdbx4_chacha_argon2id.kdbx", "kdbx4_aeskdf_plain.kdbx", "kdbx3_salsa20.kdbx",
                 "kdbx3_keepass.kdbx", "kdbx4_keyfile.kdbx", "kdbx4_twofish.kdbx", "kdbx4_argon_iterations.kdbx",
                 "kdbx4_argon_memory.kdbx", "kdbx4_argon_work.kdbx", "kdbx4_aeskdf_rounds.kdbx", "kdbx4_truncated.kdbx"):
        cases.append((rel(name), "kdbx", KDBX_PASSWORD, ""))
    cases += [
        (rel("kdbx4_aes_argon2d.kdbx"), "kdbx", "wrong kdbx password", "wrong"),
        (rel("kdbx3_salsa20.kdbx"), "kdbx", "wrong kdbx password", "wrong"),
        (rel("kdbx4_aes_argon2d.kdbx"), "kdbx", None, "nopassword"),
    ]
    for name in files:
        if name.endswith(".1pux"):
            cases.append((rel(name), "1pux", None, ""))
        elif name.startswith("dashlane_"):
            cases.append((rel(name), "dashlane-zip", None, ""))
        elif name.startswith("protonpass_"):
            cases.append((rel(name), "protonpass-json", None, ""))
    cases += [(rel("dashlane.zip"), "dashlane-zip", None, ""), (rel("proton.zip"), "protonpass-json", None, ""),
              (rel("proton_pgp.zip"), "protonpass-json", None, "")]
    return cases


# --------------------------------------------------------------------------- normalising
def _record(record) -> dict:
    return {
        "kind": record.kind, "title": record.title, "username": record.username, "password": record.password,
        "urls": list(record.urls), "notes": record.notes, "totp_uri": record.totp_uri, "folder": record.folder,
        "favorite": record.favorite, "custom_fields": record.custom_fields, "created": record.created,
        "modified": record.modified, "tags": list(record.tags), "identity": dict(record.identity),
        "card": dict(record.card), "source_row": record.source_row,
    }


def _generic_mapping(header) -> dict:
    guessed = guess_mapping(list(header))
    return {target: guessed[target] for target in GENERIC_TARGETS if target in guessed}


def _load_case(path: Path, rel: str, python_format: str, password: str | None = None) -> dict:
    case = {"input": rel, "python_format": python_format, "format": SWIFT_FORMAT[python_format]}
    if password is not None:
        case["password"] = password
    try:
        mapping = None
        if python_format == "csv":
            from localvault.importers.detect import csv_header
            mapping = _generic_mapping(csv_header(path))
            case["mapping"] = mapping
        result = load_records(path, source_format=python_format, column_mapping=mapping, password=password)
    except ImportPasswordRequired as exc:
        case["error"] = {"type": "password_required", "message": str(exc)}
        return case
    except ImportPasswordError as exc:
        case["error"] = {"type": "wrong_password", "message": str(exc)}
        return case
    except ImporterError as exc:
        case["error"] = {"type": "format", "message": str(exc)}
        return case
    case["result"] = {"source_format": result.source_format, "records": [_record(r) for r in result.records],
                      "diagnostics": list(result.diagnostics)}
    return case


def _detect(path: Path) -> str | None:
    try:
        return detect_format(path).format
    except ImporterError:
        return None


def main() -> None:
    out = Path(sys.argv[1]) if len(sys.argv) > 1 else ROOT / "tests/vectors/import"
    if out.exists():
        shutil.rmtree(out)
    inputs_dir = out / "_inputs"
    inputs_dir.mkdir(parents=True)
    for name, data in _inputs().items():
        (inputs_dir / name).write_bytes(data)
    archive_cases = _archive_inputs(inputs_dir)

    sources: list[Path] = sorted(p for p in FIXTURES.rglob("*") if p.is_file() and p.name != "README.md")
    sources += sorted(inputs_dir.iterdir())
    detect_doc = []
    mapping_doc = []
    for path in sources:
        rel = path.relative_to(ROOT).as_posix()
        python_format = _detect(path)
        detect_doc.append({"input": rel, "python_format": python_format,
                           "format": SWIFT_FORMAT.get(python_format) if python_format else None})
        load_format = python_format
        if path.name == "bitwarden_account_restricted.json":
            load_format = "bitwarden-json"
        if load_format not in TEXT_FORMATS or path.read_bytes()[:2] == b"PK":
            continue  # zip archives are Task 2 (ZipReader)
        if load_format in {"csv", "chrome-csv", "lastpass-csv"} and path.suffix == ".csv":
            from localvault.importers.detect import csv_header
            try:
                mapping_doc.append({"input": rel, "header": list(csv_header(path)),
                                    "mapping": _generic_mapping(csv_header(path))})
            except ImporterError:
                pass
        case = _load_case(path, rel, load_format)
        target = out / case["format"]
        target.mkdir(exist_ok=True)
        stem = path.name.replace(" ", "_").rsplit(".", 1)[0] + "." + path.suffix.lstrip(".")
        (target / f"{stem}.expected.json").write_text(newline="\n", data=
            json.dumps(case, indent=2, sort_keys=True, ensure_ascii=False) + "\n", encoding="utf-8")
    # Generic CSV for the browser files too: the user can always pick "Generic CSV".
    for rel in ("tests/fixtures/imports/chrome.csv", "tests/fixtures/imports/keepass2.csv"):
        path = ROOT / rel
        case = _load_case(path, rel, "csv")
        (out / "generic" / (path.stem + ".csv.expected.json")).write_text(newline="\n", data=
            json.dumps(case, indent=2, sort_keys=True, ensure_ascii=False) + "\n", encoding="utf-8")
    # Encrypted and archive formats (Task 2): (input, Python format, password, case label).
    for rel, python_format, password, label in archive_cases:
        path = ROOT / rel
        case = _load_case(path, rel, python_format, password)
        target = out / case["format"]
        target.mkdir(exist_ok=True)
        stem = path.name.replace(" ", "_").rsplit(".", 1)[0] + "." + path.suffix.lstrip(".")
        (target / f"{stem}{'.' + label if label else ''}.expected.json").write_text(newline="\n", data=
            json.dumps(case, indent=2, sort_keys=True, ensure_ascii=False) + "\n", encoding="utf-8")
    (out / "detect.json").write_text(newline="\n", data=json.dumps(detect_doc, indent=2, sort_keys=True) + "\n")
    (out / "generic_mapping.json").write_text(newline="\n", data=json.dumps(mapping_doc, indent=2, sort_keys=True,
                                                         ensure_ascii=False) + "\n")
    print(out)


# --------------------------------------------------------------------------- full backup v2 (Task 5)
BACKUP_PASSWORD = "fixture backup password 2026"
MASTER_PASSWORD = "fixture master password 2026"
PROFILE_NAME = "Fixture profile"
BACKUP_NOW = 1793000000
CHEAP_KDF = {"time_cost": 1, "memory_cost_kib": 8192, "parallelism": 1}
ATTACHMENT_IDS = ("3f2b8c1e-5a4d-4e7f-9b1a-2c3d4e5f6a7b", "0a1b2c3d-4e5f-4a6b-8c7d-9e0f1a2b3c4d")
ATTACHMENT_STORE_ID = "7c6b5a49-3827-4615-a4b3-c2d1e0f9a8b7"


class _RecordingRandom:
    """A seeded ``os.urandom`` that remembers every byte it hands out (the Swift test replays them)."""

    def __init__(self, seed: int) -> None:
        import random
        self._random = random.Random(seed)
        self.taken = bytearray()

    def __call__(self, count: int) -> bytes:
        data = self._random.randbytes(count)
        self.taken += data
        return data


class _Fixed:
    """Patch ``os.urandom`` and the clock for the duration of a block."""

    def __init__(self, random_source, now: int) -> None:
        self._random, self._now, self._saved = random_source, now, None

    def __enter__(self):
        import os
        import random
        import time
        self._saved = (os.urandom, random._urandom, time.time, time.time_ns)
        # ``secrets`` reaches the system source through ``random._urandom``.
        os.urandom = random._urandom = self._random
        time.time = lambda: float(self._now)
        time.time_ns = lambda: self._now * 1_000_000_000
        return self

    def __exit__(self, *exc) -> None:
        import os
        import random
        import time
        os.urandom, random._urandom, time.time, time.time_ns = self._saved


def _sidecar(attachment_id: str, body: bytes) -> bytes:
    """A v2 attachment sidecar (magic, header length, header, nonce, AES-GCM body); the key is irrelevant here."""
    from localvault.attachments import ATTACHMENT_MAGIC
    header = json.dumps({"format": "localgatekeys-attachment", "version": 2, "id": attachment_id,
                         "store_id": ATTACHMENT_STORE_ID}, separators=(",", ":"), sort_keys=True).encode()
    return ATTACHMENT_MAGIC + len(header).to_bytes(4, "big") + header + b"\x11" * 12 + body + b"\x22" * 16


def _fixture_profile(root: Path) -> list:
    """A Windows profile with logins, typed items and attachment sidecars; returns its synced records."""
    from localvault import vault as vault_module
    from localvault.vault import create_vault
    from localvault.backup import _full_canonical, _full_validate_settings
    # The unlock-throttle binding hashes the vault's absolute path; leave it out so the vault (and
    # the backup) does not depend on where the generator runs.  Vaults without one are valid.
    saved_binding = vault_module.UnlockThrottle.binding
    vault_module.UnlockThrottle.binding = lambda self: None
    # Windows DPAPI seals the rollback anchor with this user's machine key; turn it off so the
    # vectors are the same on every machine (the Mac has no DPAPI and writes "dpapi": null).
    saved_dpapi = vault_module._dpapi
    vault_module._dpapi = lambda: None
    try:
        return _fixture_profile_with(root, create_vault, _full_canonical, _full_validate_settings)
    finally:
        vault_module.UnlockThrottle.binding = saved_binding
        vault_module._dpapi = saved_dpapi


def _fixture_profile_with(root: Path, create_vault, _full_canonical, _full_validate_settings) -> list:
    with _Fixed(_SeededRandom(5101), BACKUP_NOW - 3600):
        session = create_vault(root / "vault.json", MASTER_PASSWORD, kdf_overrides=CHEAP_KDF)
        try:
            session.create_web_login(urls=[{"url": "https://mail.example.com", "match": "exact_origin"}],
                                     username="alex@example.com", password="Correct-Horse-1", label="Mail",
                                     notes="Main inbox", tags=["personal"])
            session.create_web_login(urls=[{"url": "https://bank.example.org", "match": "exact_origin"}],
                                     username="alex", password="Ünïcode-pässword-2", label="Bank — current")
            session.item_service.create_note("Router", "Wi-Fi: example-net\nsecond line")
            session.item_service.create_card("Visa", cardholder="Alex Example", number="4111111111111111",
                                             expiry="01/30")
            payload = session._require_payload()
            records = list(payload["entries"]) + list(payload["items"])
        finally:
            session.lock()
    settings = _full_validate_settings({"auto_lock_seconds": 600, "clipboard_clear_seconds": 20})
    (root / "settings.json").write_bytes(_full_canonical(settings))
    attachments = root / "Attachments"
    attachments.mkdir()
    for index, attachment_id in enumerate(ATTACHMENT_IDS):
        (attachments / f"{attachment_id}.blob").write_bytes(_sidecar(attachment_id, bytes([index]) * (40 + index)))
    return json.loads(json.dumps(records))


def _stored_zip(members, *, method=zipfile.ZIP_STORED) -> bytes:
    from localvault.backup import _full_zip_info
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_STORED, allowZip64=True) as archive:
        for name, data in members:
            info = _full_zip_info(name)
            info.compress_type = method
            archive.writestr(info, data)
    return buffer.getvalue()


def _members(data: bytes) -> list:
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        return [(info.filename, archive.read(info)) for info in archive.infolist()]


def _rejected(good: bytes) -> dict[str, bytes]:
    members = _members(good)
    names = [name for name, _ in members]
    data_index = names.index("data/00000000.bin")

    def edited(index: int, value: bytes | None = None, name: str | None = None) -> bytes:
        rows = list(members)
        old_name, old_data = rows[index]
        rows[index] = (name or old_name, old_data if value is None else value)
        return _stored_zip(rows)

    flipped = bytearray(members[data_index][1])
    flipped[20] ^= 0x01
    header = json.loads(members[0][1])
    bad_kdf = dict(header, kdf=dict(header["kdf"], time_cost=11))
    bad_format = dict(header, version=3)
    from localvault.backup import _full_canonical
    duplicate = list(members) + [members[data_index]]
    encrypted = bytearray(good)
    start = 0
    while (index := encrypted.find(b"PK\x01\x02", start)) >= 0:
        encrypted[index + 8] |= 0x01
        start = index + 4
    return {
        "truncated.lgkfull": good[: len(good) // 2],
        "tampered_member.lgkfull": edited(data_index, bytes(flipped)),
        "tampered_header.lgkfull": edited(0, members[0][1] + b" "),
        "bad_kdf.lgkfull": edited(0, _full_canonical(bad_kdf)),
        "bad_version.lgkfull": edited(0, _full_canonical(bad_format)),
        "deflated.lgkfull": _stored_zip(members, method=zipfile.ZIP_DEFLATED),
        "encrypted_flag.lgkfull": bytes(encrypted),
        "traversal.lgkfull": edited(data_index, name="../00000000.bin"),
        "duplicate_name.lgkfull": _stored_zip(duplicate),
        "unexpected_member.lgkfull": _stored_zip(list(members) + [("data/extra.bin", b"x" * 40)]),
        "missing_member.lgkfull": _stored_zip([row for row in members if row[0] != names[-1]]),
        "short_manifest.lgkfull": edited(names.index("manifest.bin"), b"\0" * 20),
    }


def _python_refusal(path: Path, password: str) -> str:
    from localvault.backup import BackupError, _full_read_container
    try:
        _full_read_container(path, password, on_entry=lambda entry, data: None)
    except BackupError as exc:
        return str(exc)
    raise AssertionError(f"{path.name} was accepted by Windows")


def _legacy_vault(version: int, payload: dict) -> bytes:
    """A format 1 or 2 vault (Argon2id output is the catalog key) sealed as ``vault.py`` reads it."""
    import base64
    import hashlib
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from localvault import vault as v
    salt = hashlib.sha256(b"lgk-mac-legacy-salt-%d" % version).digest()[:16]
    nonce = hashlib.sha256(b"lgk-mac-legacy-nonce-%d" % version).digest()[:12]
    kdf = {"name": "argon2id", **CHEAP_KDF, "hash_len": 32, "salt": base64.b64encode(salt).decode()}
    header = {"version": version, "kdf": kdf, "cipher": {"name": "aes-256-gcm", "nonce": base64.b64encode(nonce).decode()}}
    if version == 2:
        header.update(format=v.FORMAT_V2_IDENTIFIER, catalog=v.CATALOG_FORMAT)
    key = bytes(v._derive_key(MASTER_PASSWORD, kdf))
    plaintext = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode()
    header["cipher"]["ciphertext"] = base64.b64encode(AESGCM(key).encrypt(nonce, plaintext, v._aad(header))).decode()
    return json.dumps(header, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode()


def _legacy_vaults(out: Path, profile_vault: Path) -> dict:
    """``inputs/vault_v1.json`` and ``inputs/vault_v2.json``; each must open in Windows to the records it holds."""
    import tempfile
    from localvault.vault import unlock_vault
    with tempfile.TemporaryDirectory() as tmp:
        copy = Path(tmp) / "vault.json"
        shutil.copyfile(profile_vault, copy)
        session = unlock_vault(copy, MASTER_PASSWORD, upgrade_envelope=False)
        try:
            v2 = json.loads(json.dumps(session._require_payload()))
        finally:
            session.lock()
    v2.pop("rollback_anchor_required", None)
    v1 = {"version": 1, "generation": v2["generation"], "entries": v2["entries"], "trash": []}
    result = {}
    for version, payload in ((1, v1), (2, v2)):
        data = _legacy_vault(version, payload)
        name = f"vault_v{version}.json"
        (out / "inputs" / name).write_bytes(data)
        with tempfile.TemporaryDirectory() as tmp:
            probe = Path(tmp) / "vault.json"
            probe.write_bytes(data)
            session = unlock_vault(probe, MASTER_PASSWORD, upgrade_envelope=False)
            try:
                opened = session._require_payload()
                ids = sorted(r["id"] for r in opened["entries"] + opened.get("items", []))
            finally:
                session.lock()
        result[name] = ids
    return result


def backup_main(out: Path) -> None:
    import hashlib
    import tempfile
    from localvault.backup import export_full_backup
    keep = out / "from_mac.lgkfull"
    kept = keep.read_bytes() if keep.exists() else None
    if out.exists():
        shutil.rmtree(out)
    (out / "inputs").mkdir(parents=True)
    (out / "rejected").mkdir()
    if kept is not None:
        keep.write_bytes(kept)
    with tempfile.TemporaryDirectory() as tmp:
        profile = Path(tmp) / "profile"
        profile.mkdir()
        records = _fixture_profile(profile)
        random_source = _RecordingRandom(5102)
        with _Fixed(random_source, BACKUP_NOW):
            export_full_backup(Path(tmp) / "full.lgkfull", profile_dir=profile, profile_name=PROFILE_NAME,
                               backup_password=BACKUP_PASSWORD, kdf_overrides=CHEAP_KDF)
        good = (Path(tmp) / "full.lgkfull").read_bytes()
        inputs = {"vault.json": profile / "vault.json", "settings.json": profile / "settings.json",
                  "generation.json": profile / "vault.generation.json"}
        inputs.update({f"{a}.blob": profile / "Attachments" / f"{a}.blob" for a in ATTACHMENT_IDS})
        for name, source in inputs.items():
            (out / "inputs" / name).write_bytes(source.read_bytes())
        legacy = _legacy_vaults(out, profile / "vault.json")
    (out / "full.lgkfull").write_bytes(good)
    rejected = {}
    for name, data in _rejected(good).items():
        (out / "rejected" / name).write_bytes(data)
        rejected[name] = _python_refusal(out / "rejected" / name, BACKUP_PASSWORD)
    rejected["full.lgkfull with a wrong password"] = _python_refusal(out / "full.lgkfull", "not the backup password")
    from localvault.backup import _full_read_container
    manifest = _full_read_container(out / "full.lgkfull", BACKUP_PASSWORD, on_entry=lambda e, d: None)["manifest"]
    expected = {
        "backup_password": BACKUP_PASSWORD,
        "master_password": MASTER_PASSWORD,
        "profile_name": PROFILE_NAME,
        "created_at": BACKUP_NOW,
        "kdf": CHEAP_KDF,
        "random_hex": bytes(random_source.taken).hex(),
        "attachment_ids": sorted(ATTACHMENT_IDS),
        "manifest": manifest,
        "records": records,
        "legacy_vault_ids": legacy,
        "full_sha256": hashlib.sha256(good).hexdigest(),
        "rejected": rejected,
        "note": "TEST ONLY: every password and key here is published. inputs/ are the files export_full_backup read.",
    }
    (out / "expected.json").write_text(newline="\n", data=json.dumps(expected, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
                                       encoding="utf-8")
    print(out)


KIT_NOW = 1793000100
KIT_APP_VERSION = "1.0.0"


def kit_main(out: Path) -> None:
    """Checksum manifest and recovery kit for ``full.lgkfull`` (Windows ``recovery.py``, clock fixed)."""
    import hashlib
    import tempfile
    from unittest import mock
    from localvault import recovery
    from localvault.config import atomic_write_json
    keep = out / "from_mac"
    kept = {p.name: p.read_bytes() for p in keep.iterdir()} if keep.is_dir() else {}
    if out.exists():
        shutil.rmtree(out)
    (out / "rejected").mkdir(parents=True)
    if kept:
        keep.mkdir()
        for name, data in kept.items():
            (keep / name).write_bytes(data)
    good = (ROOT / "tests/vectors/backup/v2/full.lgkfull").read_bytes()
    name = "full.lgkfull"
    inventory = recovery.BackupInventory(
        version=2, path=name, profile_name=PROFILE_NAME, entries=5, attachment_count=2, attachment_bytes=96,
        backup_bytes=len(good), backup_sha256=hashlib.sha256(good).hexdigest(), created_at=BACKUP_NOW,
        verified=True, verified_at=KIT_NOW, same_disk=False, warnings=(), manifest_path=name + ".sha256.json",
        recovery_phrase_enrolled=False)
    rejected = {}
    with tempfile.TemporaryDirectory() as tmp, mock.patch("localvault.recovery.time.time", return_value=KIT_NOW):
        backup = Path(tmp) / name
        backup.write_bytes(good)
        manifest = Path(tmp) / (name + ".sha256.json")
        atomic_write_json(manifest, recovery._manifest_payload(backup, inventory=inventory.as_dict()))
        kit = Path(tmp) / "recovery-kit.json"
        recovery.write_recovery_kit(kit, backup=backup, inventory=inventory, manifest_path=manifest,
                                    app_version=KIT_APP_VERSION)
        plain = Path(tmp) / "plain.sha256.json"
        atomic_write_json(plain, recovery._manifest_payload(backup))
        for source in (manifest, kit, plain):
            (out / source.name).write_bytes(source.read_bytes())
        base = json.loads(manifest.read_text(encoding="utf-8"))

        def variant(label: str, change) -> None:
            value = json.loads(json.dumps(base))
            change(value)
            target = out / "rejected" / f"{label}.sha256.json"
            target.write_text(newline="\n", data=json.dumps(value, separators=(",", ":"), sort_keys=True), encoding="utf-8")
            probe = Path(tmp) / (name + ".sha256.json")
            probe.write_bytes(target.read_bytes())
            try:
                recovery.verify_sha256_manifest(backup, probe)
            except recovery.RecoveryError as exc:
                rejected[target.name] = str(exc)
            else:
                raise AssertionError(label)

        variant("wrong_format", lambda v: v.update(format="something-else"))
        variant("wrong_version", lambda v: v.update(version=2))
        variant("other_backup", lambda v: v["backup"].update(name="other.lgkfull"))
        variant("wrong_size", lambda v: v["backup"].update(size=v["backup"]["size"] + 1))
        variant("wrong_digest", lambda v: v["backup"].update(sha256="0" * 64))
        variant("bad_digest", lambda v: v["backup"].update(sha256="xyz"))
        variant("no_size", lambda v: v["backup"].pop("size"))
        (out / "rejected" / "not_json.sha256.json").write_bytes(b"{not json")
        probe = Path(tmp) / (name + ".sha256.json")
        probe.write_bytes(b"{not json")
        try:
            recovery.verify_sha256_manifest(backup, probe)
        except recovery.RecoveryError as exc:
            rejected["not_json.sha256.json"] = str(exc)
    expected = {
        "backup": "tests/vectors/backup/v2/full.lgkfull",
        "backup_name": name,
        "generated_at": KIT_NOW,
        "app_version": KIT_APP_VERSION,
        "inventory": inventory.as_dict(),
        "restore_guide": recovery._default_restore_guide(),
        "same_password_message": "Use an independent backup password, not the vault master password",
        "rejected": rejected,
        "note": "TEST ONLY. full.lgkfull.sha256.json, recovery-kit.json and plain.sha256.json are Windows output.",
    }
    (out / "expected.json").write_text(newline="\n", data=json.dumps(expected, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
                                       encoding="utf-8")
    print(out)


# --------------------------------------------------------------------------- recovery phrase (Task 7)
RECOVERY_NOW = 1793000200


def _phrase_cases() -> dict:
    import random
    from localvault.vault import RecoveryPhraseError, entropy_from_phrase, phrase_from_entropy
    seeded = random.Random(7101)
    entropies = [bytes(32), b"\xff" * 32, b"\x7f" * 32, bytes(range(32))]
    entropies += [seeded.randbytes(32) for _ in range(8)]
    phrases = [{"entropy": e.hex(), "phrase": phrase_from_entropy(e)} for e in entropies]
    base = phrases[4]["phrase"]
    words = base.split()
    swapped = words[:]
    swapped[0], swapped[1] = swapped[1], swapped[0]
    if entropy_from_phrase_ok(swapped, entropy_from_phrase):
        swapped[2], swapped[3] = swapped[3], swapped[2]
    typed = {
        "extra spaces": "  " + "   ".join(words) + "  ",
        "tabs and newlines": "\t" + "\n".join(" ".join(words[i:i + 6]) for i in range(0, 24, 6)) + "\r\n",
        "capitals": " ".join(w.upper() if i % 2 else w.capitalize() for i, w in enumerate(words)),
        "fullwidth": " ".join("".join(chr(ord(c) + 0xFEE0) for c in w) if i == 0 else w for i, w in enumerate(words)),
        "non-breaking spaces": "\u00a0".join(words),
        "23 words": " ".join(words[:23]),
        "25 words": " ".join(words + words[:1]),
        "empty": "",
        "unknown word": " ".join(["notaword"] + words[1:]),
        "bad checksum": " ".join(swapped),
        "too long": " ".join(words) + " " * 2100,
    }
    cases = {}
    for name, text in typed.items():
        try:
            cases[name] = {"input": text, "entropy": entropy_from_phrase(text).hex()}
        except RecoveryPhraseError as exc:
            cases[name] = {"input": text, "error": str(exc)}
    return {"phrases": phrases, "typed": cases}


def entropy_from_phrase_ok(words, entropy_from_phrase) -> bool:
    from localvault.vault import RecoveryPhraseError
    try:
        entropy_from_phrase(" ".join(words))
        return True
    except RecoveryPhraseError:
        return False


def recovery_main(out: Path) -> None:
    import tempfile
    from localvault import vault as vault_module
    from localvault.vault import BIP39_ENGLISH_SHA256, RECOVERY_KEY_INFO, RECOVERY_WRAPPER_KIND, create_vault
    keep = out / "from_mac_vault.json"
    kept = keep.read_bytes() if keep.exists() else None
    out.mkdir(parents=True, exist_ok=True)
    doc = _phrase_cases()
    doc["word_list_sha256"] = BIP39_ENGLISH_SHA256
    (out / "phrases.json").write_text(newline="\n", data=json.dumps(doc, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
                                      encoding="utf-8")
    saved_binding = vault_module.UnlockThrottle.binding
    vault_module.UnlockThrottle.binding = lambda self: None
    try:
        with tempfile.TemporaryDirectory() as tmp, _Fixed(_SeededRandom(7102), RECOVERY_NOW):
            session = create_vault(Path(tmp) / "vault.json", MASTER_PASSWORD, kdf_overrides=CHEAP_KDF)
            try:
                session.create_web_login(urls=[{"url": "https://mail.example.com", "match": "exact_origin"}],
                                         username="alex@example.com", password="Correct-Horse-1", label="Mail")
                phrase = session.create_recovery_phrase(MASTER_PASSWORD)
                records = json.loads(json.dumps(list(session._require_payload()["entries"])))
            finally:
                session.lock()
            vault_text = (Path(tmp) / "vault.json").read_text(encoding="utf-8")
    finally:
        vault_module.UnlockThrottle.binding = saved_binding
    wrapper = {
        "kind": RECOVERY_WRAPPER_KIND,
        "hkdf_info": RECOVERY_KEY_INFO.decode(),
        "master_password": MASTER_PASSWORD,
        "phrase": phrase,
        "records": records,
        "vault": vault_text,
        "note": "TEST ONLY: the phrase and password here are published.",
    }
    (out / "wrapper.json").write_text(newline="\n", data=json.dumps(wrapper, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
                                      encoding="utf-8")
    if kept is not None:
        keep.write_bytes(kept)
    print(out)


SCHEDULE_TIMES = ("12:00", "00:00", "23:59", "8:05", "08:30")
SCHEDULE_NOWS = ("2026-10-26T11:59:59", "2026-10-26T12:00:00", "2026-10-26T12:00:01", "2026-10-25T00:00:00",
                 "2026-10-31T23:59:00", "2026-11-01T08:04:00", "2026-03-01T08:30:00", "2028-02-29T00:00:00")


def _schedule_cases() -> dict:
    import tempfile
    from datetime import datetime, timedelta

    from localvault import backup_schedule as bs

    def iso(value):
        return None if value is None else value.isoformat()

    slots, due = [], []
    for now_text in SCHEDULE_NOWS:
        now = datetime.fromisoformat(now_text)
        for frequency in ("off", "daily", "weekly", "monthly"):
            for time_of_day in SCHEDULE_TIMES:
                for weekday in (range(7) if frequency == "weekly" else (0,)):
                    slot = bs.latest_slot(now, frequency, time_of_day, weekday)
                    slots.append({"now": now_text, "frequency": frequency, "time": time_of_day, "weekday": weekday,
                                  "slot": iso(slot)})
                    if frequency == "monthly":
                        continue
                    lasts = [None, now + timedelta(minutes=1)]
                    if slot is not None:
                        lasts += [slot - timedelta(seconds=1), slot, slot + timedelta(seconds=1)]
                    for last in lasts:
                        due.append({"now": now_text, "last_success": iso(last), "frequency": frequency,
                                    "time": time_of_day, "weekday": weekday,
                                    "due": bs.is_due(now, last, frequency, time_of_day, weekday)})
    times = [{"value": v, "validated": bs.validated_time(v)}
             for v in ("12:00", "8:05", "08:5", "24:00", "23:59", " 07:30 ", "7.30", "", "1:2", "00:00", "19:60")]
    tags = [{"profile_id": pid, "tag": bs.profile_tag(pid)}
            for pid in ("default", "mac", "Ünïcode profile", "", "3f0e2c1a-0000-4000-8000-000000000001")]
    tag = bs.profile_tag("mac")
    filenames = [{"tag": tag, "when": w, "counter": c,
                  "filename": bs.scheduled_filename(tag, datetime.fromisoformat(w), c)}
                 for w, c in (("2026-10-26T12:00:00", 0), ("2026-10-26T12:00:00", 1), ("2026-01-02T03:04:05", 999))]
    bad_tags = []
    for bad in ("ABCDEF12", "abc", "abcdefg1", "../abcdef"):
        try:
            bs.scheduled_filename(bad, datetime(2026, 1, 1))
            bad_tags.append({"tag": bad, "error": None})
        except ValueError as exc:
            bad_tags.append({"tag": bad, "error": str(exc)})
    other = bs.profile_tag("default")
    listing = [
        f"LocalGateKeys-scheduled-{tag}-20261020-120000.lgk",
        f"LocalGateKeys-scheduled-{tag}-20261026-120000.lgk",
        f"LocalGateKeys-scheduled-{tag}-20261026-120000-1.lgk",
        f"LocalGateKeys-scheduled-{tag}-20261026-120000-12.lgk",
        f"LocalGateKeys-scheduled-{tag}-20261024-090000.LGK",
        f"localgatekeys-SCHEDULED-{tag}-20261023-090000.lgk",
        f"LocalGateKeys-scheduled-{tag}-20261022-090000-1234.lgk",
        f"LocalGateKeys-scheduled-{tag}-2026102-090000.lgk",
        f"LocalGateKeys-scheduled-{tag}-20261021-090000.lgk.sha256.json",
        f"LocalGateKeys-scheduled-{other}-20261027-120000.lgk",
        "LocalGateKeys-backup-2026-10-26-120000.lgk",
        "vault-20261026.json",
    ]
    prunes = []
    with tempfile.TemporaryDirectory() as tmp:
        folder = Path(tmp)
        for name in listing:
            (folder / name).write_bytes(b"x")
        (folder / f"LocalGateKeys-scheduled-{tag}-20261025-120000.lgk").mkdir()
        owned = [p.name for p in bs.owned_backups(folder, tag)]
        listing_all = sorted(p.name for p in folder.iterdir())
        for keep in (0, 1, 2, 3):
            for protect in (None, f"LocalGateKeys-scheduled-{tag}-20261020-120000.lgk"):
                with tempfile.TemporaryDirectory() as tmp2:
                    copy = Path(tmp2)
                    for name in listing:
                        (copy / name).write_bytes(b"x")
                    (copy / f"LocalGateKeys-scheduled-{tag}-20261025-120000.lgk").mkdir()
                    removed = bs.prune(copy, tag, keep, protect=(copy / protect) if protect else None)
                    prunes.append({"keep": keep, "protect": protect, "removed": sorted(p.name for p in removed),
                                   "left": sorted(p.name for p in copy.iterdir())})
    return {
        "constants": {"frequencies": list(bs.FREQUENCIES), "keep_choices": list(bs.KEEP_CHOICES),
                      "default_time": bs.DEFAULT_TIME, "weekdays": list(bs.WEEKDAYS),
                      "scheduled_dir": bs.SCHEDULED_DIR_NAME, "state_file": bs.STATE_FILENAME,
                      "min_password": bs.MIN_BACKUP_PASSWORD_LENGTH,
                      "retry_after_seconds": int(bs.RETRY_AFTER.total_seconds())},
        "slots": slots, "due": due, "times": times, "tags": tags, "filenames": filenames, "bad_tags": bad_tags,
        "listing": {"tag": tag, "names": listing_all, "directory": f"LocalGateKeys-scheduled-{tag}-20261025-120000.lgk",
                    "owned": owned},
        "prune": prunes,
        "state": {"when": "2026-10-26T12:00:00", "timestamp": datetime(2026, 10, 26, 12, 0, 0).timestamp()},
    }


def schedule_main(out: Path) -> None:
    out.mkdir(parents=True, exist_ok=True)
    doc = _schedule_cases()
    doc.pop("state")   # the timestamp depends on the generator's time zone
    (out / "schedule.json").write_text(newline="\n", data=json.dumps(doc, indent=1, sort_keys=True, ensure_ascii=False) + "\n",
                                       encoding="utf-8")
    print(out)


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "schedule":
        schedule_main(Path(sys.argv[2]) if len(sys.argv) > 2 else ROOT / "tests/vectors/backup/schedule")
    elif len(sys.argv) > 1 and sys.argv[1] == "recovery":
        recovery_main(Path(sys.argv[2]) if len(sys.argv) > 2 else ROOT / "tests/vectors/recovery")
    elif len(sys.argv) > 1 and sys.argv[1] == "kit":
        kit_main(Path(sys.argv[2]) if len(sys.argv) > 2 else ROOT / "tests/vectors/recovery/kit")
    elif len(sys.argv) > 1 and sys.argv[1] == "backup":
        backup_main(Path(sys.argv[2]) if len(sys.argv) > 2 else ROOT / "tests/vectors/backup/v2")
    else:
        main()
