"""Property tests for the importers (src/localvault/importers/*).

Every format gets a structured template that is randomly corrupted (type swaps,
deletions, huge/odd values, deep nesting) and is loaded through the public
``detect.load_records`` path both with the forced format and with detection.

Invariants: only ``ImporterError`` subclasses escape; records are well formed
(``kind`` in RECORD_KINDS, strings where strings are expected, <= MAX_RECORDS);
each load finishes within a time bound; no file is written outside the scratch
data folder (audit hook in conftest).
"""
from __future__ import annotations

import copy
import io
import json
import os
import time
import zipfile

import pytest
from hypothesis import given, note
from hypothesis import strategies as st

from localvault.importers import MAX_RECORDS, RECORD_KINDS, ImportedRecord, ImporterError, detect
from localvault.importers.kdbx import write_kdbx

TIME_BOUND = float(os.environ.get("LGK_IMPORT_TIME_BOUND", "20"))

odd_scalar = st.one_of(
    st.none(), st.booleans(), st.integers(-2**64, 2**64), st.floats(allow_nan=True, allow_infinity=True),
    st.text(max_size=30), st.sampled_from(["", "2.", "otpauth://totp/x?secret=", "otpauth://hotp/a?secret=AAAA&counter=-1",
                                           "https://", "javascript:alert(1)", "\x00", "\ud800".encode("utf-16", "surrogatepass").decode("utf-16", "replace"),
                                           "9" * 400, "1e309", "-1", "2027-13", "0000-00-00T00:00:00"]))
odd_value = st.recursive(odd_scalar, lambda inner: st.one_of(st.lists(inner, max_size=3),
                                                            st.dictionaries(st.text(max_size=12), inner, max_size=3)),
                         max_leaves=10)

BITWARDEN = {"encrypted": False, "folders": [{"id": "f1", "name": "Folder"}], "items": [
    {"id": "i1", "type": 1, "name": "Login", "folderId": "f1", "favorite": True, "notes": "n",
     "login": {"username": "u", "password": "p", "totp": "JBSWY3DPEHPK3PXP",
               "uris": [{"uri": "https://a.example", "match": None}], "fido2Credentials": []},
     "fields": [{"name": "pin", "value": "1", "type": 1}], "creationDate": "2024-01-01T00:00:00.000Z",
     "revisionDate": "2024-01-01T00:00:00.000Z"},
    {"id": "i2", "type": 3, "name": "Card", "card": {"cardholderName": "A", "number": "4111111111111111",
                                                     "expMonth": "1", "expYear": "2030", "code": "123", "brand": "Visa"}},
    {"id": "i3", "type": 4, "name": "Id", "identity": {"firstName": "A", "ssn": "1", "passportNumber": "2"}},
    {"id": "i4", "type": 2, "name": "Note", "secureNote": {"type": 0}, "notes": "body"}]}
ONEPUX = {"accounts": [{"attrs": {"name": "acc"}, "vaults": [{"attrs": {"name": "V"}, "items": [
    {"uuid": "x", "state": "active", "favIndex": 1, "categoryUuid": "001", "createdAt": 1700000000, "updatedAt": 1700000001,
     "overview": {"title": "t", "url": "https://a.example", "urls": [{"url": "https://b.example"}], "tags": ["t"]},
     "details": {"loginFields": [{"designation": "username", "value": "u"}, {"designation": "password", "value": "p"}],
                 "notesPlain": "n", "password": "p",
                 "sections": [{"title": "s", "fields": [
                     {"title": "one-time password", "value": {"totp": "otpauth://totp/x?secret=JBSWY3DP"}},
                     {"title": "cc", "value": {"creditCardNumber": "4111"}},
                     {"title": "exp", "value": {"monthYear": 202701}},
                     {"title": "addr", "value": {"address": {"street": "s", "city": "c"}}}]}]}},
    {"uuid": "y", "state": "archived", "categoryUuid": "002", "overview": {"title": "card"}, "details": {}}]}]}]}
PROTON = {"version": "1.0", "userId": "u", "encrypted": False, "vaults": {"v1": {"name": "V", "items": [
    {"itemId": "i", "state": 1, "createTime": 1700000000, "modifyTime": 1700000000, "pinned": True,
     "data": {"metadata": {"name": "n", "note": "x"}, "type": "login",
              "content": {"itemEmail": "e@x", "itemUsername": "u", "password": "p", "urls": ["https://a.example"],
                          "totpUri": "otpauth://totp/x?secret=JBSWY3DP", "passkeys": []},
              "extraFields": [{"fieldName": "f", "type": "hidden", "data": {"content": "c"}}]}},
    {"itemId": "c", "state": 1, "data": {"metadata": {"name": "card"}, "type": "creditCard",
                                         "content": {"cardholderName": "A", "number": "4111", "expirationDate": "2027-01",
                                                     "verificationNumber": "1"}}},
    {"itemId": "d", "state": 2, "data": {"metadata": {"name": "id"}, "type": "identity", "content": {"fullName": "A B"}}}]}}}

CSV_COLUMNS = ["name", "url", "username", "password", "note", "notes", "title", "URL", "Username", "Password", "Notes",
               "OTPAuth", "folder", "favorite", "type", "fields", "reprompt", "login_uri", "login_username",
               "login_password", "login_totp", "extra", "grouping", "fav", "totp", "httpRealm", "formActionOrigin",
               "guid", "timeCreated", "timeLastUsed", "timePasswordChanged", "Group", "Account", "Login Name",
               "Web Site", "Comments", "email", "vault", "createTime", "modifyTime", "otpSecret", "category",
               "cc_number", "code", "expiration_month", "expiration_year", "Title", "Group Tree"]
csv_cell = st.one_of(st.text(max_size=20), st.sampled_from(['"', '""', '"a,b"', "a\nb", "=cmd|' /c calc'!A0", "\x00",
                                                            "https://a.example", "otpauth://totp/a?secret=AAAA", "true",
                                                            "1700000000", "9" * 30, "2027-01", "\r", ";", "\t"]))


def _corrupt(draw, doc, rounds):
    doc = copy.deepcopy(doc)
    for _ in range(rounds):
        paths = []

        def walk(node, path, paths=paths):
            paths.append(path)
            if isinstance(node, dict):
                for k, v in node.items():
                    walk(v, path + (k,), paths)
            elif isinstance(node, list):
                for i, v in enumerate(node):
                    walk(v, path + (i,), paths)
        walk(doc, ())
        path = draw(st.sampled_from(paths))
        if not path:
            continue
        parent = doc
        for key in path[:-1]:
            parent = parent[key]
        op = draw(st.sampled_from(["replace", "replace", "delete", "dup"]))
        if op == "replace":
            parent[path[-1]] = draw(odd_value)
        elif op == "delete":
            del parent[path[-1]]
        elif isinstance(parent, list):
            parent.extend([copy.deepcopy(parent[path[-1]])] * draw(st.integers(1, 3)))
    return doc


def _zip(members: dict[str, bytes], method=zipfile.ZIP_DEFLATED) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", method) as z:
        for name, data in members.items():
            z.writestr(name, data)
    return buf.getvalue()


_CACHE: dict = {}


def _bw_encrypted():
    # Generated once: the envelope uses random salts/IVs, and Hypothesis needs
    # identical bytes for identical draws (otherwise FlakyStrategyDefinition).
    if "bw" not in _CACHE:
        from localvault.importers.bitwarden import encrypt_bitwarden_export
        _CACHE["bw"] = encrypt_bitwarden_export(BITWARDEN, "pw-123456789", iterations=1000)
    return _CACHE["bw"]


_KDBX_RECORDS = [ImportedRecord(title="t", username="u", password="p", urls=["https://a.example"],
                                totp_uri="otpauth://totp/x?secret=JBSWY3DP")]


def _kdbx(version, kdf, compress):
    key = ("kdbx", version, kdf, compress)
    if key not in _CACHE:
        _CACHE[key] = write_kdbx(_KDBX_RECORDS, "pw", version=version, kdf=kdf,
                                 kdf_params={"rounds": 100, "memory": 8 * 1024 * 1024, "iterations": 1,
                                             "parallelism": 1}, compress=compress)
    return _CACHE[key]


@st.composite
def source(draw):
    fmt = draw(st.sampled_from(["bitwarden-json", "1pux", "protonpass-json", "protonpass-zip", "csv", "keepass-xml",
                                "dashlane-zip", "kdbx", "bitwarden-encrypted-json", "raw"]))
    rounds = draw(st.integers(0, 6))
    if fmt == "bitwarden-json":
        return fmt, "bitwarden-json", ".json", json.dumps(_corrupt(draw, BITWARDEN, rounds)).encode(), None
    if fmt == "bitwarden-encrypted-json":
        doc = _bw_encrypted()
        return fmt, fmt, ".json", json.dumps(_corrupt(draw, doc, rounds)).encode(), "pw-123456789"
    if fmt == "1pux":
        data = json.dumps(_corrupt(draw, ONEPUX, rounds)).encode()
        return fmt, "1pux", ".1pux", _zip({"export.attributes": b"{}", "export.data": data}), None
    if fmt in ("protonpass-json", "protonpass-zip"):
        data = json.dumps(_corrupt(draw, PROTON, rounds)).encode()
        if fmt == "protonpass-zip":
            return fmt, "protonpass-json", ".zip", _zip({"Proton Pass/data.json": data}), None
        return fmt, "protonpass-json", ".json", data, None
    if fmt in ("csv", "dashlane-zip"):
        header = draw(st.lists(st.sampled_from(CSV_COLUMNS), min_size=1, max_size=8))
        rows = draw(st.lists(st.lists(csv_cell, max_size=10), max_size=6))
        import csv as _csv
        buf = io.StringIO()
        w = _csv.writer(buf, delimiter=draw(st.sampled_from([",", ";", "\t"])))
        w.writerow(header)
        w.writerows(rows)
        text = buf.getvalue().encode(draw(st.sampled_from(["utf-8", "utf-8-sig", "utf-16"])), "surrogatepass")
        if fmt == "dashlane-zip":
            return fmt, "dashlane-zip", ".zip", _zip({draw(st.sampled_from(["credentials.csv", "x/securenotes.csv",
                                                                           "payments.csv", "ids.csv",
                                                                           "personalInfo.csv"])): text}), None
        forced = draw(st.sampled_from(sorted(detect.CSV_FORMATS)))
        return fmt, forced, ".csv", text, None
    if fmt == "keepass-xml":
        title = draw(odd_scalar)
        xml = ("<KeePassFile><Meta><Generator>x</Generator></Meta><Root><Group><Name>G</Name>"
               + "".join(f"<Entry><UUID>AAAAAAAAAAAAAAAAAAAAAA==</UUID><String><Key>{k}</Key><Value>{v}</Value></String></Entry>"
                         for k, v in draw(st.lists(st.tuples(st.sampled_from(["Title", "UserName", "Password", "URL",
                                                                              "Notes", "otp", "TimeOtp-Secret-Base32", "X"]),
                                                             st.text(alphabet=st.characters(codec="utf-8",
                                                                                            exclude_characters="<&"),
                                                                     max_size=20)), max_size=5)))
               + f"<Entry><String><Key>Title</Key><Value>{json.dumps(title)[:20].replace('<', '').replace('&', '')}</Value></String></Entry>"
               + "</Group></Root></KeePassFile>")
        data = xml.encode()
        if draw(st.booleans()):
            pos = draw(st.integers(0, len(data)))
            data = data[:pos] + draw(st.binary(max_size=6)) + data[pos:]
        return fmt, "keepass-xml", ".xml", data, None
    if fmt == "kdbx":
        version = draw(st.sampled_from([3, 4]))
        kdf = "aes-kdf" if version == 3 else draw(st.sampled_from(["aes-kdf", "argon2id"]))
        data = _kdbx(version, kdf, draw(st.booleans()))
        buf = bytearray(data)
        for _ in range(draw(st.integers(0, 3))):
            if not buf:
                break
            op = draw(st.sampled_from(["flip", "trunc", "insert"]))
            pos = draw(st.integers(0, len(buf) - 1))
            if op == "flip":
                buf[pos] ^= 1 << draw(st.integers(0, 7))
            elif op == "trunc":
                del buf[pos:]
            else:
                buf[pos:pos] = draw(st.binary(min_size=1, max_size=8))
        return fmt, "kdbx", ".kdbx", bytes(buf), "pw"
    return fmt, None, draw(st.sampled_from([".json", ".csv", ".zip", ".xml", ".kdbx", ".1pux", ""])), draw(
        st.binary(max_size=300)), None


def _check_records(result):
    assert len(result.records) <= MAX_RECORDS
    for r in result.records:
        assert r.kind in RECORD_KINDS
        for name in ("title", "username", "password", "notes", "totp_uri", "folder"):
            assert isinstance(getattr(r, name), str), (name, type(getattr(r, name)))
        assert all(isinstance(u, str) for u in r.urls)
        assert all(isinstance(t, str) for t in r.tags)
        assert r.created is None or isinstance(r.created, int)
        assert r.modified is None or isinstance(r.modified, int)


_counter = [0]


@given(source(), st.booleans())
def test_importers_fail_closed(scratch, write_audit, src, use_detection):
    label, fmt, suffix, data, password = src
    _counter[0] += 1
    path = scratch / f"imp{_counter[0]}{suffix}"
    path.write_bytes(data)
    note(f"{label} forced={fmt} detect={use_detection} {len(data)} bytes")
    started = time.perf_counter()
    try:
        result = detect.load_records(path, password=password, source_format=None if use_detection or fmt is None else fmt)
    except ImporterError:
        result = None
    finally:
        elapsed = time.perf_counter() - started
        path.unlink(missing_ok=True)
    assert elapsed < TIME_BOUND, f"{label} took {elapsed:.1f}s"
    assert not write_audit.violations, write_audit.violations
    if result is not None:
        _check_records(result)


# ---------------------------------------------------------------- explicit hostile inputs
BILLION_LAUGHS = b"""<?xml version="1.0"?><!DOCTYPE lolz [<!ENTITY lol "lol"><!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
<!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;"><!ENTITY lol4 "&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;">
<!ENTITY lol5 "&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;"><!ENTITY lol6 "&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;">
<!ENTITY lol7 "&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;"><!ENTITY lol8 "&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;">
<!ENTITY lol9 "&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;">]>
<KeePassFile><Root><Group><Entry><String><Key>Title</Key><Value>&lol9;</Value></String></Entry></Group></Root></KeePassFile>"""
XXE = b"""<?xml version="1.0"?><!DOCTYPE x [<!ENTITY e SYSTEM "file:///C:/Windows/win.ini">]>
<KeePassFile><Root><Group><Entry><String><Key>Title</Key><Value>&e;</Value></String></Entry></Group></Root></KeePassFile>"""


def _bomb_zip(name: str) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as z:
        z.writestr(name, b"[" + b" " * (200 * 1024 * 1024) + b"]")
    return buf.getvalue()


def _lying_zip(name: str, payload: bytes) -> bytes:
    """A member whose central-directory file_size claims 10 bytes but whose stream is larger."""
    data = bytearray(_zip({name: payload}, zipfile.ZIP_STORED))
    cd = data.rfind(b"PK\x01\x02")
    data[cd + 24:cd + 28] = (10).to_bytes(4, "little")  # uncompressed size in the central directory
    return bytes(data)


@pytest.mark.parametrize("label,fmt,suffix,data", [
    ("billion-laughs", "keepass-xml", ".xml", BILLION_LAUGHS),
    ("xxe", "keepass-xml", ".xml", XXE),
    ("deep-json-bitwarden", "bitwarden-json", ".json", b"[" * 200000),
    ("deep-json-proton", "protonpass-json", ".json", b'{"a":' * 100000),
    ("bomb-1pux", "1pux", ".1pux", None),
    ("bomb-proton", "protonpass-json", ".zip", None),
    ("bomb-dashlane", "dashlane-zip", ".zip", None),
    ("lying-size-1pux", "1pux", ".1pux", _lying_zip("export.data", b"{" + b" " * 100 + b"}")),
    ("traversal-dashlane", "dashlane-zip", ".zip", _zip({"../../credentials.csv": b"title,password\nx,y\n"})),
    ("bw-inf-iterations", "bitwarden-encrypted-json", ".json",
     b'{"encrypted":true,"passwordProtected":true,"salt":"c2FsdA==","kdfType":0,"kdfIterations":Infinity,"data":"2.x"}'),
    ("bw-argon-huge", "bitwarden-encrypted-json", ".json",
     b'{"encrypted":true,"passwordProtected":true,"salt":"c2FsdA==","kdfType":1,"kdfIterations":11,"kdfMemory":2048,"data":"2.x"}'),
], ids=lambda value: value if isinstance(value, str) and len(value) < 40 else "")
def test_hostile_inputs(scratch, write_audit, label, fmt, suffix, data):
    if data is None:
        data = _bomb_zip({"bomb-1pux": "export.data", "bomb-proton": "Proton Pass/data.json",
                          "bomb-dashlane": "credentials.csv"}[label])
    path = scratch / f"hostile-{label}{suffix}"
    path.write_bytes(data)
    started = time.perf_counter()
    try:
        result = detect.load_records(path, password="pw-123456789", source_format=fmt)
    except ImporterError:
        result = None
    elapsed = time.perf_counter() - started
    assert elapsed < TIME_BOUND, elapsed
    assert not write_audit.violations
    if result is not None:
        _check_records(result)
        if label == "xxe":
            assert all("[fonts]" not in r.title.lower() and "for 16-bit" not in r.title for r in result.records)
