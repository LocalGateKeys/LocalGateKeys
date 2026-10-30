"""Per-format import tests over the anonymised vendor fixtures in tests/fixtures/imports.

Each test detects the fixture by content, loads it with the format importer,
checks the field mapping into records and (for the richer formats) applies the
reviewed plan to a real vault so typed items, collections and secure-note
fallbacks are exercised end to end.
"""
from __future__ import annotations

import io
import shutil
import uuid
import zipfile
from pathlib import Path

import pytest

from localvault.import_workflow import (
    ImportWorkflowError,
    apply_import_plan,
    build_import_plan,
    plan_records,
)
from localvault.importers import (
    ImportedRecord,
    ImporterError,
    ImportFormatError,
    ImportPasswordRequired,
    card_expiry,
)
from localvault.importers.detect import detect_format, load_records
from localvault.vault import create_vault

FIXTURES = Path(__file__).parent / "fixtures" / "imports"
KDF = {"time_cost": 1, "memory_cost_kib": 8192, "parallelism": 1, "hash_len": 32}
MASTER = "fixture import master"
BITWARDEN_PASSWORD = "fixture export password"


@pytest.fixture
def workdir() -> Path:
    directory = Path(".n08-test-data") / uuid.uuid4().hex
    directory.mkdir(parents=True, exist_ok=False)
    yield directory
    shutil.rmtree(directory, ignore_errors=True)


@pytest.fixture
def session(workdir: Path):
    return create_vault(workdir / "vault.json", MASTER, kdf_overrides=KDF)


def _zip_dir(source: Path, target: Path) -> Path:
    with zipfile.ZipFile(target, "w", zipfile.ZIP_DEFLATED) as archive:
        for path in sorted(source.rglob("*")):
            if path.is_file():
                archive.write(path, path.relative_to(source).as_posix())
    return target


def _one_pux(workdir: Path) -> Path:
    target = workdir / "export.1pux"
    with zipfile.ZipFile(target, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("export.attributes", '{"version": 3, "description": "1Password Unencrypted Export"}')
        archive.write(FIXTURES / "onepassword" / "export.data", "export.data")
        archive.writestr("files/docid0000000000000000000001__lease.pdf", b"%PDF-1.4 fixture")
    return target


def _by_title(result) -> dict[str, ImportedRecord]:
    return {record.title: record for record in result.records}


def _items(session) -> dict[str, dict]:
    return {item["title"]: session.items.get_item(item["id"], include_protected=True)
            for item in session.items.list_items()}


def _collections(session) -> dict[str, str]:
    return {row["id"]: row["name"] for row in session.collections.list()}


# --------------------------------------------------------------------------- 1Password
def test_1pux_fixture_maps_every_category(workdir: Path):
    path = _one_pux(workdir)
    assert detect_format(path).format == "1pux"
    result = load_records(path)
    records = _by_title(result)
    assert "Deleted thing" not in records
    assert any("trash" in line for line in result.diagnostics)
    mail = records["Example Mail"]
    assert mail.kind == "login" and mail.username == "alex@example.com" and mail.password == "1p-login-pass-7Q"
    assert mail.urls == ["https://mail.example.com/login", "https://webmail.example.com"]
    assert "JBSWY3DPEHPK3PXP" in mail.totp_uri and mail.favorite and mail.folder == "Personal"
    assert {f["name"]: f["hidden"] for f in mail.custom_fields} == {"recovery email": False, "security answer": True}
    assert mail.tags == ["email", "personal"]
    card = records["Travel Visa"]
    assert card.kind == "card"
    assert card.card == {"cardholder": "ALEX EXAMPLE", "brand": "visa", "number": "4111 1111 1111 1111",
                         "cvv": "123", "expiry": "12/2027", "pin": "4321"}
    assert {f["name"] for f in card.custom_fields} == {"valid from", "issuing bank"}
    identity = records["Alex identity"]
    assert identity.identity["given_name"] == "Alex" and identity.identity["family_name"] == "Example"
    assert identity.identity["city"] == "Exampleton" and identity.identity["email"] == "alex@example.com"
    assert identity.identity["name"] == "Alex Q Example"
    api = records["Build API"]
    # API credentials have no website; the workflow keeps them as secure notes.
    assert not api.urls and any(f["name"] == "credential" and f["hidden"] for f in api.custom_fields)
    assert records["Old Forum"].folder == "Personal/Archive"
    assert any(f["name"] == "Attached file" for f in records["Lease scan"].custom_fields)
    assert records["Streaming"].folder == "Family"


def test_1pux_fixture_applies_typed_items_and_collections(session, workdir: Path):
    plan = build_import_plan(session, _one_pux(workdir))
    kinds = {row.label: row.kind for row in plan.rows}
    assert kinds["Example Mail"] == "login" and kinds["Travel Visa"] == "card" and kinds["Alex identity"] == "identity"
    assert kinds["Streaming"] == "login"  # bare host gets https://
    assert kinds["Old Forum"] == "login"  # http:// upgraded to https://
    assert any("http://" in issue and "https://" in issue for issue in plan.issues)
    plan.review()
    written = apply_import_plan(session, plan)
    assert written == len(plan.rows)
    mail = session.find_web("https://mail.example.com")[0]
    assert mail["password"] == "1p-login-pass-7Q" and mail["totp"]["secret"] == "JBSWY3DPEHPK3PXP"
    assert "Personal" in mail["tags"]
    urls = session.items.web_urls(mail["id"])
    assert [row["url"] for row in urls] == ["https://mail.example.com", "https://webmail.example.com",
                                           "https://mail.example.com/login"]
    assert [row["match"] for row in urls] == ["exact_origin", "exact_origin", "starts_with"]
    assert session.find_web("https://forum.example.net")[0]["password"] == "archived-pass-1"
    items = _items(session)
    card = items["Travel Visa"]
    assert card["kind"] == "card" and card["payload"]["number"] == "4111111111111111"
    assert card["payload"]["expiry"] == "12/27" and card["payload"]["cvv"] == "123" and card["payload"]["pin"] == "4321"
    assert card["payload"]["notes"] == "Travel card."
    extra = items["Travel Visa (extra details)"]
    assert {f["name"] for f in extra["payload"]["fields"]} == {"valid from", "issuing bank"}
    assert items["Alex identity"]["kind"] == "identity"
    names = _collections(session)
    assert names[card["collection_ids"][0]] == "Personal"


def test_1password_csv_fixture():
    path = FIXTURES / "onepassword.csv"
    assert detect_format(path).format == "1password-csv"
    records = _by_title(load_records(path))
    mail = records["Example Mail"]
    assert mail.favorite and mail.tags == ["email", "personal"] and "JBSWY3DPEHPK3PXP" in mail.totp_uri
    assert records["Old Forum"].folder == "Archive"
    assert records["Cabin notes"].kind == "note" and "neighbour" in records["Cabin notes"].notes


# --------------------------------------------------------------------------- Bitwarden
def test_bitwarden_json_fixture(session):
    path = FIXTURES / "bitwarden.json"
    assert detect_format(path).format == "bitwarden-json"
    result = load_records(path)
    records = _by_title(result)
    assert "Trashed login" not in records
    git = records["Example Git"]
    assert git.folder == "Work" and git.favorite and len(git.urls) == 3
    assert {f["name"]: (f["value"], f["hidden"]) for f in git.custom_fields} == {
        "Recovery code": ("rc-0000-1111", True), "Team": ("Platform", False), "Remember me": ("true", False)}
    assert any("passkey" in line for line in result.diagnostics)
    card = records["Everyday Mastercard"]
    assert card.card["expiry"] == "03/2029" and card.folder == "Finance/Cards"
    assert records["Deploy key"].kind == "note"
    assert any(f["name"] == "Private key" and f["hidden"] for f in records["Deploy key"].custom_fields)

    plan = plan_records(session, result.records, diagnostics=result.diagnostics)
    git_row = next(row for row in plan.rows if row.label == "Example Git")
    assert [row["url"] for row in git_row.web_urls] == ["https://git.example.com", "https://sso.example.com",
                                                       "https://git.example.com/login"]
    plan.review()
    apply_import_plan(session, plan)
    entry = session.find_web("https://git.example.com")[0]
    assert {f["name"] for f in entry["custom_fields"]} >= {"Recovery code", "Other website or app"}
    assert "Work" in entry["tags"]
    items = _items(session)
    assert items["Everyday Mastercard"]["payload"]["expiry"] == "03/29"
    assert _collections(session)[items["Everyday Mastercard"]["collection_ids"][0]] == "Finance/Cards"
    assert items["Home identity"]["payload"]["postal_code"] == "EX1 2PL"
    extra = items["Home identity (extra details)"]
    assert any(f["name"] == "Passport number" and f["hidden"] for f in extra["payload"]["fields"])
    assert extra["payload"]["body"] == "Use for deliveries."
    assert session.find_web("https://forum.example.net")[0]["password"] == "bw-forum-pass"


def test_bitwarden_password_protected_fixture():
    path = FIXTURES / "bitwarden_protected.json"
    detection = detect_format(path)
    assert detection.format == "bitwarden-encrypted-json" and detection.needs_password
    with pytest.raises(ImportPasswordRequired):
        load_records(path)
    with pytest.raises(ImporterError, match="Wrong password"):
        load_records(path, password="not the password")
    records = _by_title(load_records(path, password=BITWARDEN_PASSWORD))
    assert records["Example Git"].password == "bw-git-pass-3x"
    assert records["Everyday Mastercard"].card["number"] == "5555555555554444"


def test_bitwarden_account_restricted_export_is_refused_with_instructions():
    path = FIXTURES / "bitwarden_account_restricted.json"
    with pytest.raises(ImportFormatError, match="Password protected"):
        detect_format(path)
    with pytest.raises(ImportFormatError, match="account key"):
        load_records(path, source_format="bitwarden-json")


def test_bitwarden_csv_fixture():
    path = FIXTURES / "bitwarden.csv"
    assert detect_format(path).format == "bitwarden-csv"
    records = _by_title(load_records(path))
    git = records["Example Git"]
    assert git.urls == ["https://git.example.com/login", "https://sso.example.com"]
    assert {f["name"] for f in git.custom_fields} == {"Team", "Recovery code"}
    assert records["Router admin"].kind == "note"
    assert records["Example Shop"].urls == ["shop.example.com"]


# --------------------------------------------------------------------------- LastPass
def test_lastpass_csv_fixture(session):
    path = FIXTURES / "lastpass.csv"
    assert detect_format(path).format == "lastpass-csv"
    result = load_records(path)
    records = _by_title(result)
    bank = records["Example Bank"]
    assert bank.folder == "Finance/Banking" and bank.favorite and "JBSWY3DPEHPK3PXP" in bank.totp_uri
    card = records["Travel Visa"]
    assert card.kind == "card" and card.card["expiry"] == "12/2027" and card.card["cardholder"] == "Alex Example"
    assert card.notes == "Travel card."
    address = records["Home address"]
    assert address.kind == "identity" and address.identity["postal_code"] == "EX1 2PL"
    licence = records["Editor licence"]
    assert licence.kind == "note" and any(f["name"] == "License Key" for f in licence.custom_fields)
    plan = plan_records(session, result.records)
    plan.review()
    apply_import_plan(session, plan)
    items = _items(session)
    assert items["Travel Visa"]["kind"] == "card" and items["Router note"]["kind"] == "note"
    assert session.find_web("https://intranet.example.org")[0]["password"] == "lp-intranet-pass"


# --------------------------------------------------------------------------- browsers
def test_chrome_csv_fixture_keeps_app_logins_and_differing_duplicates(session):
    path = FIXTURES / "chrome.csv"
    assert detect_format(path).format == "chrome-csv"
    plan = build_import_plan(session, path)
    rows = {row.row: row for row in plan.rows}
    assert rows[2].kind == "login" and rows[2].record.notes == "Main account"
    assert rows[4].status == "duplicate" and rows[4].decision == "keep_both"
    assert rows[5].kind == "note"  # android:// app login kept as a secure note
    assert rows[6].kind == "login" and rows[6].origin == "https://192.168.1.1"  # http:// upgraded, reported
    plan.review()
    apply_import_plan(session, plan)
    items = _items(session)
    copy = items["shop.example.com (imported copy)"]
    assert any(f["name"] == "Password" and f["value"] == "chrome-pass-2-new" for f in copy["payload"]["fields"])
    assert session.find_web("https://shop.example.com")[0]["password"] == "chrome-pass-2"


def test_edge_legacy_and_safari_csv_fixtures():
    edge = load_records(FIXTURES / "edge_legacy.csv")
    assert edge.source_format == "chrome-csv" and edge.records[0].username == "reader01"
    safari = load_records(FIXTURES / "safari.csv")
    assert safari.source_format == "safari-csv" and "JBSWY3DPEHPK3PXP" in safari.records[0].totp_uri


def test_firefox_csv_fixture():
    path = FIXTURES / "firefox.csv"
    assert detect_format(path).format == "firefox-csv"
    records = load_records(path).records
    assert [record.username for record in records] == ["alex@example.com", "alex", "proxyuser"]
    assert records[0].created == 1700000000 and records[0].modified == 1700400000
    assert records[0].title == "login.example.com"


# --------------------------------------------------------------------------- KeePass
def test_keepass_xml_fixture(session):
    path = FIXTURES / "keepass.xml"
    assert detect_format(path).format == "keepass-xml"
    result = load_records(path)
    records = _by_title(result)
    assert "Deleted login" not in records
    bank = records["Example Bank"]
    assert bank.password == "kpxml-pass-1" and "JBSWY3DPEHPK3PXP" in bank.totp_uri and bank.tags == ["finance", "important"]
    assert {f["name"]: f["hidden"] for f in bank.custom_fields} == {"Customer number": False, "Telephone PIN": True}
    assert records["Ticket system"].folder == "Work" and records["Door code"].kind == "note"
    assert any("Recycle Bin" in line for line in result.diagnostics)
    assert any("attachments" in line for line in result.diagnostics)
    plan = plan_records(session, result.records)
    plan.review()
    apply_import_plan(session, plan)
    assert _collections(session)[_items(session)["Door code"]["collection_ids"][0]] == "Work"


def test_keepass_csv_fixtures():
    kpxc = _by_title(load_records(FIXTURES / "keepassxc.csv"))
    assert kpxc["VPN"].folder == "Work" and "JBSWY3DPEHPK3PXP" in kpxc["VPN"].totp_uri
    assert kpxc["Safe combination"].kind == "note" and kpxc["Safe combination"].folder == "Notes"
    kp2 = load_records(FIXTURES / "keepass2.csv")
    assert kp2.source_format == "keepass-csv" and kp2.records[0].notes == "Joined 2019"


# --------------------------------------------------------------------------- Proton Pass
def test_protonpass_zip_fixture(session, workdir: Path):
    path = _zip_dir(FIXTURES / "protonpass", workdir / "Proton Pass_export.zip")
    assert detect_format(path).format == "protonpass-json"
    result = load_records(path)
    records = _by_title(result)
    assert "Trashed login" not in records and any("trash" in line for line in result.diagnostics)
    social = records["Example Social"]
    assert social.username == "alex_example" and social.password == "proton-pass-1" and social.favorite
    assert "JBSWY3DPEHPK3PXP" in social.totp_uri and len(social.urls) == 2 and social.folder == "Personal"
    fields = {f["name"]: f for f in social.custom_fields}
    assert fields["Email"]["value"] == "alex@example.com" and fields["Backup codes"]["hidden"]
    assert fields["Second factor"]["hidden"] and "Passkeys" in fields
    assert records["Legacy shop"].username == "alex@example.com"
    card = records["Shopping Visa"]
    assert card.card == {"cardholder": "Alex Example", "number": "4111111111111111", "cvv": "456", "pin": "9876",
                         "expiry": "09/2028"}
    identity = records["Alex (personal)"]
    assert identity.identity["name"] == "Alex Q Example" and identity.identity["organization"] == "Example Ltd"
    assert {f["name"] for f in identity.custom_fields} >= {"Social security number", "Gym number", "workEmail"}
    assert records["Newsletter alias"].kind == "note"
    assert records["Office Wi-Fi"].folder == "Work"

    plan = build_import_plan(session, path)
    plan.review()
    apply_import_plan(session, plan)
    items = _items(session)
    assert items["Shopping Visa"]["payload"]["expiry"] == "09/28"
    wifi = items["Office Wi-Fi"]
    assert any(f["name"] == "Wi-Fi password" and f["hidden"] for f in wifi["payload"]["fields"])
    assert _collections(session)[wifi["collection_ids"][0]] == "Work"


def test_protonpass_csv_fixture():
    path = FIXTURES / "protonpass.csv"
    assert detect_format(path).format == "protonpass-csv"
    result = load_records(path)
    records = _by_title(result)
    social = records["Example Social"]
    assert social.urls == ["https://social.example.com/login", "https://m.social.example.com"]
    assert social.folder == "Personal" and social.created == 1700000000
    assert records["Newsletter alias"].kind == "note"
    assert any("creditcard" in line for line in result.diagnostics)


def test_protonpass_pgp_export_is_refused_with_instructions(workdir: Path):
    path = workdir / "proton.zip"
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("Proton Pass/data.pgp", b"-----BEGIN PGP MESSAGE-----\nfixture\n-----END PGP MESSAGE-----\n")
    with pytest.raises(ImportFormatError, match="Encrypt with PGP"):
        detect_format(path)
    with pytest.raises(ImportFormatError, match="PGP"):
        load_records(path, source_format="protonpass-json")
    armored = workdir / "data.pgp"
    armored.write_bytes(b"-----BEGIN PGP MESSAGE-----\nfixture\n")
    with pytest.raises(ImportFormatError, match="PGP"):
        detect_format(armored)


# --------------------------------------------------------------------------- Dashlane
def test_dashlane_zip_fixture(session, workdir: Path):
    path = _zip_dir(FIXTURES / "dashlane", workdir / "dashlane-export.zip")
    assert detect_format(path).format == "dashlane-zip"
    result = load_records(path)
    records = _by_title(result)
    travel = records["Example Travel"]
    assert travel.folder == "Travel" and "JBSWY3DPEHPK3PXP" in travel.totp_uri
    assert travel.custom_fields == [{"name": "Alternative username", "value": "alex_example", "hidden": False}]
    assert records["Spare key"].kind == "note"
    card = records["Groceries Mastercard"]
    assert card.kind == "card" and card.card["expiry"] == "11/2030" and card.card["cvv"] == "777"
    bank = records["Joint account"]
    assert bank.kind == "note" and any(f["name"] == "Account number" and f["hidden"] for f in bank.custom_fields)
    assert records["Passport - Alex Example"].kind == "note"
    assert records["Me"].identity["given_name"] == "Alex" and records["Home"].identity["postal_code"] == "EX1 2PL"

    plan = build_import_plan(session, path)
    plan.review()
    apply_import_plan(session, plan)
    items = _items(session)
    assert items["Groceries Mastercard"]["payload"]["number"] == "5555555555554444"
    assert session.find_web("https://video.example.com")[0]["password"] == "dash-pass-2"


def test_dashlane_single_csv_files():
    assert detect_format(FIXTURES / "dashlane" / "credentials.csv").format == "dashlane-csv"
    assert detect_format(FIXTURES / "dashlane" / "payments.csv").format == "dashlane-csv"
    assert detect_format(FIXTURES / "dashlane" / "personalInfo.csv").format == "dashlane-csv"
    payments = load_records(FIXTURES / "dashlane" / "payments.csv")
    assert [record.kind for record in payments.records] == ["card", "note"]


# --------------------------------------------------------------------------- cross-format behaviour
def test_card_expiry_normalisation():
    assert card_expiry("3", "2029") == "03/2029"
    assert card_expiry("December", "2027") == "12/2027"
    assert card_expiry("December,2027") == "12/2027"
    assert card_expiry("2028-09") == "09/2028"
    assert card_expiry("202712") == "12/2027"
    assert card_expiry("01/27") == "01/2027"
    assert card_expiry("13", "2027") == "" and card_expiry("soon") == ""


def test_invalid_card_falls_back_to_a_secure_note(session):
    record = ImportedRecord(kind="card", title="Broken", card={"number": "4111111111111112", "cvv": "12"},
                            custom_fields=[{"name": "Bank", "value": "Example", "hidden": False}])
    plan = plan_records(session, [record])
    assert plan.rows[0].kind == "note" and any("checksum" in issue for issue in plan.issues)
    plan.review()
    apply_import_plan(session, plan)
    note = _items(session)["Broken"]
    assert {f["name"]: f["hidden"] for f in note["payload"]["fields"]} == {"Card number": True,
                                                                           "Security code": True, "Bank": False}


def test_long_notes_overflow_into_fields_instead_of_failing(session):
    record = ImportedRecord(kind="login", title="Long", username="u", password="p", urls=["https://long.example.com"],
                            notes="x" * 25_000)
    plan = plan_records(session, [record])
    plan.review()
    apply_import_plan(session, plan)
    entry = session.find_web("https://long.example.com")[0]
    assert len(entry["notes"]) == 20_000
    assert sum(len(f["value"]) for f in entry["custom_fields"] if f["name"].startswith("Notes (continued")) == 5_000


def test_keep_both_on_a_vault_conflict(session):
    session.upsert_web(origin="https://example.com", username="alex", password="vault-pass")
    record = ImportedRecord(kind="login", title="Example", username="alex", password="import-pass",
                            urls=["https://example.com"])
    plan = plan_records(session, [record])
    row = plan.rows[0]
    assert row.status == "conflict" and row.decision == "skip"
    with pytest.raises(ImportWorkflowError):
        plan.set_decision(row, "add")
    plan.set_decision(row, "keep_both")
    assert plan.summary()["keep_both"] == 1
    plan.review()
    assert apply_import_plan(session, plan) == 1
    assert session.find_web("https://example.com")[0]["password"] == "vault-pass"
    copy = _items(session)["Example (imported copy)"]
    assert {f["name"]: f["value"] for f in copy["payload"]["fields"]}["Password"] == "import-pass"


def test_keep_both_and_merge_for_catalog_items(session):
    session.items.create_note("Memo", "old body")
    plan = plan_records(session, [ImportedRecord(kind="note", title="Memo", notes="new body")])
    assert plan.rows[0].status == "conflict"
    plan.set_all("keep_both", statuses=("conflict",))
    plan.review()
    apply_import_plan(session, plan)
    bodies = sorted(item["payload"]["body"] for item in _items_list(session))
    assert bodies == ["new body", "old body"]


def _items_list(session) -> list[dict]:
    return [session.items.get_item(item["id"], include_protected=True) for item in session.items.list_items()]


def test_existing_collection_is_reused(session):
    collection_id = session.collections.create("Work")
    plan = plan_records(session, [ImportedRecord(kind="note", title="A", notes="a", folder="work"),
                                  ImportedRecord(kind="note", title="B", notes="b", folder="Work")])
    plan.review()
    apply_import_plan(session, plan)
    assert [item["collection_ids"] for item in _items_list(session)] == [[collection_id], [collection_id]]
    assert len(session.collections.list()) == 1


@pytest.mark.parametrize("name", ["chrome.csv", "bitwarden.json", "lastpass.csv", "keepass.xml", "protonpass.csv"])
def test_fixture_secrets_never_reach_repr(name):
    result = load_records(FIXTURES / name)
    text = repr(result.records)
    for record in result.records:
        if record.password:
            assert record.password not in text
        for key in ("number", "cvv", "pin"):
            if record.card.get(key):
                assert record.card[key] not in text


def test_unsupported_and_damaged_files_get_friendly_errors(workdir: Path):
    cases = {
        "export.1pif": b'{"uuid": "x"}\n***5642bee8-a5ff-11dc-8314-0800200c9a66***\n',
        "random.zip": _zip_bytes({"readme.txt": b"hello"}),
        "other.json": b'{"hello": "world"}',
        "empty.csv": b"",
        "binary.bin": bytes(range(256)) * 4,
    }
    for name, data in cases.items():
        path = workdir / name
        path.write_bytes(data)
        with pytest.raises(ImporterError) as caught:
            detect_format(path)
        message = str(caught.value)
        assert message and "Traceback" not in message and len(message) < 400


def _zip_bytes(members: dict[str, bytes]) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        for name, data in members.items():
            archive.writestr(name, data)
    return buffer.getvalue()


def test_size_bounds_are_enforced(workdir: Path):
    big = workdir / "big.csv"
    big.write_bytes(b"name,url,username,password\n" + b"a,https://a.example.com,u,p\n" * 400_000)
    with pytest.raises(ImporterError, match="MiB"):
        load_records(big, source_format="chrome-csv")
    many = workdir / "many.csv"
    many.write_text("name,url,username,password\n" + "".join(
        f"n{i},https://s{i}.example.com,u,p\n" for i in range(5_001)), encoding="utf-8")
    with pytest.raises(ImporterError, match="5,000"):
        load_records(many)
