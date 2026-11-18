"""Exports carry every item kind the formats can hold and count what they leave out."""
from __future__ import annotations

import csv
import io
import json

import pytest

from localvault.export import export_coverage, export_csv, export_json, export_keepass_xml
from localvault.importers.bitwarden import load_bitwarden_csv
from localvault.vault import create_vault

KDF = {"time_cost": 1, "memory_cost_kib": 8192, "parallelism": 1, "hash_len": 32}
KEY = "-----BEGIN OPENSSH PRIVATE KEY-----\nAAAA\nBBBB\n-----END OPENSSH PRIVATE KEY-----"


@pytest.fixture
def session(tmp_path, monkeypatch):
    monkeypatch.setenv("LOCALGATEKEYS_DATA_DIR", str(tmp_path / "data"))
    vault = create_vault(tmp_path / "vault.json", "secret kinds master", kdf_overrides=KDF)
    vault.item_limit = None
    vault.items.create_card("Visa", cardholder="A Smith", number="4111111111111111", expiry="12/30", cvv="123")
    vault.items.create_ssh_key("Server", private_key=KEY, public_key="ssh-ed25519 AAAA")
    vault.items.create_api_key("API", service="svc", key="k-1", secret="s-1")
    vault.items.create_wifi("Home", ssid="home", password="wifi-pass")
    vault.items.create_bank_account("Bank", bank="B", account_number="DE89370400440532013000", pin="9999")
    vault.items.create_passkey("PK", relying_party_id="example.test", user_handle="dXNlcg",
                               credential_id="Y3JlZA", private_key="cHJpdg", algorithm="ES256", user_name="me")
    yield vault
    vault.lock()


def test_coverage_counts_left_out_kinds(session):
    assert export_coverage(session) == {"left_out": {"passkey": 1}, "partial": {}}


def test_json_export_carries_cards_and_secret_kinds(session, tmp_path):
    summary = export_json(session, tmp_path / "out.json")
    assert summary.left_out == {"passkey": 1}
    items = {item["name"]: item for item in json.loads((tmp_path / "out.json").read_text("utf-8"))["items"]}
    assert items["Visa"]["type"] == 3 and items["Visa"]["card"]["number"] == "4111111111111111"
    assert items["Visa"]["card"]["code"] == "123"
    ssh = {field["name"]: field for field in items["Server"]["fields"]}
    assert ssh["Private key"]["value"] == KEY and ssh["Private key"]["type"] == 1
    assert {"API", "Home", "Bank"} <= set(items)


def test_csv_round_trips_multi_line_values(session, tmp_path):
    export_csv(session, tmp_path / "out.csv")
    result = load_bitwarden_csv(tmp_path / "out.csv")
    server = next(record for record in result.records if record.title == "Server")
    assert {f["name"]: f["value"] for f in server.custom_fields}["Private key"] == KEY


def test_keepass_xml_contains_ssh_key(session, tmp_path):
    export_keepass_xml(session, tmp_path / "out.xml")
    assert "BEGIN OPENSSH PRIVATE KEY" in (tmp_path / "out.xml").read_text("utf-8")


def test_csv_login_uri_with_comma_is_not_split(tmp_path):
    rows = io.StringIO()
    writer = csv.writer(rows, lineterminator="\n")
    writer.writerow(["folder", "favorite", "type", "name", "notes", "fields", "reprompt", "login_uri",
                     "login_username", "login_password", "login_totp"])
    writer.writerow(["", "", "login", "x", "", "", "0", "https://a.test/p?x=1,2,https://b.test", "u", "p", ""])
    path = tmp_path / "in.csv"
    path.write_text(rows.getvalue(), "utf-8")
    record = load_bitwarden_csv(path).records[0]
    assert record.urls == ["https://a.test/p?x=1,2", "https://b.test"]


def test_coverage_lines_name_each_kind_before_and_after(session, tmp_path):
    from localvault.app.import_export import coverage_lines, export_summary_text

    before = coverage_lines({"passkey": 1}, {"document": 2})
    assert len(before) == 2 and "1" in before[0] and "2" in before[1]
    assert coverage_lines({}, {}) == []
    summary = export_json(session, tmp_path / "out.json")
    text = export_summary_text(summary)
    assert coverage_lines(summary.left_out, summary.partial, done=True)[0] in text
