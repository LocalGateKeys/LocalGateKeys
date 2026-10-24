"""Pro-only features on the free plan: sync, two-factor codes and attachments.

Adding or changing them is refused; what is already in the vault keeps working.
"""
from __future__ import annotations

import uuid
from pathlib import Path
from types import SimpleNamespace

import pytest

from localvault import licensing
from localvault.api.result import ApiError
from localvault.app.controller import WebController
from localvault.app.login_editor import LoginEditorService
from localvault.app.sync import SyncWebService
from localvault.attachments import DocumentService
from localvault.import_workflow import plan_records
from localvault.importers import ImportedRecord
from localvault.profiles import ProfileManager
from localvault.secret_text import SecretText
from localvault.settings import AppSettings
from localvault.totp import generate_totp
from localvault.transfer import _apply_feature_limits, _keep_totp_as_field
from localvault.vault import ProFeatureRequired, create_vault

pytestmark = pytest.mark.free_features

KDF = {"time_cost": 1, "memory_cost_kib": 8192, "parallelism": 1, "hash_len": 32}
MASTER = "correct horse battery"
TOTP = {"secret": "JBSWY3DPEHPK3PXP", "algorithm": "SHA1", "digits": 6, "period": 30}
OTHER = {"secret": "KRSXG5CTMVRXEZLU", "algorithm": "SHA1", "digits": 6, "period": 30}
URI = "otpauth://totp/ann?secret=JBSWY3DPEHPK3PXP"


class Bus:
    def __init__(self):
        self.events = []

    def emit(self, name, detail):
        self.events.append((name, detail))


class Sched:
    def call_later(self, delay, fn):
        return fn

    def cancel(self, handle):
        pass


class Port:
    def __init__(self):
        self.upgrades = []

    def show_upgrade(self, *, limit, message, on_enter):
        self.upgrades.append(message)

    def confirm(self, title, message):
        return True

    def ask_password(self, title, message):
        return SecretText.from_str(MASTER)

    def notify(self, kind, title, message):
        pass


@pytest.fixture
def session(tmp_path):
    return create_vault(tmp_path / "vault.json", MASTER, kdf_overrides=KDF)


@pytest.fixture
def controller(tmp_path, monkeypatch):
    monkeypatch.setattr("localvault.app.controller.clear_master_unlock_requirement", lambda _pid: None)
    monkeypatch.setattr(AppSettings, "save", lambda self, path=None: None)
    profiles = ProfileManager(tmp_path / "data")
    profiles.ensure_profile()
    controller = WebController(profiles=profiles, settings=AppSettings(idle_source="vault"), bus=Bus(),
                               scheduler=Sched(), create_kwargs={"kdf_overrides": KDF})
    controller.create(MASTER, MASTER)
    return controller


def _login(session, **extra) -> str:
    return session.create_web_login(urls=[{"url": "https://example.test", "match": "exact_origin"}],
                                    username="ann", password="pw-1", **extra)


# --- licensing ------------------------------------------------------------------------------


def test_free_plan_has_no_pro_features_and_pro_has_them_all(monkeypatch):
    assert licensing.status().state == "free"
    assert licensing.pro_features() == frozenset()
    monkeypatch.setattr(licensing, "LICENSE_KEYS", {})  # "unconfigured" counts as Pro
    assert licensing.pro_features() == {"unlimited_items", "sync", "totp", "attachments"}


def test_unlock_applies_the_free_plan_to_the_session(controller):
    assert controller.session.pro_features == frozenset()
    assert controller.session.item_limit == licensing.FREE_ITEM_LIMIT


# --- two-factor codes -----------------------------------------------------------------------


def test_free_plan_refuses_a_new_login_with_a_code_and_writes_nothing(session):
    session.pro_features = frozenset()
    with pytest.raises(ProFeatureRequired) as refused:
        _login(session, totp=TOTP)
    assert refused.value.feature == "totp"
    assert "Codes you already saved keep working" in str(refused.value)
    assert session.all_entries() == []


def test_existing_code_keeps_working_and_can_be_kept_or_removed(session):
    entry_id = _login(session, totp=TOTP)
    session.pro_features = frozenset()  # the licence went away (refund, removal, another PC)
    saved = session.get_entry(entry_id)["totp"]
    assert generate_totp(**saved)
    # An unrelated edit that carries the saved code along is allowed.
    session.set_details(entry_id, notes="new notes", totp=dict(saved))
    entry = session.get_entry(entry_id)
    assert entry["notes"] == "new notes" and entry["totp"] == saved
    # Changing it is not.
    with pytest.raises(ProFeatureRequired):
        session.set_details(entry_id, notes="new notes", totp=OTHER)
    assert session.get_entry(entry_id)["totp"] == saved
    # Removing it is.
    session.set_details(entry_id, notes="new notes", totp=None)
    assert not session.get_entry(entry_id).get("totp")


def test_login_editor_refuses_a_new_key_at_once_and_says_so(controller):
    port = Port()
    editor = LoginEditorService(controller, port, generate=lambda: "Generated-Pass-123!")
    view = editor.open_new()
    assert view["totp_allowed"] is False
    with pytest.raises(ApiError) as refused:
        editor.update(view["draft_id"], {"totp_text": TOTP["secret"]})
    assert refused.value.code == "pro_required"
    assert port.upgrades and "two-factor" in port.upgrades[0]
    # Everything else in the editor still works on the free plan.
    view = editor.update(view["draft_id"], {"urls": [{"url": "example.test", "match": "exact_origin"}],
                                            "username": "ann"})
    saved = editor.save(view["draft_id"])
    assert controller.session.credential_detail(saved["ref"]["id"])["username"] == "ann"


def test_import_keeps_two_factor_keys_as_hidden_fields_on_the_free_plan(session):
    session.pro_features = frozenset()
    record = ImportedRecord(kind="login", title="Example", username="ann", password="pw",
                            urls=["https://example.test"], totp_uri=URI)
    plan = plan_records(session, [record])
    row = plan.rows[0]
    assert row.record.totp_uri == ""
    assert {"name": "Two-factor key (needs Pro)", "value": URI, "hidden": True} in row.record.custom_fields
    assert any("Two-factor codes need LocalGateKeys Pro" in issue for issue in plan.issues)


def test_import_keeps_two_factor_keys_with_pro(session):
    record = ImportedRecord(kind="login", title="Example", username="ann", password="pw",
                            urls=["https://example.test"], totp_uri=URI)
    plan = plan_records(session, [record])
    assert plan.rows[0].record.totp_uri == URI


def test_transfer_keeps_a_new_key_as_a_hidden_field_and_an_unchanged_one_as_is():
    entry = {"username": "ann", "totp": dict(TOTP), "custom_fields": []}
    _keep_totp_as_field(entry, None)
    assert entry["totp"] is None
    assert entry["custom_fields"][0]["name"] == "Two-factor key (needs Pro)"
    assert "JBSWY3DPEHPK3PXP" in entry["custom_fields"][0]["value"] and entry["custom_fields"][0]["hidden"]
    same = {"username": "ann", "totp": dict(TOTP), "custom_fields": []}
    _keep_totp_as_field(same, {"totp": dict(TOTP)})
    assert same["totp"] == TOTP and same["custom_fields"] == []


# --- attachments ----------------------------------------------------------------------------


def test_free_plan_refuses_new_documents_before_writing_a_file(session, tmp_path):
    source = tmp_path / "scan.txt"
    source.write_bytes(b"passport scan")
    session.pro_features = frozenset()
    with pytest.raises(ProFeatureRequired) as refused:
        DocumentService(session).create(source, title="Passport")
    assert refused.value.feature == "attachments"
    assert session.items.list_items() == []
    assert not session._payload.get("attachments")


def test_existing_documents_stay_readable_and_exportable(session, tmp_path):
    source = tmp_path / "scan.txt"
    source.write_bytes(b"passport scan")
    item_id = DocumentService(session).create(source, title="Passport")
    session.pro_features = frozenset()
    documents = DocumentService(session)
    assert documents.read(item_id) == b"passport scan"
    exported = documents.export(item_id, tmp_path / "out.txt")
    assert Path(exported).read_bytes() == b"passport scan"
    replacement = tmp_path / "new.txt"
    replacement.write_bytes(b"new scan")
    with pytest.raises(ProFeatureRequired):
        documents.replace(item_id, replacement)
    assert documents.read(item_id) == b"passport scan"


def test_transfer_leaves_documents_and_the_items_that_need_them_out():
    d1, p1, n1 = (str(uuid.uuid4()) for _ in range(3))
    session = SimpleNamespace(pro_features=frozenset())
    doc = {"id": d1, "kind": "document", "payload": {"attachment_id": str(uuid.uuid4())}}
    purchase = {"id": p1, "kind": "purchase", "payload": {"document_ids": [d1]}}
    note = {"id": n1, "kind": "note", "payload": {}}
    actions = {d1: "import", p1: "import", n1: "import"}
    id_map = {d1: d1, p1: p1, n1: n1}
    _apply_feature_limits(session, [doc, purchase, note], actions, id_map)
    assert actions == {d1: "limit", p1: "limit", n1: "import"}
    assert id_map[d1] is None and id_map[p1] is None
    pro = SimpleNamespace(pro_features=None)
    actions = {d1: "import", p1: "import", n1: "import"}
    _apply_feature_limits(pro, [doc, purchase, note], actions, {d1: d1, p1: p1, n1: n1})
    assert set(actions.values()) == {"import"}


# --- device sync ----------------------------------------------------------------------------


def test_free_plan_builds_no_sync_service_and_explains_why(controller, tmp_path):
    built = []
    service = SyncWebService(controller, Port(), Bus(), SimpleNamespace(choose_folder=lambda t: None),
                             factory=lambda c, cb: built.append(1))
    service.start()
    assert built == [] and service.service is None
    view = service.view()
    assert view["pro"] is False and "LocalGateKeys Pro" in view["pro_text"]
    with pytest.raises(ApiError) as refused:
        service.sync_now()
    assert refused.value.code == "pro_required"


def test_sync_starts_and_stops_with_the_licence(controller, monkeypatch):
    class Fake:
        stopped = False

        def on_unlock(self):
            pass

        def stop(self):
            self.stopped = True

    fake = Fake()
    service = SyncWebService(controller, Port(), Bus(), SimpleNamespace(choose_folder=lambda t: None),
                             factory=lambda c, cb: fake)
    service.plan_changed()
    assert service.service is None
    controller.session.pro_features = frozenset({"sync", "totp", "attachments", "unlimited_items"})
    service.plan_changed()
    assert service.service is fake
    controller.session.pro_features = frozenset()
    service.plan_changed()
    assert service.service is None and fake.stopped


def test_sync_view_while_locked_does_not_pitch_pro(controller):
    service = SyncWebService(controller, Port(), Bus(), SimpleNamespace(choose_folder=lambda t: None),
                             factory=lambda c, cb: None)
    controller.lock()
    assert service.view()["pro"] is True


def test_messages_name_what_keeps_working():
    for feature, kept in (("totp", "Codes you already saved keep working."),
                          ("attachments", "Files you already saved stay available."),
                          ("sync", "Everything already on this PC stays here and keeps working.")):
        assert str(ProFeatureRequired(feature)).endswith(kept)
