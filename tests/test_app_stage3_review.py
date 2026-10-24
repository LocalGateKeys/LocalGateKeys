"""Stage 3 review findings: each test reproduces one reported defect."""
from __future__ import annotations

import threading

import pytest

from localvault.api.result import ApiError
from localvault.app.controller import WebController
from localvault.app.documents import DocumentService
from localvault.app.login_editor import LoginEditorService
from localvault.app.login_extras import LoginExtrasService
from localvault.app.typed import TypedService
from localvault.profiles import ProfileManager
from localvault.secret_text import SecretText
from localvault.settings import AppSettings

KDF = {"time_cost": 1, "memory_cost_kib": 8192, "parallelism": 1, "hash_len": 32}
MASTER = "correct horse battery"


class Bus:
    def emit(self, name, detail):
        pass


class Sched:
    def call_later(self, delay, fn):
        return fn

    def cancel(self, handle):
        pass


class Port:
    def __init__(self):
        self.passwords = []

    def ask_password(self, title, message):
        answer = self.passwords.pop(0) if self.passwords else None
        return None if answer is None else SecretText.from_str(answer)

    def confirm(self, title, message):
        return True

    def notify(self, *args):
        pass

    def show_upgrade(self, **kwargs):
        pass


class Clipboard:
    timeout_seconds = 30

    def __init__(self):
        self.value = None

    def copy(self, text):
        self.value = text

    def clear(self):
        self.value = None


@pytest.fixture
def env(tmp_path, monkeypatch):
    monkeypatch.setattr("localvault.app.controller.clear_master_unlock_requirement", lambda _pid: None)
    profiles = ProfileManager(tmp_path / "data")
    profiles.ensure_profile()
    controller = WebController(profiles=profiles, settings=AppSettings(idle_source="vault"), bus=Bus(),
                               scheduler=Sched(), create_kwargs={"kdf_overrides": KDF})
    controller.create(MASTER, MASTER)
    controller.clipboard = Clipboard()
    return controller, Port(), tmp_path


def _typed_ref(item_id, kind):
    return {"source": "typed", "id": item_id, "kind": kind}


def test_saving_an_unchanged_item_is_success(env):
    controller, port, _tmp = env
    typed = TypedService(controller, port)
    item = controller.session.item_service.create_note("Router", "codes")
    port.passwords = [MASTER]  # a note opens for editing only after the master password
    edit = typed.open_edit(_typed_ref(item, "note"))
    result = typed.save(_typed_ref(item, "note"), "note", {"title": "Router", "tags": [], "favorite": False,
                                                            "values": edit["values"], "protected": {}, "clear": [],
                                                            "revision": edit["revision"]})
    assert result["ref"]["id"] == item


def test_identity_field_can_be_cleared(env):
    controller, port, _tmp = env
    typed = TypedService(controller, port)
    item = controller.session.item_service.create_identity("Me", {"city": "X", "name": "Ann"})
    edit = typed.open_edit(_typed_ref(item, "identity"))
    typed.save(_typed_ref(item, "identity"), "identity", {"title": "Me", "tags": [], "favorite": False,
                                                          "values": {"name": "Ann", "city": ""}, "protected": {},
                                                          "clear": [], "revision": edit["revision"]})
    payload = controller.session.item_service.get_item(item, include_protected=True)["payload"]
    assert not payload.get("city")


def test_removing_a_saved_amount_is_explained(env):
    controller, port, _tmp = env
    typed = TypedService(controller, port)
    item = controller.session.item_service.create_purchase("TV", amount_minor=100, currency="EUR")
    edit = typed.open_edit(_typed_ref(item, "purchase"))
    with pytest.raises(ApiError) as refused:
        typed.save(_typed_ref(item, "purchase"), "purchase", {"title": "TV", "tags": [], "favorite": False,
                                                              "values": {}, "protected": {}, "clear": [],
                                                              "revision": edit["revision"]})
    assert refused.value.code == "invalid" and "0" in refused.value.message


def test_update_requires_the_revision(env):
    controller, port, _tmp = env
    typed = TypedService(controller, port)
    item = controller.session.item_service.create_note("Router", "codes")
    for data in ({"title": "x"}, {"title": "x", "revision": None}):
        with pytest.raises(ApiError) as missing:
            typed.save(_typed_ref(item, "note"), "note", {"tags": [], "favorite": False, "values": {}, "protected": {},
                                                          "clear": [], **data})
        assert missing.value.code == "changed"


def test_renaming_a_hidden_field_keeps_its_own_value(env):
    controller, port, _tmp = env
    session = controller.session
    entry = session.create_web_login(urls=[{"url": "https://a.test", "match": "exact_origin"}], username="u",
                                     password="pw-alpha-1234567",
                                     custom_fields=[{"name": "PIN", "value": "9999", "hidden": True},
                                                    {"name": "Code", "value": "1111", "hidden": True}])
    editor = LoginEditorService(controller, port, generate=lambda: "x" * 16)
    extras = LoginExtrasService(controller, port, editor)
    ref = {"source": "credential", "id": entry, "kind": "web"}
    fields = extras.custom_fields(ref, reveal=False)["fields"]
    assert [f["index"] for f in fields] == [0, 1]
    extras.custom_fields_save(ref, [{"index": 0, "name": "Bank PIN", "value": None, "hidden": True},
                                    {"index": 1, "name": "PIN", "value": None, "hidden": True}])
    saved = session.credential_detail(entry)["custom_fields"]
    assert saved == [{"name": "Bank PIN", "value": "9999", "hidden": True},
                     {"name": "PIN", "value": "1111", "hidden": True}]


def test_concurrent_extras_saves_do_not_resurrect_a_used_code(env, monkeypatch):
    controller, port, _tmp = env
    session = controller.session
    entry = session.create_web_login(urls=[{"url": "https://a.test", "match": "exact_origin"}], username="u",
                                     password="pw-alpha-1234567", recovery_codes=["c1", "c2"])
    editor = LoginEditorService(controller, port, generate=lambda: "x" * 16)
    extras = LoginExtrasService(controller, port, editor)
    ref = {"source": "credential", "id": entry, "kind": "web"}
    real_detail = session.credential_detail
    reading = threading.Event()
    release = threading.Event()

    def slow_detail(entry_id):
        detail = real_detail(entry_id)
        if threading.current_thread().name == "policy-writer":
            reading.set()
            release.wait(5)
        return detail

    monkeypatch.setattr(session, "credential_detail", slow_detail)
    writer = threading.Thread(target=lambda: extras.policy_save(ref, {"save_prompts": False}), name="policy-writer")
    writer.start()
    reading.wait(2)
    user = threading.Thread(target=lambda: extras.recovery_use_next(ref))
    user.start()
    user.join(0.3)
    release.set()
    writer.join(5)
    user.join(5)
    assert real_detail(entry)["recovery_codes"] == ["c2"]


def test_document_replace_checks_the_session_after_the_dialog(env):
    controller, port, tmp = env
    source = tmp / "a.txt"
    source.write_text("one", encoding="utf-8")

    class Dialogs:
        def open_file(self, title):
            controller.lock()  # the vault locks while the dialog is open
            return source

        def save_file(self, title, name):
            return None

    item = controller.session.documents.create(source, title="Doc")
    docs = DocumentService(controller, port, Dialogs())
    with pytest.raises(ApiError) as stale:
        docs.replace(_typed_ref(item, "document"))
    assert stale.value.code in {"session_changed", "locked"}
