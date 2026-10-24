"""Stage 3: encrypted documents in the WebView UI (file dialogs are opened by Python)."""
from __future__ import annotations

import pytest

from localvault.api.result import ApiError
from localvault.app.controller import WebController
from localvault.app.documents import (
    OPEN_OFF_TEXT,
    OPEN_WARNING_TEXT,
    DocumentService,
)
from localvault.profiles import ProfileManager
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
        self.asked, self.answers = [], []

    def confirm(self, title, message):
        self.asked.append((title, message))
        return self.answers.pop(0) if self.answers else True

    def notify(self, kind, title, message):
        self.asked.append((f"{kind}:{title}", message))

    def show_upgrade(self, *, limit, message, on_enter):
        self.asked.append(("upgrade", message))


class Dialogs:
    def __init__(self):
        self.open_path = None
        self.save_path = None

    def open_file(self, title):
        return self.open_path

    def save_file(self, title, name):
        return self.save_path


@pytest.fixture
def env(tmp_path, monkeypatch):
    monkeypatch.setattr("localvault.app.controller.clear_master_unlock_requirement", lambda _pid: None)
    profiles = ProfileManager(tmp_path / "data")
    profiles.ensure_profile()
    settings = AppSettings(idle_source="vault")
    monkeypatch.setattr(settings, "save", lambda *a, **k: None)
    controller = WebController(profiles=profiles, settings=settings, bus=Bus(), scheduler=Sched(),
                               create_kwargs={"kdf_overrides": KDF})
    controller.create(MASTER, MASTER)
    port, dialogs = Port(), Dialogs()
    source = tmp_path / "notes.txt"
    source.write_text("hello document", encoding="utf-8")
    dialogs.open_path = source
    return DocumentService(controller, port, dialogs), controller, port, dialogs, tmp_path


def test_create_and_info(env):
    service, _controller, _port, _dialogs, _tmp = env
    ref = service.create("My notes", "desc")["ref"]
    assert ref["kind"] == "document"
    assert service.info(ref) == {"name": "notes.txt", "mime": "text/plain", "size": 14}


def test_cancelled_dialog_changes_nothing(env):
    service, controller, _port, dialogs, _tmp = env
    dialogs.open_path = None
    with pytest.raises(ApiError) as cancelled:
        service.create("x", "")
    assert cancelled.value.code == "cancelled"
    assert controller.session.item_service.metadata_summaries() == []


def test_replace_keeps_the_item(env):
    service, _controller, _port, dialogs, tmp = env
    ref = service.create("Doc", "")["ref"]
    other = tmp / "other.txt"
    other.write_text("replacement text!", encoding="utf-8")
    dialogs.open_path = other
    service.replace(ref)
    assert service.info(ref)["name"] == "other.txt"


def test_preview_text(env):
    service, _controller, _port, _dialogs, _tmp = env
    ref = service.create("Doc", "")["ref"]
    preview = service.preview(ref)
    assert preview["kind"] == "text" and preview["content"] == "hello document"


def test_open_refused_when_setting_off(env):
    service, controller, port, _dialogs, _tmp = env
    ref = service.create("Doc", "")["ref"]
    controller.settings.document_open_enabled = False
    with pytest.raises(ApiError) as off:
        service.open_externally(ref)
    assert off.value.code == "needs_setting" and off.value.message == OPEN_OFF_TEXT
    assert off.value.fix["key"] == "document_open_enabled"


def test_first_open_warns_once(env, monkeypatch):
    service, controller, port, _dialogs, _tmp = env
    ref = service.create("Doc", "")["ref"]
    opened = []
    monkeypatch.setattr(type(controller.session.documents), "open_externally",
                        lambda self, item_id, **k: opened.append(item_id) or controller.profiles.profile_dir() / "x.txt")
    controller.settings.document_open_enabled = True
    controller.settings.document_open_warning_seen = False
    service.open_externally(ref)
    service.open_externally(ref)
    warnings = [a for a in port.asked if a[0] == "Open a decrypted copy?"]
    assert len(warnings) == 1 and warnings[0][1] == OPEN_WARNING_TEXT
    assert controller.settings.document_open_warning_seen is True and len(opened) == 2


def test_save_copy_writes_the_file(env):
    service, _controller, port, dialogs, tmp = env
    ref = service.create("Doc", "")["ref"]
    target = tmp / "out" / "copy.txt"
    target.parent.mkdir()
    dialogs.save_path = target
    service.save_copy(ref)
    assert target.read_text(encoding="utf-8") == "hello document"
    assert port.asked[-1][0] == "info:Copy saved"


def test_too_large_file_uses_vault_message(env, monkeypatch):
    service, _controller, _port, dialogs, tmp = env
    monkeypatch.setattr("localvault.attachments.MAX_ATTACHMENT_SIZE", 4)
    with pytest.raises(ApiError) as big:
        service.create("Doc", "")
    assert big.value.code == "vault_error" and "limit" in big.value.message
