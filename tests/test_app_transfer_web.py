"""Stage 6a: encrypted transfer packages for the WebView UI (real packages, two profiles)."""
from __future__ import annotations

from types import SimpleNamespace

import pytest

from localvault.api.result import ApiError
from localvault.app.controller import WebController
from localvault.app.transfer_web import TransferService
from localvault.profiles import ProfileManager
from localvault.secret_text import SecretText
from localvault.settings import AppSettings

KDF = {"time_cost": 1, "memory_cost_kib": 8192, "parallelism": 1, "hash_len": 32}
MASTER = "correct horse battery"
TRANSFER = "a separate transfer pw"
SCOPE = {"kinds": "web"}


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
        self.upgrades = []

    def confirm(self, title, message):
        return True

    def show_upgrade(self, **kwargs):
        self.upgrades.append(kwargs)

    def ask_password(self, title, message):  # export re-asks the master password before its save dialog
        return SecretText.from_str(MASTER)

    def notify(self, kind, title, message):
        pass


class Dialogs:
    def __init__(self, path):
        self.path = path

    def open_file(self, title):
        return self.path

    def save_file(self, title, name):
        return self.path


@pytest.fixture
def env(tmp_path, monkeypatch):
    monkeypatch.setattr("localvault.app.controller.clear_master_unlock_requirement", lambda pid: None)
    profiles = ProfileManager(tmp_path / "data")
    profiles.ensure_profile()
    controller = WebController(profiles=profiles, settings=AppSettings(idle_source="vault"), bus=Bus(),
                               scheduler=Sched(), create_kwargs={"kdf_overrides": KDF})
    controller.create(MASTER, MASTER)
    controller.session.create_web_login(urls=[{"url": "https://a.test", "match": "exact_origin"}], username="ann",
                                        password="pw-123456789012", label="Alpha")
    package = tmp_path / "pkg.lgt"
    return SimpleNamespace(controller=controller, profiles=profiles, port=Port(), package=package,
                           service=TransferService(controller, Port(), Dialogs(package)))


def test_export_then_import_into_another_profile(env):
    service = env.service
    handle = service.choose("export")["handle"]
    with pytest.raises(ApiError):
        service.preview("export", handle, "", SCOPE, "skip", False)
    preview = service.preview("export", handle, TRANSFER, SCOPE, "skip", False)
    assert any(line.startswith("Records: 1") for line in preview["lines"])
    with pytest.raises(ApiError) as mismatch:
        service.commit(preview["token"], "export", handle, TRANSFER, TRANSFER + "x", SCOPE, "skip", False)
    assert mismatch.value.message == "Transfer password confirmation does not match"
    handle = service.choose("export")["handle"]  # a failed commit used up the export path
    preview = service.preview("export", handle, TRANSFER, SCOPE, "skip", False)
    done = service.commit(preview["token"], "export", handle, TRANSFER, TRANSFER, SCOPE, "skip", False)
    assert done["status"].startswith("Transfer complete.") and env.package.exists()

    second = env.profiles.create_profile("Second")
    env.controller.select_profile(second.id)
    env.controller.create(MASTER, MASTER)
    handle = service.choose("import")["handle"]
    preview = service.preview("import", handle, TRANSFER, SCOPE, "skip", False)
    assert any("explicit commit is required" in line for line in preview["lines"])
    assert env.controller.session.live_item_count() == 0
    service.commit(preview["token"], "import", handle, TRANSFER, "", {}, "skip", False)
    assert env.controller.session.live_item_count() == 1


def test_commit_refuses_changed_inputs(env):
    service = env.service
    handle = service.choose("export")["handle"]
    preview = service.preview("export", handle, TRANSFER, SCOPE, "skip", False)
    with pytest.raises(ApiError) as other_password:
        service.commit(preview["token"], "export", handle, "different pw 123", "different pw 123", SCOPE, "skip", False)
    assert other_password.value.code == "stale"
    handle = service.choose("export")["handle"]
    preview = service.preview("export", handle, TRANSFER, SCOPE, "skip", False)
    with pytest.raises(ApiError) as other_scope:
        service.commit(preview["token"], "export", handle, TRANSFER, TRANSFER, {"kinds": "note"}, "skip", False)
    assert other_scope.value.code == "stale"
    assert not env.package.exists()


def test_lock_drops_previews_and_paths(env):
    service = env.service
    handle = service.choose("export")["handle"]
    service.preview("export", handle, TRANSFER, SCOPE, "skip", False)
    env.controller.lock()
    assert service._previews == {} and service._paths == {}


def test_the_password_is_not_kept(env):
    service = env.service
    handle = service.choose("export")["handle"]
    service.preview("export", handle, TRANSFER, SCOPE, "skip", False)
    assert TRANSFER not in repr(service.__dict__)


def test_a_confirmation_typo_needs_a_new_export_path(env):
    service = env.service
    handle = service.choose("export")["handle"]
    preview = service.preview("export", handle, TRANSFER, SCOPE, "skip", False)
    with pytest.raises(ApiError):
        service.commit(preview["token"], "export", handle, TRANSFER, "typo", SCOPE, "skip", False)
    with pytest.raises(ApiError) as again:  # the path was single-use: choose (and confirm) again
        service.commit(preview["token"], "export", handle, TRANSFER, TRANSFER, SCOPE, "skip", False)
    assert again.value.code == "invalid" and not env.package.exists()
