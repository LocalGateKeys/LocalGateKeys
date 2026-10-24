"""Audit 2026-10-18 M4: every export asks for the master password (no Windows Hello, no routine grace)."""
from __future__ import annotations

from types import SimpleNamespace

import pytest

from localvault.api.result import ApiError
from localvault.app.controller import WebController
from localvault.app.import_export import ExportService
from localvault.app.secrets import SecretService
from localvault.app.transfer_web import TransferService
from localvault.profiles import ProfileManager
from localvault.secret_text import SecretText
from localvault.settings import AppSettings

KDF = {"time_cost": 1, "memory_cost_kib": 8192, "parallelism": 1, "hash_len": 32}
MASTER = "correct horse battery"
KDBX_PW = "kdbx password 123"
TRANSFER_PW = "transfer pw 12345"
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
        self.asked, self.passwords = [], []

    def confirm(self, title, message):
        self.asked.append(title)
        return True

    def ask_password(self, title, message):
        self.asked.append(title)
        answer = self.passwords.pop(0) if self.passwords else None
        return None if answer is None else SecretText.from_str(answer)

    def notify(self, kind, title, message):
        self.asked.append(title)

    def show_upgrade(self, **kwargs):
        pass


class Dialogs:
    def __init__(self, path):
        self.path, self.saves = path, []

    def save_file(self, title, name):
        self.saves.append(title)
        return self.path

    def open_file(self, title):
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
    calls = []
    real = SecretService.reauthenticate

    def spy(self, title, lease, *, allow_hello=False):
        calls.append((title, allow_hello))
        return real(self, title, lease, allow_hello=allow_hello)
    monkeypatch.setattr(SecretService, "reauthenticate", spy)
    # Hello would succeed and a routine grace window is open: neither may stand in for the master password.
    controller.hello_reauth = lambda title, lease: True
    controller.routine_reauth = (controller.guard.stamp(), controller._clock() + 3600)
    return SimpleNamespace(controller=controller, port=Port(), calls=calls, tmp=tmp_path)


def _exports(env, path):
    dialogs = Dialogs(path)
    return ExportService(env.controller, env.port, dialogs), dialogs


def test_kdbx_export_asks_for_the_master_password(env):
    service, _dialogs = _exports(env, env.tmp / "out")
    env.port.passwords = [MASTER]
    service.export("kdbx", False, KDBX_PW, KDBX_PW)
    assert env.calls == [("Confirm to export passwords", False)]
    assert env.port.asked[0] == "Confirm to export passwords" and (env.tmp / "out.kdbx").exists()


@pytest.mark.parametrize(("answer", "code"), [(None, "cancelled"), ("wrong master password", "not_authorized")])
def test_kdbx_export_aborts_when_reauth_fails(env, answer, code):
    service, dialogs = _exports(env, env.tmp / "out")
    env.port.passwords = [answer]
    with pytest.raises(ApiError) as failed:
        service.export("kdbx", False, KDBX_PW, KDBX_PW)
    assert failed.value.code == code
    assert dialogs.saves == [] and not (env.tmp / "out.kdbx").exists()


def test_csv_export_still_prompts(env):
    service, dialogs = _exports(env, env.tmp / "plain.csv")
    with pytest.raises(ApiError) as cancelled:
        service.export("csv", False, "", "")
    assert cancelled.value.code == "cancelled" and env.calls == [("Confirm to export passwords", False)]
    assert dialogs.saves == [] and not (env.tmp / "plain.csv").exists()


def test_transfer_export_asks_once_before_the_file_dialog(env):
    dialogs = Dialogs(env.tmp / "pkg.lgt")
    service = TransferService(env.controller, env.port, dialogs)
    env.port.passwords = [MASTER]
    handle = service.choose("export")["handle"]
    assert env.calls == [("Confirm to export passwords", False)] and len(dialogs.saves) == 1
    preview = service.preview("export", handle, TRANSFER_PW, SCOPE, "skip", False)
    service.commit(preview["token"], "export", handle, TRANSFER_PW, TRANSFER_PW, SCOPE, "skip", False)
    assert (env.tmp / "pkg.lgt").exists() and len(env.calls) == 1


@pytest.mark.parametrize(("answer", "code"), [(None, "cancelled"), ("wrong master password", "not_authorized")])
def test_transfer_export_aborts_when_reauth_fails(env, answer, code):
    dialogs = Dialogs(env.tmp / "pkg.lgt")
    service = TransferService(env.controller, env.port, dialogs)
    env.port.passwords = [answer]
    with pytest.raises(ApiError) as failed:
        service.choose("export")
    assert failed.value.code == code and dialogs.saves == []
    with pytest.raises(ApiError):  # no handle was issued, so nothing can be previewed or committed
        service.preview("export", "", TRANSFER_PW, SCOPE, "skip", False)
    assert not (env.tmp / "pkg.lgt").exists()


def test_transfer_import_does_not_ask(env):
    service = TransferService(env.controller, env.port, Dialogs(env.tmp / "pkg.lgt"))
    service.choose("import")
    assert env.calls == []
