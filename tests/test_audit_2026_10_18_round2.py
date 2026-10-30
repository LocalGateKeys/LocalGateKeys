"""Audit 2026-10-18, review of the fix round: sync hand-over reauth, single-use export paths, strict-off in
the login editor, and custom field saves that would silently drop stored rows."""
from __future__ import annotations

from types import SimpleNamespace

import pytest
from test_app_sync import STRONG, Dialogs, FakeService
from test_app_sync import Bus as SyncBus
from test_app_transfer_web import Dialogs as FileDialogs

from localvault.api.result import ApiError
from localvault.app.controller import WebController
from localvault.app.login_editor import LoginEditorService
from localvault.app.login_extras import LoginExtrasService
from localvault.app.sync import CONFIRM_SYNC, SyncWebService
from localvault.i18n import t
from localvault.app.transfer_web import TransferService
from localvault.profiles import ProfileManager
from localvault.secret_text import SecretText
from localvault.settings import AppSettings
from localvault.sync.lan_interfaces import NetworkSnapshot

KDF = {"time_cost": 1, "memory_cost_kib": 8192, "parallelism": 1, "hash_len": 32}
MASTER = "correct horse battery"
TRANSFER = "a separate transfer pw"
SCOPE = {"kinds": "web"}
STRICT = {"fill": "click", "sign_in": "inherit", "require_master_password": True, "save_prompts": True}
FIELDS = [{"name": "PIN", "value": "9999", "hidden": True}, {"name": "Hint", "value": "blue", "hidden": False}]


class Sched:
    def call_later(self, delay, fn):
        return fn

    def cancel(self, handle):
        pass


class Port:
    """Records every prompt; a password prompt without a queued answer is cancelled."""

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
        pass

    def show_upgrade(self, **kwargs):
        pass


def _controller(tmp_path, monkeypatch, bus):
    monkeypatch.setattr("localvault.app.controller.clear_master_unlock_requirement", lambda pid: None)
    monkeypatch.setattr(AppSettings, "save", lambda self, path=None: None)
    profiles = ProfileManager(tmp_path / "data")
    profiles.ensure_profile()
    controller = WebController(profiles=profiles, settings=AppSettings(idle_source="vault"), bus=bus,
                               scheduler=Sched(), create_kwargs={"kdf_overrides": KDF})
    controller.create(MASTER, MASTER)
    return controller


# ------------------------------------------------------------------ 1. sync hand-over
@pytest.fixture
def sync(tmp_path, monkeypatch):
    calls = []
    for name in ("create_group_job", "join_folder_job", "enroll_job", "snapshot_job"):
        monkeypatch.setattr(f"localvault.app.sync.{name}",
                            lambda *args, _n=name, **kwargs: calls.append(_n) or (lambda s, lease, g: None))
    monkeypatch.setattr("localvault.app.sync_view.add_folder_job",
                        lambda *args: calls.append("add_folder_job") or (lambda s, lease, g: None))
    monkeypatch.setattr("localvault.app.sync_view.attach_folder_job",
                        lambda *args: calls.append("attach_folder_job") or (lambda s, lease, g: None))
    controller = _controller(tmp_path, monkeypatch, SyncBus())
    # Hello would succeed and a routine grace window is open: neither may stand in for the master password.
    hellos = []
    controller.hello_reauth = lambda title, lease: hellos.append(title) or True
    controller.routine_reauth = (controller.guard.stamp(), controller._clock() + 3600)
    fake = FakeService()
    fake.settings = controller.settings
    port = Port()
    service = SyncWebService(controller, port, SyncBus(), Dialogs(str(tmp_path / "cloud")),
                             factory=lambda c, cb: fake, network=NetworkSnapshot)
    service.start()
    return SimpleNamespace(service=service, fake=fake, controller=controller, port=port, calls=calls, hellos=hellos)


def _folder_actions(service):
    return {
        "create": lambda token: service.create(token, STRONG, STRONG),
        "join": lambda token: service.join(token, STRONG),
        "add-folder": lambda token: service.folder_setup("add-folder", token, STRONG, STRONG),
        "use-folder": lambda token: service.folder_setup("use-folder", token, STRONG, ""),
    }


@pytest.mark.parametrize(("action", "job"), [("create", "create_group_job"), ("join", "join_folder_job"),
                                             ("add-folder", "add_folder_job"), ("use-folder", "attach_folder_job")])
def test_handing_the_vault_to_a_folder_asks_for_the_master_password(sync, action, job):
    run = _folder_actions(sync.service)[action]
    with pytest.raises(ApiError) as cancelled:
        run(sync.service.choose_folder()["token"])
    assert cancelled.value.code == "cancelled" and sync.port.asked == [t(CONFIRM_SYNC)]
    assert job not in sync.calls and sync.fake.jobs == [] and sync.hellos == []
    sync.port.passwords = ["not the master password"]
    with pytest.raises(ApiError) as wrong:
        run(sync.service.choose_folder()["token"])
    assert wrong.value.code == "not_authorized" and sync.fake.jobs == []
    sync.port.passwords = [MASTER]
    run(sync.service.choose_folder()["token"])
    assert job in sync.calls and sync.hellos == []


def test_a_weak_sync_password_is_refused_before_the_prompt(sync):
    with pytest.raises(ApiError) as weak:
        sync.service.create(sync.service.choose_folder()["token"], "short", "short")
    assert weak.value.code == "invalid" and sync.port.asked == []


def test_the_prompt_runs_before_any_sync_job_is_submitted(sync):
    seen = []
    original = sync.port.ask_password

    def ask(title, message):
        seen.append(len(sync.fake.jobs))
        return original(title, message)

    sync.port.ask_password = ask
    sync.port.passwords = [MASTER]
    sync.service.create(sync.service.choose_folder()["token"], STRONG, STRONG)
    assert seen == [0]  # asked on the page call's thread, not from inside a worker job


def test_arming_a_pairing_code_asks_for_the_master_password(sync, monkeypatch):
    sync.controller.settings.sync_lan_endpoint = "192.168.1.20:47821"
    offer = SimpleNamespace(offer_id="o1", code="123-456", expires_at=9e12)
    sync.fake.result = offer
    monkeypatch.setattr("localvault.app.sync.begin_pairing_job", lambda *a: (lambda s, lease, g: offer))
    monkeypatch.setattr("localvault.sync.pairing.offer_qr_payload", lambda o: "payload")
    monkeypatch.setattr("localvault.sync.pairing.render_qr_png", lambda payload, scale=6: b"x")
    with pytest.raises(ApiError) as cancelled:
        sync.service.qr_show()
    assert cancelled.value.code == "cancelled" and sync.port.asked == [t(CONFIRM_SYNC)]
    assert sync.fake.armed == [] and sync.fake.jobs == [] and sync.hellos == []
    sync.port.passwords = [MASTER]
    assert sync.service.qr_show()["code"] == "123-456" and sync.fake.armed == ["o1"]


def test_joining_by_code_asks_for_the_master_password(sync):
    with pytest.raises(ApiError) as cancelled:
        sync.service.join_qr("lgk-pair:code")
    assert cancelled.value.code == "cancelled" and "enroll_job" not in sync.calls
    sync.port.passwords = [MASTER]
    sync.service.join_qr("lgk-pair:code")
    assert "enroll_job" in sync.calls


def test_ordinary_sync_runs_do_not_prompt(sync):
    sync.service.sync_now()
    sync.service.refresh()
    assert sync.fake.runs == 1 and sync.port.asked == []


# ---------------------------------------------------------- 2. single-use export path
@pytest.fixture
def transfer(tmp_path, monkeypatch):
    controller = _controller(tmp_path, monkeypatch, SyncBus())
    controller.session.create_web_login(urls=[{"url": "https://a.test", "match": "exact_origin"}], username="ann",
                                        password="pw-123456789012", label="Alpha")
    port = Port()
    package = tmp_path / "pkg.lgt"
    return SimpleNamespace(service=TransferService(controller, port, FileDialogs(package)), port=port, package=package)


def _chosen(env):
    env.port.passwords = [MASTER]
    handle = env.service.choose("export")["handle"]
    return handle, env.service.preview("export", handle, TRANSFER, SCOPE, "skip", False)["token"]


@pytest.mark.parametrize("failure", ["mismatch", "stale_password", "stale_token", "scope"])
def test_a_failed_export_commit_uses_up_the_path(transfer, failure):
    handle, token = _chosen(transfer)
    args = {
        "mismatch": (token, TRANSFER, TRANSFER + "x", SCOPE),
        "stale_password": (token, "other pw 123456", "other pw 123456", SCOPE),
        "stale_token": ("made-up", TRANSFER, TRANSFER, SCOPE),
        "scope": (token, TRANSFER, TRANSFER, {"kinds": "note"}),
    }[failure]
    with pytest.raises(ApiError):
        transfer.service.commit(args[0], "export", handle, args[1], args[2], args[3], "skip", False)
    # No later export to the same path without a new master-password prompt and save dialog.
    with pytest.raises(ApiError) as gone:
        transfer.service.preview("export", handle, TRANSFER, SCOPE, "skip", False)
    assert gone.value.message == "Choose a local package path"
    assert handle not in transfer.service._paths and not transfer.package.exists()
    asked = len(transfer.port.asked)
    handle, token = _chosen(transfer)
    transfer.service.commit(token, "export", handle, TRANSFER, TRANSFER, SCOPE, "skip", False)
    assert transfer.package.exists() and len(transfer.port.asked) == asked + 1


# ----------------------------------------------------- 3. strict off in the login editor
@pytest.fixture
def editor(tmp_path, monkeypatch):
    controller = _controller(tmp_path, monkeypatch, SyncBus())
    hellos = []
    controller.hello_reauth = lambda title, lease: hellos.append(title) or True
    controller.routine_reauth = (controller.guard.stamp(), controller._clock() + 3600)
    entry = controller.session.create_web_login(urls=[{"url": "https://s.test", "match": "exact_origin"}],
                                                username="ann", password="pw-123456789012", label="Strict",
                                                policy=dict(STRICT))
    port = Port()
    service = LoginEditorService(controller, port, generate=lambda: "Generated-Pass-123!")
    return SimpleNamespace(service=service, controller=controller, port=port, hellos=hellos,
                           ref={"source": "credential", "id": entry, "kind": "web"})


def _strict(env):
    return env.controller.session.credential_detail(env.ref["id"])["policy"]["require_master_password"]


def test_turning_strict_off_in_the_editor_asks_again(editor):
    editor.port.passwords = [MASTER]
    view = editor.service.open(editor.ref)
    editor.service.update(view["draft_id"], {"policy": {"require_master_password": False}})
    editor.port.asked.clear()
    with pytest.raises(ApiError) as cancelled:
        editor.service.save(view["draft_id"])
    assert cancelled.value.code == "cancelled" and _strict(editor) is True
    assert editor.port.asked == ["Enter your master password to change this login's rules"] and editor.hellos == []
    editor.port.passwords = [MASTER]
    editor.service.save(view["draft_id"])
    assert _strict(editor) is False and editor.hellos == []


def test_editing_a_strict_login_that_stays_strict_asks_only_at_open(editor):
    editor.port.passwords = [MASTER]
    view = editor.service.open(editor.ref)
    editor.service.update(view["draft_id"], {"notes": "new notes"})
    editor.port.asked.clear()
    editor.service.save(view["draft_id"])
    assert editor.port.asked == [] and _strict(editor) is True


def test_turning_strict_on_needs_no_extra_prompt(editor):
    session = editor.controller.session
    plain = session.create_web_login(urls=[{"url": "https://p.test", "match": "exact_origin"}], username="bo",
                                     password="pw-abcdefghijkl", label="Plain")
    view = editor.service.open({"source": "credential", "id": plain, "kind": "web"})
    editor.service.update(view["draft_id"], {"policy": {"require_master_password": True}})
    editor.service.save(view["draft_id"])
    assert editor.port.asked == [] and session.credential_detail(plain)["policy"]["require_master_password"]


# ------------------------------------------------- 5. custom field saves account for stored rows
@pytest.fixture
def extras(tmp_path, monkeypatch):
    controller = _controller(tmp_path, monkeypatch, SyncBus())
    controller.hello_reauth = lambda title, lease: True
    entry = controller.session.create_web_login(urls=[{"url": "https://f.test", "match": "exact_origin"}],
                                                username="ann", password="pw-123456789012", label="Fields",
                                                custom_fields=[dict(f) for f in FIELDS])
    port = Port()
    service = LoginExtrasService(controller, port, LoginEditorService(controller, port, generate=lambda: "x" * 16))
    return SimpleNamespace(service=service, controller=controller,
                           ref={"source": "credential", "id": entry, "kind": "web"})


def _fields(env):
    return env.controller.session.credential_detail(env.ref["id"])["custom_fields"]


@pytest.mark.parametrize("rows", [
    [{"name": "New", "value": "v", "hidden": False}],  # a page that never loaded the stored rows
    [{"index": 0, "name": "PIN", "value": None, "hidden": True}],  # a stored row left out without saying so
    [],
])
def test_a_save_that_drops_stored_rows_unannounced_is_refused(extras, rows):
    with pytest.raises(ApiError) as changed:
        extras.service.custom_fields_save(extras.ref, rows)
    assert changed.value.code == "changed" and _fields(extras) == FIELDS


def test_removing_every_row_then_adding_one_names_the_removed_rows(extras):
    extras.service.custom_fields_save(extras.ref, [{"name": "New", "value": "v", "hidden": False}], removed=[0, 1])
    assert _fields(extras) == [{"name": "New", "value": "v", "hidden": False}]


def test_a_full_edit_keeps_working(extras):
    extras.service.custom_fields_save(extras.ref, [{"index": 0, "name": "PIN", "value": None, "hidden": True},
                                                   {"index": 1, "name": "Hint", "value": "green", "hidden": False},
                                                   {"name": "Extra", "value": "e", "hidden": True}])
    assert _fields(extras) == [{"name": "PIN", "value": "9999", "hidden": True},
                               {"name": "Hint", "value": "green", "hidden": False},
                               {"name": "Extra", "value": "e", "hidden": True}]
