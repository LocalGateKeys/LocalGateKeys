"""Stage 6a: import and export for the WebView UI, against a real vault and real files."""
from __future__ import annotations

import json
from types import SimpleNamespace

import pytest

from localvault.api.result import ApiError
from localvault.app.controller import WebController
from localvault.app.import_export import ExportService, ImportService
from localvault.profiles import ProfileManager
from localvault.secret_text import SecretText
from localvault.settings import AppSettings

KDF = {"time_cost": 1, "memory_cost_kib": 8192, "parallelism": 1, "hash_len": 32}
MASTER = "correct horse battery"


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
        self.asked, self.answers, self.passwords, self.upgrades = [], [], [], []

    def confirm(self, title, message):
        self.asked.append(title)
        return self.answers.pop(0) if self.answers else True

    def ask_password(self, title, message):
        self.asked.append(title)
        answer = self.passwords.pop(0) if self.passwords else None
        return None if answer is None else SecretText.from_str(answer)

    def notify(self, kind, title, message):
        self.asked.append(title)

    def show_upgrade(self, **kwargs):
        self.upgrades.append(kwargs)


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
    monkeypatch.setattr("localvault.app.controller.clear_master_unlock_requirement", lambda pid: None)
    profiles = ProfileManager(tmp_path / "data")
    profiles.ensure_profile()
    bus = Bus()
    controller = WebController(profiles=profiles, settings=AppSettings(idle_source="vault"), bus=bus,
                               scheduler=Sched(), create_kwargs={"kdf_overrides": KDF})
    controller.create(MASTER, MASTER)
    port, dialogs = Port(), Dialogs()
    return SimpleNamespace(controller=controller, port=port, dialogs=dialogs, bus=bus, tmp=tmp_path,
                           imports=ImportService(controller, port, dialogs, bus),
                           exports=ExportService(controller, port, dialogs))


def _chrome_csv(tmp, rows=2):
    path = tmp / "chrome.csv"
    lines = ["name,url,username,password,note"]
    lines += [f"Site{i},https://site{i}.test,user{i},pw-secret-{i}-12345,note{i}" for i in range(rows)]
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return path


def test_import_review_masks_passwords_and_applies(env):
    env.dialogs.open_path = _chrome_csv(env.tmp)
    opened = env.imports.open()
    assert opened["mapping"] is None and opened["needs_password"] is False
    review = env.imports.plan(opened["handle"], None, None)
    assert len(review["rows"]) == 2 and review["summary"].startswith("Add 2 ")
    assert "pw-secret" not in json.dumps(review)
    result = env.imports.apply(opened["handle"])
    assert result["status"] == "Imported 2 record(s)." and env.port.asked == ["Apply import?"]
    assert ("items.changed", {}) in env.bus.events
    assert "pw-secret" not in json.dumps(env.bus.events)
    with pytest.raises(ApiError):
        env.imports.review(opened["handle"])  # the plan is gone after apply


def test_unknown_csv_needs_a_column_mapping(env):
    path = env.tmp / "custom.csv"
    path.write_text("Col A,Col B,Col C\nAlpha,ann,pw-alpha-123456789\n", encoding="utf-8")
    env.dialogs.open_path = path
    opened = env.imports.open()
    assert opened["mapping"] is not None and "Col C" in opened["mapping"]["columns"]
    with pytest.raises(ApiError) as no_password:
        env.imports.plan(opened["handle"], None, {"title": "Col A"})
    assert no_password.value.message == "Choose the password column (or a notes column for secure notes)."
    with pytest.raises(ApiError) as twice:
        env.imports.plan(opened["handle"], None, {"title": "Col A", "password": "Col A"})
    assert twice.value.message == "Each CSV column can feed only one field."
    review = env.imports.plan(opened["handle"], None, {"title": "Col A", "username": "Col B", "password": "Col C"})
    assert review["rows"][0]["name"] == "Alpha"


def test_decisions_and_declined_apply(env):
    env.dialogs.open_path = _chrome_csv(env.tmp)
    handle = env.imports.open()["handle"]
    env.imports.plan(handle, None, None)
    review = env.imports.decide_all(handle, "skip-all")
    assert review["summary"].startswith("Add 0 ")
    with pytest.raises(ApiError) as nothing:
        env.imports.apply(handle)
    assert nothing.value.message == "Choose Add, Replace or Merge for at least one row."
    env.imports.decide(handle, [review["rows"][0]["row"]], "apply")
    env.port.answers = [False]
    with pytest.raises(ApiError):
        env.imports.apply(handle)
    assert env.controller.session.live_item_count() == 0


def test_cancel_during_apply_writes_nothing(env, monkeypatch):
    env.dialogs.open_path = _chrome_csv(env.tmp, rows=3)
    handle = env.imports.open()["handle"]
    env.imports.plan(handle, None, None)

    def confirm(title, message):
        env.imports.cancel(handle)  # cancel is not possible before apply starts: it closes the import
        return True

    env.port.confirm = confirm
    with pytest.raises(ApiError):
        env.imports.apply(handle)
    assert env.controller.session.live_item_count() == 0


def test_lock_drops_pending_imports(env):
    env.dialogs.open_path = _chrome_csv(env.tmp)
    handle = env.imports.open()["handle"]
    env.imports.plan(handle, None, None)
    env.controller.lock()
    assert env.imports._pending == {}


def test_free_limit_rows_are_not_written(env):
    env.controller.session.item_limit = 1
    env.dialogs.open_path = _chrome_csv(env.tmp, rows=3)
    handle = env.imports.open()["handle"]
    review = env.imports.plan(handle, None, None)
    assert sum(1 for r in review["rows"] if r["decision"] == "needs Pro") == 2
    env.imports.apply(handle)
    assert env.controller.session.live_item_count() == 1
    assert env.port.upgrades


def test_export_kdbx_validation_and_write(env):
    env.controller.session.create_web_login(urls=[{"url": "https://a.test", "match": "exact_origin"}],
                                            username="a", password="pw-123456789012", label="A")
    with pytest.raises(ApiError) as short:
        env.exports.export("kdbx", False, "short", "short")
    assert short.value.message == "The KDBX password needs at least 12 characters."
    env.dialogs.save_path = env.tmp / "out"
    env.port.passwords = [MASTER]
    result = env.exports.export("kdbx", False, "kdbx password 123", "kdbx password 123")
    assert (env.tmp / "out.kdbx").exists() and result["status"] == "Exported 1 record(s)."
    assert env.port.asked == ["Confirm to export passwords", "Export now?"]


def test_plain_export_needs_reauth(env):
    env.dialogs.save_path = env.tmp / "plain.csv"
    with pytest.raises(ApiError) as cancelled:
        env.exports.export("csv", False, "", "")
    assert cancelled.value.code == "cancelled" and env.port.asked == ["Confirm to export passwords"]
    assert not (env.tmp / "plain.csv").exists()
    formats = ExportService.formats("csv", True)
    assert any("plain text" in w for w in formats["warnings"])


def test_cancel_during_the_confirm_is_honoured_by_the_service(env):
    env.dialogs.open_path = _chrome_csv(env.tmp)
    handle = env.imports.open()["handle"]
    env.imports.plan(handle, None, None)

    def confirm(title, message):
        env.imports.cancel(handle)
        return True

    env.port.confirm = confirm
    with pytest.raises(ApiError) as cancelled:
        env.imports.apply(handle)
    assert cancelled.value.code in ("cancelled", "expired")
    assert env.controller.session.live_item_count() == 0


def test_a_plan_built_after_close_is_discarded(env, monkeypatch):
    import localvault.import_workflow as workflow

    env.dialogs.open_path = _chrome_csv(env.tmp)
    handle = env.imports.open()["handle"]
    real = workflow.build_import_plan
    built = []

    def build(*args, **kwargs):
        env.imports.close(handle)  # the sheet closed while the plan was being built
        plan = real(*args, **kwargs)
        built.append(plan)
        return plan

    monkeypatch.setattr(workflow, "build_import_plan", build)
    with pytest.raises(ApiError) as gone:
        env.imports.plan(handle, None, None)
    assert gone.value.code == "expired" and built[0].cancelled
