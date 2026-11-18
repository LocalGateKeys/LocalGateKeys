"""Settings > Developer: key list, agent switch, SSH_AUTH_SOCK and Git setup (registry, broadcast and git all faked)."""
from __future__ import annotations

import threading
from pathlib import Path

import pytest

from localvault import dev_setup
from localvault.api.result import ApiError
from localvault.app import developer
from localvault.app.controller import WebController
from localvault.app.developer import GIT_KEYS, DeveloperService
from localvault.profiles import ProfileManager
from localvault.settings import AppSettings
from test_dev_setup import FakeGit, FakeRegistry, FakeUser32

KDF = {"time_cost": 1, "memory_cost_kib": 8192, "parallelism": 1, "hash_len": 32}
MASTER = "correct horse battery"
VECTORS = Path(__file__).parent / "vectors" / "ssh"
PIPE = r"\\.\pipe\localgatekeys-ssh-S-1-5-TEST"


class Bus:
    def __init__(self):
        self.events = []

    def emit(self, name, detail):
        self.events.append(name)


class Sched:
    def call_later(self, delay, fn):
        return fn

    def cancel(self, handle):
        pass


class Clipboard:
    timeout_seconds = 30
    value = None

    def copy(self, text):
        self.value = text


class Port:
    def __init__(self):
        self.upgrades = []

    def show_upgrade(self, *, limit, message, on_enter):
        self.upgrades.append(limit)


def _vector(name):
    return (VECTORS / name).read_text(encoding="utf-8")


@pytest.fixture
def env(tmp_path, monkeypatch):
    monkeypatch.setattr("localvault.app.controller.clear_master_unlock_requirement", lambda _pid: None)
    monkeypatch.setattr("localvault.settings.settings_path", lambda: tmp_path / "settings.json")
    profiles = ProfileManager(tmp_path / "data")
    profiles.ensure_profile()
    bus = Bus()
    controller = WebController(profiles=profiles, settings=AppSettings(idle_source="vault"), bus=bus,
                               scheduler=Sched(), create_kwargs={"kdf_overrides": KDF})
    controller.create(MASTER, MASTER)
    controller.clipboard = Clipboard()
    registry, user32 = FakeRegistry({"PATH": "x"}), FakeUser32()
    git = FakeGit({"user.name": "A"})
    monkeypatch.setattr(dev_setup, "_registry", lambda: registry)
    monkeypatch.setattr(dev_setup, "_user32", lambda: user32)
    monkeypatch.setattr(dev_setup.subprocess, "run", git)
    service = DeveloperService(controller, Port(), pipe=lambda: PIPE, spawn=lambda fn: fn())
    service.registry, service.user32, service.git, service.bus = registry, user32, git, bus
    return service, controller


def _add(controller, title, key_file, **extra):
    return controller.session.item_service.create_ssh_key(title, private_key=_vector(key_file), **extra)


def _key(status, item_id):
    return next(row for row in status["keys"] if row["id"] == item_id)


def test_env_apply_saves_previous_and_broadcasts(env):
    service, controller = env
    service.registry.values["SSH_AUTH_SOCK"] = "old-sock"
    service.env_apply()
    assert service.registry.values["SSH_AUTH_SOCK"] == PIPE
    assert controller.settings.developer_saved_env == {"SSH_AUTH_SOCK": {"previous": "old-sock", "applied": PIPE}}
    assert service.user32.calls and service.user32.calls[-1][3] == "Environment"
    assert service.status()["env"] == {"name": "SSH_AUTH_SOCK", "current": PIPE, "pipe": PIPE, "applied": True}
    service.env_apply()  # a second Apply keeps the first previous value
    assert controller.settings.developer_saved_env["SSH_AUTH_SOCK"]["previous"] == "old-sock"


def test_env_undo_restores_previous(env):
    service, controller = env
    service.registry.values["SSH_AUTH_SOCK"] = "old-sock"
    service.env_apply()
    calls = len(service.user32.calls)
    service.env_undo()
    assert service.registry.values["SSH_AUTH_SOCK"] == "old-sock"
    assert controller.settings.developer_saved_env == {}
    assert len(service.user32.calls) == calls + 1


def test_env_undo_deletes_when_previous_none(env):
    service, controller = env
    service.env_apply()
    assert controller.settings.developer_saved_env["SSH_AUTH_SOCK"]["previous"] is None
    service.env_undo()
    assert "SSH_AUTH_SOCK" not in service.registry.values
    assert service.registry.values["PATH"] == "x"
    with pytest.raises(ApiError):
        service.env_undo()  # nothing left to undo


def test_pipe_taken_by_another_account_removes_and_running_restores_env(env):
    """F2: another account holds the pipe name: SSH_AUTH_SOCK goes; a proper start puts it back."""
    service, controller = env
    service.registry.values["SSH_AUTH_SOCK"] = "old-sock"
    service.env_apply()
    service.agent_pipe_status("unavailable")  # this user's own process: left alone
    assert service.registry.values["SSH_AUTH_SOCK"] == PIPE
    service.agent_pipe_status("taken")
    assert "SSH_AUTH_SOCK" not in service.registry.values
    assert controller.settings.developer_saved_env["SSH_AUTH_SOCK"]["suspended"] is True
    service.agent_pipe_status("taken")  # again: nothing more to do
    service.agent_pipe_status("running")
    assert service.registry.values["SSH_AUTH_SOCK"] == PIPE
    assert controller.settings.developer_saved_env == {"SSH_AUTH_SOCK": {"previous": "old-sock", "applied": PIPE}}
    # Undo while removed still restores the previous value.
    service.agent_pipe_status("taken")
    service.env_undo()
    assert service.registry.values["SSH_AUTH_SOCK"] == "old-sock"


def test_pipe_taken_leaves_a_value_the_user_changed(env):
    service, controller = env
    service.env_apply()
    service.registry.values["SSH_AUTH_SOCK"] = "changed-by-user"
    service.agent_pipe_status("taken")
    assert service.registry.values["SSH_AUTH_SOCK"] == "changed-by-user"
    assert "suspended" not in controller.settings.developer_saved_env["SSH_AUTH_SOCK"]


def test_env_undo_leaves_a_value_the_user_changed_since(env):
    service, controller = env
    service.env_apply()
    service.registry.values["SSH_AUTH_SOCK"] = "changed-by-user"
    service.env_undo()
    assert service.registry.values["SSH_AUTH_SOCK"] == "changed-by-user"
    assert controller.settings.developer_saved_env == {}


def test_git_plan_shows_current_and_new(env):
    service, controller = env
    item_id = service.generate_key("Work")["id"]
    service.git.config["gpg.format"] = "openpgp"
    plan = service.git_plan(item_id)
    assert [key for key, _c, _n in plan] == list(GIT_KEYS)
    by_key = {key: (current, new) for key, current, new in plan}
    assert by_key["gpg.format"] == ("openpgp", "ssh")
    assert by_key["core.sshCommand"] == (None, "C:/Windows/System32/OpenSSH/ssh.exe")
    assert by_key["gpg.ssh.program"][1] == "C:/Windows/System32/OpenSSH/ssh-keygen.exe"
    assert by_key["commit.gpgsign"] == (None, "true")
    public = controller.session.item_service.get_item(item_id)["payload"]["public_key"].split()
    assert by_key["user.signingkey"][1] == f"key::{public[0]} {public[1]}"  # no comment
    assert service.git.config["gpg.format"] == "openpgp"  # a preview changes nothing
    assert service.git_preview(item_id)["rows"][1] == {"key": "gpg.format", "current": "openpgp", "new": "ssh"}


def test_git_apply_then_undo_restores(env):
    service, controller = env
    item_id = service.generate_key("Work")["id"]
    service.git.config["gpg.format"] = "openpgp"
    service.git_apply(item_id)
    assert service.git.config["gpg.format"] == "ssh" and service.git.config["commit.gpgsign"] == "true"
    assert service.git.config["user.signingkey"].startswith("key::ssh-ed25519 ")
    assert service.git.config["user.name"] == "A"
    assert controller.settings.developer_saved_git["gpg.format"] == {"previous": "openpgp", "applied": "ssh"}
    assert service.status()["git"] == {"available": True, "signing_ok": True, "version": "2.50", "applied": True}
    service.git_undo()
    assert service.git.config == {"user.name": "A", "gpg.format": "openpgp"}
    assert controller.settings.developer_saved_git == {}
    with pytest.raises(ApiError):
        service.git_undo()


def test_git_undo_keeps_values_changed_since(env):
    service, controller = env
    item_id = service.generate_key("Work")["id"]
    service.git_apply(item_id)
    service.git.config["commit.gpgsign"] = "false"  # the user turned it off by hand
    service.git_undo()
    assert service.git.config["commit.gpgsign"] == "false"
    assert "gpg.format" not in service.git.config


def test_git_apply_failure_rolls_back(env, monkeypatch):
    service, controller = env
    item_id = service.generate_key("Work")["id"]
    real = dev_setup.git_config_set

    def flaky(key, value):
        if key == "user.signingkey" and value is not None and value.startswith("key::"):
            raise dev_setup.DevSetupError("git_failed")
        real(key, value)

    monkeypatch.setattr(dev_setup, "git_config_set", flaky)
    with pytest.raises(ApiError):
        service.git_apply(item_id)
    assert service.git.config == {"user.name": "A"}
    assert controller.settings.developer_saved_git == {}


def test_git_missing_reports_unavailable(env, monkeypatch):
    service, _controller = env
    item_id = service.generate_key("Work")["id"]
    monkeypatch.setattr(dev_setup.subprocess, "run", FakeGit(missing=True))
    assert service.status()["git"]["available"] is False
    with pytest.raises(ApiError) as info:
        service.git_plan(item_id)
    assert "git" in str(info.value).lower()
    with pytest.raises(ApiError):
        service.git_apply(item_id)


def test_git_plan_needs_an_offered_usable_key(env):
    service, controller = env
    plain = _add(controller, "Plain", "ed25519.key")
    with pytest.raises(ApiError):
        service.git_plan(plain)  # not offered to the agent yet
    putty = _add(controller, "Putty", "putty.ppk")
    with pytest.raises(ApiError):
        service.git_plan(putty)


def test_generate_key_creates_ssh_item_and_allowlists(env):
    service, controller = env
    result = service.generate_key("Laptop key")
    item = controller.session.item_service.get_item(result["id"])
    assert item["kind"] == "ssh_key" and item["title"] == "Laptop key"
    assert item["payload"]["public_key"] == result["public_key"]
    assert result["public_key"].startswith("ssh-ed25519 ") and result["public_key"].endswith(" Laptop key")
    assert controller.settings.developer_ssh_keys == [result["id"]]
    row = _key(service.status(), result["id"])
    assert row["state"] == "ok" and row["offered"] is True and row["fingerprint"].startswith("SHA256:")
    assert "items.changed" in service.bus.events
    assert result["id"] in AppSettings.load().developer_ssh_keys  # saved to disk too
    assert service.generate_key("")["id"] != result["id"]  # a default title


def test_generate_key_respects_the_item_limit(env):
    service, controller = env
    controller.session.item_limit = 0
    with pytest.raises(ApiError) as info:
        service.generate_key("x")
    assert info.value.code == "item_limit"
    assert service._port.upgrades == [0]
    assert controller.settings.developer_ssh_keys == []


def test_toggle_key_updates_allowlist(env):
    service, controller = env
    item_id = _add(controller, "Plain", "ed25519.key")
    assert _key(service.status(), item_id)["offered"] is False
    service.toggle_key(item_id, True)
    assert controller.settings.developer_ssh_keys == [item_id]
    assert _key(service.status(), item_id)["offered"] is True
    assert AppSettings.load().developer_ssh_keys == [item_id]
    service.toggle_key(item_id, True)  # idempotent
    assert controller.settings.developer_ssh_keys == [item_id]
    service.toggle_key(item_id, False)
    assert controller.settings.developer_ssh_keys == []
    with pytest.raises(ApiError):
        service.toggle_key("no-such-item", True)


def test_toggle_on_refuses_keys_the_agent_cannot_use(env):
    service, controller = env
    encrypted = _add(controller, "Locked", "ed25519_enc.key")
    putty = _add(controller, "Putty", "putty.ppk")
    for item_id in (encrypted, putty):
        with pytest.raises(ApiError):
            service.toggle_key(item_id, True)
    assert controller.settings.developer_ssh_keys == []


def test_status_lists_unsupported_keys_with_reason(env):
    service, controller = env
    controller.session.item_limit = None  # six items: more than the free plan holds
    ok_id = _add(controller, "Plain", "ed25519.key")
    needs = _add(controller, "Locked", "ed25519_enc.key")
    with_pass = _add(controller, "Locked with pass", "ed25519_enc.key", passphrase="vector-pass")
    putty = _add(controller, "Putty", "putty.ppk")
    sk = _add(controller, "Hardware", "sk_ed25519.key")
    rsa = _add(controller, "RSA", "rsa3072.key")
    status = service.status()
    titles = ["Plain", "Locked", "Locked with pass", "Putty", "Hardware", "RSA"]
    assert [row["title"] for row in status["keys"]] == sorted(titles, key=str.casefold)
    assert _key(status, ok_id)["state"] == "ok"
    assert _key(status, rsa)["state"] == "ok"
    assert _key(status, with_pass)["state"] == "ok"
    assert _key(status, needs)["state"] == "needs_passphrase"
    for item_id, word in ((putty, "putty"), (sk, "hardware")):
        row = _key(status, item_id)
        assert row["state"] == "unsupported" and word in row["reason"].lower()
    assert status["agent"] == {"enabled": False, "status": "off"}


def test_status_does_not_run_the_kdf(env, monkeypatch):
    service, controller = env
    _add(controller, "Locked with pass", "ed25519_enc.key", passphrase="vector-pass")
    real = developer.load_private_key
    seen = []
    monkeypatch.setattr(developer, "load_private_key",
                        lambda text, passphrase: seen.append(passphrase) or real(text, passphrase))
    service.status()
    assert seen == []  # a stored passphrase is never tried by the list


def test_set_agent_saves_and_applies(env):
    service, controller = env
    applied = []
    service.apply_agent = lambda: applied.append(controller.settings.developer_ssh_agent) or "running"
    service.agent_status = lambda: "running"
    result = service.set_agent(True)
    assert result["enabled"] is True
    assert applied == [True] and "developer.changed" in service.bus.events
    assert AppSettings.load().developer_ssh_agent is True
    assert service.status()["agent"] == {"enabled": True, "status": "running"}
    service.set_agent(False)
    assert applied == [True, False]


def test_set_agent_uses_a_background_thread_by_default(env):
    service, controller = env
    done = threading.Event()
    where = []
    service.apply_agent = lambda: where.append(threading.current_thread()) or done.set()
    service._spawn = developer._start_thread
    service.set_agent(True)
    assert done.wait(5) and where[0] is not threading.current_thread()


def test_copy_public_key(env):
    service, controller = env
    result = service.generate_key("Work")
    out = service.copy_public_key(result["id"])
    assert controller.clipboard.value == result["public_key"]
    assert "message" in out
    plain = _add(controller, "Putty", "putty.ppk")
    with pytest.raises(ApiError):
        service.copy_public_key(plain)  # no public half


def test_locked_vault_is_refused(env):
    service, controller = env
    controller.lock("test")
    for call in (service.status, service.env_apply, service.env_undo, service.git_undo):
        with pytest.raises(ApiError) as info:
            call()
        assert info.value.code == "locked"


def test_env_apply_saves_nothing_when_the_registry_write_fails(env, monkeypatch):
    service, controller = env

    def refuse(name, value):
        raise dev_setup.DevSetupError("env_failed")

    monkeypatch.setattr(dev_setup, "set_user_env", refuse)
    with pytest.raises(ApiError):
        service.env_apply()
    assert controller.settings.developer_saved_env == {}
    assert service.status()["env"]["applied"] is False


def test_git_older_than_2_34_cannot_sign(env, monkeypatch):
    service, controller = env
    item_id = service.generate_key("Work")["id"]
    monkeypatch.setattr(dev_setup.subprocess, "run", FakeGit(version="2.33.1.windows.1"))
    git = service.status()["git"]
    assert git["available"] is True and git["signing_ok"] is False and git["version"] == "2.33"
    with pytest.raises(ApiError) as info:
        service.git_plan(item_id)
    assert "2.33" in str(info.value)
    with pytest.raises(ApiError):
        service.git_apply(item_id)
    assert controller.settings.developer_saved_git == {}
    monkeypatch.setattr(dev_setup.subprocess, "run", FakeGit(version="2.34.0"))
    assert service.status()["git"]["signing_ok"] is True
    assert service.git_plan(item_id)


def _login(controller, label, strict=False):
    return controller.session.create_web_login(
        urls=[{"url": "https://" + label.lower() + ".test", "match": "exact_origin"}], username="u", password="pw-1234567890",
        label=label, policy={"fill": "ask", "sign_in": False, "require_master_password": strict, "save_prompts": True})


def test_agent_item_switch_only_for_items_that_hold_secrets(env):
    service, controller = env
    note = controller.session.item_service.create_note("Router", "x")
    login = _login(controller, "Plain")
    assert service.agent_item(note) == {"available": True, "allowed": False}
    assert service.agent_item(login) == {"available": False, "allowed": False}
    assert service.set_agent_item(note, True) == {"allowed": True}
    assert controller.settings.agent_items == [note] and service.agent_item(note)["allowed"] is True
    with pytest.raises(ApiError):
        service.set_agent_item(login, True)  # logins have their own per-login switch
    with pytest.raises(ApiError):
        service.set_agent_item("nope", True)
    service.set_agent_item(note, False)
    assert controller.settings.agent_items == []


def test_recent_agent_runs_one_row_per_run_newest_first(env):
    from localvault.agent_run_log import AgentRunLog, run_log_path

    service, controller = env
    note = controller.session.item_service.create_note("Router", "x")
    log = AgentRunLog(lambda: run_log_path(controller))
    base = {"agent": "Claude Code", "process": "claude.exe", "command": "deploy.exe --prod", "cwd": "C:\\w",
            "purpose": "deploy", "timeout": 120, "items": [{"variable": "DB", "item_id": note, "field": "body"}]}
    log.append({**base, "run": "r1", "stage": "approved"})
    log.append({**base, "run": "r1", "stage": "finished", "result": "ok", "exit_code": 0})
    log.append({**base, "run": "r2", "stage": "denied"})
    runs = service.status()["agents"]["runs"]
    assert [run["stage"] for run in runs] == ["denied", "finished"]
    assert runs[1]["exit_code"] == 0 and runs[1]["command"] == "deploy.exe --prod"
    assert runs[1]["items"] == [{"variable": "DB", "field": "body", "title": "Router"}]


def test_cli_toggle(env):
    service, controller = env
    assert service.status()["cli"]["enabled"] is False
    assert service.set_cli(True) == {"enabled": True}
    assert controller.settings.developer_cli is True and service.cli_enabled() == {"enabled": True}
    assert service.status()["cli"]["enabled"] is True
    service.set_cli(False)
    assert controller.settings.developer_cli is False


def test_cli_is_available_in_the_store_package(env, monkeypatch):
    # The Store package runs lgk as `LocalGateKeysNativeHost.exe lgk ...` (one execution alias).
    from localvault import distribution

    service, controller = env
    assert service.status()["cli"]["packaged"] is False
    monkeypatch.setattr(distribution, "is_packaged", lambda: True)
    assert service.set_cli(True) == {"enabled": True}
    cli = service.status()["cli"]
    assert cli["enabled"] is True and cli["available"] is True and cli["packaged"] is True


def test_cli_item_allowlist(env):
    service, controller = env
    plain, strict = _login(controller, "Plain"), _login(controller, "Bank", strict=True)
    note = controller.session.item_service.create_note("Router", "x")
    rows = {row["id"]: row for row in service.status()["cli"]["items"]}
    assert rows[plain]["strict"] is False and rows[strict]["strict"] is True and rows[note]["kind"] == "note"
    assert all(row["listed"] is False for row in rows.values())
    service.toggle_cli_item(plain, True)
    service.toggle_cli_item(note, True)
    assert controller.settings.developer_cli_items == [plain, note]
    with pytest.raises(ApiError):
        service.toggle_cli_item(strict, True)  # a strict login cannot be listed
    with pytest.raises(ApiError):
        service.toggle_cli_item("nope", True)
    service.toggle_cli_item(plain, False)
    assert controller.settings.developer_cli_items == [note]


def test_copy_reference_format(env):
    service, controller = env
    from localvault import lgk_refs

    login = _login(controller, "Plain")
    result = service.copy_reference(login, "password")
    assert controller.clipboard.value == f"lgk://{login}/password"
    assert result["message"]
    assert lgk_refs.parse(controller.clipboard.value) == lgk_refs.Ref(login, "password")
    service.copy_reference(login)  # no field: a login's password
    assert controller.clipboard.value.endswith("/password")
    note = controller.session.item_service.create_note("Router", "x")
    service.copy_reference(note, "notes")
    assert lgk_refs.parse(controller.clipboard.value) == lgk_refs.Ref(note, "notes")
    with pytest.raises(ApiError):
        service.copy_reference("missing", "password")
    assert "pw-1234567890" not in controller.clipboard.value


def test_copy_reference_round_trips_awkward_ids(env, monkeypatch):
    service, controller = env
    from localvault import lgk_refs

    login = _login(controller, "Plain")
    monkeypatch.setattr(controller.session, "get_entry", lambda item_id: {"x": 1})
    for odd in ("a/b c%d", "ünï", "x?y#z"):
        service.copy_reference(odd, "pass word")
        assert lgk_refs.parse(controller.clipboard.value) == lgk_refs.Ref(odd, "pass word")
    assert login
