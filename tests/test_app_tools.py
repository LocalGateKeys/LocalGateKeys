"""Stage 2: password generator and command palette services for the WebView UI."""
from __future__ import annotations

import pytest

from localvault.api.result import ApiError
from localvault.app.controller import WebController
from localvault.app.tools import GeneratorService, PaletteService
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


class FakeClipboard:
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
    settings = AppSettings(auto_lock_seconds=300, idle_source="vault")
    saved = []
    monkeypatch.setattr(settings, "save", lambda *a, **k: saved.append(dict(settings.generator_preferences or {})))
    controller = WebController(profiles=profiles, settings=settings, bus=Bus(), scheduler=Sched(),
                               create_kwargs={"kdf_overrides": KDF})
    controller.create(MASTER, MASTER)
    controller.clipboard = FakeClipboard()
    controller.session.create_web_login(urls=[{"url": "https://github.test", "match": "exact_origin"}],
                                        username="octo", password="pw-github-1234567", label="GitHub")
    return controller, saved


def test_generator_round_trip_and_persistence(env):
    controller, saved = env
    generator = GeneratorService(controller)
    options = generator.get()["options"]
    assert options["mode"] == "password" and options["length"] == 20
    result = generator.generate({**options, "length": 32, "symbols": False})
    assert len(result["value"]) == 32 and not any(c in result["value"] for c in "!@#$%^&*")
    assert result["health"].endswith("· Local estimate, not a security guarantee")
    assert saved[-1]["length"] == 32


def test_passphrase_health_text(env):
    controller, _saved = env
    result = GeneratorService(controller).generate({"mode": "passphrase", "words": 5, "separator": "dash"})
    assert result["value"].count("-") >= 4
    assert result["health"].startswith("5 randomly selected words · about ")


def test_generator_rejects_empty_groups(env):
    controller, _saved = env
    with pytest.raises(ApiError) as bad:
        GeneratorService(controller).generate({"mode": "password", "lowercase": False, "uppercase": False,
                                               "digits": False, "symbols": False})
    assert bad.value.code == "invalid"


def test_generator_copy_message(env):
    controller, _saved = env
    message = GeneratorService(controller).copy("abc-123")["message"]
    assert message == "Generated password copied. Clipboard clears in 30 seconds."
    assert controller.clipboard.value == "abc-123"


def test_username_word(env):
    controller, _saved = env
    assert GeneratorService(controller).username("word")["value"]


def test_palette_ranking_and_prefixes(env):
    controller, _saved = env
    palette = PaletteService(controller)
    rows = palette.query("git", "everything")["rows"]
    assert any(r["kind"] == "item" and r["title"] == "GitHub" and r["ref"]["source"] == "credential" for r in rows)
    actions = palette.query(">lock", "everything")["rows"]
    assert actions and all(r["kind"] == "command" for r in actions)
    assert actions[0]["command_id"] == "lock-now"


def test_palette_run_lock_and_navigate(env):
    controller, _saved = env
    palette = PaletteService(controller)
    assert palette.run("generate-password") == {"navigate": "generator"}
    assert palette.run("settings-locking") == {"navigate": "settings", "section": "locking"}
    assert palette.run("lock-now") == {"done": "Vault locked."}
    assert not controller.is_unlocked()
    with pytest.raises(ApiError) as unknown:
        palette.run("no-such-command")
    assert unknown.value.code == "not_found"


def test_palette_locked_shows_only_unlock_free_commands(env):
    controller, _saved = env
    controller.lock()
    rows = PaletteService(controller).query("", "everything")["rows"]
    ids = {r["command_id"] for r in rows}
    assert "lock-now" not in ids and "switch-profile" in ids


def test_palette_routes_security_commands(env, monkeypatch):
    controller = env[0] if isinstance(env, tuple) else env
    marks = []
    monkeypatch.setattr("localvault.app.lockmodes.require_master_unlock", lambda pid: marks.append(pid) or True)
    palette = PaletteService(controller)
    assert palette.run("security-center") == {"navigate": "security"}
    assert palette.run("change-master") == {"navigate": "master"}
    assert palette.run("backup-restore") == {"navigate": "recovery", "initial": "restore"}
    assert palette.run("backup-now") == {"navigate": "recovery", "initial": "create"}
    palette.run("emergency-lock")
    assert not controller.is_unlocked() and marks
