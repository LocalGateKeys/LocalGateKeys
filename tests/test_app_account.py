"""Stage 5a: licence, updates, profiles and browser connections for the WebView UI."""
from __future__ import annotations

from types import SimpleNamespace

import pytest

from localvault import licensing
from localvault.api.result import ApiError
from localvault.app.connections import ConnectionsService
from localvault.app.controller import WebController
from localvault.app.licence import LicenceService
from localvault.app.profiles import ProfilesService
from localvault.app.updates import UpdatesService
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
        self.asked.append(title)
        return self.answers.pop(0) if self.answers else True


class Dialogs:
    def __init__(self, path=None):
        self.path = path

    def open_file(self, title):
        return self.path

    def save_file(self, title, name):
        return self.path


@pytest.fixture
def env(tmp_path, monkeypatch):
    monkeypatch.setattr("localvault.app.controller.clear_master_unlock_requirement", lambda pid: None)
    monkeypatch.setattr(AppSettings, "save", lambda self, path=None: None)
    profiles = ProfileManager(tmp_path / "data")
    profiles.ensure_profile()
    controller = WebController(profiles=profiles, settings=AppSettings(idle_source="vault"), bus=Bus(),
                               scheduler=Sched(), create_kwargs={"kdf_overrides": KDF})
    controller.create(MASTER, MASTER)
    return SimpleNamespace(controller=controller, port=Port(), tmp=tmp_path)


def _free(monkeypatch):
    st = licensing.LicenseStatus("free", None, "")
    monkeypatch.setattr(licensing, "status", lambda *a, **k: st)
    monkeypatch.setattr(licensing, "item_limit", lambda st=None: 4)
    monkeypatch.setattr(licensing, "reconcile_vault_copy", lambda session: None)


# ----------------------------------------------------------------- licence
def test_unlock_applies_the_free_item_limit(env, monkeypatch):
    _free(monkeypatch)
    LicenceService(env.controller, env.port, Dialogs())
    env.controller.lock()
    env.controller.unlock(MASTER)
    assert env.controller.session.item_limit == 4


def test_licence_view_and_install_errors(env, monkeypatch):
    _free(monkeypatch)
    service = LicenceService(env.controller, env.port, Dialogs())
    view = service.view()
    assert view["headline"] == "Free" and view["pitch"].startswith("LocalGateKeys Pro")
    with pytest.raises(ApiError) as empty:
        service.install("   ")
    assert empty.value.code == "invalid"

    def bad(text):
        raise licensing.LicenseError("This licence key is not valid.", reason="bad_signature")

    monkeypatch.setattr(licensing, "install_license", bad)
    with pytest.raises(ApiError) as invalid:
        service.install("LGK1-xyz")
    assert invalid.value.message == "This licence key is not valid."


def test_licence_install_reapplies_the_limit(env, monkeypatch):
    _free(monkeypatch)
    service = LicenceService(env.controller, env.port, Dialogs())
    monkeypatch.setattr(licensing, "install_license", lambda text: SimpleNamespace(name="Ann"))
    monkeypatch.setattr(licensing, "status", lambda *a, **k: licensing.LicenseStatus("pro", None, ""))
    monkeypatch.setattr(licensing, "item_limit", lambda st=None: None)
    assert service.install("LGK1-ok")["message"] == "Licence installed for Ann."
    assert env.controller.session.item_limit is None


def test_licence_file_and_remove(env, monkeypatch):
    _free(monkeypatch)
    key = env.tmp / "license.lgklicense"
    key.write_text("LGK1-from-file", encoding="utf-8")
    seen, removed = [], []
    monkeypatch.setattr(licensing, "install_license", lambda text: seen.append(text) or SimpleNamespace(name="Ann"))
    monkeypatch.setattr(licensing, "remove_license", lambda: removed.append(1))
    service = LicenceService(env.controller, env.port, Dialogs(key))
    service.install_file()
    assert seen == ["LGK1-from-file"]
    env.port.answers = [False]
    with pytest.raises(ApiError):
        service.remove()
    assert removed == [] and env.port.asked == ["Remove licence"]
    service.remove()
    assert removed == [1]


# ----------------------------------------------------------------- updates
def test_update_check_respects_strict_offline(env, monkeypatch):
    env.controller.settings.strict_offline_mode = True
    calls = []
    service = UpdatesService(env.controller, env.port, configuration=lambda: object(),
                             check=lambda: calls.append(1) or SimpleNamespace(current_version="1.0", latest_version="1.0",
                                                                               published="2026-10-01", is_newer=False))
    env.port.answers = [False]
    with pytest.raises(ApiError):
        service.check()
    assert calls == [] and env.port.asked == ["Strict offline mode is on"]
    result = service.check()
    assert result["message"] == "LocalGateKeys is up to date. Current version: 1.0."


def test_update_available_and_not_configured(env, monkeypatch):
    env.controller.settings.strict_offline_mode = False
    newer = SimpleNamespace(current_version="1.0", latest_version="1.1", published="2026-10-01", is_newer=True)
    service = UpdatesService(env.controller, env.port, configuration=lambda: object(), check=lambda: newer)
    result = service.check()
    assert result["available"] is True and result["latest"] == "1.1"
    service = UpdatesService(env.controller, env.port, configuration=lambda: None, check=lambda: newer,
                             managed=lambda: None)
    assert service.check()["message"] == ("Update checks are not configured yet. Release hosting has not been "
                                          "published.")


def test_one_update_check_at_a_time(env):
    env.controller.settings.strict_offline_mode = False
    service = UpdatesService(env.controller, env.port, configuration=lambda: object(), check=lambda: None)
    service._in_flight.acquire()
    with pytest.raises(ApiError) as busy:
        service.check()
    assert busy.value.code == "busy"


# ---------------------------------------------------------------- profiles
def test_profiles_create_rename_and_delete(env):
    service = ProfilesService(env.controller, env.port, Dialogs())
    created = service.create("Work")
    names = [p["name"] for p in service.list()["profiles"]]
    assert "Work" in names and created["profile"]["initials"]
    service.update(created["profile"]["id"], name="Office", color="#3B82F6")
    assert "Office" in [p["name"] for p in service.list()["profiles"]]
    env.port.answers = [False]
    with pytest.raises(ApiError):
        service.delete(created["profile"]["id"])
    service.delete(created["profile"]["id"])
    assert "Office" not in [p["name"] for p in service.list()["profiles"]]
    assert env.port.asked == ["Remove profile", "Remove profile"]


def test_deleting_the_active_profile_locks_first(env):
    service = ProfilesService(env.controller, env.port, Dialogs())
    other = service.create("Second")["profile"]["id"]
    active = env.controller.profiles.active_profile().id
    service.delete(active)
    assert not env.controller.is_unlocked()
    assert env.controller.profiles.active_profile().id == other


def test_the_only_profile_cannot_be_deleted(env):
    service = ProfilesService(env.controller, env.port, Dialogs())
    with pytest.raises(ApiError) as only:
        service.delete(env.controller.profiles.active_profile().id)
    assert only.value.message == "Create another profile before deleting the only profile"
    assert env.controller.is_unlocked()


# ------------------------------------------------------------- connections
def test_connections_headline_and_repair(env, monkeypatch):
    report = {"windows": True, "configured": True, "native_host_exists": True, "native_host_hash_matches": True,
              "registration": {"Chrome": "ready", "Edge": "manifest_mismatch"}, "extension_recent": False}
    repaired = []
    service = ConnectionsService(env.port, Dialogs(env.tmp / "report.json"), collect=lambda **kw: report,
                                 repair=lambda: repaired.append(1))
    view = service.view()
    assert view["headline"] == "Bridge is ready" and view["status"] == "Waiting for extension"
    assert {"browser": "Edge", "state": "Needs repair", "ok": False} in view["browsers"]
    assert service.repair()["title"] == "Browser connection repaired" and repaired
    service.export()
    assert (env.tmp / "report.json").read_text(encoding="utf-8").startswith("{")


# ------------------------------------------------------------ review fixes
def test_failed_delete_of_active_profile_still_refreshes(env, monkeypatch):
    service = ProfilesService(env.controller, env.port, Dialogs())
    service.create("Second")
    published = []
    original = env.controller._publish
    monkeypatch.setattr(env.controller, "_publish", lambda: published.append(1) or original())

    def busy(pid):
        raise OSError("file in use")

    monkeypatch.setattr(env.controller.profiles, "delete_profile", busy)
    with pytest.raises(ApiError):
        service.delete(env.controller.profiles.active_profile().id)
    assert published


def test_profile_changes_need_an_unlocked_vault(env):
    service = ProfilesService(env.controller, env.port, Dialogs())
    other = service.create("Second")["profile"]["id"]
    env.controller.lock()
    for call in (lambda: service.update(other, name="X"), lambda: service.delete(other),
                 lambda: service.photo(other), lambda: service.remove_photo(other)):
        with pytest.raises(ApiError) as locked:
            call()
        assert locked.value.code == "locked"


def test_a_profile_can_be_added_from_the_lock_screen(env):
    service = ProfilesService(env.controller, env.port, Dialogs())
    env.controller.lock()
    added = service.create("Third")["profile"]
    assert not added["active"]
    assert "Third" in [p["name"] for p in service.list()["profiles"]]
    assert not env.controller.is_unlocked()
    # Choosing it opens the create-vault screen: it has no vault yet.
    assert env.controller.select_profile(added["id"])["vault_exists"] is False


def test_licence_install_while_locked_skips_the_vault_copy(env, monkeypatch):
    _free(monkeypatch)
    touched = []
    monkeypatch.setattr(licensing, "reconcile_vault_copy", lambda session: touched.append(session))
    monkeypatch.setattr(licensing, "install_license", lambda text: SimpleNamespace(name="Ann"))
    service = LicenceService(env.controller, env.port, Dialogs())
    env.controller.lock()
    service.install("LGK1-ok")
    assert touched == []


def test_licence_install_after_a_lock_mid_call_writes_nothing(env, monkeypatch):
    _free(monkeypatch)
    touched = []
    monkeypatch.setattr(licensing, "reconcile_vault_copy", lambda session: touched.append(session))

    def install(text):
        env.controller.lock()  # the vault locks while the licence is being installed
        return SimpleNamespace(name="Ann")

    monkeypatch.setattr(licensing, "install_license", install)
    LicenceService(env.controller, env.port, Dialogs()).install("LGK1-ok")
    assert touched == []


def test_update_check_refreshes_the_revocation_list_and_hides_its_failure(env, monkeypatch):
    env.controller.settings.strict_offline_mode = False
    same = SimpleNamespace(current_version="1.0", latest_version="1.0", published="2026-10-01", is_newer=False)
    fetched = []
    service = UpdatesService(env.controller, env.port, configuration=lambda: object(), check=lambda: same,
                             revocations=lambda: fetched.append(1))
    service.check()
    assert fetched == [1]

    def broken():
        raise RuntimeError("feed down")
    logged = []
    monkeypatch.setattr("localvault.error_log.log_exception", lambda tag, exc: logged.append(tag))
    service = UpdatesService(env.controller, env.port, configuration=lambda: object(), check=lambda: same,
                             revocations=broken)
    assert service.check()["available"] is False  # the cached list stays in force; nothing surfaces
    assert logged == ["revocation-fetch"]


def test_old_build_reminder_is_offline_and_snoozes(env, monkeypatch):
    import localvault.updates as updates_module
    monkeypatch.setattr(updates_module, "build_age_days", lambda: 200)
    monkeypatch.setattr(updates_module, "update_reminder_due", lambda snoozed: not snoozed)
    monkeypatch.setattr(updates_module, "reminder_snooze_date", lambda: "2026-11-17")
    monkeypatch.setattr(type(env.controller.settings), "save", lambda self, *a, **k: None)
    calls = []
    service = UpdatesService(env.controller, env.port, configuration=lambda: object(),
                             check=lambda: calls.append(1))
    env.controller.settings.update_reminder_snoozed_until = ""
    due = service.reminder()
    assert due["due"] is True and "200 days old" in due["text"] and calls == []  # deciding uses no network
    service.snooze()
    assert env.controller.settings.update_reminder_snoozed_until == "2026-11-17"
    assert service.reminder() == {"due": False}
    assert UpdatesService(env.controller, env.port, configuration=lambda: None).reminder() == {"due": False}


def test_camera_unlock_refusal_comes_before_the_confirm_and_the_lock(env):
    from localvault.face_unlock import envelope_path
    from localvault.profiles import CAMERA_UNLOCK_BLOCKS_DELETE

    service = ProfilesService(env.controller, env.port, Dialogs())
    other = service.create("Second")["profile"]["id"]
    profiles = env.controller.profiles
    active = profiles.active_profile().id
    for profile_id in (active, other):
        envelope_path(profiles.vault_path(profile_id)).write_bytes(b"{}")
        assert profiles.camera_unlock_blocks_delete(profile_id)
        with pytest.raises(ApiError) as refused:
            service.delete(profile_id)
        assert refused.value.code == "invalid"
        assert refused.value.message == CAMERA_UNLOCK_BLOCKS_DELETE
        assert env.controller.is_unlocked()
        assert env.port.asked == []
        assert profile_id in [p.id for p in profiles.list_profiles()]
    assert profiles.active_profile().id == active


def test_camera_unlock_set_up_while_the_confirm_is_open_is_refused_before_the_lock(env):
    from localvault.face_unlock import envelope_path

    service = ProfilesService(env.controller, env.port, Dialogs())
    service.create("Second")
    profiles = env.controller.profiles
    active = profiles.active_profile().id

    class SidecarAppears(Port):
        def confirm(self, title, message):
            envelope_path(profiles.vault_path(active)).write_bytes(b"{}")
            return super().confirm(title, message)

    service = ProfilesService(env.controller, SidecarAppears(), Dialogs())
    with pytest.raises(ApiError):
        service.delete(active)
    assert env.controller.is_unlocked()
    assert profiles.active_profile().id == active
