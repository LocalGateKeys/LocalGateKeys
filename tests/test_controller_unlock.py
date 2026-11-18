"""The unlock screen with a duress password (sub-plan 08, Task 4): one flow, no tell, the hold, no services."""
from __future__ import annotations

import json
from types import SimpleNamespace

import pytest

from localvault import duress
from localvault import vault as vault_module
from localvault.api.result import ApiError
from localvault.app.controller import WebController
from localvault.app.duress_service import DuressService
from localvault.profiles import ProfileManager
from localvault.settings import AppSettings
from localvault.sync.pairing import DeviceIdentity

KDF = {"time_cost": 1, "memory_cost_kib": 8192, "parallelism": 1, "hash_len": 32}
PASSWORD = "correct horse battery"
DURESS = "orange tractor sunset"
HOURS = 6
T0 = 1_800_000_000.0


class Bus:
    def __init__(self) -> None:
        self.events: list[tuple[str, dict]] = []

    def emit(self, name, detail):
        self.events.append((name, json.loads(json.dumps(detail))))

    def text(self) -> str:
        return json.dumps(self.events).lower()

    def notices(self) -> list[dict]:
        return [d for n, d in self.events if n == "notice"]


class ManualScheduler:
    def call_later(self, delay, fn):
        return fn

    def cancel(self, handle):
        pass


class Port:
    def __init__(self, answer=True):
        self.answer = answer

    def confirm(self, title, text):
        return self.answer


@pytest.fixture
def env(tmp_path, monkeypatch):
    monkeypatch.setenv("LOCALGATEKEYS_DATA_DIR", str(tmp_path / "lgk-data"))
    monkeypatch.setattr("localvault.app.controller.clear_master_unlock_requirement", lambda _pid: None)
    vault_module._reset_unlock_throttle_state_for_tests()
    profiles = ProfileManager(tmp_path / "data")
    profiles.ensure_profile()
    bus, wall = Bus(), [T0]
    controller = WebController(profiles=profiles, settings=AppSettings(auto_lock_seconds=300, idle_source="vault"),
                               bus=bus, scheduler=ManualScheduler(), create_kwargs={"kdf_overrides": KDF},
                               now=lambda: wall[0])
    controller.spawn = lambda fn: fn()
    controller.create(PASSWORD, PASSWORD)
    # The hold's monotonic clock follows the test's wall clock (one boot, no clock change).
    monkeypatch.setattr(duress, "_boot_clock", lambda: ("boot-1", int(wall[0] - T0) + 1000))
    yield SimpleNamespace(controller=controller, profiles=profiles, bus=bus, wall=wall,
                          path=profiles.vault_path(profiles.active_profile().id))
    vault_module._reset_unlock_throttle_state_for_tests()


def _set_up(env, marker=None):
    duress.setup(env.controller.session, DURESS, lock_hours=HOURS, master_password=PASSWORD, marker=marker)
    env.controller.lock()
    env.bus.events.clear()


def test_a_duress_unlock_looks_like_any_unlock(env):
    _set_up(env)
    state = env.controller.unlock(DURESS)
    assert state["state"] == "unlocked" and duress.is_decoy(env.controller.session)
    assert set(state) == set(env.controller.state())
    assert "decoy" not in env.bus.text() and "duress" not in env.bus.text()
    assert duress.real_held(env.path, T0)


def test_a_duress_unlock_leaves_the_real_item_count_file_alone(env, monkeypatch):
    """I-1: the plaintext item-count.json keeps the real vault's count during a duress session."""
    _set_up(env)
    recorded = []
    monkeypatch.setattr(env.profiles, "record_item_count", lambda pid, count: recorded.append(count))
    env.controller.unlock(DURESS)
    assert duress.is_decoy(env.controller.session) and recorded == []


def test_a_wrong_password_reads_the_same_with_or_without_a_duress_password(env):
    env.controller.lock()
    with pytest.raises(ApiError) as plain:
        env.controller.unlock("wrong password here")
    env.controller.unlock(PASSWORD)
    _set_up(env)
    with pytest.raises(ApiError) as with_second:
        env.controller.unlock("wrong password here")
    assert (plain.value.code, plain.value.message) == (with_second.value.code, with_second.value.message)
    assert with_second.value.code == "wrong_password"


def test_the_real_vault_refuses_for_lock_hours_then_says_what_happened(env):
    _set_up(env)
    env.controller.unlock(DURESS)
    env.controller.lock()
    env.wall[0] = T0 + 3600
    with pytest.raises(ApiError) as held:
        env.controller.unlock(PASSWORD)
    assert held.value.code == "wrong_password"
    assert held.value.message == vault_module.t("vault.err.wrongPasswordOrModified")
    env.wall[0] = T0 + HOURS * 3600 + 1
    assert env.controller.unlock(PASSWORD)["state"] == "unlocked"
    assert not duress.is_decoy(env.controller.session)
    (notice,) = env.bus.notices()
    assert notice["title"] == vault_module.t("duress.usedHereTitle")
    assert not duress.hold_path(env.path).exists()


def test_no_shortcut_or_recovery_phrase_while_held(env):
    phrase = env.controller.session.create_recovery_phrase(PASSWORD)
    env.controller.offers["hello"] = lambda: True
    _set_up(env)
    assert env.controller.state()["hello"] is True
    env.controller.unlock(DURESS)
    env.controller.lock()
    assert env.controller.state()["hello"] is False
    with pytest.raises(ApiError) as alternative:
        env.controller.unlock_alternative(lambda *a: pytest.fail("the real vault must not be opened"))
    assert alternative.value.code == "master_required"
    with pytest.raises(ApiError) as recovered:
        env.controller.recover(phrase, "a brand new password", "a brand new password")
    assert recovered.value.message == vault_module.t("vault.err.recoveryWrongVault")
    assert vault_module.UnlockThrottle(env.path).failures == 1


def test_the_marker_is_signed_only_when_a_folder_was_configured(env, tmp_path):
    folder = tmp_path / "cloud"
    (folder / "LocalGateKeys Sync").mkdir(parents=True)
    device = DeviceIdentity.generate()
    _set_up(env, duress.MarkerIdentity.create(device, "group-1", str(folder)))
    env.controller.unlock(DURESS)
    (marker,) = duress.read_markers(folder, {device.device_id: device.signing_public_key}, group_id="group-1",
                                    now=T0 + 10)
    assert marker.time == int(T0)


def test_no_marker_without_a_folder(env, tmp_path):
    _set_up(env)
    written = []
    env.controller.spawn = written.append
    env.controller.unlock(DURESS)
    assert written == []


# --------------------------------------------------------------------- no services for a duress session
def test_sync_is_not_started_for_a_duress_session(env):
    from localvault.app.sync import SyncWebService

    made = []

    def factory(controller, on_status, **kwargs):
        made.append(controller.session)
        return SimpleNamespace(on_unlock=lambda: None, stop=lambda: None, licence_only=False)

    _set_up(env)
    sync = SyncWebService(env.controller, Port(), env.bus, None, factory=factory)
    env.controller.unlock(DURESS)
    sync.start()
    assert made == [] and sync.service is None
    env.controller.lock()
    env.wall[0] = T0 + HOURS * 3600 + 1
    env.controller.unlock(PASSWORD)
    sync.start()
    assert len(made) == 1 and sync.service is not None


def test_no_heir_timer_or_scheduled_backup_for_a_duress_session(env, monkeypatch):
    from localvault import heir
    from localvault.app.heir_service import HeirService
    from localvault.app.schedule import ScheduleRunner

    _set_up(env)
    env.controller.unlock(DURESS)
    monkeypatch.setattr(heir, "owner_material", lambda s: pytest.fail("no heir look from a duress session"))
    heirs = HeirService(env.controller, Port(), None, bus=env.bus, spawn=lambda fn: fn())
    assert heirs.timer_check() is False and heirs._start_backup(force=True) is False
    ran = []
    runner = ScheduleRunner(env.controller, env.bus, spawn=lambda fn: fn(), run_backup=lambda **kw: ran.append(kw))
    runner.heir = SimpleNamespace(timer_check=lambda: pytest.fail("no heir check"))
    env.controller.settings.scheduled_backup_frequency = "daily"
    env.bus.events.clear()
    assert runner.check() is False and ran == [] and env.bus.events == []


# ----------------------------------------------------------------------- Settings › Unlocking section
def test_the_settings_section_sets_up_and_removes(env):
    service = DuressService(env.controller, Port(), bus=env.bus, spawn=lambda fn: fn())
    view = service.view()
    assert view["configured"] is False and view["pro"] is True and view["lock_hours"] == duress.DEFAULT_LOCK_HOURS
    assert view["folder"] is False and view["max_items"] == duress.MAX_COPIED_ITEMS
    with pytest.raises(ApiError) as close:
        service.setup(PASSWORD, PASSWORD + "1", PASSWORD + "1", HOURS, [])
    assert close.value.code == "close"
    with pytest.raises(ApiError) as mismatch:
        service.setup(PASSWORD, DURESS, DURESS + "x", HOURS, [])
    assert mismatch.value.code == "mismatch"
    with pytest.raises(ApiError) as wrong:
        service.setup("not the password", DURESS, DURESS, HOURS, [])
    assert wrong.value.code == "wrong_password"
    done = service.setup(PASSWORD, DURESS, DURESS, HOURS, [])
    assert done["configured"] is True and done["lock_hours"] == HOURS
    assert service.remove()["configured"] is False and not duress.configured(env.path)


def test_the_section_is_pro_only(env):
    service = DuressService(env.controller, Port(), bus=env.bus)
    env.controller.session.pro_features = frozenset()
    assert service.view()["pro"] is False
    with pytest.raises(ApiError) as refused:
        service.setup(PASSWORD, DURESS, DURESS, HOURS, [])
    assert refused.value.code == "pro_required"


def test_the_section_inside_a_duress_session_shows_nothing_set_up(env):
    service = DuressService(env.controller, Port(), bus=env.bus)
    _set_up(env)
    env.controller.unlock(DURESS)
    assert service.view()["configured"] is False
    with pytest.raises(ApiError) as setup:
        service.setup(DURESS, "another long password", "another long password", HOURS, [])
    with pytest.raises(ApiError) as removal:
        service.remove()
    assert setup.value.code == removal.value.code == "generic"
    assert setup.value.message == vault_module.t("duress.err.generic")
    assert not (duress.decoy_dir(env.controller.session.path)).exists()  # nothing written
    # The usual checks still run first, as in a real vault.
    with pytest.raises(ApiError) as wrong:
        service.setup("not the password", "another long password", "another long password", HOURS, [])
    assert wrong.value.code == "wrong_password"


def test_other_devices_show_the_marker_once(env, tmp_path, monkeypatch):
    folder = tmp_path / "cloud"
    (folder / "LocalGateKeys Sync").mkdir(parents=True)
    tripped, own = DeviceIdentity.generate(), DeviceIdentity.generate()
    duress.mark_tripped(folder, duress.MarkerIdentity.create(tripped, "group-1", str(folder)), now=T0 - 60)
    state = SimpleNamespace(folder_path=str(folder), view_signers={tripped.device_id: tripped.signing_public_key},
                            keyring=None, group_id="group-1", device_id=own.device_id)
    service = DuressService(env.controller, Port(), bus=env.bus, spawn=lambda fn: fn(), clock=lambda: T0)
    monkeypatch.setattr(DuressService, "_sync_state", staticmethod(lambda session: state))
    env.bus.events.clear()
    assert service.timer_check() is True
    (notice,) = env.bus.notices()
    assert notice["title"] == vault_module.t("duress.usedOnTitle")
    service._looked = 0.0
    service.timer_check()
    assert len(env.bus.notices()) == 1  # shown once per run



# ----------------------------------------------------------------------------- fix round 1 (review T4)
def test_a_restarted_app_still_refuses_the_real_password(env):
    _set_up(env)
    env.controller.unlock(DURESS)
    env.controller.lock()
    fresh = WebController(profiles=env.profiles, settings=AppSettings(idle_source="vault"), bus=Bus(),
                          scheduler=ManualScheduler(), now=lambda: T0 + 60)
    with pytest.raises(ApiError) as held:
        fresh.unlock(PASSWORD)
    assert held.value.code == "wrong_password"


def test_profile_paths_follow_a_duress_session(env):
    real_dir = env.profiles.profile_dir()
    _set_up(env)
    env.controller.unlock(DURESS)
    inside = env.controller.profiles
    assert inside.vault_path() == env.controller.session.path
    assert inside.profile_dir() == duress.decoy_dir(env.path)
    assert inside.backups_dir().parent == duress.decoy_dir(env.path)
    env.controller.lock()
    assert env.controller.profiles.profile_dir() == real_dir


def test_a_backup_made_in_a_duress_session_is_of_that_vault(env, tmp_path):
    from localvault.app.recovery import RecoveryWebService

    class Dialogs:
        def __init__(self, path):
            self.path = path

        def save_file(self, title, name):
            return self.path

        def open_file(self, title, *a):
            return self.path

    _set_up(env)
    env.controller.unlock(DURESS)
    target = tmp_path / "made-inside.lgk"
    service = RecoveryWebService(env.controller, Port(), Dialogs(target))
    created = service.create_backup("a backup password", "a backup password", DURESS)
    assert target.exists() and "created" in created["message"].lower()
    assert service.verify("a backup password", DURESS)["message"]
    with pytest.raises(ApiError):
        service.verify("a backup password", PASSWORD)  # it is not the real vault


def test_changing_the_real_master_password_to_the_duress_one_is_refused(env):
    from localvault.app.master import MasterService

    _set_up(env)
    env.controller.unlock(PASSWORD)
    master = MasterService(env.controller, Port())
    for close in (DURESS, DURESS + "x"):
        with pytest.raises(ApiError) as refused:
            master.change(PASSWORD, close, close, None)
        assert refused.value.message == vault_module.t("duress.err.nearDuress")
    assert env.controller.is_unlocked()  # nothing changed


def test_a_phrase_reset_to_the_duress_password_is_refused(env):
    phrase = env.controller.session.create_recovery_phrase(PASSWORD)
    _set_up(env)
    with pytest.raises(ApiError) as refused:
        env.controller.recover(phrase, DURESS + "1", DURESS + "1")
    assert refused.value.code == "near_duress"
    assert env.controller.unlock(PASSWORD)["state"] == "unlocked"  # the old password still works


def test_own_markers_are_not_shown_and_shown_ones_stay_shown_after_a_restart(env, tmp_path, monkeypatch):
    folder = tmp_path / "cloud"
    (folder / "LocalGateKeys Sync").mkdir(parents=True)
    tripped, own = DeviceIdentity.generate(), DeviceIdentity.generate()
    for device in (tripped, own):
        duress.mark_tripped(folder, duress.MarkerIdentity.create(device, "group-1", str(folder)), now=T0 - 60)
    state = SimpleNamespace(folder_path=str(folder), keyring=None, group_id="group-1", device_id=own.device_id,
                            view_signers={d.device_id: d.signing_public_key for d in (tripped, own)})
    monkeypatch.setattr(DuressService, "_sync_state", staticmethod(lambda session: state))
    env.bus.events.clear()
    DuressService(env.controller, Port(), bus=env.bus, spawn=lambda fn: fn(), clock=lambda: T0).timer_check()
    assert len(env.bus.notices()) == 1  # the other device's marker only
    DuressService(env.controller, Port(), bus=env.bus, spawn=lambda fn: fn(), clock=lambda: T0).timer_check()
    assert len(env.bus.notices()) == 1  # a new run of the app remembers it



# ----------------------------------------------------------------------------- fix round 2 (re-review)
def test_open_copies_of_a_duress_session_are_swept_when_it_locks(env, monkeypatch):
    from localvault.app.documents import DocumentService

    swept = []
    monkeypatch.setattr("localvault.app.documents.cleanup_open_copies", lambda folder: swept.append(folder) or [])
    DocumentService(env.controller, Port(), None)
    _set_up(env)
    swept.clear()
    env.controller.unlock(DURESS)
    env.controller.lock()
    # The lock sweep (and its 30 s retries) works on the folder of the session that locked (review R3).
    assert swept == [duress.decoy_dir(env.path)]


def test_a_catalog_backup_source_follows_a_duress_session(env):
    _set_up(env)
    env.controller.unlock(DURESS)
    record = env.profiles.active_profile()
    assert env.controller.profiles.restore_profile_path(record, require_absent=False) == duress.decoy_dir(env.path)
    env.controller.lock()
    assert env.controller.profiles.restore_profile_path(record, require_absent=False) == env.path.parent
