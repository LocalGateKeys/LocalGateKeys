"""Audit 2026-10-18 app-level low findings: QR scan vs lock, transfer ids in the trash,
trash purge lease, scheduled backup spawn failure, Fill & sign in rollback, website icons."""
from __future__ import annotations

import json
import shutil
import threading
import uuid
from datetime import datetime
from pathlib import Path
from types import SimpleNamespace

import pytest

from localvault.api.result import ApiError
from localvault.app.icons import IconProvider
from localvault.app.qr_import import QrImportService
from localvault.app.schedule import FAILED, ScheduleRunner
from localvault.settings import AppSettings
from localvault.transfer import export_transfer, import_transfer, preview_transfer
from localvault.vault import create_vault

KDF = {"time_cost": 1, "memory_cost_kib": 8192, "parallelism": 1, "hash_len": 32}
MASTER = "audit lows master password"
TRANSFER_PASSWORD = "audit lows package password"


# --------------------------------------------------------------------- QR scan vs lock
class _QrController:
    def __init__(self):
        self.unlocked = True
        self.vault_lock = threading.RLock()
        self.on_lock = []

    def is_unlocked(self):
        return self.unlocked

    def lock(self):
        self.unlocked = False
        for hook in self.on_lock:
            hook()


class _Capture:
    def __init__(self, on_read=None):
        self.on_read = on_read
        self.released = False
        self.reads = 0

    def read(self):
        self.reads += 1
        if self.on_read is not None:
            self.on_read()
        return True, object()

    def set(self, *_args):
        return True

    def release(self):
        self.released = True


class _FakeCv:
    """Just enough of cv2 for make_decoder: nothing is ever found."""

    class QRCodeDetector:
        def detectAndDecodeMulti(self, _image):  # noqa: N802 - OpenCV name
            return False, [], None, None

        def detectAndDecode(self, _image):  # noqa: N802
            return "", None, None


def _qr(controller, *, editor_view=None, capture=None, clock=None):
    opened = []

    def open_camera(_cv2, index):
        opened.append(index)
        return capture or _Capture(), index

    editor = SimpleNamespace(view=editor_view or (lambda _draft_id: {}))
    qr = QrImportService(controller, editor, SimpleNamespace(), emit=lambda *_a: None,
                         load_cv=lambda: (_FakeCv, None), open_camera=open_camera,
                         clock=clock or (lambda: 0.0), sleep=lambda _s: None)
    qr._preview = lambda *_a: None  # no real frames to encode
    return qr, opened


def test_qr_lock_while_start_waits_for_the_vault_is_not_lost():
    controller = _QrController()

    def view(_draft_id):
        controller.lock()  # the lock lands after the first unlock check
        return {}

    qr, opened = _qr(controller, editor_view=view)
    with pytest.raises(ApiError) as caught:
        qr.scan_camera("draft")
    assert caught.value.code == "locked"
    assert opened == []  # the webcam was never opened
    assert qr._busy.acquire(blocking=False)  # and the scanner is free again


def test_qr_start_clears_flags_only_after_claiming_the_scanner():
    controller = _QrController()
    qr, _opened = _qr(controller)
    qr._busy.acquire()
    qr._cancelled.set()  # a running scan was just cancelled by a lock
    with pytest.raises(ApiError) as caught:
        qr._start("draft")
    assert caught.value.code == "busy"
    assert qr._cancelled.is_set()  # a refused second scan never clears the running one's cancel


def test_qr_lock_before_start_is_refused_and_releases_the_scanner():
    controller = _QrController()
    controller.unlocked = False
    qr, opened = _qr(controller)
    with pytest.raises(ApiError) as caught:
        qr.scan_image("draft", "data:image/png;base64,AAAA")
    assert caught.value.code == "locked" and opened == []
    assert qr._busy.acquire(blocking=False)


def test_qr_camera_loop_stops_when_the_vault_locks_even_without_cancel():
    controller = _QrController()
    capture = _Capture()

    def locked_without_hook():
        if capture.reads >= 2:
            controller.unlocked = False  # e.g. a lock path that did not run on_lock hooks

    capture.on_read = locked_without_hook
    qr, opened = _qr(controller, capture=capture)
    with pytest.raises(ApiError) as caught:
        qr.scan_camera("draft")
    assert caught.value.code == "cancelled"
    assert opened == [0] and capture.released and capture.reads == 2


def test_qr_lock_hook_during_scan_still_cancels():
    controller = _QrController()
    capture = _Capture()
    capture.on_read = lambda: controller.lock() if capture.reads == 3 else None
    qr, _opened = _qr(controller, capture=capture)
    with pytest.raises(ApiError) as caught:
        qr.scan_camera("draft")
    assert caught.value.code == "cancelled" and capture.released


# ------------------------------------------------------------ transfer ids in trash
@pytest.fixture
def case_dir() -> Path:
    root = Path(__file__).parents[1] / ".m3-focused" / f"audit-lows-{uuid.uuid4().hex}"
    root.mkdir(parents=True)
    try:
        yield root
    finally:
        shutil.rmtree(root, ignore_errors=True)


def _vault(case_dir: Path, name: str):
    return create_vault(case_dir / f"{name}.json", MASTER, kdf_overrides=KDF)


def _trash_ids(session) -> list[str]:
    return [row["entry"]["id"] for row in session._require_typed_catalog().get("trash", [])]


def _live_ids(session) -> list[str]:
    payload = session._require_typed_catalog()
    return [row["id"] for row in payload.get("items", [])] + [row["id"] for row in session.all_entries()]


def _deleted_note(case_dir: Path):
    """A vault whose note was exported and then moved to the trash."""
    session = _vault(case_dir, "v")
    note_id = session.items.create_note("Router", "codes")
    package = case_dir / "note.lgt"
    export_transfer(session, package, TRANSFER_PASSWORD, ids=[note_id])
    session.items.delete_item(note_id)
    assert _trash_ids(session) == [note_id]
    return session, package, note_id


def test_transfer_skip_leaves_a_trashed_id_alone(case_dir: Path):
    session, package, note_id = _deleted_note(case_dir)
    preview = preview_transfer(package, session, TRANSFER_PASSWORD)
    assert preview["skipped_ids"] == [note_id] and preview["imported_ids"] == []
    result = import_transfer(package, session, TRANSFER_PASSWORD)
    assert result["skipped_ids"] == [note_id]
    assert note_id not in _live_ids(session) and _trash_ids(session) == [note_id]


def test_transfer_copy_gives_a_trashed_id_a_new_id_and_restore_still_works(case_dir: Path):
    session, package, note_id = _deleted_note(case_dir)
    result = import_transfer(package, session, TRANSFER_PASSWORD, conflict_policy="copy")
    assert result["copied_ids"] == [note_id]
    new_id = result["id_map"][note_id]
    assert new_id != note_id and new_id in _live_ids(session) and note_id not in _live_ids(session)
    assert session.items.restore_item(note_id) is True  # the trash row is still the only record with its id
    live = _live_ids(session)
    assert live.count(note_id) == 1 and new_id in live and _trash_ids(session) == []


def test_transfer_replace_takes_the_trash_row_out(case_dir: Path):
    session, package, note_id = _deleted_note(case_dir)
    result = import_transfer(package, session, TRANSFER_PASSWORD, conflict_policy="replace", allow_replace=True)
    assert result["replaced_ids"] == [note_id]
    assert _live_ids(session).count(note_id) == 1 and _trash_ids(session) == []
    reopened = _vault_reopen(session)
    assert note_id in [row["id"] for row in reopened._require_typed_catalog()["items"]]
    assert _trash_ids(reopened) == []


def _vault_reopen(session):
    from localvault.vault import unlock_vault

    return unlock_vault(session.path, MASTER)


def test_transfer_replace_of_a_trashed_record_counts_against_the_free_limit(case_dir: Path):
    session, package, note_id = _deleted_note(case_dir)
    session.item_limit = 1
    session.items.create_note("Other", "body")  # the only free slot is used
    result = import_transfer(package, session, TRANSFER_PASSWORD, conflict_policy="replace", allow_replace=True)
    assert result["limit_skipped_ids"] == [note_id] and result["replaced_ids"] == []
    assert _trash_ids(session) == [note_id]  # nothing was dropped


def test_transfer_credential_in_trash_is_a_conflict(case_dir: Path):
    session = _vault(case_dir, "v")
    login_id = session.upsert_web(origin="https://example.test", username="alice", password="WEB-SECRET-1")
    package = case_dir / "login.lgt"
    export_transfer(session, package, TRANSFER_PASSWORD, ids=[login_id])
    session.delete(login_id)
    skipped = import_transfer(package, session, TRANSFER_PASSWORD)
    assert skipped["skipped_ids"] == [login_id] and login_id not in _live_ids(session)
    copied = import_transfer(package, session, TRANSFER_PASSWORD, conflict_policy="copy")
    assert copied["id_map"][login_id] != login_id
    session.purge_deleted(login_id)  # purge finds exactly the trashed row
    assert login_id not in _trash_ids(session) and copied["id_map"][login_id] in _live_ids(session)


# ------------------------------------------------------------------- trash purge lease
class _Guard:
    def __init__(self):
        self.generation = 0

    def lease(self):
        return self.generation

    def require(self, lease):
        if lease != self.generation:
            raise RuntimeError("stale lease")


def test_trash_purge_lease_is_taken_before_the_confirm_dialog():
    from localvault.app.trash import TrashService

    purged = []
    session = SimpleNamespace(
        trash_summaries=lambda: [{"id": "a1", "label": "Alpha", "username": "ann", "deleted_at": 1}],
        item_service=SimpleNamespace(trash_summaries=lambda: []),
        purge_deleted_many=lambda ids: purged.append(list(ids)) or len(ids),
    )
    guard = _Guard()
    controller = SimpleNamespace(is_unlocked=lambda: True, session=session, guard=guard,
                                 require_lease=lambda lease: guard.require(lease))

    def confirm(_title, _text):
        guard.generation += 1  # the vault locked (or the profile switched) while the dialog was open
        return True

    service = TrashService(controller, SimpleNamespace(confirm=confirm))
    with pytest.raises(RuntimeError):
        service.purge(["a1"])
    assert purged == []

    service = TrashService(controller, SimpleNamespace(confirm=lambda *_a: True))
    assert service.purge(["a1"]) == {"message": "Permanently deleted 1 item(s)."} and purged == [["a1"]]


# ------------------------------------------------------- scheduled backup spawn failure
class _Bus:
    def __init__(self):
        self.events = []

    def emit(self, name, detail):
        self.events.append((name, detail))


def _schedule_runner(tmp_path, spawn, monkeypatch):
    monkeypatch.setattr("localvault.backup_schedule.is_due", lambda *_a: True)
    monkeypatch.setattr("localvault.backup_schedule.read_last_success", lambda _d: None)
    logged = []
    monkeypatch.setattr("localvault.error_log.log_exception", lambda where, exc, **_k: logged.append(where))
    profile = SimpleNamespace(id="p1", name="Ann")
    profiles = SimpleNamespace(active_profile=lambda: profile, backups_dir=lambda _pid: tmp_path,
                               profile_dir=lambda _pid: tmp_path)
    controller = SimpleNamespace(
        settings=AppSettings(scheduled_backup_frequency="daily"), is_unlocked=lambda: True,
        session=SimpleNamespace(scheduled_backup_password=lambda: "backup-pw"), profiles=profiles,
        on_unlock=[], _scheduler=SimpleNamespace(call_later=lambda *_a: None))
    bus = _Bus()
    ran = []
    runner = ScheduleRunner(controller, bus, spawn=spawn, now=lambda: datetime(2026, 10, 18, 12, 0),
                            run_backup=lambda **job: ran.append(job) or SimpleNamespace(mirror_warning="", mirrored=None))
    return runner, bus, ran, logged


def test_schedule_spawn_failure_resets_and_reports(tmp_path, monkeypatch):
    def broken(_fn):
        raise RuntimeError("can't start new thread")

    runner, bus, ran, logged = _schedule_runner(tmp_path, broken, monkeypatch)
    assert runner.check() is False
    assert runner._running is False and runner._failed_at == datetime(2026, 10, 18, 12, 0)
    assert ("toast", {"kind": "error", "message": FAILED}) in bus.events
    assert logged == ["scheduled-backup-start"] and ran == []
    assert "backup-pw" not in repr(bus.events)
    # The retry window applies as after any failure; afterwards backups run again.
    runner._failed_at = None
    runner._spawn = lambda fn: fn()
    assert runner.check() is True and len(ran) == 1


# ------------------------------------------------------ Fill & sign in rollback
def test_fill_and_sign_in_vault_flag_reverts_when_settings_cannot_be_saved(monkeypatch):
    from localvault.app.settings import SettingsService

    flags = []
    session = SimpleNamespace(set_fill_and_sign_in_enabled=lambda value: flags.append(value))
    previous = AppSettings()
    controller = SimpleNamespace(settings=previous, session=session, is_unlocked=lambda: True,
                                 guard=SimpleNamespace(lease=lambda: 1), require_lease=lambda _lease: None,
                                 touch=lambda: None)

    def failing_save(self, path=None):
        raise OSError("disk full")

    monkeypatch.setattr(AppSettings, "save", failing_save)
    service = SettingsService(controller, SimpleNamespace(confirm=lambda *_a: True), _Bus())
    with pytest.raises(ApiError) as caught:
        service.apply("fill_and_sign_in", True)
    assert caught.value.code == "invalid"
    assert flags == [True, False]  # written, then put back
    assert controller.settings is previous and previous.fill_and_sign_in is False


def test_start_with_windows_reverts_when_settings_cannot_be_saved(monkeypatch):
    from localvault.app.settings import SettingsService

    startup = []
    monkeypatch.setattr("localvault.app.settings.set_start_with_windows", lambda value: startup.append(value))

    def failing_save(self, path=None):
        raise OSError("disk full")

    monkeypatch.setattr(AppSettings, "save", failing_save)
    controller = SimpleNamespace(settings=AppSettings(), is_unlocked=lambda: True, session=SimpleNamespace(),
                                 guard=SimpleNamespace(lease=lambda: 1), require_lease=lambda _lease: None)
    service = SettingsService(controller, SimpleNamespace(confirm=lambda *_a: True), _Bus())
    with pytest.raises(ApiError):
        service.apply("start_with_windows", True)
    assert startup == [True, False]


# ------------------------------------------------------------------ website icons
def test_website_icons_setting_is_off_by_default_and_loads_backward_compatibly(tmp_path):
    assert AppSettings().website_icons is False
    path = tmp_path / "settings.json"
    path.write_text(json.dumps({"version": 5, "strict_offline_mode": False}), encoding="utf-8")
    assert AppSettings.load(path).website_icons is False  # older files never had it
    path.write_text(json.dumps({"version": 6, "website_icons": True}), encoding="utf-8")
    assert AppSettings.load(path).website_icons is False  # v6 saved its default (on), nobody chose it
    path.write_text(json.dumps({"version": 7, "website_icons": "yes"}), encoding="utf-8")
    assert AppSettings.load(path).website_icons is False  # not a bool: default
    AppSettings(website_icons=False).save(path)
    assert AppSettings.load(path).website_icons is False
    AppSettings(website_icons=True).save(path)
    assert AppSettings.load(path).website_icons is True


def test_settings_page_shows_and_saves_the_website_icons_switch(monkeypatch):
    from localvault.app.settings import SettingsService, _Adapter, _Recorder

    recorder = _Recorder(_Adapter(SimpleNamespace()), AppSettings(website_icons=False))
    recorder.switch("strict_offline_mode", "Strict offline mode", "")
    assert [row["key"] for row in recorder.rows] == ["strict_offline_mode", "website_icons"]
    row = recorder.rows[1]
    assert row["title"] == "Show website icons" and row["value"] is False
    assert "tells that site you have an account" in row["description"]

    saved = []
    monkeypatch.setattr(AppSettings, "save", lambda self, path=None: saved.append(self.website_icons))
    controller = SimpleNamespace(settings=AppSettings(), session=SimpleNamespace(), is_unlocked=lambda: True,
                                 guard=SimpleNamespace(lease=lambda: 1), require_lease=lambda _lease: None,
                                 touch=lambda: None)
    bus = _Bus()
    service = SettingsService(controller, SimpleNamespace(confirm=lambda *_a: True), bus)
    assert service.apply("website_icons", True)["value"] is True
    assert controller.settings.website_icons is True and saved == [True]
    assert ("settings.changed", {"key": "website_icons"}) in bus.events
    with pytest.raises(ApiError):
        service.apply("website_icons", "on")


def _home_with_icons(*, website_icons: bool, strict_offline: bool):
    from localvault.app.home import HomeService

    fetched = []
    settings = AppSettings(website_icons=website_icons, strict_offline_mode=strict_offline)
    provider = IconProvider(offline=lambda: settings.strict_offline_mode, on_ready=lambda: None,
                            fetch=lambda origin: fetched.append(origin))
    home = HomeService(SimpleNamespace(settings=settings), icons=provider)
    summary = SimpleNamespace(kind="web", id="a1", title="Alpha", label="Alpha", username="ann",
                              scope={"origin": "https://alpha.test"}, favorite=False, tags=[], collection_ids=[])
    return home, provider, summary, fetched


@pytest.mark.parametrize(("website_icons", "strict_offline"), [(False, False), (False, True)])
def test_item_list_never_fetches_favicons_unless_website_icons_is_on(website_icons, strict_offline):
    home, provider, summary, fetched = _home_with_icons(website_icons=website_icons, strict_offline=strict_offline)
    try:
        home._row(summary, "https://alpha.test", {})
        provider._pool.shutdown(wait=True)
        assert fetched == []
    finally:
        provider._pool.shutdown(wait=False)


def test_item_list_fetches_favicons_with_website_icons_on_and_offline_off():
    home, provider, summary, fetched = _home_with_icons(website_icons=True, strict_offline=False)
    home._row(summary, "https://alpha.test", {})
    provider._pool.shutdown(wait=True)
    assert fetched == ["https://alpha.test"]


def test_icon_provider_own_website_icons_gate():
    fetched = []
    allowed = [False]
    provider = IconProvider(offline=lambda: False, on_ready=lambda: None, fetch=fetched.append,
                            website_icons=lambda: allowed[0])
    assert provider.website("https://alpha.test") is None
    allowed[0] = True
    provider.website("https://alpha.test")
    provider._pool.shutdown(wait=True)
    assert fetched == ["https://alpha.test"]


@pytest.mark.parametrize("website_icons", [False, True])
def test_website_icons_never_load_in_strict_offline_mode(website_icons):
    """Strict offline mode blocks favicon downloads too; the app wires the provider to that setting."""
    import inspect

    from localvault.app.home import HomeService
    from localvault.web import main as web_main

    source = inspect.getsource(web_main)
    assert "offline=lambda: False" not in source
    assert 'offline=lambda: getattr(controller.settings, "strict_offline_mode", True) is not False' in source
    fetched = []
    settings = AppSettings(website_icons=website_icons)
    assert settings.strict_offline_mode is True and AppSettings().website_icons is False
    provider = IconProvider(offline=lambda: settings.strict_offline_mode, on_ready=lambda: None,
                            fetch=fetched.append, website_icons=lambda: settings.website_icons)
    home = HomeService(SimpleNamespace(settings=settings), icons=provider)
    summary = SimpleNamespace(kind="web", id="a1", title="Alpha", label="Alpha", username="ann",
                              scope={"origin": "https://alpha.test"}, favorite=False, tags=[], collection_ids=[])
    home._row(summary, "https://alpha.test", {})
    provider._pool.shutdown(wait=True)
    assert fetched == []


def test_restored_pre_v7_backup_settings_turn_website_icons_off():
    from localvault.backup import _full_validate_settings

    assert _full_validate_settings({"version": 6, "website_icons": True})["website_icons"] is False
    assert _full_validate_settings({"version": 7, "website_icons": True})["website_icons"] is True
