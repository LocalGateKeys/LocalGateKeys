"""Extended audit 2026-10-24, stream F: desktop app layer, WebView and settings regressions."""
from __future__ import annotations

import inspect
import json
import os
import sys
import threading
from pathlib import Path
from types import SimpleNamespace as NS

import pytest
from test_app_desktop import _bind, env, snapshot  # noqa: F401 - env is a fixture

import localvault.clipboard_guard as clip
import localvault.error_log as error_log
from localvault import backup, uia, win_input
from localvault import settings as settings_mod
from localvault.api.bridge import Api
from localvault.api.result import ApiError
from localvault.app.import_export import _kdbx_password, export_request_issue
from localvault.app.updates import UpdatesService
from localvault.secret_text import SecretText
from localvault.settings import SETTINGS_VERSION, AppSettings, validated_mirror_dir
from localvault.web import window as web_window

SRC = Path(__file__).resolve().parents[1] / "src" / "localvault"


# ------------------------------------------------------------- L-5 clipboard
class _Sched:
    def __init__(self):
        self.calls = []

    def call_later(self, delay, fn):
        self.calls.append((delay, fn))
        return fn

    def cancel(self, handle):
        pass

    def run_pending(self):
        calls, self.calls = self.calls, []
        for _delay, fn in calls:
            fn()


def _windows_clipboard(monkeypatch, *, busy_opens):
    """A fake win32clipboard whose OpenClipboard fails ``busy_opens[0]`` times (another app holds it)."""
    state = {"seq": 10, "emptied": 0, "opens": 0}

    def open_():
        state["opens"] += 1
        if busy_opens[0] > 0:
            busy_opens[0] -= 1
            raise OSError("Access is denied")

    def empty():
        state["emptied"] += 1
        state["seq"] += 1

    def set_(fmt, data):
        state["seq"] += 1

    cb = NS(OpenClipboard=open_, CloseClipboard=lambda: None, EmptyClipboard=empty, SetClipboardData=set_,
            RegisterClipboardFormat=lambda name: 0xC000 + len(name), EnumClipboardFormats=lambda fmt: 0)
    monkeypatch.setitem(sys.modules, "win32clipboard", cb)
    monkeypatch.setitem(sys.modules, "win32con", NS(CF_UNICODETEXT=13, CF_TEXT=1, CF_OEMTEXT=7, CF_LOCALE=16))
    monkeypatch.setattr(clip.os, "name", "nt")
    monkeypatch.setattr(clip, "_clipboard_sequence", lambda: state["seq"])
    monkeypatch.setattr(clip.time, "sleep", lambda s: None)
    return state


def _guard(sched):
    guard = clip.ClipboardGuard(timeout_seconds=30, scheduler=sched)
    guard._adopt_synthesized_sequence = lambda cb, con: None
    return guard


def test_busy_clipboard_is_retried_briefly_then_rescheduled_until_cleared(monkeypatch):
    busy = [0]
    state = _windows_clipboard(monkeypatch, busy_opens=busy)
    sched = _Sched()
    guard = _guard(sched)
    guard.copy("hunter2-secret")
    busy[0] = 25  # held for longer than the 20 quick attempts
    sched.run_pending()  # the 30 s timer fires
    assert state["emptied"] == 1  # only the EmptyClipboard of copy() itself
    assert guard._digest is not None, "tracking must survive a busy clipboard"
    assert len(sched.calls) == 1 and 1 <= sched.calls[0][0] <= 2
    sched.run_pending()  # the retry a second or so later: the other app let go
    assert state["emptied"] == 2 and guard._digest is None and sched.calls == []


def test_busy_clipboard_stops_tracking_once_another_app_wrote(monkeypatch):
    busy = [0]
    state = _windows_clipboard(monkeypatch, busy_opens=busy)
    sched = _Sched()
    guard = _guard(sched)
    guard.copy("hunter2-secret")
    busy[0] = 100
    sched.run_pending()
    assert guard._digest is not None and sched.calls
    state["seq"] += 1  # the user copied something else meanwhile
    sched.run_pending()
    assert guard._digest is None and sched.calls == [] and state["emptied"] == 1


def test_busy_clipboard_gives_up_after_about_a_minute(monkeypatch):
    busy = [10**6]
    _windows_clipboard(monkeypatch, busy_opens=[0])
    sched = _Sched()
    guard = _guard(sched)
    guard.copy("hunter2-secret")
    busy_state = _windows_clipboard(monkeypatch, busy_opens=busy)
    busy_state["seq"] = guard._sequence
    clock = [1000.0]
    monkeypatch.setattr(clip.time, "monotonic", lambda: clock[0])
    sched.run_pending()
    for _ in range(100):
        if not sched.calls:
            break
        clock[0] += 2
        sched.run_pending()
    assert sched.calls == [] and guard._digest is None
    assert 25 <= (clock[0] - 1000.0) / 2 <= 35  # about a minute of 2 s steps


def test_lock_clear_is_retried_when_the_clipboard_is_busy(monkeypatch):
    busy = [0]
    state = _windows_clipboard(monkeypatch, busy_opens=busy)
    sched = _Sched()
    guard = _guard(sched)
    guard.copy("hunter2-secret")
    sched.calls.clear()  # drop the 30 s timer
    busy[0] = 25
    guard.clear()  # lock
    assert guard._digest is not None and len(sched.calls) == 1
    sched.run_pending()
    assert state["emptied"] == 2 and guard._digest is None


def test_exit_finish_retries_in_place(monkeypatch):
    busy = [0]
    state = _windows_clipboard(monkeypatch, busy_opens=busy)
    sched = _Sched()
    guard = _guard(sched)
    guard.copy("hunter2-secret")
    busy[0] = 30  # first 20-attempt round fails, the next succeeds
    guard.finish(timeout=5)
    assert state["emptied"] == 2 and guard._digest is None
    sched.run_pending()  # timers retired by finish() do nothing
    assert state["emptied"] == 2


def test_exit_path_calls_clipboard_finish():
    text = (SRC / "web" / "main.py").read_text(encoding="utf-8")
    assert "controller.clipboard.finish()" in text


# -------------------------------------------------- I-4 / I-5 WebView lock
def test_script_notify_from_another_origin_is_dropped():
    seen = []
    guarded = web_window.guard_script_notify(lambda sender, args: seen.append(args.Source), "http://127.0.0.1:42001")
    guarded(None, NS(Source="http://127.0.0.1:42001/index.html"))
    guarded(None, NS(Source="https://evil.example/"))
    guarded(None, NS(Source="http://127.0.0.1:42002/index.html"))
    guarded(None, NS())  # no source at all
    assert seen == ["http://127.0.0.1:42001/index.html"]


def test_navigation_lock_refuses_an_unknown_origin():
    with pytest.raises(RuntimeError):
        web_window.block_foreign_navigation(NS(), "")


class _Event:
    def __init__(self, handlers=()):
        self.handlers = list(handlers)

    def __iadd__(self, fn):
        self.handlers.append(fn)
        return self

    def __isub__(self, fn):
        self.handlers.remove(fn)  # pythonnet raises for an unknown handler too
        return self


def _fake_webview_window():
    original = lambda sender, args: None  # noqa: E731
    settings = NS()
    core = NS(NavigationStarting=_Event(), NewWindowRequested=_Event(), Settings=settings)
    control = NS(CoreWebView2=core, WebMessageReceived=_Event([original]))
    browser = NS(webview=control, on_script_notify=original, on_new_window_request=lambda s, a: None)
    core.NewWindowRequested.handlers.append(browser.on_new_window_request)
    return NS(native=NS(browser=browser)), control, original


def test_navigation_lock_swaps_the_message_handler_for_the_origin_check(monkeypatch):
    monkeypatch.setattr(web_window, "_on_ui_thread", lambda window, fn: fn())
    win, control, original = _fake_webview_window()
    web_window.block_foreign_navigation(win, "http://127.0.0.1:42001")
    handlers = control.WebMessageReceived.handlers
    assert original not in handlers and len(handlers) == 1
    assert getattr(handlers[0], "lgk_original", None) is original


def test_navigation_lock_failure_raises_so_the_window_is_closed(monkeypatch):
    monkeypatch.setattr(web_window, "_on_ui_thread", lambda window, fn: None)  # Invoke never ran it
    win, _control, _original = _fake_webview_window()
    with pytest.raises(RuntimeError):
        web_window.block_foreign_navigation(win, "http://127.0.0.1:42001")


def test_main_window_fails_closed_and_file_urls_are_off():
    text = (SRC / "web" / "main.py").read_text(encoding="utf-8")
    assert 'webview.settings["ALLOW_FILE_URLS"] = False' in text
    assert "if not win.events.loaded.wait(_LOAD_TIMEOUT):" in text
    assert "popup.disable()" in text
    start = text.index("def on_start")
    body = text[start:]
    # The bridge is attached only after the lock succeeded; failures close the window.
    assert body.index("block_foreign_navigation(win, app_origin)") < body.index("bus.attach(QueuedSink(win.evaluate_js))")
    assert body.count("exit_app()") >= 2


def test_disabled_popup_never_shows():
    shown = []
    popup = web_window.PopupWindow(NS(show=lambda: shown.append(1), hide=lambda: None))
    popup.disable()
    popup.show()
    assert shown == []


# ----------------------------------------------------------- I-6 desktop rebind
def test_identical_binary_with_a_new_window_title_asks_first(env):  # noqa: F811
    _bind(env)
    env.state.snap = snapshot(title="Other window of the same app")
    env.service._uia.desktop_entry_matches_snapshot = lambda entry, snap: False
    env.service._uia.updated_binary_binding = lambda entry, snap: (dict(entry), True)  # identical binary
    env.port.answers = [False]
    env.service.fill_foreground()
    assert "App window changed" in env.port.asked and env.filled == []


def test_identical_binary_with_the_same_title_still_fills_silently(env):  # noqa: F811
    _bind(env)
    first = [True]

    def matches(entry, snap):  # the saved layout differs once, then the adopted binding matches
        if first.pop() if first else False:
            return False
        return uia.desktop_entry_matches_snapshot(entry, snap)

    env.service._uia.desktop_entry_matches_snapshot = matches
    env.service._uia.updated_binary_binding = lambda entry, snap: (dict(entry), True)
    env.service.fill_foreground()
    assert "App window changed" not in env.port.asked and env.filled == ["ann"]


# ------------------------------------------------------------- I-7 UIPI
def test_uipi_blocked_when_the_target_runs_higher(monkeypatch):
    monkeypatch.setattr(win_input.os, "name", "nt")
    monkeypatch.setattr(win_input, "_own_integrity_level", lambda: 0x2000)
    monkeypatch.setattr(win_input, "_window_integrity_level", lambda hwnd: 0x3000)  # elevated
    assert win_input.input_blocked_by_uipi(1) is True
    monkeypatch.setattr(win_input, "_window_integrity_level", lambda hwnd: 0x2000)
    assert win_input.input_blocked_by_uipi(1) is False
    monkeypatch.setattr(win_input, "_window_integrity_level", lambda hwnd: None)  # unreadable: fail closed
    assert win_input.input_blocked_by_uipi(1) is True


@pytest.mark.skipif(os.name != "nt", reason="Windows integrity levels")
def test_uipi_reads_real_integrity_levels():
    import ctypes

    assert win_input._own_integrity_level() is not None
    assert win_input.input_blocked_by_uipi(ctypes.windll.user32.GetShellWindow()) is False


def test_typing_fallback_refuses_an_elevated_target(monkeypatch):
    typed = []
    monkeypatch.setitem(sys.modules, "win32gui", NS(IsWindow=lambda h: True, GetForegroundWindow=lambda: 7))
    monkeypatch.setattr(uia, "input_blocked_by_uipi", lambda hwnd: True)
    monkeypatch.setattr(uia, "type_unicode", lambda *a, **k: typed.append(a))
    monkeypatch.setattr(uia, "clear_focused_control", lambda: typed.append("clear"))

    def reject(value):
        raise RuntimeError("no ValuePattern")

    wrapper = NS(element_info=NS(enabled=True, visible=True), set_edit_text=reject,
                 set_focus=lambda: None, has_keyboard_focus=lambda: True)
    control = NS(wrapper=wrapper)
    with pytest.raises(uia.UIAutomationError, match="administrator"):
        uia._write_control(control, "pw", 7)
    assert typed == []


# ------------------------------------------------- L-24 SecretText passwords
_LOCKED = NS(vault_lock=threading.Lock())


def test_export_validation_takes_secret_text():
    good, same, other = (SecretText.from_str(v) for v in ("kdbx password 123", "kdbx password 123", "kdbx password 124"))
    assert export_request_issue("kdbx", good, same) is None
    assert "do not match" in export_request_issue("kdbx", good, other)
    assert "at least" in export_request_issue("kdbx", SecretText.from_str("short"), SecretText.from_str("short"))
    assert _kdbx_password(good) == "kdbx password 123"
    good.wipe()
    with pytest.raises(ValueError):
        _kdbx_password(good)


def test_bridge_export_run_passes_wiped_secret_text():
    seen = []

    class Exports:
        def export(self, fmt, include_totp, password, confirm):
            seen.append((password, confirm, password.char_count))
            return {"message": "ok"}

    result = Api.export_run(NS(_exports=Exports(), _controller=_LOCKED), "kdbx", False, "kdbx password 123", "kdbx password 123")
    assert result["ok"]
    password, confirm, count = seen[0]
    assert isinstance(password, SecretText) and isinstance(confirm, SecretText) and count == 17
    with pytest.raises(ValueError):
        _ = password.buffer  # wiped once the call returned


def test_bridge_backup_password_set_passes_secret_text():
    seen = []

    class Settings:
        def backup_password(self, first, second):
            seen.append((type(first), type(second)))
            return {"message": "saved"}

    assert Api.backup_password_set(NS(_settings=Settings(), _controller=_LOCKED), "long enough pw 1", "long enough pw 1")["ok"]
    assert seen == [(SecretText, SecretText)]


def test_bridge_backup_calls_pass_wiped_secret_text():
    seen = []

    class Recovery:
        def _record(self, *args):
            seen.append([a for a in args if isinstance(a, SecretText)])
            assert not any(isinstance(a, str) and a != "Restored" for a in args)  # no password as a str
            return {"message": "ok"}

        def create_backup(self, backup, confirm, vault):
            return self._record(backup, confirm, vault)

        def verify(self, backup, vault):
            return self._record(backup, vault)

        def restore(self, name, backup, vault):
            return self._record(name, backup, vault)

        def test_restore(self, backup, vault):
            return self._record(backup, vault)

    api = NS(_recovery=Recovery(), _controller=_LOCKED)
    bp, vp = "backup password 1", "vault password 12"
    assert Api.backup_create(api, bp, bp, vp)["ok"]
    assert Api.backup_verify(api, bp, vp)["ok"]
    assert Api.backup_restore(api, "Restored", bp, vp)["ok"]
    assert Api.backup_test(api, bp, vp)["ok"]
    assert [len(call) for call in seen] == [3, 2, 2, 2]
    for call in seen:
        for secret in call:
            with pytest.raises(ValueError):
                _ = secret.buffer  # wiped once the call returned


def test_backup_key_from_secret_text_matches_the_str_key():
    kdf = {"name": "argon2id", "time_cost": backup.MIN_BACKUP_KDF_TIME_COST,
           "memory_cost_kib": backup.MIN_KDF_MEMORY_KIB, "parallelism": backup.MIN_BACKUP_KDF_PARALLELISM}
    salt = b"s" * 16
    expected = backup._derive("backup password 1", salt, kdf)
    with SecretText.from_str("backup password 1") as secret:
        assert backup._derive(secret, salt, kdf) == expected
    with pytest.raises(backup.BackupError):
        backup._derive(SecretText.from_str("short"), salt, kdf)
    wiped = SecretText.from_str("backup password 1")
    wiped.wipe()
    with pytest.raises(backup.BackupError):
        backup._derive(wiped, salt, kdf)


# ------------------------------------------------------------ L-26 error log
def _read_log(tmp_path, monkeypatch, exc):
    monkeypatch.setenv("LOCALGATEKEYS_DATA_DIR", str(tmp_path))
    monkeypatch.setattr(error_log, "_configured", False)
    logger = error_log.logging.getLogger("localgatekeys")
    for handler in list(logger.handlers):
        logger.removeHandler(handler)
    try:
        try:
            raise exc
        except Exception as caught:  # noqa: BLE001
            error_log.log_exception("test", caught)
        for handler in logger.handlers:
            handler.flush()
        return error_log.log_path().read_text(encoding="utf-8")
    finally:
        for handler in list(logger.handlers):
            handler.close()
            logger.removeHandler(handler)


def test_error_log_never_writes_a_value_quoted_by_an_exception(tmp_path, monkeypatch):
    text = _read_log(tmp_path, monkeypatch, ValueError("invalid literal for int() with base 10: 'hunter2'"))
    assert "hunter2" not in text and "ValueError" in text and "test_secfix_app" in text


def test_error_log_keeps_os_error_text_scrubbed(tmp_path, monkeypatch):
    text = _read_log(tmp_path, monkeypatch, PermissionError(13, "Access is denied", "C:/x/vault.json"))
    assert "Access is denied" in text and "PermissionError" in text


# ------------------------------------------------------- I-2 update consent
def test_update_check_takes_no_page_consent():
    assert "consented" not in inspect.signature(UpdatesService.check).parameters


def test_strict_offline_update_check_always_asks_python_side():
    asked = []
    controller = NS(settings=NS(strict_offline_mode=True))
    port = NS(confirm=lambda title, message: asked.append(title) or False)
    service = UpdatesService(controller, port, configuration=lambda: object(), check=lambda: pytest.fail("ran"))
    with pytest.raises(ApiError):
        service.check()
    assert asked == ["Strict offline mode is on"]


# ------------------------------------------------- I-3 mirror dir and ACL
@pytest.mark.parametrize("path", [
    "\\\\?\\UNC\\server\\share", "\\\\.\\pipe\\x", "\\\\?\\C:\\backups", "//?/C:/backups", "//./PhysicalDrive0",
    "\\/?\\C:\\backups", "\\??\\C:\\backups", "C:\\backups:hidden", "C:\\backups\\x:$DATA",
])
def test_mirror_dir_rejects_device_and_namespace_paths(path):
    assert validated_mirror_dir(path) == ""


def test_mirror_dir_keeps_a_local_folder(tmp_path):
    assert validated_mirror_dir(str(tmp_path)) == str(tmp_path)


@pytest.mark.skipif(os.name != "nt", reason="Windows path forms")
@pytest.mark.parametrize("path", ["\\\\nas\\backups\\lgk", "//nas/backups/lgk", "Z:\\Backups", "C:\\Backups"])
def test_mirror_dir_allows_nas_shares_and_mapped_drives(path):
    assert validated_mirror_dir(path) == path


@pytest.mark.skipif(os.name != "nt", reason="Windows ACLs")
def test_new_data_folder_gets_an_owner_only_protected_acl(tmp_path, monkeypatch):
    import ntsecuritycon as con
    import win32api
    import win32security

    from localvault.config import data_dir

    target = tmp_path / "fresh-data"
    monkeypatch.setenv("LOCALGATEKEYS_DATA_DIR", str(target))
    assert data_dir() == target.resolve()
    descriptor = win32security.GetNamedSecurityInfo(str(target), win32security.SE_FILE_OBJECT,
                                                    win32security.DACL_SECURITY_INFORMATION)
    assert descriptor.GetSecurityDescriptorControl()[0] & win32security.SE_DACL_PROTECTED
    dacl = descriptor.GetSecurityDescriptorDacl()
    token = win32security.OpenProcessToken(win32api.GetCurrentProcess(), win32security.TOKEN_QUERY)
    user = win32security.GetTokenInformation(token, win32security.TokenUser)[0]
    system = win32security.CreateWellKnownSid(win32security.WinLocalSystemSid)
    sids = {str(dacl.GetAce(i)[2]) for i in range(dacl.GetAceCount())}
    assert sids == {str(user), str(system)}
    assert all(dacl.GetAce(i)[1] == con.FILE_ALL_ACCESS for i in range(dacl.GetAceCount()))


# ------------------------------------------------ L-16 legacy gesture default
def test_legacy_gesture_compat_is_off_by_default():
    assert AppSettings().legacy_gesture_compat is False
    assert SETTINGS_VERSION == 8


@pytest.mark.parametrize("version, stored, expected", [(7, True, False), (6, True, False), (8, True, True),
                                                       (8, False, False)])
def test_legacy_gesture_compat_migrates_off_before_v8(tmp_path, version, stored, expected):
    path = tmp_path / "settings.json"
    path.write_text(json.dumps({"version": version, "legacy_gesture_compat": stored, "website_icons": True}),
                    encoding="utf-8")
    loaded = AppSettings.load(path)
    assert loaded.legacy_gesture_compat is expected
    assert loaded.website_icons is (version >= 7)  # the v7 migration still applies by version
    loaded.save(path)
    assert json.loads(path.read_text(encoding="utf-8"))["version"] == 8


@pytest.mark.parametrize("version, expected", [(7, False), (8, True)])
def test_backup_settings_follow_the_same_migration(version, expected):
    result = backup._full_validate_settings({"version": version, "legacy_gesture_compat": True})
    assert result["legacy_gesture_compat"] is expected and result["version"] == 8


def test_settings_module_lists_every_loadable_version():
    assert settings_mod.LOADABLE_SETTINGS_VERSIONS[-1] == SETTINGS_VERSION
    assert 7 in settings_mod.LOADABLE_SETTINGS_VERSIONS
