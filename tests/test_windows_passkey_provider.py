"""Windows passkey provider switch, start-up clean-up and the names-only metadata sync (sub-plan 04 Task 6).

Every provider call goes to a fake: nothing here registers with Windows or changes Windows settings.
"""
from __future__ import annotations

import json
import subprocess
import threading
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import pytest

from localvault import windows_passkey_provider as wpp
from localvault.settings import AppSettings
from localvault.vault import create_vault
from localvault.web.bus import EventBus

KDF = {"time_cost": 1, "memory_cost_kib": 8192, "parallelism": 1, "hash_len": 32}
ALLOWED = {"credential_id", "rp_id", "rp_name", "user_id", "user_name", "user_display_name"}


class FakeProvider:
    """Records commands; answers from a table."""

    def __init__(self, **answers) -> None:
        self.calls: list[tuple[str, ...]] = []
        self.answers = {"--register": {"ok": True}, "--unregister": {"ok": True}, "--sync": {"ok": True},
                        "--clear-cache": {"ok": True},
                        "--state": {"ok": True, "build_supported": True, "state": "not_registered"}, **answers}

    def __call__(self, *args, **_kwargs):
        self.calls.append(args)
        return dict(self.answers[args[0]])

    def commands(self) -> list[str]:
        return [call[0] for call in self.calls]


# -- availability -------------------------------------------------------------------------------------------------
@pytest.fixture
def packaged(monkeypatch, tmp_path):
    """A fake MSIX layout: package root with the app exe and the provider next to it."""
    root = tmp_path / "pkg"
    (root / "PasskeyProvider").mkdir(parents=True)
    exe = root / "PasskeyProvider" / "LocalGateKeysPasskeyProvider.exe"
    exe.write_bytes(b"MZ")
    monkeypatch.setattr(wpp.os, "name", "nt")
    monkeypatch.setattr(wpp.distribution, "is_packaged", lambda: True)
    monkeypatch.setattr(wpp.distribution, "package_root", lambda: root)
    monkeypatch.setattr(wpp.sys, "executable", str(root / "LocalGateKeys.exe"))
    monkeypatch.setattr(wpp, "_windows_build", lambda: (26200, 7000))
    return exe


def test_available_when_packaged_on_supported_build(packaged) -> None:
    assert wpp.available() is True
    assert wpp.provider_path() == Path(str(packaged))


def test_unavailable_when_not_packaged(packaged, monkeypatch) -> None:
    monkeypatch.setattr(wpp.distribution, "is_packaged", lambda: False)
    assert wpp.available() is False


def test_unavailable_below_build_gate(packaged, monkeypatch) -> None:
    for build, ubr in ((26100, 6724), (26200, 100), (22631, 9999), (0, 0)):
        monkeypatch.setattr(wpp, "_windows_build", lambda b=build, u=ubr: (b, u))
        assert wpp.available() is False, (build, ubr)
    for build, ubr in ((26100, 6725), (26200, 6725), (26300, 0)):
        assert wpp.build_supported(build, ubr) is True


def test_unavailable_without_provider_exe_or_outside_package(packaged, monkeypatch, tmp_path) -> None:
    packaged.unlink()
    assert wpp.available() is False
    packaged.write_bytes(b"MZ")
    monkeypatch.setattr(wpp.sys, "executable", str(tmp_path / "elsewhere" / "LocalGateKeys.exe"))
    assert wpp.provider_path() is None


def test_unavailable_off_windows(packaged, monkeypatch) -> None:
    monkeypatch.setattr(wpp.os, "name", "posix")
    assert wpp.available() is False


# -- run_provider -------------------------------------------------------------------------------------------------
def test_run_provider_fixed_command_no_shell(packaged, monkeypatch) -> None:
    seen = {}

    def fake_run(argv, **kwargs):
        seen["argv"], seen["kwargs"] = argv, kwargs
        return SimpleNamespace(stdout=b'{"ok":true,"build_supported":true,"state":"enabled"}\r\n')

    monkeypatch.setattr(wpp, "_same_signer", lambda _path: True)
    monkeypatch.setattr(wpp.subprocess, "run", fake_run)
    assert wpp.run_provider("--state") == {"ok": True, "build_supported": True, "state": "enabled"}
    assert seen["argv"] == [str(packaged), "--state"]
    assert seen["kwargs"]["shell"] is False
    assert seen["kwargs"]["creationflags"] == getattr(subprocess, "CREATE_NO_WINDOW", 0)
    assert seen["kwargs"]["stdin"] is subprocess.DEVNULL


@pytest.mark.parametrize("args", [(), ("--register", "--sync"), ("-PluginActivated",), ("--bogus",), ("--sync x",)])
def test_run_provider_refuses_other_arguments(args) -> None:
    with pytest.raises(ValueError):
        wpp.run_provider(*args)


def test_run_provider_failures_are_plain_errors(packaged, monkeypatch) -> None:
    monkeypatch.setattr(wpp, "_same_signer", lambda _path: True)

    def timeout(*_a, **_k):
        raise subprocess.TimeoutExpired("x", 15)

    monkeypatch.setattr(wpp.subprocess, "run", timeout)
    assert wpp.run_provider("--sync") == {"ok": False, "error": "timeout"}
    for out in (b"", b"not json", b"[1]", b'{"state":"x"}'):
        monkeypatch.setattr(wpp.subprocess, "run", lambda *_a, o=out, **_k: SimpleNamespace(stdout=o))
        assert wpp.run_provider("--state")["ok"] is False


def test_run_provider_refuses_wrong_signer(packaged, monkeypatch) -> None:
    monkeypatch.setattr(wpp, "_same_signer", lambda _path: False)
    monkeypatch.setattr(wpp.subprocess, "run", lambda *_a, **_k: pytest.fail("must not launch"))
    assert wpp.run_provider("--register") == {"ok": False, "error": "signer_mismatch"}


def test_run_provider_unavailable_without_package(monkeypatch) -> None:
    monkeypatch.setattr(wpp.distribution, "package_root", lambda: None)
    monkeypatch.setattr(wpp.subprocess, "run", lambda *_a, **_k: pytest.fail("must not launch"))
    assert wpp.run_provider("--unregister") == {"ok": False, "error": "unavailable"}


# -- enable / disable / reconcile ---------------------------------------------------------------------------------
def test_enable_runs_register_then_opens_settings() -> None:
    fake, opened = FakeProvider(), []
    enabled = wpp.enable(run=fake, open_settings=lambda: opened.append(fake.commands()[:]))
    assert enabled["ok"] is True
    assert fake.commands() == ["--register"]
    assert opened == [["--register"]]  # settings open only after a successful register


def test_enable_failure_does_not_open_settings() -> None:
    fake, opened = FakeProvider(**{"--register": {"ok": False, "hresult": "0x80090029"}}), []
    enabled = wpp.enable(run=fake, open_settings=lambda: opened.append(1))
    assert enabled["ok"] is False
    assert opened == []


def test_disable_runs_unregister() -> None:
    fake = FakeProvider()
    assert wpp.disable(run=fake)["ok"] is True
    assert fake.commands() == ["--unregister"]


def test_reconcile_unregisters_orphan() -> None:
    for state in ("enabled", "disabled"):
        fake = FakeProvider(**{"--state": {"ok": True, "state": state}})
        assert wpp.reconcile(False, run=fake, is_available=lambda: True) == "unregistered"
        assert fake.commands() == ["--state", "--unregister"]


def test_reconcile_never_registers() -> None:
    for state in ("enabled", "not_registered", "unsupported_build"):
        fake = FakeProvider(**{"--state": {"ok": True, "state": state}})
        wpp.reconcile(True, run=fake, is_available=lambda: True)
        assert "--register" not in fake.commands()
    fake = FakeProvider(**{"--state": {"ok": True, "state": "not_registered"}})
    assert wpp.reconcile(True, run=fake, is_available=lambda: True) == "not_registered"
    assert wpp.reconcile(False, run=fake, is_available=lambda: True) == "not_registered"
    assert "--unregister" not in fake.commands()


def test_reconcile_without_identity_uses_native_cleanup_only() -> None:
    fake, native = FakeProvider(), []
    reconciled = wpp.reconcile(False, run=fake, is_available=lambda: False,
                               native=lambda: native.append(1) or "unregistered")
    assert reconciled == "unregistered"
    assert native == [1] and fake.calls == []
    assert wpp.reconcile(True, run=fake, is_available=lambda: False, native=lambda: 1 / 0) == "unknown"


def test_native_cleanup_skips_dev_runs() -> None:
    # Unfrozen (tests, development): never touches webauthn.dll.
    assert wpp._native_cleanup() == "skipped"


# -- the switch ---------------------------------------------------------------------------------------------------
class SyncSpy:
    def __init__(self) -> None:
        self.events: list[str] = []

    def forget(self) -> None:
        self.events.append("forget")

    def schedule(self) -> None:
        self.events.append("schedule")


def _switch(fake, desired):
    toasts, offs, sync = [], [], SyncSpy()
    switch = wpp.ProviderSwitch(desired=lambda: desired["on"], toast=lambda kind, text: toasts.append((kind, text)),
                                switch_off=lambda: offs.append(1), sync=sync, run=fake,
                                open_settings=lambda: None, spawn=lambda work: work())
    return switch, toasts, offs, sync


def test_switch_on_registers_once_and_syncs() -> None:
    fake, desired = FakeProvider(), {"on": True}
    switch, toasts, offs, sync = _switch(fake, desired)
    switch.changed()
    switch.changed()  # already applied: no second register
    assert fake.commands() == ["--register"]
    assert sync.events == ["forget", "schedule"]
    assert toasts and toasts[0][0] == "info" and offs == []


def test_switch_off_unregisters_and_forgets_cache() -> None:
    fake, desired = FakeProvider(), {"on": True}
    switch, toasts, _offs, sync = _switch(fake, desired)
    switch.changed()
    desired["on"] = False
    switch.changed()
    assert fake.commands() == ["--register", "--unregister"]  # --unregister empties Windows' cache first
    assert sync.events[-1] == "forget"
    assert toasts[-1][0] == "info"


def test_enable_failure_toasts() -> None:
    from localvault.i18n import t

    fake, desired = FakeProvider(**{"--register": {"ok": False, "error": "register_failed",
                                                     "hresult": "0x80090029"}}), {"on": True}
    switch, toasts, offs, sync = _switch(fake, desired)
    switch.changed()
    assert toasts == [("error", t("settings.windowsPasskeys.needPin"))]
    assert offs == [1]  # the switch goes back off
    assert "schedule" not in sync.events
    assert wpp.failure_message({"ok": False, "error": "unsupported_build"}, turning_on=True) == \
        t("settings.windowsPasskeys.unsupported")
    assert wpp.failure_message({"ok": False, "error": "timeout"}, turning_on=True) == \
        t("settings.windowsPasskeys.registerFailed")


def test_disable_failure_toasts() -> None:
    from localvault.i18n import t

    fake, desired = FakeProvider(**{"--unregister": {"ok": False, "error": "unregister_failed"}}), {"on": False}
    switch, toasts, _offs, _sync = _switch(fake, desired)
    switch.changed()
    assert toasts == [("error", t("settings.windowsPasskeys.unregisterFailed"))]


# -- metadata sync ------------------------------------------------------------------------------------------------
def _entries(*names):
    return [{"credential_id": f"id-{n}", "rp_id": "example.com", "rp_name": "Example", "user_id": f"u-{n}",
             "user_name": n, "user_display_name": n.title()} for n in names]


def _sync(fake, *, enabled=True, snapshot=None, delay=60.0):
    state = {"enabled": enabled, "snapshot": snapshot}
    sync = wpp.MetadataSync(enabled=lambda: state["enabled"], snapshot=lambda: state["snapshot"], run=fake,
                            delay=delay, lock=threading.RLock())
    return sync, state


def test_sync_skipped_while_locked() -> None:
    fake = FakeProvider()
    sync, _state = _sync(fake, snapshot=None)
    sync.schedule()
    sync.flush()
    assert fake.calls == []


def test_sync_skipped_when_setting_off() -> None:
    fake = FakeProvider()
    sync, state = _sync(fake, enabled=False, snapshot=_entries("ann"))
    sync.schedule()
    sync.flush()
    assert fake.calls == []
    # Turned off after scheduling: the pending run checks again.
    state["enabled"] = True
    sync.schedule()
    state["enabled"] = False
    sync.flush()
    assert fake.calls == []


def test_sync_runs_once_per_change() -> None:
    fake = FakeProvider()
    sync, _state = _sync(fake, snapshot=_entries("ann"), delay=0.2)
    bus = EventBus()
    bus.listeners.append(sync.on_event)
    bus.emit("items.changed", {})
    bus.emit("items.changed", {})  # inside the debounce
    deadline = threading.Event()
    deadline.wait(0.6)
    assert fake.calls == [("--sync",)]
    bus.emit("items.changed", {})  # unchanged digest
    sync.flush()
    assert fake.calls == [("--sync",)]
    bus.emit("toast", {})  # not a sync event
    sync.flush()
    assert fake.calls == [("--sync",)]


def test_sync_after_rename_and_delete() -> None:
    fake = FakeProvider()
    sync, state = _sync(fake, snapshot=_entries("ann", "bob"))
    sync.schedule()
    sync.flush()
    state["snapshot"] = [{**_entries("ann")[0], "user_name": "ann2"}, _entries("bob")[0]]  # rename
    sync.schedule()
    sync.flush()
    state["snapshot"] = _entries("bob")  # delete
    sync.on_event("vault.state", {})
    sync.flush()
    state["snapshot"] = []  # last one gone: Windows' cache must be emptied too
    sync.schedule()
    sync.flush()
    assert fake.calls == [("--sync",)] * 4


def test_sync_failure_retries_on_next_change_and_forget_resyncs() -> None:
    fake = FakeProvider(**{"--sync": {"ok": False, "error": "query_failed"}})
    sync, _state = _sync(fake, snapshot=_entries("ann"))
    sync.schedule()
    sync.flush()
    fake.answers["--sync"] = {"ok": True}
    sync.schedule()
    sync.flush()
    assert len(fake.calls) == 2  # the failed run did not remember the digest
    sync.forget()
    sync.schedule()
    sync.flush()
    assert len(fake.calls) == 3


def test_sync_payload_has_no_key_material(tmp_path) -> None:
    """The sync sends a fixed argument only; the names it compares come from passkey_metadata()."""
    session = create_vault(tmp_path / "v.json", "windows provider sync test", kdf_overrides=KDF)
    session.items.create_passkey("Site", relying_party_id="example.com", credential_id="Q1",
                                 private_key="PRIVATE-KEY-MATERIAL", algorithm="ES256", user_name="ann",
                                 user_handle="dQ", user_display_name="Ann", rp_name="Example")
    fake = FakeProvider()
    sync, _state = _sync(fake, snapshot=session.items.passkey_metadata())
    sync.schedule()
    sync.flush()
    assert fake.calls == [("--sync",)]
    assert "PRIVATE-KEY-MATERIAL" not in json.dumps(session.items.passkey_metadata())


def test_bus_listener_errors_do_not_break_emit() -> None:
    delivered, seen = [], []
    bus = EventBus(delivered.append)

    def broken(_name, _detail):
        raise RuntimeError("boom")

    bus.listeners.extend([broken, lambda name, detail: seen.append((name, detail))])
    bus.emit("items.changed", {"x": 1})
    assert len(delivered) == 1
    assert seen == [("items.changed", {"x": 1})]


# -- app wiring ---------------------------------------------------------------------------------------------------
class FakeController:
    def __init__(self, settings, metadata=None) -> None:
        self.settings = settings
        self.on_unlock: list = []
        self.unlocked = metadata is not None
        self.session = SimpleNamespace(item_service=SimpleNamespace(passkey_metadata=lambda: metadata or []))

    def is_unlocked(self) -> bool:
        return self.unlocked


def _attach(controller, fake, *, available=True):
    bus = EventBus()
    toasts = []
    switch = wpp.attach(controller=controller, bus=bus, run_on_ui=lambda fn, timeout=0: fn(),
                        toast=lambda kind, text: toasts.append((kind, text)), start=lambda work: work(),
                        run=fake, is_available=lambda: available)
    return switch, bus, toasts


def test_startup_cleanup_unregisters_when_setting_off() -> None:
    fake = FakeProvider(**{"--state": {"ok": True, "state": "enabled"}})
    _attach(FakeController(AppSettings()), fake)
    assert fake.commands() == ["--state", "--unregister"]


def test_startup_turns_switch_off_after_reinstall(monkeypatch) -> None:
    saved = []
    monkeypatch.setattr(AppSettings, "save", lambda self, path=None: saved.append(self.windows_passkey_provider))
    controller = FakeController(AppSettings(windows_passkey_provider=True, passkeys_enabled=True))
    fake = FakeProvider()  # --state: not_registered
    _attach(controller, fake)
    assert "--register" not in fake.commands()
    assert controller.settings.windows_passkey_provider is False and saved == [False]


def test_startup_registered_and_on_syncs_after_unlock() -> None:
    controller = FakeController(AppSettings(windows_passkey_provider=True, passkeys_enabled=True),
                                metadata=_entries("ann"))
    fake = FakeProvider(**{"--state": {"ok": True, "state": "enabled"}})
    switch, bus, _toasts = _attach(controller, fake)
    assert fake.commands() == ["--state"]
    assert controller.on_unlock and sync_of(bus) is not None
    sync_of(bus).flush()
    assert fake.commands() == ["--state", "--sync"]
    switch.changed()  # still on: nothing to do
    assert fake.commands() == ["--state", "--sync"]


def test_wiring_no_sync_when_passkeys_off_or_unavailable() -> None:
    controller = FakeController(AppSettings(windows_passkey_provider=True, passkeys_enabled=False),
                                metadata=_entries("ann"))
    fake = FakeProvider(**{"--state": {"ok": True, "state": "enabled"}})
    _switch_obj, bus, _toasts = _attach(controller, fake)
    sync_of(bus).schedule()
    sync_of(bus).flush()
    assert "--sync" not in fake.commands()
    controller.settings = replace(controller.settings, passkeys_enabled=True)
    fake2 = FakeProvider()
    _s, bus2, _t = _attach(controller, fake2, available=False)
    sync_of(bus2).schedule()
    sync_of(bus2).flush()
    assert fake2.calls == []


def test_wiring_locked_snapshot_is_none() -> None:
    controller = FakeController(AppSettings(windows_passkey_provider=True, passkeys_enabled=True))
    fake = FakeProvider(**{"--state": {"ok": True, "state": "enabled"}})
    _switch_obj, bus, _toasts = _attach(controller, fake)
    bus.emit("vault.state", {"state": "locked"})
    sync_of(bus).flush()
    assert fake.commands() == ["--state"]


def sync_of(bus):
    listener = bus.listeners[-1]
    return getattr(listener, "__self__", None)


# -- fix round 1 ----------------------------------------------------------------------------------------------------
def test_sync_gets_a_longer_timeout(packaged, monkeypatch) -> None:
    seen = []
    monkeypatch.setattr(wpp, "_same_signer", lambda _path: True)
    monkeypatch.setattr(wpp.subprocess, "run",
                        lambda argv, **kw: seen.append(kw["timeout"]) or SimpleNamespace(stdout=b'{"ok":true}'))
    wpp.run_provider("--sync")
    wpp.run_provider("--state")
    assert seen == [30.0, 15.0]


@pytest.fixture
def frozen_installer(monkeypatch):
    """A frozen build without package identity on a supported Windows."""
    monkeypatch.setattr(wpp.os, "name", "nt")
    monkeypatch.setattr(wpp.sys, "frozen", True, raising=False)
    monkeypatch.setattr(wpp.distribution, "is_packaged", lambda: False)
    monkeypatch.setattr(wpp, "_windows_build", lambda: (26200, 7000))


@pytest.mark.parametrize("installed", [True, None])
def test_native_cleanup_skipped_when_a_package_is_installed_or_unsure(frozen_installer, monkeypatch,
                                                                      installed) -> None:
    import ctypes

    monkeypatch.setattr(wpp, "package_installed", lambda: installed)
    monkeypatch.setattr(ctypes, "WinDLL", lambda *_a, **_k: pytest.fail("webauthn.dll must not be loaded"))
    assert wpp._native_cleanup() == "skipped"


def test_package_installed_is_unsure_when_a_query_fails(monkeypatch) -> None:
    monkeypatch.setattr(wpp.os, "name", "nt")
    monkeypatch.setattr(wpp, "package_family_name", lambda name, publisher: f"{name}_x")
    monkeypatch.setattr(wpp, "_packages_in_family", lambda family: None)
    assert wpp.package_installed() is None
    monkeypatch.setattr(wpp, "_packages_in_family", lambda family: 0)
    assert wpp.package_installed() is False
    monkeypatch.setattr(wpp, "_packages_in_family", lambda family: 1 if family.startswith("LocalGateKeys.Test") else 0)
    assert wpp.package_installed() is True
    monkeypatch.setattr(wpp, "package_family_name", lambda name, publisher: None)
    assert wpp.package_installed() is None


def test_package_identities_match_the_build_files() -> None:
    root = Path(__file__).resolve().parents[1]
    store = json.loads((root / "build-msix" / "store-identity.json").read_text(encoding="utf-8"))
    script = (root / "scripts" / "build_msix_package.ps1").read_text(encoding="utf-8")
    assert (store["Name"], store["Publisher"]) in wpp.PACKAGE_IDENTITIES
    for name, publisher in wpp.PACKAGE_IDENTITIES:
        if name != store["Name"]:
            assert f'Name = "{name}"' in script and f'Publisher = "{publisher}"' in script


@pytest.mark.skipif(wpp.os.name != "nt", reason="appmodel API")
def test_package_family_name_uses_the_documented_api() -> None:
    assert wpp.package_family_name("LocalGateKeys.Test", "CN=LocalGateKeys Test Signing") ==         "LocalGateKeys.Test_qhrrfmay8q2xp"
    assert wpp.package_installed() in (True, False)


def test_passkeys_off_clears_the_cache_and_on_syncs_in_full() -> None:
    fake, desired, passkeys = FakeProvider(), {"on": True}, {"on": True}
    sync = wpp.MetadataSync(enabled=lambda: passkeys["on"], snapshot=lambda: _entries("ann"), run=fake,
                            delay=60.0, lock=threading.RLock())
    switch = wpp.ProviderSwitch(desired=lambda: desired["on"], toast=lambda *_a: None, switch_off=lambda: None,
                                sync=sync, run=fake, open_settings=lambda: None, spawn=lambda work: work(),
                                passkeys_on=lambda: passkeys["on"])
    switch.changed()
    sync.flush()
    assert fake.commands() == ["--register", "--sync"]
    passkeys["on"] = False
    switch.passkeys_changed()
    assert fake.commands()[-1] == "--clear-cache"  # registration kept: no --unregister
    sync.schedule()
    sync.flush()
    assert fake.commands().count("--sync") == 1
    passkeys["on"] = True
    switch.passkeys_changed()
    sync.flush()
    assert fake.commands() == ["--register", "--sync", "--clear-cache", "--sync"]  # unchanged names, full sync


def test_passkeys_toggle_does_nothing_while_provider_off() -> None:
    fake = FakeProvider()
    switch = wpp.ProviderSwitch(desired=lambda: False, toast=lambda *_a: None, switch_off=lambda: None,
                                sync=SyncSpy(), run=fake, spawn=lambda work: work(), passkeys_on=lambda: False)
    switch.passkeys_changed()
    assert fake.calls == []


def test_startup_registered_with_passkeys_off_clears_the_cache() -> None:
    controller = FakeController(AppSettings(windows_passkey_provider=True, passkeys_enabled=False),
                                metadata=_entries("ann"))
    fake = FakeProvider(**{"--state": {"ok": True, "state": "enabled"}})
    _attach(controller, fake)
    assert fake.commands() == ["--state", "--clear-cache"]


def test_duress_unlock_clears_the_cache_and_next_real_unlock_resyncs(monkeypatch) -> None:
    """P-01: the real vault's names leave Windows' picker on a duress unlock and come back on a real one."""
    monkeypatch.setattr(wpp, "_start_ticker", lambda _tick: None)
    monkeypatch.setattr(wpp.REGISTRATION, "refresh_later", lambda **_kw: None)
    controller = FakeController(AppSettings(windows_passkey_provider=True, passkeys_enabled=True),
                                metadata=_entries("ann"))
    fake = FakeProvider(**{"--state": {"ok": True, "state": "enabled"}})
    _switch_obj, bus, _toasts = _attach(controller, fake)
    sync = sync_of(bus)
    sync.flush()
    assert fake.commands() == ["--state", "--sync"]
    real = controller.session
    controller.session = SimpleNamespace(decoy=True, item_service=real.item_service)
    for hook in controller.on_unlock:
        hook()
    sync.flush()
    assert fake.commands() == ["--state", "--sync", "--clear-cache"]  # cleared, nothing published
    controller.session = real
    for hook in controller.on_unlock:
        hook()
    sync.flush()
    assert fake.commands() == ["--state", "--sync", "--clear-cache", "--sync"]  # same names, synced again


def test_failed_clear_is_retried_from_the_ticker(monkeypatch) -> None:
    ticks = []
    monkeypatch.setattr(wpp, "_start_ticker", ticks.append)
    monkeypatch.setattr(wpp.REGISTRATION, "refresh_later", lambda **_kw: None)
    controller = FakeController(AppSettings(windows_passkey_provider=True, passkeys_enabled=False),
                                metadata=_entries("ann"))
    fake = FakeProvider(**{"--state": {"ok": True, "state": "enabled"}, "--clear-cache": {"ok": False}})
    switch, bus, _toasts = _attach(controller, fake)
    sync = sync_of(bus)
    assert fake.commands() == ["--state", "--clear-cache"] and sync.clear_pending
    (tick,) = ticks
    tick()
    assert fake.commands().count("--clear-cache") == 2 and sync.clear_pending  # still failing: keep trying
    fake.answers["--clear-cache"] = {"ok": True}
    tick()
    assert fake.commands().count("--clear-cache") == 3 and not sync.clear_pending
    tick()
    assert fake.commands().count("--clear-cache") == 3  # done: no more retries
    # Fails again, then passkeys come back on before the next tick: nothing to clear any more.
    fake.answers["--clear-cache"] = {"ok": False}
    sync.clear()
    assert sync.clear_pending
    controller.settings = AppSettings(windows_passkey_provider=True, passkeys_enabled=True)
    tick()
    assert fake.commands().count("--clear-cache") == 4 and not sync.clear_pending


def test_clear_retry_stops_when_the_provider_is_unregistered() -> None:
    fake = FakeProvider(**{"--clear-cache": {"ok": False}})
    sync = wpp.MetadataSync(enabled=lambda: False, snapshot=lambda: None, run=fake, lock=threading.RLock())
    assert sync.clear() is False and sync.clear_pending
    assert sync.retry_clear(lambda: True) is True and fake.commands() == ["--clear-cache"] * 2
    sync.forget()  # switch turned off / passkeys on: the unregister or full sync replaces the clear
    assert not sync.clear_pending and sync.retry_clear(lambda: True) is False
    assert sync.clear() is False
    assert sync.retry_clear(lambda: 1 / 0) is False and sync.clear_pending  # unknown: keep it for the next tick
    assert fake.commands().count("--clear-cache") == 3


def test_duress_unlock_hook_never_waits_on_the_provider_lock(monkeypatch) -> None:
    """Scan 3 suspicion 1: a sync holds PROVIDER_LOCK while it waits for the vault lock that an unlock hook may
    hold; the hook must hand the provider-lock read to its worker instead of taking the lock itself."""
    import threading

    monkeypatch.setattr(wpp, "_start_ticker", lambda _tick: None)
    monkeypatch.setattr(wpp.REGISTRATION, "refresh_later", lambda **_kw: None)
    controller = FakeController(AppSettings(windows_passkey_provider=True, passkeys_enabled=True),
                                metadata=_entries("ann"))
    fake = FakeProvider(**{"--state": {"ok": True, "state": "enabled"}})
    started = []
    wpp.attach(controller=controller, bus=EventBus(), run_on_ui=lambda fn, timeout=0: fn(),
               toast=lambda kind, text: None, start=lambda work: started.append(work) or (work() if
                                                                                           len(started) == 1 else None),
               run=fake, is_available=lambda: True)
    controller.session = SimpleNamespace(decoy=True, item_service=controller.session.item_service)
    held, release = threading.Event(), threading.Event()

    def holder() -> None:
        with wpp.PROVIDER_LOCK:
            held.set()
            release.wait(5)

    thread = threading.Thread(target=holder, daemon=True)
    thread.start()
    held.wait(5)
    done = threading.Event()
    hooks = threading.Thread(target=lambda: ([hook() for hook in controller.on_unlock], done.set()), daemon=True)
    hooks.start()
    assert done.wait(2), "the unlock hook blocked on PROVIDER_LOCK"
    release.set()
    thread.join(5)
    assert len(started) == 2  # start-up work, then the decoy clear handed to a worker
    started[1]()
    assert fake.commands()[-1] == "--clear-cache"
