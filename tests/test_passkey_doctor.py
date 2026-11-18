"""Passkey doctor (feature idea 3, Windows slice): read-only status lines and checks."""
from __future__ import annotations

from types import SimpleNamespace

import pytest

from localvault.app.passkey_doctor import PasskeyDoctorService, provider_status
from localvault.windows_passkey_provider import RegistrationState


@pytest.fixture(autouse=True)
def _data(tmp_path, monkeypatch):
    monkeypatch.setenv("LOCALGATEKEYS_DATA_DIR", str(tmp_path / "data"))


@pytest.mark.parametrize("available,on,state,code", [
    (False, True, "enabled", "unavailable"),
    (True, False, "enabled", "off"),
    (True, True, "enabled", "active"),
    (True, True, "disabled", "not_active"),
    (True, True, "not_registered", "not_active"),
    (True, True, None, "checking"),
])
def test_provider_status(available, on, state, code):
    assert provider_status(available, on, state)[0] == code


def _service(state="enabled", recent=True, registration=None, opened=None, passkeys=True):
    settings = SimpleNamespace(windows_passkey_provider=True, passkeys_enabled=passkeys)
    report = {"windows": True, "extension_recent": recent, "native_host_exists": True, "native_host_hash_matches": True,
              "registration": registration if registration is not None else {"Chrome": "ready", "Edge": "not_registered"}}
    return PasskeyDoctorService(lambda: settings, collect=lambda **kw: report,
                                provider=lambda: {"available": True, "state": state},
                                open_settings=(lambda: opened.append(1)) if opened is not None else (lambda: None))


def test_view_lists_checks_and_browsers():
    view = _service().view()
    assert view["provider"]["code"] == "active"
    assert {c["key"]: c["ok"] for c in view["checks"]} == {"provider": True, "passkeys": True, "host": True,
                                                           "extension": True}
    assert [(b["browser"], b["ok"]) for b in view["browsers"]] == [("Chrome", True), ("Edge", False), ("Firefox", False)]


def test_view_flags_problems():
    view = _service(state="disabled", recent=False, passkeys=False).view()
    assert {c["key"]: c["ok"] for c in view["checks"]} == {"provider": False, "passkeys": False, "host": True,
                                                           "extension": False}


def test_open_settings_only_opens_the_page():
    opened = []
    assert _service(opened=opened).open_settings() == {}
    assert opened == [1]


def test_registration_current_is_none_when_stale(monkeypatch):
    from localvault import windows_passkey_provider as module

    state = RegistrationState(spawn=lambda work: None)
    assert state.current() is None
    state.record("enabled")
    assert state.current() == "enabled"
    real = module.time.monotonic
    monkeypatch.setattr(module.time, "monotonic", lambda: real() + module.MAX_AGE + 1)
    assert state.current() is None


@pytest.mark.parametrize("exists,matches,ok,detail", [
    (True, True, True, "Yes"),
    (True, False, False, "Does not match this version, repair it in Connections"),
    (False, False, False, "Missing, repair it in Connections"),
])
def test_host_row_text_matches_its_mark(exists, matches, ok, detail):
    """Final review L8: a host that exists but does not match this version is not shown as "Yes"."""
    service = _service()
    report = service._collect()
    report.update(native_host_exists=exists, native_host_hash_matches=matches)
    service._collect = lambda **kw: report
    host = next(c for c in service.view()["checks"] if c["key"] == "host")
    assert (host["ok"], host["detail"]) == (ok, detail)
