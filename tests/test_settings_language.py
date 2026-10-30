"""The language picker: validation, live switch, option labels."""
from __future__ import annotations

import pytest

from localvault import i18n
from localvault.api.result import ApiError
from localvault.settings_ui import choice_options
from test_app_settings import env  # noqa: F401 - pytest fixture


@pytest.fixture(autouse=True)
def _restore_language(monkeypatch):
    monkeypatch.delenv("LOCALGATEKEYS_LANG", raising=False)
    monkeypatch.delenv("LOCALGATEKEYS_DEV", raising=False)
    yield
    i18n.set_language("en")


def test_choosing_a_language_switches_it_and_emits(env):  # noqa: F811
    service, controller, _port, bus, saved, _ = env
    service.apply("language", "de")
    assert controller.settings.language == "de"
    assert i18n.current() == "de"
    assert ("language_changed", {"lang": "de"}) in bus.events
    assert saved


def test_system_resolves_from_the_os_locale(env, monkeypatch):  # noqa: F811
    service, _controller, _port, bus, _saved, _ = env
    service.apply("language", "de")
    monkeypatch.setattr(i18n, "os_locale", lambda: "pl-PL")
    service.apply("language", "system")
    assert i18n.current() == "pl"


def test_unknown_language_is_refused(env):  # noqa: F811
    service, controller, *_ = env
    with pytest.raises(ApiError):
        service.apply("language", "xx")
    assert controller.settings.language == "system"


def test_options_use_native_names_and_pseudo_only_in_dev(monkeypatch):
    labels = list(choice_options("language", "system"))
    assert labels[0] == "System default"
    assert {"English", "Español", "Deutsch", "Português (Brasil)", "简体中文", "日本語"} <= set(labels)
    assert "Pseudo" not in labels
    monkeypatch.setenv("LOCALGATEKEYS_DEV", "1")
    assert "Pseudo" in choice_options("language", "system")


def test_the_language_row_sits_in_the_appearance_section(env):  # noqa: F811
    service, *_ = env
    section = next(s for s in service.page()["sections"] if s["key"] == "appearance")
    row = next(r for r in section["rows"] if r.get("key") == "language")
    assert row["type"] == "choice" and row["title"] == "Language"
    assert row["value"] == "system"
