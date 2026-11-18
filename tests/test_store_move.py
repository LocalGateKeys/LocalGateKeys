import json
from datetime import date
from types import SimpleNamespace

import pytest

from localvault import distribution
from localvault.api.result import ApiError
from localvault.app import store_move
from localvault.app.store_move import STORE_APP_URI, STORE_WEB_URL, StoreMoveService
from localvault.i18n import t
from localvault.settings import AppSettings


def _service(tmp_path, monkeypatch, *, applies=True, opener=None):
    settings = AppSettings()
    monkeypatch.setattr(settings, "save", lambda path=None: AppSettings.save(settings, tmp_path / "s.json"),
                        raising=False)
    controller = SimpleNamespace(settings=settings)
    opened = []
    service = StoreMoveService(controller, opener=opener or opened.append, is_applicable=lambda: applies)
    return service, controller, opened


def test_installer_build_shows_the_notice_after_unlock(tmp_path, monkeypatch):
    service, _, opened = _service(tmp_path, monkeypatch)
    notice = service.notice()
    assert notice == {"due": True, "title": t("storeMove.title"), "text": t("storeMove.text")}
    assert "Microsoft Store" in notice["title"]
    assert "vault stays where it is" in notice["text"] and "uninstall" in notice["text"]
    assert opened == []  # showing it opens nothing and uses no network


def test_open_store_opens_the_store_app_page_and_snoozes(tmp_path, monkeypatch):
    service, _, opened = _service(tmp_path, monkeypatch)
    service.answer(True)
    assert opened == [STORE_APP_URI]
    assert STORE_APP_URI == "ms-windows-store://pdp/?ProductId=9PNWCNLQ6597"
    assert service.notice() == {"due": False}
    assert AppSettings.load(tmp_path / "s.json").store_move_snoozed_until == store_move.snooze_date()


def test_later_snoozes_for_a_few_days_then_shows_again(tmp_path, monkeypatch):
    service, controller, opened = _service(tmp_path, monkeypatch)
    service.answer(False)
    assert opened == [] and service.notice() == {"due": False}
    controller.settings.store_move_snoozed_until = "2000-01-01"
    assert service.notice()["due"] is True


def test_snooze_date_is_three_days_out():
    assert store_move.snooze_date(date(2026, 11, 9)) == "2026-11-12"
    assert store_move._snoozed("2026-11-12", date(2026, 11, 11)) is True
    assert store_move._snoozed("2026-11-12", date(2026, 11, 12)) is False
    assert store_move._snoozed("junk", date(2026, 11, 12)) is False


def test_falls_back_to_the_web_listing_when_the_store_app_is_missing(tmp_path, monkeypatch):
    opened = []

    def opener(target):
        if target.startswith("ms-windows-store:"):
            raise OSError("no handler")
        opened.append(target)

    service, _, _ = _service(tmp_path, monkeypatch, opener=opener)
    service.open()
    assert opened == [STORE_WEB_URL] == ["https://apps.microsoft.com/detail/9PNWCNLQ6597"]


def test_reports_when_nothing_can_be_opened(tmp_path, monkeypatch):
    def opener(target):
        raise OSError("nothing")

    service, _, _ = _service(tmp_path, monkeypatch, opener=opener)
    with pytest.raises(ApiError) as caught:
        service.open()
    assert STORE_WEB_URL in str(caught.value.message)


def test_store_sideload_and_source_builds_never_show_or_open(tmp_path, monkeypatch):
    service, _, opened = _service(tmp_path, monkeypatch, applies=False)
    assert service.notice() == {"due": False}
    with pytest.raises(ApiError):
        service.open()
    assert opened == []


@pytest.mark.parametrize("frozen,channel,os_name,expected", [
    (True, distribution.CHANNEL_DIRECT, "nt", True),
    (True, distribution.CHANNEL_STORE, "nt", False),
    (True, distribution.CHANNEL_SIDELOAD, "nt", False),
    (False, distribution.CHANNEL_DIRECT, "nt", False),
    (True, distribution.CHANNEL_DIRECT, "posix", False),
])
def test_only_the_installer_build_applies(monkeypatch, frozen, channel, os_name, expected):
    monkeypatch.setattr(distribution, "_is_frozen", lambda: frozen)
    monkeypatch.setattr(distribution, "channel", lambda: channel)
    monkeypatch.setattr(distribution.os, "name", os_name)
    assert store_move.applies() is expected


def test_snooze_round_trips_and_rejects_junk(tmp_path):
    path = tmp_path / "s.json"
    AppSettings(store_move_snoozed_until="2026-11-12").save(path)
    assert AppSettings.load(path).store_move_snoozed_until == "2026-11-12"
    raw = json.loads(path.read_text())
    raw["store_move_snoozed_until"] = "tomorrow"
    path.write_text(json.dumps(raw))
    assert AppSettings.load(path).store_move_snoozed_until == ""


def test_every_catalog_translates_the_notice():
    from pathlib import Path

    folder = Path(store_move.__file__).resolve().parents[1] / "assets" / "i18n"
    english = json.loads((folder / "en.json").read_text(encoding="utf-8"))
    keys = [key for key in english if key.startswith("storeMove.")]
    assert len(keys) == 8
    catalogs = [p for p in folder.glob("*.json") if p.stem not in ("en", "en-XA")]
    assert len(catalogs) == 10
    for path in catalogs:
        data = json.loads(path.read_text(encoding="utf-8"))
        for key in keys:
            assert data.get(key) and data[key] != english[key] or key == "storeMove.later", (path.stem, key)


def test_settings_row_only_in_the_installer_build(monkeypatch):
    from localvault.shell import settings_sections

    rows = []
    form = SimpleNamespace(
        app=SimpleNamespace(store_move_clicked=lambda: None, check_updates_clicked=lambda: None),
        segmented=lambda *a, **k: None, choice=lambda *a, **k: None, switch=lambda *a, **k: None,
        button=lambda title, *a, **k: rows.append(title))
    monkeypatch.setattr(store_move, "applies", lambda: True)
    monkeypatch.setattr("localvault.app.rating.available", lambda: False)
    settings_sections.build_appearance(form)
    assert t("storeMove.settings.title") in rows
    rows.clear()
    monkeypatch.setattr(store_move, "applies", lambda: False)
    settings_sections.build_appearance(form)
    assert t("storeMove.settings.title") not in rows
