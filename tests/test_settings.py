from pathlib import Path

import pytest

from localvault.settings import AppSettings


def test_strict_offline_defaults_on() -> None:
    assert AppSettings().strict_offline_mode is True


def test_appearance_defaults_light_and_round_trips(tmp_path: Path) -> None:
    path = tmp_path / "settings.json"
    assert AppSettings().appearance == "light"
    settings = AppSettings(appearance="dark")
    settings.save(path)
    assert AppSettings.load(path).appearance == "dark"


def test_list_sort_round_trips_and_rejects_unknown(tmp_path: Path) -> None:
    import json

    path = tmp_path / "settings.json"
    assert AppSettings().list_sort == "title_asc" and AppSettings().list_favorites_first is True
    AppSettings(list_sort="created_desc", list_favorites_first=False).save(path)
    loaded = AppSettings.load(path)
    assert loaded.list_sort == "created_desc" and loaded.list_favorites_first is False
    raw = json.loads(path.read_text(encoding="utf-8"))
    raw.update(list_sort="size", list_favorites_first="no")
    path.write_text(json.dumps(raw), encoding="utf-8")
    loaded = AppSettings.load(path)
    assert loaded.list_sort == "title_asc" and loaded.list_favorites_first is True
    AppSettings(list_sort="bogus").save(path)
    assert json.loads(path.read_text(encoding="utf-8"))["list_sort"] == "title_asc"


def test_older_settings_without_appearance_migrate_to_light(tmp_path: Path) -> None:
    path = tmp_path / "settings.json"
    path.write_text('{"version":5,"auto_lock_seconds":420}', encoding="utf-8")
    loaded = AppSettings.load(path)
    assert loaded.appearance == "light"
    assert loaded.auto_lock_seconds == 420


def test_invalid_saved_appearance_falls_back_to_light(tmp_path: Path) -> None:
    path = tmp_path / "settings.json"
    path.write_text('{"version":5,"appearance":"sepia"}', encoding="utf-8")
    assert AppSettings.load(path).appearance == "light"


def test_invalid_appearance_cannot_be_saved(tmp_path: Path) -> None:
    path = tmp_path / "settings.json"
    with pytest.raises(ValueError, match="light or dark"):
        AppSettings(appearance="sepia").save(path)
    assert not path.exists()


def test_settings_round_trip(tmp_path: Path) -> None:
    path = tmp_path / "settings.json"
    settings = AppSettings(
        auto_lock_seconds=900,
        start_with_windows=True,
        browser_enabled=False,
        desktop_overlay_enabled=False,
        minimize_to_tray=False,
        lock_on_session_lock=True,
        lock_on_sleep=False,
        appearance="dark",
    )
    settings.save(path)
    loaded = AppSettings.load(path)
    assert loaded == settings


def test_settings_bounds_auto_lock_timeout(tmp_path: Path) -> None:
    path = tmp_path / "settings.json"
    path.write_text('{"version":1,"auto_lock_seconds":1}', encoding="utf-8")
    assert AppSettings.load(path).auto_lock_seconds == 30
    path.write_text('{"version":1,"auto_lock_seconds":0}', encoding="utf-8")
    assert AppSettings.load(path).auto_lock_seconds == 0


def test_hide_from_capture_defaults_on_and_round_trips(tmp_path: Path) -> None:
    assert AppSettings().hide_from_capture is True
    path = tmp_path / "settings.json"
    AppSettings(hide_from_capture=False).save(path)
    assert AppSettings.load(path).hide_from_capture is False
    path.write_text('{"version": 8, "hide_from_capture": "no"}', encoding="utf-8")
    assert AppSettings.load(path).hide_from_capture is True
