import json
from types import SimpleNamespace

import pytest

from localvault.api.result import ApiError
from localvault.app import rating
from localvault.app.rating import RatingService
from localvault.settings import AppSettings

PFN = "LocalGateKeys.LocalGateKeys_abcdefghjkmnp"


def _service(tmp_path, monkeypatch, *, strict=False, available=True):
    settings = AppSettings(strict_offline_mode=strict)
    monkeypatch.setattr(settings, "save", lambda path=None: AppSettings.save(settings, tmp_path / "s.json"),
                        raising=False)
    controller = SimpleNamespace(settings=settings, on_unlock=[])
    opened = []
    monkeypatch.setattr(rating.distribution, "package_family_name", lambda: PFN)
    service = RatingService(controller, opener=opened.append, is_available=lambda: available)
    return service, controller, opened


def _unlock(controller, times):
    for _ in range(times):
        for hook in controller.on_unlock:
            hook()


def test_prompt_waits_for_the_third_unlock_and_asks_once(tmp_path, monkeypatch):
    service, controller, opened = _service(tmp_path, monkeypatch)
    _unlock(controller, 2)
    assert service.prompt() == {"due": False}
    _unlock(controller, 1)
    assert service.prompt()["due"] is True
    service.answer(False)
    assert service.prompt() == {"due": False} and opened == []
    assert AppSettings.load(tmp_path / "s.json").rate_prompt_answered is True


def test_rate_now_opens_the_store_review_page(tmp_path, monkeypatch):
    service, controller, opened = _service(tmp_path, monkeypatch)
    _unlock(controller, 4)
    service.answer(True)
    assert opened == [f"ms-windows-store://review/?PFN={PFN}"]


def test_strict_offline_never_prompts_but_settings_row_still_opens(tmp_path, monkeypatch):
    service, controller, opened = _service(tmp_path, monkeypatch, strict=True)
    _unlock(controller, 5)
    assert service.prompt() == {"due": False}
    service.open()
    assert len(opened) == 1


def test_non_store_builds_neither_prompt_nor_open(tmp_path, monkeypatch):
    service, controller, opened = _service(tmp_path, monkeypatch, available=False)
    _unlock(controller, 5)
    assert service.prompt() == {"due": False}
    with pytest.raises(ApiError):
        service.open()


def test_unlock_count_round_trips_and_rejects_junk(tmp_path):
    path = tmp_path / "s.json"
    AppSettings(unlock_count=7).save(path)
    assert AppSettings.load(path).unlock_count == 7
    raw = json.loads(path.read_text())
    raw["unlock_count"] = True
    path.write_text(json.dumps(raw))
    assert AppSettings.load(path).unlock_count == 0


def test_review_uri_rejects_bad_family_names():
    assert rating.review_uri("bad name&x") is None
    assert rating.review_uri(None) is None
