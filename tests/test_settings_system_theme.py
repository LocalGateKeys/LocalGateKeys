"""Settings keys for the generator and the System appearance mode."""
from __future__ import annotations

from pathlib import Path

import pytest

from localvault.password_tools import GeneratorOptions
from localvault.settings import AppSettings, _validated_appearance
from localvault.settings_ui import settings_candidate


def test_appearance_accepts_system_and_round_trips(tmp_path: Path) -> None:
    assert _validated_appearance("system") == "system"
    with pytest.raises(ValueError):
        _validated_appearance("sepia")
    path = tmp_path / "settings.json"
    AppSettings(appearance="system").save(path)
    assert AppSettings.load(path).appearance == "system"
    assert settings_candidate(AppSettings(), {"appearance": "system"}).appearance == "system"


def test_generator_preferences_are_sanitized_on_load_and_save(tmp_path: Path) -> None:
    path = tmp_path / "settings.json"
    settings = AppSettings(generator_preferences={"mode": "passphrase", "words": 40, "separator": "dot", "bogus": 1})
    settings.save(path)
    loaded = AppSettings.load(path)
    assert loaded.generator_preferences == {**GeneratorOptions().as_dict(), "mode": "passphrase", "words": 16, "separator": "."}
    path.write_text('{"version":5,"generator_preferences":"nonsense"}', encoding="utf-8")
    assert AppSettings.load(path).generator_preferences == GeneratorOptions().as_dict()
    assert AppSettings().generator_preferences == GeneratorOptions().as_dict()


