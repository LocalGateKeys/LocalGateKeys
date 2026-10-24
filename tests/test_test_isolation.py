"""Tests must never read or write the owner's real LocalGateKeys data folder."""
from __future__ import annotations

import os
from pathlib import Path

from localvault.settings import settings_path


def test_settings_path_is_not_the_real_data_folder():
    real = Path(os.environ.get("LOCALAPPDATA", str(Path.home()))) / "LocalGateKeys"
    assert real not in settings_path().resolve().parents
