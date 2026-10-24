from __future__ import annotations

from localvault import ui_assets


def test_owned_brand_path_helpers_follow_frozen_asset_root(monkeypatch, tmp_path) -> None:
    frozen_root = tmp_path / "_internal"
    monkeypatch.setattr(ui_assets.sys, "_MEIPASS", str(frozen_root), raising=False)

    assert ui_assets.asset_root() == frozen_root / "assets"


