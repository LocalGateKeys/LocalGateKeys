from __future__ import annotations

import pytest

from localvault import build_check, licensing


def test_release_build_requires_license_key(monkeypatch):
    monkeypatch.setattr(licensing, "LICENSE_KEYS", {})
    with pytest.raises(RuntimeError, match="LICENSE_KEYS is empty"):
        build_check.check(require_license_keys=True)
    assert build_check.main(require_license_keys=True) == 1


def test_release_flag_defaults_off():
    import inspect
    assert inspect.signature(build_check.check).parameters["require_license_keys"].default is False


def test_build_check_requires_bcrypt(monkeypatch):
    real = build_check.importlib.import_module

    def fake(name, *args, **kwargs):
        if name == "bcrypt":
            raise ImportError("No module named 'bcrypt'")
        return real(name, *args, **kwargs)

    monkeypatch.setattr(build_check.importlib, "import_module", fake)
    with pytest.raises(ImportError, match="bcrypt"):
        build_check.check()
