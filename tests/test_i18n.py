import json

import pytest

from localvault import i18n
from localvault.settings import AppSettings


def test_resolve_maps_os_locales():
    assert i18n.resolve("system", "zh-CN") == "zh-Hans"
    assert i18n.resolve("system", "zh-TW") == "zh-Hans"
    assert i18n.resolve("system", "pt-PT") == "pt-BR"
    assert i18n.resolve("system", "es-MX") == "es"
    assert i18n.resolve("system", "nb-NO") == "en"
    assert i18n.resolve("system", None) == "en"
    assert i18n.resolve("de", "ja-JP") == "de"


def test_plural_polish():
    got = [i18n.plural_category("pl", n) for n in (1, 2, 5, 12, 22, 0)]
    assert got == ["one", "few", "many", "many", "few", "many"]
    assert i18n.plural_category("ja", 1) == "other"
    assert i18n.plural_category("pt-BR", 0) == "one"


@pytest.fixture
def cat_dir(tmp_path, monkeypatch):
    (tmp_path / "en.json").write_text(
        json.dumps({"a": "Hi {name}", "n": {"one": "{count} item", "other": "{count} items"}}),
        encoding="utf-8",
    )
    (tmp_path / "de.json").write_text("{}", encoding="utf-8")
    monkeypatch.setattr(i18n, "CATALOG_DIR", tmp_path)
    monkeypatch.setattr(i18n, "_cache", {})
    monkeypatch.delenv("LOCALGATEKEYS_LANG", raising=False)
    yield tmp_path
    i18n.set_language("en")


def test_t_falls_back_and_formats(cat_dir):
    i18n.set_language("de")
    assert i18n.t("a", name="X") == "Hi X"
    assert i18n.t("n", count=2) == "2 items"
    assert i18n.t("n", count=1) == "1 item"
    assert i18n.t("missing.key") == "missing.key"
    assert i18n.t("a") == "Hi {name}"


def test_broken_catalog_falls_back(cat_dir):
    (cat_dir / "de.json").write_text("{", encoding="utf-8")
    i18n.set_language("de")
    assert i18n.t("a", name="X") == "Hi X"


def test_env_override_and_pseudo(cat_dir, monkeypatch):
    monkeypatch.setenv("LOCALGATEKEYS_LANG", "en-XA")
    i18n.set_language("de")
    assert i18n.current() == "en-XA"
    monkeypatch.setenv("LOCALGATEKEYS_LANG", "xx")
    i18n.set_language("de")
    assert i18n.current() == "en"


def test_settings_language_validated(tmp_path):
    path = tmp_path / "s.json"
    path.write_text(json.dumps({"version": 8, "language": "xx"}), encoding="utf-8")
    assert AppSettings.load(path).language == "system"
    s = AppSettings()
    s.language = "pl"
    s.save(path)
    assert AppSettings.load(path).language == "pl"


def test_t_never_raises_on_bad_format(cat_dir):
    (cat_dir / "en.json").write_text(json.dumps({"bad": "{name[x]}", "bad2": "{0}", "bad3": "{name.x}"}), encoding="utf-8")
    i18n.set_language("en")
    assert i18n.t("bad", name="X") == "{name[x]}"
    assert i18n.t("bad2") == "{0}"
    assert i18n.t("bad3", name="X") == "{name.x}"


def test_settings_palette_titles_use_catalog_keys(monkeypatch):
    monkeypatch.delenv("LOCALGATEKEYS_LANG", raising=False)
    from localvault.shell.commands import COMMANDS, registered_section_commands  # noqa: F401
    en = json.loads((i18n.CATALOG_DIR / "en.json").read_text(encoding="utf-8"))
    i18n.set_language("de")
    try:
        cmd = next(c for c in COMMANDS if c.id == "settings-locking")
        assert cmd.title_key in en
        assert cmd.title == i18n.t(cmd.title_key) != en[cmd.title_key]
    finally:
        i18n.set_language("en")
