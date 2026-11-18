"""Starter collections stay English in the vault and are translated only on screen."""
from localvault import i18n
from localvault.collections import STARTER_COLLECTIONS, display_name


def test_starters_are_translated_on_screen_only(monkeypatch):
    monkeypatch.delenv("LOCALGATEKEYS_LANG", raising=False)
    before = i18n.current()
    try:
        i18n.set_language("de")
        assert [display_name(n) for n in STARTER_COLLECTIONS] == ["Persönlich", "Arbeit", "Reisen", "Notfall"]
        assert display_name("Family") == "Family"
        assert display_name("personal") == "personal"
        i18n.set_language("en")
        assert [display_name(n) for n in STARTER_COLLECTIONS] == list(STARTER_COLLECTIONS)
    finally:
        i18n.set_language(before)
