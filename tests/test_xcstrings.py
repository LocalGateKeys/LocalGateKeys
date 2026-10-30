import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import xcstrings as xc  # noqa: E402


def _win(tmp_path, data):
    for lang, values in data.items():
        (tmp_path / f"{lang}.json").write_text(json.dumps(values, ensure_ascii=False), encoding="utf-8")
    return tmp_path


def test_round_trip_matches_xcode_format(tmp_path):
    text = (
        '{\n  "sourceLanguage" : "en",\n  "strings" : {\n    "Hi" : {\n      "comment" : "x",\n'
        '      "localizations" : {\n        "de" : {\n          "stringUnit" : {\n'
        '            "state" : "translated",\n            "value" : "Hallo"\n          }\n'
        '        }\n      }\n    }\n  },\n  "version" : "1.0"\n}\n'
    )
    path = tmp_path / "L.xcstrings"
    path.write_bytes(text.encode())
    xc.save(path, xc.load(path))
    assert path.read_bytes() == text.encode()


def test_dumps_keeps_unicode_and_sorts():
    cat = xc.empty()
    xc.add(cat, "b")
    xc.add(cat, "a", "ä")
    out = xc.dumps(cat)
    assert out.index('"a"') < out.index('"b"') and "ä" in out and out.endswith("}\n")


def test_convert_placeholders():
    assert xc.convert("Hi {name}", ["name"]) == "Hi %@"
    assert xc.convert("{count} items", ["count"]) == "%lld items"
    assert xc.convert("{name} has {count}", ["name", "count"]) == "%1$@ has %2$lld"
    # Translations reorder; positions come from the English order.
    assert xc.convert("{count} bei {name}", ["name", "count"]) == "%2$lld bei %1$@"
    assert xc.convert("100% {x}", ["x"], {"x": "lld"}) == "100%% %lld"
    with pytest.raises(ValueError):
        xc.convert("{other}", ["name"])


def test_add_explicit_key_and_plural():
    cat = xc.empty()
    xc.add(cat, "sync.x", "Done", comment="c")
    xc.add(cat, "%lld logins", {"one": "%lld login", "other": "%lld logins"})
    e = cat["strings"]["sync.x"]
    assert e["comment"] == "c" and e["localizations"]["en"]["stringUnit"]["value"] == "Done"
    plural = cat["strings"]["%lld logins"]["localizations"]["en"]["variations"]["plural"]
    assert plural["one"]["stringUnit"]["value"] == "%lld login"


def test_import_windows_and_todo(tmp_path):
    win = _win(tmp_path, {
        "en": {"sync.off": "PC {name} is off", "a.b": "Delete {count} items?",
               "p.q": {"one": "{count} login", "other": "{count} logins"}, "diff": "Other"},
        "de": {"sync.off": "PC {name} ist aus", "a.b": "{count} Einträge löschen?",
               "p.q": {"one": "{count} Login", "other": "{count} Logins"}, "diff": "Anders"},
        "ja": {"sync.off": "PC {name} はオフ"},
    })
    cat = xc.empty()
    xc.add(cat, "sync.off", "PC %@ is off")          # explicit Windows key
    xc.add(cat, "Delete %lld items?")                 # English source key
    xc.add(cat, "%lld logins", {"one": "%lld login", "other": "%lld logins"})
    xc.add(cat, "diff", "Not the same")               # Windows key, English differs: skipped
    xc.add(cat, "Kept")
    cat["strings"]["Kept"]["localizations"] = {"de": xc._unit("Behalten")}

    n = xc.import_windows(cat, win)
    s = cat["strings"]
    assert s["sync.off"]["localizations"]["de"]["stringUnit"]["value"] == "PC %@ ist aus"
    assert s["sync.off"]["localizations"]["ja"]["stringUnit"]["value"] == "PC %@ はオフ"
    assert s["Delete %lld items?"]["localizations"]["de"]["stringUnit"]["value"] == "%lld Einträge löschen?"
    de_plural = s["%lld logins"]["localizations"]["de"]["variations"]["plural"]
    assert de_plural["one"]["stringUnit"]["value"] == "%lld Login"
    assert "de" not in s["diff"]["localizations"]
    assert n == 4

    left = xc.todo(cat)
    assert "sync.off" not in left["de"] and "Kept" not in left["de"]
    assert "Delete %lld items?" in left["ja"] and "diff" in left["de"]
    assert set(left) == set(xc.LANGS)


def test_import_keeps_existing_unless_forced(tmp_path):
    win = _win(tmp_path, {"en": {"k": "Yes"}, "de": {"k": "Ja"}})
    cat = xc.empty()
    xc.add(cat, "k", "Yes")
    cat["strings"]["k"]["localizations"]["de"] = xc._unit("Jawohl")
    assert xc.import_windows(cat, win) == 0
    assert xc.import_windows(cat, win, force=True) == 1
    assert cat["strings"]["k"]["localizations"]["de"]["stringUnit"]["value"] == "Ja"


def test_cli_add_and_todo(tmp_path, capsys):
    path = tmp_path / "L.xcstrings"
    xc.main(["add", str(path), "Hello"])
    xc.main(["todo", str(path)])
    assert json.loads(capsys.readouterr().out)["de"] == ["Hello"]


def test_repo_catalogs_are_valid():
    root = Path(__file__).resolve().parents[1] / "ios"
    for path in root.rglob("*.xcstrings"):
        cat = xc.load(path)
        assert cat["sourceLanguage"] == "en" and cat["version"] == "1.0"
        assert path.read_bytes() == xc.dumps(cat).encode("utf-8"), path


def _cat():
    cat = xc.empty()
    xc.add(cat, "Hello %@", comment="greeting")
    xc.add(cat, "n.items", {"one": "%lld item", "other": "%lld items"})
    xc.add(cat, "Line\none %1$@ %2$lld")
    xc.add(cat, "Done")
    cat["strings"]["Done"]["localizations"] = {"de": xc._unit("Fertig")}
    return cat


def test_export_lists_missing_with_plurals_and_comments(tmp_path):
    path = tmp_path / "L.xcstrings"
    xc.save(path, _cat())
    out = tmp_path / "o" / "de.json"
    assert xc.main(["export", str(path), "de", str(out)]) == 0
    data = json.loads(out.read_text(encoding="utf-8"))
    assert "Done" not in data
    assert data["Hello %@"] == "Hello %@"
    assert data["n.items"] == {"one": "%lld item", "other": "%lld items"}
    assert data["_comments"] == {"Hello %@": "greeting"}
    assert b"\r" not in out.read_bytes()


def test_merge_writes_translated_and_plural_variations(tmp_path):
    path = tmp_path / "L.xcstrings"
    xc.save(path, _cat())
    src = tmp_path / "pl.json"
    src.write_text(json.dumps({
        "Hello %@": "Cześć %@",
        "n.items": {"one": "%lld rzecz", "few": "%lld rzeczy", "many": "%lld rzeczy", "other": "%lld rzeczy"},
    }, ensure_ascii=False), encoding="utf-8")
    assert xc.main(["merge", str(path), "pl", str(src)]) == 0
    got = xc.load(path)["strings"]
    assert got["Hello %@"]["localizations"]["pl"] == {"stringUnit": {"state": "translated", "value": "Cześć %@"}}
    plural = got["n.items"]["localizations"]["pl"]["variations"]["plural"]
    assert set(plural) == {"one", "few", "many", "other"}
    assert "n.items" not in xc.export_missing(xc.load(path), "pl")[0]


@pytest.mark.parametrize("lang,data", [
    ("de", {"Hello %@": "Hallo %lld"}),
    ("de", {"Hello %@": "Hallo"}),
    ("de", {"Hello %@": "Hallo %@ %@"}),
    ("de", {"Hello %@": "Hallo\\n%@"}),
    ("de", {"n.items": {"one": "%lld Ding", "few": "x", "other": "%lld Dinge"}}),
    ("pl", {"n.items": {"one": "%lld", "other": "%lld"}}),
    ("ja", {"n.items": {"one": "%lld", "other": "%lld"}}),
    ("de", {"Line\none %1$@ %2$lld": "Zeile\neins %1$@"}),
    ("de", {"missing": "x"}),
])
def test_merge_refuses(tmp_path, capsys, lang, data):
    path = tmp_path / "L.xcstrings"
    xc.save(path, _cat())
    before = path.read_bytes()
    src = tmp_path / "in.json"
    src.write_text(json.dumps(data, ensure_ascii=False), encoding="utf-8")
    assert xc.main(["merge", str(path), lang, str(src)]) == 1
    assert capsys.readouterr().err
    assert path.read_bytes() == before


def test_merge_allows_many_for_es_and_dropped_count_in_one():
    cat = _cat()
    ok = {"n.items": {"one": "Un elemento", "many": "%lld de elementos", "other": "%lld elementos"}}
    assert xc.merge(cat, "es", ok) == []
    assert xc.merge(cat, "ja", {"n.items": {"other": "%lld"}}) == []
