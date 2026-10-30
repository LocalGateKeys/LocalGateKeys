"""Android string tooling: escaping, argument conversion, reuse, merge."""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("android_strings", ROOT / "scripts" / "android_strings.py")
a = importlib.util.module_from_spec(spec)
sys.modules["android_strings"] = a
spec.loader.exec_module(a)

BS = chr(92)


def test_escape_apostrophe_quote_newline_percent():
    assert a.escape("l'a \"b\"\nc 100%") == f"l{BS}'a {BS}\"b{BS}\"{BS}nc 100%%"


def test_escape_keeps_format_args_and_guards_leading_at():
    assert a.escape("@x %1$s of %2$d") == f"{BS}@x %1$s of %2$d"


def test_unescape_roundtrip():
    assert a.unescape(a.escape("it's\n100% \"q\"")) == "it's\n100% \"q\""


def test_args_numbered_and_plain():
    assert a.args("%s and %2$d") == [(1, "s"), (2, "d")]
    assert a.args("100%% %1$s") == [(1, "s")]


def test_norm_matches_windows():
    assert a.norm_android("Last synced %1$s") == a.norm_windows("Last synced {when}")


def test_convert_follows_argument_order():
    tokens = a._token_map("{b} of {a}", "%1$s of %2$d")
    assert a._convert_text("{a} von {b}, l'x", tokens) == f"%2$d von %1$s, l{BS}'x"
    assert a._convert_text("{zzz}", tokens) is None


def _write(path, body):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(f'<?xml version="1.0" encoding="utf-8"?>\n<resources>\n{body}</resources>\n', encoding="utf-8")


def test_reuse_strings_and_plurals(tmp_path, monkeypatch):
    cat = tmp_path / "i18n"
    cat.mkdir()
    (cat / "en.json").write_text(json.dumps({
        "k.one": "Hello {name}", "k.n": {"one": "{count} item", "other": "{count} items"}}), encoding="utf-8")
    (cat / "pl.json").write_text(json.dumps({
        "k.one": "Cześć {name}", "k.n": {"one": "{count} el", "few": "{count} ela", "many": "{count} elów",
                                          "other": "{count} elu"}}), encoding="utf-8")
    res = tmp_path / "res"
    _write(res / "values" / "strings.xml",
           '    <string name="hi">Hello %1$s</string>\n    <string name="other">Nope</string>\n'
           '    <plurals name="n">\n        <item quantity="one">%1$d item</item>\n'
           '        <item quantity="other">%1$d items</item>\n    </plurals>\n')
    monkeypatch.setattr(a, "RES", res)
    monkeypatch.setattr(a, "CATALOGS", cat)
    eng = a.english()
    got = a.reuse_lang("pl", eng, json.loads((cat / "en.json").read_text(encoding="utf-8")))
    assert got["hi"] == "Cześć %1$s"
    assert got["n"] == {"one": "%1$d el", "few": "%1$d ela", "many": "%1$d elów", "other": "%1$d elu"}
    assert "other" not in got


def test_todo_and_merge_preserve_order(tmp_path, monkeypatch):
    res = tmp_path / "res"
    _write(res / "values" / "strings.xml",
           f'    <string name="b">B it{BS}\'s</string>\n    <string name="a">A</string>\n'
           '    <string name="skip" translatable="false">x</string>\n'
           '    <plurals name="n">\n        <item quantity="one">%1$d x</item>\n'
           '        <item quantity="other">%1$d xs</item>\n    </plurals>\n')
    monkeypatch.setattr(a, "RES", res)
    t = a.todo("ja", "ja")
    assert t == {"b": "B it's", "a": "A", "n": {"other": "%1$d xs"}}
    assert a.merge("ja", "ja", {"a": "あ's", "n": {"other": "%1$d個"}}) == []
    out = (res / "values-ja" / "strings.xml").read_text(encoding="utf-8")
    assert out.index('name="a"') < out.index('name="n"')
    assert f"あ{BS}'s" in out
    assert a.todo("ja", "ja") == {"b": "B it's"}
    assert a.merge("ja", "ja", {"zzz": "x"}) == ["unknown name zzz"]
    assert a.merge("de", "de", {"n": {"one": "x"}}) == ["n: missing quantities other"]
    # A translation that already holds a backslash-n would be double-escaped and show a literal "\n".
    assert a.merge("ja", "ja", {"a": f"x{BS}ny"}) == [
        "a: text has a literal backslash escape; use a real newline (escape() adds the backslash)"]
