"""Catalog checker, glossary and pseudo-locale."""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _load(name: str):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / f"{name}.py")
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


chk = _load("i18n_check")
ps = _load("i18n_pseudo")

HEADER = "term,en,es,it,pl,zh-Hans,ja,de,pt-BR,ko,nl\n"


def _setup(tmp_path, en, de, glossary_rows=""):
    (tmp_path / "en.json").write_text(json.dumps(en), encoding="utf-8")
    (tmp_path / "de.json").write_text(json.dumps(de), encoding="utf-8")
    gl = tmp_path / "glossary.csv"
    gl.write_text(HEADER + glossary_rows, encoding="utf-8")
    return gl


def test_missing_and_extra_keys(tmp_path):
    gl = _setup(tmp_path, {"a.b": "x"}, {"z": "y"})
    problems = chk.check(tmp_path, gl, langs=("en", "de"))
    assert "de: missing a.b" in problems
    assert "de: extra z" in problems


def test_placeholder_mismatch(tmp_path):
    gl = _setup(tmp_path, {"a.b": "Hi {name}"}, {"a.b": "Hallo {nom}"})
    assert "de: placeholders differ in a.b" in chk.check(tmp_path, gl, langs=("en", "de"))


def test_plural_placeholders(tmp_path):
    en = {"n": {"one": "{count} item", "other": "{count} items"}}
    de = {"n": {"one": "{anzahl} Eintrag", "other": "{count} Einträge"}}
    gl = _setup(tmp_path, en, de)
    assert "de: placeholders differ in n" in chk.check(tmp_path, gl, langs=("en", "de"))


def test_glossary_term(tmp_path):
    gl = _setup(
        tmp_path,
        {"a": "Open the vault"},
        {"a": "Öffne den Speicher"},
        "vault,vault,,,,,,Tresor,,,\n",
    )
    problems = chk.check(tmp_path, gl, langs=("en", "de"))
    assert any(p.startswith("de: glossary") and "a" in p for p in problems)
    (tmp_path / "de.json").write_text(json.dumps({"a": "Öffne den Tresor"}), encoding="utf-8")
    assert not [p for p in chk.check(tmp_path, gl, langs=("en", "de")) if "glossary" in p]


def test_missing_language_file_skipped(tmp_path):
    gl = _setup(tmp_path, {"a": "x"}, {"a": "y"})
    assert chk.check(tmp_path, gl, langs=("en", "de", "ja")) == []


def test_pseudo_keeps_placeholders():
    assert "{name}" in ps.pseudo("Hi {name}")
    assert len(ps.pseudo("Unlock")) >= 8


def test_pseudo_catalog_plural():
    out = ps.pseudo_catalog({"a": "Hi", "n": {"one": "{count} x", "other": "{count} xs"}})
    assert "{count}" in out["n"]["one"] and "{count}" in out["n"]["other"]


def test_stale_pseudo(tmp_path):
    gl = _setup(tmp_path, {"a": "x"}, {"a": "y"})
    (tmp_path / "en-XA.json").write_text(json.dumps({"a": "old"}), encoding="utf-8")
    assert "en-XA: stale" in chk.check(tmp_path, gl, langs=("en", "de"))


def test_repo_catalogs_pass():
    assert chk.check(chk.DEFAULT_DIR, chk.DEFAULT_GLOSSARY) == []


def test_used_keys_missing_from_en_are_reported(tmp_path):
    py = tmp_path / "py"
    web = tmp_path / "web"
    py.mkdir()
    web.mkdir()
    (py / "a.py").write_text('t("a.ok")\nt("a.gone")\nt(name)\n', encoding="utf-8")
    (web / "b.svelte").write_text("{t('b.ok')} {t(\"b.gone\")} {t(x)}", encoding="utf-8")
    (web / "b.test.js").write_text("t('skipped.test')", encoding="utf-8")
    out = chk.used_keys_problems({"a.ok": "x", "b.ok": "y"}, py, web)
    assert out == ["en: missing key a.gone used in a.py", "en: missing key b.gone used in b.svelte"]


def test_extension_locales_key_parity(tmp_path):
    def write(folder, data):
        (tmp_path / folder).mkdir()
        (tmp_path / folder / "messages.json").write_text(
            json.dumps({k: {"message": v} for k, v in data.items()}), encoding="utf-8"
        )

    write("en", {"a": "x", "b": "y"})
    write("zh_CN", {"a": "x", "c": "z"})
    write("pt_BR", {"a": "x", "b": "y"})
    problems = chk._check_locales(tmp_path, ("en", "zh-Hans", "pt-BR"))
    assert "zh-Hans: _locales missing b" in problems
    assert "zh-Hans: _locales extra c" in problems
    assert not [p for p in problems if p.startswith("pt-BR")]


def test_extension_en_locale_is_found():
    assert (chk.DEFAULT_LOCALES / "en" / "messages.json").exists()


def _glossary_problems(tmp_path, en_text, tgt_text, rows):
    gl = _setup(tmp_path, {"a": en_text}, {"a": tgt_text}, rows)
    return [p for p in chk.check(tmp_path, gl, langs=("en", "de")) if "glossary" in p]


def test_plural_non_other_may_omit_count(tmp_path):
    en = {"n": {"one": "{count} item", "other": "{count} items"}}
    de = {"n": {"one": "Ein Eintrag", "other": "{count} Einträge"}}
    gl = _setup(tmp_path, en, de)
    assert chk.check(tmp_path, gl, langs=("en", "de")) == []


def test_plural_non_other_may_not_add_placeholders(tmp_path):
    en = {"n": {"one": "{count} item", "other": "{count} items"}}
    de = {"n": {"one": "{count} {name} Eintrag", "other": "{count} Einträge"}}
    gl = _setup(tmp_path, en, de)
    assert "de: placeholders differ in n" in chk.check(tmp_path, gl, langs=("en", "de"))


def test_plural_other_must_keep_placeholders(tmp_path):
    en = {"n": {"one": "{count} item", "other": "{count} items"}}
    de = {"n": {"one": "Ein Eintrag", "other": "Einträge"}}
    gl = _setup(tmp_path, en, de)
    assert "de: placeholders differ in n" in chk.check(tmp_path, gl, langs=("en", "de"))


def test_plural_category_sets_may_differ(tmp_path):
    en = {"n": {"one": "{count} item", "other": "{count} items"}}
    pl = {"n": {"one": "{count} element", "few": "{count} elementy", "many": "{count} elementów", "other": "{count} elementu"}}
    ja = {"n": {"other": "{count}件"}}
    (tmp_path / "en.json").write_text(json.dumps(en), encoding="utf-8")
    (tmp_path / "pl.json").write_text(json.dumps(pl), encoding="utf-8")
    (tmp_path / "ja.json").write_text(json.dumps(ja), encoding="utf-8")
    gl = tmp_path / "glossary.csv"
    gl.write_text(HEADER, encoding="utf-8")
    assert chk.check(tmp_path, gl, langs=("en", "pl", "ja")) == []


def test_plural_without_other_still_rejected(tmp_path):
    en = {"n": {"one": "{count} item", "other": "{count} items"}}
    ja = {"n": {"one": "{count}件"}}
    gl = _setup(tmp_path, en, ja)
    assert "de: plural without other in n" in chk.check(tmp_path, gl, langs=("en", "de"))


def test_glossary_matches_inflections(tmp_path):
    rows = "sync,sync,,,,,,synchronis,,,\nbackup,backup,,,,,,Backup,,,\n"
    for en_text in ("Syncing now", "Synced", "Backups", "Backing up", "Back up now", "Backed up"):
        assert _glossary_problems(tmp_path, en_text, "xyz", rows), en_text


def test_lock_does_not_match_inside_unlock(tmp_path):
    rows = "lock,lock,,,,,,sperr,,,\n"
    assert not _glossary_problems(tmp_path, "Unlocked", "xyz", rows)
    assert not _glossary_problems(tmp_path, "Unlock", "xyz", rows)
    assert _glossary_problems(tmp_path, "Locked", "xyz", rows)


def test_lock_not_satisfied_by_unlock_term_and_skipped_with_unlock(tmp_path):
    rows = "unlock,unlock,,,,,,entsperr,,,\nlock,lock,,,,,,sperr,,,\n"
    # en has only "Lock": translation using only "entsperr" must not satisfy lock
    assert _glossary_problems(tmp_path, "Lock the vault", "Entsperre den Tresor", rows)
    assert not _glossary_problems(tmp_path, "Lock the vault", "Sperre den Tresor", rows)
    # en has unlock: lock row not enforced
    assert not _glossary_problems(tmp_path, "Lock or unlock", "Entsperren oder so", rows)


def test_brand_names_not_required_to_change(tmp_path):
    rows = "vault,vault,,,,,,Tresor,,,\n"
    assert not _glossary_problems(tmp_path, "Import from Bitwarden, 1Password, KeePass", "Aus Bitwarden", rows)
    assert not _glossary_problems(tmp_path, "LocalGateKeys Pro with Windows Hello", "LocalGateKeys Pro", rows)


def test_lang_option_checks_only_that_language(tmp_path):
    gl = _setup(tmp_path, {"a": "x"}, {"z": "y"})
    (tmp_path / "ja.json").write_text(json.dumps({"q": "y"}), encoding="utf-8")
    out = chk.check(tmp_path, gl, langs=("ja",))
    assert out and all(p.startswith("ja:") for p in out)
    assert chk.main(["--lang", "xx"]) == 2


def test_glossary_ignores_placeholders_and_quoted_literals(tmp_path):
    rows = "item,item,,,,,,Eintrag,,,\n"
    assert not _glossary_problems(tmp_path, "Includes {items}", "Enthält {items}", rows)
    assert not _glossary_problems(tmp_path, "Needs an 'items' list", "Braucht eine „items“-Liste", rows)
    assert _glossary_problems(tmp_path, "Includes items", "Enthält xyz", rows)


def test_newline_count_and_literal_backslash_n(tmp_path):
    nl, bs = chr(10), chr(92)
    gl = _setup(tmp_path, {"a": f"One{nl}{nl}Two"}, {"a": f"Eins{bs}n{bs}nZwei"})
    problems = chk.check(tmp_path, gl, langs=("en", "de"))
    assert any("literal backslash-n in a" in p for p in problems)
    gl = _setup(tmp_path, {"a": f"One{nl}{nl}Two"}, {"a": f"Eins{nl}Zwei"})
    assert any("newline count differs in a" in p for p in chk.check(tmp_path, gl, langs=("en", "de")))
    gl = _setup(tmp_path, {"a": f"One{nl}Two"}, {"a": f"Eins{nl}Zwei"})
    assert not [p for p in chk.check(tmp_path, gl, langs=("en", "de")) if "newline" in p or "backslash" in p]


# --- Android resources -------------------------------------------------------------------------

BSL = chr(92)


def _res(tmp_path, en_body, de_body=None, pl_body=None):
    for folder, body in (("values", en_body), ("values-de", de_body), ("values-pl", pl_body)):
        if body is None:
            continue
        d = tmp_path / folder
        d.mkdir(parents=True)
        (d / "strings.xml").write_text(
            '<?xml version="1.0" encoding="utf-8"?>' + chr(10) + "<resources>" + chr(10) + body
            + "</resources>" + chr(10), encoding="utf-8")
    return tmp_path


def _android(tmp_path, en, de=None, pl=None, strict=False):
    return chk.check_android(_res(tmp_path, en, de, pl), langs=("de", "pl"), strict=strict)


def test_android_extra_and_missing(tmp_path, capsys):
    en = '<string name="a">A</string><string name="b">B</string>'
    de = '<string name="a">A</string><string name="z">Z</string>'
    assert _android(tmp_path, en, de) == ["android de: extra z"]
    assert "1 untranslated of 2" in capsys.readouterr().out


def test_android_strict_reports_missing(tmp_path):
    p = _android(tmp_path, '<string name="a">A</string>', "", strict=True)
    assert p == ["android de: missing a"]


def test_android_format_arg_parity(tmp_path):
    en = '<string name="a">%1$s of %2$d</string>'
    ok = '<string name="a">%2$d von %1$s</string>'
    bad = '<string name="a">%1$s von</string>'
    assert _android(tmp_path / "ok", en, ok) == []
    assert _android(tmp_path / "bad", en, bad) == ["android de: format arguments differ in a"]


def test_android_plural_quantities(tmp_path):
    en = '<plurals name="n"><item quantity="one">%1$d x</item><item quantity="other">%1$d xs</item></plurals>'
    pl_ok = ('<plurals name="n"><item quantity="one">%1$d a</item><item quantity="few">%1$d b</item>'
             '<item quantity="many">%1$d c</item><item quantity="other">%1$d d</item></plurals>')
    pl_bad = '<plurals name="n"><item quantity="one">%1$d a</item><item quantity="other">%1$d d</item></plurals>'
    assert _android(tmp_path / "ok", en, None, pl_ok) == []
    assert _android(tmp_path / "bad", en, None, pl_bad) == ["android pl: plural quantities wrong in n (few,many)"]


def test_android_aapt_unsafe(tmp_path):
    en = '<string name="a">A</string>'
    assert _android(tmp_path / "1", en, f"<string name=\"a\">l{BSL}'a</string>") == []
    assert _android(tmp_path / "2", en, "<string name=\"a\">l'a</string>") == ["android de: unescaped apostrophe in a"]
    assert _android(tmp_path / "3", en, '<string name="a">100%</string>') == ["android de: stray % in a"]
    assert _android(tmp_path / "4", en, '<string name="a">@a</string>') == ["android de: unescaped leading @ in a"]


def test_android_newlines(tmp_path):
    en = f'<string name="a">x{BSL}ny</string>'
    assert _android(tmp_path / "ok", en, f'<string name="a">u{BSL}nv</string>') == []
    assert _android(tmp_path / "bad", en, '<string name="a">uv</string>') == ["android de: newline count differs in a"]
    real = '<string name="a">u' + chr(10) + 'v</string>'
    assert "android de: real newline in a" in _android(tmp_path / "real", en, real)


def test_android_double_escaped_newline(tmp_path):
    en = f'<string name="a">x{BSL}ny</string>'
    bad = f'<string name="a">u{BSL}{BSL}nv</string>'
    assert "android de: escaped backslash before n (shows a literal backslash-n) in a" in _android(tmp_path, en, bad)
