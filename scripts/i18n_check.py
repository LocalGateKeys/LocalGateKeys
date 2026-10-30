"""Check UI catalogs against English: keys, placeholders, glossary, pseudo-locale freshness."""

from __future__ import annotations

import csv
import argparse
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "scripts"))

from localvault.i18n import SUPPORTED  # noqa: E402
import i18n_pseudo  # noqa: E402
import android_strings as andr  # noqa: E402
import xcstrings as xc  # noqa: E402

DEFAULT_DIR = ROOT / "src" / "localvault" / "assets" / "i18n"
DEFAULT_GLOSSARY = ROOT / "i18n" / "glossary.csv"
DEFAULT_ANDROID = ROOT / "android" / "app" / "src" / "main" / "res"
DEFAULT_LOCALES = ROOT / "browser-extension" / "_locales"
DEFAULT_WEBSITE = ROOT / "website" / "i18n"
_PH = re.compile(r"\{([^{}]*)\}")
_FOLDER = {"zh_CN": "zh-Hans", "pt_BR": "pt-BR"}


def _load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _texts(value) -> list[str]:
    return list(value.values()) if isinstance(value, dict) else [value]


def _ph(text: str) -> set[str]:
    return set(_PH.findall(text))


def _glossary(path: Path) -> list[dict]:
    with open(path, encoding="utf-8", newline="") as f:
        return list(csv.DictReader(f))


# Extra English spellings/phrasal forms per glossary term (regex fragments).
_EXTRA = {
    "backup": [r"back[ -]?ups?", r"back(?:s|ed|ing)?[ -]up"],
    "licence": [r"licenses?", r"licensed"],
}
_LOCK, _UNLOCK = "lock", "unlock"


def _forms(word: str) -> str:
    w = re.escape(word)
    if word.endswith("e"):
        return w + r"(?:s|d)?|" + re.escape(word[:-1]) + "ing"
    return w + r"(?:s|es|ed|ing)?"


def _en_regex(term: str) -> re.Pattern:
    words = term.split()
    head = r"\s+".join(re.escape(w) for w in words[:-1])
    last = _forms(words[-1])
    alts = [(head + r"\s+" if head else "") + "(?:" + last + ")"]
    alts += _EXTRA.get(term.lower(), [])
    return re.compile(r"(?<!\w)(?:" + "|".join(alts) + r")(?!\w)", re.IGNORECASE)


_LITERAL = re.compile(r"(?<!\w)'[^'\s]+'(?!\w)")


def _term_source(text: str) -> str:
    """English text for glossary matching: placeholders and quoted literals carry no translatable term."""
    return _LITERAL.sub(" ", _PH.sub(" ", text))


_BS = chr(92)
_BS_N = _BS + "n"
_NL = chr(10)


def _newline_problems(lang: str, key: str, ev, tv) -> list[str]:
    want = (ev["other"] if isinstance(ev, dict) else ev).count(_NL)
    out = []
    for text in _texts(tv):
        if _BS_N in text:
            out.append(f"{lang}: literal backslash-n in {key}")
        elif text.count(_NL) != want:
            out.append(f"{lang}: newline count differs in {key}")
    return out


def _alts(cell: str | None) -> list[str]:
    return [a.strip().lower() for a in (cell or "").split("|") if a.strip()]


def _placeholders_ok(ev, tv) -> bool:
    want = _ph(ev["other"] if isinstance(ev, dict) else ev)
    if not isinstance(tv, dict):
        return _ph(tv) == want
    for cat, text in tv.items():
        got = _ph(text)
        # Non-"other" plural forms may drop {count} (e.g. "Ein Eintrag") but not add.
        if (got - want) or (cat == "other" and got != want):
            return False
    return True


def check(catalog_dir: Path, glossary: Path, *, langs=SUPPORTED, pseudo: bool = True) -> list[str]:
    problems: list[str] = []
    en_path = catalog_dir / "en.json"
    if not en_path.exists():
        return ["en: catalog missing"]
    en = _load(en_path)
    rows = _glossary(glossary) if glossary.exists() else []
    for lang in langs:
        if lang == "en":
            continue
        path = catalog_dir / f"{lang}.json"
        if not path.exists():
            continue
        cat = _load(path)
        for k in sorted(set(en) - set(cat)):
            problems.append(f"{lang}: missing {k}")
        for k in sorted(set(cat) - set(en)):
            problems.append(f"{lang}: extra {k}")
        for k in sorted(set(en) & set(cat)):
            ev, tv = en[k], cat[k]
            if isinstance(tv, dict) and "other" not in tv:
                problems.append(f"{lang}: plural without other in {k}")
            elif not _placeholders_ok(ev, tv):
                problems.append(f"{lang}: placeholders differ in {k}")
            problems += _newline_problems(lang, k, ev, tv)
            src = _term_source(" ".join(_texts(ev)))
            tgt = " ".join(_texts(tv)).lower()
            has_unlock = any(
                _en_regex(r["en"]).search(src) for r in rows if r["term"] == _UNLOCK
            )
            for row in rows:
                if not _en_regex(row["en"]).search(src):
                    continue
                alts = _alts(row.get(lang))
                if row["term"] == _LOCK:
                    if has_unlock:
                        continue
                    for u in rows:
                        if u["term"] == _UNLOCK:
                            for ua in _alts(u.get(lang)):
                                tgt_l = tgt.replace(ua, " ")
                                tgt = tgt_l
                if alts and not any(a in tgt for a in alts):
                    problems.append(f"{lang}: glossary '{row['term']}' missing in {k}")
    xa = catalog_dir / "en-XA.json"
    if pseudo and xa.exists() and xa.read_text(encoding="utf-8") != i18n_pseudo.render(catalog_dir):
        problems.append("en-XA: stale")
    problems += _check_locales(DEFAULT_LOCALES, langs) if catalog_dir == DEFAULT_DIR else []
    return problems


def _check_locales(locales: Path, langs) -> list[str]:
    if not locales.is_dir() or not (locales / "en" / "messages.json").exists():
        return []
    en = set(_load(locales / "en" / "messages.json"))
    problems: list[str] = []
    for d in sorted(p for p in locales.iterdir() if p.is_dir()):
        lang = _FOLDER.get(d.name, d.name)
        if lang == "en" or lang not in langs or not (d / "messages.json").exists():
            continue
        msgs = _load(d / "messages.json")
        keys = set(msgs)
        enm = _load(locales / "en" / "messages.json")
        for k in sorted(keys & set(enm)):
            problems += _newline_problems(lang, f"_locales {k}", enm[k]["message"], msgs[k]["message"])
        problems += [f"{lang}: _locales missing {k}" for k in sorted(en - keys)]
        problems += [f"{lang}: _locales extra {k}" for k in sorted(keys - en)]
    return problems


_ESCAPED = re.compile(r"\\.", re.S)


def _bare(text: str, ch: str) -> bool:
    """True when ch appears without a preceding backslash escape."""
    return ch in _ESCAPED.sub("", text)


def _raw_texts(v) -> list[tuple[str, str]]:
    return list(v.items()) if isinstance(v, dict) else [("", v)]


def check_android(res: Path, *, langs=SUPPORTED, strict: bool = False) -> list[str]:
    """Android values-<q>/strings.xml against values/strings.xml."""
    en_path = res / "values" / "strings.xml"
    if not en_path.exists():
        return []
    en = andr.parse(en_path)
    problems: list[str] = []
    for lang, folder in andr.FOLDERS.items():
        if lang not in langs:
            continue
        path = res / f"values-{folder}" / "strings.xml"
        if not path.exists():
            continue
        tr = andr.parse(path)
        tag = f"android {lang}"
        extra = sorted(set(tr) - set(en))
        problems += [f"{tag}: extra {k}" for k in extra]
        missing = sorted(set(en) - set(tr))
        if strict:
            problems += [f"{tag}: missing {k}" for k in missing]
        elif missing:
            print(f"{tag}: {len(missing)} untranslated of {len(en)}")
        for k in sorted(set(tr) & set(en)):
            ev, tv = en[k], tr[k]
            if isinstance(ev, dict) != isinstance(tv, dict):
                problems.append(f"{tag}: plural/string mismatch in {k}")
                continue
            if isinstance(tv, dict):
                bad = sorted(set(tv) ^ set(andr.needed(lang)))
                if bad:
                    problems.append(f"{tag}: plural quantities wrong in {k} ({','.join(bad)})")
            want = set(andr.args(ev["other"] if isinstance(ev, dict) else ev))
            for q, text in _raw_texts(tv):
                got = set(andr.args(text))
                if (got != want) if q in ("", "other") else (got - want):
                    problems.append(f"{tag}: format arguments differ in {k}")
                if _bare(text, "'"):
                    problems.append(f"{tag}: unescaped apostrophe in {k}")
                if _bare(text, '"'):
                    problems.append(f"{tag}: unescaped quote in {k}")
                if text[:1] in ("@", "?"):
                    problems.append(f"{tag}: unescaped leading {text[:1]} in {k}")
                if "%" in andr.FMT.sub("", text.replace("%%", "")):
                    problems.append(f"{tag}: stray % in {k}")
                if _NL in text:
                    problems.append(f"{tag}: real newline in {k}")
                if _BS + _BS_N in text:
                    problems.append(f"{tag}: escaped backslash before n (shows a literal backslash-n) in {k}")
            want_nl = (ev["other"] if isinstance(ev, dict) else ev).count(_BS_N)
            if any(text.count(_BS_N) != want_nl for _, text in _raw_texts(tv)):
                problems.append(f"{tag}: newline count differs in {k}")
    return problems


def apple_catalogs(root: Path = ROOT) -> list[Path]:
    paths = [root / "ios" / "Shared" / "Localizable.xcstrings",
             root / "ios" / "LGKCore" / "Sources" / "LGKCore" / "Resources" / "Localizable.xcstrings"]
    paths += sorted((root / "ios").glob("**/InfoPlist.xcstrings"))
    out: list[Path] = []
    for p in paths:
        if p.exists() and p not in out:
            out.append(p)
    return out


def check_apple(paths, *, strict: bool = False) -> list[str]:
    """Apple String Catalogs: translations in all nine languages, specifier parity, plural quantities."""
    problems: list[str] = []
    for path in paths:
        cat = xc.load(path)
        try:
            tag = f"apple {path.relative_to(ROOT).as_posix()}"
        except ValueError:
            tag = f"apple {path.name}"
        todo = xc.todo(cat)
        total = sum(1 for e in cat["strings"].values() if e.get("shouldTranslate") is not False)
        for lang in xc.LANGS:
            if strict:
                problems += [f"{tag} {lang}: missing {k!r}" for k in todo[lang]]
            elif todo[lang]:
                print(f"{tag} {lang}: {len(todo[lang])} untranslated of {total}")
        for key, entry in sorted(cat["strings"].items()):
            if entry.get("shouldTranslate") is False:
                continue
            for lang in xc.LANGS:
                loc = entry.get("localizations", {}).get(lang)
                value = xc._value(loc) if xc._translated(loc) else None
                if value is not None:
                    problems += [f"{tag} {lang}: {line}"
                                 for line in xc.validate({"strings": {key: entry}}, lang, {key: value})]
    return problems


# Website strings keep these exactly: {{CONFIG}} values, [[root]]/[[home]] paths, if-blocks, tags with
# their attributes (only the text between tags is translated). Entities such as &amp; are text: a
# translation may spell the words differently (e.g. "und" for "&"), so they need not match.
_WEB_TOKENS = re.compile(r"\{\{[A-Z0-9_]+\}\}|\[\[[a-z_]+\]\]|<!--.*?-->|<[^>]+>", re.S)


def _web_tokens(text: str) -> list[str]:
    return sorted(_WEB_TOKENS.findall(text))


def check_website(i18n_dir: Path, *, langs=None) -> list[str]:
    """Website catalogs (website/i18n/<code>.json): same keys and same markup/placeholders as en.json.

    Only the catalogs present are checked; the build skips a language without one.
    """
    en_path = i18n_dir / "en.json"
    if not en_path.exists():
        return ["website en: catalog missing"]
    en = _load(en_path)
    problems: list[str] = []
    for path in sorted(i18n_dir.glob("*.json")):
        lang = path.stem
        if lang == "en" or (langs is not None and lang not in langs):
            continue
        cat = _load(path)
        problems += [f"website {lang}: missing key {k}" for k in en if k not in cat]
        problems += [f"website {lang}: extra key {k}" for k in cat if k not in en]
        for k, ev in en.items():
            tv = cat.get(k)
            if isinstance(tv, str) and _web_tokens(tv) != _web_tokens(ev):
                problems.append(f"website {lang}: markup or placeholders differ in {k}")
    return problems


_JS_T = re.compile(r"""(?<![\w$.])t\(\s*(['"])([^'"\\\n]+)\1""")


def used_keys_problems(en: dict, py_root: Path, web_root: Path) -> list[str]:
    """Literal keys passed to t() in source that en.json does not define."""
    import ast

    problems: list[str] = []
    for path in sorted(py_root.rglob("*.py")) if py_root.is_dir() else []:
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"))
        except (SyntaxError, UnicodeDecodeError):
            continue
        for n in ast.walk(tree):
            if (isinstance(n, ast.Call) and isinstance(n.func, ast.Name) and n.func.id == "t" and n.args
                    and isinstance(n.args[0], ast.Constant) and isinstance(n.args[0].value, str)
                    and n.args[0].value not in en):
                problems.append(f"en: missing key {n.args[0].value} used in {path.name}")
    for path in sorted(web_root.rglob("*")) if web_root.is_dir() else []:
        if path.suffix not in (".svelte", ".js") or ".test." in path.name or "node_modules" in path.parts:
            continue
        for m in _JS_T.finditer(path.read_text(encoding="utf-8", errors="ignore")):
            if m.group(2) not in en:
                problems.append(f"en: missing key {m.group(2)} used in {path.name}")
    return sorted(set(problems))


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--lang", help="check only this language code (e.g. de, zh-Hans)")
    ap.add_argument("--android-strict", action="store_true", help="report untranslated Android resources as errors")
    ap.add_argument("--apple-strict", action="store_true", help="report untranslated Apple catalog strings as errors")
    args = ap.parse_args(argv)
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    if args.lang and (args.lang not in SUPPORTED or args.lang == "en"):
        print(f"i18n: unknown language {args.lang}")
        return 2
    if args.lang:
        problems = check(DEFAULT_DIR, DEFAULT_GLOSSARY, langs=(args.lang,), pseudo=False)
    else:
        problems = check(DEFAULT_DIR, DEFAULT_GLOSSARY)
        problems += used_keys_problems(
            _load(DEFAULT_DIR / "en.json"), ROOT / "src" / "localvault", ROOT / "webui" / "src"
        )
    problems += check_android(
        DEFAULT_ANDROID, langs=(args.lang,) if args.lang else SUPPORTED, strict=args.android_strict
    )
    apple = check_apple(apple_catalogs(), strict=args.apple_strict)
    if args.lang:
        apple = [p for p in apple if f" {args.lang}:" in p]
    problems += apple
    problems += check_website(DEFAULT_WEBSITE, langs=(args.lang,) if args.lang else None)
    for p in problems:
        print(p)
    print("i18n: ok" if not problems else f"i18n: {len(problems)} problem(s)")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
