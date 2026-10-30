"""Apple String Catalogs (.xcstrings): reuse Windows translations, list what is left.

    python scripts/xcstrings.py import-windows <catalog.xcstrings> [--force]
    python scripts/xcstrings.py todo <catalog.xcstrings>
    python scripts/xcstrings.py add <catalog.xcstrings> <key> <en value> [--comment TEXT]
    python scripts/xcstrings.py export <catalog.xcstrings> <lang> <out.json>
    python scripts/xcstrings.py merge <catalog.xcstrings> <lang> <in.json>

export writes {key: english} for every key without a translation in <lang> (plurals as {"one":..,"other":..},
catalog comments under "_comments"); merge writes the translated JSON back and refuses (exit 1) on format
specifier mismatch, a literal backslash-n the English lacks, or wrong plural quantities for the language.

A catalog key matches a Windows key when the key itself is a Windows key (explicit key, e.g.
"sync.issue.pcOffline") or the key is the English source text, and the catalog's English equals the
Windows English after placeholder conversion: {name} becomes %@ (one argument) or %1$@, %2$@ ...
(several, numbered in English order); integer names (count, n, num, ...) become %lld / %1$lld.
A literal % becomes %%. Windows plurals ({"one": .., "other": ..}) become plural variations.
Files are written as Xcode writes them: sorted keys, 2-space indent, " : " separators, trailing newline.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CATALOGS = ROOT / "src" / "localvault" / "assets" / "i18n"
LANGS = ("es", "it", "pl", "zh-Hans", "ja", "de", "pt-BR", "ko", "nl")
_PH = re.compile(r"\{([^{}]*)\}")

# Placeholder names formatted as integers (%lld); every other name is an object (%@).
INT_NAMES = frozenset({
    "count", "n", "num", "number", "total", "limit", "max", "min", "items", "item_count",
    "history_count", "remaining", "seconds", "minutes", "hours", "days", "bits", "bytes",
    "FREE_ITEM_LIMIT", "KDBX_MIN_PASSWORD", "MAX_SCAN_ACCOUNTS", "MIN_TRANSFER_PASSWORD_LENGTH",
    "trash_retention_days", "imported", "skipped", "updated", "unchanged", "trashed", "restored",
    "scanned", "selected", "rows", "records", "errors", "files", "attachments", "credentials",
})


# --- load / save ---------------------------------------------------------------------------------

def empty() -> dict:
    return {"sourceLanguage": "en", "strings": {}, "version": "1.0"}


def dumps(catalog: dict) -> str:
    return json.dumps(catalog, ensure_ascii=False, indent=2, separators=(",", " : "), sort_keys=True) + "\n"


def load(path: Path) -> dict:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def save(path: Path, catalog: dict) -> None:
    Path(path).write_bytes(dumps(catalog).encode("utf-8"))


def _unit(value: str, state: str = "translated") -> dict:
    return {"stringUnit": {"state": state, "value": value}}


def _localization(value) -> dict:
    """A str becomes a stringUnit, a {"one": .., "other": ..} dict plural variations."""
    if isinstance(value, dict):
        return {"variations": {"plural": {form: _unit(text) for form, text in value.items()}}}
    return _unit(value)


def add(catalog: dict, key: str, en=None, *, comment: str | None = None) -> dict:
    """Add (or update) a key. en is the English text, or a plural dict; None keeps the key as the source."""
    entry = catalog["strings"].setdefault(key, {})
    if comment:
        entry["comment"] = comment
    if en is not None and (isinstance(en, dict) or en != key):
        entry.setdefault("localizations", {})["en"] = _localization(en)
        entry["extractionState"] = "manual"
    return entry


def english(key: str, entry: dict):
    """The entry's English: a str, a plural dict, or the key itself."""
    loc = entry.get("localizations", {}).get("en")
    return _value(loc) if loc else key


def _value(loc: dict):
    if "stringUnit" in loc:
        return loc["stringUnit"]["value"]
    plural = loc.get("variations", {}).get("plural")
    if plural:
        return {form: v["stringUnit"]["value"] for form, v in plural.items() if "stringUnit" in v}
    return None


def _translated(loc: dict | None) -> bool:
    if not loc:
        return False
    if "stringUnit" in loc:
        return loc["stringUnit"].get("state") == "translated"
    plural = loc.get("variations", {}).get("plural", {})
    return bool(plural) and all(v.get("stringUnit", {}).get("state") == "translated" for v in plural.values())


# --- placeholders --------------------------------------------------------------------------------

def _names(text: str) -> list[str]:
    out: list[str] = []
    for name in _PH.findall(text):
        if name not in out:
            out.append(name)
    return out


def order_of(en) -> list[str]:
    """Placeholder names in the order they first appear in the English ("other" for plurals)."""
    if isinstance(en, dict):
        return _names(en.get("other") or next(iter(en.values()), ""))
    return _names(en)


def convert(text: str, order: list[str], types: dict[str, str] | None = None) -> str:
    """{name} -> %@ / %lld (one name) or %1$@ / %2$lld (several), positions from `order`."""
    types = types or {}
    positional = len(order) > 1

    def spec(name: str) -> str:
        kind = types.get(name) or ("lld" if name in INT_NAMES else "@")
        if name not in order:
            raise ValueError(f"placeholder {{{name}}} not in English")
        return f"%{order.index(name) + 1}${kind}" if positional else f"%{kind}"

    out, pos = [], 0
    for m in _PH.finditer(text):
        out.append(text[pos:m.start()].replace("%", "%%"))
        out.append(spec(m.group(1)))
        pos = m.end()
    out.append(text[pos:].replace("%", "%%"))
    return "".join(out)


def convert_value(value, order: list[str], types=None):
    if isinstance(value, dict):
        return {form: convert(text, order, types) for form, text in value.items()}
    return convert(value, order, types)


# --- Windows import ------------------------------------------------------------------------------

def _windows(catalog_dir: Path) -> dict[str, dict]:
    return {lang: load(catalog_dir / f"{lang}.json") for lang in ("en",) + LANGS
            if (catalog_dir / f"{lang}.json").exists()}


def _comparable(value):
    return value.get("other") if isinstance(value, dict) else value


def _index(win_en: dict, types=None) -> dict:
    """Converted English ("other" for plurals) -> first Windows key with that text."""
    idx: dict = {}
    for wk in sorted(win_en):
        conv = _comparable(_safe_convert(win_en[wk], types))
        if conv is not None:
            idx.setdefault(conv, wk)
    return idx


def match(key: str, entry: dict, win_en: dict, types=None, index: dict | None = None) -> str | None:
    """The Windows key whose converted English equals this entry's English, or None."""
    en = _comparable(english(key, entry))
    if key in win_en:
        return key if _comparable(_safe_convert(win_en[key], types)) == en else None
    if index is None:
        index = _index(win_en, types)
    return index.get(en)


def _safe_convert(value, types=None):
    try:
        return convert_value(value, order_of(value), types)
    except ValueError:
        return None


def import_windows(catalog: dict, catalog_dir: Path = CATALOGS, *, types=None, force=False) -> int:
    """Fill translations from the Windows catalogs. Returns the number of localizations written."""
    win = _windows(catalog_dir)
    win_en = win["en"]
    index = _index(win_en, types)
    written = 0
    for key, entry in catalog["strings"].items():
        if entry.get("shouldTranslate") is False:
            continue
        wk = match(key, entry, win_en, types, index)
        if wk is None:
            continue
        order = order_of(win_en[wk])
        locs = entry.setdefault("localizations", {})
        for lang in LANGS:
            if lang not in win or wk not in win[lang]:
                continue
            if _translated(locs.get(lang)) and not force:
                continue
            try:
                locs[lang] = _localization(convert_value(win[lang][wk], order, types))
            except ValueError as exc:
                print(f"xcstrings: {lang} {wk}: {exc}", file=sys.stderr)
                continue
            written += 1
        if not locs:
            del entry["localizations"]
    return written


def todo(catalog: dict) -> dict[str, list[str]]:
    out: dict[str, list[str]] = {}
    for lang in LANGS:
        out[lang] = sorted(k for k, e in catalog["strings"].items()
                           if e.get("shouldTranslate") is not False
                           and not _translated(e.get("localizations", {}).get(lang)))
    return out


# --- export / merge -----------------------------------------------------------------------------

_SPEC = re.compile(r"%(?:\d+\$)?[-+ 0#]*(?:\d+|\*)?(?:\.\d+)?(?:hh|h|ll|l|z|q|j|t)?[@dDuUxXoOfeEgGcCsSpaAi%]")
_BS_N = chr(92) + "n"
QUANTITIES = {
    "pl": ("one", "few", "many", "other"),
    "ja": ("other",), "ko": ("other",), "zh-Hans": ("other",),
    "es": ("one", "other"), "it": ("one", "other"), "pt-BR": ("one", "other"),
    "de": ("one", "other"), "nl": ("one", "other"),
}
EXTRA_MANY = {"es", "it", "pt-BR"}


def specs(text: str) -> list[str]:
    """Format specifiers in text, sorted (multiset), positions kept."""
    return sorted(_SPEC.findall(text))


def quantity_problem(lang: str, forms) -> str | None:
    allowed = set(QUANTITIES.get(lang, ("one", "other")))
    required = set(allowed)
    if lang in EXTRA_MANY:
        allowed.add("many")
    if set(forms) - allowed or required - set(forms):
        return f"plural quantities {sorted(forms)} wrong for {lang} (need {sorted(required)})"
    return None


def export_missing(catalog: dict, lang: str) -> tuple[dict, dict]:
    out: dict = {}
    comments: dict = {}
    for key, entry in sorted(catalog["strings"].items()):
        if entry.get("shouldTranslate") is False:
            continue
        if _translated(entry.get("localizations", {}).get(lang)):
            continue
        out[key] = english(key, entry)
        if entry.get("comment"):
            comments[key] = entry["comment"]
    return out, comments


def validate(catalog: dict, lang: str, data: dict) -> list[str]:
    problems: list[str] = []
    for key, value in data.items():
        entry = catalog["strings"].get(key)
        if entry is None:
            problems.append(f"{key!r}: not in catalog")
            continue
        en = english(key, entry)
        en_text = en["other"] if isinstance(en, dict) else en
        want = specs(en_text)
        texts = value.items() if isinstance(value, dict) else [("", value)]
        if isinstance(value, dict):
            msg = quantity_problem(lang, value)
            if msg:
                problems.append(f"{key!r}: {msg}")
        for form, text in texts:
            if not isinstance(text, str):
                problems.append(f"{key!r}: value is not a string")
                continue
            got = specs(text)
            if form in ("", "other"):
                bad = got != want
            else:  # non-"other" forms may drop specifiers ("one item") but not add
                rest = list(want)
                bad = False
                for g in got:
                    if g in rest:
                        rest.remove(g)
                    else:
                        bad = True
            if bad:
                problems.append(f"{key!r}: format specifiers {got} differ from English {want}")
            if _BS_N in text and _BS_N not in en_text:
                problems.append(f"{key!r}: literal backslash-n in translation")
    return problems


def merge(catalog: dict, lang: str, data: dict) -> list[str]:
    """Write translations into the catalog; returns problems (nothing is written if any)."""
    problems = validate(catalog, lang, data)
    if problems:
        return problems
    for key, value in data.items():
        entry = catalog["strings"][key]
        entry.setdefault("localizations", {})[lang] = _localization(value)
    return []


# --- CLI -----------------------------------------------------------------------------------------

def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("import-windows")
    p.add_argument("catalog", type=Path)
    p.add_argument("--force", action="store_true", help="overwrite translations already present")
    p = sub.add_parser("todo")
    p.add_argument("catalog", type=Path)
    p = sub.add_parser("add")
    p.add_argument("catalog", type=Path)
    p.add_argument("key")
    p.add_argument("en", nargs="?")
    p.add_argument("--comment")
    for name in ("export", "merge"):
        p = sub.add_parser(name)
        p.add_argument("catalog", type=Path)
        p.add_argument("lang")
        p.add_argument("json", type=Path)
    args = ap.parse_args(argv)

    catalog = load(args.catalog) if args.catalog.exists() else empty()
    if args.cmd == "import-windows":
        n = import_windows(catalog, force=args.force)
        save(args.catalog, catalog)
        print(f"xcstrings: {n} localizations written to {args.catalog}")
    elif args.cmd == "todo":
        print(json.dumps(todo(catalog), ensure_ascii=False, indent=2))
    elif args.cmd == "export":
        out, comments = export_missing(catalog, args.lang)
        count = len(out)
        if comments:
            out["_comments"] = comments
        args.json.parent.mkdir(parents=True, exist_ok=True)
        args.json.write_bytes((json.dumps(out, ensure_ascii=False, indent=2) + "\n").encode("utf-8"))
        print(f"xcstrings: {count} entries exported to {args.json}")
    elif args.cmd == "merge":
        data = json.loads(args.json.read_text(encoding="utf-8"))
        data.pop("_comments", None)
        problems = merge(catalog, args.lang, data)
        if problems:
            for line in problems:
                print(f"xcstrings: {line}", file=sys.stderr)
            return 1
        save(args.catalog, catalog)
        print(f"xcstrings: {len(data)} {args.lang} translations merged into {args.catalog}")
    elif args.cmd == "add":
        add(catalog, args.key, args.en, comment=args.comment)
        save(args.catalog, catalog)
    return 0


if __name__ == "__main__":
    sys.exit(main())
