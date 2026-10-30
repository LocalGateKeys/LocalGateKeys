"""Android string resources: reuse Windows translations, list what is left, merge translator output.

    python scripts/android_strings.py reuse [--lang CODE]
    python scripts/android_strings.py todo <code|folder> <out.json>
    python scripts/android_strings.py merge <code|folder> <in.json>

Translator JSON uses plain text (real newlines, plain apostrophes) with Android positional
arguments (%1$s, %2$d); the merge step escapes it for aapt.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RES = ROOT / "android" / "app" / "src" / "main" / "res"
CATALOGS = ROOT / "src" / "localvault" / "assets" / "i18n"

FOLDERS = {
    "es": "es", "it": "it", "pl": "pl", "zh-Hans": "b+zh+Hans", "ja": "ja",
    "de": "de", "pt-BR": "pt-rBR", "ko": "ko", "nl": "nl",
}
ORDER = ("zero", "one", "two", "few", "many", "other")
_PH = re.compile(r"\{([^{}]*)\}")
FMT = re.compile(r"%(?:(\d+)\$)?([-#+ 0,(]*\d*(?:\.\d+)?[a-zA-Z])")
_ESC = re.compile(r"\\(u[0-9a-fA-F]{4}|.)", re.S)
_BS = chr(92)
_PCT = chr(0)


def needed(lang: str) -> tuple[str, ...]:
    if lang == "pl":
        return ("one", "few", "many", "other")
    if lang in ("ja", "ko", "zh-Hans"):
        return ("other",)
    return ("one", "other")


def resolve(q: str) -> tuple[str, str]:
    """Language code and values-folder qualifier for a code or a folder qualifier."""
    for code, folder in FOLDERS.items():
        if q in (code, folder):
            return code, folder
    raise SystemExit(f"android_strings: unknown language {q}")


def folder_path(folder: str) -> Path:
    return RES / f"values-{folder}" / "strings.xml"


# --- resource files (raw = still escaped for aapt) ---------------------------------------------

def parse(path: Path, *, translatable_only: bool = True) -> dict:
    """name -> raw string, or dict quantity -> raw string, in file order."""
    out: dict = {}
    if not path.exists():
        return out
    for el in ET.parse(path).getroot():
        if translatable_only and el.get("translatable") == "false":
            continue
        name = el.get("name")
        if el.tag == "string":
            out[name] = el.text or ""
        elif el.tag == "plurals":
            out[name] = {i.get("quantity"): i.text or "" for i in el.findall("item")}
    return out


def _x(s: str) -> str:
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def render(entries: dict, order: list[str]) -> str:
    lines = ['<?xml version="1.0" encoding="utf-8"?>', "<resources>"]
    for name in order:
        if name not in entries:
            continue
        v = entries[name]
        if isinstance(v, dict):
            lines.append(f'    <plurals name="{name}">')
            for q in ORDER:
                if q in v:
                    lines.append(f'        <item quantity="{q}">{_x(v[q])}</item>')
            lines.append("    </plurals>")
        else:
            lines.append(f'    <string name="{name}">{_x(v)}</string>')
    lines.append("</resources>")
    return "\n".join(lines) + "\n"


# --- escaping -----------------------------------------------------------------------------------

def args(raw: str) -> list[tuple[int, str]]:
    """Format arguments (position, conversion) in order of appearance, positions 1-based."""
    out, n = [], 0
    for m in FMT.finditer(raw.replace("%%", _PCT * 2)):
        n += 1
        out.append((int(m.group(1)) if m.group(1) else n, m.group(2)))
    return out


def unescape(raw: str) -> str:
    def sub(m):
        c = m.group(1)
        if c[0] == "u" and len(c) == 5:
            return chr(int(c[1:], 16))
        return {"n": "\n", "t": "\t"}.get(c, c)

    return _ESC.sub(sub, raw.replace("%%", "%"))


def _lit(s: str) -> str:
    """Escape literal text (no format arguments)."""
    s = s.replace("%%", _PCT).replace("%", "%%").replace(_PCT, "%%")
    s = s.replace(_BS, _BS * 2).replace("'", _BS + "'").replace('"', _BS + '"')
    return s.replace("\r\n", "\n").replace("\n", _BS + "n").replace("\t", _BS + "t")


def escape(text: str) -> str:
    """Plain text with Android %N$x arguments -> aapt-safe resource text."""
    parts: list[str] = []
    pos = 0
    for m in FMT.finditer(text):
        parts.append(_lit(text[pos:m.start()]))
        parts.append(m.group(0))
        pos = m.end()
    parts.append(_lit(text[pos:]))
    return _guard("".join(parts))


def _guard(s: str) -> str:
    return (_BS + s) if s[:1] in ("@", "?") else s


def norm_android(raw: str) -> str:
    """Comparable form of an Android English string: arguments become {}."""
    parts = FMT.split(raw.replace("%%", _PCT * 2))
    # re.split with 2 groups yields text, g1, g2, text, ...
    return "{}".join(unescape(t.replace(_PCT * 2, "%%")) for t in parts[0::3]).strip()


def norm_windows(text: str) -> str:
    return _PH.sub("{}", text).strip()


# --- reuse --------------------------------------------------------------------------------------

def _token_map(win_en: str, android_raw: str) -> dict[str, str] | None:
    names = _PH.findall(win_en)
    a = args(android_raw)
    if len(names) != len(a):
        return None
    m: dict[str, str] = {}
    for n, (idx, conv) in zip(names, a):
        m.setdefault(n, f"%{idx}${conv}")
    return m


def _convert_text(text: str, tokens: dict[str, str]) -> str | None:
    """Escape the literal parts of a Windows string and substitute Android arguments."""
    out, pos = [], 0
    for m in _PH.finditer(text):
        if m.group(1) not in tokens:
            return None
        out.append(_lit(text[pos:m.start()]))
        out.append(tokens[m.group(1)])
        pos = m.end()
    out.append(_lit(text[pos:]))
    return _guard("".join(out))


def english() -> dict:
    return parse(RES / "values" / "strings.xml")


def _win_index(en: dict) -> dict:
    idx: dict = {}
    for key, v in en.items():
        if isinstance(v, dict):
            k = ("p", tuple(sorted((q, norm_windows(t)) for q, t in v.items() if q in ("one", "other"))))
        else:
            k = ("s", norm_windows(v))
        idx.setdefault(k, key)
    return idx


def reuse_lang(code: str, eng: dict, win_en: dict) -> dict:
    """Entries translatable from the Windows catalog for one language."""
    path = CATALOGS / f"{code}.json"
    if not path.exists():
        return {}
    win = json.loads(path.read_text(encoding="utf-8"))
    idx = _win_index(win_en)
    out: dict = {}
    for name, v in eng.items():
        if isinstance(v, dict):
            k = ("p", tuple(sorted((q, norm_android(t)) for q, t in v.items() if q in ("one", "other"))))
        else:
            k = ("s", norm_android(v))
        key = idx.get(k)
        if key is None or key not in win:
            continue
        tv, wv = win[key], win_en[key]
        if isinstance(v, dict):
            if not (isinstance(tv, dict) and isinstance(wv, dict)):
                continue
            tokens = _token_map(wv["other"], v["other"])
            if tokens is None:
                continue
            forms = {}
            for q in needed(code):
                src = tv.get(q)
                c = _convert_text(src, tokens) if src is not None else None
                if c is None:
                    break
                forms[q] = c
            else:
                out[name] = forms
        else:
            if isinstance(tv, dict) or isinstance(wv, dict):
                continue
            tokens = _token_map(wv, v)
            c = _convert_text(tv, tokens) if tokens is not None else None
            if c is not None:
                out[name] = c
    return out


def cmd_reuse(only: str | None) -> None:
    eng = english()
    win_en = json.loads((CATALOGS / "en.json").read_text(encoding="utf-8"))
    order = list(eng)
    for code, folder in FOLDERS.items():
        if only and only not in (code, folder):
            continue
        path = folder_path(folder)
        entries = parse(path)
        got = reuse_lang(code, eng, win_en)
        for name, v in got.items():
            entries.setdefault(name, v)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(render(entries, order), encoding="utf-8", newline="\n")
        done = sum(1 for n in eng if n in entries)
        print(f"{code}: reused {len(got)}, total {done}/{len(eng)}, remaining {len(eng) - done}")


# --- todo / merge -------------------------------------------------------------------------------

def todo(code: str, folder: str) -> dict:
    eng, have = english(), parse(folder_path(folder))
    out: dict = {}
    for name, v in eng.items():
        if name in have:
            continue
        if isinstance(v, dict):
            out[name] = {q: unescape(v.get(q, v["other"])) for q in needed(code)}
        else:
            out[name] = unescape(v)
    return out


def merge(code: str, folder: str, data: dict) -> list[str]:
    eng = english()
    path = folder_path(folder)
    entries = parse(path)
    problems: list[str] = []
    for name, v in data.items():
        texts = list(v.values()) if isinstance(v, dict) else [v]
        if any(_BS + "n" in x or _BS + "t" in x for x in texts if isinstance(x, str)):
            problems.append(f"{name}: text has a literal backslash escape; use a real newline (escape() adds the backslash)")
        elif name not in eng:
            problems.append(f"unknown name {name}")
        elif isinstance(eng[name], dict) != isinstance(v, dict):
            problems.append(f"{name}: plural/string mismatch")
        elif isinstance(v, dict):
            miss = [q for q in needed(code) if q not in v]
            if miss:
                problems.append(f"{name}: missing quantities {','.join(miss)}")
            else:
                entries[name] = {q: escape(v[q]) for q in needed(code)}
        else:
            entries[name] = escape(v)
    if not problems:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(render(entries, list(eng)), encoding="utf-8", newline="\n")
    return problems


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("reuse")
    r.add_argument("--lang")
    t = sub.add_parser("todo")
    t.add_argument("q")
    t.add_argument("out")
    m = sub.add_parser("merge")
    m.add_argument("q")
    m.add_argument("json")
    a = ap.parse_args(argv)
    if a.cmd == "reuse":
        cmd_reuse(a.lang)
    elif a.cmd == "todo":
        code, folder = resolve(a.q)
        data = todo(code, folder)
        Path(a.out).parent.mkdir(parents=True, exist_ok=True)
        Path(a.out).write_text(json.dumps(data, ensure_ascii=False, indent=1) + "\n", encoding="utf-8", newline="\n")
        print(f"{code}: {len(data)} to translate -> {a.out}")
    else:
        code, folder = resolve(a.q)
        problems = merge(code, folder, json.loads(Path(a.json).read_text(encoding="utf-8")))
        for p in problems:
            print(p)
        if problems:
            return 1
        print(f"{code}: merged")
    return 0


if __name__ == "__main__":
    sys.exit(main())
