"""Check the translated store listings against the stores' text limits.

Files checked:
  docs/store/listings/{microsoft,edge,play}/<lang>.md
  ios/appstore/listing-1.1.json (English) and ios/appstore/listing-1.1.<lang>.json

Markdown listing format: an optional HTML comment, then "## <Field>" headings
(always in English, the field names of the store console). List fields
("Features", "Search terms") hold one "- item" per line.

Limits (characters, as of 2026-10; recheck in each console when uploading):
  App Store: name 30, subtitle 30, keywords 100 (comma-separated), promotional
    text 170, description 4000, what's new 4000. Characters are counted, not
    bytes.
  Google Play: title 30, short description 80, full description 4000.
  Microsoft Store: description 10000, short description 1000, features at most
    20 items of 200 each, search terms at most 7 items of 30 each (Partner
    Center has used 30 and 40 per term; the stricter 30 is checked).
  Edge Add-ons: description 250 to 10000; short description 250 (assumed:
    Partner Center does not document it clearly; the Chrome manifest summary
    limit of 132 only applies to the English manifest text).

Every language must have exactly the fields of the English file.
Exit status 0 when clean, 1 with one line per problem otherwise.
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

MD_LIMITS: dict[str, dict[str, tuple]] = {
    # field: (min, max) for text, or ("list", max_items, max_each)
    "microsoft": {
        "Short description": (0, 1000),
        "Description": (1, 10000),
        "Features": ("list", 20, 200),
        "Search terms": ("list", 7, 30),
    },
    "edge": {
        "Short description": (1, 250),
        "Description": (250, 10000),
    },
    "play": {
        "Title": (1, 30),
        "Short description": (1, 80),
        "Full description": (1, 4000),
    },
}

APPSTORE_LIMITS = {
    "name": 30,
    "subtitle": 30,
    "keywords": 100,
    "promotionalText": 170,
    "description": 4000,
    "whatsNew": 4000,
}

HEADING = re.compile(r"^## (.+?)\s*$")


def parse_md(text: str) -> dict[str, str]:
    text = re.sub(r"<!--.*?-->", "", text, flags=re.S)
    sections: dict[str, list[str]] = {}
    current = None
    for line in text.splitlines():
        m = HEADING.match(line)
        if m:
            current = m.group(1)
            sections[current] = []
        elif current is not None:
            sections[current].append(line)
    return {k: "\n".join(v).strip() for k, v in sections.items()}


def list_items(body: str) -> list[str]:
    return [ln[2:].strip() for ln in body.splitlines() if ln.startswith("- ")]


def check_md_store(store: str, folder: Path) -> list[str]:
    problems: list[str] = []
    en_path = folder / "en.md"
    if not en_path.exists():
        return [f"{en_path}: missing English source"]
    en_fields = list(parse_md(en_path.read_text(encoding="utf-8")))
    limits = MD_LIMITS[store]
    for path in sorted(folder.glob("*.md")):
        fields = parse_md(path.read_text(encoding="utf-8"))
        if list(fields) != en_fields:
            problems.append(f"{path}: fields {list(fields)} differ from en {en_fields}")
        for name, body in fields.items():
            rule = limits.get(name)
            if rule is None:
                problems.append(f"{path}: unknown field '{name}' for {store}")
            elif rule[0] == "list":
                items = list_items(body)
                if len(items) > rule[1]:
                    problems.append(f"{path}: {name} has {len(items)} items, max {rule[1]}")
                for item in items:
                    if len(item) > rule[2]:
                        problems.append(f"{path}: {name} item over {rule[2]} ({len(item)}): {item[:40]}")
            else:
                lo, hi = rule
                if not lo <= len(body) <= hi:
                    problems.append(f"{path}: {name} is {len(body)} characters, allowed {lo}-{hi}")
    return problems


def check_appstore(folder: Path) -> list[str]:
    problems: list[str] = []
    en_path = folder / "listing-1.1.json"
    if not en_path.exists():
        return [f"{en_path}: missing English source"]
    en_keys = sorted(json.loads(en_path.read_text(encoding="utf-8")))
    for path in [en_path, *sorted(folder.glob("listing-1.1.*.json"))]:
        data = json.loads(path.read_text(encoding="utf-8"))
        if sorted(data) != en_keys:
            problems.append(f"{path}: keys {sorted(data)} differ from en {en_keys}")
        for key, value in data.items():
            limit = APPSTORE_LIMITS.get(key)
            if limit is None:
                problems.append(f"{path}: unknown key '{key}'")
            elif not isinstance(value, str) or not value.strip():
                problems.append(f"{path}: {key} is empty")
            elif len(value) > limit:
                problems.append(f"{path}: {key} is {len(value)} characters, max {limit}")
    return problems


def check_all(root: Path = ROOT) -> list[str]:
    problems: list[str] = []
    for store in MD_LIMITS:
        problems += check_md_store(store, root / "docs" / "store" / "listings" / store)
    problems += check_appstore(root / "ios" / "appstore")
    return problems


def main() -> int:
    problems = check_all()
    for p in problems:
        print(p)
    if not problems:
        print("store listings: OK")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
