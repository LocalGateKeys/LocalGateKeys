"""Guard: no user-facing text still names an old free item limit (4 or 15) or the old price."""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
LIMIT = re.compile(
    r"\b4[- ]item|\b4 live items?|\b4 or more\b|\bfour (live )?items?\b|than 4 items|holds 4 items|up to 4 items"
    # Translated store listings: de, es, fr, it, nl, pl, pt-BR, ja, ko, zh-Hans.
    r"|\b4 (Eintr|elementos|éléments|elementi|onderdelen|elementów|itens)|maximaal 4 items|4 項目|항목 4개|\D4개까지|4 个项目",
    re.IGNORECASE,
)
PRICE = re.compile(r"4\.99")
GLOBS = (
    "src/localvault/assets/i18n/*.json",
    "browser-extension/*.js",
    "browser-extension/_locales/*/messages.json",
    "ios/Shared/Localizable.xcstrings",
    "ios/Mac/Shell/MainWindow.swift",
    "android/app/src/main/res/values*/strings.xml",
    "docs/store/listings/**/*.md",
    "docs/store/LISTING.md",
    "ios/appstore/*.json",
    "docs/legal/*.md",
)


def _hits(pattern: re.Pattern[str]) -> list[str]:
    hits = []
    for glob in GLOBS:
        for path in sorted(ROOT.glob(glob)):
            # Shipped, historical copy: changelog, Play 1.0.0 notes, iPhone 1.1 listing.
            if path.name == "CHANGELOG.md" or path.name.startswith(("release-notes-1.0.0", "listing-1.1.")):
                continue
            for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
                if pattern.search(line):
                    hits.append(f"{path.relative_to(ROOT)}:{number}: {line.strip()[:120]}")
    return hits


def test_no_literal_four_item_limit() -> None:
    hits = _hits(LIMIT)
    assert not hits, "\n".join(hits)


def test_no_old_price() -> None:
    hits = _hits(PRICE)
    assert not hits, "\n".join(hits)


OLD_15 = re.compile(
    r"\b15[- ]item|\b15 or more\b|\bfifteen items?\b|up to 15 items|holds 15 items"
    r"|\b15 (Eintr|elementos|éléments|elementi|onderdelen|elementów|pozycji|itens|items)|15 項目|항목 15개|\D15개까지|15 个项目",
    re.IGNORECASE,
)


def test_no_old_fifteen_item_limit() -> None:
    """The free limit dropped from 15 to 7 on 2026-11-13; shipped Play 1.1.0 notes are history."""
    hits = [h for h in _hits(OLD_15) if "release-notes-1.1.0" not in h]
    assert not hits, "\n".join(hits)
