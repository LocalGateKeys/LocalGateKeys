import importlib.util
import json
import shutil
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location("store_listing_check", ROOT / "scripts" / "store_listing_check.py")
slc = importlib.util.module_from_spec(spec)
spec.loader.exec_module(slc)

LANGS = ["es", "it", "pl", "zh-Hans", "ja", "de", "pt-BR", "ko", "nl", "fr"]

# The store listings are not part of the public source snapshot.
pytestmark = pytest.mark.skipif(not (ROOT / "docs" / "store" / "listings").is_dir(),
                                reason="docs/store/listings is not in this checkout")


def _copy_tree(tmp_path: Path) -> Path:
    shutil.copytree(ROOT / "docs" / "store" / "listings", tmp_path / "docs" / "store" / "listings")
    (tmp_path / "ios" / "appstore").mkdir(parents=True)
    for p in (ROOT / "ios" / "appstore").glob("listing-*.json"):
        shutil.copy(p, tmp_path / "ios" / "appstore" / p.name)
    return tmp_path


def test_repo_listings_are_clean():
    assert slc.check_all(ROOT) == []


def test_every_language_present():
    for store in ("microsoft", "edge", "firefox", "play"):
        for lang in ["en", *LANGS]:
            assert (ROOT / "docs" / "store" / "listings" / store / f"{lang}.md").exists(), (store, lang)
    for lang in LANGS:
        assert (ROOT / "ios" / "appstore" / f"listing-1.1.{lang}.json").exists(), lang


def test_too_long_play_title_is_reported(tmp_path):
    root = _copy_tree(tmp_path)
    path = root / "docs" / "store" / "listings" / "play" / "de.md"
    text = path.read_text(encoding="utf-8").replace("LocalGateKeys Passwortmanager", "X" * 31)
    path.write_text(text, encoding="utf-8")
    problems = slc.check_all(root)
    assert len(problems) == 1 and "Title is 31" in problems[0]


def test_missing_section_is_reported(tmp_path):
    root = _copy_tree(tmp_path)
    path = root / "docs" / "store" / "listings" / "microsoft" / "ja.md"
    text = path.read_text(encoding="utf-8").split("## Search terms")[0]
    path.write_text(text, encoding="utf-8")
    assert any("differ from en" in p for p in slc.check_all(root))


def test_long_search_term_and_too_many_items(tmp_path):
    root = _copy_tree(tmp_path)
    path = root / "docs" / "store" / "listings" / "microsoft" / "nl.md"
    path.write_text(path.read_text(encoding="utf-8") + "- " + "y" * 31 + "\n", encoding="utf-8")
    problems = slc.check_all(root)
    assert any("8 items, max 7" in p for p in problems)
    assert any("item over 30" in p for p in problems)


def test_appstore_keywords_limit_and_keys(tmp_path):
    root = _copy_tree(tmp_path)
    path = root / "ios" / "appstore" / "listing-1.1.ko.json"
    data = json.loads(path.read_text(encoding="utf-8"))
    data["keywords"] = "a" * 101
    del data["whatsNew"]
    path.write_text(json.dumps(data, ensure_ascii=False), encoding="utf-8")
    problems = slc.check_all(root)
    assert any("keywords is 101" in p for p in problems)
    assert any("keys" in p and "differ" in p for p in problems)


def test_edge_description_minimum(tmp_path):
    root = _copy_tree(tmp_path)
    path = root / "docs" / "store" / "listings" / "edge" / "it.md"
    head = path.read_text(encoding="utf-8").split("## Description")[0]
    path.write_text(head + "## Description\n\nTroppo corto.\n", encoding="utf-8")
    assert any("Description is 13 characters, allowed 250-10000" in p for p in slc.check_all(root))


def test_firefox_summary_limit(tmp_path):
    root = _copy_tree(tmp_path)
    path = root / "docs" / "store" / "listings" / "firefox" / "de.md"
    text = path.read_text(encoding="utf-8")
    head, rest = text.split("## Summary", 1)
    _, tail = rest.split("## Description", 1)
    path.write_text(head + "## Summary\n\n" + "x" * 251 + "\n\n## Description" + tail, encoding="utf-8")
    assert any("firefox" in p and "Summary is 251" in p for p in slc.check_all(root))
