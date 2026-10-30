"""website/build.py per-language output (plan 2026-10-30-multilanguage-phase4-website-stores, Tasks 1-2).

Builds into temporary folders: once with English only, and once with two fake catalogs (copies of en.json as
de and zh-Hans) so the multi-language paths, hreflang sets and switcher are exercised.
"""

from __future__ import annotations

import importlib.util
import json
import re
import shutil
import sys
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import unquote, urlsplit

import pytest

REPO = Path(__file__).resolve().parent.parent
WEBSITE = REPO / "website"


def _load_script(name: str):
    spec = importlib.util.spec_from_file_location(name, REPO / "scripts" / f"{name}.py")
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


# Loaded at collection, like tests/test_i18n_check.py, so it imports localvault from this checkout's src/.
i18n_check = _load_script("i18n_check")
PAGES = ["index.html", "features.html", "pricing.html", "security.html", "get-started.html", "download.html",
         "support.html", "licence.html", "404.html"]


def _load_build():
    spec = importlib.util.spec_from_file_location("site_build_under_test", WEBSITE / "build.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _build(out: Path, i18n: Path) -> Path:
    mod = _load_build()
    mod.OUT = out
    mod.I18N = i18n
    assert mod.build(strict=False) == 0
    return out


@pytest.fixture(scope="module")
def sites(tmp_path_factory):
    base = tmp_path_factory.mktemp("site")
    en_dir = base / "i18n_en"
    en_dir.mkdir()
    shutil.copyfile(WEBSITE / "i18n" / "en.json", en_dir / "en.json")
    en_only = _build(base / "en_only", en_dir)
    i18n = base / "i18n"
    i18n.mkdir()
    shutil.copyfile(WEBSITE / "i18n" / "en.json", i18n / "en.json")
    shutil.copyfile(WEBSITE / "i18n" / "en.json", i18n / "de.json")
    shutil.copyfile(WEBSITE / "i18n" / "en.json", i18n / "zh-Hans.json")
    multi = _build(base / "multi", i18n)
    return en_only, multi


def _html(root: Path) -> list[Path]:
    return sorted(root.rglob("*.html"))


def test_output_paths_and_html_lang(sites):
    _, multi = sites
    for folder, lang in (("", "en"), ("de/", "de"), ("zh-hans/", "zh-Hans")):
        for page in PAGES:
            doc = (multi / (folder + page)).read_text(encoding="utf-8")
            assert f'<html lang="{lang}">' in doc, folder + page
    # Legal pages stay English-only.
    assert (multi / "legal" / "eula.html").exists()
    assert not (multi / "de" / "legal").exists()
    assert not (multi / "zh-hans" / "legal").exists()
    # The checkout too: only /buy has the Paddle CSP in _headers. Translated pages link to it.
    assert '<html lang="en">' in (multi / "buy.html").read_text(encoding="utf-8")
    assert not (multi / "de" / "buy.html").exists()
    assert '<a href="../buy.html">' in (multi / "de" / "index.html").read_text(encoding="utf-8")


def test_languages_without_catalog_are_skipped(sites):
    en_only, _ = sites
    for folder in ("es", "it", "pl", "zh-hans", "ja", "de", "pt-br", "ko", "nl"):
        assert not (en_only / folder).exists()


def _alternates(doc: str) -> dict[str, str]:
    return dict(re.findall(r'<link rel="alternate" hreflang="([^"]+)" href="([^"]+)">', doc))


def test_hreflang_sets_are_complete_and_reciprocal(sites):
    _, multi = sites
    for page in PAGES:
        sets = {}
        for folder, lang in (("", "en"), ("de/", "de"), ("zh-hans/", "zh-Hans")):
            doc = (multi / (folder + page)).read_text(encoding="utf-8")
            alt = _alternates(doc)
            assert set(alt) == {"en", "de", "zh-Hans", "x-default"}, folder + page
            assert alt["x-default"] == alt["en"]
            canonical = re.search(r'<link rel="canonical" href="([^"]+)">', doc).group(1)
            assert alt[lang] == canonical, folder + page
            sets[lang] = alt
        assert sets["en"] == sets["de"] == sets["zh-Hans"], page
    assert _alternates((multi / "index.html").read_text(encoding="utf-8"))["de"] == "https://localgatekeys.app/de/"
    # English-only legal pages carry no alternates.
    assert not _alternates((multi / "legal" / "eula.html").read_text(encoding="utf-8"))


def test_footer_switcher_is_plain_links(sites):
    _, multi = sites
    doc = (multi / "de" / "features.html").read_text(encoding="utf-8")
    switch = re.search(r'<p class="lang-switch"[^>]*>(.*?)</p>', doc).group(1)
    assert '<a href="../features.html" hreflang="en" lang="en">English</a>' in switch
    assert '<a href="../de/features.html" hreflang="de" lang="de" aria-current="true">Deutsch</a>' in switch
    assert '<a href="../zh-hans/features.html" hreflang="zh-Hans" lang="zh-Hans">简体中文</a>' in switch
    assert "<script" not in doc
    # Non-English sites note that the English legal texts apply.
    assert "the English version applies" in doc
    assert "the English version applies" not in (multi / "features.html").read_text(encoding="utf-8")


class _Links(HTMLParser):
    def __init__(self):
        super().__init__()
        self.links: list[str] = []

    def handle_starttag(self, tag, attrs):
        for name, value in attrs:
            if name in ("href", "src") and value:
                self.links.append(value)
            elif name == "srcset" and value:
                self.links += [part.strip().split(" ")[0] for part in value.split(",")]


def broken_links(root: Path) -> list[str]:
    broken = []
    for path in _html(root):
        parser = _Links()
        parser.feed(path.read_text(encoding="utf-8"))
        for link in parser.links:
            parts = urlsplit(link)
            if parts.scheme or parts.netloc or link.startswith("#"):
                continue
            target_path = unquote(parts.path)
            if target_path.startswith("/"):
                target = root / target_path.lstrip("/")
            else:
                target = path.parent / target_path
            if target_path.endswith("/") or target.is_dir():
                target = target / "index.html"
            if not target.resolve().is_file():
                broken.append(f"{path.relative_to(root).as_posix()} -> {link}")
    return broken


def test_no_broken_internal_links(sites):
    en_only, multi = sites
    assert broken_links(en_only) == []
    assert broken_links(multi) == []
    assert broken_links(WEBSITE / "public") == [] if (WEBSITE / "public" / "index.html").exists() else True


def test_csp_headers_unchanged(sites):
    source = (WEBSITE / "src" / "static" / "_headers").read_bytes()
    for site in sites:
        assert (site / "_headers").read_bytes() == source


def _strip_additions(doc: str) -> str:
    doc = re.sub(r'\n  <link rel="alternate" hreflang="[^"]+" href="[^"]+">', "", doc)
    return re.sub(r'\n      <p class="lang-switch"[^>]*>.*?</p>', "", doc)


def test_english_unchanged_apart_from_additions(sites):
    en_only, multi = sites
    for path in _html(en_only):
        rel = path.relative_to(en_only)
        assert _strip_additions((multi / rel).read_text(encoding="utf-8")) == path.read_text(encoding="utf-8"), rel
    before = (en_only / "sitemap.xml").read_text(encoding="utf-8")
    after = (multi / "sitemap.xml").read_text(encoding="utf-8")
    added = [line for line in after.splitlines() if line not in before.splitlines()]
    assert "\n".join(l for l in after.splitlines() if l not in added) == before.rstrip("\n")
    assert "  <url><loc>https://localgatekeys.app/de/</loc></url>" in added
    assert "  <url><loc>https://localgatekeys.app/zh-hans/pricing</loc></url>" in added
    assert not [line for line in added if "/legal" in line]
    for name in ("robots.txt", "styles.css"):
        assert (multi / name).read_bytes() == (en_only / name).read_bytes()


def test_english_only_build_has_no_language_additions(sites):
    en_only, _ = sites
    doc = (en_only / "index.html").read_text(encoding="utf-8")
    assert "hreflang" not in doc and "lang-switch" not in doc


def test_translation_is_used():
    """A key translated in a catalog replaces the English text on that language's page only."""
    mod = _load_build()
    english = json.loads((WEBSITE / "i18n" / "en.json").read_text(encoding="utf-8"))
    assert mod.translate("<h1>[[t:nav.features]]</h1>", {"nav.features": "Funktionen"}, english, "x") == \
        "<h1>Funktionen</h1>"
    assert mod.translate("[[t:nav.features]]", {}, english, "x") == "Features"
    with pytest.raises(SystemExit):
        mod.translate("[[t:no.such.key]]", {}, english, "x")


def test_i18n_check_website_parity(tmp_path):

    en = json.loads((WEBSITE / "i18n" / "en.json").read_text(encoding="utf-8"))
    (tmp_path / "en.json").write_text(json.dumps(en), encoding="utf-8")
    bad = dict(en)
    key = next(k for k, v in en.items() if "<a href" in v)
    bad[key] = "no link here"
    del bad["nav.features"]
    bad["extra.key"] = "x"
    (tmp_path / "de.json").write_text(json.dumps(bad), encoding="utf-8")
    problems = i18n_check.check_website(tmp_path)
    assert f"website de: markup or placeholders differ in {key}" in problems
    assert "website de: missing key nav.features" in problems
    assert "website de: extra key extra.key" in problems
    assert i18n_check.check_website(WEBSITE / "i18n") == []


def test_i18n_check_website_entities_are_text(tmp_path):
    en = {"a.b": "Import &amp; export in <strong>Tools</strong>"}
    (tmp_path / "en.json").write_text(json.dumps(en), encoding="utf-8")
    (tmp_path / "de.json").write_text(json.dumps({"a.b": "Import und Export in <strong>Extras</strong>"}),
                                      encoding="utf-8")
    assert i18n_check.check_website(tmp_path) == []
    (tmp_path / "de.json").write_text(json.dumps({"a.b": "Import &amp; Export in Extras"}), encoding="utf-8")
    assert i18n_check.check_website(tmp_path) == ["website de: markup or placeholders differ in a.b"]
