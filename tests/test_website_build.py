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
    assert '<a href="../buy">' in (multi / "de" / "index.html").read_text(encoding="utf-8")


def test_languages_without_catalog_are_skipped(sites):
    en_only, _ = sites
    for folder in ("es", "it", "pl", "zh-hans", "ja", "de", "pt-br", "ko", "nl", "fr"):
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


def test_language_switchers_are_plain_links(sites):
    _, multi = sites
    doc = (multi / "de" / "features.html").read_text(encoding="utf-8")
    # Footer: a labelled <nav> with a list of links.
    switch = re.search(r'<nav class="lang-switch" aria-label="([^"]+)"><ul>(.*?)</ul></nav>', doc)
    assert switch, "footer language list"
    items = re.findall(r"<li>(.*?)</li>", switch.group(2))
    assert len(items) == 3
    assert '<a href="../features" hreflang="en" lang="en">English</a>' in items
    assert '<a href="../de/features" hreflang="de" lang="de" aria-current="true">Deutsch</a>' in items
    assert '<a href="../zh-hans/features" hreflang="zh-Hans" lang="zh-Hans">简体中文</a>' in items
    # Header: a <details> disclosure; <summary> is the button (expanded state and Enter/Space come from the browser).
    menu = re.search(r'<header class="site-header">.*?<details class="lang-menu">\s*<summary>(.*?)</summary>\s*'
                     r'<ul class="lang-menu-list">(.*?)</ul>\s*</details>.*?</header>', doc, re.S)
    assert menu, "header language menu"
    assert f"<span>{switch.group(1)}</span>" in menu.group(1)
    assert re.findall(r"<li>(.*?)</li>", menu.group(2)) == items
    assert 'href="#languages"' not in doc
    # The switcher needs no script, and site pages load none (Google Analytics removed, owner 2026-11-10).
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
            if not target.is_file():
                # Extensionless page URLs, as Cloudflare Pages serves them.
                target = target.with_name(target.name + ".html")
            if not target.resolve().is_file():
                broken.append(f"{path.relative_to(root).as_posix()} -> {link}")
    return broken


def test_no_broken_internal_links(sites):
    en_only, multi = sites
    assert broken_links(en_only) == []
    assert broken_links(multi) == []
    assert broken_links(WEBSITE / "public") == [] if (WEBSITE / "public" / "index.html").exists() else True


HTML_LINK = re.compile(r'href="(?![a-z]+:|//|#)[^"]*?\.html(?:[#?][^"]*)?"')


def test_internal_links_are_extensionless(sites):
    """Links use the URLs Pages serves (/features, /de/), the same form as the canonical: no 308 redirect."""
    for site in sites:
        for path in _html(site):
            rel = path.relative_to(site).as_posix()
            if rel.startswith("legal/app/"):
                continue  # opened inside the apps; links only between these two files
            doc = path.read_text(encoding="utf-8")
            assert not HTML_LINK.search(doc), (rel, HTML_LINK.search(doc).group(0))
            assert 'href="index"' not in doc and '/index"' not in doc, rel
    _, multi = sites
    doc = (multi / "de" / "features.html").read_text(encoding="utf-8")
    assert '<a class="brand" href="../de/">' in doc
    assert 'href="../de/pricing"' in doc
    assert 'href="../legal/eula"' in doc
    assert '<a class="brand" href="./">' in (multi / "index.html").read_text(encoding="utf-8")
    canonical = re.search(r'<link rel="canonical" href="([^"]+)">', doc).group(1)
    assert canonical == "https://localgatekeys.app/de/features"


def test_preview_server_maps_extensionless_urls(sites, monkeypatch):
    import threading
    import urllib.error
    import urllib.request
    from functools import partial
    from http.server import ThreadingHTTPServer

    spec = importlib.util.spec_from_file_location("site_serve", WEBSITE / "serve.py")
    serve = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(serve)
    _, multi = sites
    monkeypatch.setattr(serve, "PUBLIC", multi.resolve())
    server = ThreadingHTTPServer(("127.0.0.1", 0), partial(serve.PagesHandler, directory=str(multi)))
    server.RequestHandlerClass.log_message = lambda *a: None
    threading.Thread(target=server.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{server.server_address[1]}"
    try:
        for url, marker in (("/features", '<html lang="en">'), ("/de/", '<html lang="de">'),
                            ("/de/guide/mac", '<html lang="de">'), ("/legal/eula", "legal-doc")):
            with urllib.request.urlopen(base + url) as resp:
                assert marker in resp.read().decode("utf-8"), url
        with pytest.raises(urllib.error.HTTPError) as err:
            urllib.request.urlopen(base + "/no-such-page")
        assert err.value.code == 404
    finally:
        server.shutdown()
        server.server_close()


def test_csp_headers_unchanged(sites):
    source = (WEBSITE / "src" / "static" / "_headers").read_bytes()
    for site in sites:
        assert (site / "_headers").read_bytes() == source


def test_no_google_analytics(sites):
    # Owner 2026-11-10: Google Analytics / Tag Manager removed from the website entirely.
    banned = re.compile(r"googletagmanager|google-analytics|gtag|dataLayer|G-T8L6TZWSKS")
    for site in sites:
        for page in [*_html(site), site / "_headers"]:
            assert not banned.search(page.read_text(encoding="utf-8")), page


def _strip_additions(doc: str) -> str:
    doc = re.sub(r'\n  <link rel="alternate" hreflang="[^"]+" href="[^"]+">', "", doc)
    doc = re.sub(r'      <details class="lang-menu">.*?</details>\n', "", doc, flags=re.S)
    return re.sub(r'\n      <nav class="lang-switch"[^>]*>.*?</nav>', "", doc)


def test_english_unchanged_apart_from_additions(sites):
    en_only, multi = sites
    for path in _html(en_only):
        rel = path.relative_to(en_only)
        assert _strip_additions((multi / rel).read_text(encoding="utf-8")) == path.read_text(encoding="utf-8"), rel
    before = (en_only / "sitemap.xml").read_text(encoding="utf-8")
    after = (multi / "sitemap.xml").read_text(encoding="utf-8")
    added = [line for line in after.splitlines() if line not in before.splitlines()]
    assert "\n".join(l for l in after.splitlines() if l not in added) == before.rstrip("\n")
    locs = [re.match(r"  <url><loc>([^<]+)</loc><lastmod>\d{4}-\d{2}-\d{2}</lastmod></url>$", line).group(1)
            for line in added]
    assert "https://localgatekeys.app/de/" in locs
    assert "https://localgatekeys.app/zh-hans/pricing" in locs
    assert "https://localgatekeys.app/zh-hans/guide/iphone" in locs
    assert not [line for line in added if "/legal" in line]
    for name in ("robots.txt", "styles.css"):
        assert (multi / name).read_bytes() == (en_only / name).read_bytes()


def test_english_only_build_has_no_language_additions(sites):
    en_only, _ = sites
    doc = (en_only / "index.html").read_text(encoding="utf-8")
    assert "hreflang" not in doc and "lang-switch" not in doc and "lang-menu" not in doc


def test_sitemap_lastmod_from_sources(sites, monkeypatch):
    """Each sitemap entry carries the day its source last changed (git, else file time), the same in every language."""
    _, multi = sites
    mod = _load_build()
    text = (multi / "sitemap.xml").read_text(encoding="utf-8")
    entries = dict(re.findall(r"<url><loc>https://localgatekeys\.app/([^<]*)</loc><lastmod>([^<]+)</lastmod></url>",
                              text))
    assert len(entries) == text.count("<url>")
    assert entries["features"] == mod.source_date(WEBSITE / "src" / "pages" / "features.html")
    assert entries["de/features"] == entries["features"]
    assert entries["legal/eula"] == mod.source_date(REPO / "docs" / "legal" / "eula.md")
    assert entries["switch/bitwarden"] == max(mod.source_date(WEBSITE / "switch.json"),
                                              mod.source_date(WEBSITE / "src" / "partials" / "switch-page.html"))
    assert entries["guide/mac"] == mod.source_date(WEBSITE / "src" / "pages" / "help.html")
    # Outside git (or for an untracked file) the file's modification day is used.
    mod.source_date.cache_clear()
    monkeypatch.setattr(mod.subprocess, "run", lambda *a, **k: (_ for _ in ()).throw(OSError("no git")))
    import os
    import time
    stamp = time.mktime((2026, 3, 4, 12, 0, 0, 0, 0, -1))
    probe = Path(mod.__file__).parent / "site.config.json"
    old = probe.stat()
    try:
        os.utime(probe, (stamp, stamp))
        assert mod.source_date(probe) == "2026-03-04"
    finally:
        os.utime(probe, (old.st_atime, old.st_mtime))


GUIDES = ["windows", "mac", "iphone", "android", "extension"]


def test_guide_page_per_platform(sites):
    """guide/<platform> holds that help.html panel, is linked from the guide and the download page, and in every
    language its anchors into other panels point at the page that holds them."""
    _, multi = sites
    for folder in ("", "de/", "zh-hans/"):
        help_doc = (multi / folder / "help.html").read_text(encoding="utf-8")
        download = (multi / folder / "download.html").read_text(encoding="utf-8")
        for slug in GUIDES:
            doc = (multi / folder / "guide" / f"{slug}.html").read_text(encoding="utf-8")
            assert f'<section class="help-panel" id="{slug}"' in doc
            assert doc.count('<section class="help-panel"') == 1
            assert len(re.findall(r"<h1[ >]", doc)) == 1
            here = f"../{folder}" if folder else ""
            assert f'href="{here}guide/{slug}"' in help_doc
            assert f'href="{here}guide/{slug}"' in download
            up = f"../../{folder}" if folder else "../"
            assert f'href="{up}guide/{slug}" aria-current="page"' in doc
            assert f'href="{up}help"' in doc
            canonical = re.search(r'<link rel="canonical" href="([^"]+)">', doc).group(1)
            assert canonical == f"https://localgatekeys.app/{folder}guide/{slug}"
    assert broken_links(multi) == []


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


def test_site_has_no_old_price_or_limit(tmp_path):
    """The real site (every catalog, --strict) shows US$29.99 and the 7-item tier, never US$4.99 or 4 items.

    The one FAQ line that names the old price for early buyers marks it with class="old-price"."""
    import html as html_mod
    mod = _load_build()
    mod.OUT = tmp_path / "public"
    assert mod.build(strict=True) == 0
    config = json.loads((WEBSITE / "site.config.json").read_text(encoding="utf-8"))
    assert config["PRICE"] == "US$29.99"
    old = re.compile(r'<span class="old-price">[^<]*</span>')
    limit = re.compile(r"\b4[- ]items?\b|\b4-item\b|\b4 live items?\b|\b4 or more\b|\bfour (live )?items?\b|than 4 items", re.I)
    for path in _html(mod.OUT):
        rel = path.relative_to(mod.OUT).as_posix()
        doc = old.sub("", path.read_text(encoding="utf-8"))
        assert "4.99" not in doc, rel
        assert not limit.search(doc), rel
    folders = {"en": ""} | {c: c.lower() for c in ("de", "es", "fr", "it", "ja", "ko", "nl", "pl", "pt-BR", "zh-Hans")}
    for code, folder in folders.items():
        catalog = json.loads((WEBSITE / "i18n" / f"{code}.json").read_text(encoding="utf-8"))
        page = (mod.OUT / folder / "pricing.html").read_text(encoding="utf-8")
        promise = catalog["pricing.start-free-pay-once.2"].replace("{{PRICE}}", html_mod.escape(config["PRICE"]))
        assert promise in page, code
        assert "US$29.99" in page, code
        assert (mod.OUT / folder / "news" / "2026-11-pricing.html").exists(), code


CAVEAT = ("Passkeys do not transfer in a CSV export; LocalGateKeys imports them from CXF files (Apple Passwords and other apps that export CXF) on PC, Android, iPhone and Mac.")


def test_switch_pages_render(tmp_path):
    """Every switch.json competitor gets a page in every language, with the passkey caveat and the price line."""
    import html as html_mod
    mod = _load_build()
    mod.OUT = tmp_path / "public"
    assert mod.build(strict=True) == 0
    entries = json.loads((WEBSITE / "switch.json").read_text(encoding="utf-8"))["competitors"]
    assert len(entries) >= 11
    english = json.loads((WEBSITE / "i18n" / "en.json").read_text(encoding="utf-8"))
    assert english["switch.caveat"] == CAVEAT
    sitemap = (mod.OUT / "sitemap.xml").read_text(encoding="utf-8")
    for (code, _bcp47, folder, _native), catalog in mod.load_catalogs(None):
        base = mod.OUT / folder if folder else mod.OUT
        caveat = html_mod.unescape(catalog["switch.caveat"])
        index = html_mod.unescape((base / "switch" / "index.html").read_text(encoding="utf-8"))
        for e in entries:
            doc = html_mod.unescape((base / "switch" / f"{e['slug']}.html").read_text(encoding="utf-8"))
            assert caveat in doc, (code, e["slug"])
            assert "US$29.99" in doc, (code, e["slug"])
            assert e["name"] in doc and "[[" not in doc and "{{" not in doc, (code, e["slug"])
            for why in e["whyPeopleLeave"]:
                assert f"<!-- source: {why['source']} -->" in doc
            assert re.search(rf'href="[^"]*switch/{e["slug"]}"', index), (code, e["slug"])
            assert '<p class="price-strip">' in doc and '<ul class="trust-row"' in doc, (code, e["slug"])
            assert f"/{folder + '/' if folder else ''}switch/{e['slug']}</loc>" in sitemap
    assert "/de/switch/</loc>" in sitemap


def test_switch_reason_without_source_fails(tmp_path):
    mod = _load_build()
    data = json.loads((WEBSITE / "switch.json").read_text(encoding="utf-8"))
    entry = next(e for e in data["competitors"] if e["whyPeopleLeave"])
    del entry["whyPeopleLeave"][0]["source"]
    mod.SWITCH = tmp_path / "switch.json"
    mod.SWITCH.write_text(json.dumps(data), encoding="utf-8")
    mod.OUT = tmp_path / "public"
    with pytest.raises(SystemExit, match="source"):
        mod.build(strict=False)


def test_compare_table_from_data(tmp_path):
    """compare.json renders rows x columns cells in every language; a competitor `yes` needs a source."""
    import html as html_mod
    mod = _load_build()
    mod.OUT = tmp_path / "public"
    assert mod.build(strict=True) == 0
    data = json.loads((WEBSITE / "compare.json").read_text(encoding="utf-8"))
    rows, columns = data["rows"], data["columns"]
    assert [c["name"] for c in columns] == ["LocalGateKeys", "1Password", "Bitwarden", "Proton Pass", "Enpass",
                                           "KeePassXC"]
    # Only facts that can be checked today (owner 2026-11-15).
    assert [r["key"] for r in rows] == ["compare.row.price", "compare.row.account", "compare.row.vault",
                                        "compare.row.wifi", "compare.row.network", "compare.row.platforms"]
    english = json.loads((WEBSITE / "i18n" / "en.json").read_text(encoding="utf-8"))
    assert not [k for k, v in english.items() if k.startswith("compare.") and "lifetime" in v.lower()]
    for row in rows:
        assert set(row["cells"]) == {c["id"] for c in columns}, row["key"]
        for cid, cell in row["cells"].items():
            assert cell["value"] in {"yes", "no", "partial", "text"}, (row["key"], cid)
            if cid != "localgatekeys" and cell["value"] == "yes":
                assert re.fullmatch(r"https://\S+", cell.get("source", "")), (row["key"], cid)
    sitemap = (mod.OUT / "sitemap.xml").read_text(encoding="utf-8")
    for (code, _bcp47, folder, _native), _catalog in mod.load_catalogs(None):
        base = mod.OUT / folder if folder else mod.OUT
        doc = (base / "compare.html").read_text(encoding="utf-8")
        table = re.search(r'<table class="products">.*?</table>', doc, re.S).group(0)
        assert len(re.findall(r"<td[ >]", table)) == len(rows) * len(columns), code
        assert "[[" not in doc and "{{" not in doc, code
        assert "US$29.99" in html_mod.unescape(doc), code
        for c in columns:
            assert c["name"] in doc, (code, c["name"])
        pricing = (base / "pricing.html").read_text(encoding="utf-8")
        assert re.search(r'href="[^"]*compare"', pricing), code
        assert f"/{folder + '/' if folder else ''}compare</loc>" in sitemap, code


def test_compare_yes_without_source_fails(tmp_path):
    mod = _load_build()
    data = json.loads((WEBSITE / "compare.json").read_text(encoding="utf-8"))
    data["rows"][0]["cells"]["bitwarden"] = {"value": "yes"}
    mod.COMPARE = tmp_path / "compare.json"
    mod.COMPARE.write_text(json.dumps(data), encoding="utf-8")
    mod.OUT = tmp_path / "public"
    with pytest.raises(SystemExit, match="source"):
        mod.build(strict=False)


def test_compare_no_or_text_fact_without_source_fails(tmp_path):
    mod = _load_build()
    data = json.loads((WEBSITE / "compare.json").read_text(encoding="utf-8"))
    row = data["rows"][0]
    cid = next(c for c in row["cells"] if c != "localgatekeys")
    row["cells"][cid] = {"value": "no"}
    mod.COMPARE = tmp_path / "compare.json"
    mod.COMPARE.write_text(json.dumps(data), encoding="utf-8")
    mod.OUT = tmp_path / "public"
    with pytest.raises(SystemExit, match="source"):
        mod.build(strict=False)
    row["cells"][cid] = {"value": "text", "key": "compare.v.no"}
    mod.COMPARE.write_text(json.dumps(data), encoding="utf-8")
    with pytest.raises(SystemExit, match="source"):
        mod.build(strict=False)


def test_switch_price_strip_from_config(tmp_path):
    """The switch pages' price strip shows PRICE and FREE_ITEM_LIMIT from site.config.json, never a fixed number."""
    import html as html_mod
    mod = _load_build()
    mod.OUT = tmp_path / "public"
    config = json.loads(mod.CONFIG.read_text(encoding="utf-8"))
    config["PRICE"], config["FREE_ITEM_LIMIT"] = "US$31.00", "9"
    mod.CONFIG = tmp_path / "site.config.json"
    mod.CONFIG.write_text(json.dumps(config), encoding="utf-8")
    assert mod.build(strict=True, langs=["en", "de"]) == 0
    for folder, code in (("", "en"), ("de/", "de")):
        catalog = json.loads((WEBSITE / "i18n" / f"{code}.json").read_text(encoding="utf-8"))
        assert "{{PRICE}}" in catalog["switch.strip.price"] and "{{FREE_ITEM_LIMIT}}" in catalog["switch.strip.free"]
        doc = html_mod.unescape((mod.OUT / folder / "switch" / "bitwarden.html").read_text(encoding="utf-8"))
        strip = re.search(r'<p class="price-strip">(.*?)</p>', doc).group(1)
        assert "US$31.00" in strip and "9" in strip, code
        trust = re.search(r'<ul class="trust-row"[^>]*>(.*?)</ul>', doc, re.S).group(1)
        assert trust.count("<li>") == 3 and 'security"' in trust, code
