"""The legal pages the iPhone, Mac and Android apps open (website/public/legal/app/).

Store rules (App Store 3.1.1 / 3.1.3(b), Google Play Payments): nothing an app opens may lead to buying
outside the store, so these pages carry no site header, footer or menu, no shop links or names, and link
only to each other. Plan 2026-10-29-appstore-licence Task 10.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
PUBLIC = REPO / "website" / "public"
APP_PAGES = ["legal/app/privacy.html", "legal/app/eula.html"]
FORBIDDEN = ["buy.html", "pricing", "licence.html", "paddle", "lemonsqueezy"]
# Owner 2026-10-29: "In the App Store there is no mention of another vendor." Payment providers, other stores
# and platforms, other vendors' products. "Windows" (the PC app) and Apple's own names stay.
VENDORS = re.compile(
    r"\b(paddle|lemon ?squeezy|stripe|google|play store|android|microsoft|chrome|edge add-ons|firefox|mozilla|"
    r"dropbox|onedrive|proton|bitwarden|1password|keepass|lastpass|dashlane)\b",
    re.I,
)


def _read(rel: str) -> str:
    return (PUBLIC / rel).read_text(encoding="utf-8")


def _headings(doc: str) -> list[str]:
    return re.findall(r"<h[1-4] id=\"[^\"]*\">(.*?)</h[1-4]>", doc)


@pytest.mark.parametrize("rel", APP_PAGES)
def test_app_page_has_no_shop_links_or_names(rel):
    doc = _read(rel).lower()
    for word in FORBIDDEN:
        assert word not in doc, f"{rel} contains {word!r}"
    assert "lemon squeezy" not in doc


@pytest.mark.parametrize("rel", APP_PAGES)
def test_app_page_names_no_other_vendor(rel):
    text = re.sub(r"<[^>]+>", " ", _read(rel))
    assert VENDORS.findall(text) == [], f"{rel} names another vendor"


def test_vendor_pattern_catches_vendor_names():
    for words in ["Paid with Stripe", "on Google Play", "Microsoft Store", "your Android phone", "Lemon Squeezy"]:
        assert VENDORS.search(words), words
    for words in ["the Windows app", "Apple App Store", "pinstripe", "iCloud Drive"]:
        assert not VENDORS.search(words), words


@pytest.mark.parametrize("rel", APP_PAGES)
def test_app_page_has_no_site_navigation(rel):
    doc = _read(rel)
    assert "site-header" not in doc and "site-footer" not in doc
    assert 'class="nav"' not in doc
    assert "{{" not in doc, "unfilled placeholder"
    links = re.findall(r"<a\s[^>]*href=\"([^\"]*)\"", doc)
    assert links, "the two pages link to each other"
    for href in links:
        assert href.split("#", 1)[0] in {"privacy.html", "eula.html"}, f"{rel} links to {href}"


@pytest.mark.parametrize("app, site", [("legal/app/privacy.html", "legal/privacy.html"),
                                       ("legal/app/eula.html", "legal/eula.html")])
def test_app_page_has_the_same_text_as_the_site_page(app, site):
    assert _headings(_read(app)) == _headings(_read(site))
    assert len(_headings(_read(app))) > 5


def test_build_generates_the_app_pages():
    build = (REPO / "website" / "build.py").read_text(encoding="utf-8")
    for rel in APP_PAGES:
        assert f'"{rel}"' in build, f"build.py does not generate {rel}"
    sitemap = _read("sitemap.xml")
    assert "legal/app/" not in sitemap
