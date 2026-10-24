"""The bundled site-logo set (scripts/build_site_logos.mjs) and its copies stay in step.

The desktop UI and the iPhone app read src/localvault/assets/site_logos.json; the browser extension
packages its own copy, and the iPhone draws the glyphs from ios/App/SiteLogos.xcassets.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ASSET = ROOT / "src" / "localvault" / "assets" / "site_logos.json"
EXTENSION_COPY = ROOT / "browser-extension" / "site-logos.json"
CATALOG = ROOT / "ios" / "App" / "SiteLogos.xcassets"
# The characters browser-extension/content.js accepts in a logo path before drawing it.
PATH_CHARS = re.compile(r"^[0-9a-zA-Z.,\- ]{1,20000}$")


def _data() -> dict:
    return json.loads(ASSET.read_text(encoding="utf-8"))


def test_extension_copy_is_identical():
    assert EXTENSION_COPY.read_bytes() == ASSET.read_bytes(), "run: node scripts/build_site_logos.mjs"


def test_every_domain_has_a_well_formed_logo():
    data = _data()
    assert len(data["logos"]) > 100
    for domain, slug in data["domains"].items():
        assert domain == domain.lower() and "." in domain and "/" not in domain, domain
        assert slug in data["logos"], domain
    for slug, logo in data["logos"].items():
        assert re.fullmatch(r"#[0-9A-Fa-f]{6}", logo["hex"]), slug
        assert PATH_CHARS.match(logo["path"]), slug
        assert logo["title"], slug


def test_source_matches_the_pinned_simple_icons():
    pinned = json.loads((ROOT / "webui" / "package.json").read_text(encoding="utf-8"))["devDependencies"]["simple-icons"]
    assert _data()["source"] == f"simple-icons {pinned} (CC0-1.0)"


def test_ios_catalog_has_exactly_one_image_per_logo():
    sets = {p.name for p in CATALOG.iterdir() if p.is_dir()}
    assert sets == {f"logo-{slug}.imageset" for slug in _data()["logos"]}
    contents = json.loads((CATALOG / "logo-github.imageset" / "Contents.json").read_text(encoding="utf-8"))
    assert contents["properties"]["template-rendering-intent"] == "template"


def test_apps_bundle_the_logo_files():
    assert "../src/localvault/assets/site_logos.json" in (ROOT / "ios" / "project.yml").read_text(encoding="utf-8")
    assert '"site-logos.json"' in (ROOT / "browser-extension" / "build-store-package.cjs").read_text(encoding="utf-8")
