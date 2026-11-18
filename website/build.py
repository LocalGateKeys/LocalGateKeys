#!/usr/bin/env python3
"""Build the LocalGateKeys website into website/public/.

Standard library only, so it runs on a stock Python 3.9+ (including the
Cloudflare Pages build image). The output is plain HTML/CSS with no scripts.

    python website/build.py            # build, list unfilled placeholders
    python website/build.py --strict   # also fail if any placeholder is unfilled
    python website/build.py --langs en,de   # only these languages (default: every catalog present)

Inputs:
    website/src/layout.html            page shell (header, footer)
    website/src/pages/**/*.html        page bodies with a small front-matter block
    website/src/static/                copied as-is (CSS, _headers, robots.txt, ...)
    docs/legal/*.md                    legal drafts, rendered to public/legal/
    website/site.config.json           values for {{PLACEHOLDER}} tokens
    website/i18n/<code>.json           page text per language; templates say [[t:key]]
    assets/brand/, assets/icons/       logo and favicons

Unfilled placeholders stay visible as {{NAME}} and are highlighted in page
text so a reviewer can spot them.
"""

from __future__ import annotations

import html
import json
import re
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from functools import lru_cache
import unicodedata
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parent
SRC = HERE / "src"
OUT = HERE / "public"
LEGAL_SRC = REPO / "docs" / "legal"
CONFIG = HERE / "site.config.json"
I18N = HERE / "i18n"
SWITCH = HERE / "switch.json"
SWITCH_PARTIAL = SRC / "partials" / "switch-page.html"
COMPARE = HERE / "compare.json"
HELP_PAGE = SRC / "pages" / "help.html"

# One page per platform, cut from the panels of help.html: (panel id = URL slug, catalog key of its name).
GUIDE_PLATFORMS = [
    ("windows", "guide.name.windows"),
    ("mac", "guide.name.mac"),
    ("iphone", "guide.name.iphone"),
    ("android", "guide.name.android"),
    ("extension", "help.intro.tab_extension"),
]
# Every id inside each help.html panel, so guide pages can point anchors at the page that holds them.
GUIDE_IDS: "dict[str, str]" = {}
# Source files of each page (relative output path), for the sitemap's lastmod.
PAGE_SOURCES: "dict[str, list[Path]]" = {}

# (catalog code, <html lang>, URL folder, native name). English stays at the site root.
LANGUAGES = [
    ("en", "en", "", "English"),
    ("es", "es", "es", "Español"),
    ("it", "it", "it", "Italiano"),
    ("pl", "pl", "pl", "Polski"),
    ("zh-Hans", "zh-Hans", "zh-hans", "简体中文"),
    ("ja", "ja", "ja", "日本語"),
    ("de", "de", "de", "Deutsch"),
    ("pt-BR", "pt-BR", "pt-br", "Português (Brasil)"),
    ("ko", "ko", "ko", "한국어"),
    ("nl", "nl", "nl", "Nederlands"),
    ("fr", "fr", "fr", "Français"),
]
# Page text: [[t:page.section.n]] is replaced by that key of website/i18n/<code>.json.
TEXT_KEY = re.compile(r"\[\[t:([A-Za-z0-9_.-]+)\]\]")

NAV = [
    ("features.html", "nav.features"),
    ("get-started.html", "nav.get_started"),
    ("help.html", "nav.guide"),
    ("security.html", "nav.security"),
    ("pricing.html", "nav.pricing"),
    ("support.html", "nav.support"),
    ("download.html", "nav.download"),
]

# Legal drafts rendered into the site, in footer order: (markdown file, output page).
LEGAL_PAGES = [
    ("eula.md", "legal/eula.html"),
    ("privacy-policy.md", "legal/privacy.html"),
    ("terms-of-sale.md", "legal/terms-of-sale.html"),
    ("refund-policy.md", "legal/refunds.html"),
    ("vulnerability-disclosure.md", "legal/vulnerability-disclosure.html"),
]

# The variants the iPhone, Mac and Android apps open (App Store 3.1.1 / 3.1.3(b), Google Play Payments): the same
# text with no site header, footer or menu, no shop or other vendors' names and no links except between these two pages.
APP_LEGAL_PAGES = [
    ("eula.md", "legal/app/eula.html"),
    ("privacy-policy.md", "legal/app/privacy.html"),
]
APP_LEGAL_LINKS = {"eula.md": "eula.html", "privacy-policy.md": "privacy.html"}
# Store builds never name the website's payment provider.
APP_CONFIG = {
    "MERCHANT_OF_RECORD": "our payment provider",
    "MERCHANT_PRIVACY_URL": "see the provider's website",
}
# Store builds name no other vendor (owner 2026-10-29): sentences of the drafts reworded for the app variants.
# Each site wording must still be in its draft, so a later edit of the draft cannot slip a vendor name through.
APP_REWORDING = {
    "privacy-policy.md": [
        ("The Chrome Web Store and Microsoft Edge Add-ons may process data about installations under their own "
         "privacy policies.",
         "The browser's add-on store may process data about installations under its own privacy policy."),
        (" (for example Microsoft OneDrive, Dropbox, Google Drive or Proton Drive)", ""),
        ("Links to the Microsoft Store, Chrome Web Store, Edge Add-ons, App Store and {{MERCHANT_OF_RECORD}}",
         "Links to the App Store, other app stores and {{MERCHANT_OF_RECORD}}"),
        ("in the App Store or Google Play: the app sends the store's purchase record",
         "in the App Store: the app sends the store's purchase record"),
        (" The Android app does the same with the Google Play purchase token (Play Data safety: \"Purchase history\", "
         "app functionality).", ""),
    ],
    "eula.md": [
        ("the LocalGateKeys iPhone and Android apps (together", "the LocalGateKeys iPhone and mobile apps (together"),
        ("In the iPhone app you can buy Pro through the App Store, and in the Android app through Google Play. The store "
         "takes the payment",
         "In the app you can buy Pro through the app store. The store takes the payment"),
        (" (in Google Play, the product `pro_unlimited`, US$29.99 or the local price the store shows)",
         " (US$29.99 or the local price the store shows)"),
        ("such as Microsoft Windows, Google Chrome, Microsoft Edge, Apple iOS, Google Android and cloud-drive services",
         "such as Windows, web browsers, Apple iOS, macOS, your phone's operating system and cloud-drive services"),
        ("from the Microsoft Store, Apple App Store or Google Play, that", "from the Apple App Store or another app store, that"),
    ],
}
# Set while the app variants render: legal cross-links stay only between the two app pages.
_app_links: "dict[str, str] | None" = None

BRAND_FILES = {
    "brand/icon.svg": REPO / "assets" / "brand" / "localgatekeys-icon-small.svg",
    "brand/icon-detailed.svg": REPO / "assets" / "brand" / "localgatekeys-icon.svg",
    "brand/icon-32.png": REPO / "assets" / "icons" / "app_32.png",
    "brand/icon-256.png": REPO / "assets" / "icons" / "app_256.png",
}

# Open Graph locale per catalog code.
OG_LOCALES = {"en": "en_US", "es": "es_ES", "it": "it_IT", "pl": "pl_PL", "zh-Hans": "zh_CN", "ja": "ja_JP",
              "de": "de_DE", "pt-BR": "pt_BR", "ko": "ko_KR", "nl": "nl_NL", "fr": "fr_FR"}
# Search snippet limits, in display width (a CJK character counts as two): Google cuts titles at about 600 px.
TITLE_MAX = 60
DESCRIPTION_MAX = 160
# Pages that carry SoftwareApplication structured data; the home page adds Organization.
APP_SCHEMA_PAGES = {"index.html", "pricing.html", "download.html"}
FAQ_PAGES = {"support.html"}
# Responsive screenshot variants (made once from the originals: name-w720.webp, name-w1440.webp).
SCREENSHOT_WIDTHS = (720, 1440)
SCREENSHOT_SIZES = "(max-width: 700px) 100vw, (max-width: 1300px) 90vw, 1200px"
IMG_TAG = re.compile(r'<img src="([^"]*screenshots/[^"]+?)\.webp" width="(\d+)"')

PLACEHOLDER = re.compile(r"\{\{([A-Z0-9_]+)\}\}")
# <!-- if:NAME -->shown when NAME is set<!-- else -->shown otherwise<!-- /if -->
IF_BLOCK = re.compile(r"<!-- if:([A-Z0-9_]+) -->(.*?)(?:<!-- else -->(.*?))?<!-- /if -->", re.S)


# --------------------------------------------------------------------------
# Minimal Markdown (only the subset the legal drafts use)
# --------------------------------------------------------------------------

def _slug(text: str) -> str:
    text = re.sub(r"<[^>]+>", "", text)
    text = re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-")
    return text or "section"


def _inline(text: str) -> str:
    out = html.escape(text, quote=False)
    out = re.sub(r"`([^`]+)`", r"<code>\1</code>", out)
    out = re.sub(r"\*\*([^*]+)\*\*", r"<strong>\1</strong>", out)
    out = re.sub(r"(?<![\w*])\*([^*\s][^*]*)\*(?![\w*])", r"<em>\1</em>", out)

    def link(m: re.Match) -> str:
        label, href = m.group(1), m.group(2)
        if _app_links is not None:
            for md, page in _app_links.items():
                if href == md or href.startswith(md + "#"):
                    return f'<a href="{html.escape(page + href[len(md):])}">{label}</a>'
            return label
        # Cross-links between drafts point at the rendered pages.
        for md, page in LEGAL_PAGES:
            if href == md or href.startswith(md + "#"):
                href = page.split("/", 1)[1] + href[len(md):]
        return f'<a href="{html.escape(href)}">{label}</a>'

    return re.sub(r"\[([^\]]+)\]\(([^)\s]+)\)", link, out)


def markdown(text: str) -> str:
    lines = text.replace("\r\n", "\n").split("\n")
    out: list[str] = []
    i = 0
    used_ids: set[str] = set()

    def heading_id(t: str) -> str:
        base = _slug(t)
        hid, n = base, 2
        while hid in used_ids:
            hid, n = f"{base}-{n}", n + 1
        used_ids.add(hid)
        return hid

    while i < len(lines):
        line = lines[i]
        if not line.strip():
            i += 1
            continue
        m = re.match(r"^(#{1,4})\s+(.*)$", line)
        if m:
            level, body = len(m.group(1)), _inline(m.group(2).strip())
            out.append(f'<h{level} id="{heading_id(body)}">{body}</h{level}>')
            i += 1
            continue
        if re.match(r"^-{3,}\s*$", line):
            out.append("<hr>")
            i += 1
            continue
        if line.startswith(">"):
            block = []
            while i < len(lines) and lines[i].startswith(">"):
                block.append(lines[i][1:].lstrip() if lines[i] != ">" else "")
                i += 1
            out.append(f"<blockquote>{markdown(chr(10).join(block))}</blockquote>")
            continue
        if line.startswith("|"):
            rows = []
            while i < len(lines) and lines[i].startswith("|"):
                rows.append([c.strip() for c in lines[i].strip().strip("|").split("|")])
                i += 1
            head, body = rows[0], [r for r in rows[1:] if not all(re.match(r"^:?-+:?$", c) for c in r)]
            t = ["<div class=\"table-wrap\"><table><thead><tr>"]
            t += [f"<th scope=\"col\">{_inline(c)}</th>" for c in head]
            t.append("</tr></thead><tbody>")
            for r in body:
                t.append("<tr>" + "".join(f"<td>{_inline(c)}</td>" for c in r) + "</tr>")
            t.append("</tbody></table></div>")
            out.append("".join(t))
            continue
        lm = re.match(r"^(\s*)([-*]|\d+\.)\s+(.*)$", line)
        if lm:
            ordered = lm.group(2)[0].isdigit()
            tag = "ol" if ordered else "ul"
            items: list[str] = []
            while i < len(lines):
                cur = lines[i]
                im = re.match(r"^([-*]|\d+\.)\s+(.*)$", cur)
                if im and (im.group(1)[0].isdigit()) == ordered:
                    items.append(im.group(2))
                elif cur.startswith("  ") and cur.strip() and items:
                    items[-1] += " " + cur.strip()
                else:
                    break
                i += 1
            out.append(f"<{tag}>" + "".join(f"<li>{_inline(t)}</li>" for t in items) + f"</{tag}>")
            continue
        para = []
        while i < len(lines) and lines[i].strip() and not re.match(r"^(#{1,4}\s|>|\||[-*]\s|\d+\.\s|-{3,}\s*$)", lines[i]):
            para.append(lines[i].strip())
            i += 1
        out.append(f"<p>{_inline(' '.join(para))}</p>")
    return "\n".join(out)


# --------------------------------------------------------------------------
# Pages
# --------------------------------------------------------------------------

def parse_page(text: str) -> tuple[dict, str]:
    meta: dict[str, str] = {}
    if text.startswith("---\n"):
        head, _, text = text[4:].partition("\n---\n")
        for row in head.splitlines():
            if ":" in row:
                k, v = row.split(":", 1)
                meta[k.strip()] = v.strip()
    return meta, text


def render_legal(md_text: str, review_complete: bool) -> tuple[str, str, str]:
    """Return (title, summary, html) for one legal draft."""
    def section(name: str, css: str, wrapper: str) -> None:
        nonlocal md_text
        pattern = re.compile(rf"<!-- {name} -->\n(.*?)\n<!-- /{name} -->\n?", re.S)
        if review_complete:
            md_text = pattern.sub("", md_text)
        else:
            md_text = pattern.sub(
                lambda m: f"\n@@RAW@@<{wrapper} class=\"{css}\">{markdown(m.group(1))}</{wrapper}>@@/RAW@@\n",
                md_text,
            )

    section("draft-notice", "draft-notice", "div")
    section("owner-decisions", "owner-decisions", "section")
    title_m = re.search(r"^#\s+(.+)$", md_text, re.M)
    title = title_m.group(1).strip() if title_m else "Legal"
    page_title = title.removeprefix("LocalGateKeys ")
    summary_m = re.search(r"<!-- summary: (.*?) -->", md_text)
    summary = summary_m.group(1).strip() if summary_m else title
    md_text = re.sub(r"<!-- summary: .*? -->\n?", "", md_text)

    parts = re.split(r"@@RAW@@(.*?)@@/RAW@@", md_text, flags=re.S)
    body = []
    for n, part in enumerate(parts):
        body.append(part if n % 2 else markdown(part))
    return page_title, summary, "\n".join(body)


def _is_set(config: dict, name: str) -> bool:
    v = config.get(name)
    return v is True or (isinstance(v, str) and bool(v.strip()))


def resolve_ifs(doc: str, config: dict) -> str:
    """Keep the branch of each if-block that matches whether its value is set."""
    return IF_BLOCK.sub(lambda m: m.group(2) if _is_set(config, m.group(1)) else (m.group(3) or ""), doc)


def fill(doc: str, config: dict, missing: dict[str, set], page: str) -> str:
    def value(name: str):
        v = config.get(name)
        return v if isinstance(v, str) and v.strip() else None

    def sub_plain(m: re.Match) -> str:
        v = value(m.group(1))
        if v is None:
            missing.setdefault(m.group(1), set()).add(page)
            return m.group(0)
        # A value may itself contain placeholders, e.g. an address awaiting {{POSTAL_CODE}}.
        return PLACEHOLDER.sub(sub_plain, html.escape(v))

    def sub_text(m: re.Match) -> str:
        v = value(m.group(1))
        if v is None:
            missing.setdefault(m.group(1), set()).add(page)
            return f'<span class="ph">{m.group(0)}</span>'
        return PLACEHOLDER.sub(sub_text, html.escape(v))

    head, sep, body = doc.partition("<body")
    head = PLACEHOLDER.sub(sub_plain, head)
    pieces = re.split(r"(<[^>]+>)", sep + body)
    for n, piece in enumerate(pieces):
        pieces[n] = PLACEHOLDER.sub(sub_plain if piece.startswith("<") else sub_text, piece)
    return head + "".join(pieces)


def load_catalogs(wanted: "list[str] | None") -> list:
    """The languages to build, in LANGUAGES order: those with a catalog (and in `wanted`, if given)."""
    out = []
    for lang in LANGUAGES:
        path = I18N / f"{lang[0]}.json"
        if wanted is not None and lang[0] not in wanted:
            continue
        if not path.exists():
            if wanted is not None:
                print(f"No catalog for {lang[0]} ({path.name}); skipped.")
            continue
        out.append((lang, json.loads(path.read_text(encoding="utf-8"))))
    if not out or out[0][0][0] != "en":
        raise SystemExit("build.py: the English catalog (website/i18n/en.json) is always built")
    return out


def translate(text: str, catalog: dict, english: dict, page: str) -> str:
    def sub(m: re.Match) -> str:
        key = m.group(1)
        if key in catalog:
            return catalog[key]
        if key in english:
            return english[key]
        raise SystemExit(f"build.py: {page} uses unknown text key {key!r}")
    return TEXT_KEY.sub(sub, text)


def build(strict: bool, langs: "list[str] | None" = None) -> int:
    languages = load_catalogs(langs)
    english = languages[0][1]
    multi = len(languages) > 1
    config = json.loads(CONFIG.read_text(encoding="utf-8"))
    review_complete = bool(config.get("LEGAL_REVIEW_COMPLETE") is True)
    # HIDE_DRAFT_NOTES drops the DRAFT banners and owner notes from the public
    # pages without claiming a lawyer has reviewed them.
    hide_notes = review_complete or config.get("HIDE_DRAFT_NOTES") is True
    layout = (SRC / "layout.html").read_text(encoding="utf-8")

    # Empty public/ rather than deleting it, so a preview server or shell
    # sitting in the folder does not make the build fail on Windows.
    OUT.mkdir(exist_ok=True)
    for child in OUT.iterdir():
        shutil.rmtree(child) if child.is_dir() else child.unlink()
    shutil.copytree(SRC / "static", OUT, dirs_exist_ok=True)
    for dest, source in BRAND_FILES.items():
        (OUT / dest).parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, OUT / dest)

    pages: list[tuple[str, dict, str]] = []
    for path in sorted((SRC / "pages").rglob("*.html")):
        meta, body = parse_page(path.read_text(encoding="utf-8"))
        rel = path.relative_to(SRC / "pages").as_posix()
        pages.append((rel, meta, body))
        PAGE_SOURCES[rel] = [path]
    PAGE_SOURCES["compare.html"] = PAGE_SOURCES.get("compare.html", []) + [COMPARE]
    PAGE_SOURCES["switch/index.html"] = PAGE_SOURCES.get("switch/index.html", []) + [SWITCH]
    for md_name, out_name in LEGAL_PAGES:
        PAGE_SOURCES[out_name] = [LEGAL_SRC / md_name]
        title, summary, body = render_legal((LEGAL_SRC / md_name).read_text(encoding="utf-8"), hide_notes)
        meta = {"title": title, "description": summary, "section": "legal", "body_class": "legal"}
        pages.append((out_name, meta, f'<article class="prose legal-doc">\n{body}\n</article>'))
    pages = add_switch_pages(pages)
    pages = add_compare_table(pages)
    pages = add_guide_pages(pages)

    missing: dict[str, set] = {}
    LENGTH_WARNINGS.clear()
    built = 0
    for (code, _bcp47, folder, _native), catalog in languages:
        for rel, meta, body in pages:
            if folder and is_english_only(rel):
                continue
            write_page(rel, meta, body, layout, config, missing, languages, code, catalog, english, multi)
            built += 1
    write_sitemap(languages)

    # Placeholders in copied static files (security.txt, robots.txt, ...).
    for path in OUT.rglob("*"):
        if path.suffix in {".txt", ".xml"} or path.name == "_headers":
            text = path.read_text(encoding="utf-8")
            rel = path.relative_to(OUT).as_posix()
            path.write_text(
                PLACEHOLDER.sub(lambda m: _static_sub(m, config, missing, rel), text),
                encoding="utf-8",
                newline="\n",
            )

    app_pages = build_app_legal(config, hide_notes, missing)

    # A placeholder that skipped fill() (a set value never substituted) is a build bug, not a draft gap.
    unfilled = sorted({
        f"{path.relative_to(OUT).as_posix()}: {m.group(0)}"
        for path in OUT.rglob("*.html")
        for m in PLACEHOLDER.finditer(path.read_text(encoding="utf-8"))
        if m.group(1) not in missing
    })
    if unfilled:
        raise SystemExit("build.py: placeholders left unsubstituted:\n  " + "\n  ".join(unfilled[:20]))

    if LENGTH_WARNINGS:
        print(f"{len(LENGTH_WARNINGS)} titles/descriptions over {TITLE_MAX}/{DESCRIPTION_MAX} (display width):")
        for line in LENGTH_WARNINGS[:20]:
            print("  " + line)
    names = ", ".join(lang[0] for lang, _ in languages)
    shown = OUT.relative_to(REPO) if OUT.is_relative_to(REPO) else OUT
    print(f"Built {built + app_pages} pages ({names}) into {shown}")
    if not review_complete and hide_notes:
        print("Legal pages are NOT lawyer-reviewed (LEGAL_REVIEW_COMPLETE is not true); DRAFT notices hidden by HIDE_DRAFT_NOTES.")
    elif not review_complete:
        print("Legal pages carry DRAFT notices (LEGAL_REVIEW_COMPLETE is not true).")
    if missing:
        print(f"\n{len(missing)} placeholders still unfilled (set them in {CONFIG.name}):")
        for name in sorted(missing):
            where = sorted(missing[name])
            shown = ", ".join(where[:4]) + (f" +{len(where) - 4} more" if len(where) > 4 else "")
            print(f"  {{{{{name}}}}}  ({shown})")
        if strict:
            return 1
    return 0


# The checkout stays English-only: _headers grants Paddle's scripts to /buy alone, and the CSP is unchanged.
# buy.js still passes <html lang> to Paddle, so a translated /buy needs only a _headers entry later.
ENGLISH_ONLY_PAGES = {"buy.html"}


SWITCH_FORMATS = {"csv", "cxf", "1pux", "kdbx", "json"}
SWITCH_FIELDS = ("slug", "name", "exportSteps", "importFormat", "importer", "lossList", "whyPeopleLeave", "priceLine")


def load_switch() -> list:
    """The competitors of switch.json, checked: each reason people leave carries a date and a source URL."""
    entries = json.loads(SWITCH.read_text(encoding="utf-8"))["competitors"]
    for e in entries:
        where = f"switch.json {e.get('slug')!r}"
        for field in SWITCH_FIELDS:
            if field not in e:
                raise SystemExit(f"build.py: {where} has no {field}")
        if not re.fullmatch(r"[a-z0-9-]+", e["slug"]):
            raise SystemExit(f"build.py: {where}: slug must be lowercase letters, digits and hyphens")
        if e["importFormat"] not in SWITCH_FORMATS:
            raise SystemExit(f"build.py: {where}: importFormat must be one of {sorted(SWITCH_FORMATS)}")
        for why in e["whyPeopleLeave"]:
            if not re.fullmatch(r"https://\S+", why.get("source") or ""):
                raise SystemExit(f"build.py: {where}: whyPeopleLeave {why.get('key')!r} has no https source URL")
            if not re.fullmatch(r"\d{4}-\d{2}(-\d{2})?", why.get("date") or ""):
                raise SystemExit(f"build.py: {where}: whyPeopleLeave {why.get('key')!r} has no date (YYYY-MM)")
    return entries


def add_switch_pages(pages: list) -> list:
    """Render the switch-page partial once per competitor, and fill the list on switch/index.html."""
    entries = load_switch()
    meta, partial = parse_page(SWITCH_PARTIAL.read_text(encoding="utf-8"))
    out = []
    for rel, page_meta, body in pages:
        if rel == "switch/index.html":
            items = "\n".join(f'    <li><a href="[[home]]switch/{e["slug"]}.html">{html.escape(e["name"])}</a></li>'
                              for e in entries)
            body = body.replace("[[switch_list]]", items)
        out.append((rel, page_meta, body))
    for e in entries:
        why = ""
        if e["whyPeopleLeave"]:
            items = "\n".join(
                f'    <li>[[t:{w["key"]}]] <a href="{html.escape(w["source"])}" rel="nofollow noopener">'
                f'[[t:switch.source]]</a><!-- source: {html.escape(w["source"])} --></li>'
                for w in e["whyPeopleLeave"])
            why = (f"  <h2>[[t:switch.h.why]]</h2>\n  <ul>\n{items}\n  </ul>\n"
                   "  <p class=\"quiet\">[[t:switch.checked]]</p>\n\n")
        body = (partial.replace("[[switch_why]]\n", why)
                .replace("[[switch_export]]", "\n".join(f"    <li>[[t:{k}]]</li>" for k in e["exportSteps"]))
                .replace("[[switch_import]]", f"[[t:switch.import.{e['importFormat']}]]")
                .replace("[[switch_importer]]", html.escape(e["importer"]))
                .replace("[[switch_lost]]", "\n".join(f"    <li>[[t:{k}]]</li>" for k in e["lossList"]))
                .replace("[[switch_price]]", f"[[t:{e['priceLine']}]]"))
        out.append((f"switch/{e['slug']}.html", {**meta, "competitor": e["name"]}, body))
        PAGE_SOURCES[f"switch/{e['slug']}.html"] = [SWITCH_PARTIAL, SWITCH]
    return out


COMPARE_VALUES = {"yes", "no", "partial", "text"}


def load_compare() -> dict:
    """compare.json, checked: every row has a cell per column, and a competitor's yes/partial carries a source URL."""
    data = json.loads(COMPARE.read_text(encoding="utf-8"))
    ids = [c["id"] for c in data["columns"]]
    for row in data["rows"]:
        where = f"compare.json {row.get('key')!r}"
        if set(row["cells"]) != set(ids):
            raise SystemExit(f"build.py: {where}: cells must be exactly {ids}")
        for cid, cell in row["cells"].items():
            if cell.get("value") not in COMPARE_VALUES:
                raise SystemExit(f"build.py: {where} {cid}: value must be one of {sorted(COMPARE_VALUES)}")
            if cell["value"] == "text" and not cell.get("key"):
                raise SystemExit(f"build.py: {where} {cid}: a text cell needs a catalog key")
            sourced = re.fullmatch(r"https://\S+", cell.get("source") or "")
            states_fact = cell["value"] != "text" or cell.get("key") != "compare.v.unchecked"
            if cid != ids[0] and states_fact and not sourced:
                raise SystemExit(f"build.py: {where} {cid}: a competitor {cell['value']} needs an https source URL")
    return data


def add_compare_table(pages: list) -> list:
    """Fill [[compare_table]] on compare.html from compare.json, so every language shows the same values."""
    data = load_compare()
    head = "".join(f'<th scope="col">{html.escape(c["name"])}</th>' for c in data["columns"])
    rows = []
    for row in data["rows"]:
        cells = []
        for c in data["columns"]:
            cell = row["cells"][c["id"]]
            key = cell.get("key") or f"compare.v.{cell['value']}"
            kind = "unchecked" if key == "compare.v.unchecked" else cell["value"]
            source = ""
            if cell.get("source"):
                url = html.escape(cell["source"])
                source = (f' <a class="source" href="{url}" rel="nofollow noopener">[[t:compare.source]]</a>'
                          f"<!-- source: {url} -->")
            cells.append(f'<td class="{kind}">[[t:{key}]]{source}</td>')
        rows.append(f'        <tr><th scope="row">[[t:{row["key"]}]]</th>{"".join(cells)}</tr>')
    table = ('<table class="products">\n      <caption class="quiet">[[t:compare.caption]]</caption>\n'
             f'      <thead>\n        <tr><th scope="col">[[t:compare.col.feature]]</th>{head}</tr>\n      </thead>\n'
             "      <tbody>\n" + "\n".join(rows) + "\n      </tbody>\n    </table>")
    return [(rel, meta, body.replace("[[compare_table]]", table) if rel == "compare.html" else body)
            for rel, meta, body in pages]


GUIDE_PANEL = re.compile(r'  <section class="help-panel" id="([a-z]+)".*?\n  </section>\n', re.S)


def add_guide_pages(pages: list) -> list:
    """guide/<platform>.html: one help.html panel each, with links to the other platforms and the full guide."""
    help_body = next(body for rel, _meta, body in pages if rel == "help.html")
    panels = {m.group(1): m.group(0) for m in GUIDE_PANEL.finditer(help_body)}
    GUIDE_IDS.clear()
    for pid, panel in panels.items():
        for i in re.findall(r'\sid="([^"]+)"', panel):
            GUIDE_IDS[i] = pid
    for slug, _key in GUIDE_PLATFORMS:
        if slug not in panels:
            raise SystemExit(f"build.py: help.html has no help-panel {slug!r} for guide/{slug}.html")

    def links(current: "str | None", css: str) -> str:
        items = []
        for slug, key in GUIDE_PLATFORMS:
            here = ' aria-current="page"' if slug == current else ""
            items.append(f'<li><a class="{css}" href="[[home]]guide/{slug}.html"{here}>[[t:{key}]]</a></li>')
        return "".join(items)

    out = []
    for rel, meta, body in pages:
        if rel == "help.html":
            body = body.replace("[[guide_links]]", (
                '  <nav class="guide-links" aria-labelledby="guide-links-title">\n'
                '    <p id="guide-links-title">[[t:guide.pages]]</p>\n'
                f'    <ul>{links(None, "guide-link")}</ul>\n  </nav>'))
        out.append((rel, meta, body))
    basics = re.search(r'  <aside class="help-basics glass">.*?</aside>\n', help_body, re.S).group(0)
    for slug, _key in GUIDE_PLATFORMS:
        # The page names the platform in its h1; the panel heading becomes the name of its topic list.
        panel = re.sub(r'(<h2 class="panel-title" id="[^"]+">)\[\[t:help\.[a-z]+\.2\]\](</h2>)',
                       rf"\g<1>[[t:help.{slug}.1]]\g<2>", panels[slug], count=1)
        body = (
            '<div class="wrap page-head">\n'
            f'  <h1>[[t:help.{slug}.2]]</h1>\n'
            '  <p class="lead">[[t:guide.lead]]</p>\n'
            '</div>\n\n'
            '<div class="wrap page-body help guide-single">\n\n'
            f'  <nav class="help-tabs glass" aria-label="[[t:help.intro.3]]">\n    <ul>{links(slug, "help-tab")}</ul>\n  </nav>\n\n'
            f"{basics}\n{panel}\n"
            '  <p class="guide-all"><a href="[[home]]help.html">[[t:guide.all]]</a></p>\n'
            '</div>\n\n<script src="[[root]]guide.js"></script>\n'
        )
        rel = f"guide/{slug}.html"
        out.append((rel, {"body_class": "help-page", "guide": slug}, body))
        PAGE_SOURCES[rel] = [HELP_PAGE]
    return out


def guide_anchors(doc: str, slug: str) -> str:
    """On guide/<slug>.html, an anchor into another panel points at the page that now holds it."""
    platforms = dict(GUIDE_PLATFORMS)

    def sub(m: re.Match) -> str:
        target = m.group(1)
        owner = GUIDE_IDS.get(target)
        if owner is None or owner == slug:
            return m.group(0)
        if owner in platforms:
            page = f"[[home]]guide/{owner}.html"
            return f'href="{page}"' if target == owner else f'href="{page}#{target}"'
        return f'href="[[home]]help.html#{target}"'
    return re.sub(r'href="#([^"]+)"', sub, doc)


# Internal links as the sources write them, by file name: "features.html", "../de/index.html#x".
INTERNAL_HTML = re.compile(r'href="(?![A-Za-z][A-Za-z0-9+.-]*:|//)([^"#?]*?)\.html((?:[?#][^"]*)?)"')


def clean_links(doc: str) -> str:
    """Write internal links in the form Cloudflare Pages serves without a redirect: no .html, no index.html.

    Pages answers /features for features.html and /de/ for de/index.html and 308-redirects the .html forms, so the
    links match the canonical, hreflang and sitemap URLs (page_url). Preview locally with website/serve.py."""
    def sub(m: re.Match) -> str:
        path, tail = m.group(1), m.group(2)
        if path == "index" or path.endswith("/index"):
            path = path[: -len("index")]
        return f'href="{path or "./"}{tail}"'
    return INTERNAL_HTML.sub(sub, doc)


def is_english_only(rel: str) -> bool:
    """Legal texts and the checkout are English-only; other languages link to the English pages."""
    return rel.startswith("legal/") or rel in ENGLISH_ONLY_PAGES


def page_url(folder: str, rel: str) -> str:
    """The public URL path of a page (no domain or leading slash), as the canonical link has it."""
    if rel == "index.html":
        path = ""
    elif rel.endswith("/index.html"):
        path = rel.removesuffix("index.html")
    else:
        path = rel.removesuffix(".html")
    return (folder + "/" if folder else "") + path


GLOBE = ('<svg viewBox="0 0 24 24" width="18" height="18" aria-hidden="true" focusable="false">'
         '<circle cx="12" cy="12" r="9" fill="none" stroke="currentColor" stroke-width="1.6"/>'
         '<path d="M3 12h18M12 3c2.5 2.6 3.8 5.6 3.8 9s-1.3 6.4-3.8 9c-2.5-2.6-3.8-5.6-3.8-9S9.5 5.6 12 3z" '
         'fill="none" stroke="currentColor" stroke-width="1.6"/></svg>')


def write_page(rel, meta, body, layout, config, missing, languages, code, catalog, english, multi) -> None:
    _code, bcp47, folder, _native = next(lang for lang, _ in languages if lang[0] == code)
    depth = rel.count("/") + (1 if folder else 0)
    # 404.html is served at any missing path, so it needs absolute URLs.
    # [[root]] is the site root (assets, legal pages); [[home]] is this language's root (pages).
    root = "/" if rel == "404.html" else "../" * depth
    home = root + (folder + "/" if folder else "")
    page = (folder + "/" if folder else "") + rel

    def t(text: str) -> str:
        # [[name]] is the competitor on a switch page; names stay untranslated.
        return translate(text, catalog, english, page).replace("[[name]]", html.escape(meta.get("competitor", "")))

    nav = []
    # Seven links; Download is the one filled button. Switch and Buy Pro are in the footer.
    for href, key in NAV:
        current = ' aria-current="page"' if rel == href else ""
        css = ' class="nav-cta"' if href == "download.html" else ""
        base = root if is_english_only(href) else home
        nav.append(f'<li><a{css} href="{base}{href}"{current}>{t("[[t:" + key + "]]")}</a></li>')
    seo = "seo." + rel.removesuffix(".html").replace("-", "_").replace("/", ".")
    seo_title = f"[[t:{seo}.title]]" if f"{seo}.title" in english else meta.get("title", "LocalGateKeys")
    seo_description = (f"[[t:{seo}.description]]" if f"{seo}.description" in english
                       else meta.get("description", ""))
    title = t(seo_title)
    # Search titles (seo.* keys) are complete as written; others get the brand unless they already name it.
    full_title = title if seo_title.startswith("[[t:seo.") or "LocalGateKeys" in title else f"{title} | LocalGateKeys"
    description = t(seo_description)
    _check_length(page, full_title, description, config)

    # Only with more than one language: an English-only build is unchanged.
    alternates = lang_switch = lang_menu = legal_note = ""
    if multi:
        if not is_english_only(rel):
            links = [
                f'<link rel="alternate" hreflang="{lang[1]}" href="https://{{{{DOMAIN}}}}/{page_url(lang[2], rel)}">'
                for lang, _ in languages
            ]
            links.append(
                f'<link rel="alternate" hreflang="x-default" href="https://{{{{DOMAIN}}}}/{page_url("", rel)}">'
            )
            alternates = "".join("\n  " + link for link in links)
        target = "index.html" if is_english_only(rel) else rel
        items = []
        for (l_code, l_bcp47, l_folder, l_native), _ in languages:
            href = root + (l_folder + "/" if l_folder else "") + target
            current = ' aria-current="true"' if l_code == code else ""
            items.append(f'<li><a href="{href}" hreflang="{l_bcp47}" lang="{l_bcp47}"{current}>{l_native}</a></li>')
        label = t("[[t:layout.language]]")
        lang_switch = f'\n      <nav class="lang-switch" aria-label="{label}"><ul>' + "".join(items) + "</ul></nav>"
        # Header: a no-script disclosure menu. Browsers expose <summary> as a button with its expanded state; Enter
        # or Space opens it and the language links follow it in the tab order.
        lang_menu = (
            '      <details class="lang-menu">\n'
            f'        <summary>{GLOBE}<span>{label}</span></summary>\n'
            '        <ul class="lang-menu-list">' + "".join(items) + "</ul>\n"
            "      </details>\n"
        )
        if folder:
            legal_note = f'\n        <p class="quiet">{t("[[t:layout.legal_note]]")}</p>'

    doc = (
        layout.replace("[[title]]", html.escape(full_title))
        .replace("[[og_title]]", html.escape(full_title))
        .replace("[[og_type]]", "article" if rel.startswith("news/") else "website")
        .replace("[[og_locale]]", OG_LOCALES.get(code, "en_US"))
        .replace("[[description]]", html.escape(description))
        .replace("[[path]]", page_url(folder, rel))
        .replace("[[lang]]", bcp47)
        .replace("[[alternates]]", alternates)
        .replace("[[lang_switch]]", lang_switch)
        .replace("[[lang_menu]]", lang_menu)
        .replace("[[legal_note]]", legal_note)
        .replace("[[nav]]", "\n          ".join(nav))
        .replace("[[body_class]]", meta.get("body_class", "page"))
        .replace("[[referrer]]", meta.get("referrer", "no-referrer"))
        .replace("[[content]]", body.strip())
    )
    doc = t(doc)
    if meta.get("guide"):
        doc = guide_anchors(doc, meta["guide"])
    doc = doc.replace("[[home]]", home).replace("[[root]]", root)
    doc = resolve_ifs(doc, config)
    doc = fill(doc, config, missing, page)
    # The title and description are still raw text here: fill their placeholders ({{PRICE}}) for JSON-LD too.
    # structured_data reads both through _text(), which unescapes once.
    ld_title = fill(html.escape(full_title), config, missing, page)
    ld_description = fill(html.escape(description), config, missing, page)
    doc = doc.replace("[[jsonld]]", structured_data(rel, doc, config, folder, ld_title, ld_description))
    doc = responsive_images(doc)
    doc = clean_links(doc)
    out = OUT / page
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(doc, encoding="utf-8", newline="\n")


LENGTH_WARNINGS: list[str] = []


def display_width(text: str) -> int:
    return sum(2 if unicodedata.east_asian_width(c) in "WF" else 1 for c in text)


def _check_length(page: str, title: str, description: str, config: dict) -> None:
    """Warn (not fail) when a title or description would be cut in search results."""
    def filled(text: str) -> str:
        return PLACEHOLDER.sub(lambda m: str(config.get(m.group(1)) or m.group(0)), html.unescape(text))
    if page.startswith("legal/") or page.endswith("404.html"):
        return
    if display_width(filled(title)) > TITLE_MAX:
        LENGTH_WARNINGS.append(f"{page}: title {display_width(filled(title))}")
    if display_width(filled(description)) > DESCRIPTION_MAX:
        LENGTH_WARNINGS.append(f"{page}: description {display_width(filled(description))}")


def _price_parts(config: dict) -> tuple[str, str]:
    """("29.99", "USD") from PRICE ("US$29.99"), so structured data never drifts from the pages."""
    m = re.fullmatch(r"US\$(\d+(?:\.\d{2})?)", str(config.get("PRICE", "")).strip())
    if not m:
        raise SystemExit(f"build.py: PRICE {config.get('PRICE')!r} is not in the form US$12.34")
    return m.group(1), "USD"


def _text(fragment: str) -> str:
    return re.sub(r"\s+", " ", html.unescape(re.sub(r"<[^>]+>", "", fragment))).strip()


def _jsonld(data: dict) -> str:
    # Escaped "</" cannot close the script element early.
    text = json.dumps(data, ensure_ascii=False, separators=(",", ":")).replace("</", "<\\/")
    return f'\n  <script type="application/ld+json">{text}</script>'


def structured_data(rel: str, doc: str, config: dict, folder: str, title: str, description: str) -> str:
    """JSON-LD for the page, from the same config and text the page shows (CSP does not run data blocks)."""
    site = f"https://{config.get('DOMAIN', 'localgatekeys.app')}/"
    url = site + page_url(folder, rel)
    lang = re.search(r'<html lang="([^"]+)"', doc).group(1)
    out = []
    if rel in APP_SCHEMA_PAGES:
        price, currency = _price_parts(config)
        out.append({
            "@context": "https://schema.org",
            "@type": "SoftwareApplication",
            "name": "LocalGateKeys",
            "applicationCategory": "SecurityApplication",
            "operatingSystem": "Windows 10, Windows 11, macOS, iOS",
            "url": url,
            "inLanguage": lang,
            "description": _text(description),
            "image": f"{site}brand/og-image.png",
            "offers": [
                {"@type": "Offer", "name": "LocalGateKeys Free", "price": "0", "priceCurrency": currency},
                {"@type": "Offer", "name": "LocalGateKeys Pro", "price": price, "priceCurrency": currency,
                 "url": f"{site}pricing"},
            ],
        })
    if rel == "index.html":
        out.append({
            "@context": "https://schema.org",
            "@type": "Organization",
            "name": "LocalGateKeys",
            "url": site,
            "logo": f"{site}brand/icon-256.png",
            "email": config.get("CONTACT_EMAIL"),
        })
    if rel in FAQ_PAGES:
        faqs = []
        for m in re.finditer(r"<details>\s*<summary>(.*?)</summary>(.*?)</details>", doc, re.S):
            q, a = _text(m.group(1)), _text(m.group(2))
            if q and a:
                faqs.append({"@type": "Question", "name": q, "acceptedAnswer": {"@type": "Answer", "text": a}})
        if faqs:
            out.append({"@context": "https://schema.org", "@type": "FAQPage", "inLanguage": lang, "mainEntity": faqs})
    if rel.startswith("news/"):
        m = re.match(r"news/(\d{4})-(\d{2})-", rel)
        out.append({
            "@context": "https://schema.org",
            "@type": "BlogPosting",
            "headline": _text(title).removesuffix(" | LocalGateKeys"),
            "description": _text(description),
            "inLanguage": lang,
            "url": url,
            "datePublished": f"{m.group(1)}-{m.group(2)}" if m else None,
            "image": f"{site}brand/og-image.png",
            "author": {"@type": "Organization", "name": "LocalGateKeys", "url": site},
        })
    return "".join(_jsonld({k: v for k, v in d.items() if v is not None}) for d in out)


def responsive_images(doc: str) -> str:
    """Add srcset/sizes to screenshots that have smaller variants in static/screenshots."""
    def sub(m: re.Match) -> str:
        src, width = m.group(1), int(m.group(2))
        stem = src.split("screenshots/", 1)[1]
        variants = [w for w in SCREENSHOT_WIDTHS
                    if w < width and (SRC / "static" / "screenshots" / f"{stem}-w{w}.webp").is_file()]
        if not variants:
            return m.group(0)
        srcset = ", ".join([f"{src}-w{w}.webp {w}w" for w in variants] + [f"{src}.webp {width}w"])
        return f'<img src="{src}.webp" srcset="{srcset}" sizes="{SCREENSHOT_SIZES}" width="{width}"'
    return IMG_TAG.sub(sub, doc)


@lru_cache(maxsize=None)
def source_date(path: Path) -> str:
    """The day a source file last changed: its last git commit, or its modification time outside git."""
    try:
        run = subprocess.run(["git", "log", "-1", "--format=%cs", "--", str(path)], cwd=REPO,
                             capture_output=True, text=True, timeout=30)
        date = run.stdout.strip() if run.returncode == 0 else ""
    except (OSError, subprocess.SubprocessError):
        date = ""
    if re.fullmatch(r"\d{4}-\d{2}-\d{2}", date):
        return date
    return datetime.fromtimestamp(path.stat().st_mtime, timezone.utc).date().isoformat()


def write_sitemap(languages) -> None:
    """Fill static/sitemap.xml: each listed page once per language it exists in, with lastmod from its sources."""
    path = OUT / "sitemap.xml"
    text = path.read_text(encoding="utf-8")
    entries = re.findall(r"  <url><loc>https://\{\{DOMAIN\}\}/([^<]*)</loc></url>\n", text)
    lines = []
    for (_code, _bcp47, folder, _native), _ in languages:
        for url in entries:
            rel = "index.html" if url == "" else url + ("index.html" if url.endswith("/") else ".html")
            if folder and is_english_only(rel):
                continue
            sources = PAGE_SOURCES.get(rel)
            if not sources:
                raise SystemExit(f"build.py: sitemap.xml lists {url!r}, which no page builds")
            lastmod = max(source_date(s) for s in sources)
            lines.append(f"  <url><loc>https://{{{{DOMAIN}}}}/{page_url(folder, rel)}</loc>"
                         f"<lastmod>{lastmod}</lastmod></url>\n")
    head = text[: text.index("  <url>")]
    path.write_text(head + "".join(lines) + "</urlset>\n", encoding="utf-8", newline="\n")


def build_app_legal(config: dict, hide_notes: bool, missing: dict[str, set]) -> int:
    """The in-app legal pages (`legal/app/`): no site navigation, no shop links or names."""
    global _app_links
    layout = (SRC / "app-legal-layout.html").read_text(encoding="utf-8")
    app_config = {**config, **APP_CONFIG}
    _app_links = APP_LEGAL_LINKS
    try:
        for md_name, out_name in APP_LEGAL_PAGES:
            text = (LEGAL_SRC / md_name).read_text(encoding="utf-8").replace(" (`/buy`)", "")
            for site_words, app_words in APP_REWORDING.get(md_name, []):
                if site_words not in text:
                    raise SystemExit(f"build.py APP_REWORDING: {md_name} no longer contains {site_words!r}")
                text = text.replace(site_words, app_words)
            title, summary, body = render_legal(text, hide_notes)
            current = out_name.rsplit("/", 1)[1]
            doc = (
                layout.replace("[[title]]", html.escape(f"{title} | LocalGateKeys"))
                .replace("[[description]]", html.escape(summary))
                .replace("[[eula_current]]", ' aria-current="page"' if current == "eula.html" else "")
                .replace("[[privacy_current]]", ' aria-current="page"' if current == "privacy.html" else "")
                .replace("[[content]]", f'<article class="prose legal-doc">\n{body}\n</article>')
                .replace("[[root]]", "../" * out_name.count("/"))
            )
            doc = resolve_ifs(doc, app_config)
            doc = fill(doc, app_config, missing, out_name)
            # A sentence that starts with the provider.
            doc = re.sub(r"(\. |<p>|<li>)our payment provider", r"\1Our payment provider", doc)
            target = OUT / out_name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(doc, encoding="utf-8", newline="\n")
    finally:
        _app_links = None
    return len(APP_LEGAL_PAGES)


def _static_sub(m: re.Match, config: dict, missing: dict[str, set], rel: str) -> str:
    v = config.get(m.group(1))
    if isinstance(v, str) and v.strip():
        return PLACEHOLDER.sub(lambda inner: _static_sub(inner, config, missing, rel), v)
    missing.setdefault(m.group(1), set()).add(rel)
    return m.group(0)


if __name__ == "__main__":
    args = sys.argv[1:]
    wanted = None
    for n, arg in enumerate(args):
        if arg.startswith("--langs="):
            wanted = arg.split("=", 1)[1].split(",")
        elif arg == "--langs" and n + 1 < len(args):
            wanted = args[n + 1].split(",")
    if wanted is not None and "en" not in wanted:
        wanted = ["en", *wanted]
    sys.exit(build(strict="--strict" in args, langs=wanted))
