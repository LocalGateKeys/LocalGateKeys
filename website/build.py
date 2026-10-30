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
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parent
SRC = HERE / "src"
OUT = HERE / "public"
LEGAL_SRC = REPO / "docs" / "legal"
CONFIG = HERE / "site.config.json"
I18N = HERE / "i18n"

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
]
# Page text: [[t:page.section.n]] is replaced by that key of website/i18n/<code>.json.
TEXT_KEY = re.compile(r"\[\[t:([A-Za-z0-9_.-]+)\]\]")

NAV = [
    ("features.html", "nav.features"),
    ("pricing.html", "nav.pricing"),
    ("security.html", "nav.security"),
    ("get-started.html", "nav.get_started"),
    ("help.html", "nav.guide"),
    ("download.html", "nav.download"),
    ("support.html", "nav.support"),
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
        ("such as Microsoft Windows, Google Chrome, Microsoft Edge, Apple iOS and cloud-drive services",
         "such as Windows, web browsers, Apple iOS, macOS and cloud-drive services"),
        ("from the Microsoft Store or Apple App Store", "from the Apple App Store or another app store"),
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
        pages.append((path.relative_to(SRC / "pages").as_posix(), meta, body))
    for md_name, out_name in LEGAL_PAGES:
        title, summary, body = render_legal((LEGAL_SRC / md_name).read_text(encoding="utf-8"), hide_notes)
        meta = {"title": title, "description": summary, "section": "legal", "body_class": "legal"}
        pages.append((out_name, meta, f'<article class="prose legal-doc">\n{body}\n</article>'))

    missing: dict[str, set] = {}
    built = 0
    for (code, _bcp47, folder, _native), catalog in languages:
        for rel, meta, body in pages:
            if folder and is_english_only(rel):
                continue
            write_page(rel, meta, body, layout, config, missing, languages, code, catalog, english, multi)
            built += 1
    if multi:
        add_sitemap_languages(languages)

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


def is_english_only(rel: str) -> bool:
    """Legal texts and the checkout are English-only; other languages link to the English pages."""
    return rel.startswith("legal/") or rel in ENGLISH_ONLY_PAGES


def page_url(folder: str, rel: str) -> str:
    """The public URL path of a page (no domain or leading slash), as the canonical link has it."""
    path = "" if rel == "index.html" else rel.removesuffix(".html")
    return (folder + "/" if folder else "") + path


def write_page(rel, meta, body, layout, config, missing, languages, code, catalog, english, multi) -> None:
    _code, bcp47, folder, _native = next(lang for lang, _ in languages if lang[0] == code)
    depth = rel.count("/") + (1 if folder else 0)
    # 404.html is served at any missing path, so it needs absolute URLs.
    # [[root]] is the site root (assets, legal pages); [[home]] is this language's root (pages).
    root = "/" if rel == "404.html" else "../" * depth
    home = root + (folder + "/" if folder else "")
    page = (folder + "/" if folder else "") + rel

    def t(text: str) -> str:
        return translate(text, catalog, english, page)

    nav = []
    # The checkout joins the menu once Pro is on sale.
    for href, key in NAV + ([("buy.html", "nav.buy")] if config.get("BUY_URL") else []):
        current = ' aria-current="page"' if rel == href else ""
        base = root if is_english_only(href) else home
        nav.append(f'<li><a href="{base}{href}"{current}>{t("[[t:" + key + "]]")}</a></li>')
    title = t(meta.get("title", "LocalGateKeys"))
    full_title = "LocalGateKeys" if rel == "index.html" else f"{title} | LocalGateKeys"

    # Only with more than one language: an English-only build is unchanged.
    alternates = lang_switch = legal_note = ""
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
            items.append(f'<a href="{href}" hreflang="{l_bcp47}" lang="{l_bcp47}"{current}>{l_native}</a>')
        lang_switch = (
            f'\n      <p class="lang-switch" role="navigation" aria-label="{t("[[t:layout.language]]")}">'
            + " · ".join(items) + "</p>"
        )
        if folder:
            legal_note = f'\n        <p class="quiet">{t("[[t:layout.legal_note]]")}</p>'

    doc = (
        layout.replace("[[title]]", html.escape(full_title))
        .replace("[[description]]", html.escape(t(meta.get("description", ""))))
        .replace("[[path]]", page_url(folder, rel))
        .replace("[[lang]]", bcp47)
        .replace("[[alternates]]", alternates)
        .replace("[[lang_switch]]", lang_switch)
        .replace("[[legal_note]]", legal_note)
        .replace("[[nav]]", "\n          ".join(nav))
        .replace("[[body_class]]", meta.get("body_class", "page"))
        .replace("[[referrer]]", meta.get("referrer", "no-referrer"))
        .replace("[[content]]", body.strip())
    )
    doc = t(doc)
    doc = doc.replace("[[home]]", home).replace("[[root]]", root)
    doc = resolve_ifs(doc, config)
    doc = fill(doc, config, missing, page)
    out = OUT / page
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(doc, encoding="utf-8", newline="\n")


def add_sitemap_languages(languages) -> None:
    """List each translated page of static/sitemap.xml once more per extra language."""
    path = OUT / "sitemap.xml"
    text = path.read_text(encoding="utf-8")
    entries = re.findall(r"  <url><loc>https://\{\{DOMAIN\}\}/([^<]*)</loc></url>\n", text)
    extra = []
    for (_code, _bcp47, folder, _native), _ in languages[1:]:
        for url in entries:
            rel = "index.html" if url == "" else url + ".html"
            if not is_english_only(rel):
                extra.append(f"  <url><loc>https://{{{{DOMAIN}}}}/{page_url(folder, rel)}</loc></url>\n")
    path.write_text(text.replace("</urlset>", "".join(extra) + "</urlset>"), encoding="utf-8", newline="\n")


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
