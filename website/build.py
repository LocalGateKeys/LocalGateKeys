#!/usr/bin/env python3
"""Build the LocalGateKeys website into website/public/.

Standard library only, so it runs on a stock Python 3.9+ (including the
Cloudflare Pages build image). The output is plain HTML/CSS with no scripts.

    python website/build.py            # build, list unfilled placeholders
    python website/build.py --strict   # also fail if any placeholder is unfilled

Inputs:
    website/src/layout.html            page shell (header, footer)
    website/src/pages/**/*.html        page bodies with a small front-matter block
    website/src/static/                copied as-is (CSS, _headers, robots.txt, ...)
    docs/legal/*.md                    legal drafts, rendered to public/legal/
    website/site.config.json           values for {{PLACEHOLDER}} tokens
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

NAV = [
    ("features.html", "Features"),
    ("pricing.html", "Pricing"),
    ("security.html", "Security"),
    ("get-started.html", "Get started"),
    ("download.html", "Download"),
    ("support.html", "Support"),
]

# Legal drafts rendered into the site, in footer order: (markdown file, output page).
LEGAL_PAGES = [
    ("eula.md", "legal/eula.html"),
    ("privacy-policy.md", "legal/privacy.html"),
    ("terms-of-sale.md", "legal/terms-of-sale.html"),
    ("refund-policy.md", "legal/refunds.html"),
    ("vulnerability-disclosure.md", "legal/vulnerability-disclosure.html"),
]

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


def build(strict: bool) -> int:
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
    for rel, meta, body in pages:
        depth = rel.count("/")
        # 404.html is served at any missing path, so it needs absolute URLs.
        root = "/" if rel == "404.html" else "../" * depth
        nav = []
        # The checkout joins the menu once Pro is on sale.
        for href, label in NAV + ([("buy.html", "Buy Pro")] if config.get("BUY_URL") else []):
            current = ' aria-current="page"' if rel == href else ""
            nav.append(f'<li><a href="{root}{href}"{current}>{label}</a></li>')
        title = meta.get("title", "LocalGateKeys")
        full_title = "LocalGateKeys" if rel == "index.html" else f"{title} | LocalGateKeys"
        doc = (
            layout.replace("[[title]]", html.escape(full_title))
            .replace("[[description]]", html.escape(meta.get("description", "")))
            .replace("[[path]]", "" if rel == "index.html" else rel.removesuffix(".html"))
            .replace("[[nav]]", "\n          ".join(nav))
            .replace("[[body_class]]", meta.get("body_class", "page"))
            .replace("[[referrer]]", meta.get("referrer", "no-referrer"))
            .replace("[[content]]", body.strip())
            .replace("[[root]]", root)
        )
        doc = doc.replace("[[root]]", root)
        doc = resolve_ifs(doc, config)
        doc = fill(doc, config, missing, rel)
        target = OUT / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(doc, encoding="utf-8", newline="\n")

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

    print(f"Built {len(pages)} pages into {OUT.relative_to(REPO)}")
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


def _static_sub(m: re.Match, config: dict, missing: dict[str, set], rel: str) -> str:
    v = config.get(m.group(1))
    if isinstance(v, str) and v.strip():
        return PLACEHOLDER.sub(lambda inner: _static_sub(inner, config, missing, rel), v)
    missing.setdefault(m.group(1), set()).add(rel)
    return m.group(0)


if __name__ == "__main__":
    sys.exit(build(strict="--strict" in sys.argv[1:]))
