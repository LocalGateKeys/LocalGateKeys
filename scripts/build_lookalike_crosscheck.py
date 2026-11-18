"""Build tests/vectors/lookalike/crosscheck.json, the lookalike cross-check corpus.

Every origin in tests/vectors/lookalike/cases.json plus the edge hosts below is classified by
src/localvault/lookalike.py against each saved origin of the vectors on its own ("pairs") and against all of
them at once ("lists"). Python, the extension (lookalike.js), Kotlin (lgk-core) and Swift (LGKCore) must give
the same kind, matched and reason on every row; the four test suites read this file.

Run from the repository root:
    PYTHONPATH=src python scripts/build_lookalike_crosscheck.py          # write the file
    PYTHONPATH=src python scripts/build_lookalike_crosscheck.py --check  # exit 1 when stale
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CASES = ROOT / "tests" / "vectors" / "lookalike" / "cases.json"
OUT = ROOT / "tests" / "vectors" / "lookalike" / "crosscheck.json"

# Hosts the vectors do not name: scripts, bidi, joiners, IDNA validity, ports, IPs and odd URL shapes.
EDGE_ORIGINS = [
    "https://APPLE.COM", "https://apple.com.", "https://www.apple.com:443", "http://apple.com:80",
    "https://apple.com:8443", "https://apple.co", "https://apple.co.uk", "https://appl.com", "https://applee.com",
    "https://pple.com", "https://aple.com", "https://paypa1.com", "https://paypaI.com", "https://rnicrosoft.com",
    "https://micros0ft.com", "https://xn--80ak6aa92e.com", "https://xn--pple-43d.com", "https://аррӏе.com",
    "https://ехаmple.com", "https://εxample.com", "https://exаmple.co.uk", "https://éxample.com",
    "https://éxample.com", "https://xn--e-ufa.com", "https://xn--a.com", "https://xn--zz.com",
    "https://xn--.com", "https://xn--bcher-kva.de", "https://BÜCHER.de", "https://bücher.de.", "https://עברית.com",
    "https://xn--5dbqzzl.com", "https://aא.com", "https://אa.com", "https://1א.com",
    "https://א1.com", "https://عربي.com", "https://xn--ngbrx.com", "https://a١۱.com",
    "https://a‍b.com", "https://a‌b.com", "https://क्‍ष.com", "https://ｅｘａｍｐｌｅ.com",
    "https://日本.jp", "https://カタカナabc.jp", "https://ひらがな漢字.jp", "https://한국어.kr", "https://中文abc.cn",
    "https://ελληνικά.gr", "https://рф.рф", "https://пример.рф", "https://ex--ample.com", "https://-example.com",
    "https://example-.com", "https://a..com", "https://exa_mple.com", "https://192.168.1.11", "https://10.0.0.1",
    "https://[::1]", "https://[2001:db8::1]:8443", "http://localhost", "http://localhost:3000", "https://user.github.io",
    "https://other.github.io", "https://user.github.io.evil.com", "https://example.com.evil.com",
    "https://evil-example.com", "https://example-login.com", "https://login-example.co.uk", "https://shop.www.ck",
    "https://city.kawasaki.jp", "https://x.kawasaki.jp", "https://site.web.core.windows.net", "file:///etc/passwd",
    "chrome-extension://abcdefghijklmnop", "about:blank", "https://", "", "https://a:99999",
    "https://" + "a" * 64 + ".com", "https://" + "b" * 63 + ".com",
]

# Hosts where the extension differs from Python, Kotlin and Swift (found by this corpus, open for a ruling).
# lookalike.js trusts the WHATWG URL parser, which here accepts what IDNA 2008 refuses: a 64-letter label and an
# RTL letter in a left-to-right label (RFC 5893 rule 5). Python says invalid-origin; the extension says
# no-match, or mixed-script for "a" + Hebrew. The extension test checks these still differ and skips them.
JS_DIFFERS = ["https://a\u05d0.com", "https://1\u05d0.com", "https://" + "a" * 64 + ".com"]


def build() -> str:
    from localvault.lookalike import (
        classify as shield,  # the phishing shield: "related" only for the same host
    )
    from localvault.lookalike import (
        match as classify,  # the shared algorithm; classify() narrows "related" on desktop
    )

    cases = json.loads(CASES.read_text(encoding="utf-8"))["cases"]
    origins: list[str] = []
    saved: list[str] = []
    for case in cases:
        if case["origin"] not in origins:
            origins.append(case["origin"])
        for item in case["saved"]:
            if item not in saved:
                saved.append(item)
    for origin in EDGE_ORIGINS:
        if origin not in origins:
            origins.append(origin)

    def row(verdict, index: int) -> list:
        return [verdict.kind, index if verdict.matched is not None else -1, verdict.reason]

    pairs = []
    shield_pairs = []
    for o, origin in enumerate(origins):
        for s, item in enumerate(saved):
            verdict = classify(origin, [item])
            assert verdict.matched in (None, item)
            pairs.append([o, s, *row(verdict, s)])
            narrowed = shield(origin, [item])
            if narrowed != verdict:
                shield_pairs.append([o, s, *row(narrowed, s)])
    lists = []
    shield_lists = []
    for o, origin in enumerate(origins):
        verdict = classify(origin, saved)
        lists.append([o, *row(verdict, saved.index(verdict.matched) if verdict.matched is not None else -1)])
        narrowed = shield(origin, saved)
        shield_lists.append([o, *row(narrowed, saved.index(narrowed.matched) if narrowed.matched is not None
                                     else -1)])
    doc = {
        "version": 1,
        "about": ("Generated by scripts/build_lookalike_crosscheck.py from src/localvault/lookalike.py. pairs: "
                  "[origin index, saved index, kind, matched saved index or -1, reason] for classify(origin, "
                  "[saved]); lists: [origin index, kind, matched saved index or -1, reason] for classify(origin, "
                  "all saved). shield_pairs: the pairs whose phishing-shield verdict (lookalike.classify, which "
                  "keeps related for the same host or its www twin) differs, same layout; shield_lists: the shield "
                  "verdict against all saved, same layout as lists."),
        "origins": origins,
        "saved": saved,
        "pairs": pairs,
        "lists": lists,
        "shield_pairs": shield_pairs,
        "shield_lists": shield_lists,
    }
    lines = ["{"]
    doc["js_differs"] = JS_DIFFERS
    for key in ("version", "about", "js_differs", "origins", "saved"):
        lines.append(f"  {json.dumps(key)}: {json.dumps(doc[key], ensure_ascii=False)},")
    for key, last in (("pairs", False), ("lists", False), ("shield_pairs", False), ("shield_lists", True)):
        rows = ",\n".join("    " + json.dumps(r, ensure_ascii=False, separators=(",", ":")) for r in doc[key])
        lines.append(f'  "{key}": [\n{rows}\n  ]' + ("" if last else ","))
    lines.append("}")
    return "\n".join(lines) + "\n"


def main(argv: list[str]) -> int:
    text = build()
    if "--check" in argv:
        if not OUT.is_file() or OUT.read_text(encoding="utf-8") != text:
            print(f"{OUT} is stale: run scripts/build_lookalike_crosscheck.py", file=sys.stderr)
            return 1
        print(f"{OUT} is up to date")
        return 0
    OUT.write_bytes(text.encode("utf-8"))
    print(f"wrote {OUT}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
