"""Build browser-extension/psl-min.json from the bundled Public Suffix List.

The extension's lookalike classifier (browser-extension/lookalike.js) needs
the same registrable-domain rules as src/localvault/lookalike.py.  This script
reads src/localvault/assets/public_suffix_list.dat (plus the app's local
additions in localvault.origin), keeps the rules in IDNA A-label form and
drops single-label rules such as ``com``: the PSL default rule ``*`` already
makes the last label the suffix, so they never change a result.  Normal rules
are grouped by their last label to keep the file small:
``"normal": {"uk": "co ac ...", ...}`` stands for ``co.uk``, ``ac.uk``, ....

Run from the repository root:
    PYTHONPATH=src python scripts/build_psl.py          # write the file
    PYTHONPATH=src python scripts/build_psl.py --check  # exit 1 when stale
No network access: the list is the bundled copy.
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from localvault import origin  # noqa: E402

OUT = ROOT / "browser-extension" / "psl-min.json"
_VERSION = re.compile(r"^// VERSION: (\S+)", re.MULTILINE)


def build() -> str:
    text = origin.PUBLIC_SUFFIX_LIST_PATH.read_text(encoding="utf-8")
    match = _VERSION.search(text)
    rules = origin.parse_suffix_rules(text.splitlines())
    local = origin.parse_suffix_rules(origin._LOCAL_SUFFIX_RULES)
    grouped: dict[str, list[str]] = {}
    for rule in sorted(r for r in rules.normal | local.normal if "." in r):
        head, _dot, last = rule.rpartition(".")
        grouped.setdefault(last, []).append(head)
    data = {
        "source": "https://publicsuffix.org/list/public_suffix_list.dat",
        "version": match.group(1) if match else "unknown",
        "licence": "MPL-2.0",
        "normal": {last: " ".join(heads) for last, heads in sorted(grouped.items())},
        "wildcard": sorted(rules.wildcard | local.wildcard),
        "exception": sorted(rules.exception | local.exception),
    }
    return json.dumps(data, ensure_ascii=True, separators=(",", ":")) + "\n"


def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    content = build()
    if "--check" in args:
        current = OUT.read_text(encoding="utf-8") if OUT.exists() else ""
        if current != content:
            print(f"{OUT} is stale; run scripts/build_psl.py", file=sys.stderr)
            return 1
        return 0
    OUT.write_bytes(content.encode("ascii"))
    print(f"wrote {OUT} ({len(content)} bytes)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
