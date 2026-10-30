"""Pseudo-locale (en-XA): accented, padded text that exposes hard-coded strings and clipping.

Run ``python scripts/i18n_pseudo.py`` to regenerate src/localvault/assets/i18n/en-XA.json.
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

DEFAULT_DIR = Path(__file__).resolve().parents[1] / "src" / "localvault" / "assets" / "i18n"

_MAP = str.maketrans(
    "AEIOUYaeiouycnCNsSzZ",
    "ÅÉÎÕÜÝåéîõüýçñÇÑšŠžŽ",
)
_PLACEHOLDER = re.compile(r"(\{[^{}]*\})")


def pseudo(text: str) -> str:
    parts = _PLACEHOLDER.split(text)
    out = "".join(p if i % 2 else p.translate(_MAP) for i, p in enumerate(parts))
    pad = max(1, round(len(text) * 0.4))
    return out + "~" * pad


def pseudo_catalog(cat: dict) -> dict:
    out: dict = {}
    for key, value in cat.items():
        if isinstance(value, dict):
            out[key] = {c: pseudo(v) for c, v in value.items()}
        else:
            out[key] = pseudo(value)
    return out


def render(catalog_dir: Path = DEFAULT_DIR) -> str:
    en = json.loads((catalog_dir / "en.json").read_text(encoding="utf-8"))
    return json.dumps(pseudo_catalog(en), ensure_ascii=False, indent=2, sort_keys=True) + "\n"


def main() -> int:
    path = DEFAULT_DIR / "en-XA.json"
    with open(path, "w", encoding="utf-8", newline="\n") as f:
        f.write(render())
    print(f"wrote {path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
