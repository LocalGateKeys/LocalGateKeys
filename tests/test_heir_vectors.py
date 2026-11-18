"""The committed emergency access vectors (tests/vectors/heir/v1.json) are what the desktop writes today.

The phone cores (lgk-core, LGKCore) re-make these files byte for byte and read them, so a change to the desktop's
formats shows up here first: regenerate with ``python tests/vectors/heir/generate.py`` only on purpose.
"""
from __future__ import annotations

import importlib.util
import json
from pathlib import Path

from localvault import heir, heir_flow

VECTORS = Path(__file__).resolve().parent / "vectors" / "heir"


def _generator():
    spec = importlib.util.spec_from_file_location("heir_vectors_generate", VECTORS / "generate.py")
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def test_committed_vectors_match_the_desktop() -> None:
    committed = (VECTORS / "v1.json").read_text(encoding="utf-8")
    assert committed == _generator().render()


def test_the_desktop_reads_the_vector_files() -> None:
    data = json.loads((VECTORS / "v1.json").read_text(encoding="utf-8"))
    packages = [p.encode("utf-8") for p in data["packages"]]
    assert heir.combine_packages(packages[1:]).hex() == data["entropy"]
    assert heir_flow._open(data["request"]["data"].encode(), heir_flow.REQUEST_KIND,
                           heir_flow._REQUEST_FIELDS) is not None
    assert heir_flow._open(data["deny"]["data"].encode(), heir_flow.DENY_KIND, heir_flow._DENY_FIELDS) is not None
    assert heir_flow._open(data["descriptor"]["data"].encode(), heir_flow.BACKUP_KIND,
                           heir_flow._BACKUP_FIELDS) is not None
    for case in data["refused"]:
        try:
            heir.read_package(case["package"].encode("utf-8"))
        except heir.HeirError as exc:
            assert exc.reason == case["reason"], case["name"]
        else:
            raise AssertionError(case["name"])
