"""Backup key vectors (tests/vectors/backup/v3): the generator must reproduce them byte for byte.

``scripts/gen_mac_backup_vectors.py backup_v3`` writes ``key.json``, ``wrap.json``, ``record.json`` and
``authority.json``; ``test_backup_key.py`` checks their values against independent reference code.  Design section
12.1: no wall clock reaches a vector, so the bytes are the same in any time zone and at any time of day, which the
subprocess runs below check with ``TZ`` at UTC+14 and UTC-12 (for the v2 full-backup generator too, the flake that
section 12.1 names).
"""

from __future__ import annotations

import importlib.util
import os
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
VEC = ROOT / "tests" / "vectors" / "backup" / "v3"
V2 = ROOT / "tests" / "vectors" / "backup" / "v2"
SCRIPT = ROOT / "scripts" / "gen_mac_backup_vectors.py"
FILES = ("key.json", "wrap.json", "record.json", "authority.json")
#: Step 2a: the v3 container, its re-lock and the rejected set (``rejected/<name>.lgkfull``).
CONTAINER_FILES = ("full.lgkfull", "relocked.lgkfull", "expected.json")
REJECTED = ("unknown_scheme", "extra_recipient_key", "extra_header_key", "key_id_mismatch", "tampered_recipient_kdf",
            "kdf_out_of_range", "wrapped_short", "epk_low_order", "tampered_core_entry_count", "version_4",
            "manifest_version_2_in_v3", "recipient_from_other_file", "tampered_header", "tampered_member")
GENERATED = (*FILES, *CONTAINER_FILES, *(f"rejected/{name}.lgkfull" for name in REJECTED))
#: POSIX/MSVC ``TZ`` syntax: the sign is inverted, so ``XXX-14`` is UTC+14.
ZONES = {"UTC+14": "XXX-14", "UTC-12": "XXX+12"}


def _generator():
    spec = importlib.util.spec_from_file_location("gen_mac_backup_vectors", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    sys.modules["gen_mac_backup_vectors"] = module
    spec.loader.exec_module(module)
    return module


def test_generator_reproduces_the_committed_v3_vectors(tmp_path: Path) -> None:
    out = tmp_path / "v3"
    _generator().backup_v3_main(out)
    assert sorted(p.relative_to(out).as_posix() for p in out.rglob("*") if p.is_file()) == sorted(GENERATED)
    for name in GENERATED:
        assert (out / name).read_bytes() == (VEC / name).read_bytes(), name


def test_committed_vectors_use_lf_and_end_with_a_newline() -> None:
    for name in (*FILES, "expected.json", "SCHEMA.md"):
        data = (VEC / name).read_bytes()
        assert b"\r" not in data and data.endswith(b"\n"), name


#: Run after the generator: its vaults' rollback and throttle marks went to the in-memory store, never the registry.
_MARKS_STAYED_IN_MEMORY = (
    "from localvault import outside_marks as _marks\n"
    "assert isinstance(_marks.backend(), _marks.MemoryBackend), _marks.backend()\n"
    "assert any(name.startswith('rollback-mark') for name in _marks.backend().values)\n")


def _run_in_zone(zone: str, code: str) -> None:
    env = dict(os.environ, TZ=zone, PYTHONHASHSEED="0")
    env["PYTHONPATH"] = os.pathsep.join([str(ROOT / "src"), env.get("PYTHONPATH", "")])
    assert env.get("LOCALGATEKEYS_OUTSIDE_MARKS") == "memory"  # tests/conftest.py, for every subprocess
    result = subprocess.run([sys.executable, "-c", code + _MARKS_STAYED_IN_MEMORY], env=env, cwd=ROOT,  # noqa: S603
                            capture_output=True, text=True, timeout=300, check=False)
    assert result.returncode == 0, result.stdout + result.stderr


_LOAD = ("import importlib.util, sys; from pathlib import Path\n"
         f"spec = importlib.util.spec_from_file_location('g', {str(SCRIPT)!r})\n"
         "g = importlib.util.module_from_spec(spec); sys.modules['g'] = g; spec.loader.exec_module(g)\n")


@pytest.mark.parametrize("zone", sorted(ZONES))
def test_v3_vectors_do_not_depend_on_the_time_zone(tmp_path: Path, zone: str) -> None:
    out = tmp_path / "v3"
    _run_in_zone(ZONES[zone], _LOAD + f"g.backup_v3_main(Path({str(out)!r}))\n")
    for name in GENERATED:
        assert (out / name).read_bytes() == (VEC / name).read_bytes(), (zone, name)


@pytest.mark.parametrize("zone", sorted(ZONES))
def test_v2_full_backup_generator_does_not_depend_on_the_time_zone(tmp_path: Path, zone: str) -> None:
    """The v2 generator (``backup_main``) under another zone gives the committed bytes (design 12.1)."""
    out = tmp_path / "v2"
    _run_in_zone(ZONES[zone], _LOAD + f"g.backup_main(Path({str(out)!r}))\n")
    deflated = "rejected/deflated.lgkfull"   # zlib builds differ; tests/test_mac_backup_vectors.py compares members
    produced = {p.relative_to(out).as_posix(): p.read_bytes() for p in out.rglob("*") if p.is_file()}
    committed = {p.relative_to(V2).as_posix(): p.read_bytes() for p in V2.rglob("*")
                 if p.is_file() and p.name != "from_mac.lgkfull"}
    assert produced.keys() == committed.keys()
    for name in sorted(committed):
        if name != deflated:
            assert produced[name] == committed[name], (zone, name)


def test_v2_fixture_settings_match_the_current_app_settings() -> None:
    """Diagnosis for the v2 generator test: the fixture's ``settings.json`` holds every ``AppSettings`` field.

    The "near midnight" failures of ``test_generator_reproduces_the_committed_vectors`` on 2026-10-31 were runs
    made while new settings (``hide_from_capture``, ``erase_on_sync_removal``) had landed and the v2 vectors were
    not yet regenerated (commits f5e55f54 and 4b722d1a at 00:04 and 00:09); no clock value reaches the generator.
    When this fails, a settings field changed: run ``gen_mac_backup_vectors.py backup`` and ``kit``.
    """
    from localvault.backup import _full_canonical, _full_validate_settings
    expected = _full_canonical(_full_validate_settings({"auto_lock_seconds": 600, "clipboard_clear_seconds": 20}))
    assert (V2 / "inputs" / "settings.json").read_bytes() == expected, (
        "AppSettings changed since tests/vectors/backup/v2 was generated: regenerate the backup and kit vectors")
