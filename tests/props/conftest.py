"""Shared setup for the Hypothesis property suites (security audit 2026-10-24).

* Data folder: ``tests/conftest.py`` already points ``LOCALGATEKEYS_DATA_DIR`` at a
  per-test temporary folder (autouse), so these suites never see the owner's
  real profile; nothing is duplicated here.
* Budget: small by default so the normal suite stays fast.
  ``LGK_PROP_EXAMPLES`` (default 100) sets the examples per property;
  KDF-bound properties use ``LGK_PROP_SLOW_EXAMPLES`` (default 20).  A deep
  run: ``LGK_PROP_EXAMPLES=5000 LGK_PROP_SLOW_EXAMPLES=400 pytest tests/props``.
* Hypothesis keeps its own files (unicode tables, constants cache) under the
  ignored ``.pytest-tmp/hypothesis`` folder, never in ``.hypothesis`` in the
  checkout, and no example database is written.
* ``write_audit`` records every file opened for writing / renamed / removed
  outside the test's temporary folders.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest
from hypothesis import HealthCheck, settings
from hypothesis.configuration import set_hypothesis_home_dir

HYPOTHESIS_HOME = Path(__file__).resolve().parents[2] / ".pytest-tmp" / "hypothesis"
set_hypothesis_home_dir(HYPOTHESIS_HOME)

FAST = int(os.environ.get("LGK_PROP_EXAMPLES", "100"))
SLOW = int(os.environ.get("LGK_PROP_SLOW_EXAMPLES", "20"))

settings.register_profile(
    "lgk-props", max_examples=FAST, deadline=None, derandomize=False, print_blob=True, database=None,
    suppress_health_check=[HealthCheck.too_slow, HealthCheck.data_too_large, HealthCheck.filter_too_much,
                           HealthCheck.function_scoped_fixture],
)
settings.load_profile("lgk-props")


class _WriteAudit:
    def __init__(self) -> None:
        self.allowed: list[str] = []
        self.violations: list[tuple[str, str]] = []
        self.active = False

    def _ok(self, path: object) -> bool:
        try:
            text = os.path.abspath(os.fsdecode(path)).lower()
        except Exception:  # noqa: BLE001 - fd numbers etc.
            return True
        return any(text.startswith(root) for root in self.allowed)

    def hook(self, event: str, args: tuple) -> None:
        if not self.active:
            return
        if event == "open":
            path, mode, flags = args[0], args[1], args[2]
            writing = (isinstance(mode, str) and any(c in mode for c in "wax+")) or (
                isinstance(flags, int) and flags & (os.O_WRONLY | os.O_RDWR | os.O_CREAT))
            if writing and isinstance(path, (str, bytes, os.PathLike)) and not self._ok(path):
                self.violations.append((event, os.fsdecode(path)))
        elif event in {"os.rename", "os.replace", "os.remove", "os.unlink", "os.mkdir", "shutil.rmtree", "os.rmdir"}:
            for candidate in args[:2]:
                if isinstance(candidate, (str, bytes, os.PathLike)) and not self._ok(candidate):
                    self.violations.append((event, os.fsdecode(candidate)))


_AUDIT = _WriteAudit()
sys.addaudithook(_AUDIT.hook)  # inert unless a test requests ``write_audit``


@pytest.fixture(scope="session")
def scratch(tmp_path_factory) -> Path:
    return tmp_path_factory.mktemp("props")


@pytest.fixture
def write_audit(scratch):
    # The per-test data folder set by tests/conftest.py, this session's scratch folder, Hypothesis' own files.
    roots = [os.path.abspath(path).lower() for path in (os.environ["LOCALGATEKEYS_DATA_DIR"], scratch, HYPOTHESIS_HOME)]
    _AUDIT.allowed = roots
    _AUDIT.violations = []
    _AUDIT.active = True
    try:
        yield _AUDIT
    finally:
        _AUDIT.active = False
