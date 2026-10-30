from __future__ import annotations

import os
import shutil
import stat
import sys
import time
import uuid
from collections.abc import Iterator
from pathlib import Path

import pytest

# All workspace-local temporary directories live under one ignored root so that
# a crashed run leaves exactly one directory to delete and so that nothing else
# in the repository is littered.  The path is ABSOLUTE: several production code
# paths (for example install-root checks) deliberately
# reject relative install roots, and a relative fixture path made those tests
# fail for the wrong reason.
REPO_ROOT = Path(__file__).resolve().parents[1]
PYTEST_TMP_ROOT = REPO_ROOT / ".pytest-tmp"

_RMTREE_ATTEMPTS = 6
_RMTREE_DELAY_SECONDS = 0.15


def _clear_readonly(func, path, _exc_info) -> None:  # type: ignore[no-untyped-def]
    """Windows marks some generated files read-only; retry the removal writable."""
    try:
        os.chmod(path, stat.S_IWRITE)
        func(path)
    except OSError:
        pass


def _rmtree_with_retries(path: Path) -> None:
    """Remove ``path``; tolerate transient Windows sharing violations.

    Antivirus scanners, the indexer, and just-closed file handles can hold a
    file for a moment after a test finishes.  Retry briefly before giving up;
    a leftover directory is harmless because the whole root is gitignored.
    """
    for attempt in range(_RMTREE_ATTEMPTS):
        try:
            if sys.version_info >= (3, 12):
                shutil.rmtree(path, onexc=_clear_readonly)
            else:  # pragma: no cover - 3.11 only
                shutil.rmtree(path, onerror=_clear_readonly)
        except FileNotFoundError:
            return
        except OSError:
            if attempt == _RMTREE_ATTEMPTS - 1:
                return
            time.sleep(_RMTREE_DELAY_SECONDS * (attempt + 1))
            continue
        if not path.exists():
            return
        time.sleep(_RMTREE_DELAY_SECONDS * (attempt + 1))


def _new_workspace_tmp_dir() -> Path:
    root = PYTEST_TMP_ROOT / uuid.uuid4().hex
    root.mkdir(parents=True)
    return root


@pytest.fixture
def workspace_tmp() -> Iterator[Path]:
    """Workspace-local temporary root for Windows ACL constrained runners."""
    root = _new_workspace_tmp_dir()
    try:
        yield root
    finally:
        _rmtree_with_retries(root)


@pytest.fixture
def tmp_path() -> Iterator[Path]:
    """Use a workspace-local temp root instead of the managed system temp.

    The Windows validation image denies directory enumeration under the
    default ``%TEMP%/pytest-of-*`` location.  Keeping the fixture inside the
    repository matches ``workspace_tmp`` and lets tests exercise their real
    filesystem behavior without depending on that ACL.  The directory is an
    absolute path under ``<repo>/.pytest-tmp/<uuid>``.
    """
    root = _new_workspace_tmp_dir()
    try:
        yield root
    finally:
        _rmtree_with_retries(root)


_SCREEN_SIZE: tuple[int, int] | None = None


def _screen_size() -> tuple[int, int]:
    """Primary screen size in pixels, measured once with a withdrawn Tk root."""
    global _SCREEN_SIZE
    if _SCREEN_SIZE is None:
        import tkinter as tk

        root = tk.Tk()
        try:
            root.withdraw()
            _SCREEN_SIZE = (int(root.winfo_screenwidth()), int(root.winfo_screenheight()))
        finally:
            root.destroy()
    return _SCREEN_SIZE


def pytest_runtest_setup(item: pytest.Item) -> None:
    # Geometry tests size real windows (1492x800 and similar).  On a smaller
    # screen, such as a 1024x768 CI runner, Windows clamps the window and every
    # layout assertion measures the clamp instead of the layout.
    marker = item.get_closest_marker("min_screen")
    if marker is None:
        return
    width, height = marker.args
    actual = _screen_size()
    if actual[0] < width or actual[1] < height:
        pytest.skip(f"needs a screen of at least {width}x{height}; this one is {actual[0]}x{actual[1]}")


# Hosted Windows runners occasionally fail to read Tcl/Tk's own library scripts
# while creating a Tk root ("Can't find a usable tk.tcl/init.tcl", "invalid
# command name tcl_findLibrary") even though the files exist and the next root
# loads them fine.  Retry only that failure; every other TclError is raised.
_TCL_LIBRARY_FLAKES = ("Can't find a usable", "tcl_findLibrary")
_TK_CREATE_ATTEMPTS = 3


def _retry_tcl_library_flakes(create):  # type: ignore[no-untyped-def]
    def wrapper(*args, **kwargs):  # type: ignore[no-untyped-def]
        import tkinter

        for attempt in range(_TK_CREATE_ATTEMPTS):
            try:
                return create(*args, **kwargs)
            except tkinter.TclError as exc:
                if attempt == _TK_CREATE_ATTEMPTS - 1 or not any(
                    marker in str(exc) for marker in _TCL_LIBRARY_FLAKES
                ):
                    raise
                time.sleep(0.2 * (attempt + 1))
        raise AssertionError("unreachable")

    return wrapper


def pytest_configure(config: pytest.Config) -> None:
    try:
        import tkinter
    except ImportError:  # pragma: no cover - Python built without Tk
        return
    tkinter.Tk.__init__ = _retry_tcl_library_flakes(tkinter.Tk.__init__)  # type: ignore[method-assign]


@pytest.fixture(autouse=True)
def _isolated_localgatekeys_data_dir(monkeypatch, tmp_path_factory):
    """Never let a test read or write the owner's real data folder.

    ``config.data_dir()`` honours ``LOCALGATEKEYS_DATA_DIR`` on every call, so
    settings.json, profiles and logs land in a per-test temporary folder. A
    test that sets its own folder still wins (monkeypatch later in the test).
    """
    monkeypatch.setenv("LOCALGATEKEYS_DATA_DIR", str(tmp_path_factory.mktemp("lgk-data")))
    monkeypatch.setenv("LOCALGATEKEYS_LANG", "en")


@pytest.fixture(autouse=True)
def _pro_features_on_by_default(request, monkeypatch):
    """Pro-only features (sync, two-factor codes, attachments) are on in tests.

    Tests run without a licence, so the free plan's 4-item limit still applies
    as before; only the Pro-only features are switched on, so suites about
    those features keep testing them.  Mark a test ``free_features`` to see the
    real free plan, where adding or changing them is refused.
    """
    if request.node.get_closest_marker("free_features"):
        return
    from localvault import licensing

    everything = frozenset(feature.value for feature in licensing.Feature)
    monkeypatch.setattr(licensing, "pro_features", lambda st=None: everything)
