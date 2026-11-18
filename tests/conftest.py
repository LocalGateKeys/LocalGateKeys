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
    # Marks kept outside the vault folder (outside_marks: HKCU on Windows) go to an in-memory store in this
    # process and in every process the tests start (they inherit the environment): never the real registry.
    os.environ["LOCALGATEKEYS_OUTSIDE_MARKS"] = "memory"
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
def _no_real_browser_registry(monkeypatch):
    """Never let a test write or delete the owner's real native-messaging keys (HKCU ...\\NativeMessagingHosts).

    A test that needs these calls stubs them itself (monkeypatch later in the test wins)."""
    from localvault import browser_bridge

    def refuse(*_args, **_kwargs):
        raise AssertionError("a test tried to change the real registry; stub it with monkeypatch or a fake winreg")

    # Writes through the real winreg module and reg.exe started outside the package. Tests that inject a fake
    # winreg (sys.modules) are unaffected.
    monkeypatch.setattr(browser_bridge, "_run_reg_outside_package", refuse)
    try:
        import winreg
    except ImportError:
        return
    for name in ("SetValueEx", "SetValue", "DeleteKey", "DeleteKeyEx", "DeleteValue"):
        if hasattr(winreg, name):
            monkeypatch.setattr(winreg, name, refuse)


@pytest.fixture(autouse=True)
def outside_marks_store(monkeypatch):
    """Never let a test read or write the owner's registry: marks kept outside the vault folder
    (unlock-throttle high-water mark, duress hold copy, rollback marks) go to a fresh in-memory store per test.

    Guard: any use of the real ``WindowsRegistry`` store in a test is refused (OSError, which the callers treat as
    an unreachable store) and fails that test; ``store.real_registry_calls`` lists them.  Subprocesses get the
    in-memory store through ``LOCALGATEKEYS_OUTSIDE_MARKS`` (``pytest_configure``)."""
    from localvault import outside_marks

    store = outside_marks.MemoryBackend()
    trapped: list[str] = []
    store.real_registry_calls = trapped  # type: ignore[attr-defined]

    def refuse(operation: str):  # type: ignore[no-untyped-def]
        def method(self, name, *_args):  # type: ignore[no-untyped-def]
            trapped.append(f"{operation} {name}")
            raise OSError("the tests never touch the real registry")
        return method

    for operation in ("read", "write", "delete"):
        monkeypatch.setattr(outside_marks.WindowsRegistry, operation, refuse(operation))
    previous = outside_marks.set_backend(store)
    try:
        yield store
    finally:
        outside_marks.set_backend(previous)
    assert not trapped, f"a test reached the real registry store: {trapped}"


@pytest.fixture(autouse=True)
def _no_kdf_upgrade_on_unlock(request, monkeypatch):
    """Test vaults use an 8 MiB KDF on purpose; the app's password unlock would upgrade them to 256 MiB.

    Mark a test (or module) ``kdf_upgrade`` to run the real upgrade.
    """
    if request.node.get_closest_marker("kdf_upgrade"):
        return
    from localvault import vault

    monkeypatch.setattr(vault.VaultSession, "_upgrade_kdf_on_unlock", lambda _self, _password, *_factor_secrets: None)


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


@pytest.fixture(autouse=True)
def _fresh_windows_passkey_registration(monkeypatch):
    """Each test starts with no cached Windows provider state; no ``--state`` thread or refresh timer starts.

    The cache is process-wide (``windows_passkey_provider.REGISTRATION``); without this a test that reconciles to
    "enabled" would make a later broker test answer ``system_provider``.
    """
    from localvault import windows_passkey_provider

    monkeypatch.setattr(windows_passkey_provider, "REGISTRATION",
                        windows_passkey_provider.RegistrationState(spawn=lambda _work: None))
    monkeypatch.setattr(windows_passkey_provider, "_start_ticker", lambda _tick: None)


@pytest.fixture(autouse=True)
def _reset_ui_language() -> Iterator[None]:
    """A test that selects a language (or en-XA through LOCALGATEKEYS_LANG) must
    not leak it: later tests compare English messages."""
    from localvault import i18n

    before = i18n._current
    yield
    i18n._current = before