"""The test run never reads or writes the real registry store of ``outside_marks`` (HKCU on Windows).

In this process tests/conftest.py installs a ``MemoryBackend`` per test and traps any use of ``WindowsRegistry``;
processes the tests start inherit ``LOCALGATEKEYS_OUTSIDE_MARKS=memory``; and the test-only scripts that create
vaults install the in-memory store themselves, whatever entry point runs.  Nothing here touches the registry: the
subprocesses below only import modules and report which store they would use.
"""
from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

from localvault import outside_marks

ROOT = Path(__file__).resolve().parents[1]


def _python(code: str, *, inherit_memory_env: bool) -> str:
    env = dict(os.environ)
    if not inherit_memory_env:
        env.pop(outside_marks.MEMORY_ENV, None)
    env["PYTHONPATH"] = os.pathsep.join([str(ROOT / "src"), env.get("PYTHONPATH", "")])
    result = subprocess.run([sys.executable, "-c", code], env=env, cwd=ROOT, capture_output=True, text=True,  # noqa: S603
                            timeout=120, check=False)
    assert result.returncode == 0, result.stdout + result.stderr
    return result.stdout.strip().splitlines()[-1]


def test_a_test_that_reaches_the_real_registry_store_is_caught(outside_marks_store) -> None:
    trapped = outside_marks_store.real_registry_calls
    with pytest.raises(OSError):
        outside_marks.WindowsRegistry().write("rollback-mark-guard", "x")
    previous = outside_marks.set_backend(outside_marks.WindowsRegistry())
    try:
        assert outside_marks.write("rollback-mark-guard", "x") is False  # refused, as an unreachable store
        with pytest.raises(OSError):
            outside_marks.read("rollback-mark-guard")
    finally:
        outside_marks.set_backend(previous)
    assert trapped == ["write rollback-mark-guard", "write rollback-mark-guard", "read rollback-mark-guard"]
    trapped.clear()  # this test only checks the guard; any other test that reaches the store fails


def test_processes_the_tests_start_use_the_memory_store() -> None:
    assert os.environ.get(outside_marks.MEMORY_ENV) == "memory"
    code = "from localvault import outside_marks as m; print(type(m.backend()).__name__)"
    assert _python(code, inherit_memory_env=True) == "MemoryBackend"


def test_only_the_explicit_value_switches_the_store() -> None:
    code = ("import os; os.environ['LOCALGATEKEYS_OUTSIDE_MARKS'] = 'Memory '\n"
            "from localvault import outside_marks as m; print(type(m.backend()).__name__)")
    expected = "WindowsRegistry" if sys.platform == "win32" else "NoneType"
    assert _python(code, inherit_memory_env=False) == expected  # constructed only; nothing is read or written


@pytest.mark.parametrize("script", ["gen_mac_backup_vectors.py", "android_live_peer.py"])
def test_the_vault_making_scripts_use_the_memory_store_on_their_own(script: str) -> None:
    """Run by hand (no test environment), each script's vaults keep their marks in memory, whichever entry
    point is used: the store is installed when the script is loaded."""
    code = ("import importlib.util, sys\n"
            f"spec = importlib.util.spec_from_file_location('script', {str(ROOT / 'scripts' / script)!r})\n"
            "module = importlib.util.module_from_spec(spec); sys.modules['script'] = module\n"
            "spec.loader.exec_module(module)\n"
            "from localvault import outside_marks as m; print(type(m.backend()).__name__)")
    assert _python(code, inherit_memory_env=False) == "MemoryBackend"

def test_the_memory_variable_is_ignored_in_a_packaged_build(monkeypatch) -> None:
    """The shipped app (frozen) keeps its rollback marks whatever the environment says."""
    monkeypatch.setenv(outside_marks.MEMORY_ENV, "memory")
    assert isinstance(outside_marks._default_backend(), outside_marks.MemoryBackend)  # from source: honoured
    monkeypatch.setattr(sys, "frozen", True, raising=False)
    chosen = outside_marks._default_backend()
    if sys.platform == "win32":
        assert isinstance(chosen, outside_marks.WindowsRegistry)  # built only; nothing is read or written here
    else:
        assert chosen is None
