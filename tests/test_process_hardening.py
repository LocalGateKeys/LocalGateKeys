from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

from localvault import process_hardening as ph

ROOT = Path(__file__).resolve().parents[1]


class _Fn:
    def __init__(self, result, calls, name):
        self.result, self.calls, self.name = result, calls, name
        self.argtypes = self.restype = None

    def __call__(self, *args):
        self.calls.append((self.name, args))
        if isinstance(self.result, Exception):
            raise self.result
        return self.result


class _Kernel32:
    def __init__(self, default=1, policy=1):
        self.calls: list = []
        self.SetDefaultDllDirectories = _Fn(default, self.calls, "SetDefaultDllDirectories")
        self.SetProcessMitigationPolicy = _Fn(policy, self.calls, "SetProcessMitigationPolicy")


def test_no_op_off_windows(monkeypatch) -> None:
    monkeypatch.setattr(ph, "_kernel32", lambda: pytest.fail("kernel32 must not load"))
    result = ph.harden_process(platform="linux")
    assert result.ok and result.applied == []
    assert ph.image_load_policy(platform="darwin") is None
    assert ph.check_hardened(result, platform="linux") is None


def test_applies_both_policies_with_the_expected_flags(monkeypatch) -> None:
    kernel32 = _Kernel32()
    monkeypatch.setattr(ph, "_kernel32", lambda: kernel32)
    result = ph.harden_process(platform="win32")
    assert result.ok
    assert result.applied == ["SetDefaultDllDirectories", "ProcessImageLoadPolicy"]
    name, args = kernel32.calls[0]
    assert name == "SetDefaultDllDirectories" and args == (ph.LOAD_LIBRARY_SEARCH_DEFAULT_DIRS,)
    name, args = kernel32.calls[1]
    assert name == "SetProcessMitigationPolicy" and args[0] == ph.PROCESS_IMAGE_LOAD_POLICY
    assert args[1]._obj.value == ph.IMAGE_LOAD_FLAGS and args[2] == 4


def test_prefer_system32_is_not_requested() -> None:
    # Bundled C++ runtimes must keep winning over older System32 copies.
    assert not ph.IMAGE_LOAD_FLAGS & ph.IMAGE_LOAD_PREFER_SYSTEM32_IMAGES
    assert ph.IMAGE_LOAD_FLAGS == ph.IMAGE_LOAD_NO_REMOTE_IMAGES | ph.IMAGE_LOAD_NO_LOW_MANDATORY_LABEL_IMAGES


def test_failures_are_reported_not_raised(monkeypatch) -> None:
    kernel32 = _Kernel32(default=0, policy=OSError("boom"))
    monkeypatch.setattr(ph, "_kernel32", lambda: kernel32)
    monkeypatch.setattr(ph, "_last_error", lambda: 87)
    result = ph.harden_process(platform="win32")
    assert not result.ok
    assert result.failed == [("SetDefaultDllDirectories", 87), ("ProcessImageLoadPolicy", 0)]
    assert result.describe() == "SetDefaultDllDirectories:winerror=87 ProcessImageLoadPolicy:winerror=0"
    assert "process hardening failed" in ph.check_hardened(result, platform="win32")


def test_missing_kernel32_is_tolerated(monkeypatch) -> None:
    def boom():
        raise OSError("no kernel32")

    monkeypatch.setattr(ph, "_kernel32", boom)
    result = ph.harden_process(platform="win32")
    assert result.failed == [("kernel32", 0)]
    assert ph.image_load_policy(platform="win32") is None


def test_check_reports_a_policy_that_did_not_stick(monkeypatch) -> None:
    monkeypatch.setattr(ph, "image_load_policy", lambda platform=None: 0)
    assert "not in force" in ph.check_hardened(ph.HardeningResult(applied=["x"]), platform="win32")
    monkeypatch.setattr(ph, "image_load_policy", lambda platform=None: ph.IMAGE_LOAD_FLAGS)
    assert ph.check_hardened(ph.HardeningResult(), platform="win32") is None


@pytest.mark.skipif(sys.platform != "win32", reason="Windows loader policy")
def test_real_process_keeps_loading_bundled_extension_modules() -> None:
    # A separate process: the policies cannot be undone once set.
    code = (
        "import sys; sys.path.insert(0, sys.argv[1])\n"
        "from localvault import process_hardening as ph\n"
        "r = ph.harden_process()\n"
        "assert ph.check_hardened(r) is None, ph.check_hardened(r)\n"
        "import ctypes, sqlite3, ssl, win32api, pywintypes\n"
        "print('ok')\n"
    )
    out = subprocess.run([sys.executable, "-c", code, str(ROOT / "src")], capture_output=True, text=True, timeout=60)
    assert out.returncode == 0, out.stderr
    assert out.stdout.strip() == "ok"


def test_both_entry_points_harden_before_heavy_imports() -> None:
    for name in ("lgk_agent_entry.py", "lgk_native_entry.py"):
        text = (ROOT / "build-personal" / name).read_text(encoding="utf-8")
        body = text.split('if __name__ == "__main__":', 1)[1]
        first = min(body.index(call) for call in ("harden_process()", "_harden()") if call in body)
        for heavy in ("localvault.agent", "localvault.build_check", "localvault.native_host"):
            if heavy in body:
                assert first < body.index(heavy), (name, heavy)


def test_native_host_log_is_capped(monkeypatch, tmp_path) -> None:
    from localvault import native_host

    monkeypatch.setenv("LOCALGATEKEYS_DATA_DIR", str(tmp_path))
    monkeypatch.setattr(native_host, "_LOG_MAX_BYTES", 200)
    log = tmp_path / "native-host.log"
    for index in range(40):
        native_host._log(f"event_{index}")
    rotated = tmp_path / "native-host.log.1"
    assert rotated.is_file() and log.is_file()
    assert log.stat().st_size < 200 + 100 and rotated.stat().st_size < 200 + 100
    assert "event_39" in log.read_text(encoding="utf-8")
    assert sorted(p.name for p in tmp_path.iterdir()) == ["native-host.log", "native-host.log.1"]
