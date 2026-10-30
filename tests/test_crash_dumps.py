from __future__ import annotations

from localvault import crash_dumps as cd


class _Fn:
    def __init__(self, result=0):
        self.calls, self.result = [], result
        self.argtypes = self.restype = None

    def __call__(self, *args):
        self.calls.append(args)
        return self.result


def _windows(monkeypatch, wer=None, set_mode=None, error=None):
    class Wer:
        WerAddExcludedApplication = wer

    class Kernel32:
        SetErrorMode = set_mode

    class Windll:
        kernel32 = Kernel32()

    def win_dll(name):
        if error:
            raise error
        assert name == "wer"
        return Wer()

    monkeypatch.setattr(cd.os, "name", "nt")
    monkeypatch.setattr(cd.ctypes, "WinDLL", win_dll, raising=False)
    monkeypatch.setattr(cd.ctypes, "windll", Windll(), raising=False)


def test_excludes_the_program_from_error_reporting(monkeypatch):
    wer = _Fn(0)
    _windows(monkeypatch, wer=wer)
    assert cd.exclude_from_error_reporting("LocalGateKeys.exe")
    assert wer.calls == [("LocalGateKeys.exe", 0)]


def test_a_failed_hresult_is_reported_not_raised(monkeypatch):
    _windows(monkeypatch, wer=_Fn(-2147024891))
    assert not cd.exclude_from_error_reporting("LocalGateKeys.exe")


def test_error_mode_keeps_the_existing_flags(monkeypatch):
    results = iter([0x8000, 0])  # SEM_NOOPENFILEERRORBOX already set

    class Mode(_Fn):
        def __call__(self, *args):
            self.calls.append(args)
            return next(results)

    mode = Mode()
    _windows(monkeypatch, set_mode=mode)
    assert cd.suppress_fault_dialogs()
    assert mode.calls == [(0,), (0x8000 | 0x1 | 0x2,)]


def test_disable_never_raises_even_when_wer_is_missing(monkeypatch):
    _windows(monkeypatch, wer=_Fn(), set_mode=_Fn(), error=OSError("no wer.dll"))
    cd.disable_crash_dumps()
    assert not cd.exclude_from_error_reporting()


def test_no_ops_off_windows(monkeypatch):
    monkeypatch.setattr(cd.os, "name", "posix")
    assert not cd.exclude_from_error_reporting()
    assert not cd.suppress_fault_dialogs()
    cd.disable_crash_dumps()
