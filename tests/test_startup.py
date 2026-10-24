from localvault import startup


def test_source_startup_uses_pythonw_even_without_console_entry_point(monkeypatch, tmp_path) -> None:
    scripts = tmp_path / "Scripts"
    scripts.mkdir()
    pythonw = scripts / "pythonw.exe"
    pythonw.touch()
    monkeypatch.setattr(startup.sys, "frozen", False, raising=False)
    monkeypatch.setattr(startup.sys, "executable", str(scripts / "python.exe"))
    monkeypatch.setattr(startup, "agent_executable", lambda: tmp_path / "agent.py")

    assert startup.startup_command() == f'"{pythonw.resolve()}" -m localvault.agent --background'


def test_frozen_startup_uses_packaged_executable(monkeypatch, tmp_path) -> None:
    executable = tmp_path / "LocalGateKeys.exe"

    def unexpected_agent() -> None:
        raise AssertionError("frozen startup should use its own executable")

    monkeypatch.setattr(startup.sys, "frozen", True, raising=False)
    monkeypatch.setattr(startup.sys, "executable", str(executable))
    monkeypatch.setattr(startup, "agent_executable", unexpected_agent)

    assert startup.startup_command() == f'"{executable.resolve()}" --background'


def test_set_start_removes_legacy_console_entries(monkeypatch) -> None:
    import sys
    import types

    values = {"LocalVaultPrototype": "console.exe --background", "Other": "x"}

    class Key:
        def __enter__(self):
            return self

        def __exit__(self, *_):
            return False

    def delete(_key, name):
        if name not in values:
            raise FileNotFoundError(name)
        del values[name]

    fake = types.SimpleNamespace(
        HKEY_CURRENT_USER=0, REG_SZ=1, CreateKey=lambda *_: Key(),
        SetValueEx=lambda _k, name, _r, _t, value: values.__setitem__(name, value),
        DeleteValue=delete,
    )
    monkeypatch.setitem(sys.modules, "winreg", fake)
    monkeypatch.setattr(startup.os, "name", "nt")
    monkeypatch.setattr(startup, "startup_command", lambda: '"app.exe" --background')

    startup.set_start_with_windows(True)
    assert values == {"Other": "x", "LocalGateKeys": '"app.exe" --background'}
    startup.set_start_with_windows(False)
    assert values == {"Other": "x"}
