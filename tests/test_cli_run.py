"""lgk run: environment injection, masking and exit codes (real child processes, fake IPC)."""
from __future__ import annotations

import io
import sys

from localvault.cli.main import main
from localvault.cli.run import MASK, parse_env_file

SECRET = "tok-9f8e7d6c5b"


class _Out(io.StringIO):
    """A text stream with a ``buffer`` like sys.stdout, so child bytes are passed through."""

    def __init__(self):
        super().__init__()
        self.buffer = io.BytesIO()

    def text(self) -> str:
        return self.buffer.getvalue().decode()


def _forward(values, calls=None):
    def forward(request):
        if calls is not None:
            calls.append(request)
        return {"ok": True, "values": {ref: values[ref] for ref in request["refs"]}}

    return forward


def _run(argv, forward):
    out, err = _Out(), _Out()
    code = main(argv, forward=forward, out=out, err=err)
    return code, _text(out), _text(err)


def _text(stream) -> str:
    return (stream.getvalue() + stream.text()).replace("\r\n", "\n")


PRINT = [sys.executable, "-c",
         "import os,sys; print(os.environ['API_KEY']); print(os.environ['API_KEY'], file=sys.stderr)"]


def test_run_injects_env_and_returns_child_code(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("API_KEY", "lgk://Prod/key")
    monkeypatch.setenv("PLAIN", "untouched")
    env_file = tmp_path / ".env"
    env_file.write_text("# comment\nexport FROM_FILE='lgk://Prod/secret'\nOTHER=1\n", encoding="utf-8")
    calls = []
    forward = _forward({"lgk://Prod/key": SECRET, "lgk://Prod/secret": "another-secret"}, calls)
    script = ("import os,sys; "
              f"assert os.environ['API_KEY']=='{SECRET}' and os.environ['FROM_FILE']=='another-secret'; "
              "assert os.environ['PLAIN']=='untouched' and os.environ['OTHER']=='1'; sys.exit(7)")
    code, _, _ = _run(["run", "--env-file", str(env_file), "--", sys.executable, "-c", script], forward)
    assert code == 7
    assert len(calls) == 1 and calls[0]["action"] == "resolve_many"  # one request, one approval
    assert sorted(calls[0]["refs"]) == ["lgk://Prod/key", "lgk://Prod/secret"]


def test_run_masks_values_in_output(monkeypatch) -> None:
    monkeypatch.setenv("API_KEY", "lgk://Prod/key")
    code, out, err = _run(["run", "--", *PRINT], _forward({"lgk://Prod/key": SECRET}))
    assert code == 0
    assert out == MASK + "\n" and err == MASK + "\n"
    assert SECRET not in out + err


def test_run_masks_each_line_of_a_multiline_value(monkeypatch) -> None:
    monkeypatch.setenv("API_KEY", "lgk://Prod/key")
    key = "-----BEGIN KEY-----\nline-one-AAAA\n-----END KEY-----"
    code, out, _ = _run(["run", "--", sys.executable, "-c", "import os; print(os.environ['API_KEY'])"],
                        _forward({"lgk://Prod/key": key}))
    assert code == 0 and "line-one-AAAA" not in out and out.count(MASK) == 3


def test_run_no_masking_passthrough(monkeypatch, capfd) -> None:
    monkeypatch.setenv("API_KEY", "lgk://Prod/key")
    code = main(["run", "--no-masking", "--", *PRINT], forward=_forward({"lgk://Prod/key": SECRET}))
    captured = capfd.readouterr()
    assert code == 0
    assert SECRET in captured.out and SECRET in captured.err and MASK not in captured.out


def test_run_short_values_not_masked(monkeypatch, capfd) -> None:
    monkeypatch.setenv("API_KEY", "lgk://Prod/key")
    code = main(["run", "--", *PRINT], forward=_forward({"lgk://Prod/key": "abc"}))
    captured = capfd.readouterr()  # nothing to mask, so the child keeps the real stdout
    assert code == 0 and captured.out.strip() == "abc" and MASK not in captured.out


def test_run_failure_stops_before_starting_the_child(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("API_KEY", "lgk://Prod/key")
    marker = tmp_path / "ran"

    def forward(request):
        return {"ok": False, "error": "denied", "message": "No."}

    code, _, err = _run(["run", "--", sys.executable, "-c", f"open({str(marker)!r}, 'w')"], forward)
    assert code == 4 and not marker.exists() and "No." in err


def test_run_unknown_program_is_a_usage_error(monkeypatch) -> None:
    monkeypatch.delenv("API_KEY", raising=False)
    code, _, err = _run(["run", "--", "no-such-program-lgk"], _forward({}))
    assert code == 1 and "Could not start" in err


def test_parse_env_file() -> None:
    text = 'A=1\n\n# c\nexport B="two words"\nC=\'x\'\nbad line\nD=a=b\n'
    assert parse_env_file(text) == {"A": "1", "B": "two words", "C": "x", "D": "a=b"}


class _BrokenSink(io.BytesIO):
    def write(self, data):
        raise BrokenPipeError("closed")


def test_run_survives_a_closed_output_pipe(monkeypatch) -> None:
    """A sink that raises must not leave the child blocked on a full pipe."""
    monkeypatch.setenv("API_KEY", "lgk://Prod/key")
    script = "import os; [print(os.environ['API_KEY'] + 'x' * 200) for _ in range(5000)]"
    out = _Out()
    out.buffer = _BrokenSink()
    code = main(["run", "--", sys.executable, "-c", script], forward=_forward({"lgk://Prod/key": SECRET}),
                out=out, err=_Out())
    assert code == 0


def test_run_second_ctrl_c_stops_an_unresponsive_child(monkeypatch) -> None:
    import subprocess

    from localvault.cli import run as run_module

    class Child:
        returncode = None
        stopped = False

        def __init__(self):
            self.calls = 0

        def wait(self, timeout=None):
            self.calls += 1
            if self.stopped:
                self.returncode = 1
                return 1
            raise KeyboardInterrupt

        def terminate(self):
            self.stopped = True

        def kill(self):
            raise AssertionError("terminate was enough")

    child = Child()
    assert run_module._wait(child) == 1 and child.stopped  # second press within the window

    class Stubborn(Child):
        killed = False

        def wait(self, timeout=None):
            if timeout is not None and not self.killed:
                raise subprocess.TimeoutExpired("x", timeout)
            if self.killed:
                self.returncode = 9
                return 9
            raise KeyboardInterrupt

        def kill(self):
            self.killed = True

    stubborn = Stubborn()
    run_module._stop(stubborn)
    assert stubborn.killed


def test_env_file_keys_do_not_duplicate_by_case(monkeypatch) -> None:
    import os

    from localvault.cli.run import build_environment

    env, _ = build_environment({"Path": "x", "API_KEY": "old"}, {"api_key": "new"}, lambda r: {"ok": True, "values": {}})
    if os.name == "nt":
        assert [k for k in env if k.upper() == "API_KEY"] == ["api_key"] and env["api_key"] == "new"
    assert env["Path"] == "x"
