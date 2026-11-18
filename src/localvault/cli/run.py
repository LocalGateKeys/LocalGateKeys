"""``lgk run``: resolve lgk:// values into the child's environment and hide them in its output.

The same child handling and masking serve ``run_with_secrets`` in ``lgk mcp`` (mcp_server.py): ``run_captured``
starts an argv list without a shell, captures a bounded amount of output, hides each value in it (verbatim and the
usual encodings), and stops the child, and anything it started, at a time limit. The run limits are shared with the
app's agent gate, which checks them again before it asks the user.
"""
from __future__ import annotations

import base64
import json
import locale
import os
import re
import shutil
import subprocess  # noqa: S404 - runs the user's own command, never through a shell
import sys
import threading
import time
import unicodedata
import urllib.parse
from collections.abc import Iterable, Mapping
from typing import Any, BinaryIO, TextIO

from .main import EXIT_USAGE, CliError, Forward, resolve_refs

PREFIX = "lgk://"
MASK = "<concealed by LocalGateKeys>"
INTERRUPT_WINDOW = 2.0  # seconds between two Ctrl+C presses that stop an unresponsive child
MIN_MASKED = 4  # shorter values would blank out ordinary words
MIN_BASE64_CORE = 6  # the part of a value's base64 that does not depend on its neighbours, when it is this long

# run_with_secrets limits (the agent gate checks the same ones before it asks the user).
MAX_ARGV = 64
MAX_ARG = 4096
MAX_COMMAND_LINE = 8000
MAX_RUN_REFS = 20
MAX_REF = 2048
DEFAULT_TIMEOUT = 120
MAX_TIMEOUT = 600
OUTPUT_LIMIT = 64 * 1024  # per stream, what run_with_secrets returns to the agent
READER_GRACE = 5.0  # seconds to collect the output after the child and what it started are gone
ENV_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,127}\Z")
# Variables that pick the program Windows runs: the approval shows one program, so an agent may not change them.
RESERVED_ENV = frozenset({"PATH", "PATHEXT", "COMSPEC", "SYSTEMROOT", "WINDIR"})
# cmd.exe re-reads a batch file's command line and acts on these, whatever the quoting (CVE-2024-24576 class).
BATCH_EXTENSIONS = (".bat", ".cmd")
CMD_METACHARACTERS = frozenset('&|<>^%!"()`')


class RunError(Exception):
    """A run that could not start. The message never quotes a value."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(code)
        self.code = code
        self.message = message


def plain_text(value: Any, limit: int, *, empty: bool = False) -> bool:
    """Text an approval can show exactly: bounded, no control, format (bidi, zero-width) or unassigned characters."""
    if not isinstance(value, str) or len(value) > limit or (not value and not empty):
        return False
    return not any(unicodedata.category(char) in ("Cc", "Cf", "Cs", "Co", "Cn") for char in value)


def unsafe_batch_command(argv: list[str]) -> bool:
    """True for a .bat/.cmd program with an argument cmd.exe would read as more than text."""
    return bool(argv) and str(argv[0]).lower().endswith(BATCH_EXTENSIONS) \
        and any(char in CMD_METACHARACTERS for arg in argv[1:] for char in str(arg))


def command_line(argv: list[str]) -> str:
    """The exact Windows command line ``argv`` becomes (what CreateProcess receives)."""
    return subprocess.list2cmdline(argv)


def parse_env_file(text: str) -> dict[str, str]:
    """KEY=VALUE lines; ``#`` comments, ``export`` prefixes and one pair of quotes are understood."""
    values: dict[str, str] = {}
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        if line.startswith("export "):
            line = line[7:].lstrip()
        key, _, value = line.partition("=")
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
            value = value[1:-1]
        if key.strip():
            values[key.strip()] = value
    return values


def merge_environment(environ: Mapping[str, str], values: Mapping[str, str]) -> dict[str, str]:
    """``environ`` with ``values`` set; Windows names are case-insensitive, so a name is replaced, never doubled."""
    env = dict(environ)
    for key, value in values.items():
        if os.name == "nt":
            for existing in [k for k in env if k.upper() == key.upper()]:
                del env[existing]
        env[key] = value
    return env


def secret_forms(values: Iterable[str]) -> list[str]:
    """The texts to hide: each value and each line of a multi-line value (output is often re-split by line, with
    CRLF on Windows). Shorter than ``MIN_MASKED`` is left out; longest first."""
    secrets: set[str] = set()
    for value in values:
        secrets.add(value)
        secrets.update(value.splitlines())
    return sorted((s for s in secrets if len(s) >= MIN_MASKED), key=len, reverse=True)


def build_environment(environ: Mapping[str, str], file_values: Mapping[str, str],
                      forward: Forward) -> tuple[dict[str, str], list[str]]:
    """The child's environment with every lgk:// value resolved by ONE request, and the secrets to mask."""
    env = merge_environment(environ, file_values)
    values = resolve_refs(forward, [value for value in env.values() if value.startswith(PREFIX)])
    resolved = {key: values.get(value, value) for key, value in env.items()}
    return resolved, secret_forms(values.values())


def _lower_escapes(text: str) -> str:
    return re.sub(r"%[0-9A-F]{2}", lambda match: match.group(0).lower(), text)


def _base64_forms(raw: bytes) -> set[bytes]:
    """Standard and URL-safe base64 of ``raw`` alone, and the part of it that is the same wherever ``raw`` sits in a
    longer encoded stream (one per byte alignment: ``echo "user:$TOKEN" | base64``)."""
    forms: set[bytes] = set()
    for encode in (base64.b64encode, base64.urlsafe_b64encode):
        whole = encode(raw)
        forms.update((whole, whole.rstrip(b"=")))
        for offset in range(3):
            stream = encode(b"\0" * offset + raw)
            start, end = -(-8 * offset // 6), 8 * (offset + len(raw)) // 6
            if end - start >= MIN_BASE64_CORE:
                forms.add(stream[start:end])
    return forms


def encoded_forms(values: Iterable[str]) -> list[bytes]:
    """Byte strings to hide in a command's output: each secret form as UTF-8, UTF-16-LE and the ANSI code page,
    lower and upper hex, URL-encoded, JSON-escaped and base64. Longest first."""
    ansi = locale.getpreferredencoding(False)
    forms: set[bytes] = set()
    for text in secret_forms(values):
        raw = text.encode("utf-8")
        forms.update((raw, text.encode("utf-16-le"), raw.hex().encode(), raw.hex().upper().encode()))
        try:
            forms.add(text.encode(ansi))
        except (LookupError, UnicodeError):
            # Expected failure for this optional step: fall back to the default behaviour.
            pass
        for quoted in (urllib.parse.quote(text, safe=""), urllib.parse.quote(text), urllib.parse.quote_plus(text)):
            forms.update((quoted.encode(), _lower_escapes(quoted).encode()))
        forms.update((json.dumps(text)[1:-1].encode(), json.dumps(text, ensure_ascii=False)[1:-1].encode("utf-8")))
        forms.update(_base64_forms(raw))
    return sorted((form for form in forms if len(form) >= MIN_MASKED), key=len, reverse=True)


def _spans(data: bytes, forms: Iterable[bytes]) -> list[list[int]]:
    """Every place a form occurs, merged where they touch or overlap."""
    spans: list[tuple[int, int]] = []
    for form in forms:
        start = data.find(form)
        while start != -1:
            spans.append((start, start + len(form)))
            start = data.find(form, start + 1)
    merged: list[list[int]] = []
    for start, end in sorted(spans):
        if merged and start <= merged[-1][1]:
            merged[-1][1] = max(merged[-1][1], end)
        else:
            merged.append([start, end])
    return merged


def cut_masked(data: bytes, forms: Iterable[bytes], limit: int) -> tuple[bytes, bool]:
    """The first ``limit`` bytes of ``data`` with every form hidden, and whether anything was cut. A value that
    starts before the cut is hidden whole (``data`` must hold ``limit`` plus the longest form when it was cut)."""
    mask = MASK.encode()
    out = bytearray()
    position = 0
    for start, end in _spans(data, forms):
        if start >= limit:
            break
        out += data[position:start] + mask
        position = end
    if position < limit:
        out += data[position:limit]
    return bytes(out), len(data) > limit


def mask_output(data: bytes, forms: Iterable[bytes]) -> bytes:
    return cut_masked(data, forms, len(data))[0]


def mask_line(line: bytes, secrets: list[bytes]) -> bytes:
    return mask_output(line, secrets)


def _pump(source: BinaryIO, sink: BinaryIO, secrets: list[bytes]) -> None:
    writable = True
    for line in iter(source.readline, b""):
        if not writable:
            continue  # keep draining so the child never blocks on a full pipe
        try:
            sink.write(mask_line(line, secrets))
            sink.flush()
        except (OSError, ValueError):  # a closed pipe or console, e.g. `lgk run ... | head -1`
            writable = False


def _sink(stream: TextIO) -> BinaryIO:
    return getattr(stream, "buffer", stream)  # type: ignore[return-value]


def run_command(command: list[str], forward: Forward, *, env_file: str | None, masking: bool,
                out: TextIO, err: TextIO) -> int:
    file_values: dict[str, str] = {}
    if env_file:
        try:
            with open(env_file, encoding="utf-8-sig") as handle:
                file_values = parse_env_file(handle.read())
        except (OSError, UnicodeError):
            raise CliError(EXIT_USAGE, "The env file could not be read.") from None
    env, secrets = build_environment(os.environ, file_values, forward)
    program = shutil.which(command[0], path=env.get("PATH")) or command[0]
    piped = masking and bool(secrets)
    try:
        # Semgrep: argv list, shell=False: runs the user's own command.
        # nosemgrep
        child = subprocess.Popen([program, *command[1:]], env=env, shell=False,  # noqa: S603
                                 stdout=subprocess.PIPE if piped else None,
                                 stderr=subprocess.PIPE if piped else None)
    except OSError:
        raise CliError(EXIT_USAGE, f"Could not start {command[0]}.") from None
    finally:
        env.clear()
    threads = []
    try:
        if piped:
            needles = [secret.encode() for secret in secrets]
            for source, stream in ((child.stdout, out), (child.stderr, err)):
                thread = threading.Thread(target=_pump, args=(source, _sink(stream), needles), daemon=True)
                thread.start()
                threads.append(thread)
        code = _wait(child)
        for thread in threads:
            _join(thread, child)
    except KeyboardInterrupt:
        _stop(child)
        raise
    return code


def _stop(child: subprocess.Popen) -> None:
    child.terminate()
    try:
        child.wait(timeout=3)
    except subprocess.TimeoutExpired:
        child.kill()
        child.wait()


def _wait(child: subprocess.Popen) -> int:
    """Wait for the child. The first Ctrl+C is the child's to handle; a second one within 2 s stops it."""
    last = 0.0
    while True:
        try:
            return child.wait()
        except KeyboardInterrupt:
            now = time.monotonic()
            if last and now - last < INTERRUPT_WINDOW:
                _stop(child)
                return child.returncode
            last = now


def _join(thread: threading.Thread, child: subprocess.Popen) -> None:
    while thread.is_alive():
        try:
            thread.join(0.2)
        except KeyboardInterrupt:
            _stop(child)  # the pipes close with the child, so the pump ends


# ------------------------------------------------------------------------------------------- run_with_secrets
class _Group:
    """The child and every process it starts: a Windows job object (killed when closed), a POSIX session."""

    def __init__(self, child: subprocess.Popen, handle: Any = None) -> None:
        self.child = child
        self.handle = handle

    def kill(self) -> None:
        if sys.platform == "win32":
            if self.handle:
                _kernel32().TerminateJobObject(self.handle, 1)
            return
        import signal

        try:
            os.killpg(self.child.pid, signal.SIGKILL)
        except OSError:
            # Best-effort file/OS step: failure is harmless here, so it is ignored.
            pass

    def close(self) -> None:
        self.kill()  # anything still running when the command ends is stopped with it
        if sys.platform == "win32" and self.handle:
            _kernel32().CloseHandle(self.handle)
            self.handle = None


_KERNEL32: Any = None
_CREATE_SUSPENDED = 0x00000004


def _kernel32() -> Any:
    global _KERNEL32
    if _KERNEL32 is None:
        import ctypes
        import ctypes.wintypes as wintypes

        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel32.CreateJobObjectW.argtypes = [ctypes.c_void_p, wintypes.LPCWSTR]
        kernel32.CreateJobObjectW.restype = wintypes.HANDLE
        kernel32.SetInformationJobObject.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD]
        kernel32.SetInformationJobObject.restype = wintypes.BOOL
        kernel32.AssignProcessToJobObject.argtypes = [wintypes.HANDLE, wintypes.HANDLE]
        kernel32.AssignProcessToJobObject.restype = wintypes.BOOL
        kernel32.TerminateJobObject.argtypes = [wintypes.HANDLE, wintypes.UINT]
        kernel32.TerminateJobObject.restype = wintypes.BOOL
        kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
        kernel32.CloseHandle.restype = wintypes.BOOL
        _KERNEL32 = kernel32
    return _KERNEL32


def _job_for(child: subprocess.Popen) -> Any:
    """Put the suspended child in a new job object that kills everything in it when closed, then let it run."""
    import ctypes
    import ctypes.wintypes as wintypes

    class IoCounters(ctypes.Structure):
        _fields_ = [(name, ctypes.c_ulonglong) for name in (
            "ReadOperationCount", "WriteOperationCount", "OtherOperationCount",
            "ReadTransferCount", "WriteTransferCount", "OtherTransferCount")]

    class BasicLimits(ctypes.Structure):
        _fields_ = [("PerProcessUserTimeLimit", ctypes.c_int64), ("PerJobUserTimeLimit", ctypes.c_int64),
                    ("LimitFlags", wintypes.DWORD), ("MinimumWorkingSetSize", ctypes.c_size_t),
                    ("MaximumWorkingSetSize", ctypes.c_size_t), ("ActiveProcessLimit", wintypes.DWORD),
                    ("Affinity", ctypes.c_size_t), ("PriorityClass", wintypes.DWORD),
                    ("SchedulingClass", wintypes.DWORD)]

    class ExtendedLimits(ctypes.Structure):
        _fields_ = [("BasicLimitInformation", BasicLimits), ("IoInfo", IoCounters),
                    ("ProcessMemoryLimit", ctypes.c_size_t), ("JobMemoryLimit", ctypes.c_size_t),
                    ("PeakProcessMemoryUsed", ctypes.c_size_t), ("PeakJobMemoryUsed", ctypes.c_size_t)]

    kernel32 = _kernel32()
    job = kernel32.CreateJobObjectW(None, None)
    if not job:
        raise OSError("job object")
    limits = ExtendedLimits()
    limits.BasicLimitInformation.LimitFlags = 0x2000  # JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
    process = int(child._handle)  # type: ignore[attr-defined]
    ntdll = ctypes.WinDLL("ntdll")
    ntdll.NtResumeProcess.argtypes = [wintypes.HANDLE]
    ntdll.NtResumeProcess.restype = ctypes.c_long
    if not kernel32.SetInformationJobObject(job, 9, ctypes.byref(limits), ctypes.sizeof(limits)) \
            or not kernel32.AssignProcessToJobObject(job, process) or ntdll.NtResumeProcess(process) != 0:
        kernel32.TerminateJobObject(job, 1)
        kernel32.CloseHandle(job)
        raise OSError("job object")
    return job


def _start(argv: list[str], env: dict[str, str], cwd: str | None) -> _Group:
    options: dict[str, Any] = {}
    if sys.platform == "win32":
        # Suspended until it is in the job, so nothing it starts can slip out; no console window of its own.
        options["creationflags"] = _CREATE_SUSPENDED | subprocess.CREATE_NO_WINDOW
    else:
        options["start_new_session"] = True
    # Semgrep: argv list, shell=False: the command the user approved, exactly as shown.
    # nosemgrep
    child = subprocess.Popen(argv, env=env, cwd=cwd, shell=False, stdin=subprocess.DEVNULL,  # noqa: S603
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE, **options)
    if sys.platform != "win32":
        return _Group(child)
    try:
        return _Group(child, _job_for(child))
    except Exception:
        child.kill()
        child.wait()
        for pipe in (child.stdout, child.stderr):
            if pipe is not None:
                pipe.close()
        raise OSError("job object") from None


def _capture(source: BinaryIO, buffer: bytearray, keep: int) -> None:
    """Read until the pipe closes; keep the first ``keep`` bytes and drain the rest so the child never blocks."""
    descriptor = source.fileno()
    while True:
        try:
            chunk = os.read(descriptor, 65536)
        except OSError:
            break
        if not chunk:
            break
        room = keep - len(buffer)
        if room > 0:
            buffer += chunk[:room]


def run_captured(argv: list[str], values: Mapping[str, str], cwd: str | None, timeout: int,
                 forms: list[bytes]) -> dict[str, Any]:
    """Run ``argv`` (no shell) with ``values`` added to this process's environment; return its exit code and its
    output with every form hidden, at most ``OUTPUT_LIMIT`` bytes a stream. At ``timeout`` seconds the child and
    everything it started are killed; when the child ends, anything it left running is stopped too."""
    limit = OUTPUT_LIMIT
    keep = limit + max((len(form) for form in forms), default=0) + 1
    env = merge_environment(os.environ, values)
    try:
        group = _start(list(argv), env, cwd)
    except (OSError, ValueError):  # ValueError: a NUL in an argument, a variable or a value
        raise RunError("not_started", "The command could not be started.") from None
    finally:
        env.clear()
    child = group.child
    buffers = (bytearray(), bytearray())
    readers = [threading.Thread(target=_capture, args=(pipe, buffer, keep), name="lgk-run-output", daemon=True)
               for pipe, buffer in zip((child.stdout, child.stderr), buffers, strict=True)]
    for reader in readers:
        reader.start()
    timed_out = False
    try:
        child.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        timed_out = True
        group.kill()
        try:
            child.wait(timeout=READER_GRACE)
        except subprocess.TimeoutExpired:
            child.kill()
            child.wait()
    finally:
        group.close()
    deadline = time.monotonic() + READER_GRACE
    for reader in readers:
        reader.join(max(0.0, deadline - time.monotonic()))
    try:
        stdout, cut_out = cut_masked(bytes(buffers[0]), forms, limit)
        stderr, cut_err = cut_masked(bytes(buffers[1]), forms, limit)
    finally:
        for buffer in buffers:
            buffer[:] = b"\0" * len(buffer)
    for pipe, reader in zip((child.stdout, child.stderr), readers, strict=True):
        if pipe is not None and not reader.is_alive():  # a pipe still being read is left to its daemon thread
            try:
                pipe.close()
            except OSError:
                # Best-effort file/OS step: failure is harmless here, so it is ignored.
                pass
    return {"exit_code": child.returncode, "stdout": stdout.decode("utf-8", errors="replace"),
            "stderr": stderr.decode("utf-8", errors="replace"), "truncated": cut_out or cut_err,
            "timed_out": timed_out}
