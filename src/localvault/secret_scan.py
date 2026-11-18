"""Find plain SSH private keys and ``.env`` files on disk, and rewrite a ``.env`` to ``lgk://`` references.

Pure file logic, no vault and no UI. Scanning only reads under the roots it is given: it never follows symlinks or
Windows junctions (any reparse point), skips files over 1 MiB and the folders of :data:`SKIP_DIRS` (plus every
hidden folder except ``.ssh``), and never returns a value, only a path, a kind and a variable count. Nothing here
deletes or moves a file; :func:`write_atomic` replaces one file through a temp file in the same folder.
"""
from __future__ import annotations

import os
import re
import stat
import tempfile
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from pathlib import Path
from threading import Event
from typing import Literal

from .item_schema import sniff_private_key_format

MAX_FILE_BYTES = 1024 * 1024
MAX_DEPTH = 4
SKIP_DIRS = frozenset({"appdata", "node_modules", ".git", "venv", ".venv", "library"})
# Template files hold no real secrets and are not a place to put references.
TEMPLATE_SUFFIXES = frozenset({"example", "sample", "template", "dist", "defaults"})
_REPARSE_POINT = 0x400
_HEADER_BYTES = 512

Kind = Literal["ssh_private_key", "env_file"]


@dataclass(frozen=True)
class Finding:
    path: Path
    kind: Kind
    var_count: int = 0
    key_format: str | None = None


def _is_link(entry: os.DirEntry[str]) -> bool:
    """A symlink, a junction or any other reparse point (cloud placeholders included): never followed."""
    try:
        if entry.is_symlink():
            return True
        return bool(getattr(entry.stat(follow_symlinks=False), "st_file_attributes", 0) & _REPARSE_POINT)
    except OSError:
        return True


def is_env_name(name: str) -> bool:
    lowered = name.casefold()
    if lowered == ".env":
        return True
    if not lowered.startswith(".env."):
        return False
    return lowered.rsplit(".", 1)[1] not in TEMPLATE_SUFFIXES


def _walk(root: Path, max_depth: int, cancel: Event) -> Iterator[tuple[os.DirEntry[str], bool]]:
    """(file entry, is inside a ``.ssh`` folder) for every regular file under ``root``; depth 0 is ``root``."""
    stack = [(str(root), 0, False)]
    while stack and not cancel.is_set():
        folder, depth, in_ssh = stack.pop()
        try:
            with os.scandir(folder) as scanner:
                entries = list(scanner)
        except OSError:
            continue
        for entry in entries:
            if cancel.is_set():
                return
            if _is_link(entry):
                continue
            try:
                if entry.is_dir(follow_symlinks=False):
                    name = entry.name.casefold()
                    ssh = name == ".ssh"
                    if depth < max_depth and name not in SKIP_DIRS and (ssh or not name.startswith(".")):
                        stack.append((entry.path, depth + 1, ssh))
                elif entry.is_file(follow_symlinks=False):
                    yield entry, in_ssh
            except OSError:
                continue


def regular_file(path: Path) -> bool:
    """A plain file of at most 1 MiB: not a symlink, junction or other reparse point."""
    try:
        info = path.lstat()
    except OSError:
        return False
    return (stat.S_ISREG(info.st_mode) and info.st_size <= MAX_FILE_BYTES
            and not getattr(info, "st_file_attributes", 0) & _REPARSE_POINT)


def describe_file(path: Path) -> Finding | None:
    """The finding for one file, or None when it holds no plain secret (also used to re-check a rewritten file)."""
    try:
        if not regular_file(path):
            return None
        if is_env_name(path.name):
            text = read_text(path)
            count = 0 if text is None else plain_variable_count(text)
            return Finding(path, "env_file", count) if count else None
        if path.parent.name.casefold() == ".ssh" and not path.name.casefold().endswith(".pub"):
            with open(path, "rb") as handle:
                head = handle.read(_HEADER_BYTES).decode("utf-8", errors="ignore")
            fmt = sniff_private_key_format(head)
            if fmt not in ("", "unknown"):
                return Finding(path, "ssh_private_key", 0, fmt)
    except OSError:
        return None
    return None


def read_text(path: Path) -> str | None:
    """The file as UTF-8 text (a leading BOM is dropped), or None when it is too big or not UTF-8."""
    try:
        with open(path, "rb") as handle:
            data = handle.read(MAX_FILE_BYTES + 1)
    except OSError:
        return None
    if len(data) > MAX_FILE_BYTES:
        return None
    try:
        return data.decode("utf-8-sig")
    except UnicodeDecodeError:
        return None


def scan(roots: list[Path], *, max_depth: int = MAX_DEPTH, cancel: Event | None = None,
         progress: Callable[[int], None] | None = None) -> list[Finding]:
    """Findings under ``roots``, sorted by path; stops early (with what it has) when ``cancel`` is set."""
    cancel = cancel or Event()
    found: dict[str, Finding] = {}
    seen = 0
    for root in roots:
        try:
            if _is_link_path(root) or not root.is_dir():
                continue
        except OSError:
            continue
        for entry, in_ssh in _walk(root, max_depth, cancel):
            seen += 1
            if progress is not None and seen % 200 == 0:
                progress(seen)
            name = entry.name
            if not (is_env_name(name) or (in_ssh and not name.casefold().endswith(".pub"))):
                continue
            finding = describe_file(Path(entry.path))
            if finding is not None:
                found.setdefault(os.path.normcase(entry.path), finding)
    return sorted(found.values(), key=lambda f: str(f.path).casefold())


def _is_link_path(path: Path) -> bool:
    info = path.lstat()
    return stat.S_ISLNK(info.st_mode) or bool(getattr(info, "st_file_attributes", 0) & _REPARSE_POINT)


# ---------------------------------------------------------------------------------------------- .env files

@dataclass(frozen=True)
class EnvLine:
    """One original line of an env file (its terminator included in ``raw``) and what it assigns, if anything."""

    raw: str
    key: str | None = None
    value: str | None = None
    value_span: tuple[int, int] | None = None  # slice of ``raw`` holding the value, quotes excluded
    quoted: bool = False
    trailing: bool = False  # something other than whitespace follows the value (an inline comment)
    quote: str = ""  # the quote character around the value, if any

    @property
    def escaped(self) -> bool:
        """A double-quoted value with a backslash: dotenv expands escapes such as backslash-n, a stored raw copy would differ."""
        return self.quote == '"' and "\\" in (self.value or "")


_ASSIGN = re.compile(r"^([ \t]*)(?:export[ \t]+)?([A-Za-z_][A-Za-z0-9_.\-]*)[ \t]*=[ \t]*")


def _split_lines(text: str) -> list[str]:
    return re.findall(r"[^\n]*\n|[^\n]+", text)


def _end_of_quote(text: str, start: int, quote: str) -> int:
    """Index of the closing quote that follows ``start``, or -1. A double quote honours backslash escapes."""
    i = start
    while i < len(text):
        ch = text[i]
        if ch == "\\" and quote == '"':
            i += 2
            continue
        if ch == quote:
            return i
        i += 1
    return -1


def parse_env(text: str) -> list[EnvLine]:
    """Every line of ``text`` as an :class:`EnvLine`; ``"".join(line.raw for line in parse_env(t)) == t``.

    A quoted value that does not close on its own line continues over the following lines (they join one EnvLine).
    """
    lines = _split_lines(text)
    result: list[EnvLine] = []
    index = 0
    while index < len(lines):
        raw = lines[index]
        index += 1
        body = raw.rstrip("\r\n")
        if body.lstrip().startswith("#"):
            result.append(EnvLine(raw))
            continue
        match = _ASSIGN.match(body)
        if not match:
            result.append(EnvLine(raw))
            continue
        key, start = match.group(2), match.end()
        quote = body[start] if start < len(body) and body[start] in "\"'" else ""
        if quote:
            closing = _end_of_quote(body, start + 1, quote)
            while closing < 0 and index < len(lines):  # a multi-line quoted value
                raw += lines[index]
                index += 1
                body = raw.rstrip("\r\n")
                closing = _end_of_quote(body, start + 1, quote)
            if closing < 0:  # never closed: keep the rest as plain text
                result.append(EnvLine(raw))
                continue
            rest = body[closing + 1:]
            result.append(EnvLine(raw, key, body[start + 1:closing], (start + 1, closing), True,
                                  bool(rest.strip()), quote))
            continue
        if body[start:start + 1] == "#" and body[start - 1:start] in (" ", "\t"):  # KEY= #note: empty value
            result.append(EnvLine(raw, key, "", (start, start), False, True))
            continue
        # Unquoted: the value ends at the first " #" (a comment) or at the end of the line.
        comment = re.search(r"[ \t]#", body[start:])
        end = start + comment.start() if comment else len(body)
        value = body[start:end].rstrip(" \t")
        result.append(EnvLine(raw, key, value, (start, start + len(value)), False, comment is not None))
    return result


def plain_variable_count(text: str) -> int:
    """Variables with a value that is not already an ``lgk://`` reference."""
    return sum(1 for line in parse_env(text) if line.key and line.value and not line.value.startswith("lgk://"))


MAX_FIELDS = 50
MAX_FIELD_VALUE = 4096
MAX_FIELD_NAME = 100


def conflicting_duplicates(text: str) -> set[str]:
    """Names assigned more than once with different plain values; a rewrite would lose the earlier value."""
    seen: dict[str, str] = {}
    conflicts: set[str] = set()
    for line in parse_env(text):
        if not line.key or not line.value or line.value.startswith("lgk://"):
            continue
        if seen.setdefault(line.key, line.value) != line.value:
            conflicts.add(line.key)
    return conflicts


def referenceable(text: str) -> dict[str, str]:
    """name -> value of the variables a reference can stand for (the last assignment of a name wins; a name assigned different values more than once is left out).

    Left out: empty values, existing references, values too long for a note field, a name with an inline comment
    on any of its lines (a comment after a reference would be read as part of it), a double-quoted value with a
    backslash (dotenv expands the escapes, the stored raw text would differ), and everything past 50 names.
    """
    last: dict[str, str] = {}
    blocked = conflicting_duplicates(text)
    for line in parse_env(text):
        if not line.key or not line.value or line.value.startswith("lgk://"):
            continue
        if line.trailing or line.escaped:
            blocked.add(line.key)
        last[line.key] = line.value
    names = [n for n, v in last.items() if n not in blocked and len(v) <= MAX_FIELD_VALUE and len(n) <= MAX_FIELD_NAME]
    return {name: last[name] for name in names[:MAX_FIELDS]}


def rewrite_env(text: str, refs: dict[str, str]) -> str:
    """``text`` with the value of every assignment of a key in ``refs`` replaced by ``refs[key]``.

    Only that value changes: quotes stay, and every other byte (comments, blank lines, ``export``, CRLF, other
    keys, duplicates of other keys) is copied as it was. A line with an inline comment is left alone.
    """
    out: list[str] = []
    for line in parse_env(text):
        if (line.key in refs and line.value and line.value_span is not None and not line.trailing
                and not line.escaped and not line.value.startswith("lgk://")):
            start, end = line.value_span
            out.append(line.raw[:start] + refs[line.key] + line.raw[end:])
        else:
            out.append(line.raw)
    return "".join(out)


def write_atomic(path: Path, data: bytes) -> None:
    """Replace ``path`` with ``data`` through a temp file in the same folder (``os.replace``), keeping its mode."""
    # On Windows the new file inherits the folder's ACL (the old file's own ACL is not carried over).
    handle = tempfile.NamedTemporaryFile(dir=path.parent, prefix=f".{path.name}.", suffix=".tmp", delete=False)
    temp = Path(handle.name)
    try:
        with handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        try:
            os.chmod(temp, stat.S_IMODE(path.stat().st_mode))
        except OSError:
            # Best-effort file/OS step: failure is harmless here, so it is ignored.
            pass
        os.replace(temp, path)
    except BaseException:
        try:
            temp.unlink()
        except OSError:
            # Best-effort file/OS step: failure is harmless here, so it is ignored.
            pass
        raise
