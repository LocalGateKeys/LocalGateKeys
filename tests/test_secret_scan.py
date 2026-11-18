"""secret_scan: finding plain SSH keys and .env files (tmp_path only) and rewriting .env values to references."""
from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path
from threading import Event

import pytest

from localvault import lgk_refs, secret_scan
from localvault.secret_scan import parse_env, rewrite_env, scan

VECTORS = Path(__file__).parent / "vectors" / "ssh"


def _key() -> str:
    return (VECTORS / "ed25519.key").read_text(encoding="utf-8")


def _write(path: Path, text: str | bytes) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(text if isinstance(text, bytes) else text.encode("utf-8"))
    return path


def _paths(findings, root: Path) -> set[str]:
    return {f.path.relative_to(root).as_posix() for f in findings}


def test_finds_openssh_and_pem_keys_in_dot_ssh(tmp_path):
    _write(tmp_path / ".ssh" / "id_ed25519", _key())
    _write(tmp_path / ".ssh" / "id_rsa", (VECTORS / "rsa3072.key").read_text(encoding="utf-8"))
    _write(tmp_path / ".ssh" / "legacy", "-----BEGIN RSA PRIVATE KEY-----\nabc\n-----END RSA PRIVATE KEY-----\n")
    _write(tmp_path / ".ssh" / "config", "Host *\n  User me\n")
    _write(tmp_path / ".ssh" / "known_hosts", "github.com ssh-ed25519 AAAA\n")
    found = scan([tmp_path], cancel=Event())
    assert _paths(found, tmp_path) == {".ssh/id_ed25519", ".ssh/id_rsa", ".ssh/legacy"}
    formats = {f.path.name: f.key_format for f in found}
    assert formats["id_ed25519"] == "openssh" and formats["legacy"] == "pem-rsa"
    assert all(f.kind == "ssh_private_key" and f.var_count == 0 for f in found)
    # A private key outside a .ssh folder is not looked for.
    _write(tmp_path / "src" / "id_ed25519", _key())
    assert "src/id_ed25519" not in _paths(scan([tmp_path], cancel=Event()), tmp_path)


def test_ignores_public_keys(tmp_path):
    _write(tmp_path / ".ssh" / "id_ed25519.pub", (VECTORS / "ed25519.pub").read_text(encoding="utf-8"))
    _write(tmp_path / ".ssh" / "named.pub", _key())  # even a key body under a .pub name is not offered
    assert scan([tmp_path], cancel=Event()) == []


def test_finds_env_and_env_local(tmp_path):
    _write(tmp_path / "app" / ".env", "A=1\nB=two\n")
    _write(tmp_path / "app" / ".env.local", "TOKEN=abc\n")
    _write(tmp_path / "app" / ".env.example", "TOKEN=changeme\n")  # a template: no secret
    _write(tmp_path / "app" / "env.txt", "A=1\n")
    _write(tmp_path / "empty" / ".env", "# only a comment\nEMPTY=\n")
    _write(tmp_path / "refs" / ".env", "A=lgk://x/A\n")
    found = scan([tmp_path], cancel=Event())
    assert {(f.path.relative_to(tmp_path).as_posix(), f.var_count) for f in found} == {
        ("app/.env", 2), ("app/.env.local", 1)}
    assert all(f.kind == "env_file" and f.key_format is None for f in found)


def test_skips_node_modules_git_appdata(tmp_path):
    for skipped in ("node_modules", ".git", "AppData", "venv", ".venv", "Library", ".hidden", "appdata"):
        _write(tmp_path / skipped / "proj" / ".env", "A=1\n")
    _write(tmp_path / "keep" / ".env", "A=1\n")
    assert _paths(scan([tmp_path], cancel=Event()), tmp_path) == {"keep/.env"}


def test_depth_limit(tmp_path):
    _write(tmp_path / ".env", "A=1\n")
    _write(tmp_path / "a" / "b" / "c" / "d" / ".env", "A=1\n")        # four folders down: found
    _write(tmp_path / "a" / "b" / "c" / "d" / "e" / ".env", "A=1\n")  # five folders down: too deep
    assert _paths(scan([tmp_path], cancel=Event()), tmp_path) == {".env", "a/b/c/d/.env"}
    assert _paths(scan([tmp_path], max_depth=1, cancel=Event()), tmp_path) == {".env"}


def test_does_not_follow_symlinks(tmp_path):
    outside = tmp_path / "outside"
    _write(outside / ".env", "A=1\n")
    root = tmp_path / "root"
    root.mkdir()
    made = False
    try:
        os.symlink(outside, root / "linked", target_is_directory=True)
        made = True
    except (OSError, NotImplementedError):
        # Symlinks need a privilege on Windows; the test still covers the links that could be made.
        pass
    if sys.platform == "win32":  # a junction needs no privilege
        subprocess.run(["cmd", "/c", "mklink", "/J", str(root / "junction"), str(outside)], check=True,
                       capture_output=True)
        made = True
    if not made:
        pytest.skip("cannot create a link here")
    try:
        os.symlink(outside / ".env", root / ".env", target_is_directory=False)
    except (OSError, NotImplementedError):
        # Symlinks need a privilege on Windows; the test still covers the links that could be made.
        pass
    assert scan([root], cancel=Event()) == []
    assert (outside / ".env").read_text() == "A=1\n"  # and nothing was touched


def test_large_file_skipped(tmp_path):
    _write(tmp_path / "big" / ".env", "A=1\n" + "#" * secret_scan.MAX_FILE_BYTES)
    _write(tmp_path / "ok" / ".env", "A=1\n")
    assert _paths(scan([tmp_path], cancel=Event()), tmp_path) == {"ok/.env"}


def test_cancel_stops(tmp_path):
    _write(tmp_path / "a" / ".env", "A=1\n")
    cancel = Event()
    cancel.set()
    assert scan([tmp_path], cancel=cancel) == []
    # Cancelled part-way: whatever was found before stays, nothing more is read.
    for n in range(5):
        _write(tmp_path / f"d{n}" / ".env", "A=1\n")
    later = Event()
    seen = []

    def progress(count):
        seen.append(count)
        later.set()
    many = tmp_path / "many"
    for n in range(450):
        _write(many / "x" / f"f{n}.txt", "x")
    assert len(scan([tmp_path], cancel=later, progress=progress)) <= 6
    assert seen  # progress was reported, then the scan noticed the cancel


def test_missing_or_unreadable_root_is_skipped(tmp_path):
    assert scan([tmp_path / "nope"], cancel=Event()) == []


def test_parse_env_keeps_layout():
    text = ("# comment\r\n\r\nexport A=1\r\nB = 'two words'\r\n  C=\"x#y\"  # note\r\nD=plain # tail\r\n"
            "E=\r\nnot an assignment\r\nF=last")
    lines = parse_env(text)
    assert "".join(line.raw for line in lines) == text
    by_key = {line.key: line for line in lines if line.key}
    assert by_key["A"].value == "1" and by_key["B"].value == "two words" and by_key["B"].quoted
    assert by_key["C"].value == "x#y" and by_key["C"].trailing
    assert by_key["D"].value == "plain" and by_key["D"].trailing
    assert by_key["E"].value == "" and by_key["F"].value == "last"
    assert [line.key for line in lines if not line.key][:2] == [None, None]


def test_parse_env_multiline_quoted_value():
    text = 'KEY="line one\nline two"\nNEXT=1\n'
    lines = parse_env(text)
    assert "".join(line.raw for line in lines) == text
    assert lines[0].key == "KEY" and lines[0].value == "line one\nline two" and lines[1].key == "NEXT"


def test_rewrite_preserves_layout():
    text = ("# Production\r\n\r\nexport API_KEY=abc123\r\nDB_URL='postgres://u:p@h/db'\r\nPLAIN=keep me\r\n"
            "TOKEN=\"t0k\"  # inline\r\nDUP=first\r\nDUP=second\r\nEMPTY=\r\nSPACED = spaced\r\nlast=nonewline")
    refs = {"API_KEY": "lgk://id/API_KEY", "DB_URL": "lgk://id/DB_URL", "DUP": "lgk://id/DUP",
            "TOKEN": "lgk://id/TOKEN", "EMPTY": "lgk://id/EMPTY", "SPACED": "lgk://id/SPACED"}
    assert rewrite_env(text, refs) == (
        "# Production\r\n\r\nexport API_KEY=lgk://id/API_KEY\r\nDB_URL='lgk://id/DB_URL'\r\nPLAIN=keep me\r\n"
        "TOKEN=\"t0k\"  # inline\r\nDUP=lgk://id/DUP\r\nDUP=lgk://id/DUP\r\nEMPTY=\r\nSPACED = lgk://id/SPACED\r\n"
        "last=nonewline")
    assert rewrite_env(text, {}) == text
    again = rewrite_env(rewrite_env(text, refs), refs)  # references are never rewritten twice
    assert again == rewrite_env(text, refs)


def test_rewritten_lines_round_trip_with_lgk_refs():
    ref = "lgk://abc%2F1/API_KEY"
    line = parse_env(rewrite_env("API_KEY=secret\n", {"API_KEY": ref}))[0]
    parsed = lgk_refs.parse(line.value)
    assert (parsed.item, parsed.field) == ("abc/1", "API_KEY")


def test_referenceable_limits():
    text = "A=1\nB=lgk://x/B\nC=\nD=3 # c\nD=4\nE=" + "x" * 5000 + "\n" + "".join(f"V{i}=v\n" for i in range(60))
    names = list(secret_scan.referenceable(text))
    assert "A" in names and "B" not in names and "C" not in names and "D" not in names and "E" not in names
    assert len(names) == secret_scan.MAX_FIELDS


def test_write_atomic_replaces_in_place_and_leaves_no_temp(tmp_path):
    target = _write(tmp_path / ".env", "A=1\n")
    secret_scan.write_atomic(target, b"A=2\n")
    assert target.read_bytes() == b"A=2\n"
    assert [p.name for p in tmp_path.iterdir()] == [".env"]


def test_parse_env_empty_value_before_a_comment():
    lines = parse_env("KEY= #comment\nOTHER=\t#tab comment\nPLAIN=x #c\n")
    assert [(line.key, line.value, line.trailing) for line in lines] == [
        ("KEY", "", True), ("OTHER", "", True), ("PLAIN", "x", True)]
    assert secret_scan.plain_variable_count("KEY= #comment\n") == 0
    assert rewrite_env("KEY= #comment\n", {"KEY": "lgk://i/KEY"}) == "KEY= #comment\n"


def test_double_quoted_values_with_backslashes_are_never_referenced():
    text = (r'PEM="-----BEGIN KEY-----\nMIIE\n-----END KEY-----"' + "\n" + r"SINGLE='a\nb'" + "\n"
            + 'PLAIN="no escapes"\n' + r"PATH_=C:\dir" + "\n")
    lines = {line.key: line for line in parse_env(text)}
    assert lines["PEM"].escaped and not lines["SINGLE"].escaped and not lines["PLAIN"].escaped
    assert set(secret_scan.referenceable(text)) == {"SINGLE", "PLAIN", "PATH_"}
    refs = {name: f"lgk://i/{name}" for name in ("PEM", "SINGLE")}
    out = rewrite_env(text, refs)
    assert out.splitlines()[0] == text.splitlines()[0]  # untouched, escapes and all
    assert "SINGLE='lgk://i/SINGLE'" in out


def test_write_atomic_removes_its_temp_file_when_replace_fails(tmp_path, monkeypatch):
    target = _write(tmp_path / ".env", "A=1\n")

    def boom(src, dst):
        raise PermissionError("locked")
    monkeypatch.setattr(secret_scan.os, "replace", boom)
    with pytest.raises(PermissionError):
        secret_scan.write_atomic(target, b"A=2\n")
    assert target.read_bytes() == b"A=1\n"
    assert [p.name for p in tmp_path.iterdir()] == [".env"]
