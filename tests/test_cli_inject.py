"""lgk inject: placeholder replacement, private output, overwrite refusal."""
from __future__ import annotations

import io
import os

import pytest

from localvault.cli import inject
from localvault.cli.main import main


def _forward(values, calls=None):
    def forward(request):
        if calls is not None:
            calls.append(request)
        return {"ok": True, "values": {ref: values[ref] for ref in request["refs"]}}

    return forward


def _inject(argv, forward):
    err = io.StringIO()
    return main(argv, forward=forward, out=io.StringIO(), err=err), err.getvalue()


def test_inject_replaces_and_sets_acl(tmp_path, monkeypatch) -> None:
    template = tmp_path / "app.tpl"
    template.write_text("db={{ lgk://DB/password }}\nagain={{lgk://DB/password}}\nuser={{ lgk://DB%20Prod/username }}\n"
                        "keep={ not a ref } {{ other }}\n", encoding="utf-8", newline="\n")
    out = tmp_path / "app.conf"
    restricted = []
    # Windows: the DACL is set at creation by _create_private_windows; elsewhere chmod after mkstemp.
    name = "_create_private_windows" if os.name == "nt" else "restrict_to_current_user"
    real = getattr(inject, name)

    def spy(*args):
        result = real(*args)
        restricted.append(result if os.name == "nt" else args[0])
        return result

    monkeypatch.setattr(inject, name, spy)
    calls = []
    forward = _forward({"lgk://DB/password": "p@ss", "lgk://DB%20Prod/username": "admin"}, calls)
    code, err = _inject(["inject", "-i", str(template), "-o", str(out)], forward)
    assert code == 0, err
    assert out.read_text(encoding="utf-8") == "db=p@ss\nagain=p@ss\nuser=admin\nkeep={ not a ref } {{ other }}\n"
    assert len(calls) == 1 and sorted(calls[0]["refs"]) == ["lgk://DB%20Prod/username", "lgk://DB/password"]
    # The ACL was set on the temp file (same folder), before the rename.
    assert len(restricted) == 1 and os.path.dirname(restricted[0]) == str(tmp_path) and restricted[0] != str(out)
    assert sorted(p.name for p in tmp_path.iterdir()) == ["app.conf", "app.tpl"]  # no temp file left


@pytest.mark.skipif(os.name != "nt", reason="Windows DACL")
def test_inject_temp_file_is_private_from_creation(tmp_path) -> None:
    import win32security

    path = inject._create_private_windows(str(tmp_path), b"secret")
    descriptor = win32security.GetNamedSecurityInfo(
        path, win32security.SE_FILE_OBJECT, win32security.DACL_SECURITY_INFORMATION)
    assert descriptor.GetSecurityDescriptorControl()[0] & win32security.SE_DACL_PROTECTED
    assert descriptor.GetSecurityDescriptorDacl().GetAceCount() == 1
    with open(path, "rb") as handle:
        assert handle.read() == b"secret"


@pytest.mark.skipif(os.name != "nt", reason="Windows DACL")
def test_inject_output_dacl_is_current_user_only(tmp_path) -> None:
    import win32api
    import win32security

    template = tmp_path / "t"
    template.write_text("{{ lgk://A/b }}", encoding="utf-8")
    out = tmp_path / "o"
    assert _inject(["inject", "-i", str(template), "-o", str(out)], _forward({"lgk://A/b": "v"}))[0] == 0
    descriptor = win32security.GetNamedSecurityInfo(
        str(out), win32security.SE_FILE_OBJECT, win32security.DACL_SECURITY_INFORMATION)
    assert descriptor.GetSecurityDescriptorControl()[0] & win32security.SE_DACL_PROTECTED
    dacl = descriptor.GetSecurityDescriptorDacl()
    token = win32security.OpenProcessToken(win32api.GetCurrentProcess(), win32security.TOKEN_QUERY)
    me = win32security.GetTokenInformation(token, win32security.TokenUser)[0]
    assert dacl.GetAceCount() == 1 and dacl.GetAce(0)[2] == me


def test_inject_refuses_overwrite(tmp_path) -> None:
    template = tmp_path / "t"
    template.write_text("{{ lgk://A/b }}", encoding="utf-8")
    out = tmp_path / "o"
    out.write_text("old", encoding="utf-8")
    forward = _forward({"lgk://A/b": "new"})
    code, err = _inject(["inject", "-i", str(template), "-o", str(out)], forward)
    assert code == 1 and "--force" in err and out.read_text() == "old"
    assert _inject(["inject", "-i", str(template), "-o", str(out), "--force"], forward)[0] == 0
    assert out.read_text() == "new"


def test_inject_failure_writes_nothing(tmp_path) -> None:
    template = tmp_path / "t"
    template.write_text("{{ lgk://A/b }}", encoding="utf-8")
    out = tmp_path / "o"
    code, _ = _inject(["inject", "-i", str(template), "-o", str(out)],
                      lambda r: {"ok": False, "error": "not_found", "message": "No such item."})
    assert code == 5 and sorted(p.name for p in tmp_path.iterdir()) == ["t"]


def test_inject_keeps_crlf(tmp_path) -> None:
    template = tmp_path / "t"
    template.write_bytes(b"a={{ lgk://A/b }}\r\nz=1\r\n")
    out = tmp_path / "o"
    assert _inject(["inject", "-i", str(template), "-o", str(out)], _forward({"lgk://A/b": "v"}))[0] == 0
    assert out.read_bytes() == b"a=v\r\nz=1\r\n"
