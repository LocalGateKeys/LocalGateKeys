import base64
import datetime as dt
import hashlib
import importlib.util
import os
import re
import subprocess
import sys
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

from localvault import licensing

TEST_PW = "pw-test"  # noqa: S105
SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "issue_license.py"
_spec = importlib.util.spec_from_file_location("issue_license", SCRIPT)
issue_license = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(issue_license)


def _keys(private):
    raw = private.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    return {hashlib.sha256(raw).digest()[:8].hex(): base64.b64encode(raw).decode("ascii")}


def test_issue_verifies():
    private = ed25519.Ed25519PrivateKey.generate()
    bundle = issue_license.issue(private, "Ada", "ada@example.com", dt.date(2026, 10, 1), 365)
    lic = licensing.verify_bundle(bundle, _keys(private))
    assert lic.name == "Ada"
    assert lic.email == "ada@example.com"
    assert lic.edition == "pro"


def test_updates_until_is_365_days():
    private = ed25519.Ed25519PrivateKey.generate()
    bundle = issue_license.issue(private, "Ada", "ada@example.com", dt.date(2026, 10, 1), 365)
    assert bundle["license"]["updates_until"] == "2027-10-01"
    assert bundle["license"]["issued_at"] == "2026-10-01"


def test_license_id_format():
    pattern = re.compile(r"^lgk_[0-9A-HJKMNP-TV-Z]{26}$")
    ids = {issue_license.new_license_id() for _ in range(50)}
    assert len(ids) == 50
    assert all(pattern.match(i) for i in ids)


def test_issue_rejects_bad_inputs():
    private = ed25519.Ed25519PrivateKey.generate()
    today = dt.date(2026, 10, 1)
    for args in [("Ada", "a@b.c", 0), ("Ada", "a@b.c", -5), ("  ", "a@b.c", 365),
                 ("", "a@b.c", 365), ("Ada", "nope", 365)]:
        with pytest.raises(ValueError):
            issue_license.issue(private, args[0], args[1], today, args[2])


def _run(tmp_path, *a, password=TEST_PW):
    env = {**os.environ, "LGK_TEST_PW": password}
    return subprocess.run(
        [sys.executable, str(SCRIPT), *a, "--password-env", "LGK_TEST_PW"],
        cwd=tmp_path, capture_output=True, text=True, env=env,
    )


def test_cli_keygen_then_issue(tmp_path):
    pem = tmp_path / "license-key.pem"
    keygen = _run(tmp_path, "keygen", "--out", str(pem))
    assert keygen.returncode == 0, keygen.stderr
    assert re.search(r"[0-9a-f]{16}", keygen.stdout)
    with pytest.raises(TypeError):
        serialization.load_pem_private_key(pem.read_bytes(), password=None)
    out_file = tmp_path / "ada.lgklicense"
    issued = _run(
        tmp_path, "issue", "--key", str(pem), "--name", "Ada", "--email", "ada@example.com",
        "--issued", "2026-10-01", "--out", str(out_file),
    )
    assert issued.returncode == 0, issued.stderr
    assert issued.stdout.strip().startswith("LGK1-")
    bundle = licensing.parse_license_text(out_file.read_text(encoding="utf-8"))
    private = serialization.load_pem_private_key(pem.read_bytes(), password=TEST_PW.encode())
    assert licensing.verify_bundle(bundle, _keys(private)).updates_until == licensing.LIFETIME_UNTIL
    assert _run(tmp_path, "keygen", "--out", str(pem)).returncode != 0


def test_cli_wrong_password_and_bad_input(tmp_path):
    pem = tmp_path / "k.pem"
    assert _run(tmp_path, "keygen", "--out", str(pem)).returncode == 0
    base = ("issue", "--key", str(pem), "--email", "a@b.c")
    wrong = _run(tmp_path, *base, "--name", "Ada", password="wrong")
    assert wrong.returncode != 0 and "decrypted" in wrong.stderr
    assert "Traceback" not in wrong.stderr
    bad = _run(tmp_path, *base, "--name", " ", "--days", "0")
    assert bad.returncode != 0 and "error:" in bad.stderr
    assert "Traceback" not in bad.stderr


def test_issue_defaults_to_lifetime():
    private = ed25519.Ed25519PrivateKey.generate()
    bundle = issue_license.issue(private, "Ada", "ada@example.com", dt.date(2026, 10, 1))
    assert bundle["license"]["updates_until"] == "9999-12-31"
    lic = licensing.verify_bundle(bundle, _keys(private))
    assert licensing.covers(dt.date(2500, 1, 1), lic)


def test_cli_days_override(tmp_path):
    pem = tmp_path / "license-key.pem"
    assert _run(tmp_path, "keygen", "--out", str(pem)).returncode == 0
    out_file = tmp_path / "ada.lgklicense"
    issued = _run(
        tmp_path, "issue", "--key", str(pem), "--name", "Ada", "--email", "ada@example.com",
        "--issued", "2026-10-01", "--days", "365", "--out", str(out_file),
    )
    assert issued.returncode == 0, issued.stderr
    bundle = licensing.parse_license_text(out_file.read_text(encoding="utf-8"))
    assert bundle["license"]["updates_until"] == "2027-10-01"
