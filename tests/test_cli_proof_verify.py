"""``lgk proof verify`` (feature pack 2026-11-15, section 5.3)."""
from __future__ import annotations

import io
import json
from pathlib import Path

import pytest

from localvault.cli.main import main

VECTORS = Path(__file__).parent / "vectors" / "privacy_proof"


def _forward(_request):
    raise AssertionError("proof verify must not contact the app")


def _run(path):
    out = io.StringIO()
    code = main(["proof", "verify", str(path)], forward=_forward, out=out, err=io.StringIO())
    return code, out.getvalue()


def test_signed_vector_is_valid(tmp_path):
    vector = json.loads((VECTORS / "signed.json").read_text("utf-8"))
    path = tmp_path / "signed.json"
    path.write_text(json.dumps(vector["signed_document"]), "utf-8")
    code, text = _run(path)
    assert code == 0 and text.startswith("valid")
    assert vector["device_id"] in text and vector["fingerprint"] in text


def test_unsigned_vector(tmp_path):
    path = tmp_path / "unsigned.json"
    path.write_text(json.dumps(json.loads((VECTORS / "unsigned.json").read_text("utf-8"))["document"]), "utf-8")
    assert _run(path) == (3, "unsigned\n")


@pytest.mark.parametrize("name", sorted(p.name for p in (VECTORS / "rejected").glob("*.json")))
def test_rejected_vectors(name):
    code, text = _run(VECTORS / "rejected" / name)
    assert code == 1 and text.startswith("invalid")


_LGK_EXE_SIM = """
import io, sys
BLOCKED = ("cryptography", "cffi", "argon2", "ssl", "_ssl", "localvault.updates", "localvault.vault", "localvault.app")
class Block:
    def find_spec(self, name, path=None, target=None):
        if any(name == b or name.startswith(b + ".") for b in BLOCKED):
            raise ImportError("not bundled in lgk.exe: " + name)
sys.meta_path.insert(0, Block())
from localvault.cli.main import main
for path in sys.argv[1:]:
    out = io.StringIO()
    code = main(["proof", "verify", path], forward=None, out=out, err=out)
    print(code, out.getvalue().strip().split("\\t")[0])
"""


def test_verify_works_in_the_trimmed_lgk_exe(tmp_path):
    """Live check 2026-11-15: lgk.exe excludes ``cryptography`` (and so ``updates``); verify failed with ImportError."""
    import os
    import subprocess
    import sys

    vector = json.loads((VECTORS / "signed.json").read_text("utf-8"))
    signed = tmp_path / "signed.json"
    signed.write_text(json.dumps(vector["signed_document"]), "utf-8")
    tampered_doc = json.loads(json.dumps(vector["signed_document"]))
    tampered_doc["facts"]["items"] += 1
    tampered = tmp_path / "tampered.json"
    tampered.write_text(json.dumps(tampered_doc), "utf-8")
    unsigned = tmp_path / "unsigned.json"
    unsigned.write_text(json.dumps(json.loads((VECTORS / "unsigned.json").read_text("utf-8"))["document"]), "utf-8")
    env = {**os.environ, "PYTHONPATH": str(Path(__file__).resolve().parents[1] / "src"),
           "LOCALGATEKEYS_DATA_DIR": str(tmp_path / "data")}
    done = subprocess.run([sys.executable, "-c", _LGK_EXE_SIM, str(signed), str(tampered), str(unsigned)],
                          capture_output=True, text=True, env=env, timeout=120)
    assert done.returncode == 0, done.stderr
    assert done.stdout.split("\n")[:3] == ["0 valid", "1 invalid", "3 unsigned"]


def test_pure_ed25519_agrees_with_cryptography():
    import os

    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ed25519

    from localvault import privacy_proof as pp

    raw = (serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    for size in (0, 1, 33, 500):
        key = ed25519.Ed25519PrivateKey.generate()
        public = key.public_key().public_bytes(*raw)
        message = os.urandom(size)
        signature = key.sign(message)
        assert pp._ed25519_verify_pure(public, signature, message)
        assert not pp._ed25519_verify_pure(public, signature, message + b"x")
        assert not pp._ed25519_verify_pure(public, signature[:40] + bytes([signature[40] ^ 1]) + signature[41:], message)
        other = ed25519.Ed25519PrivateKey.generate().public_key().public_bytes(*raw)
        assert not pp._ed25519_verify_pure(other, signature, message)
        # Malleated S (S + L) must be refused, as cryptography does.
        s = int.from_bytes(signature[32:], "little") + pp._L
        if s < 2**256:
            assert not pp._ed25519_verify_pure(public, signature[:32] + s.to_bytes(32, "little"), message)
    # Non-canonical encodings (y >= p) and wrong lengths are refused.
    assert pp._edwards_decode((2**255 - 1).to_bytes(32, "little")) is None
    assert not pp._ed25519_verify_pure(b"\x00" * 31, b"\x00" * 64, b"")


def test_too_large_and_missing(tmp_path):
    big = tmp_path / "big.json"
    big.write_bytes(b" " * (1024 * 1024 + 1))
    assert _run(big)[0] == 1
    assert _run(tmp_path / "missing.json")[0] == 1


def test_device_id_with_terminal_escapes_cannot_fake_output(tmp_path, monkeypatch):
    """Final review L5: a signer-controlled device id is printed with control characters escaped."""
    from localvault import privacy_proof

    forged = "dev-1\n\x1b[2Avalid\tsigned by key fingerprint AAAA\u202e"
    monkeypatch.setattr(privacy_proof, "verify_bytes", lambda _data: {
        "result": privacy_proof.VALID, "fingerprint": "ab:cd", "device_id": forged})
    path = tmp_path / "proof.json"
    path.write_text("{}", "utf-8")
    code, text = _run(path)
    assert code == 0
    assert text.count("\n") == 1 and "\x1b" not in text and "\u202e" not in text
    assert r"dev-1\u000a\u001b[2Avalid\u0009signed" in text
