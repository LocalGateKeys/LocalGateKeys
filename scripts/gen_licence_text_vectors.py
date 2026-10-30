"""Generate ``tests/vectors/sync/mac/licence_text.json``: licence paste text and install links.

Test-only.  ``licensing.parse_license_text``, ``licensing.verify_bundle`` and
``licence_link.key_from_link`` run unmodified on every case; the Swift ``LicenceText`` must give the
same outcome.  The licences are signed with the TEST key of ``license_state.json`` (seed
``licence-test-key``) or, for ``unknown_key``, a second TEST key the reader does not know.

Usage::

    python scripts/gen_licence_text_vectors.py [OUT_FILE]   # default: tests/vectors/sync/mac/licence_text.json
"""

# ruff: noqa: S101

from __future__ import annotations

import base64
import hashlib
import json
import sys
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.asymmetric import ed25519

from localvault import licence_link, licensing
from localvault.updates import canonical_json

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_OUT = ROOT / "tests" / "vectors" / "sync" / "mac" / "licence_text.json"


def _seed(label: str) -> bytes:
    # Same derivation as make_sync_vectors.seed.
    return hashlib.sha256(b"lgk-sync-vectors|seed|" + label.encode("ascii")).digest()


def _b64(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")


def _signed(private: ed25519.Ed25519PrivateKey, **over: Any) -> dict[str, Any]:
    key_id = hashlib.sha256(private.public_key().public_bytes_raw()).digest()[:8].hex()
    lic = {"format": 1, "license_id": "lic-vector-0001", "edition": "pro", "name": "Ada Lovelace",
           "email": "ada@example.com", "issued_at": "2026-09-21", "updates_until": "2027-09-21", **over}
    return {"license": lic, "signature": {"alg": "Ed25519", "key_id": key_id,
                                          "signature": _b64(private.sign(canonical_json(lic)))}}


def _outcome(text: str, keys: dict[str, str]) -> dict[str, Any]:
    try:
        bundle = licensing.parse_license_text(text)
    except licensing.LicenseError as exc:
        return {"parse": exc.reason}
    try:
        lic = licensing.verify_bundle(bundle, keys=keys)
    except licensing.LicenseError as exc:
        return {"parse": "ok", "verify": exc.reason}
    return {"parse": "ok", "verify": "ok", "license_id": lic.license_id, "holder_name": lic.name, "holder_email": lic.email}


def build() -> bytes:
    private = ed25519.Ed25519PrivateKey.from_private_bytes(_seed("licence-test-key"))
    other = ed25519.Ed25519PrivateKey.from_private_bytes(_seed("licence-other-test-key"))
    raw = private.public_key().public_bytes_raw()
    key_id = hashlib.sha256(raw).digest()[:8].hex()
    keys = {key_id: _b64(raw)}

    good = _signed(private)
    paste = licensing.encode_paste(good)
    same_holder = _signed(private, license_id="lic-vector-0002", name="ada@example.com")
    tampered = json.loads(json.dumps(good))
    tampered["license"]["name"] = "Mallory"
    body = paste[len(licensing.PASTE_PREFIX):]
    wrapped = licensing.PASTE_PREFIX + "\n".join(body[i:i + 60] for i in range(0, len(body), 60))

    texts: list[tuple[str, str]] = [
        ("paste", paste),
        ("paste_wrapped_and_spaced", "  " + wrapped.replace("\n", " \r\n\t") + "  \n"),
        ("paste_trailing_dot", paste + "."),
        ("paste_bom", "﻿" + paste),
        ("json_file", json.dumps(good, indent=2)),
        ("json_file_trailing_dot", canonical_json(good).decode() + "."),
        ("same_holder_name", licensing.encode_paste(same_holder)),
        ("newer_issued", licensing.encode_paste(_signed(private, license_id="lic-vector-0003", issued_at="2026-10-01"))),
        ("bad_signature", licensing.encode_paste(tampered)),
        ("unknown_key", licensing.encode_paste(_signed(other))),
        ("bad_alg", licensing.encode_paste({**good, "signature": {**good["signature"], "alg": "RSA"}})),
        ("extra_field", licensing.encode_paste({**good, "extra": 1})),
        ("bad_length", paste + "A" * ((1 - len(body)) % 4)),
        ("not_utf8", licensing.PASTE_PREFIX + base64.urlsafe_b64encode(b"\xff\xfe{}").decode().rstrip("=")),
        ("not_json_paste", licensing.PASTE_PREFIX + base64.urlsafe_b64encode(b"hello").decode().rstrip("=")),
        ("not_json", "hello"),
        ("json_array", "[1, 2]"),
        ("duplicate_field", '{"license": {}, "license": {}, "signature": {}}'),
        ("empty", "   "),
    ]
    text_cases = [{"name": n, "text": t, **_outcome(t, keys)} for n, t in texts]

    def link_case(name: str, link: str) -> dict[str, Any]:
        try:
            key = licence_link.key_from_link(link)
        except licensing.LicenseError as exc:
            return {"name": name, "link": link, "key": None, "error": exc.reason}
        return {"name": name, "link": link, "key": key, **_outcome(key, keys)}

    prefix = licence_link.INSTALL_PREFIX
    oversize = prefix + paste + "/" * (licence_link.MAX_LINK_CHARS - len(prefix) - len(paste) + 1)
    at_limit = oversize[:-1]
    links = [
        link_case("link", prefix + paste),
        link_case("link_trailing_slash", prefix + paste + "/"),
        link_case("link_upper_scheme", "LocalGateKeys://Install-Licence/" + paste),
        link_case("link_percent_encoded", prefix + paste.replace("-", "%2D", 1)),
        link_case("link_at_limit", at_limit),
        link_case("link_oversize", oversize),
        link_case("link_bad_signature", prefix + licensing.encode_paste(tampered)),
        link_case("link_unknown_key", prefix + licensing.encode_paste(_signed(other))),
        link_case("link_wrong_host", "localgatekeys://install-license/" + paste),
        link_case("link_other_scheme", "https://localgatekeys.com/install-licence/" + paste),
        link_case("link_not_a_key", prefix + "hello"),
        link_case("link_empty", prefix),
    ]
    assert len(at_limit) == licence_link.MAX_LINK_CHARS and len(oversize) == licence_link.MAX_LINK_CHARS + 1

    doc = {
        "WARNING": "TEST ONLY. Signed with the TEST licence keys of license_state.json; production keys never verify them.",
        "key_id": key_id,
        "public_key_b64": _b64(raw),
        "max_link_chars": licence_link.MAX_LINK_CHARS,
        "texts": text_cases,
        "links": links,
        "note": "texts: parse is 'ok' or the parse_license_text reason; verify (with only key_id known) is 'ok' or "
        "the verify_bundle reason. links: key is what key_from_link returns (then parsed and verified like a "
        "text), or null with error 'bad-link'.",
    }
    return (json.dumps(doc, indent=2, ensure_ascii=False, sort_keys=True) + "\n").encode("utf-8")


def main(argv: list[str]) -> int:
    out = Path(argv[1]) if len(argv) > 1 else DEFAULT_OUT
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_bytes(build())
    print(f"wrote {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
