#!/usr/bin/env python
"""Owner tooling for LocalGateKeys Pro licences.

Commands
--------
keygen   Create the licence signing key (Ed25519 PEM, owner-only) and print its
         key_id and base64 public key for ``localvault.licensing.LICENSE_KEYS``.
issue    Sign a Pro licence and print the ``LGK1-`` paste text; ``--out`` also
         writes the ``.lgklicense`` JSON file.

The licence signing key is NOT the release signing key. Keep it offline.
"""

from __future__ import annotations

import argparse
import base64
import datetime as dt
import getpass
import hashlib
import json
import os
import secrets
import sys
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

from localvault import config
from localvault.licensing import LIFETIME_UNTIL, encode_paste, verify_bundle
from localvault.updates import canonical_json

ENV_FLAG_HELP = "read the key password from this environment variable instead of prompting"
_CROCKFORD = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"


def key_id_for(public_raw: bytes) -> str:
    return hashlib.sha256(public_raw).digest()[:8].hex()


def public_raw(key: ed25519.Ed25519PrivateKey) -> bytes:
    return key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def new_license_id() -> str:
    """``lgk_`` + 26 Crockford base32 characters of 16 random bytes."""
    value = int.from_bytes(secrets.token_bytes(16), "big") << 2  # 128 -> 130 bits
    chars = [_CROCKFORD[(value >> shift) & 31] for shift in range(125, -1, -5)]
    return "lgk_" + "".join(chars)


def issue(
    private_key: ed25519.Ed25519PrivateKey,
    name: str,
    email: str,
    issued_at: dt.date,
    days: int | None = None,
) -> dict:
    if days is not None and (not isinstance(days, int) or isinstance(days, bool) or days < 1):
        raise ValueError("days must be a positive integer")
    if not isinstance(name, str) or not name.strip():
        raise ValueError("name must not be empty")
    if not isinstance(email, str) or "@" not in email:
        raise ValueError("email must contain '@'")
    lic = {
        "format": 1,
        "license_id": new_license_id(),
        "edition": "pro",
        "name": name,
        "email": email,
        "issued_at": issued_at.isoformat(),
        "updates_until": (
            LIFETIME_UNTIL if days is None else issued_at + dt.timedelta(days=days)
        ).isoformat(),
    }
    raw = public_raw(private_key)
    key_id = key_id_for(raw)
    bundle = {
        "license": lic,
        "signature": {
            "alg": "Ed25519",
            "key_id": key_id,
            "signature": base64.b64encode(private_key.sign(canonical_json(lic))).decode("ascii"),
        },
    }
    # Refuse to hand out anything the app would reject.
    verify_bundle(bundle, {key_id: base64.b64encode(raw).decode("ascii")})
    return bundle


def _read_password(env_name: str | None, *, confirm: bool) -> bytes:
    if env_name:
        value = os.environ.get(env_name)
        if value is None:
            raise SystemExit(f"error: environment variable {env_name} is not set")
    else:
        value = getpass.getpass("Key password: ")
        if confirm and getpass.getpass("Confirm password: ") != value:
            raise SystemExit("error: passwords do not match")
    if not value:
        raise SystemExit("error: the key password must not be empty")
    return value.encode("utf-8")


def _write_private(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
    try:
        fd = os.open(path, flags, 0o600)
    except FileExistsError:
        raise SystemExit(f"error: refusing to overwrite existing file {path}") from None
    with os.fdopen(fd, "wb") as handle:
        handle.write(data)
        handle.flush()
        os.fsync(handle.fileno())
    config._restrict_path(path)


def cmd_keygen(args: argparse.Namespace) -> int:
    out = Path(args.out)
    if out.exists():
        raise SystemExit(f"error: refusing to overwrite existing file {out}")
    password = _read_password(args.password_env, confirm=True)
    key = ed25519.Ed25519PrivateKey.generate()
    pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.BestAvailableEncryption(password),
    )
    _write_private(out, pem)
    raw = public_raw(key)
    key_id = key_id_for(raw)
    public = base64.b64encode(raw).decode("ascii")
    print(json.dumps({"key_id": key_id, "public_key": public, "key_file": str(out)}, indent=2))
    print(
        f'\nAdd to localvault/licensing.py:  LICENSE_KEYS = {{"{key_id}": "{public}"}}',
        file=sys.stderr,
    )
    return 0


def cmd_issue(args: argparse.Namespace) -> int:
    password = _read_password(args.password_env, confirm=False)
    try:
        key = serialization.load_pem_private_key(Path(args.key).read_bytes(), password=password)
    except OSError as exc:
        raise SystemExit(f"error: could not read key {args.key}: {exc}") from None
    except (ValueError, TypeError):
        raise SystemExit(
            "error: the key could not be decrypted (wrong password or not a PEM key)"
        ) from None
    if not isinstance(key, ed25519.Ed25519PrivateKey):
        raise SystemExit("error: the key is not an Ed25519 private key")
    try:
        issued_at = dt.date.fromisoformat(args.issued) if args.issued else dt.date.today()
    except ValueError:
        raise SystemExit("error: --issued must be YYYY-MM-DD") from None
    try:
        bundle = issue(key, args.name, args.email, issued_at, args.days)
    except ValueError as exc:
        raise SystemExit(f"error: {exc}") from None
    if args.out:
        out = Path(args.out)
        out.parent.mkdir(parents=True, exist_ok=True)
        config.atomic_write_json(out, bundle)
    print(encode_paste(bundle))
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    sub = parser.add_subparsers(dest="command", required=True)

    keygen = sub.add_parser("keygen", help="create the licence signing key")
    keygen.add_argument("--out", required=True, help="new private key PEM (must not exist)")
    keygen.add_argument("--password-env", help=ENV_FLAG_HELP)
    keygen.set_defaults(func=cmd_keygen)

    issue_cmd = sub.add_parser("issue", help="sign a Pro licence")
    issue_cmd.add_argument("--key", required=True, help="private key PEM from keygen")
    issue_cmd.add_argument("--name", required=True)
    issue_cmd.add_argument("--email", required=True)
    issue_cmd.add_argument(
        "--days", type=int, default=None, help="limit updates to N days (default: lifetime)"
    )
    issue_cmd.add_argument("--issued", help="issue date YYYY-MM-DD (default today)")
    issue_cmd.add_argument("--out", help="also write the .lgklicense file here")
    issue_cmd.add_argument("--password-env", help=ENV_FLAG_HELP)
    issue_cmd.set_defaults(func=cmd_issue)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
