#!/usr/bin/env python3
"""Pipe the licence signing key into the licence Worker's LICENSE_PRIVATE_KEY secret.

The key file made by ``issue_license.py keygen`` is a password-protected PEM.
The Worker wants the unencrypted PKCS8 DER, base64-encoded. This script
decrypts the key, checks its key id against the one the app trusts, and
writes the base64 to stdout only when stdout is a pipe, so the key never
appears on screen:

    python scripts\\export_license_key_for_worker.py C:\\path\\to\\key.pem ^
      | npx wrangler secret put LICENSE_PRIVATE_KEY --config cloudflare\\license-issuer\\wrangler.jsonc

The password is read with getpass on the terminal, or from the environment
variable named by ``--password-env``.
"""

from __future__ import annotations

import argparse
import base64
import getpass
import hashlib
import os
import sys
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

# Key id of the licence public key in localvault.licensing.LICENSE_KEYS (2026-10-19).
EXPECTED_KEY_ID = "9f76e21ed03c0482"
# Release (update-signing) keys look identical on disk; never upload one. 6a892769c82386b3 is
# current (0.4.4+), 2c85b99e44279161 the lost one 0.4.0-0.4.3 trusted.
RELEASE_KEY_IDS = frozenset({"6a892769c82386b3", "2c85b99e44279161"})


def key_id_for(public_raw: bytes) -> str:
    return hashlib.sha256(public_raw).digest()[:8].hex()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("key_file", help="the licence signing key PEM from issue_license.py keygen")
    parser.add_argument("--password-env", help="read the key password from this environment variable")
    parser.add_argument("--expect", default=EXPECTED_KEY_ID, help=f"required key id (default {EXPECTED_KEY_ID})")
    args = parser.parse_args(argv)

    if sys.stdout.isatty():
        print("error: refusing to print the private key to the screen; pipe it into "
              "'npx wrangler secret put LICENSE_PRIVATE_KEY ...' instead.", file=sys.stderr)
        return 2

    pem = Path(args.key_file).read_bytes()
    if args.password_env:
        password = os.environ.get(args.password_env, "")
    else:
        # getpass prompts on the console, not on the piped stdout.
        password = getpass.getpass("Licence key password: ", stream=sys.stderr)
    try:
        key = serialization.load_pem_private_key(pem, password=password.encode("utf-8") or None)
    except (ValueError, TypeError) as exc:
        print(f"error: could not open the key ({exc}). Wrong password or not a key file?", file=sys.stderr)
        return 1
    if not isinstance(key, ed25519.Ed25519PrivateKey):
        print("error: this is not an Ed25519 key.", file=sys.stderr)
        return 1

    raw = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    key_id = key_id_for(raw)
    if key_id in RELEASE_KEY_IDS:
        print(f"error: this is the RELEASE key ({key_id}), not the licence key. Nothing was written.", file=sys.stderr)
        return 1
    if key_id != args.expect:
        print(f"error: key id {key_id} is not the licence key the app trusts ({args.expect}). "
              "Nothing was written.", file=sys.stderr)
        return 1

    der = key.private_bytes(serialization.Encoding.DER, serialization.PrivateFormat.PKCS8,
                            serialization.NoEncryption())
    sys.stdout.write(base64.b64encode(der).decode("ascii"))
    sys.stdout.flush()
    print(f"OK: licence key {key_id} sent to the pipe.", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
