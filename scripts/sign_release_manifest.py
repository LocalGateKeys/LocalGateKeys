#!/usr/bin/env python
"""Publisher tooling for LocalGateKeys signed release manifests.

Self-contained (standard library + ``cryptography``) so that it can run on an
offline signing machine without the application installed.

Commands
--------
keygen   Create a password-protected Ed25519 private key (PEM) and print the
         base64 public key plus its key_id for ``localvault.updates.PUBLISHER_KEYS``.
sign     Validate a manifest, optionally fill artifact hashes/sizes and the
         sequence number, and write the signed bundle served at RELEASE_FEED_URL.
verify   Check a signed bundle against a base64 public key.
revocations
         Sign a list of revoked licence ids (one per line) into the revocations.json
         bundle served next to the release feed. Same key and bundle shape.

The signature covers the canonical JSON of the manifest: keys sorted, no
whitespace, UTF-8, exactly as ``localvault.updates.canonical_json`` produces.
See docs/UPDATES.md for the full workflow.
"""

from __future__ import annotations

import argparse
import base64
import getpass
import hashlib
import json
import os
import re
import sys
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import urlsplit

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

MANIFEST_FORMAT = "localgatekeys-release-manifest"
MANIFEST_FORMAT_VERSION = 1
SIGNATURE_ALGORITHM = "Ed25519"
MANIFEST_FIELDS = frozenset(
    {"format", "version", "app_version", "published", "min_supported_version",
     "notes_url", "artifacts", "sequence"}
)
LICENSE_ID_PATTERN = re.compile(r"^lgk_[0-9A-HJKMNP-TV-Z]{26}$")
MAX_REVOCATION_IDS = 10000
ARTIFACT_FIELDS = frozenset({"name", "sha256", "size", "url"})
VERSION_PATTERN = re.compile(r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$")
SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")
ARTIFACT_NAME_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")


class ManifestError(ValueError):
    """The manifest or bundle does not satisfy the signed-manifest contract."""


# ---------------------------------------------------------------------------
# Shared helpers (kept byte-for-byte compatible with localvault.updates)
# ---------------------------------------------------------------------------


def canonical_json(value: object) -> bytes:
    return json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False
    ).encode("utf-8")


def key_id_for(public_raw: bytes) -> str:
    return hashlib.sha256(public_raw).digest()[:8].hex()


def _is_int(value: object) -> bool:
    return type(value) is int


def _check_version(value: object, field: str) -> None:
    if not isinstance(value, str) or VERSION_PATTERN.fullmatch(value) is None:
        raise ManifestError(f"{field} must be a version in x.y.z form")


def _check_https_url(value: object, field: str) -> None:
    if not isinstance(value, str) or not value or len(value) > 2048:
        raise ManifestError(f"{field} must be an HTTPS URL")
    parsed = urlsplit(value)
    try:
        port = parsed.port
    except ValueError as exc:
        raise ManifestError(f"{field} has an invalid port") from exc
    if (
        parsed.scheme.lower() != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.fragment
        or port == 0
    ):
        raise ManifestError(f"{field} must be an HTTPS URL without credentials or fragments")


def _check_published(value: object) -> None:
    if not isinstance(value, str) or "T" not in value or len(value) > 64:
        raise ManifestError("published must be an RFC 3339 timestamp with a UTC offset")
    text = value[:-1] + "+00:00" if value.endswith(("Z", "z")) else value
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError as exc:
        raise ManifestError("published must be an RFC 3339 timestamp with a UTC offset") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ManifestError(
            "published must include a UTC offset (for example 2026-10-05T12:00:00Z)"
        )


def validate_manifest(manifest: object) -> None:
    if type(manifest) is not dict:
        raise ManifestError("manifest must be a JSON object")
    missing = MANIFEST_FIELDS - set(manifest)
    extra = set(manifest) - MANIFEST_FIELDS
    if missing:
        raise ManifestError(f"manifest is missing fields: {', '.join(sorted(missing))}")
    if extra:
        raise ManifestError(f"manifest has unsupported fields: {', '.join(sorted(extra))}")
    if manifest["format"] != MANIFEST_FORMAT:
        raise ManifestError(f"format must be {MANIFEST_FORMAT!r}")
    if not _is_int(manifest["version"]) or manifest["version"] != MANIFEST_FORMAT_VERSION:
        raise ManifestError(f"version must be the integer {MANIFEST_FORMAT_VERSION}")
    _check_version(manifest["app_version"], "app_version")
    _check_version(manifest["min_supported_version"], "min_supported_version")
    _check_published(manifest["published"])
    _check_https_url(manifest["notes_url"], "notes_url")
    if not _is_int(manifest["sequence"]) or manifest["sequence"] < 0:
        raise ManifestError("sequence must be a non-negative integer")
    artifacts = manifest["artifacts"]
    if type(artifacts) is not list:
        raise ManifestError("artifacts must be a list")
    for index, artifact in enumerate(artifacts):
        where = f"artifacts[{index}]"
        if type(artifact) is not dict or set(artifact) != ARTIFACT_FIELDS:
            raise ManifestError(f"{where} must have exactly the fields name, sha256, size, url")
        name = artifact["name"]
        if not isinstance(name, str) or ARTIFACT_NAME_PATTERN.fullmatch(name) is None:
            raise ManifestError(f"{where}.name must be a plain file name")
        digest = artifact["sha256"]
        if not isinstance(digest, str) or SHA256_PATTERN.fullmatch(digest) is None:
            raise ManifestError(f"{where}.sha256 must be 64 lowercase hex characters")
        if not _is_int(artifact["size"]) or artifact["size"] < 0:
            raise ManifestError(f"{where}.size must be a non-negative integer")
        _check_https_url(artifact["url"], f"{where}.url")


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ManifestError(f"duplicate field {key!r}")
        result[key] = value
    return result


def load_json(path: Path) -> object:
    try:
        return json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=_unique_object)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ManifestError(f"could not read JSON from {path}: {exc}") from exc


def read_password(env_name: str | None, *, confirm: bool) -> bytes:
    if env_name:
        value = os.environ.get(env_name)
        if value is None:
            raise ManifestError(f"environment variable {env_name} is not set")
    else:
        value = getpass.getpass("Key password: ")
        if confirm and getpass.getpass("Confirm password: ") != value:
            raise ManifestError("passwords do not match")
    if not value:
        raise ManifestError("the key password must not be empty")
    return value.encode("utf-8")


def read_key_pem(path: str | None, env_name: str | None) -> bytes:
    """The encrypted private key PEM, from a file or an environment variable."""
    if env_name:
        value = os.environ.get(env_name)
        if not value:
            raise ManifestError(f"environment variable {env_name} is not set")
        return value.strip().encode("ascii", errors="replace") + b"\n"
    try:
        return Path(path).read_bytes()
    except OSError as exc:
        raise ManifestError(f"could not read key file {path}: {exc}") from exc


def load_private_key(pem: bytes, password: bytes) -> ed25519.Ed25519PrivateKey:
    try:
        key = serialization.load_pem_private_key(pem, password=password)
    except (ValueError, TypeError) as exc:
        raise ManifestError(
            "the key could not be decrypted (wrong password or not a PEM key)"
        ) from exc
    if not isinstance(key, ed25519.Ed25519PrivateKey):
        raise ManifestError("the key is not an Ed25519 private key")
    return key


def public_raw(key: ed25519.Ed25519PrivateKey | ed25519.Ed25519PublicKey) -> bytes:
    public = key.public_key() if isinstance(key, ed25519.Ed25519PrivateKey) else key
    return public.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def write_atomically(path: Path, data: bytes, *, exclusive: bool = False) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if exclusive and path.exists():
        raise ManifestError(f"refusing to overwrite existing file {path}")
    temp = path.with_name(path.name + ".tmp")
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_BINARY", 0)
    fd = os.open(temp, flags, 0o600)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        if exclusive and path.exists():
            raise ManifestError(f"refusing to overwrite existing file {path}")
        os.replace(temp, path)
    finally:
        if temp.exists():
            temp.unlink()


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------


def cmd_keygen(args: argparse.Namespace) -> int:
    out = Path(args.out) if args.out else None
    if out is not None and out.exists():
        raise ManifestError(f"refusing to overwrite existing key file {out}")
    password = read_password(args.password_env, confirm=True)
    key = ed25519.Ed25519PrivateKey.generate()
    pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.BestAvailableEncryption(password),
    )
    raw = public_raw(key)
    result = {
        "public_key": base64.b64encode(raw).decode("ascii"),
        "key_id": key_id_for(raw),
    }
    if out is None:
        # --print-key: the encrypted PEM is the only thing on stdout so it can
        # be piped straight to the clipboard (`| clip`) and pasted into a
        # password manager; no key file is ever written.
        sys.stdout.write(pem.decode("ascii"))
        print(json.dumps(result, indent=2), file=sys.stderr)
    else:
        write_atomically(out, pem, exclusive=True)
        result["key_file"] = str(out)
        print(json.dumps(result, indent=2))
    print(
        "\nAdd to localvault/updates.py:  PUBLISHER_KEYS = "
        f'{{"{result["key_id"]}": "{result["public_key"]}"}}',
        file=sys.stderr,
    )
    return 0


def cmd_sign(args: argparse.Namespace) -> int:
    manifest = load_json(Path(args.manifest))
    if type(manifest) is not dict:
        raise ManifestError("manifest must be a JSON object")
    if args.sequence is not None:
        manifest["sequence"] = args.sequence
    if args.published:
        manifest["published"] = args.published
    for artifact_path in args.artifact or []:
        path = Path(artifact_path)
        if not path.is_file():
            raise ManifestError(f"artifact not found: {path}")
        matches = [
            a
            for a in manifest.get("artifacts", [])
            if type(a) is dict and a.get("name") == path.name
        ]
        if not matches:
            raise ManifestError(f"no manifest artifact is named {path.name!r}")
        digest = hashlib.sha256()
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
        for artifact in matches:
            artifact["sha256"] = digest.hexdigest()
            artifact["size"] = path.stat().st_size
    validate_manifest(manifest)

    password = read_password(args.password_env, confirm=False)
    key = load_private_key(read_key_pem(args.key, args.key_env), password)
    raw = public_raw(key)
    signature = key.sign(canonical_json(manifest))
    bundle = {
        "manifest": manifest,
        "signature": {
            "alg": SIGNATURE_ALGORITHM,
            "key_id": key_id_for(raw),
            "signature": base64.b64encode(signature).decode("ascii"),
        },
    }
    out = Path(args.out)
    write_atomically(out, json.dumps(bundle, indent=2, ensure_ascii=False).encode("utf-8") + b"\n")
    print(
        f"signed {args.manifest} -> {out} (app_version {manifest['app_version']}, "
        f"sequence {manifest['sequence']}, key_id {bundle['signature']['key_id']})"
    )
    return 0


def read_revoked_ids(path: Path) -> list[str]:
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeDecodeError) as exc:
        raise ManifestError(f"could not read ids file {path}: {exc}") from exc
    ids: list[str] = []
    for number, line in enumerate(lines, start=1):
        text = line.strip()
        if not text or text.startswith("#"):
            continue
        if LICENSE_ID_PATTERN.fullmatch(text) is None:
            raise ManifestError(f"{path}:{number}: not a licence id (lgk_ + 26 characters)")
        ids.append(text)
    ids = sorted(set(ids))
    if len(ids) > MAX_REVOCATION_IDS:
        raise ManifestError(f"at most {MAX_REVOCATION_IDS} revoked ids are supported")
    return ids


def cmd_revocations(args: argparse.Namespace) -> int:
    ids = read_revoked_ids(Path(args.ids_file))
    published = args.published or datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    _check_published(published)
    manifest = {"format": 1, "published": published, "revoked": ids}
    password = read_password(args.password_env, confirm=False)
    key = load_private_key(read_key_pem(args.key, args.key_env), password)
    raw = public_raw(key)
    bundle = {
        "manifest": manifest,
        "signature": {
            "alg": SIGNATURE_ALGORITHM,
            "key_id": key_id_for(raw),
            "signature": base64.b64encode(key.sign(canonical_json(manifest))).decode("ascii"),
        },
    }
    out = Path(args.out)
    write_atomically(out, json.dumps(bundle, indent=2, ensure_ascii=False).encode("utf-8") + b"\n")
    print(f"signed {len(ids)} revoked id(s) -> {out} (published {published})")
    return 0


def verify_bundle(bundle: object, public_keys: dict[str, ed25519.Ed25519PublicKey]) -> dict:
    if type(bundle) is not dict or set(bundle) != {"manifest", "signature"}:
        raise ManifestError("bundle must contain exactly 'manifest' and 'signature'")
    block = bundle["signature"]
    if type(block) is not dict or set(block) != {"alg", "key_id", "signature"}:
        raise ManifestError("signature block must contain exactly alg, key_id, signature")
    if block["alg"] != SIGNATURE_ALGORITHM:
        raise ManifestError(f"signature alg must be {SIGNATURE_ALGORITHM}")
    key = public_keys.get(block["key_id"]) if isinstance(block["key_id"], str) else None
    if key is None:
        raise ManifestError(f"key_id {block['key_id']!r} does not match any provided public key")
    try:
        signature = base64.b64decode(block["signature"], validate=True)
    except (ValueError, TypeError) as exc:
        raise ManifestError("signature is not valid base64") from exc
    try:
        key.verify(signature, canonical_json(bundle["manifest"]))
    except InvalidSignature as exc:
        raise ManifestError("signature does not verify") from exc
    validate_manifest(bundle["manifest"])
    return bundle["manifest"]


def cmd_verify(args: argparse.Namespace) -> int:
    public_keys: dict[str, ed25519.Ed25519PublicKey] = {}
    for encoded in args.public_key:
        try:
            raw = base64.b64decode(encoded, validate=True)
            key = ed25519.Ed25519PublicKey.from_public_bytes(raw)
        except (ValueError, TypeError) as exc:
            raise ManifestError(
                "--public-key must be the base64 of a raw 32-byte Ed25519 key"
            ) from exc
        public_keys[key_id_for(raw)] = key
    manifest = verify_bundle(load_json(Path(args.bundle)), public_keys)
    print(
        f"OK: {args.bundle} verifies (app_version {manifest['app_version']}, "
        f"sequence {manifest['sequence']}, published {manifest['published']})"
    )
    return 0


ENV_FLAG_HELP = "read the key password from this environment variable instead of prompting"


def cmd_pubkey(args: argparse.Namespace) -> int:
    password = read_password(args.password_env, confirm=False)
    raw = public_raw(load_private_key(read_key_pem(args.key, args.key_env), password))
    result = {"public_key": base64.b64encode(raw).decode("ascii"), "key_id": key_id_for(raw)}
    print(json.dumps(result, indent=2))
    print(
        "PUBLISHER_KEYS entry: "
        f'{{"{result["key_id"]}": "{result["public_key"]}"}}',
    )
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    sub = parser.add_subparsers(dest="command", required=True)

    keygen = sub.add_parser("keygen", help="create a password-protected Ed25519 signing key")
    keygen_target = keygen.add_mutually_exclusive_group(required=True)
    keygen_target.add_argument("--out", help="path of the new private key PEM (must not exist)")
    keygen_target.add_argument(
        "--print-key",
        action="store_true",
        help="write the encrypted PEM to stdout instead of a file (public key goes to stderr)",
    )
    keygen.add_argument("--password-env", help=ENV_FLAG_HELP)
    keygen.set_defaults(func=cmd_keygen)

    sign = sub.add_parser("sign", help="validate and sign a release manifest")
    sign.add_argument("--manifest", required=True, help="unsigned manifest JSON")
    sign_key = sign.add_mutually_exclusive_group(required=True)
    sign_key.add_argument("--key", help="private key PEM file from keygen")
    sign_key.add_argument(
        "--key-env", help="environment variable holding the encrypted private key PEM text"
    )
    sign.add_argument("--out", required=True, help="where to write the signed bundle")
    sign.add_argument(
        "--artifact",
        action="append",
        help="artifact file whose sha256/size fill the entry with the same name (repeatable)",
    )
    sign.add_argument(
        "--sequence", type=int, help="monotonic release sequence to write into the manifest"
    )
    sign.add_argument("--published", help="RFC 3339 timestamp to write into the manifest")
    sign.add_argument("--password-env", help=ENV_FLAG_HELP)
    sign.set_defaults(func=cmd_sign)

    revocations = sub.add_parser(
        "revocations", help="sign the licence revocation list served next to the feed"
    )
    revocations_key = revocations.add_mutually_exclusive_group(required=True)
    revocations_key.add_argument("--key", help="private key PEM file from keygen")
    revocations_key.add_argument(
        "--key-env", help="environment variable holding the encrypted private key PEM text"
    )
    revocations.add_argument("--ids-file", required=True, help="text file, one licence id per line")
    revocations.add_argument("--out", required=True, help="where to write revocations.json")
    revocations.add_argument("--published", help="RFC 3339 timestamp (default: now, UTC)")
    revocations.add_argument("--password-env", help=ENV_FLAG_HELP)
    revocations.set_defaults(func=cmd_revocations)

    pubkey = sub.add_parser("pubkey", help="print the public key and key_id of a private key")
    pubkey_key = pubkey.add_mutually_exclusive_group(required=True)
    pubkey_key.add_argument("--key", help="private key PEM file from keygen")
    pubkey_key.add_argument(
        "--key-env", help="environment variable holding the encrypted private key PEM text"
    )
    pubkey.add_argument("--password-env", help=ENV_FLAG_HELP)
    pubkey.set_defaults(func=cmd_pubkey)

    verify = sub.add_parser("verify", help="verify a signed bundle")
    verify.add_argument("--bundle", required=True, help="signed bundle JSON")
    verify.add_argument(
        "--public-key",
        required=True,
        action="append",
        help="base64 raw Ed25519 public key (repeatable)",
    )
    verify.set_defaults(func=cmd_verify)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except ManifestError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
