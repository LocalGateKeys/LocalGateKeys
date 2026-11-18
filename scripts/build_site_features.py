#!/usr/bin/env python3
"""Build the bundled site-features table (which sites support TOTP and passkeys), deterministically.

Sources (both free to redistribute with attribution, recorded in the output under "sources"):
  TOTP      https://api.2fa.directory/v3/totp.json            2factorauth/twofactorauth, MIT licence
  passkeys  https://passkeys-api.2fa.directory/v1/supported.json   2factorauth/passkeys, CC BY 4.0

Every domain is reduced to its registrable domain (localvault.origin.base_domain). Writes

  src/localvault/assets/site_features.json         {"format","version","generated","sources","sites":{domain:[...]}}
  android/app/src/main/assets/site_features.json   byte copy (the iPhone and Mac read the first file)

Usage:
  python scripts/build_site_features.py                    fetch the sources and write both files
  python scripts/build_site_features.py --from-cache DIR   read DIR/totp.json and DIR/passkeys.json instead
  python scripts/build_site_features.py --check            offline: only verify that the copies match
Reruns on the same input and the same day change nothing; "generated" is the only moving part.
"""
import argparse
import datetime
import json
import sys
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))
from localvault.origin import base_domain  # noqa: E402

TARGET = ROOT / "src/localvault/assets/site_features.json"
ANDROID = ROOT / "android/app/src/main/assets/site_features.json"
TOTP_URL = "https://api.2fa.directory/v3/totp.json"
PASSKEY_URL = "https://passkeys-api.2fa.directory/v1/supported.json"
SOURCES = {
    "totp": {"url": TOTP_URL, "licence": "MIT", "licenceUrl": "https://github.com/2factorauth/twofactorauth/blob/master/LICENSE.md"},
    "passkey": {"url": PASSKEY_URL, "licence": "CC BY 4.0", "licenceUrl": "https://github.com/2factorauth/passkeys/blob/master/LICENSE.md"},
}


def fetch(url: str) -> bytes:
    request = urllib.request.Request(url, headers={"User-Agent": "LocalGateKeys-build-site-features"})
    with urllib.request.urlopen(request, timeout=60) as response:
        return response.read()


def registrable(domain: object) -> str | None:
    if not isinstance(domain, str):
        return None
    host = domain.strip().lower().rstrip(".")
    if not host or "/" in host or ":" in host or " " in host:
        return None
    try:
        host = host.encode("idna").decode("ascii")
        result = base_domain(host)
    except (UnicodeError, ValueError, Exception):
        return None
    return result if "." in result else None


def build(totp_raw: bytes, passkey_raw: bytes, generated: str) -> dict:
    sites: dict[str, set[str]] = {}
    for _name, entry in json.loads(totp_raw):
        if "totp" not in entry.get("tfa", []):
            continue
        for domain in [entry.get("domain"), *entry.get("additional-domains", [])]:
            key = registrable(domain)
            if key:
                sites.setdefault(key, set()).add("totp")
    for domain, entry in json.loads(passkey_raw).items():
        if "allowed" in (entry.get("passwordless"), entry.get("mfa")) or "required" in (entry.get("passwordless"), entry.get("mfa")):
            key = registrable(domain)
            if key:
                sites.setdefault(key, set()).add("passkey")
    return {"format": "localgatekeys-site-features", "version": 1, "generated": generated, "sources": SOURCES,
            "sites": {key: sorted(sites[key]) for key in sorted(sites)}}


def write(data: dict) -> None:
    text = json.dumps(data, sort_keys=True, ensure_ascii=True, separators=(",", ":")) + "\n"
    for path in (TARGET, ANDROID):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(text.encode("ascii"))
    print(f"wrote {len(data['sites'])} sites, {len(text)} bytes")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--check", action="store_true", help="offline: verify the Android copy matches")
    parser.add_argument("--from-cache", metavar="DIR", help="read DIR/totp.json and DIR/passkeys.json")
    args = parser.parse_args()
    if args.check:
        if not TARGET.is_file() or TARGET.read_bytes() != ANDROID.read_bytes():
            print("site_features.json copies differ: run scripts/build_site_features.py", file=sys.stderr)
            return 1
        print("copies match")
        return 0
    if args.from_cache:
        cache = Path(args.from_cache)
        totp_raw, passkey_raw = (cache / "totp.json").read_bytes(), (cache / "passkeys.json").read_bytes()
    else:
        totp_raw, passkey_raw = fetch(TOTP_URL), fetch(PASSKEY_URL)
    write(build(totp_raw, passkey_raw, datetime.date.today().isoformat()))
    return 0


if __name__ == "__main__":
    sys.exit(main())
