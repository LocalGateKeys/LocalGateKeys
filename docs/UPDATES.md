# Signed release manifests (update checks)

LocalGateKeys performs **manual, metadata-only** update checks. The client
fetches one small signed JSON document, verifies it with a publisher key that
is compiled into the application, compares versions, and offers to open the
release-notes page in the browser. It never downloads or runs an installer.

Everything lives in `src/localvault/updates.py` (client), `src/localvault/version.py`
(`APP_VERSION`, `BUILD_DATE`), `scripts/sign_release_manifest.py` (publisher
tooling) and `tests/test_updates.py`.

## Current state: configured

`RELEASE_FEED_URL` is `https://updates.localgatekeys.app/stable.json` (the
`lgk-updates` Worker's custom domain, added 2026-10-15). Version 0.4.0 shipped
with `https://lgk-updates.<account>.workers.dev/stable.json`; that address was
switched off on 2026-10-24 (`workers_dev: false`) because no client uses 0.4.0. `PUBLISHER_KEYS`
trusts key_id `6a892769c82386b3` since 0.4.4 (private key held offline by the
publisher, created with `keygen --print-key` on 2026-10-23).

Versions 0.4.0 to 0.4.3 trusted key_id `2c85b99e44279161`, whose private half
was lost after it signed the 0.4.0 feed. Once the feed is signed with
the new key they report that it could not be verified, and must install 0.4.4
by hand once.

Builds before 0.4.0 trusted key_id `18a42ce22228ca9d`, whose private half was
lost before any manifest was published. Those builds cannot verify the feed
and must install 0.4.0 by hand once. To print the public half of a key you
hold, run `sign_release_manifest.py pubkey --key-env LGK_RELEASE_KEY`.

If either value is emptied again, the check is "not configured": in that state
`updates.release_configuration()` returns `None`, nothing touches the network,
and the UI reports *"Update checks are not configured yet."* Both values must be
set for checks to run; either one missing fails closed to "not configured".
MSIX builds (Microsoft Store or sideloaded package) are updated by their
channel instead: the UI says who installs updates (`managed_update_channel()`).

## Manifest format

The feed serves a **signed bundle**:

```json
{
  "manifest": {
    "format": "localgatekeys-release-manifest",
    "version": 1,
    "app_version": "0.4.0",
    "published": "2026-10-05T12:00:00Z",
    "min_supported_version": "0.3.0",
    "notes_url": "https://example.test/localgatekeys/releases/0.4.0",
    "artifacts": [
      {
        "name": "LocalGateKeys-Setup-Personal.exe",
        "sha256": "<64 lowercase hex>",
        "size": 12345678,
        "url": "https://example.test/localgatekeys/releases/0.4.0/LocalGateKeys-Setup-Personal.exe"
      }
    ],
    "sequence": 12
  },
  "signature": {
    "alg": "Ed25519",
    "key_id": "<first 8 bytes of SHA-256(raw public key), hex>",
    "signature": "<base64 of the 64-byte Ed25519 signature>"
  }
}
```

Rules enforced by both the signing script and the client:

| Field                   | Rule                                                                 |
|-------------------------|----------------------------------------------------------------------|
| `format`                | exactly `localgatekeys-release-manifest`                             |
| `version`               | integer `1`                                                          |
| `app_version`           | `x.y.z`, no leading zeros, no `v` prefix                             |
| `published`             | RFC 3339 with explicit offset (`Z` or `+hh:mm`)                      |
| `min_supported_version` | `x.y.z`; older clients are told they are unsupported                 |
| `notes_url`             | `https://` only, no credentials, no fragment, max 2048 chars         |
| `artifacts[]`           | exactly `name`, `sha256` (64 lowercase hex), `size` (int >= 0), `url` (https) |
| `sequence`              | integer >= 0, strictly increasing across releases                    |

No extra fields are allowed anywhere; duplicate JSON keys are rejected.

The signature is over the **canonical JSON** of `manifest`: keys sorted,
separators `,` and `:` with no whitespace, UTF-8, non-ASCII kept as-is
(`json.dumps(m, sort_keys=True, separators=(",", ":"), ensure_ascii=False)`).

## Publisher workflow

Requirements on the signing machine: Python 3.11+ and the `cryptography`
package. The script has no dependency on the application package, so it can
run from a clean checkout on an offline machine.

### 1. Generate a signing key (once per key)

```powershell
python scripts/sign_release_manifest.py keygen --out .\release-signing-key.pem
```

You are prompted for a password (or pass `--password-env NAME` to read it from
an environment variable in CI). The private key is written as an encrypted
PKCS#8 PEM with owner-only permissions; the script refuses to overwrite an
existing file. It prints:

```json
{"public_key": "<base64>", "key_id": "<16 hex>", "key_file": "..."}
```

Keep the PEM and its password **offline** (hardware token, encrypted vault,
air-gapped machine). Only the public key and key_id go into the repository.

**Without a key file.** `keygen --print-key` writes the encrypted PEM to
stdout instead of a file, so it can go straight to the clipboard and into a
password manager note; the public key and key_id are printed to stderr. To
sign, put the note's text in an environment variable for that one command and
pass `--key-env` instead of `--key`:

```powershell
.venv\Scripts\python.exe scripts\sign_release_manifest.py keygen --print-key | clip
$env:LGK_RELEASE_KEY = Get-Clipboard -Raw   # after copying the note
... sign --key-env LGK_RELEASE_KEY ...
Remove-Item Env:LGK_RELEASE_KEY; Set-Clipboard -Value $null
```

### 2. Embed the public key in the client

In `src/localvault/updates.py`:

```python
RELEASE_FEED_URL = "https://<your-host>/localgatekeys/stable.json"
PUBLISHER_KEYS = {"<key_id>": "<base64 public key>"}
```

The client checks at startup of a check that each `key_id` really is the
SHA-256 prefix of its key; a mismatch is reported as an invalid configuration.
Also bump `BUILD_DATE` in `src/localvault/version.py` to the day the release
is cut (see "anti-freeze" below). Commit, build, and ship that client *before*
or together with the first manifest signed by the new key.

### 3. Write the unsigned manifest

Create `release-manifest.json` with the fields above. `sha256`/`size` of the
artifacts and `sequence` can be placeholders; the `sign` step fills them.

### 4. Sign

```powershell
python scripts/sign_release_manifest.py sign `
  --manifest .\release-manifest.json `
  --key .\release-signing-key.pem `
  --artifact .\dist\installer\LocalGateKeys-Setup-Personal.exe `
  --sequence 12 `
  --published 2026-10-05T12:00:00Z `
  --out .\dist\installer\stable.json
```

* `--artifact` (repeatable) hashes the file and fills `sha256`/`size` of the
  manifest entry whose `name` equals the file name. The build does not need
  the private key: the build script can emit the unsigned manifest and the
  release engineer signs it afterwards.
* `--sequence` must be **greater than every previously published sequence**.
  Keep the counter in your release checklist; the client refuses to go back.
* The manifest is validated before signing, so a malformed manifest never
  gets a signature.

Suggested one-line hook for `scripts/build_personal_installer.ps1` (after the
installer and its `.manifest.json` are produced; the key is supplied by the
release engineer, not stored on the build machine):

```powershell
& $Python scripts/sign_release_manifest.py sign --manifest "$InstallerRoot\release-manifest.json" --key $env:LGK_RELEASE_KEY --out "$InstallerRoot\stable.json" --artifact $Installer --sequence $ReleaseSequence --password-env LGK_RELEASE_KEY_PASSWORD
```

### 5. Verify before uploading

```powershell
python scripts/sign_release_manifest.py verify --bundle .\dist\installer\stable.json --public-key "<base64 public key>"
```

### 6. Publish

Upload `stable.json` to `RELEASE_FEED_URL` over HTTPS. The host must not
redirect to a different origin (scheme, host, port) or the client aborts.
Keep the document small; the client reads at most 64 KB. With the Cloudflare
hosting below this is one command:

```powershell
.\scripts\publish_release_feed.ps1 -Bundle .\dist-installer\stable.json -Artifact .\dist-installer\LocalGateKeys-Setup-Personal.exe
```

## Hosting on Cloudflare

The feed and installers are served by a Worker (`cloudflare/update-feed`) in
front of one R2 bucket. The Worker is read-only and serves exactly:

| Path                          | R2 key                       | Caching                 |
|-------------------------------|------------------------------|-------------------------|
| `/stable.json`                | `stable.json`                | 5 minutes               |
| `/revocations.json`           | `revocations.json`           | 5 minutes               |
| `/releases/<x.y.z>/<file>`    | `releases/<x.y.z>/<file>`    | 1 year, `immutable`     |

Everything else is 404, only GET/HEAD are allowed, query strings are
rejected, it never redirects, and it refuses to serve a `stable.json` larger
than the client's 64 KB cap. The Worker is not trusted for integrity: the
signature in `stable.json` is, so a tampered Worker or bucket can only make
checks fail. Releases older than the `MIN_RELEASE` var in `wrangler.jsonc`
(now `0.4.7`) are no longer served; the objects stay in R2. Tests: `tests/update-feed-worker.test.cjs` (part of `npm test`).

### One-time setup

```powershell
wrangler login                                   # opens the browser
wrangler r2 bucket create localgatekeys-releases
cd cloudflare\update-feed
wrangler deploy                                  # serves the custom domain in wrangler.jsonc
```

Then set the client config (step 2 above) to that origin:

```python
RELEASE_FEED_URL = "https://updates.localgatekeys.app/stable.json"
```

The URL is compiled into every client, so do not rename the Worker or move
the account afterwards; a move means shipping a client with the new URL and
keeping the old origin alive until old clients have upgraded.

### Each release

1. Build the installer (`scripts/build_personal_installer.ps1`).
2. Write the manifest with artifact URLs of the form
   `https://updates.localgatekeys.app/releases/<app_version>/<file>`
   and `notes_url` pointing at the release notes (e.g. the GitHub release).
3. Sign it (step 4) with a `--sequence` above the live one.
4. Run `scripts/publish_release_feed.ps1` (add `-WhatIf` for a dry run). It
   refuses to upload unless the bundle verifies against the keys in
   `updates.py`, every artifact's sha256/size/URL matches the manifest, and
   the sequence is higher than the live feed's. It uploads the installers
   first and `stable.json` last.

## Licence revocations

Refunded Pro licences are revoked with a second signed document,
`revocations.json`, served at `/revocations.json` from the same R2 bucket (R2
key `revocations.json`, same Worker). It is signed with the release key, so the
client trusts no extra key, and it is separate from `stable.json`, which never
carries licence data.

```powershell
python scripts/sign_release_manifest.py revocations --key .\release-signing-key.pem `
  --ids-file .\revoked.txt --out .\revocations.json
wrangler r2 object put localgatekeys-releases/revocations.json --file .\revocations.json --content-type application/json --remote
```

`.\scripts\publish_revocations.ps1 -IdsFile <ids> -Key <release key PEM>` does
both steps (sign, verify, upload; `-NoUpload` or `-WhatIf` to stop short).
`revoked.txt` has one licence id per line and must list every id that should
stay revoked. The client reads at most 1 MiB and 10,000 ids. See [LICENSING.md](LICENSING.md) for when and why.

## Key rotation

`PUBLISHER_KEYS` is a dictionary so several keys can be trusted at once.

1. Generate the new key (`keygen`). Add its entry to `PUBLISHER_KEYS` **next
   to** the old one and ship a client release. Manifests are still signed with
   the old key, so old and new clients both verify.
2. Once the release from step 1 has been out long enough, switch signing to
   the new key. New clients accept it (new key_id present); clients older than
   step 1 report "could not be verified" and should upgrade via the previous
   release first; set `min_supported_version` accordingly.
3. In a later release remove the old key_id from `PUBLISHER_KEYS`.

If a private key is **compromised**: remove its key_id immediately, ship a
client with only the new key, and sign the new manifest with a `sequence`
higher than anything the attacker could have published so that clients that
already saw a rogue manifest are not pinned to it. Because the feed URL and
keys are compiled into the binary, a compromised key can never make a client
download or run anything; the worst case is a misleading "update available"
dialog pointing at an HTTPS page.

Rotate `BUILD_DATE` with every release even when the key does not change.

## Client enforcement (what `check_for_updates` guarantees)

In order, each step failing stops the check and raises `UpdateCheckError`
whose message is static ("The release manifest could not be verified.") and
never contains feed contents or URLs. A short machine-readable `reason`
attribute is available for logs and tests.

1. **Configured?** Empty `RELEASE_FEED_URL` or empty `PUBLISHER_KEYS` returns
   `None` without any network activity.
2. **Transport**: single HTTP GET to the fixed HTTPS feed URL, 3 s timeout,
   redirects only to the same origin, `Content-Length` and actual body capped
   at 64 KB (65 536 bytes), status must be 200.
3. **Shape**: top-level object with exactly `manifest` and `signature`; the
   signature block has exactly `alg`, `key_id`, `signature`; `alg` is
   `Ed25519`; `key_id` must be in `PUBLISHER_KEYS`; signature is 64 bytes.
4. **Signature**: Ed25519 verification over the canonical JSON of `manifest`
   with the embedded key for `key_id`. Only after this passes is any manifest
   field interpreted.
5. **Schema**: exact field set and types as in the table above, HTTPS-only
   URLs, no extra or duplicate fields.
6. **Anti-freeze**: `published` must not be more than 400 days before
   `version.BUILD_DATE`. A frozen or replayed feed therefore stops validating
   after about 13 months, instead of hiding newer releases forever.
7. **Rollback protection**: `sequence` is compared with the highest sequence
   previously verified on this machine, stored in
   `<app data dir>/update-state.json` (same directory resolution as the
   vault, via `config.data_dir()`). A lower sequence is rejected; a higher one
   is persisted only after every other check has passed. Corrupt state is
   treated as unknown and replaced on the next success.
8. **Comparison**: numeric `x.y.z` comparison of `app_version` against
   `APP_VERSION`; `min_supported_version` is surfaced as `is_unsupported`.

**Strict offline mode** (on by default) never checks on its own. Clicking
*Check for updates* asks "Check once anyway?" and makes the single request
only on yes; the setting stays on. After an unlock, a build more than
`STALE_BUILD_DAYS` (90) past `BUILD_DATE` asks whether to check now. That
decision uses only the clock, no network. Declining stores
`update_reminder_snoozed_until` in settings and stays quiet for
`REMINDER_SNOOZE_DAYS` (30). The request identifies as
`LocalGateKeys/<version>`: Cloudflare blocks urllib's default agent
(error 1010).

The only side effects are the GET request and writing `update-state.json`.
`open_release_page()` opens the `notes_url` of the **last verified** manifest
in this process and refuses when no verified manifest exists; a failed check
clears the previously verified value. Strict offline mode is enforced by the
UI before `check_for_updates` is called.

## Tests

`tests/test_updates.py` covers: not-configured behaviour with empty keys and
empty feed, malformed embedded keys, sign/verify round trip (in-process and
through the CLI script), tampering with every signed field, wrong key /
unknown key_id / malformed signature block, non-bundle payloads, HTTP feed
URL, stale `published`, replayed lower `sequence`, state persistence in the
data dir, 64 KB cap (declared and actual), non-200 responses, URL-free error
messages, cross-origin redirect rejection, release-page opening, and the UI
threading behaviour. All network access is through the injected
`opener_factory`; no test reaches the network.
