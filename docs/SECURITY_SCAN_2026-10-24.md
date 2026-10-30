# Free security and privacy scan, 2026-10-24

Scope: `main` at 53884e7, the installed app on the PC (0.4.5), and the live services
localgatekeys.app, licenses.localgatekeys.app and updates.localgatekeys.app.
Everything below was run with free tools.

**Status:** M1, M2, L1 and L3 are fixed on branch `security-scan-fixes-2026-10-24`
(Pillow 13.0.0, setuptools 84.2.1, BouncyCastle 1.86, vite 8.3.5; website icons off by default and
blocked by strict offline mode; privacy policy section 2.5). L2 (DNS) needs the Cloudflare dashboard.

## Tools run

| Area | Tool | Result |
|---|---|---|
| Python code (SAST) | bandit 1.x over `src`, `localgatekeys_app`, `scripts` | 262 hits, 8 medium/high, all false positives (see below) |
| All code (SAST) | semgrep OSS rulesets `p/default p/secrets p/javascript p/python p/kotlin p/swift` | 43 hits, all false positives or informational |
| Python dependencies | pip-audit on the three lock files | **Pillow 12.3.0: 35 advisories**, setuptools 84.0.0: 1 |
| JS dependencies | `npm audit` (root, webui) | production: 0; webui dev: vite 8.3.0 (high, dev server only) |
| Android/iOS dependencies | OSV.dev API | **BouncyCastle 1.80.2: 3 advisories**; swift-crypto 3.15.1 clean |
| Secrets | detect-secrets (tree) + regex over all 718 commits | no real secret; only test fixtures and public key material |
| Live web | curl probes, TLS version tests, DNS (SPF/DMARC/CAA/DNSSEC), HSTS preload | strong; DNS hardening missing |
| Licence/update workers | code review + unauthenticated probes | webhooks reject unsigned/forged calls (401), no traversal |
| Local app (pentest) | port/pipe enumeration of the running app, traversal and Host-header tests, native-host manifests, folder ACLs | no exploitable issue |

## Findings

### M1. Pillow 12.3.0 has 35 known vulnerabilities (fix: 13.0.0) — Medium
`requirements.lock.txt:315`. The advisories include heap buffer overflow writes (JPEG comment after
ICC profile, TIFF write, bundled libopenjp2), out-of-bounds reads and many decompression-bomb / DoS
bugs. The app decodes untrusted images with Pillow: website favicons fetched from the internet
(`item_icons.py`, `site_icon.py`), profile pictures and imported data. The 0.4.5 installer ships
this version. A `cp314 win_amd64` wheel of 13.0.0 exists. **Fix:** bump the pin, re-run the icon
and profile tests, ship in the next release.

### M2. Website icons contact every saved site by default, even in strict offline mode — Medium (privacy)
`settings.py:58` (`website_icons: bool = True`), `web/main.py:131` (`offline=lambda: False`).
After unlock the app connects to the favicon host of each saved login. Each site and anyone on the
network (DNS, SNI) learns that this IP has an account there. This contradicts parts of the docs:

- `item_icons.py:366` says icons are fetched only when strict offline mode is off.
- `website/public/security.html` says strict offline mode "blocks background internet requests".
- The privacy policy (`website/public/legal/privacy.html`) does not mention favicon requests at all.

**Fix (pick one):** default the switch to off and/or make strict offline mode block it; at minimum
disclose it in the privacy policy and correct the docstring.

### L1. BouncyCastle 1.80.2 (Android) — Low
`android/gradle/libs.versions.toml`. GHSA-9pwp-9qqc-pr26 (name-constraints bypass, critical),
GHSA-qp49-qgx5-5m26 (ASN.1 nesting-depth guard, high), GHSA-c3fc-8qff-9hwx (LDAP injection).
The app uses BouncyCastle only for Argon2id, Curve25519 and passkey keys, not X.509 or LDAP, so
exposure is unlikely, but the bump to 1.85 is free.

### L2. No DMARC, CAA or DNSSEC on localgatekeys.app — Low
SPF exists (`~all`), but there is no `_dmarc` record, so mail claiming to come from
`support@` or `security@localgatekeys.app` (for example a fake "your licence" email) is not
rejected by receivers. There is no CAA record and no DS record (DNSSEC off).
**Fix in the Cloudflare dashboard:** add `_dmarc TXT "v=DMARC1; p=reject; adkim=s; aspf=s"`
(the domain sends no mail of its own), change SPF to `-all`, add CAA `0 issue "letsencrypt.org"`
plus the CAs Cloudflare uses (or let Cloudflare manage CAA), and enable DNSSEC.

### L3. Dev/build-only dependencies — Low
- `webui`: vite 8.3.0 → 8.3.5 (dev server advisories; not in the shipped bundle).
- setuptools 84.0.0 → 84.1.0 in the dev and build locks.

### I1. Local UI server accepts any Host header — Info
pywebview's built-in server (`web/main.py:252`, `http_server=True`) listens on `127.0.0.1:<random>`.
Traversal attempts return 403. Because the Host header is not checked, a DNS-rebinding page could
read the static UI files; those contain no vault data (the JS bridge is not on HTTP). No action
needed unless the server ever serves dynamic data.

### I2. Native host still allows the unpacked development extension ID — Info (known, M6)
`com.localgatekeys.app.json` allows `hojebpmbiibhbhhkohgongojilojijmb` next to the Edge store ID.
Already tracked as M6 in `docs/AUDIT_2026-10-18.md`.

Update 2026-10-30: closed for builds made after 2026-10-28. Both store IDs are set (`src/localvault/config.py`), so `extension_trust()` drops the developer ID from installed builds unless the `allow-developer-extension` opt-in file exists.

### I3. Paddle script without SRI on /buy — Info
Paddle does not publish versioned SRI hashes for `paddle.js` v2; the page's CSP limits scripts to
`self` and `cdn.paddle.com`. Accepted.

### I4. Tracked PyInstaller output in `build-personal/agent-discord-stable/` — Info
Contains the local Windows path and username. The repo is private; consider untracking it before
the repo is ever made public.

## Confirmed good

- Website: HSTS (and `.app` is preloaded), strict CSP with no scripts outside /buy, X-Frame-Options,
  COOP/CORP, Referrer-Policy, Permissions-Policy, nosniff, HTTP→HTTPS 301, TLS 1.0/1.1 refused,
  no exposed `.git`, `.env`, `wrangler` or `_headers`, valid `security.txt` (expires 2027-10-01).
  No analytics or trackers, matching the privacy policy.
- Licence worker: HMAC verified in constant time before parsing, Paddle timestamp tolerance 300 s,
  idempotent per order, body size cap, 256-bit unguessable licence links, escaped HTML, fails closed
  when `PRODUCT_IDS` is unset. Lemon Squeezy route is off (404) because `PROVIDER` is set.
- Update worker: read-only, GET/HEAD only, query strings refused, strict path regex.
- Running app: agent pipe requires a DPAPI-protected token (constant-time compare), user-only DACL
  and `FILE_FLAG_FIRST_PIPE_INSTANCE`; only loopback TCP; extension has no
  `web_accessible_resources` or `externally_connectable` (no fingerprinting by pages).
- Git history: no private keys, API tokens or `.env`/`.pem`/`.pfx` files ever committed.

## False positives (for the next run)

bandit B324 / semgrep sha1 (HIBP k-anonymity, UUIDv5), B305 and semgrep CBC/ECB (KeePass AES-KDF,
Bitwarden import with HMAC verified before decrypt), B314 (expat pre-pass rejects DOCTYPE/ENTITY),
B613 / bidi (the characters are inside a regex that strips them), B104 (route-table parsing, not a
bind), semgrep missing-integrity on `<link rel="canonical">`, non-literal RegExp in
`heuristics.js` (built from escaped constant phrase lists), tainted-env subprocess (`SystemRoot`).

## Not covered by this run

- Authenticated DAST with OWASP ZAP (needs Java or Docker; neither is installed). Free option.
- MobSF scan of a built APK/IPA (needs a build; iOS needs the Mac).
- A real payment flow against the licence worker (would need a Paddle sandbox order).
- External graders worth running by hand: Mozilla HTTP Observatory, SSL Labs (tick "Do not show
  the results on the boards"), internet.nl (mail and web).
