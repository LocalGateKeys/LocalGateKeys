# Deep security audit, round 3 (2026-10-24)

Scope: `main` at 6eb8831 (after the extended-audit fixes), the installed app on the
release PC, and the live services localgatekeys.app, licenses.localgatekeys.app and
updates.localgatekeys.app. Fixes are on branch `security-round3-2026-10-24`.
Swift changes are written but not compiled (no Mac); everything else is tested.

## What was run

| Stream | Tools | Result |
|---|---|---|
| CodeQL | CLI 2.27.3; python, javascript-typescript, java-kotlin; security-extended, security-and-quality, security-experimental; Svelte script blocks converted to JS | No security true positive. One crash bug (history quota). One non-constant-time token compare. |
| Static and supply chain | Semgrep 1.182.1 with Trail of Bits rules and r/python, r/javascript, r/typescript, r/kotlin, r/swift, p/secrets; Bandit `-l -i`; njsscan rules via Semgrep; retire.js; ShellCheck; zizmor; OpenSSF Scorecard 5.6.0; GuardDog (npm and PyPI lockfiles); Syft + Grype | No exploitable first-party finding. Low: CPython 3.14.9 `TemporaryDirectory` cleanup race; System32 paths from `%SystemRoot%`; CI checkout tokens; unpinned xcodegen; Gradle wrapper without checksum; no Dependabot cooldown. Scorecard 4.6/10 (mostly solo-repo structure). |
| Windows assessment | BinSkim 4.4.9.13, sigcheck, accesschk, pefile, icacls | Build and release folders writable by other local accounts; installer folder choosable; no image-load policy; unsigned binaries; stale installed build (0.4.3). Install folder, data folder, pipe, registry and startup entries pass. |
| Dynamic | Hypothesis (about 225,000 cases across origin, vault envelope, frame codecs, sync, importers, backups); AST mutation testing (992 mutants on vault, origin, broker, licensing, updates) | 6 robustness bugs (all fail closed, wrong exception type). Security-relevant surviving mutants: update-feed rollback, anchor MAC and DPAPI layers, origin edge cases, broker guards, licensing shapes. |
| Live services | nuclei 3.11.1 (rate-limited, non-intrusive), testssl.sh 3.2.4, manual curl probes, crt.sh/certspotter, source-vs-deployment comparison | No critical/high/medium. Low: site `Access-Control-Allow-Origin: *` (fix not yet deployed); TLS 1.2 CBC/static-RSA suites (needs Cloudflare ACM to change). Info: Worker HSTS, licence page framing/indexing, /recover timing, no resumable downloads, www/pages.dev duplicates, old installers downloadable. |
| Fresh-eyes review of the last day's fixes | manual, end to end | 2 regressions, 2 incomplete fixes, 5 smaller bugs (below). |

## Findings and status

| Id | Finding | Severity | Status |
|---|---|---|---|
| R-1 | LAN pre-auth cap equal to the per-address cap: one device on the home /24 blocks sync | Medium | Fixed: 1 per address, 3 per /24 or /64, one slot reserved for recently verified peers |
| R-2 | Data-folder ACL rewritten recursively on every browser message | Medium | Fixed: main app only, skipped when already owner-only |
| R-3 | Same ACL applied to any `LOCALGATEKEYS_DATA_DIR` folder | Low | Fixed: only folders the app created (marker file) |
| R-4 / M-7 | Sync signer pins were trust-on-first-use | Medium | Fixed: keyring format 2 carries signing keys with proofs; precedence keyring > LAN-paired > first-use (older members only) |
| R-5 / M-3 | Save prompt was a password-guessing oracle on Chromium/Firefox | Low | Fixed: answers only new/exists; comparison happens in the app after Save |
| R-6 | `/recover` without per-email limit | Low | Fixed: 5 per email per hour, uniform work for known/unknown orders |
| R-7 | Attachment decrypt without the older-cryptography fallback | Low | Fixed |
| R-8 | Unlock throttle reset by deleting or downgrading its key | Info | Fixed: throttle key bound in the v3 header AAD (vaults saved now cannot be opened by older releases) |
| R-9 | Disabled popup swallowed prompts | Low | Fixed: falls back to the main window |
| L-2 | Licence claim race (check-then-write in KV) | Low | Fixed and deployed: D1 `lgk-licence-claims` (weur), licence Worker b7f9d8fb |
| L-4 | Camera unlock off kept the data key when a recovery phrase existed | Low | Fixed: rotate and issue a new phrase shown once; profile delete blocked while a camera sidecar exists |
| I-8 | No forward secrecy on LAN sync | Info | Fixed: protocol v2 with per-connection ephemeral X25519, no downgrade |
| Pairing | No Accept step on the inviting device | Low | Fixed: 6-digit code on both screens, Accept/Decline, 60 s timeout |
| W-4 | Installer folder choosable (inherits writable ACLs under C:\) | Medium | Fixed: only `%LOCALAPPDATA%\Programs\LocalGateKeys` |
| W-5 | No DLL search/image-load hardening | Low | Fixed: `SetDefaultDllDirectories`, NoRemoteImages, NoLowMandatoryLabelImages |
| W-6/7 | Version resource; unused payload (FFmpeg plugin, x86/arm64 copies, test modules) | Low | Fixed: 39 MB smaller |
| W-8 | Restore snapshot as a bare file in %TEMP% | Low | Fixed: owner-only scratch folder |
| W-10 | Native-host log never rotated | Info | Fixed: about 2 MB cap |
| W-1 | Build and release folders writable by other local accounts | High (environment) | Fixed in process: the build script refuses release and signed builds from any folder another account can write; releases are built in an owner-only folder. |
| W-2 | Binaries unsigned | Medium | Open: needs a code-signing certificate |
| F-1, V-1, V-2, B-1, T-1 | Deep JSON / non-finite numbers escaped as RecursionError/OverflowError | Low | Fixed |
| O-1 | Full-width trailing dot made canonicalisation non-idempotent | Low | Fixed |
| S-1 | Equal vectors with different content re-reported a conflict every round | Low | Fixed on desktop, Android and iPhone |
| CQ-1 | `history.py` quota path raised UnboundLocalError | Low | Fixed |
| CQ-2 | Extension `session_id` compared with `!=`; empty skipped a check | Info | Fixed: constant time, empty never matches |
| S-4 | System32 paths from `%SystemRoot%` | Low | Fixed: `GetSystemWindowsDirectoryW` |
| S-2/3/5/6 | CI checkout tokens, Dependabot cooldown, xcodegen pin, Gradle checksum | Low | Fixed |
| S-1py | CPython `TemporaryDirectory` cleanup race | Low | Mitigated: backup temp dirs in an owner-only folder; rebuild on the next CPython patch |
| X-1 | Site sends `Access-Control-Allow-Origin: *` | Low | Fixed and deployed (verified: no ACAO header) |
| X-2 | TLS 1.2 CBC/static-RSA suites | Low | Accepted: changing suites needs Cloudflare ACM; clients use TLS 1.3 |
| X-3/4 | Worker HSTS; licence page framing and indexing | Info | Fixed and deployed (verified) |
| X-6 | Installer downloads not resumable | Info | Fixed and deployed: 206/304/416 (update Worker 8dac329d) |
| X-7 | Pre-fix installers still downloadable | Info | Fixed: update Worker answers 410 below MIN_RELEASE 0.4.5; objects kept in R2 |
| X-9 | www and pages.dev serve full copies | Info | Fixed: Redirect Rule (www) and Bulk Redirect (pages.dev), 301 keeping path and query |
| DNS | No DMARC, CAA, DNSSEC | Low | Fixed: DMARC quarantine with reports, CAA (Let's Encrypt, Google Trust Services, SSL.com), DNSSEC on |

New tests: mutation-gap suites (about 260 tests), a v3 vault known-answer vector,
Hypothesis property suites under `tests/props` (small default budget;
`LGK_PROP_EXAMPLES` raises it), and per-finding regression tests.
