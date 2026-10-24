# Security breach audit — 2026-10-14

Scope: vault crypto and storage, local IPC and native host, MV3 browser extension,
importers / updates / sync / unlock methods. Branch `edit-in-place` (including the
uncommitted `vault.py` work at the time of the audit).

Each attack is a test. Defenses that hold are passing tests; confirmed weaknesses are
written as the *secure* expectation and marked `xfail(strict=True)` (Python) or
`{ todo }` (node:test), so they flip to a failure the moment a fix lands and the marker
must be removed.

| Test file | Result |
|---|---|
| `tests/test_security_audit_vault.py` | 28 passed, 3 xfailed |
| `tests/test_security_audit_ipc.py` | 60 passed, 5 xfailed |
| `tests/test_security_audit_inputs.py` | 23 passed, 8 xfailed |
| `tests/extension/security-audit.test.cjs` | 25 passed, 6 todo |

Run with `.venv/Scripts/python.exe -m pytest -q -p no:cacheprovider tests/test_security_audit_*.py`
and `npm test`. Add `--runxfail` to see each confirmed weakness fail on its security assertion.

No path was found for a remote website or a cross-origin frame to obtain a stored
credential, or for anyone to decrypt the vault without the master password, recovery
phrase or an enrolled unlock factor.

## Fix status (2026-10-15, branch `security-fixes`)

All 22 confirmed findings and the informational items below are fixed; every
`xfail` / `todo` marker has been removed, so each attack above is now a normal
passing test. `SECURITY.md` describes the new behaviour.

| ID | Fix |
|---|---|
| SEC-I1 | `browser_ancestry.py`: host and agent walk the parent chain (≤1 System32 `cmd.exe` hop, allow-listed vendor-signed browser via `WinVerifyTrust`, creation-time ordering); unverified hosts may only `ping`. |
| SEC-P17 / P18 | `winpaths.py`: absolute System32 `powershell.exe` (restricted `PSModulePath`, module-qualified cmdlet) and `icacls.exe` granting by token SID. OCR runner refuses non-absolute executables. |
| SEC-V12 | Password change rotates the data key, purges old-key rolling backups, re-creates or invalidates the recovery wrapper; crash-safe dual-MAC anchor during the switch. The UI asks for the recovery phrase and explains the consequence. |
| SEC-E2 | In-page UI pinned (`!important`, top layer), every click checked for style, geometry, `elementFromPoint` and overlapping top-layer elements; a single match still needs the picker. |
| SEC-P15 | Persistent per-profile "master password required" marker (fails closed). |
| SEC-I11 | UTS-46 non-transitional IDNA (`idna` added as a runtime dependency). |
| SEC-V19 | Export ACL applied before any plaintext is written (private folder + pre-restricted file). |
| SEC-V14 / V25 | Plaintext anchors rejected for v3; `rollback_anchor_required` in the payload; missing anchor warns in the UI; migration journals never restore their anchor and are discarded below the current generation. |
| SEC-I12 | Bundled Public Suffix List (2026-10-07 snapshot) with wildcard and exception rules; fails closed to exact host. |
| SEC-E12 / E13 | `safeForm` checks every submitter and resolves against `document.baseURI`; cross-origin `<base>` refused. |
| SEC-P1 / P4 / P5 | KDBX DOCTYPE rejected by expat handlers in any encoding; `RecursionError` and 1PUX decoder errors mapped to format errors; encrypted / unknown-compression members rejected. |
| SEC-E14 / E15 / E30 | Clobbering-proof globals; no `web_accessible_resources` (inline SVG icons). |
| V26 / V27 / V28 | No `%TEMP%` migration copy; replace-restore requires the vault password, rollback confirmation and sanitising; KDBX export minimum 12. |
| INFO-1 / 2 / 4 | New-account browser saves get a desktop confirmation; probe rate limit (10/origin, 30 total per minute); pipe client SQOS flags. |
| Other info items | Import KDF work caps; settings `false` no longer disables auto-lock; error log redacts short secret assignments; PDF name escapes decoded; content script blanks released values on every path; `visible()` rejects near-zero opacity and clipping. |

**Residual risk and not verified**

- SEC-I1 raises the bar for a same-user process but is not a boundary: parent-process
  spoofing or driving a real browser still works. Not yet exercised with a real
  Chrome / Edge / Firefox install end to end.
- SEC-E2 top-layer behaviour, real `elementFromPoint` and computed-style checks are
  unverified outside jsdom; Chromium < 114 (no popover) can still be covered by a
  `pointer-events:none` overlay.
- Recovery-phrase unlock + new password does not rotate the data key; old vault
  copies still expose their own older contents to the old password.
- A missing anchor is warned about, not refused; a planted v2-era copy plus a
  plaintext anchor is still undetectable without state outside the vault folder.
- Signature checks still shell out to PowerShell in `signature.py` (browser ancestry
  uses `WinVerifyTrust` directly).
- Full Python suite after the fixes (including GUI tests): 1,639 passed; the one
  remaining failure, `test_shell_home_layout.py::test_rebuilt_rows_inherit_collapsed_state`,
  is intermittent and fails the same way on the unfixed branch point (7eaa29a). `npm test`: 119/119.

## Findings (as found on 2026-10-14)

| ID | Sev. | Location | Weakness | Fix | Evidence |
|---|---|---|---|---|---|
| SEC-I1 | **High** (vs. threat model) | `native_host.py:157,278`, `pipe_transport.py:204-232` | Any same-user process can launch the registered native host with a `chrome-extension://<id>/` argument and drive it over stdin. The pipe pin accepts it (it *is* the registered exe), the host supplies the DPAPI token, and `user_gesture:true` is self-asserted, so `begin_browser` → `get_browser` returns any origin's password while the vault is unlocked, with no desktop prompt. Bypasses the "arbitrary process without the token" protection SECURITY.md claims. | Host verifies its parent process is an allow-listed, signed browser; agent verifies the host's parent chain; consider a trusted desktop confirmation for releases without recent desktop interaction. | xfail + end-to-end probe |
| SEC-P17 | Medium | `signature.py:46` | `authenticode_info` runs bare `powershell.exe`; Windows search order lets a planted binary in the app/current directory run and return a forged signer, defeating the native-host and desktop-fill signer pins. | Absolute System32 path (as `export._system32` does) or WinVerifyTrust. | xfail + planting check |
| SEC-V12 | Medium | `vault.py` `change_master_password` (~2173), `_rolling_backup` (~2617) | Changing the master password keeps the data key; the rolling backup created by the change still holds the old-password wrapper, so a leaked old password + any old copy decrypts the *current* vault. | Rotate the data key on password change (`rotate_data_key` exists), or purge backups wrapped under the old password and warn. | xfail |
| SEC-E2 | Medium | `content.js:557-613`, `122-149`, `486` | The in-page icon / picker hosts live in the page DOM; a same-origin XSS can restyle them (`opacity:0`, reposition) and clickjack a one-click fill (single match fills without a picker). | At click time check computed style/position and `elementFromPoint`; or use the top layer; optionally confirm single-match fills. | todo (jsdom) |
| SEC-P15 | Low–Med | `runtime_actions.py:31,374` | Emergency lock's "master password required" flag is in memory only; exit + relaunch re-offers Windows Hello / camera unlock. | Persist an authenticated per-profile marker cleared only by master unlock. | xfail |
| SEC-I11 | Low–Med | `origin.py:145` | `host.encode("idna")` is IDNA 2003: `straße.de` → `strasse.de`, while browsers send `xn--strae-oqa.de`. The owner of `strasse.de` gets an exact-origin match for the victim's login. | UTS-46 non-transitional (`idna.encode(..., uts46=True, transitional=False)`). | xfail |
| SEC-V19 | Low | `export.py` `atomic_write` (~344-372) | Plaintext export is written and fsync'd *before* the owner-only ACL is applied; a handle opened in that window keeps read access. | Apply ACL (or create with a security descriptor) before writing. | xfail |
| SEC-V14 | Low | `vault.py` `_read_generation_anchor` (~653-694) | A legacy plaintext anchor `{"version":1,"generation":0}` is accepted next to a v3 vault, enabling rollback without unlocking — contradicts SECURITY.md's "cannot be rewritten without unlocking". | Reject plaintext anchors for v3; record "anchor required" inside the encrypted payload. | xfail |
| SEC-I12 | Low | `origin.py:251-276` | `base_domain` falls back to last-two-labels for suffixes missing from the curated list (e.g. `*.elasticbeanstalk.com` regions, `*.web.core.windows.net`), offering the login to other tenants. | Ship a full PSL snapshot or fail closed to `host` mode. | xfail ×3 |
| SEC-E12 | Low | `login-safety.js:60-73` | `snapshot` checks `safeForm(form)` without submitters; a same-origin injected button with cross-origin `formaction` passes, and the user's manual click posts credentials away. | Refuse forms with any cross-origin `formaction` / non-`_self` `formtarget`. | todo |
| SEC-E13 | Low | `login-safety.js:62-63` | Relative `action` resolved against `location.href`, not the `<base href>`; injected `<base>` sends the form elsewhere. | Use the resolved IDL `form.action` / `submitter.formAction`. | todo |
| SEC-P18 | Low | `browser_bridge.py:105,112` | Bare `icacls.exe` during bridge repair (planting) and grant by `getpass.getuser()` (env-derived) rather than SID. | `_system32("icacls.exe")` + current SID. | xfail |
| SEC-P1 | Low | `importers/kdbx.py:803`, `:417` | DOCTYPE/ENTITY guard scans raw bytes; UTF-16 XML bypasses it and internal entities expand (expat still stops billion-laughs and XXE). | Reject DOCTYPE via expat handlers or defusedxml. | xfail |
| SEC-E14/E15 | Low (DoS, fails closed) | `content.js:3,20`, `api.js:13`, `heuristics.js:15` | DOM clobbering (`id="__lgk019"`, `id="browser"`, `id="LGKHeuristics"`) disables the content script on that page. | Strict `=== true` / `typeof ... === "function"` checks. | todo |
| SEC-P4/P5 | Low (DoS) | `importers/bitwarden.py:281`, `detect.py:88`, `onepassword.py:201-212` | Deep JSON → `RecursionError`; encrypted/unknown-compression 1PUX → `RuntimeError`/`NotImplementedError`; both escape the `ImporterError` contract. | Catch and re-raise as format errors; reject unsupported ZIP flags. | xfail |
| SEC-E30 | Info | `manifest.json:56-67` | Pages can fingerprint the extension via web-accessible icons (already in backlog). | `data:` icons or `use_dynamic_url`. | todo |

### Informational (code reading only)

- **SECURITY.md mismatches:** new-account saves (`browser_broker.py:812,879`) have no desktop confirmation although SECURITY.md promises one; `uia.updated_binary_binding` adopts new titles/layouts for identical or pinned-signer binaries, unlike the documented exact-title rule; `starts_with` URL rows are not path isolation (any same-origin page can `pushState`).
- **Oracle:** `check_browser` / `capture_browser` answer (username, password) guesses with no gesture or rate limit — only reachable directly via SEC-I1.
- **Pipe client** opens without `SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION` (`pipe_transport.py:702`).
- **Migration journal** (`vault.py` ~747-827) is unauthenticated: a planted journal can roll the vault back (equivalent to SEC-V14).
- `restore_full_backup(replace=True)` skips the rollback confirmation and sign-in-policy sanitising that the UI path applies.
- Verifying a v2-era backup can leave a ciphertext migration copy in `%TEMP%\Backups`.
- KDBX export password minimum is 8 vs 12 elsewhere; import KDF ceilings (1 GiB × 1000) allow a long local stall.
- `settings.json` `false` timeout disables auto-lock; `error_log` only redacts ≥24-char runs; PDF active-content check is a raw byte search (flag currently unused). All need same-user write access or have no live path.
- Content script: early-return path in `get_browser` and `releaseIdentity` don't blank released values (isolated world, consistency only); `visible()` accepts `opacity:0.01` / `clip-path` fields.

## Verified defenses (passing tests)

Vault: KDF downgrade and parameter tampering refused before Argon2; wrapper transplant
across vaults; header / generation / version relabel / ciphertext tamper; no nonce reuse;
no plaintext or key material on disk; `lock()` zeroes keys; foreign anchors rejected;
backup and transfer-package tamper; attachment sidecar swap and traversal IDs; exports
never overwrite without consent; 256-bit recovery phrase with shared throttle; Hello/camera
wrap bound to context.

IPC: JSON / bigint bombs on host and pipe; every token variant refused and token stripped
before dispatch; single-SID pipe DACL with first-instance and remote-client rejection;
exhaustive origin-confusion corpus (schemes, userinfo, loopback spellings, homographs,
ports, http downgrade); grant / nonce replay across origins, tabs, documents, locks and
profile switches; exactly one credential per release; TOTP only on exact origin; pending
captures tab-private; PNG dimension bomb; desktop fill refuses copied binaries, spoofed
titles and lookalike signers.

Extension: untrusted (scripted) clicks ignored; closed shadow roots; no DOM XSS sinks
anywhere; overlay hit-testing; hidden / offscreen fields refused; form-action TOCTOU during
picker and in-flight fill; cross-origin `formaction` never auto-submitted; sender id,
`sender.url` origin, frame-tree walk (loops, depth), document lifecycle and replacement;
smuggled fields ignored; minimal permissions, strict CSP, no `externally_connectable`.

Inputs: billion laughs and XXE fail closed; 1PUX zip bomb; full-backup zip-slip; URL
scheme allow-list for Open website; attachments never executed; update key-id confusion;
sync peer impersonation, reflection, replay, pairing MITM and attempt burn-out; forged
face-failure file; clipboard cleared on lock; CSV formula warning.

## Not covered

Real-browser rendering (SEC-E2 and E14/E15 shown in jsdom only), memory forensics,
the Flutter app (`localgatekeys_app/`), the PyInstaller build artifacts, and dependency /
supply-chain review.
