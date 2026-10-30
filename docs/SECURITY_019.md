# Security notes for release 019

**Engineering prototype. Not independently audited. Keep recoverable independent
copies of important credentials and use disposable test logins initially.**

## Intentional change: user-opted-in sign-in

Previous patches never submitted login forms. Release 019 adds explicit opt-in
per-profile/per-entry automatic sign-in after an explicit fill action, not on
page load. The encrypted profile preference defaults false. Per-entry policies
are encrypted, and restore/rebind resets automatic-sign-in trust. Ambiguous destinations stay manual.

This design uses HTML `requestSubmit` to preserve validation/submit events and
UI Automation Invoke for a saved desktop button. It does not skip MFA, CAPTCHA,
password-change approval, purchase confirmation, or provider authorization.

## Profile/session boundary

Opaque random capabilities bind asynchronous work to a profile and unlock-session
epoch. Browser grants also bind exact origin, browser-supplied tab/document identity,
full URL, request nonce and permitted entry IDs. Metadata precedes selected-secret
release. Release is one-use; final validation/submit is short-lived and single-use.
Lock/switch/timeout revokes capabilities; late callbacks are discarded. Security
notifications revoke the epoch before waiting for the Tk UI thread.

A final check cannot retract input or a submission already handed to the OS/site.
A provider can hang inside an already-issued UIA call. Deadlines prevent subsequent
steps, not cancellation of an OS action already executing. No 180-Hz responsiveness
or universal input latency is guaranteed by portable unit tests.

People sharing one Windows login still share an OS identity and may control the
same running applications. Profiles protect locked vault contents with separate
master passwords; they are not process/OS sandboxes. Anyone using an already-unlocked
profile can act as that profile. Separate Windows accounts give a stronger boundary.
Locking this app does not clear website cookies or sign out other apps.

## Destination boundary

Browser service worker validates top-frame/documentId/current URL/lifecycle/active
state using browser APIs both before forwarding and after a native response.
Content scripts recheck visible fields, form/action/target and URL before writing
and again before requesting one sign-in. Dynamic/ambiguous targets fail closed.
No web page is asked for the vault master password. In-page UI can be imitated;
master-password entry belongs to LocalGateKeys' desktop UI.

The website can read passwords filled into its own ordinary DOM input. Extension
isolated worlds/closed Shadow DOM are not a secret boundary against that website.
A same-origin compromise is not solved by this password manager.

Desktop binds remain exact executable/hash/window/edit-layout/selector checks;
publisher pins apply when available. No existing protected desktop field values
are read. Embedded CEF/WebView origin is not attested by a desktop binding. A
remembered embedded-page approval acknowledges this residual risk, not origin verification.

No global keyboard hooks, process-memory access, DLL injection, screen/OCR password
capture, browser database decryption, inbound keystroke logging, or generic Enter
submission were introduced. GUI screenshot tests capture only our own dummy-data
application in a controlled test session.

## IPC / installation

Windows uses a current-user ACL named pipe, random per-agent token, and pinned
native launcher. A spawned Python client additionally requires the pinned
interpreter binary and launcher parent. Missing identity pins now fail closed;
run current-user bridge repair. Python source/dependencies are not a signed native
security boundary; a malicious same-user process or administrator is out of scope.

Repair operates on the repository containing its script and only HKCU native-host
registration. It does not copy the program into AppData or delete profile data.
The existing installer remains per-user (%LOCALAPPDATA% Programs, HKCU, no elevation)
and gains interpreter pin metadata, but was not run on Windows during this validation.
An administrator can override user ACLs. Per-user installation does not distinguish
two humans using the same Windows login.

## Persistence and recovery

Vault format remains authenticated Argon2id + AES-GCM JSON, version 1, with optional
new encrypted fields. Writes use atomic replacement and a short exclusive writer
lock. A committed-file digest detects competing writers instead of last-writer-wins
overwrite. Failed commits restore the in-memory committed payload. New backup/import
reads are bounded; existing KDF bounds remain. Master-password change uses a fresh
salt/key and retains old-password requirements for old backups.

Recently Deleted and password history are encrypted, not plaintext logs. Retention
purging/permanent deletion cannot erase prior independent copies/backups. Encrypted
backup verify/restore uses encrypted-only temporary files, validates both passwords,
and defaults to a new profile. Existing unverified restore helpers are retained only
for legacy API compatibility; the UI uses the verified new-profile workflow.

Windows clipboard copies set documented history/cloud exclusion formats before
plaintext. Auto-clear/lock compares the sequence captured while owning the clipboard;
unrelated copies are left alone. Non-Windows fallback compares a digest of the owned
value. Clearing is best effort if access is blocked and cannot retract third-party
clipboard copies/history. Passwords already filled into a website/app remain there.

Python strings/copies, interpreter memory, page files and crash dumps cannot be
completely zeroized. The app reduces reference lifetimes and clears owned mutable
key buffers, but does not claim perfect secret erasure or resistance to same-user
malware. A smaller native secret-handling component remains future hardening work.

## Updates / external checks

The patch manifest detects version drift and changed payloads; it is not a digital
signature. The rollback helper touches only whitelisted application-relative files.
It refuses unknown edits/symlinks and retains code backups. Signing, supply-chain
review, independent audit, Windows/mixed-DPI/accessibility testing remain release gates.

HIBP requests are optional, manual, HTTPS-only, no redirect, short-prefix with
Add-Padding enabled. No password/full hash/site/username is sent; source IP remains
visible to the service. Default operation remains local-only. Tests mock the service.

## Primary implementation references

- HTML requestSubmit and validation: https://developer.mozilla.org/en-US/docs/Web/API/HTMLFormElement/requestSubmit
- Chromium content scripts/shared DOM: https://developer.chrome.com/docs/extensions/develop/concepts/content-scripts
- Chromium MessageSender/documentId: https://developer.chrome.com/docs/extensions/reference/api/runtime#type-MessageSender
- Chromium current document/lifecycle: https://developer.chrome.com/docs/extensions/reference/api/webNavigation
- Clipboard sequence: https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-getclipboardsequencenumber
- Clipboard history/cloud exclusion formats: https://learn.microsoft.com/en-us/windows/win32/dataxchg/clipboard-formats
- UI Automation Invoke: https://learn.microsoft.com/en-us/windows/win32/winauto/uiauto-implementinginvoke
- Session timeout distinction: https://pages.nist.gov/800-63-4/sp800-63b/session/
- Password age guidance: https://pages.nist.gov/800-63-4/sp800-63b/authenticators/
- HIBP range/padding: https://haveibeenpwned.com/API/v3

These are implementation references, not certifications or endorsements.
