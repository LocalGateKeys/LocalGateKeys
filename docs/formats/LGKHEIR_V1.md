# `.lgkheir` v1: one emergency-access shard

Status: sub-plan 08, Task 2. Reference code: `src/localvault/heir.py` (package, plan, sheet) and
`src/localvault/envelope.py` (the signed envelope). LGKCore (`Recovery/Heir.swift`, `SignedEnvelope.swift`) and
lgk-core (`core/recovery/Heir.kt`, `SignedEnvelope.kt`) implement it.

An owner splits the 32-byte recovery entropy (the 256 bits behind the 24-word recovery phrase) with
Shamir's secret sharing over GF(256) (`sss.py`; the byte rules are in its module header) into `n`
shards, any `k` of which recover it (`2 <= k <= n <= 5`). Each shard is made out to one holder by nickname and
travels as one signed package: a file, a QR text or a printed sheet.

## Limit: collusion (read this first)

There is no server, so nothing outside the holders' own apps enforces the waiting period or the owner's
refusal. **Any `k` holders acting together, or anyone who gets hold of `k` shards (for example sheets kept in
one drawer or files in one shared folder), can recover the entropy at once and open the owner's backups and
vault file, with no wait and no veto.** The waiting period and the deny file only stop honest requests made
through LocalGateKeys. Encrypting the packages would not change this. The owner must pick holders who would
not act together and who keep their shard apart from the others. The plan editor shows this
(`heir.collusionWarning`) and so does every printed sheet.

## Signed envelope

UTF-8 canonical JSON (keys sorted, no spaces, non-ASCII kept as is), the same rules as `.lgkshare`
(`LGKSHARE_V1.md`), at most 4096 bytes for `.lgkheir`. Duplicate keys are refused.

| key | value |
|---|---|
| `format` | `"localgatekeys-heir"` |
| `version` | `1` (any other value: `unsupported`) |
| `id` | random UUID v4, lower case: this package |
| `sender` | the owner's name as typed, at most 64 characters, may be empty |
| `signer` | base64 of the plan's 32-byte Ed25519 public key |
| `payload` | base64 of the exact canonical JSON bytes of the payload |
| `sig` | base64 of the 64-byte Ed25519 signature |

The signature is over `"LocalGateKeys signed envelope v1\n"` (ASCII) followed by the canonical JSON of the
object without `sig`. A reader checks the key set, the id, the base64 lengths and the signature before it
parses the payload, then requires the payload bytes to be canonical. Base64 is standard with padding and must
round-trip exactly. Why `.lgkshare` is not reused as is: it is sealed under a one-time code and expires after
24 hours; a shard must last years and be opened with nothing else, and it needs an author, not secrecy.

Signed, not encrypted: a single shard (indeed any `k - 1` shards) is statistically independent of the entropy
(Task 1 tests), so a code would add a second thing for the holder to lose in an emergency without protecting
the vault. Authenticity matters instead: the signature binds every field, and all packages of one plan carry
the same `signer`.

## Payload

| key | value |
|---|---|
| `kind` | `"heir-shard"` |
| `plan_id` | random UUID v4, lower case, the same in every package of the plan |
| `index` | the share index `x`, `1..n` |
| `holder` | the holder's nickname: NFC, trimmed, 1 to 32 characters, no control or format characters |
| `k`, `n` | the threshold and the number of shards |
| `wait_days` | the waiting period, `1..30` |
| `created` | Unix seconds when the plan was made |
| `share` | base64 of the 33-byte shard `[index, 32 bytes]`; its first byte equals `index` |
| `check_salt` | base64 of 16 random bytes, one per plan |
| `check` | base64 of the 32-byte entropy check |

Integers are JSON integers (no booleans, no floats). Any other key, or a missing one, is `malformed`.

## Entropy check

`check = HKDF-SHA256(ikm = entropy, salt = check_salt, info = "LocalGateKeys heir check v1\n" || plan_id,
length = 32)` (`plan_id` as its 36 ASCII characters).

`combine` cannot tell a wrong or missing share from a good one (it returns unrelated bytes), so the requester
recomputes the check over the combined secret and compares it in constant time (`hmac.compare_digest`) before
using it; a mismatch is `check-failed`. The check reveals nothing practical about the phrase: the entropy is
256 uniformly random bits, the salt is per plan and the plan id is the context, so it cannot be looked up in a
table, and guessing needs on the order of 2^256 tries. It is never a hash of the phrase words. With `k - 1`
shards the remaining secret is still uniform over 2^256 values, so the check does not help an attacker there
either.

## Combining

A reader accepts a set of packages only when every package verifies, they all carry the same `plan_id`,
`signer`, `k`, `n`, `wait_days`, `created`, `sender`, `check_salt` and `check` (`mixed-plans`), no index
repeats (`duplicate`), there are at least `k` (`need-more`, with the number missing) and the combined secret
passes the check (`check-failed`). A forger without the plan key cannot add a share to a plan (different
`signer`); a forged share signed with the plan key still fails the check.

## QR text

`lgkheir:` followed by the unpadded base64url of the package bytes, at most 2048 characters (one QR code at
error correction M). A scanned text is decoded and verified like a file.

## Plan record (owner side, inside the encrypted vault)

The owner's vault keeps one plan in its preferences under `heir_plan`: `version`, `plan_id`, `k`, `n`,
`holders` (nicknames, in index order), `wait_days`, `folder` (the shared folder on this device, or `null`),
`created`, `owner`, `signer`, `signing_key` (base64 of the 32-byte Ed25519 private key), `check_salt`,
`check`, `backup_public` (the plan's X25519 backup key, below) and `holder_keys` (one 32-byte holder key per
shard, in index order). It never holds the phrase, the entropy or any shard. The signing key lets the owner's devices sign
later plan files (deny, grant) that a requester checks against the `signer` in the shards (Task 3).

Creating a plan needs Pro (`emergency_access`), re-authentication and the recovery phrase typed by the owner
(`VaultSession.recovery_entropy`): the vault never stores the phrase, so the phrase is checked against the
vault's recovery wrapper and must yield the session's data key. A new plan replaces the stored record, but
shards of an older plan still recover the same entropy: replacing the recovery phrase is what revokes them.

Stale plans: whenever a data-key rotation leaves the current recovery phrase unwrapped (the phrase is
replaced or removed, or the master password is changed without supplying the phrase), the vault sets
`"stale": true` in the stored record in the same save (`heir_plan_stale` in the rotation result). The shards
of a stale plan no longer open the vault; the app says "re-issue shards" and the emergency kit lists no
holders for it.

Revoking the folder's backups: the backups already in the heir folder are locked to the old phrase's backup key, so
the old shards would still open them. Each owner device that looks at a stale plan's folder (the desktop timer, the
Android and iPhone Emergency access page and their request notices) therefore deletes every `backup-*.lgk` file and
`backup-*.lgkheirbackup` descriptor in `<plan id>/` (`heir_flow.purge_backups`, `HeirFlow.purgeBackups`), best
effort, again on every look until none is left, and writes no new one. With no descriptor left the holder's app
reports `no-backup`: the desktop restores nothing and a phone shows no phrase. A copy someone took out of the folder
before the deletion is not covered. `stale` (a boolean), `denied` (at most 64 refused request ids) and `home` (a boolean:
`true` on the device that made the plan) are the optional record keys. Only a home plan is marked stale by a
rotation: a device that received the plan by sync has a phrase of its own.

The record syncs to the owner's other devices inside the encrypted vault sync (`sync/vault_bridge.py`,
namespace `heir`, state id `heir:plan`): everything except `folder` (a path on this device) and `home`. The
newest plan wins; for the same plan `denied` is the union and `stale` either side's. So any of the owner's
devices can deny (and grant with the plan's phrase) once its own shared folder is chosen; only the home
device writes the heir folder's backups, because only its vault opens with the plan's phrase.

Memory: wiping the entropy after splitting is best effort. Python `bytes` copies (phrase decoding, the split
coefficients, the record's key bytes) cannot be erased; nothing here claims they are.

## Printed sheet

`sheet_facts(plan, packages)` gives what the sheet shows, one page per holder in index order: the holder's
nickname, `index / n`, `k`, the waiting period, the owner, the plan id, the date, the package id, and the QR
code of the shard as SVG path data (`qr_size` modules square including the 4-module border, one `M x y h w v1
h-w z` run per dark stretch). `webui/src/components/HeirSheet.svelte` renders it as HTML that the browser
prints with system fonts, exactly like the emergency kit, so Greek and every other script print as typed. The
sheet text is translated and ends with the collusion warning. The emergency kit lists current holders by
nickname only on its own page.

## Folder flow (Task 3, `heir_flow.py`)

Everything travels through the folder the owner shares with the holders, in
`<folder>/LocalGateKeys Emergency/<plan id>/`. Every file is a signed envelope as above (format
`localgatekeys-heir`, version 1) with its own `kind` and an exact payload key set; nothing in the folder is
trusted, and the folder sync's `read_peers` skips these names silently.

- Keys derived per plan: `holder_key = HKDF-SHA256(ikm=share (33 bytes), salt=check_salt,
  info="LocalGateKeys heir holder v1\n" || plan_id)`; the backup key is
  `clamp(HKDF-SHA256(ikm=entropy, salt=check_salt, info="LocalGateKeys heir backup key v1\n" || plan_id))`
  (X25519, RFC 7748 clamping); only its public half is in the record.
- Scans read only names of the exact form below (denies and grants also as a provider's conflict copy,
  `deny-<id> (1).lgkheirdeny`), at most 512 each; a requester reads its deny under its own name first, so
  junk names cannot push it out.
- `request-<id>.lgkheirreq` (`heir-request`: `plan_id`, `holder_index`, `box_public`, `created`, `proof`),
  signed by the requester's own Ed25519 key; the envelope id is the request id.
  `proof = HMAC-SHA256(holder_key, "LocalGateKeys heir request v1\n" || canonical({plan_id, request_id,
  holder_index, signer, box_public, created}))`, so a request proves a shard of this plan and cannot be re-used
  with another key. The owner lists only requests whose proof matches the stored holder key (constant-time).
- `deny-<id>.lgkheirdeny` (`heir-deny`: `plan_id`, `request_id`, `created`), signed by the plan key. Any valid
  deny for the request present in the folder when the requester combines wins, whatever its time says. The
  owner's app keeps refused ids in the record and writes a missing deny again when it next lists requests.
- `grant-<id>.lgkheirgrant` (`heir-grant`: `plan_id`, `request_id`, `box_public`, `ephemeral`, `wrapped`,
  `created`), signed by the plan key: the 32-byte entropy under AES-256-GCM (zero nonce) with
  `kek = HKDF-SHA256(ikm=X25519(esk, box_public), salt=ephemeral || box_public,
  info="LocalGateKeys heir grant v1\n" || plan_id || "\n" || request_id)` and AAD
  `"LocalGateKeys heir grant v1\n" || canonical({plan_id, request_id, box_public})`. Granting needs
  re-authentication, the typed recovery phrase and a current (not stale) plan.
- `backup-<UTC time>-<8 hex>.lgk`: a full backup v3 whose recipient is the plan's backup key (its `kdf` only
  fills the record shape: no password opens it), with `backup-....lgkheirbackup` (`heir-backup`: `plan_id`,
  `file`, `size`, `sha256`, `written_at`, `backup_public`) signed by the plan key. Written right after a plan is
  made and then daily while the home device's app is open and unlocked; the newest two are kept. What the
  folder shows anyone who can read it: the backup's size and number of entries, and the times in the names and
  descriptors, so holders can see when the owner's app was last running (a liveness signal). The profile name,
  the manifest and every member are encrypted to the plan's backup key.

Combining: the requester's newest own request (same Ed25519 and X25519 keys) must exist (`no-request`) and have
no deny (`denied`); then either a grant for it, or `k` shards (`need-more`) once `created + wait_days` days have
passed on the requester's clock (`waiting`). The entropy is checked against the plan's check before anything
uses it (`check-failed`). The backup must be signed by the plan key, written at or after the plan's `created`,
match the signed size and SHA-256, and be locked to this entropy's backup key (`no-backup`: "no recent
backup"). A private copy is restored as a new profile opened with the recovery phrase under the heir's new
master password, without the owner's plan record; the deny is checked again just before the profile is
published. `LGK_HEIR_NOW` (integer Unix seconds) overrides the clock in a source run only (tests and manual
checks); a frozen release build ignores it, so a requester cannot skip the wait with it.

Limits: as above, only honest apps enforce the wait and the veto. Anyone who can write to the folder can delete
files: a deleted request or grant only delays, and a deleted deny is written again by any of the owner's
devices on its next timer look (every 10 minutes while unlocked), which also shows a notice for each new
request.

## Phones (Task 5a/5b)

lgk-core (`recovery/Sss.kt`, `SignedEnvelope.kt`, `Heir.kt`, `HeirFlow.kt`) and LGKCore mirror these rules byte for
byte; `tests/vectors/heir/v1.json` (made by `tests/vectors/heir/generate.py` from the desktop's own functions) holds
packages, a request, a deny, a grant and a backup descriptor the phones re-make or read, plus the plan record's
merge cases. Phones never make a plan or write the heir folder's backups. As one of the owner's devices a phone holds
the synced plan (namespace `heir`, same merge rules; it writes the `.lgkheircap` capability file in the folder (an empty signed view like `.lgkcap`, but with view
`counter` 2^53 - 1, which readers require, so a copied heartbeat or `.lgkcap` does not count) and,
as the Wi-Fi initiator, sends `heir-hello`), lists requests, denies and grants with the typed phrase. As a holder
it asks for access and, once access is open, shows the owner's recovery phrase after the plan's check: the full
backup restore stays on the computer. The phone keeps the desktop restore's gate: it reveals the phrase only when the
folder holds a backup descriptor written no earlier than the plan whose `backup_public` is the recovered entropy's
backup key (so shards of a replaced phrase open nothing), and only after the phone's screen lock.

Names on phones: a name's code points are refused for categories Cc, Cf, Cs and Co, as on the desktop. Unassigned
code points (Cn) are accepted, because a phone's JDK or ICU can be older than the desktop's Unicode tables and would
report later emoji as unassigned; the names come from signed packages the desktop already checked.
