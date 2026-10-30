# LocalGateKeys Pro licensing (owner runbook)

LocalGateKeys has two editions (owner decision 2026-10-19).

- **Free** is the password manager (browser fill, desktop app fill, backups,
  recovery phrase, transfer, unlock options) with up to **4 live items**.
- **Pro** removes the item limit and adds the **Pro features**: device sync
  (Wi-Fi and cloud folder), adding or changing two-factor (TOTP) codes, and
  adding or replacing attachments (document items). It costs **US$4.99
  one-time** and includes **lifetime updates**.

A licence is an Ed25519-signed file checked offline by the app. There is no
activation server and no account.

Code: `src/localvault/licensing.py` (verification, item limit, vault copy),
`app/licence.py` and `app/licence_view.py` (Tools > Licence, upgrade dialog),
`pro_gate.py` (applies the limit to the unlocked vault and routes a refusal to
the upgrade dialog), `licence_link.py` (the `localgatekeys://install-licence/`
link), `scripts/issue_license.py` (owner tooling), `cloudflare/license-issuer` (Worker that issues licences after
payment). The item-limit model is described below.

## What the app enforces

- **Pro features.** `licensing.pro_features()` returns the `Feature` values the
  licence allows (all on Pro, none on Free; fails closed). The app copies it to
  `session.pro_features` with the item limit at unlock and after every licence
  change; `None` (a bare `VaultSession`) means unrestricted.
  `vault.require_pro_feature` raises `ProFeatureRequired`, which the app turns
  into `ApiError("pro_required")` plus the upgrade prompt
  (`app/licence_view.pro_required`).
  - *Two-factor codes:* `VaultSession.set_details` refuses a new or changed key
    (`_same_totp` compares the normalised form, so unrelated edits of a login
    that already has a code still save). Removing a code is allowed. Showing,
    copying and browser fill of existing codes stay free. The login editor
    refuses a new key at once (`totp_allowed` in its view). File imports keep
    keys as hidden "Two-factor key (needs Pro)" fields; encrypted transfer does
    the same for new or changed keys.
  - *Attachments:* `DocumentService.create`/`replace` refuse before any file is
    written. Opening, previewing, saving a copy and exporting existing
    documents stay free. Encrypted transfer leaves new documents (and items
    that reference them) out as "limit".
  - *Sync:* on Free, `SyncWebService` builds a **licence-only** service
    (`SyncService(licence_only=True)`, `view()["licence_only"]` true,
    `view()["pro"]` false). Pairing, joining and Sync now work; a round reads
    only `license`-namespace records from peers, adopts a valid one through
    `licensing.adopt_synced_license`, stores no other record and publishes
    nothing (an empty view; witness and attachment requests answer
    `bad-message`). It never runs in the background: only Sync now, and the
    Wi-Fi listener only for 120 s after a round or while a pairing code is
    shown. Revoked licences, licences whose updates ended before this build
    and a pending removal marker block adoption. Once a licence is adopted the
    plan turns Pro (`LicenceService.on_plan_change`) and full sync starts.
    Data earlier syncs brought stays in the vault.
  - *Store purchases unlock the PC:* an App Store (iPhone/Mac) or Google Play
    (Android) purchase of `pro_unlimited` claims an `LGK1-` licence from the
    licence Worker (`POST /appstore/claim` with the transaction JWS,
    `POST /play/claim` with the purchase token). The Worker verifies the
    purchase, issues one licence per original purchase (name "App Store
    purchase" / "Google Play purchase", no personal data) and revokes it on a
    refund. The app writes it as the synced licence state, so pairing a free PC
    with the phone makes the PC Pro. A licence bought on the website still
    works by key on Windows. Claims are silent; Pro on the phone never depends
    on them.

- **The limit.** `FREE_ITEM_LIMIT = 4`. Live items are web and desktop logins
  plus every typed kind (notes, cards, identities, documents, passkeys and so
  on). Items in the trash do not count.
- **Over the limit, nothing is locked.** A free vault with more than 4 items
  (for example upgraded from 0.4.0, or items that arrived by sync) keeps every
  item visible, editable, fillable and deletable. Only *adding* is blocked:
  new logins and items, new desktop bindings, templates, restoring
  from the trash, and the browser extension's save of a new login (it shows a
  clear message). Updating an existing login is never blocked. Deleting down to
  3 items frees a slot. Items arriving by sync are never blocked.
- **Import.** An encrypted transfer ("Encrypted transfer…") brings in new records
  only up to the free slots left, in package order; the preview and the result
  say how many were skipped and offer Pro. Updates to existing records are never
  limited.
- **Import from other password managers.** New rows beyond the free slots left
  are marked "needs Pro" in review order and left out; the rest are imported.
  The review and the result say how many. When no row fits, nothing is written
  and the upgrade dialog opens. Updates to existing items never use a slot.
- **Pro and builds.** A licence is valid when its signature verifies and its id
  is not on the revocation list. Newly issued licences carry
  `updates_until = 9999-12-31`, so every build is covered. Older licences
  (issued with a 365-day window) keep their own date; a build released after
  that date is not covered, the update dialog warns before installing it, and
  the installed version keeps working.
- A licence problem never blocks start, unlock or vault access, and never
  deletes data. The free limit just applies.
- The licence signing key is **not** the release signing key.
- `LICENSE_KEYS` empty means status "unconfigured", and the limit is lifted.
  That is for development builds only; see the release check below.

### Vault copy and reinstalls

- The licence file lives in the app data folder, so a normal reinstall keeps it.
- When a licence is installed, an encrypted copy is also stored inside the
  vault. After unlock, if the licence file is missing or unusable and the vault
  holds a valid copy, the file is restored silently. Restoring a backup on a
  new PC therefore restores Pro with no user action after unlock. A copy that
  does not verify is never written.
- A valid licence file is never replaced by the vault copy; if it differs, the
  vault copy is updated to match the file.
- Sync carries the licence between the Pro devices in the group. A device publishes its vault copy and the licences it received by sync, each
  as a signed licence state (namespace `license`, id `lic:` plus the first 32
  hex digits of sha256 of the licence id). Only a licence that verifies and is
  not revoked is published or accepted; anything else is refused for that one
  record and the rest of the sync carries on. A received licence is kept in the
  vault and installed (file and vault copy) only when this PC has no valid
  licence, the licence covers this build and no removal is pending (see below).
  A licence never counts as an item and never touches the free limit. Deleting
  or editing a licence state on another device changes nothing here.

### Removing a licence

Removing the licence deletes the licence file and writes a removal marker
(`license.removed`). The marker stays until a licence is installed again. While
it exists, every profile on the PC drops its vault copy at the next unlock and
restores nothing, so a removed licence is never silently brought back by another
profile's vault. The limit applies immediately. Installing a licence clears the
marker.

## 1. Generate the licence key (once)

Use an offline machine with Python 3.11+ and the `cryptography` package.

```powershell
python scripts/issue_license.py keygen --out .\license-signing-key.pem
```

You are prompted for a password (or pass `--password-env NAME`). The PEM is
encrypted PKCS#8 with owner-only permissions; the script refuses to overwrite an
existing file. It prints the `key_id` and the base64 public key.

Store the PEM text **and** its password offline (an encrypted store only you can
open), then keep no other copy on a networked disk. Losing the key means no new licences can be
issued under that `key_id`; a leaked key lets anyone mint licences (see key
rotation).

## 2. Put the public key in the app

In `src/localvault/licensing.py`:

```python
LICENSE_KEYS = {"<key_id>": "<base64 public key>"}
```

The `key_id` is the first 8 bytes of the SHA-256 of the raw public key, as hex
(the same rule as `updates.PUBLISHER_KEYS`). Commit and ship that build before
selling anything.

## 3. Release check

A release build with an empty `LICENSE_KEYS` would give unlimited items to everyone. The
build entry point refuses it, but no build script runs the check yet, so run it
yourself on the **frozen** executable before publishing:

```powershell
.\LocalGateKeys.exe --check-build --release   # the frozen exe from your build output
```

It must exit 0. It fails when `LICENSE_KEYS` is empty (an unconfigured build
would lift the item limit for everyone). This is also an item in
[RELEASE_CHECKLIST.md](RELEASE_CHECKLIST.md).

## 4. Worker setup

The Worker verifies the payment provider's webhook, signs a licence and stores
it for the buyer to fetch. Full details are in
[cloudflare/license-issuer/README.md](../cloudflare/license-issuer/README.md).
Summary:

1. Deploy only once the custom domain exists. `workers_dev` is off and
   `wrangler.jsonc` has no routes; add the custom-domain route first.
2. Create the KV namespace and put its id into `wrangler.jsonc`:
   `npx wrangler kv namespace create LICENSES`.
3. Export the key from the PEM and set the secrets
   (`scripts/export_license_key_for_worker.py` does the export and checks the
   key id, piping straight into `wrangler secret put` so the key never shows):

```
openssl pkey -in license-signing-key.pem -outform DER | base64 -w0
npx wrangler secret put LICENSE_PRIVATE_KEY   # the base64 above
npx wrangler secret put WEBHOOK_SECRET        # from the payment provider
npx wrangler secret put PADDLE_API_KEY        # Paddle only
npx wrangler deploy
```

4. Set the non-secret settings as plain `vars` in `wrangler.jsonc`, not with
`secret put` (they are not sensitive and you want to see them in the dashboard):

```jsonc
"vars": {
  "PRODUCT_IDS": "pro_01m58y778xrg43pvvznfhy5k0d",  // comma-separated product ids that sell Pro
  "PROVIDER": "paddle",          // optional: lemonsqueezy | paddle (other webhook 404s)
  "SUPPORT_EMAIL": "support@localgatekeys.app"  // shown on the pending page after 10 minutes
}
```

`openssl` will ask for the PEM password. The Worker derives the `key_id` from
`LICENSE_PRIVATE_KEY` and checks each new licence against it before storing, so
a wrong key makes the webhook return 500 (the provider retries) rather than
selling a licence the app rejects. Set `PRODUCT_IDS` so other products you sell
never mint Pro. `ALLOW_TEST_MODE=1` makes Lemon Squeezy test orders issue real
licences; leave it unset in production and use it only while testing.

Point the provider's webhooks at `/webhooks/lemonsqueezy` (event
`order_created`) or `/webhooks/paddle` (event `transaction.completed`).

## 5. Website checkout

The buyer needs to land on a page showing their licence without logging in.

1. When the checkout opens, generate 32 random bytes in the browser and encode
   them as base64url without padding (43 characters). This is the claim token.
2. Pass it to the provider as checkout custom data named `lgk_claim`.
3. Set the checkout's success redirect to `https://<your-domain>/license/<token>`.
4. The page at that URL refreshes until the webhook has arrived, then shows the
   `LGK1-` key and a download link for `LocalGateKeys-Pro.lgklicense`.

The token is the only thing that retrieves the licence, so it is generated in
the buyer's browser and never sent anywhere but the provider and the Worker. A
malformed or already used token is replaced by a random one; the licence is
still issued, and you can find it through the order (the Worker indexes
`order:<provider>:<order id>` to the token). A retried webhook never issues a
second licence.

The Worker issues lifetime licences (`updates_until` 9999-12-31).

`PURCHASE_URL` in `app/licence_view.py` is `https://localgatekeys.app/buy`; an
empty value hides the Buy buttons.

The licence page also has an **Install in LocalGateKeys** button: a
`localgatekeys://install-licence/` link that both installers register (and the
Mac app handles). The app checks the signature and asks before installing.

## 6. Manual issue (support)

For a lost licence, a buyer who closed the page, or a gift:

```powershell
python scripts/issue_license.py issue --key .\license-signing-key.pem `
  --name "Buyer Name" --email buyer@example.com --out .\buyer.lgklicense
```

It prints the `LGK1-` paste text; `--out` also writes the `.lgklicense` file.
Licences are lifetime by default (`9999-12-31`). Optional: `--days N` (an
explicit override that limits updates to N days, for special cases only),
`--issued YYYY-MM-DD`, `--password-env NAME`.
Send it by email. The app tolerates the wrapping and trailing punctuation that
mail clients add to the pasted text. Note the `license_id` it creates in your
records; you need it to revoke.

## 7. Refunds and revocation

Revocation is a signed list of licence ids. It is signed with the **release**
key (the one in `updates.PUBLISHER_KEYS`), not the licence key, and served from
the update feed at `/revocations.json`.

The Worker records each refund or chargeback as a `revoke:<license_id>:<id>` KV
record; the weekly routine in
[cloudflare/license-issuer/README.md](../cloudflare/license-issuer/README.md)
("Refunds and revocation") lists them and runs
`.\scripts\publish_revocations.ps1 -IdsFile <ids> -Key <release key PEM>`,
which signs (steps 3-4 below) and uploads in one go. By hand:

1. Find the `license_id` (`lgk_...`) of the refunded order. The Worker stores
   licences in the `LICENSES` KV namespace; for a manual licence use your
   records. For a webhook order, take the provider and order id from the
   provider dashboard and look it up in two steps:

```powershell
# 1. order key -> token
npx wrangler kv key get --binding LICENSES "order:<provider>:<order id>" --remote
# 2. token -> signed bundle; its "license" object holds license_id
npx wrangler kv key get --binding LICENSES "license:<token>" --remote
```

   `<provider>` is `lemonsqueezy` or `paddle`. Read `license_id` from the
   `license` object in the JSON that step 2 prints.
2. Put **every** currently revoked id, old ones included, one per line in a
   text file. The list replaces the previous one.
3. Sign it:

```powershell
python scripts/sign_release_manifest.py revocations --key .\release-signing-key.pem `
  --ids-file .\revoked.txt --out .\revocations.json
```

   Use `--key-env NAME` instead of `--key` to read the key from an environment
   variable, `--password-env NAME` for the password, and `--published` to set
   the timestamp (default now, UTC).
4. Upload it as the R2 object `revocations.json`:

```powershell
wrangler r2 object put localgatekeys-releases/revocations.json --file .\revocations.json --content-type application/json --remote
```

Apps fetch the list after a successful update check and keep the last good copy
for offline use. A list that fails to download or verify never clears the cache,
and a list older than the cached one is rejected.

## 8. Key rotation

Licences are checked against every key in `LICENSE_KEYS`, so several can be
trusted at once.

1. Run `keygen` for a new key and add it to `LICENSE_KEYS` next to the old one,
   and to the copies in `ios/AppShared/Pro/ItemLimit.swift` and
   `android/.../pro/LicenseKeys.kt`. Ship those builds.
2. Switch the Worker's `LICENSE_PRIVATE_KEY` to the new key.
3. Existing licences keep working while the old key stays in `LICENSE_KEYS`.
   Removing it invalidates every licence it signed, so remove it only if it
   leaked, and reissue those licences.

If the key leaked, anyone can mint licences that verify. Revocation helps only
for ids you know about, so the real fix is rotating and shipping a build that no
longer trusts the old key.

## Limitations

- Revocation is best-effort. The app is offline by design, so it only learns of
  a revocation after an update check, and only if the check succeeds. Deleting
  the cached list makes an older signed list acceptable again, and there is no
  freshness floor.
- A licence is a file. It can be copied and shared; nothing binds it to a
  machine, and the vault copy travels with backups. The licence is meant to keep honest users honest, not to stop
  determined copying.
- The app is open to patching; anyone who edits the code can remove the gate.
- No third party has reviewed this scheme.
